import type { ProductHttpServices } from './http-services.js';
import { ProductMetrics } from './metrics.js';
import { type OnApplicationBootstrap, type OnApplicationShutdown } from '@nestjs/common';
import { DataSource } from 'typeorm';
import { ReadinessGate } from '@base-authorization/nest';
import {
  ProductTransactionRunner,
  ProductManifestReconciler,
  ProductAuthorization,
  ProductBindingRegistry,
  ProductIdentityService,
  ProductOidcService,
  createProductOidcProvider,
  createProductPasswordHasher,
  verifyProductPrivileges,
  type ProductSessionIdentity,
} from '@base-authorization/typeorm-postgres';
import type { IdentityId } from '@base-authorization/core';
import { productRelease, productBindings } from './product-manifest.js';
import type { AppConfig } from './config.js';
export type RecoveryDelivery = (userId: string, secret: string) => Promise<void>;
export class ProductRuntime implements OnApplicationBootstrap, OnApplicationShutdown {
  readonly readiness = new ReadinessGate();
  readonly authorization: ProductAuthorization;
  readonly identity: ProductIdentityService;
  readonly oidc: ProductOidcService;
  private constructor(
    readonly config: AppConfig,
    private readonly pools: Record<'data' | 'identity' | 'authority' | 'sync', DataSource>,
    private readonly runner: ProductTransactionRunner,
    identity: ProductIdentityService,
    oidc: ProductOidcService,
    readonly recoveryDelivery?: RecoveryDelivery,
    readonly metrics = new ProductMetrics(),
  ) {
    this.identity = identity;
    this.oidc = oidc;
    this.authorization = new ProductAuthorization(
      runner,
      new ProductBindingRegistry(productRelease.declarations, productBindings),
      {
        validators: { 'fresh@1': (_params, input) => input.context.freshAuthentication === true },
        obligationHandlers: ['audit@1'],
      },
      [{ resource: 'document', action: 'update', fields: ['title'] }],
    );
  }
  static async create(
    config: AppConfig,
    recoveryDelivery?: RecoveryDelivery,
  ): Promise<ProductRuntime> {
    const pools = {} as Record<'data' | 'identity' | 'authority' | 'sync', DataSource>;
    try {
      for (const purpose of ['data', 'identity', 'authority', 'sync'] as const)
        pools[purpose] = await new DataSource({
          type: 'postgres',
          url: config.databases[purpose].href,
          synchronize: false,
          migrationsRun: false,
          logging: false,
          ssl: config.nodeEnv === 'production' ? { rejectUnauthorized: true } : false,
          extra: {
            max: purpose === 'data' ? 5 : purpose === 'sync' ? 1 : 2,
            connectionTimeoutMillis: 2000,
          },
        }).initialize();
      // Offline capabilities are absent from the HTTP process.
      const metrics = new ProductMetrics();
      const runner = new ProductTransactionRunner(pools, { onMetric: metrics.observe });
      const hasher = await createProductPasswordHasher(
        new Set([
          'passwordpassword',
          'password123456789',
          '123456789012345',
          'qwertyuiopasdfgh',
          'correct horse battery staple',
        ]),
      );
      const identity = new ProductIdentityService(runner, hasher);
      const providers = new Map();
      for (const settings of config.oidcProviders)
        providers.set(settings.issuer, await createProductOidcProvider(settings));
      return new ProductRuntime(
        config,
        pools,
        runner,
        identity,
        new ProductOidcService(identity, providers),
        recoveryDelivery,
        metrics,
      );
    } catch (error) {
      await Promise.all(Object.values(pools).map((p) => p.destroy()));
      throw error;
    }
  }
  httpServices(): ProductHttpServices {
    return {
      config: { origin: this.config.origin, localEnabled: this.config.localEnabled },
      authorization: {
        list: this.authorization.list.bind(this.authorization),
        detail: this.authorization.detail.bind(this.authorization),
        update: this.authorization.update.bind(this.authorization),
        suspendUser: this.authorization.suspendUser.bind(this.authorization),
        checkSession: this.authorization.checkSession.bind(this.authorization),
      },
      identity: {
        login: this.identity.login.bind(this.identity),
        activate: this.identity.activate.bind(this.identity),
        reauthenticate: this.identity.reauthenticate.bind(this.identity),
        logout: this.identity.logout.bind(this.identity),
        requestPasswordReset: this.identity.requestPasswordReset.bind(this.identity),
        resetPassword: this.identity.resetPassword.bind(this.identity),
        changePassword: this.identity.changePassword.bind(this.identity),
      },
      oidc: {
        begin: this.oidc.begin.bind(this.oidc),
        callback: this.oidc.callback.bind(this.oidc),
        unlink: this.oidc.unlink.bind(this.oidc),
      },
      metrics: { snapshot: this.metrics.snapshot.bind(this.metrics) },
      recoveryDelivery: this.recoveryDelivery,
      currentSession: this.currentSession.bind(this),
    };
  }
  async onApplicationBootstrap(): Promise<void> {
    await verifyProductPrivileges(this.pools);
    await new ProductManifestReconciler(this.runner, {
      actor: '00000000-0000-4000-8000-000000000001' as IdentityId,
      capabilities: { validators: ['fresh@1'], obligationHandlers: ['audit@1'] },
    }).reconcile(productRelease);
    await this.runner.run('sync', async (tx) => {
      const declared = this.config.oidcProviders.map((p) => p.issuer);
      const existing = await tx.manager.query<
        { issuer: string; version: string; enabled: boolean }[]
      >('SELECT issuer,version::text version,enabled FROM oidc_provider');
      if (existing.some((p) => p.enabled && !declared.includes(p.issuer)))
        throw new Error('Provider disable requires explicit offline revoke');
      for (const provider of this.config.oidcProviders) {
        const current = existing.find((p) => p.issuer === provider.issuer);
        if (current && (current.version !== provider.version || !current.enabled))
          throw new Error('Provider drift requires explicit release');
        if (!current) {
          await tx.manager.query(
            'INSERT INTO oidc_provider(issuer,version,enabled) VALUES($1,$2,true)',
            [provider.issuer, provider.version],
          );
          await tx.manager.query('UPDATE authz_state SET revision=revision+1 WHERE singleton');
        }
      }
    });
    // A declared resource without its application migration must prevent the listener from opening.
    await this.pools.data.query('SELECT id,title,owner_id,state,object_id FROM document LIMIT 0');
    const [writes] = await this.pools.data.query<{ valid: boolean }[]>(
      "SELECT has_column_privilege(current_user,'public.document','title','UPDATE') valid",
    );
    if (!writes?.valid) throw new Error('Application write capability missing');
    this.readiness.markReady();
  }
  async onApplicationShutdown(): Promise<void> {
    await Promise.all(Object.values(this.pools).map((p) => p.destroy()));
  }
  async currentSession(secret: string): Promise<ProductSessionIdentity> {
    return this.runner.run('identity', (tx) => this.identity.authenticate(tx, secret));
  }
}
