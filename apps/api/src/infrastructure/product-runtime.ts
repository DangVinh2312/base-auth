import { ProductMetrics } from '../health/product-metrics.js';
import { type OnApplicationBootstrap, type OnApplicationShutdown } from '@nestjs/common';
import { DataSource } from 'typeorm';
import { ReadinessGate } from '@base-authorization/nest';
import {
  type ProductReleaseManifest,
  type ProductSessionIdentity,
} from '@base-authorization/typeorm-postgres';
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
  productObligations,
  PRODUCT_OFFLINE_ACTOR,
} from '@base-authorization/typeorm-postgres/composition';
import type { AuthorizationCore } from '@base-authorization/core';
import {
  createProductAuthorizationCore,
  createProductRelease,
  productBindings,
} from '../authorization/product-manifest.js';
import type { AppConfig } from '../config/app.config.js';
export type RecoveryDelivery = (userId: string, secret: string) => Promise<void>;
export class ProductRuntime implements OnApplicationBootstrap, OnApplicationShutdown {
  readonly readiness = new ReadinessGate();
  readonly authorization: ProductAuthorization;
  readonly identity: ProductIdentityService;
  readonly oidc: ProductOidcService;
  readonly release: ProductReleaseManifest;
  private constructor(
    readonly config: AppConfig,
    private readonly core: AuthorizationCore,
    private readonly pools: Record<'data' | 'identity' | 'authority' | 'sync', DataSource>,
    private readonly runner: ProductTransactionRunner,
    identity: ProductIdentityService,
    oidc: ProductOidcService,
    readonly recoveryDelivery?: RecoveryDelivery,
    readonly metrics = new ProductMetrics(),
  ) {
    this.identity = identity;
    this.oidc = oidc;
    this.release = createProductRelease(core);
    this.authorization = new ProductAuthorization(
      runner,
      new ProductBindingRegistry(core, this.release.declarations, productBindings),
      {
        validators: { 'fresh@1': (_params, input) => input.context.freshAuthentication === true },
        obligations: productObligations,
      },
      [{ resource: 'document', action: 'update', fields: ['title'] }],
    );
  }
  static async create(
    config: AppConfig,
    recoveryDelivery?: RecoveryDelivery,
  ): Promise<ProductRuntime> {
    // Codecs are chosen before any pool opens: a missing/invalid codec fails before the listener.
    const core = createProductAuthorizationCore();
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
        core,
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
  async onApplicationBootstrap(): Promise<void> {
    // Exact grants, including those of the application document migration.
    await verifyProductPrivileges(this.pools, {
      data: ['table:document:SELECT', 'column:document.title:UPDATE'],
      authority: ['table:document:SELECT'],
    });
    await new ProductManifestReconciler(this.runner, {
      core: this.core,
      actor: PRODUCT_OFFLINE_ACTOR,
      capabilities: {
        validators: ['fresh@1'],
        obligationHandlers: Object.keys(productObligations),
      },
    }).reconcile(this.release);
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
    this.readiness.markReady();
  }
  #closed: Promise<unknown> | undefined;
  /** Idempotent (TypeORM destroy() throws when repeated): main.ts and Nest's shutdown hook may both call it. */
  async onApplicationShutdown(): Promise<void> {
    // A rejection is memoized too: retrying destroy() on half-closed pools would only throw again.
    this.#closed ??= Promise.all(Object.values(this.pools).map((p) => p.destroy()));
    await this.#closed;
  }
  async currentSession(secret: string): Promise<ProductSessionIdentity> {
    return this.runner.run('identity', (tx) => this.identity.authenticate(tx, secret));
  }
}
