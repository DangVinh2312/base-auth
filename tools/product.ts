import { open, unlink } from 'node:fs/promises';
import { DataSource } from 'typeorm';
import type { IdentityId } from '@base-authorization/core';
import {
  ReleaseRejectedError,
  canonicalLoginEmail,
  type PostgresConnectionSettings,
  type ProductDatabasePurpose,
} from '@base-authorization/typeorm-postgres';
import {
  ProductTransactionRunner,
  ProductManifestReconciler,
  ProductIdentityService,
  createProductPasswordHasher,
  PRODUCT_OFFLINE_ACTOR,
  productObligations,
  purgeExpiredSessions,
} from '@base-authorization/typeorm-postgres/composition';
import {
  productDataSourceOptions,
  provisionProductDatabase,
  bootstrapProductRoot,
  revokeProductRoot,
  reissueRootActivation,
  appendProductAudit,
} from '@base-authorization/typeorm-postgres/operations';
import {
  createProductAuthorizationCore,
  createProductRelease,
} from '../apps/api/dist/authorization/product-manifest.js';
import { ProductDocument1792108800002 } from '../apps/api/dist/documents/migrations/product-document.js';
import { adminConnection, requireEnv } from './env.ts';

function connection(variable: string): PostgresConnectionSettings {
  try {
    const u = new URL(requireEnv(variable));
    if (
      !['postgres:', 'postgresql:'].includes(u.protocol) ||
      !u.username ||
      !u.hostname ||
      u.pathname.length < 2
    )
      throw new Error();
    return {
      host: u.hostname,
      port: Number(u.port || 5432),
      username: decodeURIComponent(u.username),
      password: decodeURIComponent(u.password),
      database: decodeURIComponent(u.pathname.slice(1)),
    };
  } catch {
    throw new Error(`${variable} must be a PostgreSQL URL`);
  }
}

// Same codec composition as the API runtime (apps/api authorization/product-manifest).
const core = createProductAuthorizationCore();
const { isCanonicalUuid } = core;
const [command, ...args] = process.argv.slice(2);
const flags: Record<string, string> = {};
for (let i = 0; i < args.length; i += 2) {
  const key = args[i];
  const value = args[i + 1];
  if (!key?.startsWith('--') || !value || Object.hasOwn(flags, key))
    throw new Error('Expected unique --option value pairs');
  flags[key] = value;
}
const sources: DataSource[] = [];

async function source(purpose: string): Promise<DataSource> {
  const ds = await new DataSource(
    productDataSourceOptions(connection(`PRODUCT_${purpose.toUpperCase()}_DATABASE_URL`)),
  ).initialize();
  sources.push(ds);
  return ds;
}

try {
  if (command === 'provision') {
    const admin = adminConnection();
    const name = requireEnv('PRODUCT_DATABASE_NAME');
    if (!/^[a-z_][a-z0-9_]{0,62}$/.test(name)) throw new Error('Invalid PRODUCT_DATABASE_NAME');
    const control = await new DataSource(
      productDataSourceOptions({ ...admin, database: 'postgres' }),
    ).initialize();
    sources.push(control);
    if (
      !(await control.query<unknown[]>('SELECT 1 FROM pg_database WHERE datname=$1', [name])).length
    )
      await control.query(`CREATE DATABASE "${name}"`);
    const purposes = [
      'data',
      'identity',
      'authority',
      'sync',
      'migration',
      'bootstrap',
      'outbox',
    ] as const;
    const passwords = Object.fromEntries(
      purposes.map((p) => [p, requireEnv(`PRODUCT_${p.toUpperCase()}_PASSWORD`)]),
    ) as Record<ProductDatabasePurpose, string>;
    await provisionProductDatabase({ ...admin, database: name }, passwords);
    console.log('Product database provisioned; credentials are never printed.');
  } else if (command === 'migrate') {
    const settings = connection('PRODUCT_MIGRATION_DATABASE_URL');
    const base = productDataSourceOptions(settings);
    const ds = await new DataSource({
      ...base,
      migrations: [
        ...('migrations' in base && Array.isArray(base.migrations) ? base.migrations : []),
        ProductDocument1792108800002,
      ],
    }).initialize();
    sources.push(ds);
    const applied = await ds.runMigrations({ transaction: 'each' });
    console.log(`Applied ${applied.length} forward migrations.`);
  } else if (command === 'sync') {
    const sync = await source('sync');
    const runner = new ProductTransactionRunner({ sync });
    await new ProductManifestReconciler(runner, {
      core,
      actor: PRODUCT_OFFLINE_ACTOR,
      capabilities: {
        validators: ['fresh@1'],
        obligationHandlers: Object.keys(productObligations),
      },
    }).reconcile(createProductRelease(core));
    console.log('Manifest synchronized.');
  } else if (command === 'enroll' || command === 'invite') {
    const userId = flags['--user'];
    if (!isCanonicalUuid(userId) || userId === PRODUCT_OFFLINE_ACTOR)
      throw new Error('--user must be an explicit canonical UUID, not the offline actor id');
    const method = flags['--method'];
    if (method !== 'local' && method !== 'oidc') throw new Error('--method local|oidc is required');
    const identity = await source('identity');
    const runner = new ProductTransactionRunner({ identity });
    // Invite without enrollment flags reissues an invitation for an existing pending account.
    const reissue =
      command === 'invite' && !flags['--email'] && !flags['--issuer'] && !flags['--subject'];
    const email =
      method === 'local' && !reissue ? canonicalLoginEmail(flags['--email'] || '') : null;
    if (method === 'oidc' && !reissue && (!flags['--issuer'] || !flags['--subject']))
      throw new Error('OIDC enrollment requires exact --issuer and --subject');
    const artifact = command === 'invite' ? flags['--activation-file'] : undefined;
    if (command === 'invite' && !artifact) throw new Error('Invite requires --activation-file');
    const file = artifact ? await open(artifact, 'wx', 0o600) : undefined;
    let committed = false;
    try {
      const service =
        command === 'invite'
          ? new ProductIdentityService(runner, await createProductPasswordHasher(new Set()))
          : undefined;
      const proof = await runner.run('revoke', async (tx) => {
        // issueActivation rechecks that the account is pending and fits the method.
        if (reissue) {
          const token = await service!.issueActivation(tx, userId, method);
          await appendProductAudit(tx, {
            kind: 'identity.invite',
            actor: PRODUCT_OFFLINE_ACTOR,
            target: { userId },
            method,
          });
          return token;
        }
        await tx.manager.query(
          `INSERT INTO app_user(id,email_canonical,state) VALUES($1,$2,'pending')`,
          [userId, email],
        );
        if (method === 'oidc')
          await tx.manager.query(
            'INSERT INTO external_identity(issuer,subject,user_id) VALUES($1,$2,$3)',
            [flags['--issuer'], flags['--subject'], userId],
          );
        await appendProductAudit(tx, {
          kind: 'identity.enroll',
          actor: PRODUCT_OFFLINE_ACTOR,
          target: { userId },
          method,
        });
        return service?.issueActivation(tx, userId, method);
      });
      committed = true;
      if (proof) await file!.writeFile(proof + '\n');
      console.log(
        reissue
          ? 'Invitation reissued for the pending account; no password or session created.'
          : 'Pending account enrolled; no password or session created.',
      );
    } finally {
      await file?.close();
      if (file && !committed) await unlink(artifact!).catch(() => undefined);
    }
  } else if (command === 'purge-sessions') {
    // Retention is a deployment decision: required, no default.
    const retention = flags['--retention-days'];
    if (!retention || !/^\d{1,4}$/.test(retention))
      throw new Error('--retention-days <0-3650> is required');
    const runner = new ProductTransactionRunner({ identity: await source('identity') });
    // Bounded run: at most 200 short transactions of 500 rows; rerun to continue.
    let deleted = 0;
    for (let batch = 0; batch < 200; batch++) {
      const n = await purgeExpiredSessions(runner, Number(retention), 500);
      deleted += n;
      if (n < 500) break;
    }
    console.log(`Purged ${deleted} expired sessions.`);
  } else if (command === 'bootstrap') {
    const userId = flags['--user'];
    const operationId = flags['--operation'];
    if (!isCanonicalUuid(userId) || !isCanonicalUuid(operationId))
      throw new Error('Explicit canonical --user and --operation required');
    const method = flags['--method'];
    if (method !== 'local' && method !== 'oidc') throw new Error('--method local|oidc required');
    const path = flags['--activation-file'];
    if (!path) throw new Error('Bootstrap requires --activation-file outside the repository/logs');
    // Reserve the delivery artifact before mutating persistent state; never overwrite an old secret.
    const file = await open(path, 'wx', 0o600);
    let committed = false;
    try {
      const bootstrap = await source('bootstrap');
      const runner = new ProductTransactionRunner({ bootstrap });
      const result = await bootstrapProductRoot(runner, createProductRelease(core), {
        operationId,
        userId: userId as IdentityId,
        method,
        ...(method === 'oidc' ? { issuer: flags['--issuer'], subject: flags['--subject'] } : {}),
      });
      committed = result.initialized;
      if (result.activationSecret) await file.writeFile(result.activationSecret + '\n');
      console.log(
        result.initialized
          ? 'Root enrollment committed; activation still required.'
          : 'Operation already committed; marker and Root unchanged.',
      );
    } finally {
      await file.close();
      if (!committed) await unlink(path).catch(() => undefined);
    }
  } else if (command === 'revoke-root') {
    const userId = flags['--user'];
    const operationId = flags['--operation'];
    if (!isCanonicalUuid(userId) || !isCanonicalUuid(operationId))
      throw new Error('Explicit canonical --user and --operation required');
    if (!flags['--approval'] || !flags['--reason'])
      throw new Error('Root revocation requires --approval and --reason');
    const bootstrap = await source('bootstrap');
    const result = await revokeProductRoot(
      new ProductTransactionRunner({ bootstrap }),
      {
        operationId,
        userId: userId as IdentityId,
        approval: flags['--approval'],
        reason: flags['--reason'],
      },
      core,
    );
    console.log(
      result.revoked
        ? 'Root suspended and its sessions revoked; marker unchanged.'
        : 'No unsuspended Root for this user; nothing changed.',
    );
  } else if (command === 'reissue-root') {
    const userId = flags['--user'];
    const method = flags['--method'];
    const path = flags['--activation-file'];
    if (!isCanonicalUuid(userId)) throw new Error('Explicit canonical --user required');
    if (method !== 'local' && method !== 'oidc') throw new Error('--method local|oidc required');
    if (!path) throw new Error('Reissue requires --activation-file outside the repository/logs');
    const file = await open(path, 'wx', 0o600);
    let committed = false;
    try {
      const bootstrap = await source('bootstrap');
      const result = await reissueRootActivation(
        new ProductTransactionRunner({ bootstrap }),
        {
          userId: userId as IdentityId,
          method,
          ...(method === 'oidc' ? { issuer: flags['--issuer'], subject: flags['--subject'] } : {}),
        },
        core,
      );
      committed = true;
      await file.writeFile(result.activationSecret + '\n');
      console.log('Root activation proof reissued; earlier proofs are void.');
    } finally {
      await file.close();
      if (!committed) await unlink(path).catch(() => undefined);
    }
  } else
    throw new Error(
      'Expected provision|migrate|sync|enroll|invite|purge-sessions|bootstrap|revoke-root|reissue-root',
    );
} catch (error) {
  // Class, release reason enum and SQLSTATE only: messages and driver details may carry secrets or PII.
  const detail = error as { code?: unknown; driverError?: { code?: unknown } } | null;
  const parts = [
    error instanceof Error ? error.constructor.name : typeof error,
    error instanceof ReleaseRejectedError ? error.reason : undefined,
    detail?.driverError?.code ?? detail?.code,
  ].filter((p): p is string => typeof p === 'string');
  console.error(
    `Product operation failed (${parts.join(' ')}); no secrets are printed. Check inputs, privileges and migration/data mapping requirements.`,
  );
  process.exitCode = 1;
} finally {
  await Promise.all(sources.map((ds) => ds.destroy()));
}
