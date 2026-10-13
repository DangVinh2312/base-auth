import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { DataSource } from 'typeorm';
import { type IdentityId } from '@base-authorization/core';
import {
  provisionProductDatabase,
  productDataSourceOptions,
  ProductTransactionRunner,
  ProductManifestReconciler,
  prepareProductRelease,
  bootstrapProductRoot,
  systemGrantHash,
  createProductPasswordHasher,
  ProductIdentityService,
  type ProductDatabasePurpose,
} from '@base-authorization/typeorm-postgres';
import { startPostgres, type TestPostgres } from './setup-postgres.ts';
import { productDeclarations } from '../apps/api/dist/product-manifest.js';
let pg: TestPostgres;
let runner: ProductTransactionRunner;
let migration: DataSource;
const pools: DataSource[] = [];
const actor = randomUUID() as IdentityId;
const base = {
  sequence: '1',
  predecessor: '0',
  declarations: productDeclarations,
  roles: [],
  defaultGrants: [],
  seeds: [],
  removeSeeds: [],
  boundaryBindings: [],
  removeBoundaryBindings: [],
  systemGrants: [],
  removeSystemGrants: [],
};
const grant = {
  owner: 'product',
  key: 'root-suspend',
  role: 'system.root',
  permission: 'account.suspend',
  template: { key: 'allAccounts', version: 1 },
  parameters: {},
};
const release2 = () =>
  prepareProductRelease({
    ...base,
    sequence: '2',
    predecessor: '1',
    roles: [{ key: 'system.root', authorityLevel: 1000, label: 'Root' }],
    systemGrants: [grant],
  });
const reconciler = () =>
  new ProductManifestReconciler(runner, {
    actor,
    capabilities: { validators: ['fresh@1'], obligationHandlers: ['audit@1'] },
  });
before(async () => {
  pg = await startPostgres();
  const passwords = Object.fromEntries(
    ['data', 'identity', 'authority', 'sync', 'migration', 'bootstrap'].map((p) => [
      p,
      randomBytes(24).toString('hex'),
    ]),
  ) as Record<ProductDatabasePurpose, string>;
  const settings = await provisionProductDatabase(pg.superuser, passwords);
  const sources = {} as Record<
    'data' | 'identity' | 'authority' | 'sync' | 'bootstrap',
    DataSource
  >;
  for (const p of ['data', 'identity', 'authority', 'sync', 'bootstrap'] as const) {
    const ds = await new DataSource(productDataSourceOptions(settings[p])).initialize();
    sources[p] = ds;
    pools.push(ds);
  }
  runner = new ProductTransactionRunner(sources);
  migration = await new DataSource(productDataSourceOptions(settings.migration)).initialize();
});
after(async () => {
  await migration?.destroy();
  await Promise.all(pools.map((p) => p.destroy()));
  await pg?.stop();
});
test('catalog first then late Root grants old permissions; repeated and concurrent boot do not change revision', async () => {
  const first = prepareProductRelease(base);
  assert.equal((await reconciler().reconcile(first)).changed, true);
  const second = release2();
  assert.equal((await reconciler().reconcile(second)).changed, true);
  const results = await Promise.all([
    reconciler().reconcile(second),
    reconciler().reconcile(second),
  ]);
  assert.ok(results.every((r) => !r.changed));
  assert.equal(results[0]?.revision, results[1]?.revision);
  const rows = await migration.query<{ n: number }[]>(
    `SELECT count(*)::int n FROM policy_rule WHERE system_owner=$1`,
    [Buffer.from('product')],
  );
  assert.equal(rows[0]?.n, 1);
});
test('same release full drift fails; rollback avoids runtime seed takeover', async () => {
  const second = release2();
  await migration.query('ALTER TABLE role_definition DISABLE TRIGGER protect_product_rows');
  await migration.query(`UPDATE role_definition SET label='drift'`);
  await assert.rejects(reconciler().reconcile(second), /drift|not_ready/);
  await migration.query(`UPDATE role_definition SET label='Root'`);
  await migration.query('ALTER TABLE role_definition ENABLE TRIGGER protect_product_rows');
  assert.equal((await reconciler().reconcile(second)).changed, false);
  const id = randomUUID();
  await runner.run('admin', (tx) =>
    tx.manager.query(
      `INSERT INTO role_definition(role_key,managed_by,authority_level,label) VALUES($1,'runtime',1,'Runtime')`,
      [Buffer.from('runtime')],
    ),
  );
  const collision = prepareProductRelease({
    ...base,
    sequence: '3',
    predecessor: '2',
    roles: [{ key: 'runtime', authorityLevel: 1000, label: 'Root' }],
  });
  await assert.rejects(reconciler().reconcile(collision), /collision/);
  void id;
});
test('persistent bootstrap races once, mandatory boundary, no boot reseed after assignment revoke', async () => {
  const target = randomUUID() as IdentityId;
  await migration.query(
    `INSERT INTO app_user(id,email_canonical,state) VALUES($1,'root@example.test','pending')`,
    [target],
  );
  const input = {
    operationId: randomUUID(),
    userId: target,
    method: 'local' as const,
    boundaries: [{ permission: 'account.suspend', boundary: { key: 'rootAccounts', version: 1 } }],
  };
  await assert.rejects(
    bootstrapProductRoot(runner, release2(), { ...input, boundaries: [] }),
    /boundary/,
  );
  const outcomes = await Promise.all([
    bootstrapProductRoot(runner, release2(), input),
    bootstrapProductRoot(runner, release2(), { ...input, operationId: randomUUID() }).catch(
      (e: unknown) => (e instanceof Error ? e : new Error('Bootstrap failed')),
    ),
  ]);
  assert.equal(outcomes.filter((o) => !(o instanceof Error) && o.initialized).length, 1);
  const success = outcomes.find((o) => !(o instanceof Error) && o.initialized);
  assert.ok(success && !(success instanceof Error) && success.activationSecret);
  const identity = new ProductIdentityService(runner, await createProductPasswordHasher(new Set()));
  await identity.activate(
    success.activationSecret,
    'this is a long unique root password',
    'fixture',
  );
  const session = await identity.login(
    'root@example.test',
    'this is a long unique root password',
    'fixture',
  );
  assert.ok(session.secret);
  // Offline fixture revokes assignment; marker persists and boot does not assign it again.
  await migration.query('ALTER TABLE user_role DISABLE TRIGGER protect_product_rows');
  await migration.query('DELETE FROM user_role WHERE user_id=$1', [target]);
  await migration.query('ALTER TABLE user_role ENABLE TRIGGER protect_product_rows');
  await reconciler().reconcile(release2());
  assert.equal(
    (
      await migration.query<{ n: number }[]>(
        'SELECT count(*)::int n FROM user_role WHERE user_id=$1',
        [target],
      )
    )[0]?.n,
    0,
  );
  await assert.rejects(
    bootstrapProductRoot(runner, release2(), { ...input, operationId: randomUUID() }),
    /already initialized/,
  );
});
test('system grant explicit content change/removal requires prior exact hash', async () => {
  const changedGrant = { ...grant, template: { key: 'limitedAccounts', version: 1 } };
  const declarations = {
    ...productDeclarations,
    resources: productDeclarations.resources.map((r) =>
      r.key === 'document'
        ? {
            ...r,
            actions: {
              ...r.actions,
              archive: { policy: { key: 'readable', version: 1 }, boundary: 'optional' as const },
            },
          }
        : r,
    ),
    templates: [
      ...productDeclarations.templates,
      {
        key: 'limitedAccounts',
        version: 1,
        resource: 'account',
        parameters: {},
        expression: {
          op: 'lte' as const,
          field: 'authorityLevel',
          value: { from: 'literal' as const, value: '500' },
        },
      },
    ],
  };
  const thirdSource = {
    ...base,
    declarations,
    sequence: '3',
    predecessor: '2',
    roles: [{ key: 'system.root', authorityLevel: 1000, label: 'Root' }],
    systemGrants: [changedGrant],
    removeSystemGrants: [],
  };
  await assert.rejects(reconciler().reconcile(prepareProductRelease(thirdSource)), /previousHash/);
  const third = prepareProductRelease({
    ...thirdSource,
    systemGrants: [{ ...changedGrant, previousHash: systemGrantHash(grant) }],
  });
  await reconciler().reconcile(third);
  assert.equal(
    (
      await migration.query<{ n: number }[]>(
        'SELECT count(*)::int n FROM policy_rule WHERE permission_key=$1',
        [Buffer.from('document.archive')],
      )
    )[0]?.n,
    0,
  );

  const fourth = prepareProductRelease({
    ...base,
    sequence: '4',
    predecessor: '3',
    roles: [{ key: 'system.root', authorityLevel: 1000, label: 'Root' }],
    removeSystemGrants: [
      { owner: grant.owner, key: grant.key, expectedHash: systemGrantHash(changedGrant) },
    ],
  });
  await reconciler().reconcile(fourth);
  assert.equal(
    (await migration.query<{ n: number }[]>('SELECT count(*)::int n FROM policy_rule'))[0]?.n,
    0,
  );
  assert.equal((await reconciler().reconcile(fourth)).changed, false);
});
