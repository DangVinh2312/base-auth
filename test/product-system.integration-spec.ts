import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { DataSource } from 'typeorm';
import { type IdentityId } from '@base-authorization/core';
import { type ProductDatabasePurpose } from '@base-authorization/typeorm-postgres';
import {
  ProductTransactionRunner,
  ProductManifestReconciler,
  prepareProductRelease,
  systemGrantHash,
  createProductPasswordHasher,
  ProductIdentityService,
  PRODUCT_OFFLINE_ACTOR,
} from '@base-authorization/typeorm-postgres/composition';
import {
  provisionProductDatabase,
  productDataSourceOptions,
  bootstrapProductRoot,
  reissueRootActivation,
  revokeProductRoot,
} from '@base-authorization/typeorm-postgres/operations';
import { startPostgres, type TestPostgres } from './setup-postgres.ts';
import { productDeclarations } from '../apps/api/dist/authorization/product-manifest.js';
import { core } from '../packages/core/test/fixtures.ts';
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
  prepareProductRelease(
    {
      ...base,
      sequence: '2',
      predecessor: '1',
      roles: [{ key: 'system.root', authorityLevel: 1000, label: 'Root' }],
      systemGrants: [grant],
    },
    core,
  );
const reconciler = () =>
  new ProductManifestReconciler(runner, {
    core,
    actor,
    capabilities: { validators: ['fresh@1'], obligationHandlers: ['audit@1'] },
  });
before(async () => {
  pg = await startPostgres();
  const passwords = Object.fromEntries(
    ['data', 'identity', 'authority', 'sync', 'migration', 'bootstrap', 'outbox'].map((p) => [
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
  const first = prepareProductRelease(base, core);
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
      "INSERT INTO role_definition(role_key,managed_by,label) VALUES($1,'runtime','Runtime')",
      [Buffer.from('runtime')],
    ),
  );
  const collision = prepareProductRelease(
    {
      ...base,
      sequence: '3',
      predecessor: '2',
      roles: [{ key: 'runtime', authorityLevel: 1000, label: 'Root' }],
    },
    core,
  );
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
  };
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
  // The offline command revokes the assignment; marker persists and boot does not assign it again.
  const revocation = {
    operationId: randomUUID(),
    userId: target,
    approval: 'CHG-fixture',
    reason: 'Fixture revocation',
  };
  await assert.rejects(revokeProductRoot(runner, { ...revocation, reason: ' ' }, core), /invalid/);
  const revisionNow = async () =>
    (await migration.query<{ r: string }[]>('SELECT revision::text r FROM authz_state'))[0]!.r;
  const beforeRevoke = await revisionNow();
  assert.deepEqual(await revokeProductRoot(runner, revocation, core), { revoked: true });
  const afterRevoke = await revisionNow();
  assert.equal(BigInt(afterRevoke), BigInt(beforeRevoke) + 1n);
  // Offline Root events: the operator sentinel is the actor, the Root account is the target.
  const rootEvents = await migration.query<
    { kind: string; actor: string; revision: string; metadata: Record<string, string> }[]
  >(
    `SELECT convert_from(event_kind,'UTF8') kind,actor_id::text actor,policy_revision::text revision,safe_metadata metadata FROM audit_outbox WHERE event_kind IN ($1,$2) ORDER BY event_kind`,
    [Buffer.from('root.bootstrap'), Buffer.from('root.revoke')],
  );
  assert.deepEqual(
    rootEvents.map((e) => [e.kind, e.actor, e.metadata.targetUserId]),
    [
      ['root.bootstrap', PRODUCT_OFFLINE_ACTOR, target],
      ['root.revoke', PRODUCT_OFFLINE_ACTOR, target],
    ],
  );
  assert.notEqual(PRODUCT_OFFLINE_ACTOR, target);
  for (const e of rootEvents)
    assert.equal(BigInt(e.metadata.resultingRevision!), BigInt(e.revision) + 1n);
  assert.deepEqual(
    [rootEvents[1]!.revision, rootEvents[1]!.metadata.resultingRevision],
    [beforeRevoke, afterRevoke],
  );
  assert.deepEqual(await revokeProductRoot(runner, revocation, core), { revoked: false });
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
  assert.deepEqual(await migration.query('SELECT kind,state FROM app_user WHERE id=$1', [target]), [
    { kind: 'root', state: 'suspended' },
  ]);
  await assert.rejects(
    bootstrapProductRoot(runner, release2(), { ...input, operationId: randomUUID() }),
    /already initialized/,
  );
});
const denied = (e: { driverError?: { code?: string } }) => e.driverError?.code === '42501';
test('bootstrap credential cannot promote another Root once the marker is initialized', async () => {
  const marker = await migration.query<{ initialized: boolean }[]>(
    'SELECT initialized_at IS NOT NULL AS initialized FROM security_bootstrap_state',
  );
  assert.equal(marker[0]?.initialized, true);
  const second = randomUUID();
  await migration.query(
    `INSERT INTO app_user(id,email_canonical,state) VALUES($1,'second@example.test','pending')`,
    [second],
  );
  // The previous test suspended Root; the permanent marker alone refuses another promotion.
  await assert.rejects(
    runner.run('bootstrap', (tx) =>
      tx.manager.query(`UPDATE app_user SET kind='root' WHERE id=$1`, [second]),
    ),
    denied,
  );
  // Nor can it fall back to a role assignment: the bootstrap login has no INSERT on user_role.
  await assert.rejects(
    runner.run('bootstrap', (tx) =>
      tx.manager.query('INSERT INTO user_role(user_id,role_key) VALUES($1,$2)', [
        second,
        Buffer.from('system.root'),
      ]),
    ),
    denied,
  );
  assert.deepEqual(await migration.query('SELECT kind FROM app_user WHERE id=$1', [second]), [
    { kind: 'iam' },
  ]);
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
          op: 'eq' as const,
          field: 'state',
          value: { from: 'literal' as const, value: 'active' },
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
  await assert.rejects(
    reconciler().reconcile(prepareProductRelease(thirdSource, core)),
    /previousHash/,
  );
  const third = prepareProductRelease(
    {
      ...thirdSource,
      systemGrants: [{ ...changedGrant, previousHash: systemGrantHash(grant) }],
    },
    core,
  );
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

  const fourth = prepareProductRelease(
    {
      ...base,
      sequence: '4',
      predecessor: '3',
      roles: [{ key: 'system.root', authorityLevel: 1000, label: 'Root' }],
      removeSystemGrants: [
        { owner: grant.owner, key: grant.key, expectedHash: systemGrantHash(changedGrant) },
      ],
    },
    core,
  );
  await reconciler().reconcile(fourth);
  assert.equal(
    (await migration.query<{ n: number }[]>('SELECT count(*)::int n FROM policy_rule'))[0]?.n,
    0,
  );
  assert.equal((await reconciler().reconcile(fourth)).changed, false);
});

test('code-owned roles are runtime assignments; their grants leave only by explicit release removal', async () => {
  const reviewGrant = {
    permission: 'document.review',
    role: 'reviewer',
    template: { key: 'ownedDocuments', version: 1 },
    parameters: {},
  };
  const declarations = {
    ...productDeclarations,
    resources: productDeclarations.resources.map((r) =>
      r.key === 'document'
        ? {
            ...r,
            actions: {
              ...r.actions,
              review: { policy: { key: 'readable', version: 1 }, boundary: 'optional' as const },
            },
          }
        : r,
    ),
  };
  const roles = [
    { key: 'system.root', authorityLevel: 1000, label: 'Root' },
    { key: 'reviewer', authorityLevel: 10, label: 'Reviewer' },
  ];
  const fifth = { ...base, declarations, sequence: '5', predecessor: '4', roles };
  assert.equal(
    prepareProductRelease({ ...fifth, removeDefaultGrants: [] }, core).hash,
    prepareProductRelease(fifth, core).hash,
    'an empty removal list keeps the published hash',
  );
  await reconciler().reconcile(
    prepareProductRelease({ ...fifth, defaultGrants: [reviewGrant] }, core),
  );
  const seeded = async () =>
    (
      await migration.query<{ n: number }[]>(
        'SELECT count(*)::int n FROM policy_rule WHERE permission_key=$1',
        [Buffer.from('document.review')],
      )
    )[0]?.n;
  assert.equal(await seeded(), 1);
  const user = randomUUID();
  await migration.query(`INSERT INTO app_user(id,state) VALUES($1,'active')`, [user]);
  const admin = (sql: string, params: unknown[]) =>
    runner.run('admin', (tx) => tx.manager.query(sql, params));
  // Assigning and unassigning a code-owned, non-system role is an ordinary authority fact.
  await admin('INSERT INTO user_role(user_id,role_key) VALUES($1,$2)', [
    user,
    Buffer.from('reviewer'),
  ]);
  await admin('DELETE FROM user_role WHERE user_id=$1', [user]);
  // Code-role grants and seeded defaults stay out of runtime reach.
  await assert.rejects(
    admin(
      `INSERT INTO policy_rule(rule_id,permission_key,role_key,effect,template_key,template_version,parameters,managed_by) VALUES($1,$2,$3,'allow',$4,1,'{}','runtime')`,
      [
        randomUUID(),
        Buffer.from('document.read'),
        Buffer.from('reviewer'),
        Buffer.from('ownedDocuments'),
      ],
    ),
    denied,
  );
  await assert.rejects(
    admin('DELETE FROM policy_rule WHERE permission_key=$1', [Buffer.from('document.review')]),
    denied,
  );
  const sixth = prepareProductRelease(
    {
      ...fifth,
      sequence: '6',
      predecessor: '5',
      removeDefaultGrants: [reviewGrant],
    },
    core,
  );
  await reconciler().reconcile(sixth);
  assert.equal(await seeded(), 0);
  assert.equal((await reconciler().reconcile(sixth)).changed, false);
  await assert.rejects(
    reconciler().reconcile(
      prepareProductRelease(
        {
          ...fifth,
          sequence: '7',
          predecessor: '6',
          removeDefaultGrants: [reviewGrant],
        },
        core,
      ),
    ),
    /missing/,
  );
});
test('Root bootstrap and reissue refuse the offline actor id as target user', async () => {
  await assert.rejects(
    bootstrapProductRoot(runner, release2(), {
      operationId: randomUUID(),
      userId: PRODUCT_OFFLINE_ACTOR,
      method: 'local',
    }),
    /offline actor/,
  );
  await assert.rejects(
    reissueRootActivation(runner, { userId: PRODUCT_OFFLINE_ACTOR, method: 'local' }, core),
    /offline actor/,
  );
});
