import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { DataSource } from 'typeorm';
import type { IdentityId } from '@base-authorization/core';
import type { ProductDatabasePurpose } from '@base-authorization/typeorm-postgres';
import {
  ProductIdentityService,
  ProductManifestReconciler,
  ProductTransactionRunner,
  createProductPasswordHasher,
  verifyProductPrivileges,
} from '@base-authorization/typeorm-postgres/composition';
import {
  bootstrapProductRoot,
  productDataSourceOptions,
  productMigrations,
  provisionProductDatabase,
} from '@base-authorization/typeorm-postgres/operations';
import { ProductIamRoot1792108800012 } from '../packages/typeorm-postgres/dist/migrations/product/012-iam-root.js';
import {
  createProductAuthorizationCore,
  createProductRelease,
} from '../apps/api/dist/authorization/product-manifest.js';
import * as one from './fixtures/release-one/product-manifest.ts';
import { prepareReleaseOne, releaseOneSource } from './fixtures/release-one/release.ts';
import { startPostgres, withClient, type TestPostgres } from './setup-postgres.ts';

const core = createProductAuthorizationCore();
const releaseTwo = createProductRelease(core);
const utf8 = (value: string) => Buffer.from(value);
const password = 'a long unique upgrade fixture password';
const capabilities = { validators: ['fresh@1'], obligationHandlers: ['audit@1'] };
const rootBoundary = [
  { permission: 'account.suspend', boundary: { key: 'rootAccounts', version: 1 } },
];
const userRoleGuards = ['protect_product_rows', 'require_root_marker', 'protect_system_activation'];
const passwords = Object.fromEntries(
  ['data', 'identity', 'authority', 'sync', 'migration', 'bootstrap', 'outbox'].map((p) => [
    p,
    randomBytes(24).toString('hex'),
  ]),
) as Record<ProductDatabasePurpose, string>;
let fixture: TestPostgres;
before(async () => {
  fixture = await startPostgres();
});
after(async () => {
  await fixture?.stop();
});

type Pools = Record<'data' | 'identity' | 'authority' | 'sync' | 'bootstrap', DataSource>;
interface ReleaseOne {
  readonly pools: Pools;
  readonly migration: DataSource;
  readonly runner: ProductTransactionRunner;
  readonly release: one.ProductReleaseManifest;
  /** Real provisioning with every migration: 012 runs as product_migration (spec 4.1). */
  readonly upgrade: () => Promise<unknown>;
  readonly close: () => Promise<void>;
}
/** A database migrated to 011 by real provisioning and synced with release 1 by 50d6053 code. */
async function releaseOneDatabase(name: string, source = releaseOneSource): Promise<ReleaseOne> {
  await withClient(fixture.superuser, (c) => c.query(`CREATE DATABASE ${name}`));
  const admin = { ...fixture.superuser, database: name };
  const settings = await provisionProductDatabase(admin, passwords, productMigrations.slice(0, 11));
  const pools = {} as Pools;
  for (const p of ['data', 'identity', 'authority', 'sync', 'bootstrap'] as const)
    pools[p] = await new DataSource(productDataSourceOptions(settings[p])).initialize();
  const migration = await new DataSource(productDataSourceOptions(settings.migration)).initialize();
  const runner = new ProductTransactionRunner(pools);
  const release = one.prepareProductRelease(source, core);
  await new one.ProductManifestReconciler(runner, {
    core,
    actor: randomUUID() as IdentityId,
    capabilities,
  }).reconcile(release);
  return {
    pools,
    migration,
    runner,
    release,
    upgrade: () => provisionProductDatabase(admin, passwords),
    close: async () => {
      for (const pool of Object.values(pools)) await pool.destroy();
      await migration.destroy();
    },
  };
}
const pending = async (db: ReleaseOne, email: string): Promise<IdentityId> => {
  const id = randomUUID() as IdentityId;
  await db.migration.query(
    `INSERT INTO app_user(id,email_canonical,state) VALUES($1,$2,'pending')`,
    [id, email],
  );
  return id;
};
/** Table-owner tampering for states no command can reach (guards off for one statement). */
async function asOwner(db: ReleaseOne, sql: string, params: unknown[]): Promise<void> {
  await db.migration.transaction(async (m) => {
    for (const t of userRoleGuards) await m.query(`ALTER TABLE user_role DISABLE TRIGGER ${t}`);
    await m.query(sql, params);
    for (const t of userRoleGuards) await m.query(`ALTER TABLE user_role ENABLE TRIGGER ${t}`);
  });
}
/** 012 refused: everything rolled back, the database is still at release 1 without `kind`. */
async function refusedUpgrade(db: ReleaseOne, message: RegExp, label = String(message)) {
  await assert.rejects(db.upgrade(), message, label);
  assert.deepEqual(
    await db.migration.query(
      `SELECT (SELECT count(*)::int FROM information_schema.columns WHERE table_schema='public' AND table_name='app_user' AND column_name='kind') kind,
        (SELECT count(*)::int FROM migrations WHERE name='ProductIamRoot1792108800012') applied,
        (SELECT release_sequence::text FROM authz_state) sequence`,
    ),
    [{ kind: 0, applied: 0, sequence: '1' }],
    label,
  );
}
const syncReleaseTwo = (db: ReleaseOne) =>
  new ProductManifestReconciler(db.runner, {
    core,
    actor: randomUUID() as IdentityId,
    capabilities,
  }).reconcile(releaseTwo);

test('the frozen release 1 is byte-identical to the published one; 012 cannot be reverted', async () => {
  assert.equal(
    prepareReleaseOne(core).hash,
    'c1fbb3451d9292477ae24ed1d342f581612b68d9519ffccce6f08a9a3c874fa9',
  );
  await assert.rejects(
    new ProductIamRoot1792108800012().down(),
    /irreversible; restore from backup/,
  );
});

test('unmarked release 1: drift and a stray holder roll back; then 012 upgrades and release 2 syncs', async () => {
  const db = await releaseOneDatabase('upgrade_unmarked');
  try {
    // Binary of release 2 on the 011 schema: the startup probe refuses it.
    await assert.rejects(verifyProductPrivileges(db.pools), /privilege drift|protection drift/);
    const relabel = (label: string) =>
      db.migration.transaction(async (m) => {
        await m.query('ALTER TABLE role_definition DISABLE TRIGGER protect_product_rows');
        await m.query('UPDATE role_definition SET label=$1 WHERE role_key=$2', [
          label,
          utf8('reviewer'),
        ]);
        await m.query('ALTER TABLE role_definition ENABLE TRIGGER protect_product_rows');
      });
    await relabel('drift');
    await refusedUpgrade(db, /code-owned facts drifted; repair before migration/);
    await relabel('Reviewer');
    const stray = await pending(db, 'stray@example.test');
    await asOwner(db, 'INSERT INTO user_role(user_id,role_key) VALUES($1,$2)', [
      stray,
      utf8('system.root'),
    ]);
    await refusedUpgrade(db, /does not match the bootstrap marker/);
    await asOwner(db, 'DELETE FROM user_role WHERE user_id=$1', [stray]);
    await db.upgrade();
    assert.deepEqual(
      await db.migration.query(
        `SELECT to_regprocedure('public.require_root_marker()')::text marker,to_regprocedure('public.protect_system_activation()')::text activation,
          (SELECT count(*)::int FROM role_definition WHERE role_key=$1) roles,
          (SELECT count(*)::int FROM permission_boundary WHERE boundary_key=$2) boundaries,
          (SELECT release_sequence::text FROM authz_state) sequence`,
        [utf8('system.root'), utf8('rootAccounts')],
      ),
      [{ marker: null, activation: null, roles: 0, boundaries: 1, sequence: '1' }],
    );
    await verifyProductPrivileges(db.pools);
    assert.equal((await syncReleaseTwo(db)).changed, true);
    const next = await pending(db, 'first-root@example.test');
    assert.ok(
      (
        await bootstrapProductRoot(db.runner, releaseTwo, {
          operationId: randomUUID(),
          userId: next,
          method: 'local',
        })
      ).initialized,
    );
    assert.deepEqual(await db.migration.query('SELECT kind FROM app_user WHERE id=$1', [next]), [
      { kind: 'root' },
    ]);
  } finally {
    await db.close();
  }
});

test('a Root holder keeps state and credential and loses every IAM fact; other holder shapes fail', async () => {
  const db = await releaseOneDatabase('upgrade_holder');
  try {
    const target = await pending(db, 'holder@example.test');
    const bootstrap = await one.bootstrapProductRoot(db.runner, db.release, {
      operationId: randomUUID(),
      userId: target,
      method: 'local',
      boundaries: rootBoundary,
    });
    assert.ok(bootstrap.activationSecret);
    const identity = new ProductIdentityService(
      db.runner,
      await createProductPasswordHasher(new Set()),
    );
    await identity.activate(bootstrap.activationSecret, password, 'holder');
    const document = randomUUID();
    await db.runner.run('admin', async (tx) => {
      await tx.manager.query(
        "INSERT INTO object_ref(object_id,type_key,key_kind,key_bytes) VALUES($1,$2,'uuid',$3)",
        [document, utf8('document'), utf8(document)],
      );
      await tx.manager.query(
        "INSERT INTO policy_rule(rule_id,permission_key,user_id,effect,template_key,template_version,parameters,managed_by) VALUES($1,$2,$3,'allow',$4,1,'{}','runtime')",
        [randomUUID(), utf8('document.read'), target, utf8('ownedDocuments')],
      );
      await tx.manager.query(
        "INSERT INTO record_exception(exception_id,object_id,type_key,permission_key,user_id,effect,purpose,starts_at,reason,issued_by) VALUES($1,$2,$3,$4,$5,'allow','manual',statement_timestamp(),'fixture',$5)",
        [randomUUID(), document, utf8('document'), utf8('document.read'), target],
      );
      await tx.manager.query('INSERT INTO user_role(user_id,role_key) VALUES($1,$2)', [
        target,
        utf8('reviewer'),
      ]);
    });
    const other = await pending(db, 'other@example.test');
    const holder = (sql: string, user: string) => asOwner(db, sql, [user, utf8('system.root')]);
    await holder('INSERT INTO user_role(user_id,role_key) VALUES($1,$2)', other);
    await refusedUpgrade(db, /more than one Root holder/);
    await holder('DELETE FROM user_role WHERE user_id=$1 AND role_key=$2', target);
    await refusedUpgrade(db, /does not match the bootstrap marker/);
    await holder('DELETE FROM user_role WHERE user_id=$1 AND role_key=$2', other);
    await holder('INSERT INTO user_role(user_id,role_key) VALUES($1,$2)', target);
    await db.upgrade();
    assert.deepEqual(
      await db.migration.query(
        `SELECT kind,state,(SELECT count(*)::int FROM user_role WHERE user_id=$1)+(SELECT count(*)::int FROM user_boundary WHERE user_id=$1)
          +(SELECT count(*)::int FROM policy_rule WHERE user_id=$1)+(SELECT count(*)::int FROM record_exception WHERE user_id=$1) facts
         FROM app_user WHERE id=$1`,
        [target],
      ),
      [{ kind: 'root', state: 'active', facts: 0 }],
    );
    assert.ok((await identity.login('holder@example.test', password, 'holder')).secret);
    await verifyProductPrivileges(db.pools);
    assert.equal((await syncReleaseTwo(db)).changed, true);
    await assert.rejects(
      bootstrapProductRoot(db.runner, releaseTwo, {
        operationId: randomUUID(),
        userId: await pending(db, 'late@example.test'),
        method: 'local',
      }),
      /already initialized/,
    );
  } finally {
    await db.close();
  }
});

test('a revoked Root (real bootstrap → revoke-root) stays IAM; any allow source keeps its binding live', async () => {
  const db = await releaseOneDatabase('upgrade_revoked');
  try {
    const former = await pending(db, 'former@example.test');
    await one.bootstrapProductRoot(db.runner, db.release, {
      operationId: randomUUID(),
      userId: former,
      method: 'local',
      boundaries: rootBoundary,
    });
    assert.deepEqual(
      await one.revokeProductRoot(
        db.runner,
        { operationId: randomUUID(), userId: former, approval: 'CHG-upgrade', reason: 'Fixture' },
        core,
      ),
      { revoked: true },
    );
    const account = randomUUID();
    await db.runner.run('admin', async (tx) => {
      await tx.manager.query(
        "INSERT INTO role_definition(role_key,managed_by,authority_level,label) VALUES($1,'runtime',1,'Operator')",
        [utf8('operator')],
      );
      await tx.manager.query(
        "INSERT INTO object_ref(object_id,type_key,key_kind,key_bytes) VALUES($1,$2,'uuid',$3)",
        [account, utf8('account'), utf8(former)],
      );
    });
    type Fact = readonly [string, readonly unknown[]];
    const rule = (subject: 'user_id' | 'role_key', effect: 'allow' | 'deny'): Fact => [
      `INSERT INTO policy_rule(rule_id,permission_key,${subject},effect,template_key,template_version,parameters,managed_by) VALUES($1,$2,$3,'${effect}',$4,1,'{}','runtime')`,
      [
        randomUUID(),
        utf8('account.suspend'),
        subject === 'user_id' ? former : utf8('operator'),
        utf8('allAccounts'),
      ],
    ];
    const exception = (subject: 'user_id' | 'role_key'): Fact => [
      `INSERT INTO record_exception(exception_id,object_id,type_key,permission_key,${subject},effect,purpose,starts_at,reason,issued_by) VALUES($1,$2,$3,$4,$5,'allow','manual',statement_timestamp(),'fixture',$6)`,
      [
        randomUUID(),
        account,
        utf8('account'),
        utf8('account.suspend'),
        subject === 'user_id' ? former : utf8('operator'),
        former,
      ],
    ];
    const assigned: Fact = [
      'INSERT INTO user_role(user_id,role_key) VALUES($1,$2)',
      [former, utf8('operator')],
    ];
    const write = (facts: readonly Fact[]) =>
      db.runner.run('admin', async (tx) => {
        for (const [sql, params] of facts) await tx.manager.query(sql, [...params]);
      });
    const clear = () =>
      db.runner.run('admin', async (tx) => {
        await tx.manager.query('DELETE FROM record_exception WHERE permission_key=$1', [
          utf8('account.suspend'),
        ]);
        await tx.manager.query(
          "DELETE FROM policy_rule WHERE permission_key=$1 AND managed_by='runtime'",
          [utf8('account.suspend')],
        );
        await tx.manager.query('DELETE FROM user_role WHERE user_id=$1', [former]);
      });
    for (const [label, facts] of [
      ['direct allow rule', [rule('user_id', 'allow')]],
      ['allow rule through a role', [assigned, rule('role_key', 'allow')]],
      ['direct allow exception', [exception('user_id')]],
      ['allow exception through a role', [assigned, exception('role_key')]],
      ['allow and deny together', [rule('user_id', 'allow'), rule('user_id', 'deny')]],
    ] as const) {
      await write(facts);
      await refusedUpgrade(db, /former Root boundary binding is not inert/, label);
      await clear();
    }
    // Only a deny remains: the binding is inert, 012 removes it and keeps the deny.
    await write([rule('user_id', 'deny')]);
    await db.upgrade();
    assert.deepEqual(
      await db.migration.query(
        `SELECT kind,(SELECT count(*)::int FROM user_boundary WHERE user_id=$1) bindings,(SELECT count(*)::int FROM policy_rule WHERE user_id=$1 AND effect='deny') denies FROM app_user WHERE id=$1`,
        [former],
      ),
      [{ kind: 'iam', bindings: 0, denies: 1 }],
    );
    assert.equal((await syncReleaseTwo(db)).changed, true);
    await assert.rejects(
      bootstrapProductRoot(db.runner, releaseTwo, {
        operationId: randomUUID(),
        userId: await pending(db, 'next@example.test'),
        method: 'local',
      }),
      /already initialized/,
    );
  } finally {
    await db.close();
  }
});

test('a revoked Root without facts converts; an IAM user still bound to rootAccounts@1 blocks release 2', async () => {
  const db = await releaseOneDatabase('upgrade_bound_member');
  try {
    const former = await pending(db, 'former2@example.test');
    await one.bootstrapProductRoot(db.runner, db.release, {
      operationId: randomUUID(),
      userId: former,
      method: 'local',
      boundaries: rootBoundary,
    });
    await one.revokeProductRoot(
      db.runner,
      { operationId: randomUUID(), userId: former, approval: 'CHG-upgrade', reason: 'Fixture' },
      core,
    );
    const member = randomUUID();
    await db.migration.query(`INSERT INTO app_user(id,state) VALUES($1,'active')`, [member]);
    await db.runner.run('admin', (tx) =>
      tx.manager.query(
        'INSERT INTO user_boundary(user_id,permission_key,boundary_key,boundary_version) VALUES($1,$2,$3,1)',
        [member, utf8('account.suspend'), utf8('rootAccounts')],
      ),
    );
    await db.upgrade();
    assert.deepEqual(
      await db.migration.query('SELECT count(*)::int n FROM user_boundary WHERE user_id=$1', [
        former,
      ]),
      [{ n: 0 }],
    );
    await assert.rejects(syncReleaseTwo(db), /definition_in_use/);
  } finally {
    await db.close();
  }
});

test('an unknown system.* role is surfaced, never converted silently', async () => {
  const db = await releaseOneDatabase('upgrade_system_role', {
    ...releaseOneSource,
    roles: [...releaseOneSource.roles, { key: 'system.audit', label: 'Audit', authorityLevel: 1 }],
  });
  try {
    await refusedUpgrade(db, /unknown system\.\* role/);
  } finally {
    await db.close();
  }
});

test('a fresh database migrates to 012 and takes release 2 through genesis', async () => {
  await withClient(fixture.superuser, (c) => c.query('CREATE DATABASE upgrade_fresh'));
  const settings = await provisionProductDatabase(
    { ...fixture.superuser, database: 'upgrade_fresh' },
    passwords,
  );
  const sync = await new DataSource(productDataSourceOptions(settings.sync)).initialize();
  try {
    const result = await new ProductManifestReconciler(new ProductTransactionRunner({ sync }), {
      core,
      actor: randomUUID() as IdentityId,
      capabilities,
    }).reconcile(releaseTwo);
    assert.equal(result.changed, true);
  } finally {
    await sync.destroy();
  }
});
