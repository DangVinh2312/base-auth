import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { DataSource, QueryFailedError } from 'typeorm';
import {
  productDataSourceOptions,
  provisionProductDatabase,
  verifyProductPrivileges,
} from '../packages/typeorm-postgres/dist/product-database.js';
import { ProductInitial1792108800000 } from '../packages/typeorm-postgres/dist/migrations/product/001-initial.js';
import { productRowsBody } from '../packages/typeorm-postgres/dist/migrations/product/004-protection-guards.js';
import { requireRootMarkerBody } from '../packages/typeorm-postgres/dist/migrations/product/007-root-marker.js';
import { ProductTransactionRunner } from '../packages/typeorm-postgres/dist/product-transaction.js';
import { startPostgres, withClient, sqlState, type TestPostgres } from './setup-postgres.ts';

let fixture: TestPostgres;
let pools: Record<'data' | 'identity' | 'authority' | 'sync' | 'bootstrap', DataSource>;
let fixturePasswords: Record<
  'data' | 'identity' | 'authority' | 'sync' | 'migration' | 'bootstrap',
  string
>;
let connections: Awaited<ReturnType<typeof provisionProductDatabase>>;
before(async () => {
  fixture = await startPostgres();
  const passwords = Object.fromEntries(
    ['data', 'identity', 'authority', 'sync', 'migration', 'bootstrap'].map((p) => [
      p,
      randomBytes(20).toString('hex'),
    ]),
  ) as Record<'data' | 'identity' | 'authority' | 'sync' | 'migration' | 'bootstrap', string>;
  fixturePasswords = passwords;
  connections = await provisionProductDatabase(fixture.superuser, passwords);
  pools = {} as typeof pools;
  for (const purpose of ['data', 'identity', 'authority', 'sync', 'bootstrap'] as const)
    pools[purpose] = await new DataSource(
      productDataSourceOptions(connections[purpose]),
    ).initialize();
});
after(async () => {
  for (const source of Object.values(pools ?? {})) await source.destroy();
  await fixture?.stop();
});
test('real runtime logins cannot read credentials, escalate roles, alter schema or grant identity authority', async () => {
  for (const purpose of ['data', 'identity', 'authority', 'sync'] as const) {
    await withClient(connections[purpose], async (c) => {
      assert.equal(
        (await c.query<{ current_user: string }>('SELECT current_user')).rows[0]!.current_user,
        `product_${purpose}`,
      );
      assert.equal(await sqlState(c.query('SET ROLE product_migration')), '42501');
      assert.equal(await sqlState(c.query('CREATE TABLE public.forbidden(id integer)')), '42501');
    });
  }
  await withClient(connections.data, async (c) => {
    assert.equal(await sqlState(c.query('SELECT * FROM local_credential')), '42501');
  });
  await withClient(connections.authority, async (c) => {
    assert.equal(await sqlState(c.query('DELETE FROM application_session')), '42501');
  });
  await withClient(connections.identity, async (c) => {
    assert.equal(await sqlState(c.query('DELETE FROM user_role')), '42501');
  });
});
test('code rows and ownership transitions protected, sync cannot take runtime ownership', async () => {
  const key = Buffer.from('system.root');
  await pools.sync.query(
    "INSERT INTO role_definition(role_key,managed_by,authority_level,label) VALUES($1,'code',1000,'Root')",
    [key],
  );
  for (const sql of [
    "UPDATE role_definition SET label='hijack' WHERE role_key=$1",
    "UPDATE role_definition SET managed_by='runtime' WHERE role_key=$1",
    'DELETE FROM role_definition WHERE role_key=$1',
  ]) {
    await assert.rejects(pools.authority.query(sql, [key]));
  }
  await pools.authority.query(
    "INSERT INTO role_definition(role_key,managed_by,authority_level,label) VALUES($1,'runtime',1,'Runtime')",
    [Buffer.from('custom')],
  );
  await assert.rejects(
    pools.sync.query("UPDATE role_definition SET managed_by='code' WHERE role_key=$1", [
      Buffer.from('custom'),
    ]),
  );
});
test('shared fence blocks revoke and following statements see committed epoch', async () => {
  const runner = new ProductTransactionRunner(pools);
  let release!: () => void;
  let acquired!: () => void;
  const ready = new Promise<void>((r) => {
    acquired = r;
  });
  const hold = new Promise<void>((r) => {
    release = r;
  });
  const read = runner.run('read', async () => {
    acquired();
    await hold;
  });
  await ready;
  let revoked = false;
  const revoke = runner.run('revoke', () => {
    revoked = true;
    return Promise.resolve();
  });
  try {
    await new Promise((r) => setTimeout(r, 75));
    assert.equal(revoked, false);
  } finally {
    release();
    await read;
    await revoke;
  }
  assert.equal(await runner.run('read', (tx) => Promise.resolve(tx.revision)), '2');
});

test('repeat provision and migrations are no-op, persisted runtime facts survive', async () => {
  await provisionProductDatabase(fixture.superuser, fixturePasswords);
  const migration = await new DataSource(
    productDataSourceOptions(connections.migration),
  ).initialize();
  try {
    assert.deepEqual(await migration.runMigrations({ transaction: 'each' }), []);
  } finally {
    await migration.destroy();
  }
  assert.equal(
    (
      await pools.data.query<{ label: string }[]>(
        'SELECT label FROM role_definition WHERE role_key=$1',
        [Buffer.from('custom')],
      )
    )[0]!.label,
    'Runtime',
  );
});
test('startup rejects any privilege drift, not only sampled grants', async () => {
  await verifyProductPrivileges(pools);
  for (const [grant, revoke] of [
    [
      'GRANT SELECT ON local_credential TO product_data',
      'REVOKE SELECT ON local_credential FROM product_data',
    ],
    // Secrets the old sampled probe did not cover: OIDC PKCE verifier/nonce and one-time tokens.
    [
      'GRANT SELECT ON oidc_login_attempt,one_time_token TO product_data',
      'REVOKE SELECT ON oidc_login_attempt,one_time_token FROM product_data',
    ],
    [
      'GRANT SELECT(password_hash) ON local_credential TO product_bootstrap',
      'REVOKE SELECT(password_hash) ON local_credential FROM product_bootstrap',
    ],
    [
      'GRANT INSERT ON user_boundary TO product_identity',
      'REVOKE INSERT ON user_boundary FROM product_identity',
    ],
    ['GRANT SELECT ON rate_limit TO PUBLIC', 'REVOKE SELECT ON rate_limit FROM PUBLIC'],
    [
      'GRANT SELECT ON user_role TO product_data WITH GRANT OPTION',
      'REVOKE GRANT OPTION FOR SELECT ON user_role FROM product_data',
    ],
    [
      'REVOKE UPDATE(revision) ON authz_state FROM product_authority',
      'GRANT UPDATE(revision) ON authz_state TO product_authority',
    ],
    // Outside schema public: a view re-exposing credentials.
    [
      'CREATE SCHEMA leak; CREATE VIEW leak.credentials AS SELECT * FROM public.local_credential; GRANT USAGE ON SCHEMA leak TO product_data; GRANT SELECT ON leak.credentials TO product_data',
      'DROP SCHEMA leak CASCADE',
    ],
    // Ownership anywhere or database CREATE is unsafe even without a listed grant.
    [
      'CREATE FUNCTION public.owned() RETURNS int LANGUAGE sql AS $$SELECT 1$$; REVOKE ALL ON FUNCTION public.owned() FROM PUBLIC; ALTER FUNCTION public.owned() OWNER TO product_data',
      'DROP FUNCTION public.owned()',
    ],
    [
      'CREATE SCHEMA extra; GRANT USAGE,CREATE ON SCHEMA extra TO product_data',
      'DROP SCHEMA extra',
    ],
    [
      "DO $$BEGIN EXECUTE format('GRANT TEMP ON DATABASE %I TO PUBLIC',current_database()); END$$",
      "DO $$BEGIN EXECUTE format('REVOKE TEMP ON DATABASE %I FROM PUBLIC',current_database()); END$$",
    ],
    [
      "DO $$BEGIN EXECUTE format('GRANT CREATE ON DATABASE %I TO product_data',current_database()); END$$",
      "DO $$BEGIN EXECUTE format('REVOKE CREATE ON DATABASE %I FROM product_data',current_database()); END$$",
    ],
    // Replica mode skips every protection trigger.
    [
      'GRANT SET ON PARAMETER session_replication_role TO product_authority',
      'REVOKE SET ON PARAMETER session_replication_role FROM product_authority',
    ],
  ] as const) {
    await withClient(fixture.superuser, (c) => c.query(grant));
    try {
      await assert.rejects(
        verifyProductPrivileges(pools),
        /privilege drift|Unsafe product credential/,
        grant,
      );
    } finally {
      await withClient(fixture.superuser, (c) => c.query(revoke));
    }
    await verifyProductPrivileges(pools);
  }
});
test('startup rejects disabled or weakened protection triggers', async () => {
  for (const [alter, restore] of [
    [
      'ALTER TABLE user_role DISABLE TRIGGER require_root_marker',
      'ALTER TABLE user_role ENABLE TRIGGER require_root_marker',
    ],
    [
      // Constraint triggers cannot be altered by DDL; simulate catalog drift as superuser.
      "UPDATE pg_trigger SET tginitdeferred=false WHERE tgname='require_root_marker'",
      "UPDATE pg_trigger SET tginitdeferred=true WHERE tgname='require_root_marker'",
    ],
    [
      'ALTER TABLE one_time_token DISABLE TRIGGER protect_system_activation',
      'ALTER TABLE one_time_token ENABLE TRIGGER protect_system_activation',
    ],
    [
      'ALTER TABLE user_role DISABLE TRIGGER protect_system_activation',
      'ALTER TABLE user_role ENABLE TRIGGER protect_system_activation',
    ],
    [
      'ALTER TABLE one_time_token DISABLE TRIGGER protect_token_consumption',
      'ALTER TABLE one_time_token ENABLE TRIGGER protect_token_consumption',
    ],
    [
      'DROP TRIGGER protect_token_consumption ON one_time_token; CREATE TRIGGER protect_token_consumption AFTER INSERT ON one_time_token FOR EACH ROW EXECUTE FUNCTION protect_token_consumption()',
      'DROP TRIGGER protect_token_consumption ON one_time_token; CREATE TRIGGER protect_token_consumption BEFORE UPDATE ON one_time_token FOR EACH ROW EXECUTE FUNCTION protect_token_consumption()',
    ],
    [
      'ALTER FUNCTION protect_system_activation() SECURITY INVOKER',
      'ALTER FUNCTION protect_system_activation() SECURITY DEFINER',
    ],
    [
      'ALTER FUNCTION protect_system_activation() RESET search_path',
      'ALTER FUNCTION protect_system_activation() SET search_path=pg_catalog,pg_temp',
    ],
    [
      'ALTER FUNCTION protect_system_activation() OWNER TO product_fence_owner',
      'ALTER FUNCTION protect_system_activation() OWNER TO product_session_owner',
    ],
    // A neutralized body behind the same name, owner and settings.
    [
      `CREATE OR REPLACE FUNCTION public.protect_product_rows() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $fn$BEGIN IF TG_OP='DELETE' THEN RETURN OLD; END IF; RETURN NEW; END$fn$`,
      `CREATE OR REPLACE FUNCTION public.protect_product_rows() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $fn$${productRowsBody}$fn$`,
    ],
    [
      `CREATE OR REPLACE FUNCTION public.require_root_marker() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $fn$BEGIN RETURN NULL; END$fn$`,
      `CREATE OR REPLACE FUNCTION public.require_root_marker() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $fn$${requireRootMarkerBody}$fn$`,
    ],
    // Same trigger name bound to another function, event, column list or condition.
    [
      'DROP TRIGGER protect_account_lifecycle ON app_user; CREATE TRIGGER protect_account_lifecycle BEFORE UPDATE ON app_user FOR EACH ROW EXECUTE FUNCTION protect_product_state()',
      'DROP TRIGGER protect_account_lifecycle ON app_user; CREATE TRIGGER protect_account_lifecycle BEFORE UPDATE ON app_user FOR EACH ROW EXECUTE FUNCTION protect_account_lifecycle()',
    ],
    [
      'DROP TRIGGER protect_product_rows ON user_role; CREATE TRIGGER protect_product_rows BEFORE INSERT OR DELETE ON user_role FOR EACH ROW EXECUTE FUNCTION protect_product_rows()',
      'DROP TRIGGER protect_product_rows ON user_role; CREATE TRIGGER protect_product_rows BEFORE INSERT OR UPDATE OR DELETE ON user_role FOR EACH ROW EXECUTE FUNCTION protect_product_rows()',
    ],
    [
      'DROP TRIGGER protect_system_activation ON user_role; CREATE TRIGGER protect_system_activation BEFORE INSERT OR UPDATE OF user_id ON user_role FOR EACH ROW EXECUTE FUNCTION protect_system_activation()',
      'DROP TRIGGER protect_system_activation ON user_role; CREATE TRIGGER protect_system_activation BEFORE INSERT OR UPDATE OF user_id,role_key ON user_role FOR EACH ROW EXECUTE FUNCTION protect_system_activation()',
    ],
    [
      'DROP TRIGGER protect_product_state ON authz_state; CREATE TRIGGER protect_product_state BEFORE UPDATE ON authz_state FOR EACH ROW WHEN (false) EXECUTE FUNCTION protect_product_state()',
      'DROP TRIGGER protect_product_state ON authz_state; CREATE TRIGGER protect_product_state BEFORE UPDATE ON authz_state FOR EACH ROW EXECUTE FUNCTION protect_product_state()',
    ],
    // A later trigger could rewrite a row the protection already accepted.
    [
      'CREATE TRIGGER zz_rewrite BEFORE INSERT ON user_role FOR EACH ROW EXECUTE FUNCTION protect_product_state()',
      'DROP TRIGGER zz_rewrite ON user_role',
    ],
  ] as const) {
    await withClient(fixture.superuser, (c) => c.query(alter));
    try {
      await assert.rejects(verifyProductPrivileges(pools), /protection drift/, alter);
    } finally {
      await withClient(fixture.superuser, (c) => c.query(restore));
    }
    await verifyProductPrivileges(pools);
  }
});
test('identity may only activate pending accounts and authority may only suspend', async () => {
  const id = randomUUID();
  await pools.identity.query(
    `INSERT INTO app_user(id,email_canonical,state) VALUES($1,'lifecycle@example.test','pending')`,
    [id],
  );
  await pools.identity.query(`UPDATE app_user SET state='active' WHERE id=$1`, [id]);
  await pools.authority.query(`UPDATE app_user SET state='suspended' WHERE id=$1`, [id]);
  await withClient(connections.identity, async (c) => {
    assert.equal(
      await sqlState(c.query(`UPDATE app_user SET state='active' WHERE id=$1`, [id])),
      '42501',
    );
    assert.equal(
      await sqlState(c.query(`UPDATE app_user SET state='pending' WHERE id=$1`, [id])),
      '42501',
    );
    assert.equal(
      await sqlState(
        c.query(`UPDATE app_user SET email_canonical='taken@example.test' WHERE id=$1`, [id]),
      ),
      '42501',
    );
  });
  // Authority may only suspend: no reopening, and no activation of a pending account without proof.
  const pending = randomUUID();
  await pools.identity.query(
    `INSERT INTO app_user(id,email_canonical,state) VALUES($1,'pending-lifecycle@example.test','pending')`,
    [pending],
  );
  await withClient(connections.authority, async (c) => {
    for (const [target, state] of [
      [id, 'active'],
      [id, 'pending'],
      [pending, 'active'],
    ] as const)
      assert.equal(
        await sqlState(c.query(`UPDATE app_user SET state=$2 WHERE id=$1`, [target, state])),
        '42501',
        `${target === id ? 'suspended' : 'pending'}→${state}`,
      );
  });
  await pools.authority.query(`UPDATE app_user SET state='suspended' WHERE id=$1`, [pending]);
});
test('legacy fixture refuses automatic merge and retains original rows', async () => {
  await withClient(fixture.superuser, (c) => c.query('CREATE DATABASE legacy_fixture'));
  const legacyConnection = { ...fixture.superuser, database: 'legacy_fixture' };
  await withClient(legacyConnection, async (c) => {
    await c.query('CREATE TABLE tenant_anchor(tenant_id uuid PRIMARY KEY)');
    await c.query("INSERT INTO tenant_anchor VALUES('10000000-0000-4000-8000-000000000001')");
  });
  const legacy = await new DataSource(productDataSourceOptions(legacyConnection)).initialize();
  try {
    await assert.rejects(
      legacy.runMigrations({ transaction: 'each' }),
      /explicit reviewed mapping/,
    );
    assert.equal(
      (
        await legacy.query<{ count: number }[]>('SELECT count(*)::int AS count FROM tenant_anchor')
      )[0]!.count,
      1,
    );
    assert.equal(
      (
        await legacy.query<{ product: string | null }[]>(
          "SELECT to_regclass('public.app_user') AS product",
        )
      )[0]!.product,
      null,
    );
  } finally {
    await legacy.destroy();
  }
});
test('session projection exposes no credential and checks expiry, epoch and credential version', async () => {
  const id = '10000000-0000-4000-8000-000000000099';
  const digest = randomBytes(32);
  await pools.identity.query(
    "INSERT INTO app_user(id,email_verified,state) VALUES($1,true,'active')",
    [id],
  );
  await pools.identity.query(
    "INSERT INTO local_credential(user_id,password_hash,version) VALUES($1,'fixture-hash',1)",
    [id],
  );
  await pools.identity.query(
    "INSERT INTO application_session(token_hash,user_id,auth_epoch,credential_version,method,assurance,authenticated_at,expires_at) VALUES($1,$2,1,1,'local','password',statement_timestamp(),statement_timestamp()+interval '1 hour')",
    [digest, id],
  );
  const read = () =>
    pools.data.query<Record<string, unknown>[]>('SELECT * FROM public.resolve_session($1)', [
      digest,
    ]);
  const rows = await read();
  assert.equal(rows.length, 1);
  assert.equal(rows[0]!.user_id, id);
  assert.equal('password_hash' in rows[0]!, false);
  assert.equal('email_canonical' in rows[0]!, false);
  await pools.identity.query('UPDATE local_credential SET version=2 WHERE user_id=$1', [id]);
  assert.deepEqual(await read(), []);
  await pools.identity.query('UPDATE local_credential SET version=1 WHERE user_id=$1', [id]);
  await pools.identity.query('UPDATE app_user SET auth_epoch=2 WHERE id=$1', [id]);
  assert.deepEqual(await read(), []);
});

test('forward protection migration preserves preexisting product fixture rows', async () => {
  await withClient(fixture.superuser, (c) => c.query('CREATE DATABASE product_upgrade_fixture'));
  const connection = { ...fixture.superuser, database: 'product_upgrade_fixture' };
  const initial = await new DataSource({
    ...productDataSourceOptions(connection),
    migrations: [ProductInitial1792108800000],
  }).initialize();
  try {
    assert.equal((await initial.runMigrations()).length, 1);
    await initial.query(
      "INSERT INTO app_user(id,state) VALUES('10000000-0000-4000-8000-000000000088','pending')",
    );
    await initial.query(
      "INSERT INTO role_definition(role_key,managed_by,authority_level,label) VALUES($1,'runtime',1,'Before upgrade')",
      [Buffer.from('retained')],
    );
  } finally {
    await initial.destroy();
  }
  const upgraded = await new DataSource(productDataSourceOptions(connection)).initialize();
  try {
    assert.equal((await upgraded.runMigrations()).length, 7);
    assert.equal(
      (await upgraded.query<{ label: string }[]>('SELECT label FROM role_definition'))[0]!.label,
      'Before upgrade',
    );
    assert.equal(
      (await upgraded.query<{ count: number }[]>('SELECT count(*)::int AS count FROM app_user'))[0]!
        .count,
      1,
    );
    assert.deepEqual(await upgraded.runMigrations(), []);
  } finally {
    await upgraded.destroy();
  }
});
test('real lock timeout retries are bounded and diagnostic failures do not change commits', async () => {
  let retryCount = 0;
  const runner = new ProductTransactionRunner(pools, {
    lockTimeoutMs: 20,
    maxRetries: 2,
    onMetric: (metric) => {
      if (metric === 'retry') retryCount++;
    },
  });
  const held = pools.data.createQueryRunner();
  await held.connect();
  await held.startTransaction();
  try {
    await held.query('SELECT public.authz_acquire_shared_fence(1)');
    await assert.rejects(
      runner.run('admin', () => Promise.resolve(undefined)),
      /persisted after retries/,
    );
    assert.equal(retryCount, 2);
  } finally {
    await held.rollbackTransaction();
    await held.release();
  }
  const badMetric = new ProductTransactionRunner(pools, {
    onMetric: () => {
      throw new Error('metrics unavailable');
    },
  });
  await badMetric.run('admin', () => Promise.resolve(undefined));
});

test('bootstrap marker cannot be reset and revision/release cannot downgrade', async () => {
  const target = '10000000-0000-4000-8000-000000000077';
  await pools.identity.query('INSERT INTO app_user(id) VALUES($1)', [target]);
  await pools.bootstrap.query(
    'UPDATE security_bootstrap_state SET operation_id=$1,target_user_id=$2,initialized_at=statement_timestamp() WHERE singleton',
    ['20000000-0000-4000-8000-000000000077', target],
  );
  await assert.rejects(
    pools.bootstrap.query(
      'UPDATE security_bootstrap_state SET operation_id=NULL,target_user_id=NULL,initialized_at=NULL WHERE singleton',
    ),
    /permanent/,
  );
  await assert.rejects(
    pools.sync.query('UPDATE authz_state SET revision=1 WHERE singleton'),
    /cannot downgrade/,
  );
  await pools.sync.query('UPDATE authz_state SET release_sequence=10 WHERE singleton');
  await assert.rejects(
    pools.sync.query('UPDATE authz_state SET release_sequence=9 WHERE singleton'),
    /cannot downgrade/,
  );
});

test('OIDC provider version change prevents re-enabled provider reviving sessions', async () => {
  const id = '10000000-0000-4000-8000-000000000066';
  const issuer = 'https://issuer.fixture.invalid';
  const digest = randomBytes(32);
  await pools.identity.query("INSERT INTO app_user(id,state) VALUES($1,'active')", [id]);
  await pools.identity.query(
    "INSERT INTO external_identity(issuer,subject,user_id) VALUES($1,'subject',$2)",
    [issuer, id],
  );
  await pools.sync.query('INSERT INTO oidc_provider(issuer,version,enabled) VALUES($1,1,true)', [
    issuer,
  ]);
  await pools.identity.query(
    "INSERT INTO application_session(token_hash,user_id,auth_epoch,method,assurance,authenticated_at,expires_at,external_issuer,external_subject,binding_version,provider_version) VALUES($1,$2,1,'oidc','oidc',statement_timestamp(),statement_timestamp()+interval '1 hour',$3,'subject',1,1)",
    [digest, id, issuer],
  );
  const read = () =>
    pools.data.query<Record<string, unknown>[]>('SELECT * FROM public.resolve_session($1)', [
      digest,
    ]);
  assert.equal((await read()).length, 1);
  await pools.sync.query('UPDATE oidc_provider SET enabled=false,version=2 WHERE issuer=$1', [
    issuer,
  ]);
  assert.deepEqual(await read(), []);
  await pools.sync.query('UPDATE oidc_provider SET enabled=true WHERE issuer=$1', [issuer]);
  assert.deepEqual(await read(), []);
});

test('runner refuses unavailable bootstrap capability without falling back to sync', async () => {
  const runner = new ProductTransactionRunner({
    data: pools.data,
    identity: pools.identity,
    authority: pools.authority,
    sync: pools.sync,
  });
  await assert.rejects(
    runner.run('bootstrap', () => Promise.resolve()),
    /capability_unavailable/,
  );
});
test('version migration refuses existing unversioned relation tuples without guessing', async () => {
  await withClient(fixture.superuser, (c) => c.query('CREATE DATABASE unversioned_fixture'));
  const connection = { ...fixture.superuser, database: 'unversioned_fixture' };
  const initial = await new DataSource({
    ...productDataSourceOptions(connection),
    migrations: [ProductInitial1792108800000],
  }).initialize();
  const user = '10000000-0000-4000-8000-000000000055';
  const object = '20000000-0000-4000-8000-000000000055';
  try {
    await initial.runMigrations();
    await initial.query('INSERT INTO app_user(id) VALUES($1)', [user]);
    await initial.query(
      "INSERT INTO resource_type(type_key,key_kind,binding_key) VALUES($1,'uuid',$1)",
      [Buffer.from('fixture')],
    );
    await initial.query(
      "INSERT INTO object_ref(object_id,type_key,key_kind,key_bytes) VALUES($1,$2,'uuid',$3)",
      [object, Buffer.from('fixture'), Buffer.from(object)],
    );
    await initial.query(
      'INSERT INTO user_relation(relation_key,object_id,user_id,starts_at) VALUES($1,$2,$3,statement_timestamp())',
      [Buffer.from('assigned'), object, user],
    );
  } finally {
    await initial.destroy();
  }
  const upgrading = await new DataSource(productDataSourceOptions(connection)).initialize();
  try {
    await assert.rejects(
      upgrading.runMigrations({ transaction: 'each' }),
      /explicit reviewed mapping/,
    );
    assert.equal(
      (
        await upgrading.query<{ count: number }[]>(
          'SELECT count(*)::int AS count FROM user_relation',
        )
      )[0]!.count,
      1,
    );
    assert.equal(
      (
        await upgrading.query<{ count: number }[]>(
          "SELECT count(*)::int AS count FROM information_schema.columns WHERE table_schema='public' AND table_name='user_relation' AND column_name='relation_version'",
        )
      )[0]!.count,
      0,
    );
  } finally {
    await upgrading.destroy();
  }
});

test('runtime replication privilege drift fails startup and repeat provisioning', async () => {
  await withClient(fixture.superuser, (c) => c.query('ALTER ROLE product_data REPLICATION'));
  try {
    await assert.rejects(verifyProductPrivileges(pools), /Unsafe product credential/);
    await assert.rejects(
      provisionProductDatabase(fixture.superuser, fixturePasswords),
      /unsafe capabilities/,
    );
  } finally {
    await withClient(fixture.superuser, (c) => c.query('ALTER ROLE product_data NOREPLICATION'));
  }
});

test('provision refuses an existing login-capable fence function owner', async () => {
  await withClient(fixture.superuser, (c) => c.query('ALTER ROLE product_fence_owner LOGIN'));
  try {
    await assert.rejects(
      provisionProductDatabase(fixture.superuser, fixturePasswords),
      /unsafe capabilities/,
    );
  } finally {
    await withClient(fixture.superuser, (c) => c.query('ALTER ROLE product_fence_owner NOLOGIN'));
  }
});

test('startup rejects a missing required authority session capability', async () => {
  await withClient(fixture.superuser, (c) =>
    c.query('REVOKE EXECUTE ON FUNCTION public.resolve_session(bytea) FROM product_authority'),
  );
  try {
    await assert.rejects(verifyProductPrivileges(pools), /privilege drift/);
  } finally {
    await withClient(fixture.superuser, (c) =>
      c.query('GRANT EXECUTE ON FUNCTION public.resolve_session(bytea) TO product_authority'),
    );
  }
});

// Conflict SQLSTATEs are deliberately injected; rollback/commit and effects use actual PostgreSQL.
test('product runner retries injected 40P01 and 40001 with rollback and one committed effect', async () => {
  for (const code of ['40P01', '40001']) {
    let attempts = 0;
    let retries = 0;
    const runner = new ProductTransactionRunner(pools, {
      maxRetries: 2,
      onMetric: (metric) => {
        if (metric === 'retry') retries++;
      },
    });
    const key = Buffer.from(`fault${code}`);
    await runner.run('admin', async (tx) => {
      attempts++;
      await tx.manager.query(
        "INSERT INTO role_definition(role_key,managed_by,authority_level,label) VALUES($1,'runtime',1,'Fault fixture')",
        [key],
      );
      if (attempts < 3)
        throw new QueryFailedError(
          'fault injection',
          [],
          Object.assign(new Error('simulated conflict'), { code }),
        );
    });
    assert.equal(attempts, 3);
    assert.equal(retries, 2);
    assert.equal(
      (
        await pools.authority.query<{ n: number }[]>(
          'SELECT count(*)::int n FROM role_definition WHERE role_key=$1',
          [key],
        )
      )[0]?.n,
      1,
    );
  }
});
