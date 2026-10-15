import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { DataSource, QueryFailedError } from 'typeorm';
import {
  productDataSourceOptions,
  provisionProductDatabase,
} from '@base-authorization/typeorm-postgres/operations';
import {
  ProductTransactionRunner,
  verifyProductPrivileges,
} from '@base-authorization/typeorm-postgres/composition';
import { ProductInitial1792108800000 } from '../packages/typeorm-postgres/dist/migrations/product/001-initial.migration.js';
import { tokenConsumptionBody } from '../packages/typeorm-postgres/dist/migrations/product/008-system-activation.migration.js';
import {
  guardRootActivationBody,
  guardRootKindBody,
  guardRootLifecycleBody,
  guardRootNotIamSubjectBody,
  productRowsIamBody,
  requireRootMarkerKindBody,
} from '../packages/typeorm-postgres/dist/migrations/product/012-iam-root.migration.js';
import { startPostgres, withClient, sqlState, type TestPostgres } from './setup-postgres.ts';

let fixture: TestPostgres;
let pools: Record<'data' | 'identity' | 'authority' | 'sync' | 'bootstrap', DataSource>;
let fixturePasswords: Record<
  'data' | 'identity' | 'authority' | 'sync' | 'migration' | 'bootstrap' | 'outbox',
  string
>;
let connections: Awaited<ReturnType<typeof provisionProductDatabase>>;
before(async () => {
  fixture = await startPostgres();
  const passwords = Object.fromEntries(
    ['data', 'identity', 'authority', 'sync', 'migration', 'bootstrap', 'outbox'].map((p) => [
      p,
      randomBytes(20).toString('hex'),
    ]),
  ) as Record<
    'data' | 'identity' | 'authority' | 'sync' | 'migration' | 'bootstrap' | 'outbox',
    string
  >;
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
test('every runtime login is refused CREATE in any schema, TEMP objects and replica mode by PostgreSQL itself', async () => {
  for (const purpose of runtimeLogins) {
    await withClient(connections[purpose], async (c) => {
      for (const statement of [
        'CREATE TABLE public.forbidden(id integer)',
        'CREATE TEMP TABLE forbidden_temp(id integer)',
        'CREATE SCHEMA forbidden_schema',
        'SET session_replication_role=replica',
      ])
        assert.equal(await sqlState(c.query(statement)), '42501', `${purpose}: ${statement}`);
    });
  }
});
test('code rows and ownership transitions protected, sync cannot take runtime ownership', async () => {
  const key = Buffer.from('coded');
  await pools.sync.query(
    "INSERT INTO role_definition(role_key,managed_by,label) VALUES($1,'code','Coded')",
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
    "INSERT INTO role_definition(role_key,managed_by,label) VALUES($1,'runtime','Runtime')",
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
const runtimeLogins = ['data', 'identity', 'authority', 'sync', 'bootstrap'] as const;

const onDatabase = (statement: string) =>
  `DO $$BEGIN EXECUTE format('${statement.replace('%DB', '%I')}',current_database()); END$$`;

async function rejectsDrift(purposes: readonly (typeof runtimeLogins)[number][], label: string) {
  for (const purpose of purposes) {
    const probe = verifyProductPrivileges({ [purpose]: pools[purpose] }).then(() => {
      throw new Error(`${purpose}: probe accepted ${label}`);
    });
    await assert.rejects(probe, (error: Error) => {
      assert.match(
        error.message,
        /privilege drift|Unsafe product credential/,
        `${purpose}: ${label}`,
      );
      // The failure names the drift, never connection details or credentials.
      for (const secret of [...Object.values(fixturePasswords), fixture.superuser.host])
        assert.ok(!error.message.includes(secret), `${purpose}: ${label}`);
      return true;
    });
  }
}

test('every runtime login rejects CREATE, TEMP, grant option and role membership drift individually', async () => {
  await verifyProductPrivileges(pools);
  for (const purpose of runtimeLogins) {
    const role = `product_${purpose}`;
    for (const [grant, revoke] of [
      [`GRANT CREATE ON SCHEMA public TO ${role}`, `REVOKE CREATE ON SCHEMA public FROM ${role}`],
      [
        `GRANT CREATE ON SCHEMA public TO ${role} WITH GRANT OPTION`,
        `REVOKE CREATE ON SCHEMA public FROM ${role}`,
      ],
      [`CREATE SCHEMA other; GRANT USAGE,CREATE ON SCHEMA other TO ${role}`, 'DROP SCHEMA other'],
      [
        onDatabase(`GRANT TEMP ON DATABASE %DB TO ${role}`),
        onDatabase(`REVOKE TEMP ON DATABASE %DB FROM ${role}`),
      ],
      [
        onDatabase(`GRANT TEMP ON DATABASE %DB TO ${role} WITH GRANT OPTION`),
        onDatabase(`REVOKE TEMP ON DATABASE %DB FROM ${role}`),
      ],
      [
        onDatabase(`GRANT CREATE ON DATABASE %DB TO ${role} WITH GRANT OPTION`),
        onDatabase(`REVOKE CREATE ON DATABASE %DB FROM ${role}`),
      ],
      [`GRANT product_fence_owner TO ${role}`, `REVOKE product_fence_owner FROM ${role}`],
      [
        `GRANT product_session_owner TO ${role} WITH ADMIN OPTION`,
        `REVOKE product_session_owner FROM ${role}`,
      ],
      // Re-delegating the access a login legitimately holds is drift as well.
      [
        `GRANT USAGE ON SCHEMA public TO ${role} WITH GRANT OPTION`,
        `REVOKE GRANT OPTION FOR USAGE ON SCHEMA public FROM ${role}`,
      ],
      [
        onDatabase(`GRANT CONNECT ON DATABASE %DB TO ${role} WITH GRANT OPTION`),
        onDatabase(`REVOKE GRANT OPTION FOR CONNECT ON DATABASE %DB FROM ${role}`),
      ],
    ] as const) {
      await withClient(fixture.superuser, (c) => c.query(grant));
      try {
        await rejectsDrift([purpose], grant);
      } finally {
        await withClient(fixture.superuser, (c) => c.query(revoke));
      }
      await verifyProductPrivileges(pools);
    }
  }
});
test('every runtime login rejects PUBLIC CREATE and TEMP drift', async () => {
  for (const [grant, revoke] of [
    ['GRANT CREATE ON SCHEMA public TO PUBLIC', 'REVOKE CREATE ON SCHEMA public FROM PUBLIC'],
    ['CREATE SCHEMA other; GRANT CREATE ON SCHEMA other TO PUBLIC', 'DROP SCHEMA other'],
    [
      onDatabase('GRANT TEMP ON DATABASE %DB TO PUBLIC'),
      onDatabase('REVOKE TEMP ON DATABASE %DB FROM PUBLIC'),
    ],
    [
      onDatabase('GRANT CREATE ON DATABASE %DB TO PUBLIC'),
      onDatabase('REVOKE CREATE ON DATABASE %DB FROM PUBLIC'),
    ],
  ] as const) {
    await withClient(fixture.superuser, (c) => c.query(grant));
    try {
      await rejectsDrift(runtimeLogins, grant);
    } finally {
      await withClient(fixture.superuser, (c) => c.query(revoke));
    }
    await verifyProductPrivileges(pools);
  }
});
test('startup rejects missing, miswired or inventory-diverging protection triggers and functions', async () => {
  const markerKind =
    'CREATE CONSTRAINT TRIGGER require_root_marker_kind AFTER UPDATE OF kind ON app_user DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.require_root_marker_kind()';
  const dropMarker = 'DROP TRIGGER require_root_marker_kind ON app_user';
  const kindGuard =
    'CREATE TRIGGER guard_root_kind BEFORE INSERT OR UPDATE OF kind ON app_user FOR EACH ROW EXECUTE FUNCTION public.guard_root_kind()';
  const lifecycle =
    'CREATE TRIGGER guard_root_lifecycle BEFORE UPDATE OF state,auth_epoch ON app_user FOR EACH ROW EXECUTE FUNCTION public.guard_root_lifecycle()';
  const activation =
    'CREATE TRIGGER guard_root_activation BEFORE INSERT ON one_time_token FOR EACH ROW EXECUTE FUNCTION public.guard_root_activation()';

  const subject = (table: string) =>
    `CREATE TRIGGER guard_root_not_iam_subject BEFORE INSERT OR UPDATE ON ${table} FOR EACH ROW EXECUTE FUNCTION public.guard_root_not_iam_subject()`;

  const fn = (name: string, body: string, definer = '') =>
    `CREATE OR REPLACE FUNCTION public.${name}() RETURNS trigger LANGUAGE plpgsql ${definer} SET search_path=pg_catalog,pg_temp AS $fn$${body}$fn$`;

  const guardBodies = [
    ['guard_root_kind', guardRootKindBody, 'BEGIN RETURN NEW; END'],
    ['require_root_marker_kind', requireRootMarkerKindBody, 'BEGIN RETURN NULL; END'],
    ['guard_root_not_iam_subject', guardRootNotIamSubjectBody, 'BEGIN RETURN NEW; END'],
    ['guard_root_activation', guardRootActivationBody, 'BEGIN RETURN NEW; END'],
    ['guard_root_lifecycle', guardRootLifecycleBody, 'BEGIN RETURN NEW; END'],
  ] as const;
  const iamTables = ['user_role', 'user_boundary', 'policy_rule', 'record_exception'];
  const cases: (readonly [string, string])[] = [
    // Missing triggers.
    [dropMarker, markerKind],
    ['DROP TRIGGER guard_root_kind ON app_user', kindGuard],
    ['DROP TRIGGER guard_root_lifecycle ON app_user', lifecycle],
    ['DROP TRIGGER guard_root_activation ON one_time_token', activation],
    ...iamTables.map(
      (t) => [`DROP TRIGGER guard_root_not_iam_subject ON ${t}`, subject(t)] as const,
    ),
    // Marker check: not deferrable, initially immediate, wrong function, wider event, WHEN, copy.
    [
      `${dropMarker}; CREATE TRIGGER require_root_marker_kind AFTER UPDATE OF kind ON app_user FOR EACH ROW EXECUTE FUNCTION public.require_root_marker_kind()`,
      `${dropMarker}; ${markerKind}`,
    ],
    [
      `${dropMarker}; CREATE CONSTRAINT TRIGGER require_root_marker_kind AFTER UPDATE OF kind ON app_user DEFERRABLE INITIALLY IMMEDIATE FOR EACH ROW EXECUTE FUNCTION public.require_root_marker_kind()`,
      `${dropMarker}; ${markerKind}`,
    ],
    [
      `${dropMarker}; CREATE CONSTRAINT TRIGGER require_root_marker_kind AFTER UPDATE OF kind ON app_user DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.protect_product_state()`,
      `${dropMarker}; ${markerKind}`,
    ],
    [
      `${dropMarker}; CREATE CONSTRAINT TRIGGER require_root_marker_kind AFTER UPDATE ON app_user DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.require_root_marker_kind()`,
      `${dropMarker}; ${markerKind}`,
    ],
    [
      `${dropMarker}; CREATE CONSTRAINT TRIGGER require_root_marker_kind AFTER UPDATE OF kind ON app_user DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (false) EXECUTE FUNCTION public.require_root_marker_kind()`,
      `${dropMarker}; ${markerKind}`,
    ],
    [
      'CREATE CONSTRAINT TRIGGER require_root_marker_kind_copy AFTER UPDATE OF kind ON app_user DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.require_root_marker_kind()',
      'DROP TRIGGER require_root_marker_kind_copy ON app_user',
    ],
    // Firing modes other than origin-only.
    [
      'ALTER TABLE user_role ENABLE REPLICA TRIGGER guard_root_not_iam_subject',
      'ALTER TABLE user_role ENABLE TRIGGER guard_root_not_iam_subject',
    ],
    [
      'ALTER TABLE app_user ENABLE ALWAYS TRIGGER require_root_marker_kind',
      'ALTER TABLE app_user ENABLE TRIGGER require_root_marker_kind',
    ],
    // Same trigger name bound to a same-named function in another schema.
    [
      `CREATE SCHEMA shadow; CREATE FUNCTION shadow.guard_root_activation() RETURNS trigger LANGUAGE plpgsql AS $f$BEGIN RETURN NEW; END$f$; REVOKE ALL ON FUNCTION shadow.guard_root_activation() FROM PUBLIC; DROP TRIGGER guard_root_activation ON one_time_token; CREATE TRIGGER guard_root_activation BEFORE INSERT ON one_time_token FOR EACH ROW EXECUTE FUNCTION shadow.guard_root_activation()`,
      `DROP TRIGGER guard_root_activation ON one_time_token; ${activation}; DROP SCHEMA shadow CASCADE`,
    ],
    // Timing, event, column list and granularity.
    [
      'DROP TRIGGER guard_root_activation ON one_time_token; CREATE TRIGGER guard_root_activation AFTER INSERT ON one_time_token FOR EACH ROW EXECUTE FUNCTION public.guard_root_activation()',
      `DROP TRIGGER guard_root_activation ON one_time_token; ${activation}`,
    ],
    [
      'DROP TRIGGER guard_root_kind ON app_user; CREATE TRIGGER guard_root_kind BEFORE UPDATE OF kind ON app_user FOR EACH ROW EXECUTE FUNCTION public.guard_root_kind()',
      `DROP TRIGGER guard_root_kind ON app_user; ${kindGuard}`,
    ],
    [
      'DROP TRIGGER guard_root_lifecycle ON app_user; CREATE TRIGGER guard_root_lifecycle BEFORE UPDATE OF state ON app_user FOR EACH ROW EXECUTE FUNCTION public.guard_root_lifecycle()',
      `DROP TRIGGER guard_root_lifecycle ON app_user; ${lifecycle}`,
    ],
    [
      'DROP TRIGGER guard_root_not_iam_subject ON user_role; CREATE TRIGGER guard_root_not_iam_subject BEFORE INSERT OR UPDATE ON user_role FOR EACH STATEMENT EXECUTE FUNCTION public.guard_root_not_iam_subject()',
      `DROP TRIGGER guard_root_not_iam_subject ON user_role; ${subject('user_role')}`,
    ],
    // Neutralized bodies behind the same name, owner and settings.
    ...guardBodies.map(
      ([name, body, neutral]) =>
        [fn(name, neutral, 'SECURITY DEFINER'), fn(name, body, 'SECURITY DEFINER')] as const,
    ),
    [
      fn('protect_token_consumption', 'BEGIN RETURN NEW; END'),
      fn('protect_token_consumption', tokenConsumptionBody),
    ],
    // Function inventory: overload, search_path, owner.
    [
      'CREATE FUNCTION public.guard_root_kind(int) RETURNS int LANGUAGE sql AS $f$SELECT 1$f$; REVOKE ALL ON FUNCTION public.guard_root_kind(int) FROM PUBLIC',
      'DROP FUNCTION public.guard_root_kind(int)',
    ],
    [
      'ALTER FUNCTION guard_root_not_iam_subject() SET search_path=public',
      'ALTER FUNCTION guard_root_not_iam_subject() SET search_path=pg_catalog,pg_temp',
    ],
    [
      'ALTER FUNCTION guard_root_lifecycle() OWNER TO product_migration',
      'ALTER FUNCTION guard_root_lifecycle() OWNER TO product_session_owner',
    ],
    [
      'ALTER FUNCTION protect_product_rows() OWNER TO product_session_owner',
      'ALTER FUNCTION protect_product_rows() OWNER TO product_migration',
    ],
    // Owner hardening.
    ['ALTER ROLE product_session_owner LOGIN', 'ALTER ROLE product_session_owner NOLOGIN'],
    [
      'GRANT product_data TO product_session_owner',
      'REVOKE product_data FROM product_session_owner',
    ],
    [
      'GRANT CREATE ON SCHEMA public TO product_session_owner',
      'REVOKE CREATE ON SCHEMA public FROM product_session_owner',
    ],
    // Exact owner ACL (spec 3.2): one grant too many or one missing.
    [
      'GRANT SELECT(password_hash) ON local_credential TO product_session_owner',
      'REVOKE SELECT(password_hash) ON local_credential FROM product_session_owner',
    ],
    [
      'GRANT UPDATE(state) ON app_user TO product_session_owner',
      'REVOKE UPDATE(state) ON app_user FROM product_session_owner',
    ],
    [
      'GRANT SELECT(role_key) ON user_role TO product_session_owner',
      'REVOKE SELECT(role_key) ON user_role FROM product_session_owner',
    ],
    [
      'REVOKE SELECT(kind) ON app_user FROM product_session_owner',
      'GRANT SELECT(kind) ON app_user TO product_session_owner',
    ],
    [
      'REVOKE SELECT ON security_bootstrap_state FROM product_session_owner',
      'GRANT SELECT ON security_bootstrap_state TO product_session_owner',
    ],
  ];
  for (const [alter, restore] of cases) {
    await withClient(fixture.superuser, (c) => c.query(alter));
    try {
      await assert.rejects(verifyProductPrivileges(pools), /protection drift/, alter);
    } finally {
      await withClient(fixture.superuser, (c) => c.query(restore));
    }
    await verifyProductPrivileges(pools).catch((error: Error) => {
      throw new Error(`restore of [${alter}] left drift: ${error.message}`);
    });
  }
  // A dropped guard function takes its triggers with it and cannot start the runtime.
  await withClient(fixture.superuser, (c) =>
    c.query('DROP FUNCTION public.guard_root_activation() CASCADE'),
  );
  try {
    await assert.rejects(verifyProductPrivileges(pools), /protection drift/);
  } finally {
    await withClient(fixture.superuser, (c) =>
      c.query(`${fn('guard_root_activation', guardRootActivationBody, 'SECURITY DEFINER')};
        ${activation};
        REVOKE ALL ON FUNCTION public.guard_root_activation() FROM PUBLIC;
        ALTER FUNCTION public.guard_root_activation() OWNER TO product_session_owner;`),
    );
  }
  await verifyProductPrivileges(pools);
});
test('protection function ACL is exact for every runtime login', async () => {
  const targets = [
    'guard_root_kind',
    'require_root_marker_kind',
    'guard_root_not_iam_subject',
    'guard_root_activation',
    'guard_root_lifecycle',
    'protect_token_consumption',
  ];
  const cases = targets.flatMap((name) => [
    ...(['PUBLIC', ...runtimeLogins.map((p) => `product_${p}`)] as const).map((grantee) => ({
      grant: `GRANT EXECUTE ON FUNCTION public.${name}() TO ${grantee}${grantee === 'PUBLIC' ? '' : ' WITH GRANT OPTION'}`,
      revoke: `REVOKE EXECUTE ON FUNCTION public.${name}() FROM ${grantee}`,
      affected: grantee === 'PUBLIC' ? runtimeLogins : [grantee.slice('product_'.length) as never],
    })),
  ]);
  for (const { grant, revoke, affected } of cases) {
    await withClient(fixture.superuser, (c) => c.query(grant));
    try {
      await rejectsDrift(affected, grant);
    } finally {
      await withClient(fixture.superuser, (c) => c.query(revoke));
    }
    await verifyProductPrivileges(pools);
  }
});
test('startup rejects disabled or weakened protection triggers', async () => {
  for (const [alter, restore] of [
    [
      'ALTER TABLE app_user DISABLE TRIGGER require_root_marker_kind',
      'ALTER TABLE app_user ENABLE TRIGGER require_root_marker_kind',
    ],
    [
      // Constraint triggers cannot be altered by DDL; simulate catalog drift as superuser.
      "UPDATE pg_trigger SET tginitdeferred=false WHERE tgname='require_root_marker_kind'",
      "UPDATE pg_trigger SET tginitdeferred=true WHERE tgname='require_root_marker_kind'",
    ],
    ...(['guard_root_kind', 'guard_root_lifecycle'] as const).map(
      (t) =>
        [
          `ALTER TABLE app_user DISABLE TRIGGER ${t}`,
          `ALTER TABLE app_user ENABLE TRIGGER ${t}`,
        ] as const,
    ),
    [
      'ALTER TABLE one_time_token DISABLE TRIGGER guard_root_activation',
      'ALTER TABLE one_time_token ENABLE TRIGGER guard_root_activation',
    ],
    ...['user_role', 'user_boundary', 'policy_rule', 'record_exception'].map(
      (t) =>
        [
          `ALTER TABLE ${t} DISABLE TRIGGER guard_root_not_iam_subject`,
          `ALTER TABLE ${t} ENABLE TRIGGER guard_root_not_iam_subject`,
        ] as const,
    ),
    [
      'ALTER FUNCTION guard_root_kind() SECURITY INVOKER',
      'ALTER FUNCTION guard_root_kind() SECURITY DEFINER',
    ],
    [
      'ALTER FUNCTION guard_root_activation() RESET search_path',
      'ALTER FUNCTION guard_root_activation() SET search_path=pg_catalog,pg_temp',
    ],
    [
      'ALTER FUNCTION require_root_marker_kind() OWNER TO product_fence_owner',
      'ALTER FUNCTION require_root_marker_kind() OWNER TO product_session_owner',
    ],
    [
      'ALTER TABLE one_time_token DISABLE TRIGGER protect_token_consumption',
      'ALTER TABLE one_time_token ENABLE TRIGGER protect_token_consumption',
    ],
    [
      'DROP TRIGGER protect_token_consumption ON one_time_token; CREATE TRIGGER protect_token_consumption AFTER INSERT ON one_time_token FOR EACH ROW EXECUTE FUNCTION protect_token_consumption()',
      'DROP TRIGGER protect_token_consumption ON one_time_token; CREATE TRIGGER protect_token_consumption BEFORE UPDATE ON one_time_token FOR EACH ROW EXECUTE FUNCTION protect_token_consumption()',
    ],
    // Same body, owner and ACL, weaker volatility: a STABLE guard reuses the caller's snapshot and
    // misses a fact committed while it waited on the account row lock (spec 3.3).
    [
      'ALTER FUNCTION public.guard_root_kind() STABLE',
      'ALTER FUNCTION public.guard_root_kind() VOLATILE',
    ],
    [
      'ALTER FUNCTION public.protect_product_rows() IMMUTABLE',
      'ALTER FUNCTION public.protect_product_rows() VOLATILE',
    ],
    // iam_account must stay the IAM-only projection: a Root row in it is visible to IAM (spec 7.2).
    [
      'CREATE OR REPLACE VIEW public.iam_account WITH (security_invoker=true) AS SELECT id,state FROM public.app_user',
      "CREATE OR REPLACE VIEW public.iam_account WITH (security_invoker=true) AS SELECT id,state FROM public.app_user WHERE kind='iam'",
    ],
    [
      'ALTER VIEW public.iam_account RESET (security_invoker)',
      'ALTER VIEW public.iam_account SET (security_invoker=true)',
    ],
    // A neutralized body behind the same name, owner and settings.
    [
      `CREATE OR REPLACE FUNCTION public.protect_product_rows() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $fn$BEGIN IF TG_OP='DELETE' THEN RETURN OLD; END IF; RETURN NEW; END$fn$`,
      `CREATE OR REPLACE FUNCTION public.protect_product_rows() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $fn$${productRowsIamBody}$fn$`,
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
  assert.equal(rows[0]!.kind, 'iam');
  assert.equal('authority_level' in rows[0]!, false);
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
    await initial.query(
      "INSERT INTO audit_outbox(event_id,actor_id,event_kind,policy_revision,occurred_at,safe_metadata) VALUES('10000000-0000-4000-8000-000000000089','10000000-0000-4000-8000-000000000088','\\x6c6567616379',1,statement_timestamp(),'{}')",
    );
  } finally {
    await initial.destroy();
  }
  const upgraded = await new DataSource(productDataSourceOptions(connection)).initialize();
  try {
    // Every forward product migration after the initial one (002..012).
    assert.equal((await upgraded.runMigrations()).length, 11);
    // Events written before delivery state existed become pending, never-attempted deliveries.
    assert.deepEqual(
      await upgraded.query(
        'SELECT delivery_attempts,lease_token,lease_until,dead_at,delivered_at FROM audit_outbox',
      ),
      [
        {
          delivery_attempts: 0,
          lease_token: null,
          lease_until: null,
          dead_at: null,
          delivered_at: null,
        },
      ],
    );
    assert.equal(
      (await upgraded.query<{ label: string }[]>('SELECT label FROM role_definition'))[0]!.label,
      'Before upgrade',
    );
    assert.deepEqual(await upgraded.query('SELECT kind FROM app_user'), [{ kind: 'iam' }]);
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
        "INSERT INTO role_definition(role_key,managed_by,label) VALUES($1,'runtime','Fault fixture')",
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
test('012 replaced the system-role guards and recreated resolve_session with an exact ACL', async () => {
  assert.deepEqual(
    await pools.data.query(
      `SELECT to_regprocedure('public.require_root_marker()')::text marker,to_regprocedure('public.protect_system_activation()')::text activation,to_regclass('public.account_rank')::text rank,to_regclass('public.iam_account')::text iam`,
    ),
    [{ marker: null, activation: null, rank: null, iam: 'iam_account' }],
  );
  const acl = await withClient(
    fixture.superuser,
    async (c) =>
      (
        await c.query<{ owner: string; grantee: string; privilege: string }>(
          `SELECT r.rolname AS owner,COALESCE(g.rolname,'PUBLIC') AS grantee,a.privilege_type AS privilege
         FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner,aclexplode(p.proacl) a
         LEFT JOIN pg_roles g ON g.oid=a.grantee
         WHERE p.oid='public.resolve_session(bytea)'::regprocedure ORDER BY 2`,
        )
      ).rows,
  );
  assert.deepEqual(
    acl.map((r) => [r.owner, r.grantee, r.privilege]),
    [
      ['product_session_owner', 'product_authority', 'EXECUTE'],
      ['product_session_owner', 'product_data', 'EXECUTE'],
      ['product_session_owner', 'product_identity', 'EXECUTE'],
      ['product_session_owner', 'product_session_owner', 'EXECUTE'],
    ],
  );
  assert.deepEqual(
    await withClient(
      fixture.superuser,
      async (c) =>
        (
          await c.query<{ n: number }>(
            "SELECT count(*)::int n FROM information_schema.columns WHERE table_schema='public' AND column_name='authority_level'",
          )
        ).rows,
    ),
    [{ n: 0 }],
  );
});
