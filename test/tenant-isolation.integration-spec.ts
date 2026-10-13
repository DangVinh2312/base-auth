import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { after, before, describe, test } from 'node:test';
import { parseTenantId, type TenantId } from '@base-authorization/core';
import {
  type ConnectionPurpose,
  directoryRouteResolver,
  identityDataSourceOptions,
  TenantDataSourceRegistry,
  tenantDatabaseName,
  tenantFenceOwnerName,
  TenantProvisioner,
  tenantRoleName,
  TenantRoutingError,
} from '@base-authorization/typeorm-postgres';
import { DataSource } from 'typeorm';
import {
  type Connection,
  sqlState,
  startPostgres,
  type TestPostgres,
  withClient,
} from './setup-postgres.ts';

const tenantA = parseTenantId('00000000-0000-4000-8000-00000000000a');
const tenantB = parseTenantId('00000000-0000-4000-8000-00000000000b');
const tenantC = parseTenantId('00000000-0000-4000-8000-00000000000c');
const identityDatabase = 'authz_identity';
const purposes = ['data', 'authority', 'sync'] as const;

const passwords = new Map<string, string>();
const passwordFor = (tenant: TenantId, purpose: ConnectionPurpose) => {
  const key = `${tenant}/${purpose}`;
  if (!passwords.has(key)) passwords.set(key, randomBytes(24).toString('base64url'));
  return passwords.get(key)!;
};
const credentialsFor = (tenant: TenantId) => ({
  data: passwordFor(tenant, 'data'),
  authority: passwordFor(tenant, 'authority'),
  sync: passwordFor(tenant, 'sync'),
});

describe('tenant provisioning and isolation', () => {
  let postgres: TestPostgres;
  let provisioner: TenantProvisioner;
  let identity: DataSource;

  const as = (tenant: TenantId, purpose: ConnectionPurpose, database: string): Connection => ({
    ...postgres.admin,
    username: tenantRoleName(tenant, purpose),
    password: passwordFor(tenant, purpose),
    database,
  });
  const adminOn = (database: string): Connection => ({ ...postgres.admin, database });

  before(async () => {
    postgres = await startPostgres();
    provisioner = new TenantProvisioner(postgres.admin, { identityDatabase });
    await provisioner.provisionIdentity();
    for (const [tenant, label] of [
      [tenantA, 'Tenant A'],
      [tenantB, 'Tenant B'],
    ] as const) {
      assert.equal(
        await provisioner.provision({
          tenantId: tenant,
          displayLabel: label,
          passwords: credentialsFor(tenant),
        }),
        tenant,
      );
    }
    identity = await new DataSource(
      identityDataSourceOptions(adminOn(identityDatabase)),
    ).initialize();
  });

  after(async () => {
    await identity?.destroy();
    await postgres?.stop();
  });

  test('tenant roles carry no elevated attributes and PUBLIC cannot connect', async () => {
    await withClient(postgres.superuser, async (client) => {
      const roles = await client.query<Record<string, boolean | string>>(
        `SELECT rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication
         FROM pg_roles WHERE rolname = ANY($1) ORDER BY rolname`,
        [
          [tenantA, tenantB].flatMap((t) => [
            ...purposes.map((p) => tenantRoleName(t, p)),
            tenantFenceOwnerName(t),
          ]),
        ],
      );
      assert.equal(roles.rows.length, 8);
      for (const role of roles.rows) {
        assert.deepEqual(
          [
            role.rolsuper,
            role.rolbypassrls,
            role.rolcreaterole,
            role.rolcreatedb,
            role.rolreplication,
          ],
          [false, false, false, false, false],
          String(role.rolname),
        );
      }
      const publicConnect = await client.query(
        `SELECT d.datname FROM pg_database d, aclexplode(d.datacl) acl
         WHERE d.datname = ANY($1) AND acl.grantee = 0 AND acl.privilege_type IN ('CONNECT', 'TEMPORARY', 'CREATE')`,
        [[identityDatabase, tenantDatabaseName(tenantA), tenantDatabaseName(tenantB)]],
      );
      assert.deepEqual(publicConnect.rows, []);
      const nullAcl = await client.query(
        `SELECT datname FROM pg_database WHERE datname = ANY($1) AND datacl IS NULL`,
        [[identityDatabase, tenantDatabaseName(tenantA), tenantDatabaseName(tenantB)]],
      );
      assert.deepEqual(nullAcl.rows, [], 'NULL datacl would mean default PUBLIC CONNECT');
    });
  });

  test('credential A cannot connect to tenant B or the identity database', async () => {
    for (const purpose of purposes) {
      for (const foreign of [tenantDatabaseName(tenantB), identityDatabase]) {
        assert.equal(
          await sqlState(withClient(as(tenantA, purpose, foreign), () => Promise.resolve())),
          '42501',
        );
      }
      await withClient(as(tenantA, purpose, tenantDatabaseName(tenantA)), async (client) => {
        const who = await client.query('SELECT current_user AS role, current_database() AS db');
        assert.deepEqual(who.rows, [
          { role: tenantRoleName(tenantA, purpose), db: tenantDatabaseName(tenantA) },
        ]);
      });
    }
  });

  test('a query without a tenant predicate still only sees its own tenant', async () => {
    for (const [tenant, identityId] of [
      [tenantA, '10000000-0000-4000-8000-00000000000a'],
      [tenantB, '10000000-0000-4000-8000-00000000000b'],
    ] as const) {
      await withClient(adminOn(tenantDatabaseName(tenant)), (client) =>
        client.query(
          `INSERT INTO membership (tenant_id, identity_id, state) VALUES ($1, $2, 'active')`,
          [tenant, identityId],
        ),
      );
    }
    await withClient(as(tenantA, 'data', tenantDatabaseName(tenantA)), async (client) => {
      const members = await client.query('SELECT tenant_id::text AS tenant_id FROM membership');
      assert.deepEqual(members.rows, [{ tenant_id: tenantA }]);
      const anchors = await client.query('SELECT tenant_id::text AS tenant_id FROM tenant_anchor');
      assert.deepEqual(anchors.rows, [{ tenant_id: tenantA }]);
    });
  });

  test('data and authority credentials follow the privilege matrix', async () => {
    const db = tenantDatabaseName(tenantA);
    await withClient(as(tenantA, 'data', db), async (client) => {
      await client.query('SELECT * FROM permission_policy');
      await client.query(
        `INSERT INTO audit_outbox VALUES ($1, gen_random_uuid(), $2, $3, NULL, NULL, 1, now(), NULL, '{}', NULL)`,
        [tenantA, '10000000-0000-4000-8000-00000000000a', Buffer.from('fixture.event')],
      );
      for (const statement of [
        `INSERT INTO role_definition VALUES ('${tenantA}', '\\x61', 'tenant', 1, 'x')`,
        'UPDATE authz_fence SET revision = revision + 1',
        `INSERT INTO tenant_anchor VALUES ('${tenantB}')`,
        'DELETE FROM tenant_anchor',
        "INSERT INTO permission_policy VALUES ('" +
          tenantA +
          "', '\\x61', 1, '\\x00', '{}', 'active')",
        'SELECT * FROM audit_outbox',
        'CREATE TABLE escape_hatch (id int)',
        'CREATE TEMP TABLE escape_hatch (id int)',
      ]) {
        assert.equal(await sqlState(client.query(statement)), '42501', statement);
      }
    });
    await withClient(as(tenantA, 'authority', db), async (client) => {
      await client.query(`INSERT INTO role_definition VALUES ($1, $2, 'tenant', 1, 'Custom')`, [
        tenantA,
        Buffer.from('custom'),
      ]);
      await client.query('UPDATE authz_fence SET revision = revision + 1');
      for (const statement of [
        "INSERT INTO permission_policy VALUES ('" +
          tenantA +
          "', '\\x61', 1, '\\x00', '{}', 'active')",
        'UPDATE authz_fence SET release_sequence = 99',
        'DELETE FROM tenant_anchor',
        'CREATE TABLE escape_hatch (id int)',
      ]) {
        assert.equal(await sqlState(client.query(statement)), '42501', statement);
      }
    });
  });

  test('the shared fence is reachable only through the SECURITY DEFINER function', async () => {
    const db = tenantDatabaseName(tenantA);
    await withClient(as(tenantA, 'data', db), async (client) => {
      for (const statement of [
        'SELECT revision FROM authz_fence',
        'SELECT 1 FROM authz_fence FOR SHARE',
        'SELECT 1 FROM authz_fence FOR UPDATE',
        'UPDATE authz_fence SET revision = revision',
        'DELETE FROM authz_fence',
      ]) {
        assert.equal(await sqlState(client.query(statement)), '42501', statement);
      }
      await client.query('BEGIN');
      const locked = await client.query<{ revision: string }>(
        'SELECT public.authz_acquire_shared_fence($1)::text AS revision',
        [tenantA],
      );
      assert.match(locked.rows[0]!.revision, /^[1-9][0-9]*$/);
      await client.query('ROLLBACK');
      assert.equal(
        await sqlState(client.query('SELECT public.authz_acquire_shared_fence($1)', [tenantB])),
        'P0002',
        'missing fence row fails closed',
      );
    });
    for (const purpose of ['authority', 'sync'] as const) {
      await withClient(as(tenantA, purpose, db), async (client) => {
        assert.equal(
          await sqlState(client.query('SELECT public.authz_acquire_shared_fence($1)', [tenantA])),
          '42501',
        );
        assert.equal(
          await sqlState(
            client.query('SELECT public.authz_acquire_shared_fence($1, 1)', [tenantA]),
          ),
          '42501',
        );
      });
    }
    await withClient(adminOn(db), async (client) => {
      for (const signature of ['(uuid)', '(uuid, integer)']) {
        const fn = await client.query<{
          prosecdef: boolean;
          proconfig: string[];
          owner: string;
          canlogin: boolean;
          super: boolean;
        }>(
          `SELECT p.prosecdef, p.proconfig, r.rolname AS owner, r.rolcanlogin AS canlogin, r.rolsuper AS super
         FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner
         WHERE p.oid = $1::regprocedure`,
          [`public.authz_acquire_shared_fence${signature}`],
        );
        assert.deepEqual(fn.rows, [
          {
            prosecdef: true,
            proconfig: ['search_path=pg_catalog, pg_temp'],
            owner: tenantFenceOwnerName(tenantA),
            canlogin: false,
            super: false,
          },
        ]);
        const executors = await client.query<{ grantee: string }>(
          `SELECT CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END AS grantee
         FROM pg_proc p, aclexplode(p.proacl) a
         WHERE p.oid = $1::regprocedure AND a.privilege_type = 'EXECUTE'
         ORDER BY 1`,
          [`public.authz_acquire_shared_fence${signature}`],
        );
        assert.deepEqual(
          executors.rows.map((r) => r.grantee).sort(),
          [tenantFenceOwnerName(tenantA), tenantRoleName(tenantA, 'data')].sort(),
        );
      }
      const ownerTables = await client.query<{ privilege: string }>(
        `SELECT table_name || ':' || privilege_type AS privilege FROM information_schema.role_table_grants
         WHERE grantee = $1 ORDER BY 1`,
        [tenantFenceOwnerName(tenantA)],
      );
      assert.deepEqual(ownerTables.rows, [], 'fence owner has column privileges only');
    });
  });

  test('registry routes only verified, active, correctly anchored tenants', async () => {
    const resolveRoute = directoryRouteResolver(identity, (tenant, purpose) =>
      Promise.resolve({ password: passwordFor(tenant, purpose), credentialVersion: 'v1' }),
    );
    const registryOptions = {
      host: postgres.admin.host,
      port: postgres.admin.port,
      poolSize: { data: 5, authority: 2, sync: 2 },
      maxConnections: 14,
      idleTimeoutMs: 60_000,
      resolveRoute,
    };
    const registry = new TenantDataSourceRegistry(registryOptions);
    try {
      const lease = await registry.acquire(tenantA, 'data');
      const rows = await lease.dataSource.query<{ db: string; role: string }[]>(
        'SELECT current_database() AS db, current_user AS role',
      );
      assert.deepEqual(rows, [
        { db: tenantDatabaseName(tenantA), role: tenantRoleName(tenantA, 'data') },
      ]);
      await lease.release();

      for (const input of [
        'not-a-uuid',
        tenantB.toUpperCase(),
        '00000000-0000-4000-8000-0000000000ff',
      ]) {
        await assert.rejects(registry.acquire(input as TenantId, 'data'), TenantRoutingError);
      }

      // Directory tampering: tenant B routed to tenant A's database with B's credentials cannot connect.
      const setRoute = (tenant: TenantId, database: string) =>
        identity.query('UPDATE tenant_directory SET route_ref = $1 WHERE id = $2', [
          Buffer.from(database),
          tenant,
        ]);
      await setRoute(tenantA, 'moved_for_test');
      await setRoute(tenantB, tenantDatabaseName(tenantA));
      await assert.rejects(registry.acquire(tenantB, 'data'));

      // Misconfigured secrets: B routed to A's database with A's credentials fails the anchor check.
      const resolveWithTenantACredentials: typeof resolveRoute = async (tenant, purpose) => {
        const route = await resolveRoute(tenant, purpose);
        return (
          route && {
            ...route,
            username: tenantRoleName(tenantA, purpose),
            password: passwordFor(tenantA, purpose),
          }
        );
      };
      const misconfigured = new TenantDataSourceRegistry({
        ...registryOptions,
        resolveRoute: resolveWithTenantACredentials,
      });
      await assert.rejects(misconfigured.acquire(tenantB, 'data'), TenantRoutingError);
      await misconfigured.close();

      await setRoute(tenantB, tenantDatabaseName(tenantB));
      await setRoute(tenantA, tenantDatabaseName(tenantA));
      await identity.query(`UPDATE tenant_directory SET state = 'disabled' WHERE id = $1`, [
        tenantB,
      ]);
      await assert.rejects(registry.acquire(tenantB, 'data'), TenantRoutingError);
      await identity.query(`UPDATE tenant_directory SET state = 'active' WHERE id = $1`, [tenantB]);
      await (await registry.acquire(tenantB, 'data')).release();
    } finally {
      await registry.close();
    }
  });

  test('provisioning is idempotent and resumes from a partial state', async () => {
    assert.equal(
      await provisioner.provision({
        tenantId: tenantA,
        displayLabel: 'Tenant A',
        passwords: credentialsFor(tenantA),
      }),
      tenantA,
    );
    await withClient(adminOn(tenantDatabaseName(tenantA)), async (client) => {
      const fence = await client.query('SELECT tenant_id::text AS tenant_id FROM authz_fence');
      assert.deepEqual(fence.rows, [{ tenant_id: tenantA }]);
    });

    // Simulate a crash after CREATE DATABASE: database exists, no roles/grants/schema/directory row.
    await withClient(postgres.admin, (client) =>
      client.query(`CREATE DATABASE ${tenantDatabaseName(tenantC)}`),
    );
    const directoryRow = () =>
      identity.query<{ state: string }[]>('SELECT state FROM tenant_directory WHERE id = $1', [
        tenantC,
      ]);
    assert.deepEqual(await directoryRow(), [], 'half-provisioned tenant is not routable');

    await provisioner.provision({
      tenantId: tenantC,
      displayLabel: 'Tenant C',
      passwords: credentialsFor(tenantC),
    });
    assert.deepEqual(await directoryRow(), [{ state: 'active' }]);
    await withClient(as(tenantC, 'data', tenantDatabaseName(tenantC)), async (client) => {
      const anchors = await client.query('SELECT tenant_id::text AS tenant_id FROM tenant_anchor');
      assert.deepEqual(anchors.rows, [{ tenant_id: tenantC }]);
    });
    assert.equal(
      await sqlState(
        withClient(as(tenantC, 'data', tenantDatabaseName(tenantA)), () => Promise.resolve()),
      ),
      '42501',
    );
  });

  test('migrateAll is a no-op on migrated databases and re-applies the privilege matrix', async () => {
    await withClient(adminOn(tenantDatabaseName(tenantA)), (client) =>
      client.query(`GRANT INSERT ON permission_policy TO ${tenantRoleName(tenantA, 'data')}`),
    );
    const results = await provisioner.migrateAll();
    assert.ok(results.length >= 3);
    assert.ok(results.every((result) => result.applied.length === 0));
    await withClient(as(tenantA, 'data', tenantDatabaseName(tenantA)), async (client) => {
      assert.equal(
        await sqlState(
          client.query(
            "INSERT INTO permission_policy VALUES ('" +
              tenantA +
              "', '\\x62', 1, '\\x00', '{}', 'active')",
          ),
        ),
        '42501',
      );
    });
  });
});
