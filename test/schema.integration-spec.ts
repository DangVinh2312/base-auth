import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import {
  identityDataSourceOptions,
  tenantDataSourceOptions,
} from '@base-authorization/typeorm-postgres/legacy';
import type pg from 'pg';
import { DataSource } from 'typeorm';
import {
  type Connection,
  openClient,
  sqlState,
  startPostgres,
  type TestPostgres,
  withClient,
} from './setup-postgres.ts';

const tenantA = '00000000-0000-4000-8000-00000000000a';
const tenantB = '00000000-0000-4000-8000-00000000000b';
const member = '10000000-0000-4000-8000-000000000001';
const outsider = '10000000-0000-4000-8000-000000000002';
const submissionObject = '20000000-0000-4000-8000-000000000001';
const siteObject = '20000000-0000-4000-8000-000000000002';
const hash = Buffer.alloc(32, 1);
const bytes = (value: string) => Buffer.from(value, 'utf8');

const tenantTables = [
  'audit_outbox',
  'authz_fence',
  'identity_relation',
  'member_permission_boundary',
  'member_role',
  'membership',
  'object_ref',
  'permission_boundary',
  'permission_boundary_entry',
  'permission_catalog',
  'permission_policy',
  'policy_rule',
  'record_exception',
  'relation_edge',
  'resource_relation_definition',
  'resource_type',
  'role_definition',
  'scope_template',
  'tenant_anchor',
];
const identityTables = [
  'auth_session',
  'federated_identity',
  'identity_record',
  'tenant_directory',
];

async function createDatabase(admin: Connection, name: string): Promise<Connection> {
  await withClient(admin, (client) => client.query(`CREATE DATABASE ${name}`));
  return { ...admin, database: name };
}

async function userTables(connection: Connection): Promise<string[]> {
  return withClient(connection, async (client) => {
    const result = await client.query<{ table_name: string }>(
      `SELECT table_name FROM information_schema.tables
       WHERE table_schema = 'public' AND table_name <> 'migrations' ORDER BY table_name`,
    );
    return result.rows.map((row) => row.table_name);
  });
}

describe('PostgreSQL authority schema', () => {
  let postgres: TestPostgres;
  let tenantDb: Connection;
  let identityDb: Connection;
  let firstRun: { tenant: string[]; identity: string[] };
  let client: pg.Client;

  const migrate = async (options: ReturnType<typeof tenantDataSourceOptions>) => {
    const dataSource = await new DataSource(options).initialize();
    try {
      return (await dataSource.runMigrations({ transaction: 'each' })).map((m) => m.name);
    } finally {
      await dataSource.destroy();
    }
  };

  before(async () => {
    postgres = await startPostgres();
    tenantDb = await createDatabase(postgres.admin, 'schema_tenant');
    identityDb = await createDatabase(postgres.admin, 'schema_identity');
    firstRun = {
      tenant: await migrate(tenantDataSourceOptions(tenantDb)),
      identity: await migrate(identityDataSourceOptions(identityDb)),
    };
    client = await openClient(tenantDb);
    await seedTenantFixture(client);
  });

  after(async () => {
    await client?.end();
    await postgres?.stop();
  });

  test('migrations_apply_on_empty_database', async () => {
    assert.equal(firstRun.tenant.length, 3);
    assert.equal(firstRun.identity.length, 1);
    assert.deepEqual(await userTables(tenantDb), tenantTables);
    assert.deepEqual(await userTables(identityDb), identityTables);
    assert.equal(tenantTables.length + identityTables.length, 23);
  });

  test('migrations_rerun_is_noop_and_keeps_data', async () => {
    const before = await client.query('SELECT count(*)::text AS n FROM object_ref');
    assert.deepEqual(await migrate(tenantDataSourceOptions(tenantDb)), []);
    assert.deepEqual(await migrate(identityDataSourceOptions(identityDb)), []);
    const after = await client.query('SELECT count(*)::text AS n FROM object_ref');
    assert.deepEqual(after.rows, before.rows);
  });

  test('migration_down_up_on_disposable_database', async () => {
    const scratch = await createDatabase(postgres.admin, 'schema_down_up');
    const options = tenantDataSourceOptions(scratch);
    await migrate(options);
    const dataSource = await new DataSource(options).initialize();
    try {
      for (let i = 0; i < 3; i++) await dataSource.undoLastMigration({ transaction: 'each' });
    } finally {
      await dataSource.destroy();
    }
    assert.deepEqual(await userTables(scratch), []);
    assert.equal((await migrate(options)).length, 3);
    assert.deepEqual(await userTables(scratch), tenantTables);
  });

  test('entities_match_migrated_columns', async () => {
    for (const [options, connection] of [
      [tenantDataSourceOptions(tenantDb), tenantDb],
      [identityDataSourceOptions(identityDb), identityDb],
    ] as const) {
      const dataSource = await new DataSource(options).initialize();
      try {
        assert.equal(dataSource.options.synchronize, false);
        assert.equal(dataSource.options.migrationsRun, false);
        const columns = await withClient(connection, async (c) =>
          (
            await c.query<{
              table_name: string;
              column_name: string;
              udt_name: string;
              is_nullable: string;
            }>(
              `SELECT table_name, column_name, udt_name, is_nullable FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name <> 'migrations'`,
            )
          ).rows.map(
            (r) => `${r.table_name}.${r.column_name}:${r.udt_name}:${r.is_nullable === 'YES'}`,
          ),
        );
        const typeNames: Record<string, string> = {
          smallint: 'int2',
          integer: 'int4',
          bigint: 'int8',
          boolean: 'bool',
        };
        const mapped = dataSource.entityMetadatas.flatMap((entity) =>
          entity.columns.map((column) => {
            const type = String(column.type);
            return `${entity.tableName}.${column.databaseName}:${typeNames[type] ?? type}:${column.isNullable}`;
          }),
        );
        assert.deepEqual(mapped.sort(), columns.sort());
      } finally {
        await dataSource.destroy();
      }
    }
  });

  test('cross_tenant_fk_rejected', async () => {
    assert.equal(
      await sqlState(client.query('INSERT INTO tenant_anchor VALUES ($1)', [tenantB])),
      '23505',
    );
    assert.equal(
      await sqlState(
        client.query(
          `INSERT INTO membership (tenant_id, identity_id, state) VALUES ($1, $2, 'active')`,
          [tenantB, outsider],
        ),
      ),
      '23503',
    );
    assert.equal(
      await sqlState(
        client.query(`INSERT INTO object_ref VALUES ($1, $2, $3, 'integer', $4)`, [
          tenantB,
          '20000000-0000-4000-8000-000000000009',
          bytes('submission'),
          bytes('7'),
        ]),
      ),
      '23503',
    );
    assert.equal(
      await sqlState(
        client.query('INSERT INTO member_role VALUES ($1, $2, $3)', [
          tenantA,
          outsider,
          bytes('reviewer'),
        ]),
      ),
      '23503',
    );
  });

  test('permission_without_policy_rejected', async () => {
    const insertPermission = (key: string, policyKey: string | null, version: number) =>
      client.query(
        `INSERT INTO permission_catalog VALUES ($1, $2, $3, $4, $5, $6, 'active', 'optional')`,
        [
          tenantA,
          bytes(key),
          bytes('submission'),
          bytes(key),
          policyKey && bytes(policyKey),
          version,
        ],
      );
    assert.equal(await sqlState(insertPermission('submission.approve', 'missing', 1)), '23503');
    assert.equal(
      await sqlState(insertPermission('submission.export', 'submission-read', 2)),
      '23503',
    );
    assert.equal(await sqlState(insertPermission('submission.update', null, 1)), '23502');
  });

  test('relation_type_mismatch_rejected', async () => {
    const insertEdge = (sourceType: string, source: string, targetType: string, target: string) =>
      client.query(
        `INSERT INTO relation_edge (tenant_id, relation_key, relation_version, source_object, source_type,
           target_object, target_type, starts_at) VALUES ($1, $2, 1, $3, $4, $5, $6, now())`,
        [tenantA, bytes('submission.site'), source, bytes(sourceType), target, bytes(targetType)],
      );
    // Object types disagree with the stored object registry.
    assert.equal(
      await sqlState(insertEdge('submission', siteObject, 'site', submissionObject)),
      '23503',
    );
    // Direction disagrees with the relation definition.
    assert.equal(
      await sqlState(insertEdge('site', siteObject, 'submission', submissionObject)),
      '23503',
    );
    await insertEdge('submission', submissionObject, 'site', siteObject);
  });

  test('expired_interval_rejected', async () => {
    const at = '2026-10-13T00:00:00.000000Z';
    assert.equal(
      await sqlState(
        client.query(
          `INSERT INTO identity_relation (tenant_id, relation_key, relation_version, object_id, identity_id, starts_at, expires_at)
           VALUES ($1, $2, 1, $3, $4, $5, $5)`,
          [tenantA, bytes('site.manager'), siteObject, member, at],
        ),
      ),
      '23514',
    );
    const insertException = (purpose: string, expiresAt: string | null) =>
      client.query(
        `INSERT INTO record_exception (tenant_id, exception_id, object_id, type_key, permission_key,
           identity_id, effect, purpose, starts_at, expires_at, reason, issued_by)
         VALUES ($1, gen_random_uuid(), $2, $3, $4, $5, 'allow', $6, $7, $8, 'fixture reason', $5)`,
        [
          tenantA,
          submissionObject,
          bytes('submission'),
          bytes('submission.read'),
          member,
          purpose,
          at,
          expiresAt,
        ],
      );
    assert.equal(await sqlState(insertException('manual', '2026-10-12T23:59:59.000000Z')), '23514');
    assert.equal(await sqlState(insertException('emergency', null)), '23514');
    await insertException('manual', null);
    await insertException('emergency', '2026-10-13T00:15:00.000000Z');
  });

  test('duplicate_seed_owner_key_rejected', async () => {
    const otherSubmission = '20000000-0000-4000-8000-000000000003';
    await client.query(`INSERT INTO object_ref VALUES ($1, $2, $3, 'integer', $4)`, [
      tenantA,
      otherSubmission,
      bytes('submission'),
      bytes('102'),
    ]);
    const insertSeed = (source: string, owner: string | null, key: string | null) =>
      client.query(
        `INSERT INTO relation_edge (tenant_id, relation_key, relation_version, source_object, source_type,
           target_object, target_type, starts_at, seed_owner, seed_key)
         VALUES ($1, $2, 1, $3, $4, $5, $6, now(), $7, $8)`,
        [
          tenantA,
          bytes('submission.site'),
          source,
          bytes('submission'),
          siteObject,
          bytes('site'),
          owner && bytes(owner),
          key && bytes(key),
        ],
      );
    await client.query('DELETE FROM relation_edge');
    await insertSeed(submissionObject, 'review-module', 'default-submission-site');
    assert.equal(
      await sqlState(insertSeed(otherSubmission, 'review-module', 'default-submission-site')),
      '23505',
    );
    assert.equal(await sqlState(insertSeed(otherSubmission, 'review-module', null)), '23514');
    await insertSeed(otherSubmission, null, null);
  });

  test('identity_schema_constraints', async () => {
    await withClient(identityDb, async (c) => {
      const identity = '30000000-0000-4000-8000-000000000001';
      await c.query(`INSERT INTO identity_record VALUES ($1, 'active', 1, now())`, [identity]);
      const link = () =>
        c.query('INSERT INTO federated_identity VALUES ($1, $2, $3)', [
          bytes('https://issuer.example.test'),
          bytes('subject-1'),
          identity,
        ]);
      await link();
      assert.equal(await sqlState(link()), '23505');
      assert.equal(
        await sqlState(
          c.query(
            `INSERT INTO auth_session VALUES ($1, $2, 1, now() + interval '1 hour', NULL, now())`,
            [Buffer.alloc(16), identity],
          ),
        ),
        '23514',
      );
      assert.equal(
        await sqlState(
          c.query(`INSERT INTO tenant_directory VALUES ($1, 'Fixture', $2, 'provisioning')`, [
            tenantA,
            bytes('db'),
          ]),
        ),
        '23514',
      );
    });
  });
});

async function seedTenantFixture(client: pg.Client): Promise<void> {
  await client.query('INSERT INTO tenant_anchor VALUES ($1)', [tenantA]);
  await client.query('INSERT INTO authz_fence (tenant_id, manifest_hash) VALUES ($1, $2)', [
    tenantA,
    hash,
  ]);
  await client.query(
    `INSERT INTO membership (tenant_id, identity_id, state) VALUES ($1, $2, 'active')`,
    [tenantA, member],
  );
  for (const [type, kind] of [
    ['submission', 'integer'],
    ['site', 'uuid'],
  ] as const) {
    await client.query('INSERT INTO resource_type VALUES ($1, $2, $3, $4)', [
      tenantA,
      bytes(type),
      kind,
      bytes(type),
    ]);
  }
  await client.query(
    `INSERT INTO permission_policy VALUES ($1, $2, 1, $3, '{}'::jsonb, 'active')`,
    [tenantA, bytes('submission-read'), hash],
  );
  await client.query(
    `INSERT INTO permission_catalog VALUES ($1, $2, $3, $4, $5, 1, 'active', 'optional')`,
    [
      tenantA,
      bytes('submission.read'),
      bytes('submission'),
      bytes('read'),
      bytes('submission-read'),
    ],
  );
  await client.query(`INSERT INTO role_definition VALUES ($1, $2, 'code', 10, 'Reviewer')`, [
    tenantA,
    bytes('reviewer'),
  ]);
  await client.query(
    `INSERT INTO object_ref VALUES ($1, $2, $3, 'integer', $4), ($1, $5, $6, 'uuid', $7)`,
    [
      tenantA,
      submissionObject,
      bytes('submission'),
      bytes('101'),
      siteObject,
      bytes('site'),
      bytes('d97eecc9-8f23-4a76-a9aa-82b9d4ef33ac'),
    ],
  );
  await client.query(
    `INSERT INTO resource_relation_definition VALUES ($1, $2, 1, $3, $4, 'edgeStore', $2, $5, 'active')`,
    [tenantA, bytes('submission.site'), bytes('submission'), bytes('site'), hash],
  );
}

describe('migration 002: identity_relation.relation_version backfill', () => {
  let postgres: TestPostgres;
  before(async () => {
    postgres = await startPostgres();
  });
  after(async () => {
    await postgres?.stop();
  });

  const optionsUpTo = (db: Connection, count: number) => {
    const options = tenantDataSourceOptions(db);
    return {
      ...options,
      migrations: (options.migrations as unknown[]).slice(0, count),
    } as typeof options;
  };
  const run = async (options: ReturnType<typeof tenantDataSourceOptions>) => {
    const dataSource = await new DataSource(options).initialize();
    try {
      return (await dataSource.runMigrations({ transaction: 'each' })).map((m) => m.name);
    } finally {
      await dataSource.destroy();
    }
  };
  const objectA = '20000000-0000-4000-8000-0000000000a1';
  const objectB = '20000000-0000-4000-8000-0000000000b1';
  const legacyDatabase = async (name: string) => {
    const db = await createDatabase(postgres.admin, name);
    assert.equal((await run(optionsUpTo(db, 1))).length, 1);
    await withClient(db, async (c) => {
      await c.query('INSERT INTO tenant_anchor VALUES ($1)', [tenantA]);
      await c.query(
        `INSERT INTO membership (tenant_id, identity_id, state) VALUES ($1, $2, 'active')`,
        [tenantA, member],
      );
      await c.query(`INSERT INTO resource_type VALUES ($1, $2, 'integer', $2)`, [
        tenantA,
        bytes('submission'),
      ]);
      await c.query(
        `INSERT INTO object_ref VALUES ($1, $2, $3, 'integer', $4), ($1, $5, $3, 'integer', $6)`,
        [tenantA, objectA, bytes('submission'), bytes('1'), objectB, bytes('2')],
      );
    });
    return db;
  };
  const insertLegacy = (c: pg.Client, key: Buffer, object: string) =>
    c.query(`INSERT INTO identity_relation VALUES ($1, $2, $3, $4, '2020-01-01Z', NULL)`, [
      tenantA,
      key,
      object,
      member,
    ]);

  test('upgrading existing data keeps every tuple and does not widen any', async () => {
    const db = await legacyDatabase('upgrade_ok');
    await withClient(db, async (c) => {
      await insertLegacy(c, bytes('submission.assignee@1'), objectA);
      await insertLegacy(c, bytes('submission.assignee@2'), objectB);
      await insertLegacy(c, bytes('site.manager@12'), objectA);
    });
    const tuples = (c: pg.Client, sql: string) =>
      c.query<{ t: string }>(sql).then((r) => r.rows.map((row) => row.t).sort());
    const before = await withClient(db, (c) =>
      tuples(
        c,
        `SELECT convert_from(relation_key, 'UTF8') || '|' || object_id || '|' || identity_id AS t FROM identity_relation`,
      ),
    );
    assert.deepEqual(await run(optionsUpTo(db, 2)), ['TenantRelationVersion1791936000000']);
    await withClient(db, async (c) => {
      const after = await tuples(
        c,
        `SELECT convert_from(relation_key, 'UTF8') || '@' || relation_version || '|' || object_id || '|' || identity_id AS t
         FROM identity_relation`,
      );
      assert.deepEqual(after, before);
      const assigneeV1 = await c.query(
        `SELECT object_id::text AS o FROM identity_relation WHERE relation_key = $1 AND relation_version = 1`,
        [bytes('submission.assignee')],
      );
      assert.deepEqual(
        assigneeV1.rows,
        [{ o: objectA }],
        'version 2 tuple must not answer for version 1',
      );
    });
  });

  for (const [label, key] of [
    ['missing version', bytes('submission.assignee')],
    ['zero version', bytes('submission.assignee@0')],
    ['non-numeric version', bytes('submission.assignee@v1')],
    ['invalid UTF-8', Buffer.from([0x73, 0xff, 0x40, 0x31])],
  ] as const) {
    test(`unconvertible legacy value stops the migration (${label})`, async () => {
      const db = await legacyDatabase(`upgrade_bad_${label.replace(/[^a-z]/g, '_')}`);
      await withClient(db, (c) => insertLegacy(c, key, objectA));
      await assert.rejects(run(tenantDataSourceOptions(db)));
      await withClient(db, async (c) => {
        const column = await c.query(
          `SELECT 1 FROM information_schema.columns WHERE table_name = 'identity_relation' AND column_name = 'relation_version'`,
        );
        assert.equal(column.rowCount, 0, 'migration rolled back');
        const rows = await c.query('SELECT relation_key FROM identity_relation');
        assert.deepEqual(
          rows.rows.map((r: { relation_key: Buffer }) => r.relation_key),
          [key],
        );
        const applied = await c.query('SELECT name FROM migrations');
        assert.equal(applied.rowCount, 1);
      });
    });
  }
});

describe('migration 003: permission boundary on existing data', () => {
  let postgres: TestPostgres;
  before(async () => {
    postgres = await startPostgres();
  });
  after(async () => {
    await postgres?.stop();
  });
  const run = async (options: ReturnType<typeof tenantDataSourceOptions>) => {
    const dataSource = await new DataSource(options).initialize();
    try {
      return (await dataSource.runMigrations({ transaction: 'each' })).map((m) => m.name);
    } finally {
      await dataSource.destroy();
    }
  };

  test('existing catalog rows are kept without a guessed requirement; new rows must state one', async () => {
    const db = await createDatabase(postgres.admin, 'upgrade_boundary');
    const options = tenantDataSourceOptions(db);
    await run({
      ...options,
      migrations: (options.migrations as unknown[]).slice(0, 2),
    } as typeof options);
    await withClient(db, async (c) => {
      // Rows as written before migration 003 (seven catalog columns).
      await c.query('INSERT INTO tenant_anchor VALUES ($1)', [tenantA]);
      await c.query('INSERT INTO authz_fence (tenant_id, manifest_hash) VALUES ($1, $2)', [
        tenantA,
        hash,
      ]);
      await c.query(`INSERT INTO resource_type VALUES ($1, $2, 'integer', $2)`, [
        tenantA,
        bytes('submission'),
      ]);
      await c.query(`INSERT INTO permission_policy VALUES ($1, $2, 1, $3, '{}', 'active')`, [
        tenantA,
        bytes('submission-read'),
        hash,
      ]);
      await c.query(`INSERT INTO permission_catalog VALUES ($1, $2, $3, $4, $5, 1, 'active')`, [
        tenantA,
        bytes('submission.read'),
        bytes('submission'),
        bytes('read'),
        bytes('submission-read'),
      ]);
    });
    assert.deepEqual(await run(options), ['TenantPermissionBoundary1792022400000']);
    assert.deepEqual(await run(options), [], 'second run is a no-op');
    await withClient(db, async (c) => {
      const legacy = await c.query(
        `SELECT convert_from(permission_key, 'UTF8') AS p, boundary_requirement AS r FROM permission_catalog`,
      );
      assert.deepEqual(legacy.rows, [{ p: 'submission.read', r: null }], 'no wildcard backfill');
      const insert = (requirement: string | null) =>
        c.query(`INSERT INTO permission_catalog VALUES ($1, $2, $3, $4, $5, 1, 'active', $6)`, [
          tenantA,
          bytes('submission.export'),
          bytes('submission'),
          bytes('export'),
          bytes('submission-read'),
          requirement,
        ]);
      assert.equal(await sqlState(insert(null)), '23514');
      assert.equal(await sqlState(insert('sometimes')), '23514');
      assert.equal(
        await sqlState(c.query(`UPDATE permission_catalog SET lifecycle = 'deprecated'`)),
        '23514',
        'touching a legacy row requires its requirement',
      );
      await c.query(`UPDATE permission_catalog SET boundary_requirement = 'required'`);
      const fence = await c.query<{ capability: number }>(
        'SELECT min_runtime_capability AS capability FROM authz_fence',
      );
      assert.deepEqual(
        fence.rows,
        [{ capability: 0 }],
        'old runtimes keep working until a release',
      );
      await c.query('BEGIN');
      await c.query('SELECT public.authz_acquire_shared_fence($1)', [tenantA]);
      await c.query('ROLLBACK');
      await c.query('UPDATE authz_fence SET min_runtime_capability = 1');
      assert.equal(
        await sqlState(c.query('SELECT public.authz_acquire_shared_fence($1)', [tenantA])),
        'AZ001',
      );
      await c.query('BEGIN');
      await c.query('SELECT public.authz_acquire_shared_fence($1, 1)', [tenantA]);
      await c.query('ROLLBACK');
    });
  });
});
