// Timestamp values across codec, planner/evaluator and PostgreSQL with real product credentials.
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { after, before, test } from 'node:test';
import { DataSource, type EntityManager } from 'typeorm';
import type { Expr, UserCompleteFacts, UserId } from '@base-authorization/core';
import {
  ProductAccessDenied,
  ProductInvalidRequest,
  type ProductReleaseSource,
  ReleaseRejectedError,
} from '@base-authorization/typeorm-postgres';
import {
  ProductAuthorization,
  ProductBindingRegistry,
  ProductDataGateway,
  ProductManifestReconciler,
  type ProductTransaction,
  ProductTransactionRunner,
  prepareProductRelease,
  readProductAuthority,
  sessionDigest,
} from '@base-authorization/typeorm-postgres/composition';
import {
  productDataSourceOptions,
  provisionProductDatabase,
} from '@base-authorization/typeorm-postgres/operations';
import { createProductAuthorizationCore } from '../apps/api/dist/authorization/product.manifest.js';
import { startPostgres, withClient, type TestPostgres } from './setup-postgres.ts';

// The codec composition the API runtime and the CLI use.
const core = createProductAuthorizationCore();
const fmt = `'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'`;

const utc = (column: string) => `to_char((${column}) AT TIME ZONE 'UTC', ${fmt})`;

const utf8 = (value: string) => Buffer.from(value);

const cutoff = '2026-10-14T12:00:00.123456Z';
const denyBefore = '2026-10-14T12:00:00.000002Z';
const rows = [
  { key: '1', occurredAt: '2026-10-14T12:00:00.000001Z', edge: 'live' }, // deny: < denyBefore
  { key: '2', occurredAt: '2026-10-14T12:00:00.000002Z', edge: 'live' }, // visible (= denyBefore)
  { key: '3', occurredAt: '2026-10-14T12:00:00.123456Z', edge: 'live' }, // boundary lt excludes
  { key: '4', occurredAt: '2026-10-14T12:00:00.123457Z', edge: 'live' }, // policy lte excludes
  { key: '5', occurredAt: '2024-02-29T23:59:59.999999Z', edge: 'live' }, // leap day; deny
  { key: '6', occurredAt: '2026-10-14T12:00:00.1Z', edge: 'expired' }, // allow edge expired
  { key: '7', occurredAt: '2026-10-14T12:00:00.05Z', edge: 'live' }, // visible
].map((row) => ({ ...row, objectId: randomUUID() }));

const literal = (value: string) => ({ from: 'literal' as const, value });

const window = { key: 'window', version: 1 };
const boundary = { key: 'cutoff', version: 1 };
const cutoffScope: Expr = { op: 'lt', field: 'occurredAt', value: literal(cutoff) };
const source: ProductReleaseSource = {
  sequence: '1',
  predecessor: '0',
  declarations: {
    resources: [
      {
        key: 'event',
        keyKind: 'integer',
        fields: { occurredAt: { kind: 'timestamp' }, status: { kind: 'string' } },
        actions: {
          read: { policy: window, boundary: 'required' },
          update: { policy: window, boundary: 'required' },
        },
      },
    ],
    relations: [
      {
        key: 'event.assignee',
        version: 1,
        sourceType: 'event',
        target: { kind: 'identity' },
        binding: { kind: 'edgeStore' },
      },
    ],
    policies: [
      {
        ...window,
        contextRequirements: [],
        obligations: [],
        requiredScope: { op: 'lte', field: 'occurredAt', value: literal(cutoff) },
      },
    ],
    templates: [
      {
        key: 'assigned',
        version: 1,
        resource: 'event',
        parameters: {},
        expression: {
          op: 'exists',
          relation: 'event.assignee@1',
          where: { op: 'eq', field: 'identityId', value: { from: 'principal', name: 'id' } },
        },
      },
      {
        key: 'before',
        version: 1,
        resource: 'event',
        parameters: { at: 'timestamp' },
        expression: { op: 'lt', field: 'occurredAt', value: { from: 'parameter', name: 'at' } },
      },
    ],
    boundaries: [
      {
        ...boundary,
        entries: ['event.read', 'event.update'].map((permission) => ({
          permission,
          contextRequirements: [],
          requiredScope: cutoffScope,
        })),
      },
    ],
    capabilities: { validators: [], obligationHandlers: [] },
  },
  roles: [],
  defaultGrants: [],
  seeds: [],
  removeSeeds: [],
  boundaryBindings: [],
  removeBoundaryBindings: [],
};
const release = prepareProductRelease(source, core);
const registry = { validators: {}, obligationHandlers: [] };
const userId = randomUUID() as UserId;
const secret = randomBytes(32).toString('base64url');
let postgres: TestPostgres;
let pools: Record<'data' | 'identity' | 'authority' | 'sync', DataSource>;
let runner: ProductTransactionRunner;
let bindings: ProductBindingRegistry;
let authorization: ProductAuthorization;

before(async () => {
  postgres = await startPostgres();
  const passwords = Object.fromEntries(
    ['data', 'identity', 'authority', 'sync', 'bootstrap', 'migration', 'outbox'].map((purpose) => [
      purpose,
      randomBytes(20).toString('hex'),
    ]),
  ) as Record<
    'data' | 'identity' | 'authority' | 'sync' | 'bootstrap' | 'migration' | 'outbox',
    string
  >;
  const connections = await provisionProductDatabase(postgres.superuser, passwords);
  pools = {} as typeof pools;
  for (const purpose of ['data', 'identity', 'authority', 'sync'] as const)
    pools[purpose] = await new DataSource(
      productDataSourceOptions(connections[purpose]),
    ).initialize();
  runner = new ProductTransactionRunner(pools);
  await pools.identity.query(
    "INSERT INTO app_user(id,state,email_verified) VALUES($1,'active',true)",
    [userId],
  );
  await pools.identity.query(
    "INSERT INTO local_credential(user_id,password_hash,version) VALUES($1,'fixture-only',1)",
    [userId],
  );
  await pools.identity.query(
    "INSERT INTO application_session(token_hash,user_id,auth_epoch,credential_version,method,assurance,authenticated_at,expires_at) VALUES($1,$2,1,1,'local','password',statement_timestamp(),statement_timestamp()+interval '1 hour')",
    [sessionDigest(secret), userId],
  );
  await new ProductManifestReconciler(runner, {
    core,
    actor: userId,
    capabilities: release.declarations.capabilities,
  }).reconcile(release);
  await withClient(postgres.superuser, async (client) => {
    await client.query(
      'CREATE TABLE product_event(id bigint PRIMARY KEY,object_id uuid UNIQUE NOT NULL REFERENCES object_ref(object_id),occurred_at timestamptz(6) NOT NULL,status text NOT NULL)',
    );
    await client.query('GRANT SELECT,UPDATE ON product_event TO product_data');
  });
  await runner.run('admin', async (tx) => {
    for (const permission of ['event.read', 'event.update'])
      await tx.manager.query(
        'INSERT INTO user_boundary(user_id,permission_key,boundary_key,boundary_version) VALUES($1,$2,$3,1)',
        [userId, utf8(permission), utf8(boundary.key)],
      );
    for (const [template, effect, parameters] of [
      ['assigned', 'allow', {}],
      ['before', 'deny', { at: denyBefore }],
    ] as const)
      await tx.manager.query(
        "INSERT INTO policy_rule(rule_id,permission_key,user_id,effect,template_key,template_version,parameters,managed_by) VALUES($1,$2,$3,$4,$5,1,$6,'runtime')",
        [randomUUID(), utf8('event.read'), userId, effect, utf8(template), parameters],
      );
    await tx.manager.query(
      "INSERT INTO policy_rule(rule_id,permission_key,user_id,effect,template_key,template_version,parameters,managed_by) VALUES($1,$2,$3,'allow',$4,1,'{}','runtime')",
      [randomUUID(), utf8('event.update'), userId, utf8('assigned')],
    );
    for (const row of rows) {
      await tx.manager.query(
        "INSERT INTO object_ref(object_id,type_key,key_kind,key_bytes) VALUES($1,$2,'integer',$3)",
        [row.objectId, utf8('event'), utf8(row.key)],
      );
      await tx.manager.query(
        row.edge === 'live'
          ? "INSERT INTO user_relation(relation_key,relation_version,object_id,user_id,starts_at,expires_at) VALUES($1,1,$2,$3,statement_timestamp()-interval '1 minute',statement_timestamp()+interval '1 hour')"
          : "INSERT INTO user_relation(relation_key,relation_version,object_id,user_id,starts_at,expires_at) VALUES($1,1,$2,$3,statement_timestamp()-interval '1 hour',statement_timestamp()-interval '1 second')",
        [utf8('event.assignee'), row.objectId, userId],
      );
    }
  });
  await withClient(postgres.superuser, async (client) => {
    for (const row of rows)
      await client.query('INSERT INTO product_event VALUES($1,$2,$3::timestamptz,$4)', [
        row.key,
        row.objectId,
        row.occurredAt,
        'open',
      ]);
  });
  bindings = new ProductBindingRegistry(core, release.declarations, {
    resources: [
      {
        resource: 'event',
        table: 'product_event',
        objectIdColumn: 'object_id',
        keyColumn: 'id',
        columns: { occurredAt: 'occurred_at', status: 'status' },
        projection: ['occurredAt', 'status'],
      },
    ],
    domains: {},
  });
  authorization = new ProductAuthorization(runner, bindings, { validators: {}, obligations: {} }, [
    { resource: 'event', action: 'update', fields: ['occurredAt'] },
  ]);
});
after(async () => {
  for (const pool of Object.values(pools ?? {})) await pool.destroy();
  await postgres?.stop();
});

/** Plans `event.read` with the DB clock inside `tx`. */
async function readPlan(tx: ProductTransaction) {
  const [clock] = await tx.manager.query<{ now: string; until: string }[]>(
    `SELECT ${utc('statement_timestamp()')} now, ${utc("statement_timestamp()+interval '2 seconds'")} until`,
  );
  const snapshot = await readProductAuthority(
    tx,
    userId,
    'event.read',
    release.declarations,
    registry,
  );
  const decision = core.planUser(
    {
      principal: { id: userId, assurance: 1 },
      resource: 'event',
      action: 'read',
      context: {},
      now: clock!.now,
      validUntil: clock!.until,
    },
    snapshot,
  );
  if (decision.effect !== 'allow') throw new Error(decision.internalReason);
  return { plan: decision.plan, now: clock!.now };
}

test('timestamp literal, parameter deny, boundary and expiry: SQL equals evaluateUser on DB facts', async () => {
  const page = await authorization.list(secret, 'event', 'read');
  assert.deepEqual(
    page.items.map((item) => [item.key, item.occurredAt]),
    [
      ['2', '2026-10-14T12:00:00.000002Z'],
      ['7', '2026-10-14T12:00:00.050000Z'],
    ],
  );
  await runner.run('read', async (tx) => {
    const { plan, now } = await readPlan(tx);
    const stored = await tx.manager.query<{ key: string; object_id: string; at: string }[]>(
      `SELECT id::text key, object_id, ${utc('occurred_at')} at FROM product_event ORDER BY id`,
    );
    // Six fractional digits survive storage and projection; nothing was rounded.
    assert.deepEqual(
      stored.map((row) => row.at),
      rows.map((row) => core.canonicalTimestamp(row.occurredAt)),
    );
    const edges = await tx.manager.query<
      { object_id: string; starts: string; expires: string | null }[]
    >(
      `SELECT object_id, ${utc('starts_at')} starts, ${utc('expires_at')} expires FROM user_relation WHERE relation_key=$1 AND user_id=$2`,
      [utf8('event.assignee'), userId],
    );
    const expected = stored
      .filter((row) => {
        const record = {
          type: 'event',
          key: core.parseKey('integer', row.key),
          objectId: row.object_id,
          fields: { occurredAt: row.at, status: 'open' },
        };
        const facts: UserCompleteFacts = {
          now,
          record,
          objects: [record],
          edges: edges.map((edge) => ({
            relation: { key: 'event.assignee', version: 1 },
            source: edge.object_id,
            target: { kind: 'identity', identity: userId },
            startsAt: edge.starts,
            expiresAt: edge.expires,
          })),
          exceptions: [],
        };
        return core.evaluateUser(plan, facts).effect === 'allow';
      })
      .map((row) => row.key);
    assert.deepEqual(expected, ['2', '7']);
    const gateway = new ProductDataGateway(bindings);
    assert.deepEqual(
      (await gateway.list(plan, {}, tx)).items.map((row) => row.key),
      expected,
    );
    assert.equal(await gateway.count(plan, {}, tx), String(expected.length));
    // Microsecond-exact filters agree with the codec's comparison.
    const at = await gateway.list(
      plan,
      { filter: { op: 'lte', field: 'occurredAt', value: '2026-10-14T12:00:00.000002Z' } },
      tx,
    );
    assert.deepEqual(
      at.items.map((row) => row.key),
      ['2'],
    );
  });
});

test('writes keep all six fractional digits and canonicalize shorter fractions', async () => {
  assert.equal(
    await authorization.update(secret, 'event', 'update', '2', {
      occurredAt: '2026-10-14T12:00:00.012345Z',
    }),
    true,
  );
  assert.equal(
    (await authorization.detail(secret, 'event', 'read', '2'))?.occurredAt,
    '2026-10-14T12:00:00.012345Z',
  );
  assert.equal(
    await authorization.update(secret, 'event', 'update', '7', {
      occurredAt: '2026-10-14T12:00:00.06Z',
    }),
    true,
  );
  assert.equal(
    (await authorization.detail(secret, 'event', 'read', '7'))?.occurredAt,
    '2026-10-14T12:00:00.060000Z',
  );
});

const invalid = [
  '2026-02-30T00:00:00Z',
  '2026-10-14T24:00:00Z',
  '2026-06-30T23:59:60Z',
  '2026-10-14T12:00:00+07:00',
  '2026-10-14T12:00:00.1234567Z',
  '2026-10-14 12:00:00Z',
  '2026-10-14T12:00:00',
];

test('invalid timestamps are refused before any SQL is sent', async () => {
  await runner.run('read', async (tx) => {
    const { plan } = await readPlan(tx);
    const gateway = new ProductDataGateway(bindings);
    let statements = 0;
    const counted: ProductTransaction = {
      mode: tx.mode,
      revision: tx.revision,
      manager: {
        query: (sql: string, parameters?: unknown[]) => {
          statements++;
          return tx.manager.query(sql, parameters);
        },
      } as unknown as EntityManager,
    };
    for (const value of invalid) {
      await assert.rejects(
        gateway.list(plan, { filter: { op: 'lt', field: 'occurredAt', value } }, counted),
        ProductInvalidRequest,
        value,
      );
    }
    assert.equal(statements, 0);
  });
  const previous = (await authorization.detail(secret, 'event', 'read', '2'))?.occurredAt;
  for (const value of invalid)
    await assert.rejects(
      authorization.update(secret, 'event', 'update', '2', { occurredAt: value }),
      ProductAccessDenied,
      value,
    );
  assert.equal((await authorization.detail(secret, 'event', 'read', '2'))?.occurredAt, previous);
  // A release literal that PostgreSQL might coerce is refused while preparing, before any lock.
  for (const value of invalid)
    assert.throws(
      () =>
        prepareProductRelease(
          {
            ...source,
            declarations: {
              ...source.declarations,
              policies: [
                {
                  ...window,
                  contextRequirements: [],
                  obligations: [],
                  requiredScope: { op: 'lte', field: 'occurredAt', value: literal(value) },
                },
              ],
            },
          },
          core,
        ),
      ReleaseRejectedError,
      value,
    );
});
