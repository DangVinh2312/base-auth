// T8 fence I/O benchmark: statements, latency and fence wait/hold for the service path behind HTTP
// list/detail/update and revoke. Synthetic data, disposable container; numbers are diagnostics.
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { after, before, test } from 'node:test';
import { performance } from 'node:perf_hooks';
import { DataSource, type Logger } from 'typeorm';
import type { UserId } from '@base-authorization/core';
import {
  ProductAuthorization,
  ProductBindingRegistry,
  ProductIdentityService,
  ProductManifestReconciler,
  ProductTransactionRunner,
  createProductPasswordHasher,
  prepareProductRelease,
  productObligations,
  sessionDigest,
} from '@base-authorization/typeorm-postgres/composition';
import {
  productDataSourceOptions,
  provisionProductDatabase,
} from '@base-authorization/typeorm-postgres/operations';
import { startPostgres, withClient, type TestPostgres } from './setup-postgres.ts';
import { core } from './fixtures/resources.ts';

const datasetRows = 10_000;
const extraActions = Array.from({ length: 38 }, (_, i) => `act${String(i).padStart(2, '0')}`);
const actions = ['read', 'update', ...extraActions];
const samples = 100;
const warmup = 20;
const concurrency = 8;
const mixedOperations = 400;

let postgres: TestPostgres;
let pools: Record<'data' | 'identity' | 'authority' | 'sync' | 'bootstrap', DataSource>;
let authorization: ProductAuthorization;
let identity: ProductIdentityService;
const metrics: { metric: string; mode: string; value: number }[] = [];
const statements: { sql: string; parameters: unknown[] }[] = [];
const userId = randomUUID() as UserId;
const secret = randomBytes(32).toString('base64url');

const utf8 = (value: string) => Buffer.from(value);

const counter: Logger = {
  logQuery: (sql, parameters) => {
    statements.push({ sql, parameters: Array.isArray(parameters) ? parameters : [] });
  },

  logQueryError: () => undefined,

  logQuerySlow: () => undefined,

  logSchemaBuild: () => undefined,

  logMigration: () => undefined,

  log: () => undefined,
};

const release = prepareProductRelease(
  {
    sequence: '1',
    predecessor: '0',
    declarations: {
      resources: [
        {
          key: 'item',
          keyKind: 'integer',
          fields: {
            amount: { kind: 'decimal' },
            status: { kind: 'string' },
            title: { kind: 'string' },
          },
          actions: Object.fromEntries(
            actions.map((action) => [
              action,
              {
                policy: { key: action === 'update' ? 'editable' : 'readable', version: 1 },
                boundary: 'required' as const,
              },
            ]),
          ),
        },
      ],
      policies: ['readable', 'editable'].map((key) => ({
        key,
        version: 1,
        contextRequirements: [],
        obligations: key === 'editable' ? [{ handler: 'audit@1' }] : [],
        requiredScope: {
          op: 'eq' as const,
          field: 'status',
          value: { from: 'literal' as const, value: 'pending' },
        },
      })),
      templates: [
        {
          key: 'allItems',
          version: 1,
          resource: 'item',
          parameters: {},
          expression: { op: 'constant', value: true },
        },
        {
          key: 'deniedTitle',
          version: 1,
          resource: 'item',
          parameters: {},
          expression: { op: 'eq', field: 'title', value: { from: 'literal', value: 'denied' } },
        },
      ],
      relations: [],
      boundaries: [
        {
          key: 'amountLimit',
          version: 1,
          entries: actions.map((action) => ({
            permission: `item.${action}`,
            contextRequirements: [],
            requiredScope: {
              op: 'lte' as const,
              field: 'amount',
              value: { from: 'literal' as const, value: '500' },
            },
          })),
        },
      ],
      capabilities: { validators: [], obligationHandlers: ['audit@1'] },
    },
    roles: [{ key: 'reviewer', label: 'Reviewer fixture' }],
    defaultGrants: actions.map((action) => ({
      permission: `item.${action}`,
      role: 'reviewer',
      template: { key: 'allItems', version: 1 },
      parameters: {},
    })),
    seeds: [],
    removeSeeds: [],
    boundaryBindings: [],
    removeBoundaryBindings: [],
  },
  core,
);

async function newSession(): Promise<string> {
  const value = randomBytes(32).toString('base64url');
  await pools.identity.query(
    "INSERT INTO application_session(token_hash,user_id,auth_epoch,credential_version,method,assurance,authenticated_at,expires_at) VALUES($1,$2,1,1,'local','password',statement_timestamp(),statement_timestamp()+interval '1 hour')",
    [sessionDigest(value), userId],
  );
  return value;
}

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
  for (const purpose of ['data', 'identity', 'authority', 'sync', 'bootstrap'] as const)
    pools[purpose] = await new DataSource({
      ...productDataSourceOptions(connections[purpose]),
      logging: ['query'],
      logger: counter,
    }).initialize();
  const runner = new ProductTransactionRunner(pools, {
    onMetric: (metric, mode, value) => {
      metrics.push({ metric, mode, value });
    },
  });
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
      'CREATE TABLE product_item(id bigint PRIMARY KEY,object_id uuid UNIQUE NOT NULL REFERENCES object_ref(object_id),amount numeric(20,2) NOT NULL,status text NOT NULL,title text NOT NULL)',
    );
    // Object refs and items in bulk: ~2/3 pending, amounts 0..999 so the boundary halves them.
    await client.query(
      `INSERT INTO object_ref(object_id,type_key,key_kind,key_bytes)
       SELECT gen_random_uuid(),convert_to('item','UTF8'),'integer',convert_to(i::text,'UTF8') FROM generate_series(1,$1) i`,
      [datasetRows],
    );
    await client.query(
      `INSERT INTO product_item(id,object_id,amount,status,title)
       SELECT convert_from(key_bytes,'UTF8')::bigint,object_id,(convert_from(key_bytes,'UTF8')::bigint*37%1000),
       CASE WHEN convert_from(key_bytes,'UTF8')::bigint%3=0 THEN 'closed' ELSE 'pending' END,
       CASE WHEN convert_from(key_bytes,'UTF8')::bigint%50=0 THEN 'denied' ELSE 'title' END
       FROM object_ref WHERE type_key=convert_to('item','UTF8')`,
    );
    await client.query('GRANT SELECT,UPDATE ON product_item TO product_data');
    await client.query('ANALYZE');
  });
  await runner.run('admin', async (tx) => {
    await tx.manager.query('INSERT INTO user_role(user_id,role_key) VALUES($1,$2)', [
      userId,
      utf8('reviewer'),
    ]);
    for (const action of actions) {
      await tx.manager.query(
        'INSERT INTO user_boundary(user_id,permission_key,boundary_key,boundary_version) VALUES($1,$2,$3,1)',
        [userId, utf8(`item.${action}`), utf8('amountLimit')],
      );
      await tx.manager.query(
        "INSERT INTO policy_rule(rule_id,permission_key,user_id,effect,template_key,template_version,parameters,managed_by) VALUES($1,$2,$3,'deny',$4,1,'{}','runtime')",
        [randomUUID(), utf8(`item.${action}`), userId, utf8('deniedTitle')],
      );
    }
  });
  const bindings = new ProductBindingRegistry(core, release.declarations, {
    resources: [
      {
        resource: 'item',
        table: 'product_item',
        objectIdColumn: 'object_id',
        keyColumn: 'id',
        columns: { amount: 'amount', status: 'status', title: 'title' },
        projection: ['amount', 'status', 'title'],
      },
    ],
    domains: {},
  });
  authorization = new ProductAuthorization(
    runner,
    bindings,
    { validators: {}, obligations: productObligations },
    [{ resource: 'item', action: 'update', fields: ['title'] }],
  );
  identity = new ProductIdentityService(runner, await createProductPasswordHasher(new Set()));
});
after(async () => {
  for (const pool of Object.values(pools ?? {})) await pool.destroy();
  await postgres?.stop();
});

function percentile(values: readonly number[], fraction: number): number {
  const sorted = [...values].sort((a, b) => a - b);
  return Number((sorted[Math.max(0, Math.ceil(sorted.length * fraction) - 1)] ?? 0).toFixed(2));
}

function summary(values: readonly number[]) {
  return { n: values.length, p50: percentile(values, 0.5), p95: percentile(values, 0.95) };
}

type Operation = 'list' | 'detail' | 'update' | 'revoke';
const run: Record<Operation, (index: number) => Promise<void>> = {
  list: async (index) => {
    const page = await authorization.list(secret, 'item', 'read', {
      limit: 20,
      offset: (index % 10) * 20,
    });
    assert.equal(page.items.length, 20);
  },

  detail: async (index) => {
    // Pending, within boundary and not denied for i%3!=0, i*37%1000<=500, i%50!=0.
    const key = [1, 2, 4, 5, 7][index % 5]!;
    assert.notEqual(await authorization.detail(secret, 'item', 'read', String(key)), null);
  },

  update: async (index) => {
    const key = [1, 2, 4, 5, 7][index % 5]!;
    assert.equal(
      await authorization.update(secret, 'item', 'update', String(key), { title: `t${index}` }),
      true,
    );
  },

  revoke: async () => {
    const target = await newSession();
    await identity.logout(target);
  },
};

test('fence I/O per operation and mixed workload are measured on a 10k-row, 40-permission fixture', async (context) => {
  const perOperation: Record<string, unknown> = {};
  for (const operation of ['list', 'detail', 'update', 'revoke'] as const) {
    for (let i = 0; i < warmup; i++) await run[operation](i);
    const latencies: number[] = [];
    const counts: number[] = [];
    metrics.length = 0;
    for (let i = 0; i < samples; i++) {
      // Revoke's own session insert is setup, not part of the measured operation.
      const target = operation === 'revoke' ? await newSession() : undefined;
      const before = statements.length;
      const start = performance.now();
      if (target) await identity.logout(target);
      else await run[operation](i);
      latencies.push(performance.now() - start);
      counts.push(statements.length - before);
    }

    const by = (name: string) => metrics.filter((m) => m.metric === name).map((m) => m.value);

    perOperation[operation] = {
      statements: { min: Math.min(...counts), max: Math.max(...counts) },
      latencyMs: summary(latencies),
      lockWaitMs: summary(by('lock_wait')),
      lockHoldMs: summary(by('lock_hold')),
    };
  }

  // Statements per operation, BEGIN..COMMIT included. Inside the fence a data access is session+clock,
  // one authority read, the data statement(s) and commit; revoke is the identity path, unchanged.
  assert.deepEqual(
    Object.fromEntries(
      Object.entries(perOperation).map(([name, value]) => [
        name,
        (value as { statements: { max: number } }).statements.max,
      ]),
    ),
    { list: 8, detail: 8, update: 10, revoke: 10 },
  );

  // Mixed concurrent workload: 50% list, 20% detail, 20% update, 10% revoke.
  metrics.length = 0;
  const latencies: number[] = [];
  const failures: Record<string, number> = {};
  let next = 0;
  const started = performance.now();
  await Promise.all(
    Array.from({ length: concurrency }, async () => {
      for (;;) {
        const index = next++;
        if (index >= mixedOperations) return;
        const slot = index % 10;
        const operation: Operation =
          slot < 5 ? 'list' : slot < 7 ? 'detail' : slot < 9 ? 'update' : 'revoke';
        const start = performance.now();
        try {
          await run[operation](index);
        } catch (error) {
          // Bounded runner errors are a measured outcome of contention; anything else fails the test.
          const code = (error as { code?: unknown }).code;
          if (!(error instanceof Error) || typeof code !== 'string') throw error;
          const label = `${operation}:${error.constructor.name}:${code}`;
          failures[label] = (failures[label] ?? 0) + 1;
        } finally {
          latencies.push(performance.now() - start);
        }
      }
    }),
  );
  const elapsedMs = Number((performance.now() - started).toFixed(2));

  const by = (name: string) => metrics.filter((m) => m.metric === name).map((m) => m.value);

  // Plan of the list statement as issued (data credential, real parameters).
  const list = statements.findLast((s) => s.sql.includes('"$total"'));
  assert.ok(list);
  const plan = await pools.data.query<{ 'QUERY PLAN': string }[]>(
    `EXPLAIN (ANALYZE, BUFFERS, COSTS OFF, TIMING OFF, SUMMARY OFF) ${list.sql}`,
    list.parameters,
  );
  const [counts] = await pools.data.query<
    { permissions: string; rules: string; boundaries: string; items: string }[]
  >(
    `SELECT (SELECT count(*) FROM permission_catalog)::text permissions,(SELECT count(*) FROM policy_rule)::text rules,(SELECT count(*) FROM user_boundary)::text boundaries,(SELECT count(*) FROM product_item)::text items`,
  );
  const [version] = await pools.data.query<{ version: string }[]>(
    "SELECT current_setting('server_version') AS version",
  );
  context.diagnostic(
    `PRODUCT_FENCE_IO_RESULT ${JSON.stringify({
      node: process.version,
      platform: `${process.platform}/${process.arch}`,
      postgres: version?.version,
      fixture: counts,
      samples,
      warmup,
      perOperation,
      mixed: {
        concurrency,
        operations: mixedOperations,
        elapsedMs,
        latencyMs: { ...summary(latencies), p99: percentile(latencies, 0.99) },
        lockWaitMs: summary(by('lock_wait')),
        lockHoldMs: summary(by('lock_hold')),
        failures,
      },
    })}`,
  );
  context.diagnostic(`PRODUCT_FENCE_IO_LIST_PLAN\n${plan.map((r) => r['QUERY PLAN']).join('\n')}`);
});
