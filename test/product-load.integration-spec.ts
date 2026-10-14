import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { after, before, test } from 'node:test';
import { performance } from 'node:perf_hooks';
import { DataSource } from 'typeorm';
import {
  TransactionConflictError,
  type ProductTransactionOptions,
} from '@base-authorization/typeorm-postgres';
import { ProductTransactionRunner } from '@base-authorization/typeorm-postgres/composition';
import {
  productDataSourceOptions,
  provisionProductDatabase,
} from '@base-authorization/typeorm-postgres/operations';
import { startPostgres, withClient, type TestPostgres } from './setup-postgres.ts';

let postgres: TestPostgres;
let pools: Record<'data' | 'identity' | 'authority' | 'sync' | 'bootstrap', DataSource>;
const userId = randomUUID();
const dataset = 100;
const concurrency = 8;
const operations = 80;

before(async () => {
  postgres = await startPostgres();
  const passwords = Object.fromEntries(
    ['data', 'identity', 'authority', 'sync', 'bootstrap', 'migration'].map((purpose) => [
      purpose,
      randomBytes(20).toString('hex'),
    ]),
  ) as Record<'data' | 'identity' | 'authority' | 'sync' | 'bootstrap' | 'migration', string>;
  const connections = await provisionProductDatabase(postgres.superuser, passwords);
  pools = {} as typeof pools;
  for (const purpose of ['data', 'identity', 'authority', 'sync', 'bootstrap'] as const)
    pools[purpose] = await new DataSource(
      productDataSourceOptions(connections[purpose]),
    ).initialize();
  await pools.identity.query("INSERT INTO app_user(id,state) VALUES($1,'active')", [userId]);
  await withClient(postgres.superuser, async (client) => {
    await client.query(
      'CREATE TABLE product_load_item(id integer PRIMARY KEY,value integer NOT NULL DEFAULT 0)',
    );
    await client.query('INSERT INTO product_load_item(id) SELECT generate_series(1,$1)', [dataset]);
    await client.query('GRANT SELECT,UPDATE ON product_load_item TO product_data');
  });
});
after(async () => {
  for (const pool of Object.values(pools ?? {})) await pool.destroy();
  await postgres?.stop();
});

function percentile(values: readonly number[], fraction: number): number {
  const sorted = [...values].sort((a, b) => a - b);
  return Number((sorted[Math.max(0, Math.ceil(sorted.length * fraction) - 1)] ?? 0).toFixed(2));
}

test('measured small mixed workload uses real purpose credentials and singleton application fence', async (context) => {
  const metrics: { metric: string; mode: string; value: number }[] = [];
  const runner = new ProductTransactionRunner(pools, {
    onMetric: (metric, mode, value) => {
      metrics.push({ metric, mode, value });
    },
  });
  const latencies: number[] = [];
  const failures: unknown[] = [];
  let next = 0;
  let writes = 0;
  const started = performance.now();
  await Promise.all(
    Array.from({ length: concurrency }, async () => {
      for (;;) {
        const index = next++;
        if (index >= operations) return;
        const start = performance.now();
        try {
          const mode =
            index % 10 === 0
              ? 'admin'
              : index % 10 === 1
                ? 'revoke'
                : index % 10 < 6 && index % 10 > 2
                  ? 'write'
                  : 'read';
          await runner.run(mode, async (tx) => {
            if (mode === 'admin')
              await tx.manager.query(
                'UPDATE app_user SET authority_level=(authority_level+1)%10 WHERE id=$1',
                [userId],
              );
            else if (mode === 'revoke')
              await tx.manager.query('UPDATE app_user SET auth_epoch=auth_epoch+1 WHERE id=$1', [
                userId,
              ]);
            else if (mode === 'write') {
              await tx.manager.query('UPDATE product_load_item SET value=value+1 WHERE id=$1', [
                (index % dataset) + 1,
              ]);
            } else {
              if (index % 10 === 2) await tx.manager.query('SELECT pg_sleep(0.04)');
              const [row] = await tx.manager.query<{ count: string }[]>(
                'SELECT count(*)::text AS count FROM product_load_item',
              );
              assert.equal(row?.count, String(dataset));
            }
          });
          if (mode === 'write') writes += 1;
        } catch (error) {
          failures.push(error);
        } finally {
          latencies.push(performance.now() - start);
        }
      }
    }),
  );
  const elapsedMs = Number((performance.now() - started).toFixed(2));
  const [totals] = await pools.data.query<{ total: string }[]>(
    'SELECT sum(value)::text AS total FROM product_load_item',
  );
  assert.equal(totals!.total, String(writes));
  assert.deepEqual(failures, []);
  assert.equal(latencies.length, operations);
  for (const name of ['pool_wait', 'lock_wait', 'lock_hold', 'transaction', 'revoke_commit'])
    assert.ok(metrics.some((entry) => entry.metric === name));
  const [version] = await pools.data.query<{ version: string }[]>(
    "SELECT current_setting('server_version') AS version",
  );
  context.diagnostic(
    `PRODUCT_LOAD_RESULT ${JSON.stringify({
      dataset,
      concurrency,
      operations,
      mix: { read: 40, write: 24, admin: 8, revoke: 8, slowRead: 8 },
      node: process.version,
      platform: `${process.platform}/${process.arch}`,
      postgres: version?.version,
      elapsedMs,
      p95Ms: percentile(latencies, 0.95),
      p99Ms: percentile(latencies, 0.99),
      timeoutRate: metrics.filter((entry) => entry.metric === 'timeout').length / operations,
      failures: failures.length,
      metrics: Object.fromEntries(
        ['pool_wait', 'lock_wait', 'lock_hold', 'transaction', 'revoke_commit'].map((name) => [
          name,
          {
            count: metrics.filter((entry) => entry.metric === name).length,
            p95Ms: percentile(
              metrics.filter((entry) => entry.metric === name).map((entry) => entry.value),
              0.95,
            ),
            p99Ms: percentile(
              metrics.filter((entry) => entry.metric === name).map((entry) => entry.value),
              0.99,
            ),
          },
        ]),
      ),
    })}`,
  );
});

test('real lock timeout retries are bounded and report timeout/retry metrics', async () => {
  const metrics: Parameters<NonNullable<ProductTransactionOptions['onMetric']>>[] = [];
  const runner = new ProductTransactionRunner(pools, {
    lockTimeoutMs: 30,
    maxRetries: 1,
    onMetric: (...entry) => {
      metrics.push(entry);
    },
  });
  let release!: () => void;
  let acquired!: () => void;
  const held = new Promise<void>((resolve) => {
    acquired = resolve;
  });
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const reader = runner.run('read', async () => {
    acquired();
    await gate;
  });
  await held;
  try {
    await assert.rejects(
      runner.run('revoke', async (tx) => {
        await tx.manager.query('UPDATE app_user SET auth_epoch=auth_epoch+1 WHERE id=$1', [userId]);
      }),
      TransactionConflictError,
    );
  } finally {
    release();
    await reader;
  }
  assert.equal(metrics.filter(([metric]) => metric === 'retry').length, 1);
  assert.equal(metrics.filter(([metric]) => metric === 'timeout').length, 2);
});
