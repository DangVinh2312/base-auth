import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setTimeout as sleep } from 'node:timers/promises';
import type { TenantId } from '@base-authorization/core';
import {
  type ConnectionPurpose,
  TenantDataSourceRegistry,
  type TenantDataSourceRegistryOptions,
  TenantRoutingError,
  type TenantRoute,
  TenantUnavailableError,
} from '@base-authorization/typeorm-postgres/legacy';

const tenantA = '00000000-0000-4000-8000-00000000000a' as TenantId;
const tenantB = '00000000-0000-4000-8000-00000000000b' as TenantId;
const idleTimeoutMs = 30;

interface FakeDataSource {
  database: string;
  username: string;
  initialized: number;
  destroyed: number;
}

function harness(overrides: Partial<TenantDataSourceRegistryOptions> = {}) {
  const created: FakeDataSource[] = [];
  const anchors = new Map<string, string>([
    ['db_a', tenantA],
    ['db_b', tenantB],
  ]);
  const routes = new Map<string, TenantRoute>();
  for (const [tenant, database] of [
    [tenantA, 'db_a'],
    [tenantB, 'db_b'],
  ] as const) {
    for (const purpose of ['data', 'authority'] as const) {
      routes.set(`${tenant}/${purpose}`, {
        database,
        username: `${database}_${purpose}`,
        password: 'fixture-password',
        credentialVersion: 'v1',
      });
    }
  }
  const resolved: string[] = [];
  let failNextInit = false;
  const registry = new TenantDataSourceRegistry({
    host: '127.0.0.1',
    port: 5432,
    poolSize: { data: 5, authority: 2, sync: 2 },
    maxConnections: 14,
    idleTimeoutMs,

    resolveRoute: (tenant: TenantId, purpose: ConnectionPurpose) => {
      resolved.push(`${tenant}/${purpose}`);
      return Promise.resolve(routes.get(`${tenant}/${purpose}`));
    },

    createDataSource: (options) => {
      const fake: FakeDataSource = {
        database: String(options.database),
        username: String((options as { username?: string }).username),
        initialized: 0,
        destroyed: 0,
      };
      created.push(fake);
      return {
        initialize: async () => {
          await sleep(5);
          if (failNextInit) {
            failNextInit = false;
            throw new Error('connection refused (fixture)');
          }
          fake.initialized++;
        },

        destroy: () => {
          fake.destroyed++;
          return Promise.resolve();
        },

        query: () => Promise.resolve([{ tenant_id: anchors.get(fake.database) }]),

        fake,
      } as never;
    },

    ...overrides,
  });
  return {
    registry,
    created,
    anchors,
    routes,
    resolved,

    failInit: () => (failNextInit = true),
  };
}

const fakeOf = (lease: { dataSource: unknown }) =>
  (lease.dataSource as { fake: FakeDataSource }).fake;

test('20 concurrent acquires share one single-flight pool and reference count', async () => {
  const { registry, created } = harness();
  const leases = await Promise.all(
    Array.from({ length: 20 }, () => registry.acquire(tenantA, 'data')),
  );
  assert.equal(created.length, 1);
  assert.equal(created[0]?.initialized, 1);
  assert.ok(leases.every((lease) => lease.dataSource === leases[0]?.dataSource));

  for (const lease of leases.slice(1)) await lease.release();
  await sleep(idleTimeoutMs * 3);
  assert.equal(created[0]?.destroyed, 0, 'one lease still active');

  await leases[0]?.release();
  await sleep(idleTimeoutMs * 3);
  assert.equal(created[0]?.destroyed, 1, 'idle pool evicted after last release');
  await registry.close();
});

test('release is idempotent and cannot drop another lease', async () => {
  const { registry, created } = harness();
  const first = await registry.acquire(tenantA, 'data');
  const second = await registry.acquire(tenantA, 'data');
  await first.release();
  await first.release();
  await sleep(idleTimeoutMs * 3);
  assert.equal(created[0]?.destroyed, 0);
  await second.release();
  await sleep(idleTimeoutMs * 3);
  assert.equal(created[0]?.destroyed, 1);
  await registry.close();
});

test('idle eviction never closes a pool with an active transaction lease', async () => {
  const { registry, created } = harness();
  const lease = await registry.acquire(tenantA, 'authority');
  await sleep(idleTimeoutMs * 4);
  assert.equal(created[0]?.destroyed, 0);
  assert.equal(created[0]?.username, 'db_a_authority');
  await lease.release();
  await sleep(idleTimeoutMs * 3);
  assert.equal(created[0]?.destroyed, 1);
  await registry.close();
});

test('purposes get separate pools keyed by tenant, purpose and credential version', async () => {
  const { registry, created, routes } = harness();
  const data = await registry.acquire(tenantA, 'data');
  const authority = await registry.acquire(tenantA, 'authority');
  assert.notEqual(data.dataSource, authority.dataSource);
  assert.deepEqual(
    created.map((c) => c.username),
    ['db_a_data', 'db_a_authority'],
  );

  routes.set(`${tenantA}/data`, { ...routes.get(`${tenantA}/data`)!, credentialVersion: 'v2' });
  const rotated = await registry.acquire(tenantA, 'data');
  assert.notEqual(rotated.dataSource, data.dataSource);
  assert.equal(fakeOf(data).destroyed, 0, 'retired pool stays open while leased');
  await data.release();
  assert.equal(fakeOf(data).destroyed, 1, 'retired pool closes on last release');
  await Promise.all([authority.release(), rotated.release()]);
  await registry.close();
});

test('capacity full returns a controlled unavailable error, idle pools are evicted first', async () => {
  const { registry, created } = harness({ maxConnections: 7 });
  const a = await registry.acquire(tenantA, 'data');
  await assert.rejects(registry.acquire(tenantB, 'data'), TenantUnavailableError);
  assert.equal(created.length, 1, 'no connection attempted beyond the budget');

  await a.release();
  const b = await registry.acquire(tenantB, 'data');
  assert.equal(created[0]?.destroyed, 1, 'idle LRU pool evicted to make room');
  assert.equal(fakeOf(b).database, 'db_b');
  await b.release();
  await registry.close();
});

test('unverified or unknown routing input is rejected before any connection', async () => {
  const { registry, created, resolved } = harness();
  for (const input of [
    'tenant_b',
    '',
    tenantA.toUpperCase(),
    ` ${tenantA}`,
    `${tenantA}' OR '1'='1`,
  ]) {
    await assert.rejects(registry.acquire(input as TenantId, 'data'), TenantRoutingError);
  }
  await assert.rejects(registry.acquire(tenantA, 'admin' as ConnectionPurpose), TenantRoutingError);
  assert.deepEqual(resolved, []);

  await assert.rejects(
    registry.acquire('00000000-0000-4000-8000-0000000000ff' as TenantId, 'data'),
    TenantRoutingError,
  );
  assert.equal(created.length, 0);
  await registry.close();
});

test('a pool whose database anchor belongs to another tenant is destroyed and not cached', async () => {
  const { registry, created, anchors } = harness();
  anchors.set('db_a', tenantB);
  await assert.rejects(registry.acquire(tenantA, 'data'), TenantRoutingError);
  assert.equal(created[0]?.destroyed, 1);

  anchors.set('db_a', tenantA);
  const lease = await registry.acquire(tenantA, 'data');
  assert.equal(created.length, 2);
  await lease.release();
  await registry.close();
});

test('initialization failure rejects every waiter and is not cached', async () => {
  const { registry, created, failInit } = harness();
  failInit();
  const results = await Promise.allSettled(
    Array.from({ length: 5 }, () => registry.acquire(tenantA, 'data')),
  );
  assert.ok(results.every((result) => result.status === 'rejected'));
  assert.equal(created.length, 1);

  const lease = await registry.acquire(tenantA, 'data');
  assert.equal(created.length, 2);
  await lease.release();
  await registry.close();
});

test('close destroys every pool and refuses new leases', async () => {
  const { registry, created } = harness();
  await registry.acquire(tenantA, 'data');
  await registry.acquire(tenantB, 'authority');
  await registry.close();
  assert.deepEqual(
    created.map((c) => c.destroyed),
    [1, 1],
  );
  await assert.rejects(registry.acquire(tenantA, 'data'), TenantUnavailableError);
});
