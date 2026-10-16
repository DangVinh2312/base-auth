// T10 audit outbox delivery: lease + SKIP LOCKED claim, network send outside any transaction, ack in
// its own transaction, bounded retry, poison parking. The sink here is a test recorder, not a provider.
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { after, before, beforeEach, test } from 'node:test';
import { DataSource } from 'typeorm';
import {
  type ProductAuditEnvelope,
  type ProductAuditSink,
  ProductAuditOutbox,
} from '../apps/api/dist/audit/product-outbox.service.js';

import { ProductTransactionRunner } from '../apps/api/dist/database/product-transaction.runner.js';
import {
  verifyProductPrivileges,
  productDataSourceOptions,
  provisionProductDatabase,
} from '../apps/api/dist/database/helpers/product-database.helper.js';
import { appendProductAudit } from '../apps/api/dist/audit/product-audit.repository.js';

import { sqlState, startPostgres, withClient, type TestPostgres } from './setup-postgres.ts';

type Purpose = 'data' | 'identity' | 'authority' | 'sync' | 'bootstrap' | 'migration' | 'outbox';
let postgres: TestPostgres;
let connections: Awaited<ReturnType<typeof provisionProductDatabase>>;
let identityPool: DataSource;
let outboxPool: DataSource;
let runner: ProductTransactionRunner;

/** Records every delivery attempt and dedupes by eventId, as the sink contract requires. */
class RecordingSink implements ProductAuditSink {
  readonly attempts: ProductAuditEnvelope[] = [];
  readonly stored = new Map<string, ProductAuditEnvelope>();

  readonly #behaviour: (event: ProductAuditEnvelope) => Promise<void>;

  constructor(behaviour: (event: ProductAuditEnvelope) => Promise<void> = () => Promise.resolve()) {
    this.#behaviour = behaviour;
  }

  async deliver(event: ProductAuditEnvelope): Promise<void> {
    this.attempts.push(event);
    await this.#behaviour(event);
    if (!this.stored.has(event.eventId)) this.stored.set(event.eventId, event);
  }
}

async function appendEvents(count: number): Promise<string[]> {
  const actor = randomUUID();
  await runner.run('identity', async (tx) => {
    for (let i = 0; i < count; i++) await appendProductAudit(tx, { kind: 'identity.login', actor });
  });
  const rows = await withClient(superDb(), (client) =>
    client.query<{ event_id: string }>(
      'SELECT event_id FROM audit_outbox WHERE actor_id=$1 ORDER BY occurred_at,event_id',
      [actor],
    ),
  );
  return rows.rows.map((r) => r.event_id);
}

const superDb = () => ({ ...postgres.superuser, database: connections.data.database });

const expireLeases = () =>
  withClient(superDb(), (client) =>
    client.query(
      "UPDATE audit_outbox SET lease_until=statement_timestamp()-interval '1 second' WHERE lease_until IS NOT NULL",
    ),
  );

const row = async (eventId: string) =>
  (
    await withClient(superDb(), (client) =>
      client.query<{
        delivered: boolean;
        dead: boolean;
        attempts: number;
        lease_in_ms: number | null;
      }>(
        `SELECT delivered_at IS NOT NULL delivered,dead_at IS NOT NULL dead,delivery_attempts attempts,
          (extract(epoch FROM lease_until-statement_timestamp())*1000)::int lease_in_ms FROM audit_outbox WHERE event_id=$1`,
        [eventId],
      ),
    )
  ).rows[0]!;

before(async () => {
  postgres = await startPostgres();
  const passwords = Object.fromEntries(
    ['data', 'identity', 'authority', 'sync', 'bootstrap', 'migration', 'outbox'].map((p) => [
      p,
      randomBytes(20).toString('hex'),
    ]),
  ) as Record<Purpose, string>;
  connections = await provisionProductDatabase(postgres.superuser, passwords);
  identityPool = await new DataSource(productDataSourceOptions(connections.identity)).initialize();
  outboxPool = await new DataSource(productDataSourceOptions(connections.outbox)).initialize();
  runner = new ProductTransactionRunner({ identity: identityPool });
});
after(async () => {
  await identityPool?.destroy();
  await outboxPool?.destroy();
  await postgres?.stop();
});
// Each test starts with no pending events from earlier tests.
beforeEach(async () => {
  if (connections)
    await withClient(superDb(), (client) =>
      client.query(
        'UPDATE audit_outbox SET delivered_at=statement_timestamp(),lease_token=NULL,lease_until=NULL WHERE delivered_at IS NULL AND dead_at IS NULL',
      ),
    );
});

test('the outbox login holds exactly the delivery privileges', async () => {
  await verifyProductPrivileges({ outbox: outboxPool });
  for (const sql of [
    'SELECT 1 FROM application_session LIMIT 1',
    'SELECT 1 FROM local_credential LIMIT 1',
    'SELECT 1 FROM one_time_token LIMIT 1',
    'SELECT 1 FROM app_user LIMIT 1',
    "INSERT INTO audit_outbox(event_id,actor_id,event_kind,policy_revision,occurred_at,safe_metadata) VALUES(gen_random_uuid(),gen_random_uuid(),'\\x78',1,statement_timestamp(),'{}')",
    'DELETE FROM audit_outbox',
    "UPDATE audit_outbox SET event_kind='\\x78'",
    "UPDATE audit_outbox SET safe_metadata='{}'",
    'UPDATE audit_outbox SET actor_id=gen_random_uuid()',
    'SELECT public.authz_acquire_shared_fence(1)',
    "SELECT * FROM public.resolve_session(sha256('x'))",
  ])
    assert.equal(await sqlState(outboxPool.query(sql)), '42501', sql); // USAGE is granted to the login itself, not only inherited from PUBLIC.
  const usage = await withClient(superDb(), (client) =>
    client.query<{ explicit: boolean }>(
      "SELECT EXISTS(SELECT FROM pg_namespace n,aclexplode(n.nspacl) a WHERE n.nspname='public' AND a.grantee='product_outbox'::regrole AND a.privilege_type='USAGE') explicit",
    ),
  );
  assert.equal(usage.rows[0]!.explicit, true);
});

test('options are bounded and the lease covers a whole batch of delivery timeouts', () => {
  for (const options of [
    { batchSize: 0 },
    { batchSize: 101 },
    { maxAttempts: 0 },
    { maxAttempts: 21 },
    { leaseMs: 999 },
    { backoffMs: 0 },
    { deliveryTimeoutMs: 200, batchSize: 10, leaseMs: 1000 },
  ])
    assert.throws(() => new ProductAuditOutbox(outboxPool, options), RangeError);
});

test('delivery runs outside any transaction or fence; acknowledgement is its own transaction', async () => {
  const [eventId] = await appendEvents(1);
  let revoked = false;
  const sink = new RecordingSink(async () => {
    const open = await withClient(superDb(), (client) =>
      client.query<{ n: number }>(
        "SELECT count(*)::int n FROM pg_stat_activity WHERE usename='product_outbox' AND xact_start IS NOT NULL",
      ),
    );
    assert.equal(open.rows[0]!.n, 0);
    // An exclusive revoke commits while the sink is busy: no fence share is held.
    // The runner bumps the revision under the exclusive fence before commit.
    await runner.run('revoke', async (tx) => {
      await tx.manager.query('SELECT 1');
      revoked = true;
    });
  });
  const result = await new ProductAuditOutbox(outboxPool).deliver(sink);
  assert.deepEqual(result, { claimed: 1, delivered: 1, retried: 0, dead: 0 });
  assert.equal(revoked, true);
  assert.deepEqual(
    sink.attempts.map((e) => [e.eventId, e.kind, e.attempt, e.policyRevision]),
    [[eventId, 'identity.login', 1, sink.attempts[0]!.policyRevision]],
  );
  assert.match(sink.attempts[0]!.occurredAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/);
  assert.equal((await row(eventId!)).delivered, true);
  assert.deepEqual(await new ProductAuditOutbox(outboxPool).deliver(sink), {
    claimed: 0,
    delivered: 0,
    retried: 0,
    dead: 0,
  });
});

test('crash before send: a claimed event is not lost and is redelivered after its lease expires', async () => {
  const [eventId] = await appendEvents(1);
  const crashed = await new ProductAuditOutbox(outboxPool).claim();
  assert.deepEqual(
    crashed.events.map((e) => e.eventId),
    [eventId],
  );
  const sink = new RecordingSink();
  // Lease still held by the crashed worker: nothing to claim.
  assert.equal((await new ProductAuditOutbox(outboxPool).deliver(sink)).claimed, 0);
  await expireLeases();
  assert.deepEqual(await new ProductAuditOutbox(outboxPool).deliver(sink), {
    claimed: 1,
    delivered: 1,
    retried: 0,
    dead: 0,
  });
  assert.deepEqual(
    sink.attempts.map((e) => [e.eventId, e.attempt]),
    [[eventId, 2]],
  );
});

test('crash after send before ack: redelivery is expected, the sink dedupes, a stale ack is ignored', async () => {
  const [eventId] = await appendEvents(1);
  const sink = new RecordingSink();
  const outbox = new ProductAuditOutbox(outboxPool);
  const first = await outbox.claim();
  await sink.deliver(first.events[0]!);
  // Process dies here; the lease expires and another worker takes over.
  await expireLeases();
  const second = await new ProductAuditOutbox(outboxPool).claim();
  assert.deepEqual(
    second.events.map((e) => e.eventId),
    [eventId],
  );
  assert.deepEqual(await outbox.acknowledge(first, [eventId!], []), {
    delivered: 0,
    retried: 0,
    dead: 0,
  });
  assert.equal((await row(eventId!)).delivered, false);
  await sink.deliver(second.events[0]!);
  assert.deepEqual(await outbox.acknowledge(second, [eventId!], []), {
    delivered: 1,
    retried: 0,
    dead: 0,
  });
  assert.equal(sink.attempts.length, 2);
  assert.equal(sink.stored.size, 1);
  assert.equal((await row(eventId!)).delivered, true);
});

test('two workers with separate pools never claim the same event at the same time', async () => {
  const ids = await appendEvents(60);
  const secondPool = await new DataSource(
    productDataSourceOptions(connections.outbox),
  ).initialize();
  try {
    const sink = new RecordingSink(() => new Promise((resolve) => setTimeout(resolve, 2)));

    const work = async (pool: DataSource) => {
      const outbox = new ProductAuditOutbox(pool, { batchSize: 7 });
      for (let i = 0; i < 50; i++) if ((await outbox.deliver(sink)).claimed === 0) return;
    };

    await Promise.all([work(outboxPool), work(secondPool)]);
    assert.equal(sink.attempts.length, 60);
    assert.deepEqual([...sink.stored.keys()].sort(), [...ids].sort());
    for (const id of ids) assert.equal((await row(id)).delivered, true);
  } finally {
    await secondPool.destroy();
  }
});

test('failures retry with bounded exponential backoff; a poison event is parked without blocking others', async () => {
  const [poison, healthy] = await appendEvents(2);
  const sink = new RecordingSink((event) =>
    event.eventId === poison ? Promise.reject(new Error('sink rejected')) : Promise.resolve(),
  );
  const outbox = new ProductAuditOutbox(outboxPool, { maxAttempts: 3, backoffMs: 1000 });
  assert.deepEqual(await outbox.deliver(sink), { claimed: 2, delivered: 1, retried: 1, dead: 0 });
  assert.equal((await row(healthy!)).delivered, true);
  let state = await row(poison!);
  assert.ok(state.lease_in_ms! > 800 && state.lease_in_ms! <= 1000, `${state.lease_in_ms}`);
  // Backoff not elapsed: not claimable yet.
  assert.equal((await outbox.deliver(sink)).claimed, 0);
  await expireLeases();
  assert.deepEqual(await outbox.deliver(sink), { claimed: 1, delivered: 0, retried: 1, dead: 0 });
  state = await row(poison!);
  assert.ok(state.lease_in_ms! > 1800 && state.lease_in_ms! <= 2000, `${state.lease_in_ms}`);
  await expireLeases();
  assert.deepEqual(await outbox.deliver(sink), { claimed: 1, delivered: 0, retried: 0, dead: 1 });
  await expireLeases();
  assert.equal((await outbox.deliver(sink)).claimed, 0);
  state = await row(poison!);
  assert.deepEqual([state.dead, state.delivered, state.attempts], [true, false, 3]);
});

test('a sink that never answers counts as a failed attempt after the delivery timeout', async () => {
  const [eventId] = await appendEvents(1);
  const sink = new RecordingSink(() => new Promise(() => undefined));
  const outbox = new ProductAuditOutbox(outboxPool, {
    deliveryTimeoutMs: 50,
    leaseMs: 1000,
    backoffMs: 1000,
  });
  assert.deepEqual(await outbox.deliver(sink), { claimed: 1, delivered: 0, retried: 1, dead: 0 });
  assert.equal((await row(eventId!)).delivered, false);
});

test('a worker crashing on the last allowed attempt still ends with the event parked', async () => {
  const [eventId] = await appendEvents(1);
  for (let attempt = 0; attempt < 2; attempt++) {
    // Claim, then die before sending or acknowledging.
    assert.equal(
      (await new ProductAuditOutbox(outboxPool, { maxAttempts: 2 }).claim()).events.length,
      1,
    );
    await expireLeases();
  }
  const sink = new RecordingSink();
  assert.deepEqual(await new ProductAuditOutbox(outboxPool, { maxAttempts: 2 }).deliver(sink), {
    claimed: 0,
    delivered: 0,
    retried: 0,
    dead: 1,
  });
  const state = await row(eventId!);
  assert.deepEqual([state.dead, state.delivered, state.attempts], [true, false, 2]);
  assert.equal(sink.attempts.length, 0);
});

test('a row with malformed metadata is a failed attempt, never sent, and does not block healthy events', async () => {
  const malformed = randomUUID();
  await withClient(superDb(), (client) =>
    client.query(
      `INSERT INTO audit_outbox(event_id,actor_id,event_kind,policy_revision,occurred_at,safe_metadata) VALUES($1,gen_random_uuid(),convert_to('identity.login','UTF8'),1,statement_timestamp()-interval '1 minute','{"n":1}')`,
      [malformed],
    ),
  );
  const [healthy] = await appendEvents(1);
  const sink = new RecordingSink();
  const outbox = new ProductAuditOutbox(outboxPool, { maxAttempts: 2 });
  assert.deepEqual(await outbox.deliver(sink), { claimed: 2, delivered: 1, retried: 1, dead: 0 });
  assert.equal((await row(healthy!)).delivered, true);
  await expireLeases();
  assert.deepEqual(await outbox.deliver(sink), { claimed: 1, delivered: 0, retried: 0, dead: 1 });
  assert.deepEqual(
    sink.attempts.map((e) => e.eventId),
    [healthy],
  );
  assert.equal((await row(malformed)).dead, true);
});
