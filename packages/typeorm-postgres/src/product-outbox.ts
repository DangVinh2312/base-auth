import { randomUUID } from 'node:crypto';
import type { DataSource, EntityManager } from 'typeorm';

/** One audit event as handed to a sink; `eventId` is the idempotency key. */
export interface ProductAuditEnvelope {
  readonly eventId: string;
  readonly kind: string;
  readonly actorId: string;
  readonly permission: string | null;
  readonly objectId: string | null;
  readonly policyRevision: string;
  /** UTC, six fractional digits. */
  readonly occurredAt: string;
  readonly reason: string | null;
  readonly metadata: Readonly<Record<string, string>>;
  /** 1-based delivery attempt of this event, counted at claim. */
  readonly attempt: number;
}
/**
 * Delivery port. Delivery is at-least-once: a crash after send and before acknowledgement sends
 * again, so a sink must deduplicate by `eventId`. Resolve only after the sink durably accepted it.
 */
export interface ProductAuditSink {
  deliver(event: ProductAuditEnvelope): Promise<void>;
}
export interface ProductOutboxClaim {
  readonly token: string;
  readonly events: readonly ProductAuditEnvelope[];
  /** Claimed rows whose stored metadata is not a flat string map; never sent, counted as failed. */
  readonly malformed: readonly string[];
  /** Events parked by this claim: their last attempt's lease expired without acknowledgement. */
  readonly parked: number;
}
export interface ProductOutboxOptions {
  readonly batchSize?: number;
  readonly leaseMs?: number;
  readonly maxAttempts?: number;
  readonly backoffMs?: number;
  readonly maxBackoffMs?: number;
  readonly deliveryTimeoutMs?: number;
}

function bounded(name: string, value: number, min: number, max: number): number {
  if (!Number.isSafeInteger(value) || value < min || value > max)
    throw new RangeError(`${name} must be an integer ${min}-${max}`);
  return value;
}
const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/**
 * Audit outbox delivery over the `outbox` login: claims a batch with a lease (`SKIP LOCKED`) in one
 * short transaction, delivers with no transaction or fence open, then acknowledges in another short
 * transaction. Only the current lease holder can acknowledge. Attempts are counted at claim; an
 * event whose last allowed attempt expired unacknowledged (worker crashed) is parked at the next
 * claim, so a crash loop also ends in the parked (dead) state after `maxAttempts`.
 */
export class ProductAuditOutbox {
  readonly #pool: DataSource;
  readonly #batch: number;
  readonly #lease: number;
  readonly #attempts: number;
  readonly #backoff: number;
  readonly #maxBackoff: number;
  readonly #timeout: number;

  constructor(pool: DataSource, options: ProductOutboxOptions = {}) {
    this.#pool = pool;
    this.#batch = bounded('batchSize', options.batchSize ?? 20, 1, 100);
    this.#lease = bounded('leaseMs', options.leaseMs ?? 300_000, 1000, 3_600_000);
    this.#attempts = bounded('maxAttempts', options.maxAttempts ?? 8, 1, 20);
    this.#backoff = bounded('backoffMs', options.backoffMs ?? 1000, 1, 3_600_000);
    this.#maxBackoff = bounded(
      'maxBackoffMs',
      options.maxBackoffMs ?? 300_000,
      this.#backoff,
      86_400_000,
    );
    this.#timeout = bounded('deliveryTimeoutMs', options.deliveryTimeoutMs ?? 10_000, 1, 600_000);
    // Sequential sends must finish inside the lease, or another worker may take the batch over.
    if (this.#timeout * this.#batch > this.#lease)
      throw new RangeError('leaseMs must cover batchSize * deliveryTimeoutMs');
  }

  async #transaction<T>(work: (manager: EntityManager) => Promise<T>): Promise<T> {
    const runner = this.#pool.createQueryRunner();
    try {
      await runner.connect();
      await runner.startTransaction('READ COMMITTED');
      await runner.query(
        "SELECT set_config('statement_timeout','2000ms',true),set_config('lock_timeout','1000ms',true)",
      );
      const result = await work(runner.manager);
      await runner.commitTransaction();
      return result;
    } catch (error) {
      if (runner.isTransactionActive) await runner.rollbackTransaction().catch(() => undefined);
      throw error;
    } finally {
      await runner.release();
    }
  }

  // Data-modifying statements are wrapped as `WITH … SELECT`: TypeORM returns [rows, count] for a
  // bare UPDATE … RETURNING.
  async claim(): Promise<ProductOutboxClaim> {
    const token = randomUUID();
    const { rows, parked } = await this.#transaction(async (m) => {
      const [parkedRows] = await m.query<{ n: number }[]>(
        `WITH parked AS (UPDATE audit_outbox SET dead_at=statement_timestamp(),lease_token=NULL,lease_until=NULL
          WHERE event_id IN (SELECT event_id FROM audit_outbox
            WHERE delivered_at IS NULL AND dead_at IS NULL AND delivery_attempts>=$1
              AND (lease_until IS NULL OR lease_until<=statement_timestamp()) FOR UPDATE SKIP LOCKED)
          RETURNING 1) SELECT count(*)::int n FROM parked`,
        [this.#attempts],
      );
      const claimed = await m.query<
        {
          event_id: string;
          kind: string;
          actor_id: string;
          permission: string | null;
          object_id: string | null;
          policy_revision: string;
          occurred_at: string;
          reason: string | null;
          safe_metadata: unknown;
          delivery_attempts: number;
        }[]
      >(
        `WITH claimable AS (SELECT event_id FROM audit_outbox
          WHERE delivered_at IS NULL AND dead_at IS NULL AND delivery_attempts<$4
            AND (lease_until IS NULL OR lease_until<=statement_timestamp())
          ORDER BY occurred_at,event_id LIMIT $1 FOR UPDATE SKIP LOCKED)
        , claimed AS (UPDATE audit_outbox o SET lease_token=$2,lease_until=statement_timestamp()+make_interval(secs=>$3::float8/1000),delivery_attempts=o.delivery_attempts+1
        FROM claimable c WHERE o.event_id=c.event_id
        RETURNING o.event_id,convert_from(o.event_kind,'UTF8') kind,o.actor_id,convert_from(o.permission_key,'UTF8') permission,o.object_id,
          o.policy_revision::text policy_revision,to_char(o.occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') occurred_at,
          o.reason,o.safe_metadata,o.delivery_attempts,o.occurred_at sort_at)
        SELECT * FROM claimed ORDER BY sort_at,event_id`,
        [this.#batch, token, this.#lease, this.#attempts],
      );
      return { rows: claimed, parked: parkedRows?.n ?? 0 };
    });
    const events: ProductAuditEnvelope[] = [];
    const malformed: string[] = [];
    for (const r of rows) {
      if (
        !isRecord(r.safe_metadata) ||
        Object.values(r.safe_metadata).some((v) => typeof v !== 'string')
      ) {
        malformed.push(r.event_id);
        continue;
      }
      events.push({
        eventId: r.event_id,
        kind: r.kind,
        actorId: r.actor_id,
        permission: r.permission,
        objectId: r.object_id,
        policyRevision: r.policy_revision,
        occurredAt: r.occurred_at,
        reason: r.reason,
        metadata: Object.freeze({ ...(r.safe_metadata as Record<string, string>) }),
        attempt: r.delivery_attempts,
      });
    }
    return { token, events, malformed, parked };
  }

  /** Marks delivered and schedules retries (exponential backoff) or parks after `maxAttempts`. */
  async acknowledge(
    claim: ProductOutboxClaim,
    delivered: readonly string[],
    failed: readonly string[],
  ): Promise<{ delivered: number; retried: number; dead: number }> {
    return this.#transaction(async (m) => {
      const done = await m.query<{ n: number }[]>(
        `WITH done AS (UPDATE audit_outbox SET delivered_at=statement_timestamp(),lease_token=NULL,lease_until=NULL
          WHERE event_id=ANY($1::uuid[]) AND lease_token=$2 AND delivered_at IS NULL RETURNING 1) SELECT count(*)::int n FROM done`,
        [delivered, claim.token],
      );
      const outcome = await m.query<{ dead: boolean }[]>(
        `WITH failed AS (UPDATE audit_outbox SET lease_token=NULL,
          dead_at=CASE WHEN delivery_attempts>=$3 THEN statement_timestamp() END,
          lease_until=CASE WHEN delivery_attempts>=$3 THEN NULL
            ELSE statement_timestamp()+make_interval(secs=>LEAST($5::float8,$4::float8*power(2,delivery_attempts-1))/1000) END
          WHERE event_id=ANY($1::uuid[]) AND lease_token=$2 AND delivered_at IS NULL RETURNING dead_at IS NOT NULL dead)
        SELECT * FROM failed`,
        [failed, claim.token, this.#attempts, this.#backoff, this.#maxBackoff],
      );
      return {
        delivered: done[0]?.n ?? 0,
        retried: outcome.filter((r) => !r.dead).length,
        dead: outcome.filter((r) => r.dead).length,
      };
    });
  }

  /** One claim, sequential sends with a timeout each, one acknowledgement. */
  async deliver(
    sink: ProductAuditSink,
  ): Promise<{ claimed: number; delivered: number; retried: number; dead: number }> {
    const claim = await this.claim();
    const claimed = claim.events.length + claim.malformed.length;
    if (claimed === 0) return { claimed: 0, delivered: 0, retried: 0, dead: claim.parked };
    const delivered: string[] = [];
    const failed: string[] = [...claim.malformed];
    for (const event of claim.events) {
      let timer: NodeJS.Timeout | undefined;
      try {
        await Promise.race([
          sink.deliver(event),
          new Promise<never>((_, reject) => {
            timer = setTimeout(() => reject(new Error('Audit delivery timed out')), this.#timeout);
          }),
        ]);
        delivered.push(event.eventId);
      } catch {
        // Sink errors may carry event data; only the outcome is kept (retry or park).
        failed.push(event.eventId);
      } finally {
        clearTimeout(timer);
      }
    }
    const outcome = await this.acknowledge(claim, delivered, failed);
    return { claimed, ...outcome, dead: outcome.dead + claim.parked };
  }
}
