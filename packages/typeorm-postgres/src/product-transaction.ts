import {
  type DataSource,
  type EntityManager,
  QueryFailedError,
  QueryRunnerProviderAlreadyReleasedError,
} from 'typeorm';
import {
  AuthorityUnavailableError,
  TransactionConflictError,
  RUNTIME_CAPABILITY,
} from './tenant-transaction.js';

export type ProductConnectionPurpose = 'data' | 'identity' | 'authority' | 'sync' | 'bootstrap';
export type ProductTransactionMode =
  'read' | 'write' | 'identity' | 'revoke' | 'admin' | 'sync' | 'bootstrap';
export interface ProductTransaction {
  readonly mode: ProductTransactionMode;
  readonly revision: string;
  readonly manager: EntityManager;
}
export interface ProductTransactionOptions {
  readonly deadlineMs?: number;
  readonly lockTimeoutMs?: number;
  readonly maxRetries?: number;
  readonly onMetric?: (
    metric:
      | 'pool_wait'
      | 'lock_wait'
      | 'lock_hold'
      | 'transaction'
      | 'revoke_commit'
      | 'retry'
      | 'timeout'
      | 'deadlock',
    mode: ProductTransactionMode,
    value: number,
  ) => void;
}
const purposes: Record<ProductTransactionMode, ProductConnectionPurpose> = {
  read: 'data',
  write: 'data',
  identity: 'identity',
  revoke: 'identity',
  admin: 'authority',
  sync: 'sync',
  bootstrap: 'bootstrap',
};
const shared = new Set<ProductTransactionMode>(['read', 'write', 'identity']);
/** Fixed-purpose pools; transaction manager never escapes the adapter callback. */
export class ProductTransactionRunner {
  readonly #pools: Readonly<Partial<Record<ProductConnectionPurpose, DataSource>>>;
  readonly #options: ProductTransactionOptions;
  readonly #deadline: number;
  readonly #lock: number;
  readonly #retries: number;
  constructor(
    pools: Readonly<Partial<Record<ProductConnectionPurpose, DataSource>>>,
    options: ProductTransactionOptions = {},
  ) {
    this.#pools = pools;
    this.#options = options;
    this.#deadline = Math.min(options.deadlineMs ?? 2000, 2000);
    this.#lock = Math.min(options.lockTimeoutMs ?? 1000, this.#deadline, 1000);
    this.#retries = Math.min(options.maxRetries ?? 2, 2);
    for (const value of [this.#deadline, this.#lock])
      if (!Number.isSafeInteger(value) || value < 1)
        throw new TypeError('Invalid transaction timeout');
    if (!Number.isInteger(this.#retries) || this.#retries < 0)
      throw new TypeError('Invalid retry count');
  }
  #metric(
    metric: Parameters<NonNullable<ProductTransactionOptions['onMetric']>>[0],
    mode: ProductTransactionMode,
    value: number,
  ): void {
    try {
      this.#options.onMetric?.(metric, mode, value);
    } catch {
      /* Diagnostics must not change commit semantics. */
    }
  }
  /**
   * `serialize` joins a transaction-scoped advisory queue before the fence: waiters hold no fence
   * share, so queued work cannot keep an exclusive revoke off the fence. Waiters still hold a pool
   * connection (bounded by lock_timeout); a queue larger than the pool delays revoke at checkout.
   * Lock order is always advisory, then fence. `lock_wait` covers both.
   */
  async run<T>(
    mode: ProductTransactionMode,
    work: (tx: ProductTransaction) => Promise<T>,
    options: { readonly serialize?: number } = {},
  ): Promise<T> {
    const purpose = purposes[mode];
    if (!purpose) throw new TypeError('Unknown product transaction mode');
    if (options.serialize !== undefined && !Number.isSafeInteger(options.serialize))
      throw new TypeError('Invalid advisory lock key');
    const pool = this.#pools[purpose];
    if (!pool) throw new AuthorityUnavailableError('capability_unavailable');
    const requestStart = Date.now();
    for (let attempt = 0; ; attempt++) {
      const runner = pool.createQueryRunner();
      const started = Date.now();
      let locked: number | undefined;
      try {
        await runner.connect();
        this.#metric('pool_wait', mode, Date.now() - started);
        await runner.startTransaction('READ COMMITTED');
        await runner.query(
          "SELECT set_config('statement_timeout',$1,true),set_config('transaction_timeout',$1,true),set_config('lock_timeout',$2,true)",
          [`${this.#deadline}ms`, `${this.#lock}ms`],
        );
        const wait = Date.now();
        if (options.serialize !== undefined)
          await runner.query('SELECT pg_advisory_xact_lock($1)', [options.serialize]);
        const rows = await runner.manager.query<{ revision: string; required: number }[]>(
          shared.has(mode)
            ? 'SELECT public.authz_acquire_shared_fence($1)::text AS revision,0 AS required'
            : 'SELECT revision::text AS revision,min_runtime_capability AS required FROM public.authz_state WHERE singleton FOR UPDATE',
          shared.has(mode) ? [RUNTIME_CAPABILITY] : [],
        );
        locked = Date.now();
        this.#metric('lock_wait', mode, locked - wait);
        if (!rows[0]) throw new AuthorityUnavailableError('fence_missing');
        if (rows[0].required > RUNTIME_CAPABILITY)
          throw new AuthorityUnavailableError('runtime_incompatible');
        const result = await work({ mode, revision: rows[0].revision, manager: runner.manager });
        if (mode === 'revoke' || mode === 'admin' || mode === 'bootstrap')
          await runner.query('UPDATE public.authz_state SET revision=revision+1 WHERE singleton');
        if (Date.now() - started > this.#deadline || Date.now() - requestStart > 5000)
          throw new AuthorityUnavailableError('deadline');
        await runner.commitTransaction();
        if (mode === 'revoke') this.#metric('revoke_commit', mode, Date.now() - requestStart);
        return result;
      } catch (error) {
        if (runner.isTransactionActive) await runner.rollbackTransaction().catch(() => undefined);
        const code =
          error instanceof QueryFailedError
            ? (error.driverError as { code?: string }).code
            : error instanceof QueryRunnerProviderAlreadyReleasedError ||
                (error instanceof Error &&
                  'code' in error &&
                  ['ECONNREFUSED', 'ETIMEDOUT', 'ENOTFOUND', 'ECONNRESET'].includes(
                    String(error.code),
                  ))
              ? 'connection'
              : undefined;
        if (code === '40P01') this.#metric('deadlock', mode, 1);
        if (code === '55P03' || code === '57014') this.#metric('timeout', mode, 1);
        if (code && ['40P01', '40001', '55P03'].includes(code)) {
          if (attempt >= this.#retries || Date.now() - requestStart >= 5000)
            throw new TransactionConflictError(code);
          this.#metric('retry', mode, 1);
          continue;
        }
        if (
          code === 'connection' ||
          code === 'AZ001' ||
          code === 'P0002' ||
          (code && /^(08|53|57|25P0[34])/.test(code))
        )
          throw new AuthorityUnavailableError(code);
        throw error;
      } finally {
        if (locked !== undefined) this.#metric('lock_hold', mode, Date.now() - locked);
        this.#metric('transaction', mode, Date.now() - started);
        await runner.release();
      }
    }
  }
}
