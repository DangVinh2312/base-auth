import {
  type AuthorizationCore,
  type AuthoritySnapshot,
  type TenantId,
  type TrustedPrincipal,
  type ValidatedDeclarations,
} from '@base-authorization/core';
import {
  type EntityManager,
  QueryFailedError,
  type QueryRunner,
  QueryRunnerProviderAlreadyReleasedError,
} from 'typeorm';
import { readAuthorityFacts } from '../repositories/authority-store.repository.js';
import {
  type ConnectionPurpose,
  parseRoutableTenant,
  type TenantDataSourceRegistry,
} from '../datasource.registry.js';

/**
 * Classified before the transaction starts; a transaction never upgrades shared → exclusive.
 * read/write: data credential + shared fence. admin: authority credential + exclusive fence, revision
 * bumped on success. sync: sync credential + exclusive fence; the reconciler bumps revision itself.
 */
export type TransactionMode = 'read' | 'write' | 'admin' | 'sync';

export interface TenantTransaction {
  readonly tenant: TenantId;
  readonly mode: TransactionMode;
  /** Authority revision read under the fence in this transaction. */
  readonly revision: string;
  /** The transaction's own `QueryRunner.manager`; never a global repository. */
  readonly manager: EntityManager;
}

export interface TransactionOptions {
  /** Whole-transaction deadline, enforced by PostgreSQL (statement + transaction timeout). */
  readonly deadlineMs?: number;
  readonly lockTimeoutMs?: number;
  /** Extra attempts for 40P01/40001/55P03; the reference profile allows at most 2. */
  readonly maxRetries?: number;

  /** Metrics hook, awaited before the next attempt. */
  readonly onRetry?: (code: string, attempt: number) => void | Promise<void>;
}

/** Retryable conflict that persisted after all attempts (maps to 409). */
export class TransactionConflictError extends Error {
  constructor(readonly code: string) {
    super(`Transaction conflict (${code}) persisted after retries`);
  }
}

/** Authority could not decide: timeout, lost connection, missing fence (maps to 503). */
export class AuthorityUnavailableError extends Error {
  constructor(readonly code: string) {
    super(`Authority unavailable (${code})`);
  }
}

/**
 * Authorization features this runtime enforces; sync raises the tenant's minimum to it. 1 = permission
 * boundaries (ADR 0003). Bump when a release can carry facts that an older runtime would ignore.
 */
export const RUNTIME_CAPABILITY = 1;

const retryable = new Set(['40P01', '40001', '55P03']);
const unavailable = /^(08|53|57|25P0[34])/;
const purposeOf: Readonly<Record<TransactionMode, ConnectionPurpose>> = {
  read: 'data',
  write: 'data',
  admin: 'authority',
  sync: 'sync',
};

function sqlState(error: unknown): string | undefined {
  // TypeORM releases a query runner whose connection emitted an error (e.g. terminated backend).
  if (error instanceof QueryRunnerProviderAlreadyReleasedError) return 'connection';
  if (!(error instanceof QueryFailedError)) return undefined;
  const code = (error.driverError as { code?: unknown } | undefined)?.code;
  return typeof code === 'string' ? code : 'connection';
}

/**
 * Runs work in one tenant transaction: READ COMMITTED, DB-enforced timeouts, fence first (lock
 * order: fence → everything else), bounded retry of the whole transaction. Side effects belong in
 * the transaction (outbox), so a retried attempt never repeats a committed effect.
 */
export class TenantTransactionRunner {
  readonly #registry: TenantDataSourceRegistry;
  readonly #deadlineMs: number;
  readonly #lockTimeoutMs: number;
  readonly #maxRetries: number;
  readonly #onRetry: TransactionOptions['onRetry'];

  constructor(registry: TenantDataSourceRegistry, options: TransactionOptions = {}) {
    this.#registry = registry;
    this.#deadlineMs = options.deadlineMs ?? 2_000;
    this.#lockTimeoutMs = Math.min(options.lockTimeoutMs ?? 1_000, this.#deadlineMs);
    this.#maxRetries = Math.min(options.maxRetries ?? 2, 2);
    this.#onRetry = options.onRetry;
    for (const value of [this.#deadlineMs, this.#lockTimeoutMs]) {
      if (!Number.isSafeInteger(value) || value < 1)
        throw new TypeError('Timeouts must be positive integers');
    }
  }

  async run<T>(
    tenant: TenantId,
    mode: TransactionMode,
    work: (tx: TenantTransaction) => Promise<T>,
  ): Promise<T> {
    parseRoutableTenant(tenant);
    const purpose = purposeOf[mode];
    if (!purpose) throw new TypeError('Unknown transaction mode');
    for (let attempt = 0; ; attempt++) {
      try {
        return await this.#attempt(tenant, mode, purpose, work);
      } catch (error) {
        const code = sqlState(error);
        if (code !== undefined && retryable.has(code)) {
          if (attempt >= this.#maxRetries) throw new TransactionConflictError(code);
          await this.#onRetry?.(code, attempt + 1);
          await new Promise((resolve) =>
            setTimeout(resolve, 10 + Math.random() * 40 * (attempt + 1)),
          );
          continue;
        }
        if (code === 'AZ001') throw new AuthorityUnavailableError('runtime_incompatible');
        if (
          code !== undefined &&
          (code === 'connection' || code === 'P0002' || unavailable.test(code))
        ) {
          throw new AuthorityUnavailableError(code);
        }
        throw error;
      }
    }
  }

  async #attempt<T>(
    tenant: TenantId,
    mode: TransactionMode,
    purpose: ConnectionPurpose,
    work: (tx: TenantTransaction) => Promise<T>,
  ): Promise<T> {
    const lease = await this.#registry.acquire(tenant, purpose);
    let runner: QueryRunner | undefined;
    try {
      runner = lease.dataSource.createQueryRunner();
      await runner.connect();
      await runner.startTransaction('READ COMMITTED');
      const started = Date.now();
      await runner.query(
        `SELECT set_config('statement_timeout', $1, true), set_config('transaction_timeout', $1, true),
                set_config('lock_timeout', $2, true)`,
        [`${this.#deadlineMs}ms`, `${this.#lockTimeoutMs}ms`],
      );
      // Fence first, then authority facts in later statements (fresh READ COMMITTED snapshots).
      // A tenant that requires a newer runtime is refused under the fence (AZ001 / below).
      const fence = await runner.manager.query<{ revision: string; required: number }[]>(
        mode === 'read' || mode === 'write'
          ? 'SELECT public.authz_acquire_shared_fence($1, $2)::text AS revision, 0 AS required'
          : `SELECT revision::text AS revision, min_runtime_capability AS required
             FROM public.authz_fence WHERE tenant_id = $1 FOR UPDATE`,
        mode === 'read' || mode === 'write' ? [tenant, RUNTIME_CAPABILITY] : [tenant],
      );
      const revision = fence[0]?.revision;
      if (revision === undefined) throw new AuthorityUnavailableError('fence_missing');
      if (fence[0]!.required > RUNTIME_CAPABILITY)
        throw new AuthorityUnavailableError('runtime_incompatible');
      const result = await work({ tenant, mode, revision, manager: runner.manager });
      if (mode === 'admin') {
        await runner.query(
          'UPDATE public.authz_fence SET revision = revision + 1 WHERE tenant_id = $1',
          [tenant],
        );
      }
      if (Date.now() - started > this.#deadlineMs) throw new AuthorityUnavailableError('deadline');
      await runner.commitTransaction();
      return result;
    } catch (error) {
      if (runner?.isTransactionActive) await runner.rollbackTransaction().catch(() => undefined);
      throw error;
    } finally {
      await runner?.release();
      await lease.release();
    }
  }
}

export interface AuthorityRegistry {
  readonly validators: AuthoritySnapshot['registry']['validators'];
  readonly obligationHandlers: readonly string[];
}

/**
 * `AuthorityPort.withSnapshot`: one transaction holds the fence, the authority facts (permission
 * boundary bindings included), the plan and the data access, all at one revision.
 */
export class PostgresAuthority {
  readonly #core: AuthorizationCore;
  readonly #runner: TenantTransactionRunner;
  readonly #declarations: ValidatedDeclarations;
  readonly #registry: AuthorityRegistry;

  /** `declarations` must come from `core`, which also checks the identities it reads. */
  constructor(
    core: AuthorizationCore,
    runner: TenantTransactionRunner,
    declarations: ValidatedDeclarations,
    registry: AuthorityRegistry,
  ) {
    if (!core.isValidated(declarations))
      throw new TypeError('Declarations must come from validate() of this authorization core');
    this.#core = core;
    this.#runner = runner;
    this.#declarations = declarations;
    this.#registry = registry;
  }

  withSnapshot<T>(
    principal: TrustedPrincipal,
    tenant: TenantId,
    mode: 'read' | 'write' | 'admin',
    run: (snapshot: AuthoritySnapshot, tx: TenantTransaction) => Promise<T>,
  ): Promise<T> {
    return this.#runner.run(tenant, mode, async (tx) => {
      const facts = await readAuthorityFacts(tx, principal.id, this.#core);
      return run({ ...facts, declarations: this.#declarations, registry: this.#registry }, tx);
    });
  }
}
