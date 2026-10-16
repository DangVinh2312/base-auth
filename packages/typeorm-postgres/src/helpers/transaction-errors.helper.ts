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
 * Authorization features this runtime enforces; sync raises the database minimum to it. 1 = permission
 * boundaries (ADR 0003). Bump when a release can carry facts that an older runtime would ignore.
 */
export const RUNTIME_CAPABILITY = 1;
