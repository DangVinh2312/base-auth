import type { AuthorizedPlan } from '@base-authorization/core';
import type { TenantTransaction } from '../runners/tenant-transaction.runner.js';

/** Executes one obligation inside the authorizing transaction (e.g. an outbox insert). No network I/O. */
export type ObligationHandler = (tx: TenantTransaction, plan: AuthorizedPlan) => Promise<void>;

/**
 * Runs every obligation of the plan before the caller releases a payload or commits an effect.
 * A missing handler or a failing one throws, so the transaction rolls back and nothing is returned.
 */
export async function fulfillObligations(
  plan: AuthorizedPlan,
  tx: TenantTransaction,
  handlers: Readonly<Record<string, ObligationHandler>>,
): Promise<void> {
  if (plan.tenant !== tx.tenant || plan.revision !== tx.revision) {
    throw new Error('Obligations must run in the transaction that produced the plan');
  }
  for (const obligation of plan.obligations) {
    const handler = Object.hasOwn(handlers, obligation.handler)
      ? handlers[obligation.handler]
      : undefined;
    if (!handler) throw new Error(`No obligation handler registered for ${obligation.handler}`);
    await handler(tx, plan);
  }
}
