import type { UserAuthorizedPlan } from '@base-authorization/core';
import type { ProductTransaction } from '../runners/product-transaction.runner.js';
import { appendProductAudit } from '../repositories/product-audit.repository.js';

/** Runs inside the authorizing transaction before payload/commit; no network I/O. */
export type ProductObligationHandler = (
  tx: ProductTransaction,
  plan: UserAuthorizedPlan,
) => Promise<void>;

export type ProductObligationRegistry = Readonly<Record<string, ProductObligationHandler>>;

/** Default handlers chosen at composition; `audit@1` appends the access event. */
export const productObligations: ProductObligationRegistry = Object.freeze({
  'audit@1': (tx: ProductTransaction, plan: UserAuthorizedPlan) =>
    appendProductAudit(tx, {
      kind: `access.${plan.action}`,
      actor: plan.userId,
      permission: plan.permission,
    }),
});

/**
 * Fulfils every obligation of the plan in its own transaction. A missing or failing handler throws,
 * so the transaction rolls back and no payload or effect is released.
 */
export async function fulfillProductObligations(
  tx: ProductTransaction,
  plan: UserAuthorizedPlan,
  handlers: ProductObligationRegistry,
): Promise<void> {
  if (plan.revision !== tx.revision)
    throw new Error('Obligations must run in the transaction that produced the plan');
  for (const obligation of plan.obligations) {
    const handler = Object.hasOwn(handlers, obligation.handler)
      ? handlers[obligation.handler]
      : undefined;
    if (!handler) throw new Error(`No obligation handler registered for ${obligation.handler}`);
    await handler(tx, plan);
  }
}
