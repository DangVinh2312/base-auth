import { createHash } from 'node:crypto';
import { canonicalJson } from '../core/policy.validator.js';
import type { EntityManager } from 'typeorm';

/**
 * The code-owned catalog: every table/predicate whose rows `materialized_hash` covers. Registered
 * code, never request identifiers. The reconciler, genesis and migration 012 share this one list.
 */
const codeOwned: readonly (readonly [table: string, predicate: string])[] = [
  ['resource_type', 'true'],
  ['permission_policy', 'true'],
  ['permission_catalog', 'true'],
  ['scope_template', 'true'],
  ['permission_boundary', 'true'],
  ['permission_boundary_entry', 'true'],
  ['resource_relation_definition', 'true'],
  ['role_definition', "managed_by='code'"],
  ['policy_rule', "managed_by='code'"],
  ['relation_edge', 'seed_owner IS NOT NULL'],
  ['user_boundary', 'seed_owner IS NOT NULL'],
];

/** Hash of every code-owned fact, compared with and published as `authz_state.materialized_hash`. */
export async function protectedStateHash(m: EntityManager): Promise<string> {
  const rows: unknown[] = [];
  for (const [table, predicate] of codeOwned)
    rows.push(
      await m.query(
        `SELECT to_jsonb(t) fact FROM public.${table} t WHERE ${predicate} ORDER BY to_jsonb(t)::text COLLATE "C"`,
      ),
    );
  return createHash('sha256').update(canonicalJson(rows)).digest('hex');
}

/** Genesis condition (spec 5.2): no code-owned fact, judged by the same tables and predicates. */
export async function codeOwnedCatalogIsEmpty(m: EntityManager): Promise<boolean> {
  for (const [table, predicate] of codeOwned) {
    const rows = await m.query<unknown[]>(
      `SELECT 1 FROM public.${table} t WHERE ${predicate} LIMIT 1`,
    );
    if (rows.length > 0) return false;
  }
  return true;
}
