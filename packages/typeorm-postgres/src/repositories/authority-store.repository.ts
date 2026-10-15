import {
  type AuthorizationCore,
  type AuthoritySnapshot,
  type BoundaryRequirement,
  type IdentityId,
  type Lifecycle,
  type PermissionFact,
  type RelationRef,
  type RuleFact,
  type Scalar,
} from '@base-authorization/core';
import type { TenantTransaction } from '../runners/tenant-transaction.runner.js';

export type AuthorityFacts = Omit<AuthoritySnapshot, 'declarations' | 'registry'>;

/**
 * Reads membership, roles, catalog, applicable rules and permission boundary bindings for one
 * identity inside a fenced tenant transaction (statements after the fence, so READ COMMITTED sees
 * every commit that preceded it). The revision is the one read under the fence.
 */
export async function readAuthorityFacts(
  tx: TenantTransaction,
  identity: IdentityId,
  core: AuthorizationCore,
): Promise<AuthorityFacts> {
  const { tenant, manager, revision } = tx;
  if (!core.isCanonicalUuid(tenant) || !core.isCanonicalUuid(identity))
    throw new TypeError('Tenant and identity must be canonical UUIDs');
  const membership = await manager.query<{ state: 'active' | 'suspended' }[]>(
    'SELECT state FROM membership WHERE tenant_id = $1 AND identity_id = $2',
    [tenant, identity],
  );
  const roles = await manager.query<{ role: string }[]>(
    `SELECT convert_from(role_key, 'UTF8') AS role FROM member_role
     WHERE tenant_id = $1 AND identity_id = $2 ORDER BY role_key`,
    [tenant, identity],
  );
  const permissions = await manager.query<
    {
      key: string;
      resource: string;
      action: string;
      policy_key: string;
      policy_version: number;
      boundary: BoundaryRequirement | null;
      lifecycle: Lifecycle;
    }[]
  >(
    `SELECT convert_from(permission_key, 'UTF8') AS key, convert_from(type_key, 'UTF8') AS resource,
            convert_from(action_key, 'UTF8') AS action, convert_from(policy_key, 'UTF8') AS policy_key,
            policy_version, boundary_requirement AS boundary, lifecycle
     FROM permission_catalog WHERE tenant_id = $1`,
    [tenant],
  );
  const rules = await manager.query<
    {
      id: string;
      permission: string;
      identity_id: string | null;
      role: string | null;
      effect: 'allow' | 'deny';
      template_key: string;
      template_version: number;
      parameters: Record<string, Scalar>;
    }[]
  >(
    `SELECT rule_id::text AS id, convert_from(permission_key, 'UTF8') AS permission,
            identity_id::text AS identity_id, convert_from(role_key, 'UTF8') AS role, effect,
            convert_from(template_key, 'UTF8') AS template_key, template_version, parameters
     FROM policy_rule
     WHERE tenant_id = $1 AND (identity_id = $2 OR role_key IN (
       SELECT role_key FROM member_role WHERE tenant_id = $1 AND identity_id = $2))`,
    [tenant, identity],
  );
  const boundaries = await manager.query<
    { permission: string; key: string; version: number; lifecycle: Lifecycle }[]
  >(
    `SELECT convert_from(b.permission_key, 'UTF8') AS permission, convert_from(b.boundary_key, 'UTF8') AS key,
            b.boundary_version AS version, d.lifecycle
     FROM member_permission_boundary b
     JOIN permission_boundary d ON d.tenant_id = b.tenant_id AND d.boundary_key = b.boundary_key
       AND d.boundary_version = b.boundary_version
     WHERE b.tenant_id = $1 AND b.identity_id = $2`,
    [tenant, identity],
  );
  return {
    tenant,
    revision,
    membership: membership[0] && { identity, state: membership[0].state },
    roles: roles.map((r) => r.role),
    permissions: permissions.map((p): PermissionFact => ({
      key: p.key,
      resource: p.resource,
      action: p.action,
      policy: { key: p.policy_key, version: p.policy_version },
      boundary: p.boundary,
      lifecycle: p.lifecycle,
    })),
    rules: rules.map((r): RuleFact => ({
      id: r.id,
      permission: r.permission,
      subject:
        r.identity_id !== null
          ? { kind: 'identity', identity: r.identity_id as IdentityId }
          : { kind: 'role', role: r.role ?? '' },
      effect: r.effect,
      template: { key: r.template_key, version: r.template_version },
      parameters: r.parameters,
    })),
    boundaries: boundaries.map((b) => ({
      identity,
      permission: b.permission,
      boundary: { key: b.key, version: b.version },
      lifecycle: b.lifecycle,
    })),
  };
}

export interface BoundaryBindingChange {
  /** Authenticated administrator; recorded in the audit event. */
  readonly actor: IdentityId;
  readonly identity: IdentityId;
  readonly permission: string;
  /** Exact definition version to bind; `null` removes the binding. */
  readonly boundary: RelationRef | null;
}

const utf8 = (value: string) => Buffer.from(value, 'utf8');

/**
 * Runtime change of one membership's boundary binding: a security fact, so only in `admin` mode
 * (exclusive fence; the runner bumps the revision on commit) and audited in the same transaction.
 * Refuses self-changes, code-owned (seeded) bindings and non-active definitions; composite FKs
 * refuse other tenants, non-members and an entry of another permission. Who may change whose
 * binding (permission, rank, delegation, affected set) is the Task 11 command service's check.
 */
export async function writeBoundaryBinding(
  tx: TenantTransaction,
  change: BoundaryBindingChange,
  core: AuthorizationCore,
): Promise<void> {
  if (tx.mode !== 'admin')
    throw new Error('Boundary bindings change only under the exclusive fence (admin mode)');
  const { actor, identity, permission, boundary } = change;
  if (!core.isCanonicalUuid(actor) || !core.isCanonicalUuid(identity))
    throw new TypeError('Actor and identity must be canonical UUIDs');
  if (actor === identity) throw new Error('An actor cannot change its own permission boundary');
  const m = tx.manager;
  const [current] = await m.query<{ seeded: boolean }[]>(
    `SELECT seed_owner IS NOT NULL AS seeded FROM member_permission_boundary
     WHERE tenant_id = $1 AND identity_id = $2 AND permission_key = $3`,
    [tx.tenant, identity, utf8(permission)],
  );
  if (current?.seeded)
    throw new Error('A code-owned boundary binding changes only through a release');
  if (boundary === null) {
    await m.query(
      `DELETE FROM member_permission_boundary WHERE tenant_id = $1 AND identity_id = $2 AND permission_key = $3`,
      [tx.tenant, identity, utf8(permission)],
    );
  } else {
    const [definition] = await m.query<{ lifecycle: Lifecycle }[]>(
      `SELECT lifecycle FROM permission_boundary WHERE tenant_id = $1 AND boundary_key = $2 AND boundary_version = $3`,
      [tx.tenant, utf8(boundary.key), boundary.version],
    );
    if (definition?.lifecycle !== 'active')
      throw new Error('Only an active boundary definition can be bound');
    await m.query(
      `INSERT INTO member_permission_boundary (tenant_id, identity_id, permission_key, boundary_key, boundary_version)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (tenant_id, identity_id, permission_key)
       DO UPDATE SET boundary_key = EXCLUDED.boundary_key, boundary_version = EXCLUDED.boundary_version`,
      [tx.tenant, identity, utf8(permission), utf8(boundary.key), boundary.version],
    );
  }
  await m.query(
    `INSERT INTO audit_outbox (tenant_id, event_id, actor_id, event_kind, permission_key, policy_revision, occurred_at, safe_metadata)
     VALUES ($1, gen_random_uuid(), $2, $3, $4, $5, clock_timestamp(), $6)`,
    [
      tx.tenant,
      actor,
      utf8('boundary.binding'),
      utf8(permission),
      // The runner bumps the revision by exactly one when this admin transaction commits.
      String(BigInt(tx.revision) + 1n),
      JSON.stringify({
        identity,
        boundary: boundary?.key ?? null,
        version: boundary?.version ?? null,
      }),
    ],
  );
}
