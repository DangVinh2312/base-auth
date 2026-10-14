import { createHash } from 'node:crypto';
import {
  type AuthorizationCore,
  canonicalJson,
  type IdentityId,
  type Key,
  refKey,
  type RelationRef,
  type Scalar,
  type SystemDeclarations,
  type TenantId,
  type ValidatedDeclarations,
} from '@base-authorization/core';
import { type EntityManager, QueryFailedError } from 'typeorm';
import { RUNTIME_CAPABILITY, type TenantTransactionRunner } from './tenant-transaction.js';

export interface CodeRole {
  readonly key: string;
  readonly authorityLevel: number;
  readonly label: string;
}
/** Default grant created only when its permission first appears in a tenant's catalog. */
export interface DefaultGrant {
  readonly permission: string;
  readonly role: string;
  readonly template: RelationRef;
  readonly parameters: Readonly<Record<string, Scalar>>;
}
/** Code-owned resource → resource tuple (spec 7.1); runtime tuples are never touched. */
export interface RelationSeed {
  readonly owner: string;
  readonly key: string;
  readonly relation: RelationRef;
  readonly source: { readonly type: string; readonly key: Key };
  readonly target: { readonly type: string; readonly key: Key };
  readonly startsAt: string;
  readonly expiresAt?: string;
}
export interface SeedRemoval {
  readonly owner: string;
  readonly key: string;
}
/**
 * Code-owned permission boundary binding (e.g. a service member). Runtime bindings (no owner) are
 * never overwritten; a seed is removed only by an explicit removal from the same owner.
 */
export interface BoundaryBindingSeed {
  readonly owner: string;
  readonly identity: IdentityId;
  readonly permission: string;
  readonly boundary: RelationRef;
}
export interface BoundaryBindingRemoval {
  readonly owner: string;
  readonly identity: IdentityId;
  readonly permission: string;
}

/**
 * Release content from a trusted deployment artifact (never from an HTTP client or tenant API).
 * Nothing here is signed yet: release signing is deferred until before staging (ADR 0004).
 */
export interface ReleaseSource {
  /** Monotonic release sequence assigned by the pipeline (int64 decimal). */
  readonly sequence: string;
  /** Sequence the tenant must currently be at ('0' for the first release). */
  readonly predecessor: string;
  readonly declarations: SystemDeclarations;
  readonly roles: readonly CodeRole[];
  readonly defaultGrants: readonly DefaultGrant[];
  readonly seeds: readonly RelationSeed[];
  readonly removeSeeds: readonly SeedRemoval[];
  readonly boundaryBindings: readonly BoundaryBindingSeed[];
  readonly removeBoundaryBindings: readonly BoundaryBindingRemoval[];
}

/**
 * Output of `prepareRelease`: a manifest from a trusted deployment, validated and frozen. "Verified"
 * means validated in-process (structure, references, types, size) — not a cryptographic signature
 * check; the trust limit is documented in ADR 0004.
 */
export interface VerifiedReleaseManifest extends Omit<ReleaseSource, 'declarations'> {
  readonly declarations: ValidatedDeclarations;
  /** SHA-256 (hex) of the canonical content; sequence/predecessor are not part of it. */
  readonly hash: string;
}

export interface SyncResult {
  readonly changed: boolean;
  readonly revision: string;
  readonly manifestHash: string;
}

export type RejectReason =
  | 'invalid_release'
  | 'missing_capability'
  | 'conflicting_release'
  | 'downgrade'
  | 'predecessor_mismatch'
  | 'immutable_definition'
  | 'collision'
  | 'missing_reference'
  | 'definition_in_use'
  | 'not_ready';

/** The tenant is not ready for this build; nothing was written. */
export class ReleaseRejectedError extends Error {
  constructor(
    readonly reason: RejectReason,
    detail: string,
  ) {
    super(`Release rejected (${reason}): ${detail}`);
  }
}

/** Release → the authorization core that validated it (provenance; never part of the hash). */
const verified = new WeakMap<object, AuthorizationCore>();
const sizeLimits = {
  roles: 200,
  defaultGrants: 1_000,
  seeds: 1_000,
  removeSeeds: 1_000,
  boundaryBindings: 1_000,
  removeBoundaryBindings: 1_000,
};
const identifier = /^[a-z][A-Za-z0-9_]*(\.[a-z][A-Za-z0-9_]*)*$/;
const ownerKey = /^[a-z][a-z0-9._-]{0,127}$/;
const reject = (reason: RejectReason, detail: string): never => {
  throw new ReleaseRejectedError(reason, detail);
};
const sha256 = (text: string) => createHash('sha256').update(text).digest('hex');
const utf8 = (value: string) => Buffer.from(value, 'utf8');

/**
 * Validates and freezes a release from a trusted deployment artifact before any lock is taken (size
 * limits, references, typed parameters and keys) and computes its canonical hash. It does not verify
 * a signature (none exists yet, ADR 0004). `reconcile` accepts only these objects, and only from the
 * same `core`. The core is provenance, not content: it never enters the hash.
 */
export function prepareRelease(
  source: ReleaseSource,
  core: AuthorizationCore,
): VerifiedReleaseManifest {
  const sequence = core.canonicalInt64(source.sequence);
  const predecessor = core.canonicalInt64(source.predecessor);
  if (
    !sequence ||
    !predecessor ||
    BigInt(sequence) < 1n ||
    BigInt(predecessor) < 0n ||
    BigInt(predecessor) >= BigInt(sequence)
  ) {
    reject('invalid_release', 'sequence must be a positive int64 above its predecessor');
  }
  const validated = core.validate(source.declarations);
  if (!validated.ok) return reject('invalid_release', validated.errors.join('; '));
  const declarations = validated.declarations;
  for (const [name, limit] of Object.entries(sizeLimits)) {
    if (source[name as keyof typeof sizeLimits].length > limit)
      reject('invalid_release', `too many ${name}`);
  }

  const roleKeys = new Set<string>();
  for (const role of source.roles) {
    if (!identifier.test(role.key) || roleKeys.has(role.key))
      reject('invalid_release', `role ${role.key}`);
    if (
      !Number.isSafeInteger(role.authorityLevel) ||
      role.authorityLevel < 0 ||
      role.authorityLevel > 1000
    ) {
      reject('invalid_release', `role ${role.key} authority level`);
    }
    if (role.label.trim().length === 0 || role.label.length > 120)
      reject('invalid_release', `role ${role.key} label`);
    roleKeys.add(role.key);
  }

  const defaultGrants = source.defaultGrants.map((grant) => {
    const [resource = '', action = ''] = grant.permission.split('.');
    const declared = Object.hasOwn(declarations.resources, resource)
      ? declarations.resources[resource]
      : undefined;
    const template = declarations.templates[refKey(grant.template)];
    if (
      !declared ||
      !Object.hasOwn(declared.actions, action) ||
      `${resource}.${action}` !== grant.permission
    ) {
      reject('invalid_release', `default grant for unknown permission ${grant.permission}`);
    }
    if (!roleKeys.has(grant.role))
      reject('invalid_release', `default grant for unknown code role ${grant.role}`);
    if (!template || template.resource !== resource)
      reject('invalid_release', `default grant template ${refKey(grant.template)}`);
    const names = Object.keys(template!.parameters);
    if (names.length !== Object.keys(grant.parameters).length)
      reject('invalid_release', 'default grant parameters');
    const parameters: Record<string, Scalar> = {};
    for (const name of names) {
      const value = Object.hasOwn(grant.parameters, name)
        ? core.normalizeValue(template!.parameters[name]!, grant.parameters[name])
        : undefined;
      if (value === undefined) return reject('invalid_release', `default grant parameter ${name}`);
      parameters[name] = value;
    }
    return {
      permission: grant.permission,
      role: grant.role,
      template: { key: grant.template.key, version: grant.template.version },
      parameters,
    };
  });

  const seedIds = new Set<string>();
  const seeds = source.seeds.map((seed) => {
    if (
      !ownerKey.test(seed.owner) ||
      !ownerKey.test(seed.key) ||
      seedIds.has(`${seed.owner}/${seed.key}`)
    ) {
      reject('invalid_release', `seed ${seed.owner}/${seed.key}`);
    }
    seedIds.add(`${seed.owner}/${seed.key}`);
    const relation = declarations.relations[refKey(seed.relation)];
    if (
      !relation ||
      relation.target.kind !== 'resource' ||
      relation.sourceType !== seed.source.type ||
      relation.target.type !== seed.target.type
    ) {
      return reject('invalid_release', `seed ${seed.key} relation does not match its endpoints`);
    }
    const startsAt = core.canonicalTimestamp(seed.startsAt);
    const expiresAt =
      seed.expiresAt === undefined ? undefined : core.canonicalTimestamp(seed.expiresAt);
    if (
      !startsAt ||
      (seed.expiresAt !== undefined &&
        (!expiresAt || core.compareValues('timestamp', expiresAt, startsAt) <= 0))
    ) {
      reject('invalid_release', `seed ${seed.key} validity window`);
    }
    const endpoint = (end: RelationSeed['source']) => ({
      type: end.type,
      key: core.parseKey(declarations.resources[end.type]!.keyKind, end.key.value),
    });
    return {
      owner: seed.owner,
      key: seed.key,
      relation: { key: seed.relation.key, version: seed.relation.version },
      source: endpoint(seed.source),
      target: endpoint(seed.target),
      startsAt: startsAt!,
      ...(expiresAt ? { expiresAt } : {}),
    };
  });
  const removeSeeds = source.removeSeeds.map((removal) => {
    if (!ownerKey.test(removal.owner) || !ownerKey.test(removal.key))
      reject('invalid_release', 'seed removal');
    return { owner: removal.owner, key: removal.key };
  });

  const bindingIds = new Set<string>();
  const boundaryBindings = source.boundaryBindings.map((seed) => {
    const id = `${seed.identity}/${seed.permission}`;
    if (!ownerKey.test(seed.owner) || !core.isCanonicalUuid(seed.identity) || bindingIds.has(id))
      reject('invalid_release', `boundary binding ${seed.owner}/${id}`);
    bindingIds.add(id);
    const ref = refKey(seed.boundary);
    const boundary = Object.hasOwn(declarations.boundaries, ref)
      ? declarations.boundaries[ref]
      : undefined;
    if (
      !boundary ||
      boundary.lifecycle === 'retired' ||
      !boundary.entries.some((entry) => entry.permission === seed.permission)
    ) {
      reject('invalid_release', `boundary binding ${id}: ${ref} has no usable entry for it`);
    }
    return {
      owner: seed.owner,
      identity: seed.identity,
      permission: seed.permission,
      boundary: { key: seed.boundary.key, version: seed.boundary.version },
    };
  });
  const removeBoundaryBindings = source.removeBoundaryBindings.map((removal) => {
    if (!ownerKey.test(removal.owner) || !core.isCanonicalUuid(removal.identity))
      reject('invalid_release', 'boundary binding removal');
    return { owner: removal.owner, identity: removal.identity, permission: removal.permission };
  });

  const byJson = <T>(items: T[]) =>
    [...items].sort((a, b) => (canonicalJson(a) < canonicalJson(b) ? -1 : 1));
  const roles = source.roles.map((r) => ({
    key: r.key,
    authorityLevel: r.authorityLevel,
    label: r.label,
  }));
  const hash = sha256(
    canonicalJson({
      declarations: JSON.parse(declarations.canonical) as unknown,
      roles: byJson(roles),
      defaultGrants: byJson(defaultGrants),
      seeds: byJson(seeds),
      removeSeeds: byJson(removeSeeds),
      boundaryBindings: byJson(boundaryBindings),
      removeBoundaryBindings: byJson(removeBoundaryBindings),
    }),
  );
  const manifest: VerifiedReleaseManifest = Object.freeze({
    sequence: sequence!,
    predecessor: predecessor!,
    declarations,
    roles,
    defaultGrants,
    seeds,
    removeSeeds,
    boundaryBindings,
    removeBoundaryBindings,
    hash,
  });
  verified.set(manifest, core);
  return manifest;
}

export interface ReconcilerOptions {
  /** The runtime's core; releases prepared by another core are refused. */
  readonly core: AuthorizationCore;
  /** Deployment workload identity recorded in audit events. */
  readonly actor: IdentityId;
  /** Validators and obligation handlers this binary registers; a release needing more is refused. */
  readonly capabilities: {
    readonly validators: readonly string[];
    readonly obligationHandlers: readonly string[];
  };
}

/**
 * `reconcile(tenant, release)` (spec 7.2) with the sync credential: exclusive fence, sequence/hash
 * protocol, code-owned DML only, audit + revision in the same transaction. No DDL; runtime tuples,
 * runtime boundary bindings, tenant roles and tenant rules are never overwritten; an older binary
 * never downgrades, and a published release raises the tenant's minimum runtime capability.
 */
export class ManifestReconciler {
  readonly #runner: TenantTransactionRunner;
  readonly #options: ReconcilerOptions;

  constructor(runner: TenantTransactionRunner, options: ReconcilerOptions) {
    if (!options.core.isCanonicalUuid(options.actor))
      throw new TypeError('Reconciler actor must be a canonical UUID');
    this.#runner = runner;
    this.#options = options;
  }

  async reconcile(tenant: TenantId, release: VerifiedReleaseManifest): Promise<SyncResult> {
    if (verified.get(release) !== this.#options.core)
      reject('invalid_release', 'release was not prepared by prepareRelease with this core');
    const needed = [
      ...release.declarations.capabilities.validators,
      ...release.declarations.capabilities.obligationHandlers,
    ];
    const available = new Set([
      ...this.#options.capabilities.validators,
      ...this.#options.capabilities.obligationHandlers,
    ]);
    const missing = needed.filter((name) => !available.has(name));
    if (missing.length > 0) reject('missing_capability', missing.join(', '));

    return this.#runner.run(tenant, 'sync', async (tx) => {
      const m = tx.manager;
      const [current] = await m.query<{ sequence: string; hash: string }[]>(
        `SELECT release_sequence::text AS sequence, encode(manifest_hash, 'hex') AS hash FROM authz_fence WHERE tenant_id = $1`,
        [tenant],
      );
      if (!current) return reject('not_ready', 'tenant fence is missing');
      const currentSequence = BigInt(current.sequence);
      const nextSequence = BigInt(release.sequence);
      if (nextSequence === currentSequence) {
        if (current.hash !== release.hash)
          reject(
            'conflicting_release',
            `sequence ${release.sequence} already published with another hash`,
          );
        await verifyApplied(m, tenant, release);
        return { changed: false, revision: tx.revision, manifestHash: release.hash };
      }
      if (nextSequence < currentSequence)
        reject('downgrade', `tenant is at ${current.sequence}, release is ${release.sequence}`);
      if (BigInt(release.predecessor) !== currentSequence) {
        reject(
          'predecessor_mismatch',
          `release expects ${release.predecessor}, tenant is at ${current.sequence}`,
        );
      }

      await apply(m, tenant, release);
      await m.query(
        `UPDATE authz_fence SET revision = revision + 1, manifest_hash = decode($2, 'hex'), release_sequence = $3,
           min_runtime_capability = GREATEST(min_runtime_capability, $4)
         WHERE tenant_id = $1`,
        [tenant, release.hash, release.sequence, RUNTIME_CAPABILITY],
      );
      const [bumped] = await m.query<{ revision: string }[]>(
        'SELECT revision::text AS revision FROM authz_fence WHERE tenant_id = $1',
        [tenant],
      );
      await m.query(
        `INSERT INTO audit_outbox (tenant_id, event_id, actor_id, event_kind, policy_revision, occurred_at, safe_metadata)
         VALUES ($1, gen_random_uuid(), $2, $3, $4, clock_timestamp(), $5)`,
        [
          tenant,
          this.#options.actor,
          utf8('manifest.sync'),
          bumped!.revision,
          JSON.stringify({ sequence: release.sequence, hash: release.hash }),
        ],
      );
      return { changed: true, revision: bumped!.revision, manifestHash: release.hash };
    });
  }
}

const definitionHash = (value: unknown) => sha256(canonicalJson(value));

/** Deterministic id for a code-owned default grant (UUID layout, version nibble 5). */
function grantId(tenant: TenantId, grant: DefaultGrant): string {
  const h = sha256(`${tenant}|${canonicalJson(grant)}`);
  const variant = (8 | (parseInt(h[16]!, 16) & 3)).toString(16);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-${variant}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

async function objectId(
  m: EntityManager,
  tenant: TenantId,
  release: VerifiedReleaseManifest,
  end: RelationSeed['source'],
) {
  const kind = release.declarations.resources[end.type]!.keyKind;
  const rows = await m.query<{ id: string }[]>(
    `SELECT object_id::text AS id FROM object_ref WHERE tenant_id = $1 AND type_key = $2 AND key_kind = $3 AND key_bytes = $4`,
    [tenant, utf8(end.type), kind, utf8(end.key.value)],
  );
  return rows[0]?.id;
}

async function apply(
  m: EntityManager,
  tenant: TenantId,
  release: VerifiedReleaseManifest,
): Promise<void> {
  const d = release.declarations;

  for (const resource of Object.values(d.resources)) {
    const rows = await m.query<{ key_kind: string }[]>(
      'SELECT key_kind FROM resource_type WHERE tenant_id = $1 AND type_key = $2',
      [tenant, utf8(resource.key)],
    );
    if (rows.length === 0) {
      await m.query('INSERT INTO resource_type VALUES ($1, $2, $3, $2)', [
        tenant,
        utf8(resource.key),
        resource.keyKind,
      ]);
    } else if (rows[0]!.key_kind !== resource.keyKind) {
      reject('immutable_definition', `resource ${resource.key} key kind`);
    }
  }

  // Policies before catalog bindings; published versions are immutable.
  for (const policy of Object.values(d.policies)) {
    const hash = definitionHash(policy);
    const rows = await m.query<{ hash: string; lifecycle: string }[]>(
      `SELECT encode(definition_hash, 'hex') AS hash, lifecycle FROM permission_policy
       WHERE tenant_id = $1 AND policy_key = $2 AND policy_version = $3`,
      [tenant, utf8(policy.key), policy.version],
    );
    const lifecycle = policy.lifecycle ?? 'active';
    if (rows.length === 0) {
      await m.query('INSERT INTO permission_policy VALUES ($1, $2, $3, decode($4, $5), $6, $7)', [
        tenant,
        utf8(policy.key),
        policy.version,
        hash,
        'hex',
        canonicalJson(policy),
        lifecycle,
      ]);
    } else if (rows[0]!.hash !== hash) {
      reject('immutable_definition', `policy ${refKey(policy)} changed without a new version`);
    } else if (rows[0]!.lifecycle !== lifecycle) {
      await m.query(
        'UPDATE permission_policy SET lifecycle = $4 WHERE tenant_id = $1 AND policy_key = $2 AND policy_version = $3',
        [tenant, utf8(policy.key), policy.version, lifecycle],
      );
    }
  }

  for (const template of Object.values(d.templates)) {
    const hash = definitionHash(template);
    const rows = await m.query<{ hash: string }[]>(
      `SELECT encode(definition_hash, 'hex') AS hash FROM scope_template WHERE tenant_id = $1 AND template_key = $2 AND version = $3`,
      [tenant, utf8(template.key), template.version],
    );
    if (rows.length === 0) {
      await m.query(`INSERT INTO scope_template VALUES ($1, $2, $3, decode($4, 'hex'))`, [
        tenant,
        utf8(template.key),
        template.version,
        hash,
      ]);
    } else if (rows[0]!.hash !== hash) {
      reject('immutable_definition', `template ${refKey(template)} changed without a new version`);
    }
  }

  // Resource → resource relation definitions; identity targets are validated in code only.
  for (const relation of Object.values(d.relations)) {
    if (relation.target.kind !== 'resource') continue;
    const hash = definitionHash(relation);
    const rows = await m.query<{ hash: string }[]>(
      `SELECT encode(definition_hash, 'hex') AS hash FROM resource_relation_definition
       WHERE tenant_id = $1 AND relation_key = $2 AND relation_version = $3`,
      [tenant, utf8(relation.key), relation.version],
    );
    if (rows.length === 0) {
      await m.query(
        `INSERT INTO resource_relation_definition VALUES ($1, $2, $3, $4, $5, $6, $7, decode($8, 'hex'), 'active')`,
        [
          tenant,
          utf8(relation.key),
          relation.version,
          utf8(relation.sourceType),
          utf8(relation.target.type),
          relation.binding.kind,
          utf8(relation.binding.kind === 'domain' ? relation.binding.key : relation.key),
          hash,
        ],
      );
    } else if (rows[0]!.hash !== hash) {
      reject('immutable_definition', `relation ${refKey(relation)} changed without a new version`);
    }
  }

  // Catalog: new permissions, policy binding switches; permissions gone from code are deprecated.
  const created = new Set<string>();
  const declared: string[] = [];
  for (const resource of Object.values(d.resources)) {
    for (const [action, declaration] of Object.entries(resource.actions)) {
      const permission = `${resource.key}.${action}`;
      declared.push(permission);
      const rows = await m.query<
        { policy_key: string; policy_version: number; lifecycle: string; boundary: string | null }[]
      >(
        `SELECT convert_from(policy_key, 'UTF8') AS policy_key, policy_version, lifecycle,
                boundary_requirement AS boundary
         FROM permission_catalog WHERE tenant_id = $1 AND permission_key = $2`,
        [tenant, utf8(permission)],
      );
      if (rows.length === 0) {
        await m.query(
          `INSERT INTO permission_catalog VALUES ($1, $2, $3, $4, $5, $6, 'active', $7)`,
          [
            tenant,
            utf8(permission),
            utf8(resource.key),
            utf8(action),
            utf8(declaration.policy.key),
            declaration.policy.version,
            declaration.boundary,
          ],
        );
        created.add(permission);
      } else {
        const row = rows[0]!;
        // Also backfills the boundary requirement of rows that predate migration 003.
        if (
          row.policy_key !== declaration.policy.key ||
          row.policy_version !== declaration.policy.version ||
          row.lifecycle !== 'active' ||
          row.boundary !== declaration.boundary
        ) {
          await m.query(
            `UPDATE permission_catalog SET policy_key = $3, policy_version = $4, lifecycle = 'active',
               boundary_requirement = $5
             WHERE tenant_id = $1 AND permission_key = $2`,
            [
              tenant,
              utf8(permission),
              utf8(declaration.policy.key),
              declaration.policy.version,
              declaration.boundary,
            ],
          );
        }
      }
    }
  }
  // A legacy row gone from code gets the fail-closed requirement; code no longer declares it anyway.
  await m.query(
    `UPDATE permission_catalog SET lifecycle = 'deprecated',
       boundary_requirement = COALESCE(boundary_requirement, 'required')
     WHERE tenant_id = $1 AND lifecycle = 'active' AND convert_from(permission_key, 'UTF8') <> ALL ($2::text[])`,
    [tenant, declared],
  );

  // Permission boundaries (ADR 0003): immutable versions + entries, then code-owned bindings.
  for (const boundary of Object.values(d.boundaries)) {
    const { lifecycle = 'active', ...definition } = boundary;
    const hash = definitionHash(definition);
    const rows = await m.query<{ hash: string; lifecycle: string }[]>(
      `SELECT encode(definition_hash, 'hex') AS hash, lifecycle FROM permission_boundary
       WHERE tenant_id = $1 AND boundary_key = $2 AND boundary_version = $3`,
      [tenant, utf8(boundary.key), boundary.version],
    );
    if (rows.length === 0) {
      await m.query(
        `INSERT INTO permission_boundary VALUES ($1, $2, $3, decode($4, 'hex'), $5, $6)`,
        [tenant, utf8(boundary.key), boundary.version, hash, canonicalJson(definition), lifecycle],
      );
      for (const entry of boundary.entries) {
        await m.query(`INSERT INTO permission_boundary_entry VALUES ($1, $2, $3, $4, $5)`, [
          tenant,
          utf8(boundary.key),
          boundary.version,
          utf8(entry.permission),
          canonicalJson(entry),
        ]);
      }
    } else if (rows[0]!.hash !== hash) {
      reject('immutable_definition', `boundary ${refKey(boundary)} changed without a new version`);
    } else if (rows[0]!.lifecycle !== lifecycle) {
      await m.query(
        `UPDATE permission_boundary SET lifecycle = $4
         WHERE tenant_id = $1 AND boundary_key = $2 AND boundary_version = $3`,
        [tenant, utf8(boundary.key), boundary.version, lifecycle],
      );
    }
  }
  for (const seed of release.boundaryBindings) {
    const at = [tenant, seed.identity, utf8(seed.permission)];
    const [occupant] = await m.query<{ owner: string | null; key: string; version: number }[]>(
      `SELECT convert_from(seed_owner, 'UTF8') AS owner, convert_from(boundary_key, 'UTF8') AS key,
              boundary_version AS version
       FROM member_permission_boundary WHERE tenant_id = $1 AND identity_id = $2 AND permission_key = $3`,
      at,
    );
    if (occupant && occupant.owner !== seed.owner) {
      reject(
        'collision',
        `boundary binding ${seed.identity}/${seed.permission} is ${occupant.owner === null ? 'runtime-managed' : 'owned by another seed'}`,
      );
    }
    if (occupant?.key === seed.boundary.key && occupant.version === seed.boundary.version) continue;
    try {
      await m.query(
        occupant
          ? `UPDATE member_permission_boundary SET boundary_key = $4, boundary_version = $5
             WHERE tenant_id = $1 AND identity_id = $2 AND permission_key = $3`
          : `INSERT INTO member_permission_boundary VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          ...at,
          utf8(seed.boundary.key),
          seed.boundary.version,
          ...(occupant ? [] : [utf8(seed.owner)]),
        ],
      );
    } catch (error) {
      const code =
        error instanceof QueryFailedError
          ? (error.driverError as { code?: unknown } | undefined)?.code
          : undefined;
      if (code === '23503')
        reject('missing_reference', `boundary binding ${seed.identity}/${seed.permission}`);
      throw error;
    }
  }
  for (const removal of release.removeBoundaryBindings) {
    await m.query(
      `DELETE FROM member_permission_boundary
       WHERE tenant_id = $1 AND identity_id = $2 AND permission_key = $3 AND seed_owner = $4`,
      [tenant, removal.identity, utf8(removal.permission), utf8(removal.owner)],
    );
  }
  // A definition someone is still bound to is never retired or dropped: the code must keep it
  // until a binding command moves the members (bindings never follow a new version implicitly).
  const bound = await m.query<{ key: string; version: number }[]>(
    `SELECT convert_from(d.boundary_key, 'UTF8') AS key, d.boundary_version AS version
     FROM permission_boundary d
     WHERE d.tenant_id = $1 AND EXISTS (
       SELECT 1 FROM member_permission_boundary b WHERE b.tenant_id = d.tenant_id
         AND b.boundary_key = d.boundary_key AND b.boundary_version = d.boundary_version)`,
    [tenant],
  );
  const unusable = bound.filter((ref) => {
    const declaredBoundary = Object.hasOwn(d.boundaries, refKey(ref))
      ? d.boundaries[refKey(ref)]
      : undefined;
    return !declaredBoundary || declaredBoundary.lifecycle === 'retired';
  });
  if (unusable.length > 0)
    reject('definition_in_use', unusable.map((ref) => refKey(ref)).join(', '));

  for (const role of release.roles) {
    const rows = await m.query<{ managed_by: string; authority_level: number; label: string }[]>(
      'SELECT managed_by, authority_level, label FROM role_definition WHERE tenant_id = $1 AND role_key = $2',
      [tenant, utf8(role.key)],
    );
    if (rows.length === 0) {
      await m.query(`INSERT INTO role_definition VALUES ($1, $2, 'code', $3, $4)`, [
        tenant,
        utf8(role.key),
        role.authorityLevel,
        role.label,
      ]);
    } else if (rows[0]!.managed_by !== 'code') {
      reject('collision', `role ${role.key} is tenant-managed`);
    } else if (rows[0]!.authority_level !== role.authorityLevel || rows[0]!.label !== role.label) {
      await m.query(
        'UPDATE role_definition SET authority_level = $3, label = $4 WHERE tenant_id = $1 AND role_key = $2',
        [tenant, utf8(role.key), role.authorityLevel, role.label],
      );
    }
  }

  // Defaults only for permissions created now: an administrator's later removal is not undone.
  for (const grant of release.defaultGrants) {
    if (!created.has(grant.permission)) continue;
    await m.query(
      `INSERT INTO policy_rule VALUES ($1, $2, $3, NULL, $4, 'allow', $5, $6, $7, 'code') ON CONFLICT DO NOTHING`,
      [
        tenant,
        grantId(tenant, grant),
        utf8(grant.permission),
        utf8(grant.role),
        utf8(grant.template.key),
        grant.template.version,
        canonicalJson(grant.parameters),
      ],
    );
  }

  for (const seed of release.seeds) {
    const source = await objectId(m, tenant, release, seed.source);
    const target = await objectId(m, tenant, release, seed.target);
    if (!source || !target) reject('missing_reference', `seed ${seed.owner}/${seed.key}`);
    const occupant = await m.query<{ owner: string | null; key: string | null }[]>(
      `SELECT convert_from(seed_owner, 'UTF8') AS owner, convert_from(seed_key, 'UTF8') AS key FROM relation_edge
       WHERE tenant_id = $1 AND relation_key = $2 AND relation_version = $3 AND source_object = $4 AND target_object = $5`,
      [tenant, utf8(seed.relation.key), seed.relation.version, source, target],
    );
    if (occupant[0] && (occupant[0].owner !== seed.owner || occupant[0].key !== seed.key)) {
      reject(
        'collision',
        `seed ${seed.owner}/${seed.key} collides with ${occupant[0].owner === null ? 'a runtime tuple' : 'another seed'}`,
      );
    }
    const values = [
      tenant,
      utf8(seed.relation.key),
      seed.relation.version,
      source,
      utf8(seed.source.type),
      target,
      utf8(seed.target.type),
      seed.startsAt,
      seed.expiresAt ?? null,
      utf8(seed.owner),
      utf8(seed.key),
    ];
    const own = await m.query<unknown[]>(
      'SELECT 1 FROM relation_edge WHERE tenant_id = $1 AND seed_owner = $2 AND seed_key = $3',
      [tenant, utf8(seed.owner), utf8(seed.key)],
    );
    await m.query(
      own.length > 0
        ? `UPDATE relation_edge SET relation_key = $2, relation_version = $3, source_object = $4, source_type = $5,
             target_object = $6, target_type = $7, starts_at = $8, expires_at = $9
           WHERE tenant_id = $1 AND seed_owner = $10 AND seed_key = $11`
        : `INSERT INTO relation_edge (tenant_id, relation_key, relation_version, source_object, source_type, target_object,
             target_type, starts_at, expires_at, seed_owner, seed_key) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      values,
    );
  }
  for (const removal of release.removeSeeds) {
    await m.query(
      'DELETE FROM relation_edge WHERE tenant_id = $1 AND seed_owner = $2 AND seed_key = $3',
      [tenant, utf8(removal.owner), utf8(removal.key)],
    );
  }
}

/** Same release already published: confirm every code-owned fact is still present (readiness). */
async function verifyApplied(
  m: EntityManager,
  tenant: TenantId,
  release: VerifiedReleaseManifest,
): Promise<void> {
  const d = release.declarations;
  const missing: string[] = [];
  for (const policy of Object.values(d.policies)) {
    const rows = await m.query<unknown[]>(
      `SELECT 1 FROM permission_policy WHERE tenant_id = $1 AND policy_key = $2 AND policy_version = $3
       AND definition_hash = decode($4, 'hex')`,
      [tenant, utf8(policy.key), policy.version, definitionHash(policy)],
    );
    if (rows.length === 0) missing.push(`policy ${refKey(policy)}`);
  }
  for (const resource of Object.values(d.resources)) {
    for (const [action, declaration] of Object.entries(resource.actions)) {
      const rows = await m.query<unknown[]>(
        `SELECT 1 FROM permission_catalog WHERE tenant_id = $1 AND permission_key = $2 AND policy_key = $3
         AND policy_version = $4 AND lifecycle = 'active' AND boundary_requirement = $5`,
        [
          tenant,
          utf8(`${resource.key}.${action}`),
          utf8(declaration.policy.key),
          declaration.policy.version,
          declaration.boundary,
        ],
      );
      if (rows.length === 0) missing.push(`permission ${resource.key}.${action}`);
    }
  }
  for (const boundary of Object.values(d.boundaries)) {
    const { lifecycle = 'active', ...definition } = boundary;
    const rows = await m.query<unknown[]>(
      `SELECT 1 FROM permission_boundary WHERE tenant_id = $1 AND boundary_key = $2 AND boundary_version = $3
       AND definition_hash = decode($4, 'hex') AND lifecycle = $5`,
      [tenant, utf8(boundary.key), boundary.version, definitionHash(definition), lifecycle],
    );
    if (rows.length === 0) missing.push(`boundary ${refKey(boundary)}`);
  }
  for (const seed of release.boundaryBindings) {
    const rows = await m.query<unknown[]>(
      `SELECT 1 FROM member_permission_boundary WHERE tenant_id = $1 AND identity_id = $2
       AND permission_key = $3 AND boundary_key = $4 AND boundary_version = $5 AND seed_owner = $6`,
      [
        tenant,
        seed.identity,
        utf8(seed.permission),
        utf8(seed.boundary.key),
        seed.boundary.version,
        utf8(seed.owner),
      ],
    );
    if (rows.length === 0) missing.push(`boundary binding ${seed.identity}/${seed.permission}`);
  }
  for (const role of release.roles) {
    const rows = await m.query<unknown[]>(
      `SELECT 1 FROM role_definition WHERE tenant_id = $1 AND role_key = $2 AND managed_by = 'code'`,
      [tenant, utf8(role.key)],
    );
    if (rows.length === 0) missing.push(`role ${role.key}`);
  }
  for (const seed of release.seeds) {
    const source = await objectId(m, tenant, release, seed.source);
    const target = await objectId(m, tenant, release, seed.target);
    const rows = await m.query<unknown[]>(
      `SELECT 1 FROM relation_edge WHERE tenant_id = $1 AND seed_owner = $2 AND seed_key = $3 AND relation_key = $4
       AND relation_version = $5 AND source_object = $6 AND target_object = $7 AND starts_at = $8
       AND expires_at IS NOT DISTINCT FROM $9::timestamptz`,
      [
        tenant,
        utf8(seed.owner),
        utf8(seed.key),
        utf8(seed.relation.key),
        seed.relation.version,
        source ?? null,
        target ?? null,
        seed.startsAt,
        seed.expiresAt ?? null,
      ],
    );
    if (rows.length === 0) missing.push(`seed ${seed.owner}/${seed.key}`);
  }
  if (missing.length > 0) reject('not_ready', missing.slice(0, 10).join(', '));
}
