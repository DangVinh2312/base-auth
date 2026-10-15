import { createHash } from 'node:crypto';
import {
  type AuthorizationCore,
  canonicalJson,
  refKey,
  type IdentityId,
} from '@base-authorization/core';
import { type EntityManager, QueryFailedError } from 'typeorm';
import {
  ReleaseRejectedError,
  releaseContentHash,
  validateReleaseContent,
  validateRoleKeys,
  type DefaultGrant,
  type ReleaseContentSource,
  type ValidatedReleaseContent,
  type RelationSeed,
  type SyncResult,
  type RejectReason,
} from './manifest-reconciler.js';
import { ProductTransactionRunner } from './product-transaction.js';
import { appendProductAudit, PRODUCT_OFFLINE_ACTOR } from './product-audit.js';
import { codeOwnedCatalogIsEmpty, protectedStateHash } from './protected-state.js';

const sha256 = (text: string) => createHash('sha256').update(text).digest('hex');

const utf8 = (value: string) => Buffer.from(value, 'utf8');

const reject = (reason: RejectReason, detail: string): never => {
  throw new ReleaseRejectedError(reason, detail);
};

const RUNTIME_CAPABILITY = 1;
export interface ProductRole {
  readonly key: string;
  readonly label: string;
}

export interface ProductReleaseSource extends ReleaseContentSource {
  readonly roles: readonly ProductRole[];
  /** Exact earlier default grants to delete; default grants stay code-owned until removed here. */
  readonly removeDefaultGrants?: readonly DefaultGrant[];
}

export interface ProductReleaseManifest extends ValidatedReleaseContent {
  readonly roles: readonly ProductRole[];
  readonly removeDefaultGrants: readonly DefaultGrant[];
  readonly hash: string;
}

/** Release → the authorization core that prepared it (provenance; never part of the hash). */
const productVerified = new WeakMap<object, AuthorizationCore>();

export function prepareProductRelease(
  source: ProductReleaseSource,
  core: AuthorizationCore,
): ProductReleaseManifest {
  if ((source.removeDefaultGrants?.length ?? 0) > 1000)
    reject('invalid_release', 'default grant removal limit');
  // `system.` is reserved: Root lives outside IAM (ADR 0012), no role may look like a system role.
  if (source.roles.some((role) => role.key.startsWith('system.')))
    reject('invalid_release', 'role key prefix system. is reserved');
  const roleKeys = validateRoleKeys(source.roles);
  const base = validateReleaseContent(source, core, roleKeys);
  // Same exact permission/template/parameter validation as the grants being removed.
  const removeDefaultGrants = validateReleaseContent(
    { ...source, defaultGrants: source.removeDefaultGrants ?? [] },
    core,
    roleKeys,
  ).defaultGrants;
  const removedIds = new Set(removeDefaultGrants.map(grantId));
  if (
    removedIds.size !== removeDefaultGrants.length ||
    base.defaultGrants.some((g) => removedIds.has(grantId(g)))
  )
    reject('invalid_release', 'default grant removal');
  const roles = source.roles.map((role) => ({ key: role.key, label: role.label }));
  const hash = sha256(
    canonicalJson({
      base: releaseContentHash(base, roles),
      // Omitted when empty so a release without removals keeps its hash.
      ...(removeDefaultGrants.length ? { removeDefaultGrants: [...removedIds].sort() } : {}),
    }),
  );
  const release: ProductReleaseManifest = Object.freeze({
    ...base,
    roles,
    hash,
    removeDefaultGrants: Object.freeze(removeDefaultGrants),
  });
  freezeRelease(release);
  productVerified.set(release, core);
  return release;
}

function freezeRelease(value: unknown): void {
  if (value && typeof value === 'object') {
    for (const nested of Object.values(value)) freezeRelease(nested);
    Object.freeze(value);
  }
}

export class ProductManifestReconciler {
  constructor(
    private readonly runner: ProductTransactionRunner,
    private readonly options: {
      /** The runtime's core; a release prepared by another core is refused. */
      core: AuthorizationCore;
      actor: IdentityId;
      capabilities: { validators: readonly string[]; obligationHandlers: readonly string[] };
    },
  ) {
    if (!options.core.isCanonicalUuid(options.actor)) throw new TypeError('Invalid manifest actor');
  }

  async reconcile(release: ProductReleaseManifest): Promise<SyncResult> {
    if (productVerified.get(release) !== this.options.core)
      reject('invalid_release', 'product release was not prepared with this core');
    const available = new Set([
      ...this.options.capabilities.validators,
      ...this.options.capabilities.obligationHandlers,
    ]);
    if (
      [
        ...release.declarations.capabilities.validators,
        ...release.declarations.capabilities.obligationHandlers,
      ].some((c) => !available.has(c))
    )
      reject('missing_capability', 'missing registered implementation');
    return this.runner.run('sync', async (tx) => {
      const m = tx.manager;
      const [current] = await m.query<
        { sequence: string; hash: string; materialized: string | null }[]
      >(
        `SELECT release_sequence::text sequence,encode(manifest_hash,'hex') hash,encode(materialized_hash,'hex') materialized FROM authz_state WHERE singleton`,
      );
      if (!current) reject('not_ready', 'missing application state');
      if (BigInt(release.sequence) === BigInt(current!.sequence)) {
        if (release.hash !== current!.hash)
          reject('conflicting_release', 'same sequence with different content');
        await verifyApplied(m, release);
        if ((await protectedStateHash(m)) !== current!.materialized)
          reject('not_ready', 'code-owned facts drifted');
        return { changed: false, revision: tx.revision, manifestHash: release.hash };
      }
      if (BigInt(release.sequence) < BigInt(current!.sequence))
        reject('downgrade', 'older release');
      // Genesis (ADR 0012): a fresh database (sequence 0, empty code-owned catalog) accepts any
      // release as its first. Every other case keeps the strict predecessor.
      const genesis = current!.sequence === '0' && (await codeOwnedCatalogIsEmpty(m));
      if (!genesis && release.predecessor !== current!.sequence)
        reject('predecessor_mismatch', 'unexpected previous release');
      if (current!.sequence !== '0' && (await protectedStateHash(m)) !== current!.materialized)
        reject(
          'not_ready',
          'code-owned drift requires explicit offline repair before another release',
        );
      await apply(m, release);
      for (const grant of release.removeDefaultGrants) {
        const removed = await m.query<unknown[]>(
          "WITH removed AS (DELETE FROM policy_rule WHERE rule_id=$1 AND managed_by='code' AND system_owner IS NULL RETURNING 1) SELECT * FROM removed",
          [grantId(grant)],
        );
        if (!removed.length) reject('missing_reference', 'removed default grant is missing');
      }
      const materialized = await protectedStateHash(m);
      await m.query(
        `UPDATE authz_state SET revision=revision+1,manifest_hash=decode($1,'hex'),release_sequence=$2,min_runtime_capability=$3,materialized_hash=decode($4,'hex') WHERE singleton`,
        [release.hash, release.sequence, RUNTIME_CAPABILITY, materialized],
      );
      const revision = String(BigInt(tx.revision) + 1n);
      await appendProductAudit(tx, {
        kind: 'manifest.sync',
        actor: this.options.actor,
        sequence: release.sequence,
        hash: release.hash,
        publishedRevision: revision,
      });
      return { changed: true, revision, manifestHash: release.hash };
    });
  }
}

const definitionHash = (value: unknown) => sha256(canonicalJson(value));

/** Deterministic id for a code-owned default grant (UUID layout, version nibble 5). */
function grantId(grant: DefaultGrant): string {
  const h = sha256(canonicalJson(grant));
  const variant = (8 | (parseInt(h[16]!, 16) & 3)).toString(16);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-${variant}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

async function objectId(
  m: EntityManager,
  release: ProductReleaseManifest,
  end: RelationSeed['source'],
) {
  const kind = release.declarations.resources[end.type]!.keyKind;
  const rows = await m.query<{ id: string }[]>(
    `SELECT object_id::text AS id FROM object_ref WHERE type_key = $1 AND key_kind = $2 AND key_bytes = $3`,
    [utf8(end.type), kind, utf8(end.key.value)],
  );
  return rows[0]?.id;
}

async function apply(m: EntityManager, release: ProductReleaseManifest): Promise<void> {
  const d = release.declarations;

  for (const resource of Object.values(d.resources)) {
    const rows = await m.query<{ key_kind: string }[]>(
      'SELECT key_kind FROM resource_type WHERE type_key = $1',
      [utf8(resource.key)],
    );
    if (rows.length === 0) {
      await m.query('INSERT INTO resource_type VALUES ($1, $2, $1)', [
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
       WHERE policy_key = $1 AND policy_version = $2`,
      [utf8(policy.key), policy.version],
    );
    const lifecycle = policy.lifecycle ?? 'active';
    if (rows.length === 0) {
      await m.query('INSERT INTO permission_policy VALUES ($1, $2, decode($3, $4), $5, $6)', [
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
        'UPDATE permission_policy SET lifecycle = $3 WHERE policy_key = $1 AND policy_version = $2',
        [utf8(policy.key), policy.version, lifecycle],
      );
    }
  }

  for (const template of Object.values(d.templates)) {
    const hash = definitionHash(template);
    const rows = await m.query<{ hash: string }[]>(
      `SELECT encode(definition_hash, 'hex') AS hash FROM scope_template WHERE template_key = $1 AND version = $2`,
      [utf8(template.key), template.version],
    );
    if (rows.length === 0) {
      await m.query(`INSERT INTO scope_template VALUES ($1, $2, decode($3, 'hex'))`, [
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
       WHERE relation_key = $1 AND relation_version = $2`,
      [utf8(relation.key), relation.version],
    );
    if (rows.length === 0) {
      await m.query(
        `INSERT INTO resource_relation_definition VALUES ($1, $2, $3, $4, $5, $6, decode($7, 'hex'), 'active')`,
        [
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
         FROM permission_catalog WHERE permission_key = $1`,
        [utf8(permission)],
      );
      if (rows.length === 0) {
        await m.query(`INSERT INTO permission_catalog VALUES ($1, $2, $3, $4, $5, 'active', $6)`, [
          utf8(permission),
          utf8(resource.key),
          utf8(action),
          utf8(declaration.policy.key),
          declaration.policy.version,
          declaration.boundary,
        ]);
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
            `UPDATE permission_catalog SET policy_key = $2, policy_version = $3, lifecycle = 'active',
               boundary_requirement = $4
             WHERE permission_key = $1`,
            [
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
     WHERE lifecycle = 'active' AND convert_from(permission_key, 'UTF8') <> ALL ($1::text[])`,
    [declared],
  );

  // Permission boundaries (ADR 0003): immutable versions + entries, then code-owned bindings.
  for (const boundary of Object.values(d.boundaries)) {
    const { lifecycle = 'active', ...definition } = boundary;
    const hash = definitionHash(definition);
    const rows = await m.query<{ hash: string; lifecycle: string }[]>(
      `SELECT encode(definition_hash, 'hex') AS hash, lifecycle FROM permission_boundary
       WHERE boundary_key = $1 AND boundary_version = $2`,
      [utf8(boundary.key), boundary.version],
    );
    if (rows.length === 0) {
      await m.query(`INSERT INTO permission_boundary VALUES ($1, $2, decode($3, 'hex'), $4, $5)`, [
        utf8(boundary.key),
        boundary.version,
        hash,
        canonicalJson(definition),
        lifecycle,
      ]);
      for (const entry of boundary.entries) {
        await m.query(`INSERT INTO permission_boundary_entry VALUES ($1, $2, $3, $4)`, [
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
        `UPDATE permission_boundary SET lifecycle = $3
         WHERE boundary_key = $1 AND boundary_version = $2`,
        [utf8(boundary.key), boundary.version, lifecycle],
      );
    }
  }
  for (const seed of release.boundaryBindings) {
    const at = [seed.identity, utf8(seed.permission)];
    const [occupant] = await m.query<{ owner: string | null; key: string; version: number }[]>(
      `SELECT convert_from(seed_owner, 'UTF8') AS owner, convert_from(boundary_key, 'UTF8') AS key,
              boundary_version AS version
       FROM user_boundary WHERE user_id = $1 AND permission_key = $2`,
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
          ? `UPDATE user_boundary SET boundary_key = $3, boundary_version = $4
             WHERE user_id = $1 AND permission_key = $2`
          : `INSERT INTO user_boundary VALUES ($1, $2, $3, $4, $5)`,
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
      `DELETE FROM user_boundary
       WHERE user_id = $1 AND permission_key = $2 AND seed_owner = $3`,
      [removal.identity, utf8(removal.permission), utf8(removal.owner)],
    );
  }
  // A definition someone is still bound to is never retired or dropped: the code must keep it
  // until a binding command moves the members (bindings never follow a new version implicitly).
  const bound = await m.query<{ key: string; version: number }[]>(
    `SELECT convert_from(d.boundary_key, 'UTF8') AS key, d.boundary_version AS version
     FROM permission_boundary d
     WHERE EXISTS (
       SELECT 1 FROM user_boundary b WHERE b.boundary_key = d.boundary_key AND b.boundary_version = d.boundary_version)`,
    [],
  );
  const unusable = bound.filter((ref) => {
    const declaredBoundary = Object.hasOwn(d.boundaries, refKey(ref))
      ? d.boundaries[refKey(ref)]
      : undefined;
    return !declaredBoundary || declaredBoundary.lifecycle === 'retired';
  });
  if (unusable.length > 0)
    reject('definition_in_use', unusable.map((ref) => refKey(ref)).join(', '));

  // No rank since 012: a role is its key, owner and label.
  for (const role of release.roles) {
    const rows = await m.query<{ managed_by: string; label: string }[]>(
      'SELECT managed_by, label FROM role_definition WHERE role_key = $1',
      [utf8(role.key)],
    );
    if (rows.length === 0) {
      await m.query(
        `INSERT INTO role_definition(role_key, managed_by, label) VALUES ($1, 'code', $2)`,
        [utf8(role.key), role.label],
      );
    } else if (rows[0]!.managed_by !== 'code') {
      reject('collision', `role ${role.key} is runtime-managed`);
    } else if (rows[0]!.label !== role.label) {
      await m.query('UPDATE role_definition SET label = $2 WHERE role_key = $1', [
        utf8(role.key),
        role.label,
      ]);
    }
  }

  // Defaults only for permissions created now. They stay code-owned (DB-protected) and leave only
  // through an explicit removeDefaultGrants entry of a later release.
  for (const grant of release.defaultGrants) {
    if (!created.has(grant.permission)) continue;
    await m.query(
      `INSERT INTO policy_rule (rule_id,permission_key,user_id,role_key,effect,template_key,template_version,parameters,managed_by) VALUES ($1, $2, NULL, $3, 'allow', $4, $5, $6, 'code') ON CONFLICT DO NOTHING`,
      [
        grantId(grant),
        utf8(grant.permission),
        utf8(grant.role),
        utf8(grant.template.key),
        grant.template.version,
        canonicalJson(grant.parameters),
      ],
    );
  }

  for (const seed of release.seeds) {
    const source = await objectId(m, release, seed.source);
    const target = await objectId(m, release, seed.target);
    if (!source || !target) reject('missing_reference', `seed ${seed.owner}/${seed.key}`);
    const occupant = await m.query<{ owner: string | null; key: string | null }[]>(
      `SELECT convert_from(seed_owner, 'UTF8') AS owner, convert_from(seed_key, 'UTF8') AS key FROM relation_edge
       WHERE relation_key = $1 AND relation_version = $2 AND source_object = $3 AND target_object = $4`,
      [utf8(seed.relation.key), seed.relation.version, source, target],
    );
    if (occupant[0] && (occupant[0].owner !== seed.owner || occupant[0].key !== seed.key)) {
      reject(
        'collision',
        `seed ${seed.owner}/${seed.key} collides with ${occupant[0].owner === null ? 'a runtime tuple' : 'another seed'}`,
      );
    }
    const values = [
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
      'SELECT 1 FROM relation_edge WHERE seed_owner = $1 AND seed_key = $2',
      [utf8(seed.owner), utf8(seed.key)],
    );
    await m.query(
      own.length > 0
        ? `UPDATE relation_edge SET relation_key = $1, relation_version = $2, source_object = $3, source_type = $4,
             target_object = $5, target_type = $6, starts_at = $7, expires_at = $8
           WHERE seed_owner = $9 AND seed_key = $10`
        : `INSERT INTO relation_edge (relation_key, relation_version, source_object, source_type, target_object,
             target_type, starts_at, expires_at, seed_owner, seed_key) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      values,
    );
  }
  for (const removal of release.removeSeeds) {
    await m.query('DELETE FROM relation_edge WHERE seed_owner = $1 AND seed_key = $2', [
      utf8(removal.owner),
      utf8(removal.key),
    ]);
  }
}

/** Same release already published: confirm every code-owned fact is still present (readiness). */
async function verifyApplied(m: EntityManager, release: ProductReleaseManifest): Promise<void> {
  const d = release.declarations;
  const missing: string[] = [];
  for (const policy of Object.values(d.policies)) {
    const rows = await m.query<unknown[]>(
      `SELECT 1 FROM permission_policy WHERE policy_key = $1 AND policy_version = $2
       AND definition_hash = decode($3, 'hex')`,
      [utf8(policy.key), policy.version, definitionHash(policy)],
    );
    if (rows.length === 0) missing.push(`policy ${refKey(policy)}`);
  }
  for (const resource of Object.values(d.resources)) {
    for (const [action, declaration] of Object.entries(resource.actions)) {
      const rows = await m.query<unknown[]>(
        `SELECT 1 FROM permission_catalog WHERE permission_key = $1 AND policy_key = $2
         AND policy_version = $3 AND lifecycle = 'active' AND boundary_requirement = $4`,
        [
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
      `SELECT 1 FROM permission_boundary WHERE boundary_key = $1 AND boundary_version = $2
       AND definition_hash = decode($3, 'hex') AND lifecycle = $4`,
      [utf8(boundary.key), boundary.version, definitionHash(definition), lifecycle],
    );
    if (rows.length === 0) missing.push(`boundary ${refKey(boundary)}`);
  }
  for (const seed of release.boundaryBindings) {
    const rows = await m.query<unknown[]>(
      `SELECT 1 FROM user_boundary WHERE user_id = $1
       AND permission_key = $2 AND boundary_key = $3 AND boundary_version = $4 AND seed_owner = $5`,
      [
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
      `SELECT 1 FROM role_definition WHERE role_key = $1 AND managed_by = 'code'`,
      [utf8(role.key)],
    );
    if (rows.length === 0) missing.push(`role ${role.key}`);
  }
  for (const seed of release.seeds) {
    const source = await objectId(m, release, seed.source);
    const target = await objectId(m, release, seed.target);
    const rows = await m.query<unknown[]>(
      `SELECT 1 FROM relation_edge WHERE seed_owner = $1 AND seed_key = $2 AND relation_key = $3
       AND relation_version = $4 AND source_object = $5 AND target_object = $6 AND starts_at = $7
       AND expires_at IS NOT DISTINCT FROM $8::timestamptz`,
      [
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

export interface RootBootstrapInput {
  readonly operationId: string;
  readonly userId: IdentityId;
  readonly method: 'local' | 'oidc';
  readonly issuer?: string;
  readonly subject?: string;
}

/**
 * Offline capability only: promotes one pending IAM account to Root (kind = 'root') with the
 * permanent marker and a one-time proof (ADR 0012). No role, grant or boundary is written.
 */
export async function bootstrapProductRoot(
  runner: ProductTransactionRunner,
  release: ProductReleaseManifest,
  input: RootBootstrapInput,
): Promise<{ initialized: boolean; activationSecret?: string }> {
  const core = productVerified.get(release);
  if (!core || !core.isCanonicalUuid(input.operationId) || !core.isCanonicalUuid(input.userId))
    reject('invalid_release', 'invalid bootstrap input');
  if (input.userId === PRODUCT_OFFLINE_ACTOR)
    reject('invalid_release', 'offline actor id cannot be a user');
  return runner.run('bootstrap', async (tx) => {
    const m = tx.manager;
    const [marker] = await m.query<
      { operation_id: string | null; target_user_id: string | null }[]
    >(
      'SELECT operation_id,target_user_id FROM security_bootstrap_state WHERE singleton FOR UPDATE',
    );
    if (!marker) reject('not_ready', 'bootstrap marker missing');
    if (marker!.operation_id) {
      if (marker!.operation_id === input.operationId && marker!.target_user_id === input.userId)
        return { initialized: false };
      reject('collision', 'Root bootstrap already initialized');
    }
    const [state] = await m.query<{ hash: string; materialized: string | null }[]>(
      `SELECT encode(manifest_hash,'hex') hash,encode(materialized_hash,'hex') materialized FROM authz_state WHERE singleton`,
    );
    if (state?.hash !== release.hash || state.materialized !== (await protectedStateHash(m)))
      reject('not_ready', 'manifest must be applied without drift');
    // Lock the target before any check (spec 3.3): a concurrent fact or token insert either
    // waits for this promotion or is already visible to the DB guard.
    const [target] = await m.query<{ state: string; email_canonical: string | null }[]>(
      'SELECT state,email_canonical FROM app_user WHERE id=$1 FOR NO KEY UPDATE',
      [input.userId],
    );
    if (target?.state !== 'pending')
      reject('collision', 'Root enrollment target must already be pending');
    if (input.method === 'local') {
      if (!target!.email_canonical)
        reject('missing_reference', 'local target needs verified delivery address enrollment');
    } else if (input.method === 'oidc') {
      if (!input.issuer || !input.subject)
        reject('invalid_release', 'OIDC enrollment requires exact issuer and subject');
      const [binding] = await m.query<{ only: boolean }[]>(
        'SELECT (SELECT count(*) FROM external_identity WHERE user_id=$3 AND enabled)=1 AS only FROM external_identity WHERE issuer=$1 AND subject=$2 AND user_id=$3 AND enabled',
        [input.issuer, input.subject, input.userId],
      );
      if (!binding?.only) reject('missing_reference', 'pending OIDC binding does not match target');
    } else reject('invalid_release', 'unsupported Root activation method');
    // Proof material is generated here and returned only after commit to the offline delivery tool.
    // OIDC activation additionally needs a fresh IdP proof of the exact pre-bound subject.
    const { randomBytes } = await import('node:crypto');
    const activationSecret = randomBytes(32).toString('base64url');
    // Promotion before the proof: the guard refuses a target holding IAM facts or a live invitation.
    await m.query(`UPDATE app_user SET kind='root' WHERE id=$1`, [input.userId]);
    await m.query(
      `INSERT INTO one_time_token(token_hash,user_id,purpose,expires_at) VALUES($1,$2,$3,statement_timestamp()+interval '15 minutes')`,
      [
        createHash('sha256').update(activationSecret).digest(),
        input.userId,
        input.method === 'local' ? 'activation' : 'oidc-activation',
      ],
    );
    await m.query(
      'UPDATE security_bootstrap_state SET operation_id=$1,target_user_id=$2,initialized_at=statement_timestamp() WHERE singleton',
      [input.operationId, input.userId],
    );
    await appendProductAudit(tx, {
      kind: 'root.bootstrap',
      actor: PRODUCT_OFFLINE_ACTOR,
      target: { userId: input.userId },
      operationId: input.operationId,
      method: input.method,
    });
    return { initialized: true, activationSecret };
  });
}

export interface RootReissueInput {
  readonly userId: IdentityId;
  readonly method: 'local' | 'oidc';
  /** OIDC only: the operator re-confirms the exact pre-bound identity. */
  readonly issuer?: string;
  readonly subject?: string;
}

/**
 * Offline capability only: a fresh one-time proof for the still pending bootstrap Root (expired or
 * lost artifact). Earlier proofs are consumed in the same fenced transaction, with audit.
 */
export async function reissueRootActivation(
  runner: ProductTransactionRunner,
  input: RootReissueInput,
  core: AuthorizationCore,
): Promise<{ activationSecret: string }> {
  if (!core.isCanonicalUuid(input.userId) || (input.method !== 'local' && input.method !== 'oidc'))
    reject('invalid_release', 'invalid Root reissue input');
  if (input.userId === PRODUCT_OFFLINE_ACTOR)
    reject('invalid_release', 'offline actor id cannot be a user');
  return runner.run('bootstrap', async (tx) => {
    const m = tx.manager;
    const [target] = await m.query<
      { state: string; delivery: boolean; root: boolean; credential: boolean; bindings: number }[]
    >(
      `SELECT u.state,u.email_canonical IS NOT NULL delivery,u.kind='root' root,
        EXISTS(SELECT FROM local_credential c WHERE c.user_id=u.id) credential,
        (SELECT count(*) FROM external_identity e WHERE e.user_id=u.id AND e.enabled)::int bindings
       FROM security_bootstrap_state b JOIN app_user u ON u.id=b.target_user_id
       WHERE b.singleton AND b.initialized_at IS NOT NULL AND u.id=$1 FOR UPDATE OF b FOR NO KEY UPDATE OF u`,
      [input.userId],
    );
    if (!target || target.state !== 'pending' || !target.root || target.credential)
      reject('collision', 'only the pending bootstrap Root can receive a new proof');
    if (input.method === 'local' ? !target!.delivery : target!.bindings !== 1)
      reject('missing_reference', 'Root target does not fit the activation method');
    if (input.method === 'oidc') {
      const [binding] = await m.query<unknown[]>(
        'SELECT 1 FROM external_identity WHERE issuer=$1 AND subject=$2 AND user_id=$3 AND enabled',
        [input.issuer ?? '', input.subject ?? '', input.userId],
      );
      if (!binding) reject('missing_reference', 'pending OIDC binding does not match target');
    }
    await m.query(
      `UPDATE one_time_token SET consumed_at=statement_timestamp() WHERE user_id=$1 AND purpose IN ('activation','oidc-activation') AND consumed_at IS NULL`,
      [input.userId],
    );
    const { randomBytes } = await import('node:crypto');
    const activationSecret = randomBytes(32).toString('base64url');
    await m.query(
      `INSERT INTO one_time_token(token_hash,user_id,purpose,expires_at) VALUES($1,$2,$3,statement_timestamp()+interval '15 minutes')`,
      [
        createHash('sha256').update(activationSecret).digest(),
        input.userId,
        input.method === 'local' ? 'activation' : 'oidc-activation',
      ],
    );
    await appendProductAudit(tx, {
      kind: 'root.reissue',
      actor: PRODUCT_OFFLINE_ACTOR,
      target: { userId: input.userId },
      method: input.method,
    });
    return { activationSecret };
  });
}

export interface RootRevocationInput {
  readonly operationId: string;
  readonly userId: IdentityId;
  /** Reference of the independent approval record; never a secret. */
  readonly approval: string;
  readonly reason: string;
}

/**
 * Offline capability only: suspends the Root and ends its sessions (auth_epoch) under the
 * exclusive fence with audit. The marker stays, so no new Root can follow (ADR 0012).
 */
export async function revokeProductRoot(
  runner: ProductTransactionRunner,
  input: RootRevocationInput,
  core: AuthorizationCore,
): Promise<{ revoked: boolean }> {
  const printable = (value: unknown, max: number) =>
    typeof value === 'string' &&
    value.trim().length > 0 &&
    value.length <= max &&
    !/\p{Cc}/u.test(value);

  if (
    !core.isCanonicalUuid(input.operationId) ||
    !core.isCanonicalUuid(input.userId) ||
    !printable(input.approval, 200) ||
    !printable(input.reason, 1000)
  )
    reject('invalid_release', 'invalid Root revocation input');
  return runner.run('bootstrap', async (tx) => {
    const removed = await tx.manager.query<unknown[]>(
      `WITH revoked AS (UPDATE app_user SET state='suspended',auth_epoch=auth_epoch+1 WHERE id=$1 AND kind='root' AND state<>'suspended' RETURNING 1) SELECT * FROM revoked`,
      [input.userId],
    );
    if (!removed.length) return { revoked: false };
    await appendProductAudit(tx, {
      kind: 'root.revoke',
      actor: PRODUCT_OFFLINE_ACTOR,
      target: { userId: input.userId },
      operationId: input.operationId,
      approval: input.approval,
      reason: input.reason,
    });
    return { revoked: true };
  });
}
