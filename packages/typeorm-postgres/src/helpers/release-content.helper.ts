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
  type ValidatedDeclarations,
} from '@base-authorization/core';

/** Default grant created only when its permission first appears in the product catalog. */
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
 * Release content from a trusted deployment artifact (never from an HTTP client).
 * Nothing here is signed yet: release signing is deferred until before staging (ADR 0004).
 */
export interface ReleaseContentSource {
  /** Monotonic release sequence assigned by the pipeline (int64 decimal). */
  readonly sequence: string;
  /** Sequence the product must currently be at ('0' for the first release). */
  readonly predecessor: string;
  readonly declarations: SystemDeclarations;
  readonly defaultGrants: readonly DefaultGrant[];
  readonly seeds: readonly RelationSeed[];
  readonly removeSeeds: readonly SeedRemoval[];
  readonly boundaryBindings: readonly BoundaryBindingSeed[];
  readonly removeBoundaryBindings: readonly BoundaryBindingRemoval[];
}

/**
 * Release content validated in-process (structure, references, types, size), not a cryptographic
 * signature check; the trust limit is documented in ADR 0004.
 */
export interface ValidatedReleaseContent extends Omit<ReleaseContentSource, 'declarations'> {
  readonly declarations: ValidatedDeclarations;
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

/** The product is not ready for this build; nothing was written. */
export class ReleaseRejectedError extends Error {
  constructor(
    readonly reason: RejectReason,
    detail: string,
  ) {
    super(`Release rejected (${reason}): ${detail}`);
  }
}

const identifier = /^[a-z][A-Za-z0-9_]*(\.[a-z][A-Za-z0-9_]*)*$/;
const ownerKey = /^[a-z][a-z0-9._-]{0,127}$/;

const reject = (reason: RejectReason, detail: string): never => {
  throw new ReleaseRejectedError(reason, detail);
};

const sha256 = (text: string) => createHash('sha256').update(text).digest('hex');

const contentLimits = {
  defaultGrants: 1_000,
  seeds: 1_000,
  removeSeeds: 1_000,
  boundaryBindings: 1_000,
  removeBoundaryBindings: 1_000,
};
const maxRoles = 200;

/**
 * Key grammar, uniqueness, label and count of release roles.
 */
export function validateRoleKeys(
  roles: readonly { readonly key: string; readonly label: string }[],
): ReadonlySet<string> {
  if (roles.length > maxRoles) reject('invalid_release', 'too many roles');
  const keys = new Set<string>();
  for (const role of roles) {
    if (!identifier.test(role.key) || keys.has(role.key))
      reject('invalid_release', `role ${role.key}`);
    if (role.label.trim().length === 0 || role.label.length > 120)
      reject('invalid_release', `role ${role.key} label`);
    keys.add(role.key);
  }
  return keys;
}

function validateHead(source: ReleaseContentSource, core: AuthorizationCore) {
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
  return { sequence: sequence!, predecessor: predecessor!, declarations: validated.declarations };
}

function checkContentLimits(source: ReleaseContentSource): void {
  for (const [name, limit] of Object.entries(contentLimits)) {
    if (source[name as keyof typeof contentLimits].length > limit)
      reject('invalid_release', `too many ${name}`);
  }
}

function validateBody(
  source: ReleaseContentSource,
  core: AuthorizationCore,
  head: ReturnType<typeof validateHead>,
  roleKeys: ReadonlySet<string>,
): ValidatedReleaseContent {
  const { declarations } = head;
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
  return {
    sequence: head.sequence,
    predecessor: head.predecessor,
    declarations,
    defaultGrants,
    seeds,
    removeSeeds,
    boundaryBindings,
    removeBoundaryBindings,
  };
}

/** Everything but roles: sequence, declarations, limits, references, typed parameters and keys. */
export function validateReleaseContent(
  source: ReleaseContentSource,
  core: AuthorizationCore,
  roleKeys: ReadonlySet<string>,
): ValidatedReleaseContent {
  const head = validateHead(source, core);
  checkContentLimits(source);
  return validateBody(source, core, head, roleKeys);
}

const byJson = <T>(items: readonly T[]) =>
  [...items].sort((a, b) => (canonicalJson(a) < canonicalJson(b) ? -1 : 1));

/** Canonical release envelope: unchanged keys and order keep deployed manifest hashes stable. */
export function releaseContentHash(
  content: ValidatedReleaseContent,
  roles: readonly object[],
): string {
  return sha256(
    canonicalJson({
      declarations: JSON.parse(content.declarations.canonical) as unknown,
      roles: byJson(roles),
      defaultGrants: byJson(content.defaultGrants),
      seeds: byJson(content.seeds),
      removeSeeds: byJson(content.removeSeeds),
      boundaryBindings: byJson(content.boundaryBindings),
      removeBoundaryBindings: byJson(content.removeBoundaryBindings),
    }),
  );
}
