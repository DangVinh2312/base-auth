import type {
  SystemDeclarations,
  ValidatedDeclarations,
  ValidationResult,
} from './declarations.js';
import { evaluate as evaluateWith, evaluateUser as evaluateUserWith } from './evaluator.js';
import { fieldKinds } from './expression.js';
import { MAX_KEY_BYTES, utf8ByteLength } from './key-codec.js';
import {
  plan as planWith,
  planUnrestricted as planUnrestrictedWith,
  planUser as planUserWith,
} from './planner.js';
import { validateDeclarations } from './policy-validator.js';
import type { Comparison, ValueCodecs } from './ports/value-codecs.js';
import type {
  AuthorizedPlan,
  AuthoritySnapshot,
  CompleteFacts,
  Decision,
  FieldKind,
  Key,
  KeyKind,
  Scalar,
  TenantId,
  TrustedInput,
  UserAuthorizedPlan,
  UserAuthoritySnapshot,
  UserCompleteFacts,
  UserDecision,
  UserTrustedInput,
} from './types.js';

/**
 * One authorization engine bound to one set of value codecs. Declarations and plans carry the
 * provenance of the instance that produced them; another instance refuses them (fail closed).
 * Members are plain functions (no `this`), so destructuring them is safe.
 */
export interface AuthorizationCore {
  readonly validate: (declarations: SystemDeclarations) => ValidationResult;
  /** True only for declarations this instance validated (copies and other instances' are refused). */
  readonly isValidated: (value: unknown) => value is ValidatedDeclarations;
  readonly planUser: (input: UserTrustedInput, snapshot: UserAuthoritySnapshot) => UserDecision;
  readonly evaluateUser: (plan: UserAuthorizedPlan, facts: UserCompleteFacts) => UserDecision;
  /**
   * planUser's checks with predicate `true` and no obligations, for a principal the adapter has
   * verified as unrestricted. Only ProductAuthorization.access may call it (ESLint, ADR 0012):
   * a developer boundary, not a sandbox.
   */
  readonly planUnrestricted: (
    input: UserTrustedInput,
    snapshot: UserAuthoritySnapshot,
  ) => UserDecision;
  /** Legacy tenant contracts; tenant is still checked. */
  readonly plan: (input: TrustedInput, snapshot: AuthoritySnapshot) => Decision;
  readonly evaluate: (plan: AuthorizedPlan, facts: CompleteFacts) => Decision;
  /** Canonical value of a field kind, or undefined when the input is not one. */
  readonly normalizeValue: (kind: FieldKind, input: unknown) => Scalar | undefined;
  /** Exact comparison of two normalized values. */
  readonly compareValues: (kind: FieldKind, left: Scalar, right: Scalar) => Comparison;
  readonly canonicalTimestamp: (input: unknown) => string | undefined;
  readonly canonicalInt64: (input: unknown) => string | undefined;
  /** External key: int64 (bigint or canonical string), uuid (lowercased), text of 1..256 UTF-8 bytes. */
  readonly parseKey: (kind: KeyKind, input: unknown) => Key;
  /** Canonical lowercase UUID only (identity/tenant ids are never normalized). */
  readonly isCanonicalUuid: (input: unknown) => input is string;
  readonly parseTenantId: (input: unknown) => TenantId;
}

interface Codec {
  normalize(input: unknown): unknown;
  compare(left: Scalar, right: Scalar): unknown;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null;

/** Copies the six codecs (bound, frozen) so later changes to the supplied table cannot leak in. */
function captureCodecs(values: unknown): Readonly<Record<FieldKind, Codec>> {
  const codecs = {} as Record<FieldKind, Codec>;
  for (const kind of fieldKinds) {
    const codec = isRecord(values) ? values[kind] : undefined;
    if (
      !isRecord(codec) ||
      typeof codec.normalize !== 'function' ||
      typeof codec.compare !== 'function'
    )
      throw new TypeError(`Value codec ${kind} is missing or malformed`);
    const normalize = codec.normalize as (input: unknown) => unknown;
    const compare = codec.compare as (left: Scalar, right: Scalar) => unknown;
    codecs[kind] = Object.freeze({
      normalize: (input: unknown) => normalize.call(codec, input),
      compare: (left: Scalar, right: Scalar) => compare.call(codec, left, right),
    });
  }
  return Object.freeze(codecs);
}

/**
 * Creates an authorization core with explicitly injected value codecs (no default engine). A codec
 * that throws or answers outside its contract surfaces as an error, which every decision path turns
 * into deny; `validate` returns `{ ok: false }` instead of accepting.
 */
export function createAuthorizationCore(options: {
  readonly values: ValueCodecs;
}): AuthorizationCore {
  const codecs = captureCodecs(isRecord(options) ? options.values : undefined);
  const validated = new WeakSet<object>();
  const issued = new WeakSet<object>();

  const codecOf = (kind: FieldKind): Codec => {
    if (!fieldKinds.includes(kind)) throw new TypeError('Unknown field kind');
    return codecs[kind];
  };
  const normalizeValue = (kind: FieldKind, input: unknown): Scalar | undefined => {
    const value = codecOf(kind).normalize(input);
    if (value === undefined) return undefined;
    if (typeof value !== (kind === 'boolean' ? 'boolean' : 'string'))
      throw new TypeError(`Value codec ${kind} returned a value outside its contract`);
    return value as Scalar;
  };
  const compareValues = (kind: FieldKind, left: Scalar, right: Scalar): Comparison => {
    const order = codecOf(kind).compare(left, right);
    if (order !== -1 && order !== 0 && order !== 1)
      throw new TypeError(`Value codec ${kind} returned an invalid comparison`);
    return order;
  };
  const text = (kind: 'timestamp' | 'integer') => (input: unknown) =>
    normalizeValue(kind, input) as string | undefined;
  const canonicalTimestamp = text('timestamp');
  const canonicalInt64 = text('integer');
  // Validity is the codec's; the lowercase-only identity invariant is the core's own, so a codec
  // that keeps uppercase cannot relax identity/tenant checks.
  const isCanonicalUuid = (input: unknown): input is string =>
    typeof input === 'string' &&
    input === input.toLowerCase() &&
    normalizeValue('uuid', input) === input;

  const issue = <D extends Decision | UserDecision>(decision: D): D => {
    if (decision.effect === 'allow') issued.add(decision.plan);
    return decision;
  };
  const foreign = () => ({ effect: 'deny', internalReason: 'foreign_plan' }) as const;

  const core: AuthorizationCore = Object.freeze({
    validate(declarations: SystemDeclarations): ValidationResult {
      let result: ValidationResult;
      try {
        result = validateDeclarations(declarations, normalizeValue);
      } catch {
        // A failing codec (or validator fault) is a configuration error; no input value is echoed.
        return { ok: false, errors: ['declarations could not be validated: value codec failure'] };
      }
      if (result.ok) validated.add(result.declarations);
      return result;
    },
    isValidated: (value: unknown): value is ValidatedDeclarations =>
      isRecord(value) && validated.has(value),
    planUser: (input: UserTrustedInput, snapshot: UserAuthoritySnapshot) =>
      issue(planUserWith(core, input, snapshot)),
    evaluateUser: (plan: UserAuthorizedPlan, facts: UserCompleteFacts) =>
      isRecord(plan) && issued.has(plan) ? evaluateUserWith(core, plan, facts) : foreign(),
    planUnrestricted: (input: UserTrustedInput, snapshot: UserAuthoritySnapshot) =>
      issue(planUnrestrictedWith(core, input, snapshot)),
    plan: (input: TrustedInput, snapshot: AuthoritySnapshot) =>
      issue(planWith(core, input, snapshot)),
    evaluate: (plan: AuthorizedPlan, facts: CompleteFacts) =>
      isRecord(plan) && issued.has(plan) ? evaluateWith(core, plan, facts) : foreign(),
    normalizeValue,
    compareValues,
    canonicalTimestamp,
    canonicalInt64,
    parseKey(kind: KeyKind, input: unknown): Key {
      if (kind === 'integer') {
        const value = canonicalInt64(input);
        if (value === undefined)
          throw new TypeError('Integer key must be a canonical int64 decimal string or bigint');
        return { kind, value };
      }
      if (kind === 'uuid') {
        const value = normalizeValue('uuid', input);
        if (typeof value !== 'string') throw new TypeError('UUID key is malformed');
        return { kind, value };
      }
      if (kind === 'string') {
        const value = normalizeValue('string', input);
        if (
          typeof value !== 'string' ||
          value.length === 0 ||
          utf8ByteLength(value) > MAX_KEY_BYTES
        )
          throw new TypeError(
            `String key must be well-formed text of 1-${MAX_KEY_BYTES} UTF-8 bytes`,
          );
        return { kind, value };
      }
      throw new TypeError('Unknown key kind');
    },
    isCanonicalUuid,
    parseTenantId(input: unknown): TenantId {
      if (!isCanonicalUuid(input))
        throw new TypeError('Tenant id must be a canonical lowercase UUID');
      return input as TenantId;
    },
  });
  return core;
}
