import type { ValidatedDeclarations } from './declarations.js';

/** Branded tenant id. The brand prevents programming mistakes only; it is not a security boundary. */
export type TenantId = string & { readonly tenantId: unique symbol };
/** Branded global identity id (canonical lowercase UUID). Not a security boundary either. */
export type IdentityId = string & { readonly identityId: unique symbol };

const canonicalUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function isCanonicalUuid(value: unknown): value is string {
  return typeof value === 'string' && canonicalUuid.test(value);
}

/**
 * Accepts only the canonical lowercase UUID form so one tenant cannot have aliases.
 * Throws instead of normalizing: callers must not route on unverified spellings.
 */
export function parseTenantId(value: unknown): TenantId {
  if (!isCanonicalUuid(value)) throw new TypeError('Tenant id must be a canonical lowercase UUID');
  return value as TenantId;
}

export type KeyKind = 'integer' | 'uuid' | 'string';
/** Typed object key. Integers stay canonical decimal strings, never JS numbers. */
export interface Key {
  readonly kind: KeyKind;
  readonly value: string;
}

export type FieldKind = 'integer' | 'decimal' | 'string' | 'uuid' | 'boolean' | 'timestamp';
export type Scalar = string | boolean;

export type ValueRef =
  | { readonly from: 'literal'; readonly value: string | boolean | null }
  | { readonly from: 'principal' | 'context' | 'parameter'; readonly name: string };

/** Declaration AST written by system code (templates, required scopes). No `not`: only the core creates it. */
export type Expr =
  | { readonly op: 'constant'; readonly value: boolean }
  | { readonly op: 'and' | 'or'; readonly args: readonly Expr[] }
  | { readonly op: 'eq' | 'lt' | 'lte'; readonly field: string; readonly value: ValueRef }
  | { readonly op: 'isNull'; readonly field: string }
  | { readonly op: 'exists'; readonly relation: string; readonly where: Expr };

export interface RelationRef {
  readonly key: string;
  readonly version: number;
}

/** Lowered, typed, fully bound predicate. Compilers and the evaluator consume only this. */
export type PlanExpr =
  | { readonly op: 'constant'; readonly value: boolean }
  | { readonly op: 'and' | 'or'; readonly args: readonly PlanExpr[] }
  | { readonly op: 'not'; readonly arg: PlanExpr }
  | {
      readonly op: 'eq' | 'lt' | 'lte';
      readonly field: string;
      readonly kind: FieldKind;
      readonly value: Scalar;
    }
  | { readonly op: 'isNull'; readonly field: string }
  | {
      readonly op: 'exists';
      readonly relation: RelationRef;
      readonly source: string;
      readonly target:
        { readonly kind: 'resource'; readonly type: string } | { readonly kind: 'identity' };
      readonly where: PlanExpr;
    }
  | {
      /** Record exception lookup on the requested object; created by the core only. */
      readonly op: 'exception';
      readonly effect: 'allow' | 'deny';
      readonly permission: string;
      readonly identity: IdentityId;
      readonly roles: readonly string[];
    };

export interface Obligation {
  readonly handler: string;
}

export interface AuthorizedPlan {
  readonly tenant: TenantId;
  readonly identity: IdentityId;
  readonly resource: string;
  readonly action: string;
  readonly permission: string;
  readonly revision: string;
  readonly predicate: PlanExpr;
  readonly validUntil: string;
  readonly obligations: readonly Obligation[];
}

export type Decision =
  | { readonly effect: 'deny'; readonly internalReason: string }
  | {
      readonly effect: 'allow';
      readonly plan: AuthorizedPlan;
      readonly obligations: readonly Obligation[];
    };

export interface TrustedPrincipal {
  readonly id: IdentityId;
  readonly assurance: number;
}

/** Built by trusted adapters only (verified session, validated routing, authority clock). */
export interface TrustedInput {
  readonly tenant: TenantId;
  readonly principal: TrustedPrincipal;
  readonly resource: string;
  readonly action: string;
  readonly context: Readonly<Record<string, Scalar>>;
  /** Trusted decision instant, `YYYY-MM-DDTHH:MM:SS[.ffffff]Z`. */
  readonly now: string;
  /** min(session expiry, request deadline); the plan is unusable afterwards. */
  readonly validUntil: string;
}

/**
 * Context validator registered by an adapter. Reads trusted context only: no record data,
 * no network I/O. Anything other than `true` (including a throw) denies.
 */
export type ContextValidator = (
  parameters: Readonly<Record<string, Scalar>>,
  input: {
    readonly principal: TrustedPrincipal;
    readonly context: Readonly<Record<string, Scalar>>;
  },
) => boolean | 'unknown';

export type Lifecycle = 'active' | 'deprecated' | 'retired';
/** Code-owned per action (ADR 0003). Never chosen by a caller; there is no default. */
export type BoundaryRequirement = 'required' | 'optional';

export interface PermissionFact {
  readonly key: string;
  readonly resource: string;
  readonly action: string;
  readonly policy: RelationRef;
  /** Stored requirement; `null` (not yet synced) never matches the code and denies. */
  readonly boundary: BoundaryRequirement | null;
  readonly lifecycle: Lifecycle;
}

/** The membership's boundary binding for one permission, with the stored definition lifecycle. */
export interface BoundaryBindingFact {
  readonly identity: IdentityId;
  readonly permission: string;
  readonly boundary: RelationRef;
  readonly lifecycle: Lifecycle;
}

export interface RuleFact {
  readonly id: string;
  readonly permission: string;
  readonly subject:
    | { readonly kind: 'role'; readonly role: string }
    | { readonly kind: 'identity'; readonly identity: IdentityId };
  readonly effect: 'allow' | 'deny';
  readonly template: RelationRef;
  readonly parameters: Readonly<Record<string, Scalar>>;
}

/** Authority facts read inside the tenant transaction, plus the adapter's handler registry. */
export interface AuthoritySnapshot {
  readonly tenant: TenantId;
  readonly revision: string;
  readonly declarations: ValidatedDeclarations;
  readonly membership:
    { readonly identity: IdentityId; readonly state: 'active' | 'suspended' } | undefined;
  readonly roles: readonly string[];
  readonly permissions: readonly PermissionFact[];
  readonly rules: readonly RuleFact[];
  /** Permission boundary bindings of this membership, read under the same fence/revision. */
  readonly boundaries: readonly BoundaryBindingFact[];
  readonly registry: {
    readonly validators: Readonly<Record<string, ContextValidator>>;
    readonly obligationHandlers: readonly string[];
  };
}

export type FieldValue = string | boolean | null;

export interface FactObject {
  readonly type: string;
  readonly key: Key;
  readonly objectId: string;
  readonly fields: Readonly<Record<string, FieldValue>>;
}

export interface EdgeFact {
  readonly tenant: TenantId;
  readonly relation: RelationRef;
  readonly source: string;
  readonly target:
    | { readonly kind: 'object'; readonly objectId: string }
    | { readonly kind: 'identity'; readonly identity: IdentityId };
  readonly startsAt: string;
  readonly expiresAt: string | null;
}

export interface ExceptionFact {
  readonly tenant: TenantId;
  readonly objectId: string;
  readonly permission: string;
  readonly subject: RuleFact['subject'];
  readonly effect: 'allow' | 'deny';
  readonly purpose: 'manual' | 'emergency';
  readonly startsAt: string;
  readonly expiresAt: string | null;
  readonly revokedAt: string | null;
}

/** Everything needed to decide one record; missing facts make the evaluator deny. */
export interface CompleteFacts {
  readonly tenant: TenantId;
  readonly now: string;
  readonly record: FactObject;
  readonly objects: readonly FactObject[];
  readonly edges: readonly EdgeFact[];
  readonly exceptions: readonly ExceptionFact[];
}

/** Product user id; UUID validation is still required at trusted adapter boundaries. */
export type UserId = IdentityId;
export type UserTrustedInput = Omit<TrustedInput, 'tenant'>;
export type UserAuthoritySnapshot = Omit<AuthoritySnapshot, 'tenant' | 'membership'> & {
  readonly user:
    { readonly id: UserId; readonly state: 'active' | 'suspended' | 'pending' } | undefined;
};
export type UserAuthorizedPlan = Omit<AuthorizedPlan, 'tenant' | 'identity'> & {
  readonly userId: UserId;
};
export type UserDecision =
  | Extract<Decision, { effect: 'deny' }>
  | {
      readonly effect: 'allow';
      readonly plan: UserAuthorizedPlan;
      readonly obligations: readonly Obligation[];
    };
export type UserEdgeFact = Omit<EdgeFact, 'tenant'>;
export type UserExceptionFact = Omit<ExceptionFact, 'tenant'>;
export type UserCompleteFacts = Omit<CompleteFacts, 'tenant' | 'edges' | 'exceptions'> & {
  readonly edges: readonly UserEdgeFact[];
  readonly exceptions: readonly UserExceptionFact[];
};
