import type {
  BoundaryRequirement,
  Expr,
  FieldKind,
  KeyKind,
  Lifecycle,
  Obligation,
  RelationRef,
  Scalar,
} from './types.js';

export type PolicyRef = RelationRef;

export interface FieldType {
  readonly kind: FieldKind;
  readonly nullable?: boolean;
}

export interface ActionDeclaration {
  readonly policy: PolicyRef;
  /** Explicit for every action: `required` denies without a binding; `optional` enforces one if bound. */
  readonly boundary: BoundaryRequirement;
}

export interface ResourceDeclaration {
  readonly key: string;
  readonly keyKind: KeyKind;
  readonly fields: Readonly<Record<string, FieldType>>;
  readonly actions: Readonly<Record<string, ActionDeclaration>>;
}

export interface RelationDeclaration {
  readonly key: string;
  readonly version: number;
  readonly sourceType: string;
  readonly target:
    { readonly kind: 'resource'; readonly type: string } | { readonly kind: 'identity' };
  readonly binding:
    { readonly kind: 'edgeStore' } | { readonly kind: 'domain'; readonly key: string };
}

/** Code-owned contract every grant path of a permission must satisfy (spec 4.1). */
export interface PermissionPolicy {
  readonly key: string;
  readonly version: number;
  readonly lifecycle?: Lifecycle;
  readonly contextRequirements: readonly {
    readonly validator: string;
    readonly parameters: Readonly<Record<string, Scalar>>;
  }[];
  /** ANDed outside every grant, including record allows. Use `constant: true` explicitly. */
  readonly requiredScope: Expr;
  readonly obligations: readonly Obligation[];
}

/**
 * Permission boundary (ADR 0003): a code-owned limit bound to a membership per permission. Entries
 * only restrict — ANDed outside every allow, record allows included — and never grant.
 */
export interface PermissionBoundary {
  readonly key: string;
  readonly version: number;
  readonly lifecycle?: Lifecycle;
  readonly entries: readonly {
    readonly permission: string;
    readonly contextRequirements: PermissionPolicy['contextRequirements'];
    readonly requiredScope: Expr;
  }[];
}

export type BoundaryRef = RelationRef;

/** Reviewed scope template. Parameters are typed values bound per rule; no code, no SQL. */
export interface ScopeTemplate {
  readonly key: string;
  readonly version: number;
  readonly resource: string;
  readonly parameters: Readonly<Record<string, FieldKind>>;
  readonly expression: Expr;
}

export interface DeclarationLimits {
  /** Relation path depth; never above the reference profile's 8. */
  readonly maxPathDepth?: number;
  readonly maxExpressionNodes?: number;
  /** Applicable rules per decision; more rules deny instead of being truncated. */
  readonly maxRules?: number;
}

export interface SystemDeclarations {
  readonly resources: readonly ResourceDeclaration[];
  readonly relations: readonly RelationDeclaration[];
  readonly policies: readonly PermissionPolicy[];
  readonly templates: readonly ScopeTemplate[];
  readonly boundaries: readonly PermissionBoundary[];
  /** Validator and obligation handler names the adapter registers; checked for readiness. */
  readonly capabilities: {
    readonly validators: readonly string[];
    readonly obligationHandlers: readonly string[];
  };
  readonly limits?: DeclarationLimits;
}

/** Output of `validate`: frozen lookup tables plus a canonical, order-independent serialization. */
export interface ValidatedDeclarations {
  readonly resources: Readonly<Record<string, ResourceDeclaration>>;
  /** Keyed by `key@version`. */
  readonly relations: Readonly<Record<string, RelationDeclaration>>;
  readonly policies: Readonly<Record<string, PermissionPolicy>>;
  readonly templates: Readonly<Record<string, ScopeTemplate>>;
  /** Keyed by `key@version`. */
  readonly boundaries: Readonly<Record<string, PermissionBoundary>>;
  readonly capabilities: SystemDeclarations['capabilities'];
  readonly limits: Required<DeclarationLimits>;
  /** Hash this (e.g. SHA-256) for the manifest hash; the core has no platform crypto. */
  readonly canonical: string;
}

export type ValidationResult =
  | { readonly ok: true; readonly declarations: ValidatedDeclarations }
  | { readonly ok: false; readonly errors: readonly string[] };

export const refKey = (ref: RelationRef): string => `${ref.key}@${ref.version}`;
