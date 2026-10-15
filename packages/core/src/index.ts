export type {
  ActionDeclaration,
  BoundaryRef,
  DeclarationLimits,
  FieldType,
  PermissionBoundary,
  PermissionPolicy,
  PolicyRef,
  RelationDeclaration,
  ResourceDeclaration,
  ScopeTemplate,
  SystemDeclarations,
  ValidatedDeclarations,
  ValidationResult,
} from './declarations.js';

export { refKey } from './declarations.js';

export { IDENTITY_FIELDS, MAX_PATH_DEPTH } from './expression.js';

export { compareText, keyEquals, keyToString, MAX_KEY_BYTES, utf8ByteLength } from './key-codec.js';

export type { Comparison, ScalarCodec, ValueCodecs } from './ports/value-codecs.js';

export { canonicalJson } from './policy-validator.js';

export { type AuthorizationCore, createAuthorizationCore } from './runtime.js';

export {
  type AuthoritySnapshot,
  type AuthorizedPlan,
  type BoundaryBindingFact,
  type BoundaryRequirement,
  type CompleteFacts,
  type ContextValidator,
  type Decision,
  type EdgeFact,
  type ExceptionFact,
  type Expr,
  type FactObject,
  type FieldKind,
  type FieldValue,
  type IdentityId,
  type Key,
  type KeyKind,
  type Lifecycle,
  type Obligation,
  type PermissionFact,
  type PlanExpr,
  type RelationRef,
  type RuleFact,
  type Scalar,
  type TenantId,
  type TrustedInput,
  type TrustedPrincipal,
  type UserId,
  type UserTrustedInput,
  type UserAuthoritySnapshot,
  type UserAuthorizedPlan,
  type UserDecision,
  type UserEdgeFact,
  type UserExceptionFact,
  type UserCompleteFacts,
  type ValueRef,
} from './types.js';
