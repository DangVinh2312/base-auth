export type {
  ActionDeclaration,
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
} from './authorization.declarations.js';

export { refKey } from './authorization.declarations.js';

export { IDENTITY_FIELDS, MAX_PATH_DEPTH } from './expression.helper.js';

export { compareText, keyEquals, keyToString, MAX_KEY_BYTES, utf8ByteLength } from './key.codec.js';

export type { Comparison, ScalarCodec, ValueCodecs } from './ports/value-codecs.port.js';

export { canonicalJson } from './policy.validator.js';

export { type AuthorizationCore, createAuthorizationCore } from './authorization.factory.js';

export {
  type BoundaryBindingFact,
  type BoundaryRequirement,
  type ContextValidator,
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
} from './authorization.types.js';
