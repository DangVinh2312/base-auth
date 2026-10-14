// Safe service contracts: errors, pure helpers and types. Constructors and low-level adapters are
// in ./composition, offline capability in ./operations, historical tenant APIs in ./legacy.
export { type PostgresConnectionSettings } from './data-source-options.js';
export { TransactionConflictError } from './tenant-transaction.js';
export { ReleaseRejectedError } from './manifest-reconciler.js';
export {
  type ProductConnectionPurpose,
  type ProductTransactionMode,
  type ProductTransactionOptions,
} from './product-transaction.js';
export { type ProductDatabasePurpose } from './product-database.js';
export {
  type Page as ProductPage,
  type Row as ProductRow,
  ProductInvalidRequest,
} from './product-gateway.js';
export { ProductAccessDenied, type ProductResourceWrite } from './product-authority.js';
export { type ProductAuditEvent, type ProductIdentityAuditKind } from './product-audit.js';
export { type ProductStorageBindings } from './product-sql.js';
export {
  type ProductReleaseSource,
  type ProductReleaseManifest,
  type SystemGrant,
  type SystemGrantRemoval,
} from './product-manifest.js';
export {
  type ProductIdentityService,
  rateLimitClient,
  ProductAuthenticationError,
  ProductAuthenticationUnavailable,
  canonicalLoginEmail,
  type ProductSession,
  type ProductSessionIdentity,
  type ProductPasswordHasher,
} from './product-identity.js';
export {
  type ProductOidcService,
  type ProductOidcProvider,
  type ProductOidcProviderConfig,
} from './product-oidc.js';
