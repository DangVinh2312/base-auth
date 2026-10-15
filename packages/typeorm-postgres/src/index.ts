// Safe service contracts: errors, pure helpers and types. Constructors and low-level adapters are
// in ./composition, offline capability in ./operations, historical tenant APIs in ./legacy.
export { type PostgresConnectionSettings } from './helpers/data-source-options.helper.js';

export { TransactionConflictError } from './runners/tenant-transaction.runner.js';

export { ReleaseRejectedError } from './services/manifest-reconciler.service.js';

export {
  type ProductConnectionPurpose,
  type ProductTransactionMode,
  type ProductTransactionOptions,
} from './runners/product-transaction.runner.js';

export { type ProductDatabasePurpose } from './helpers/product-database.helper.js';

export {
  type Page as ProductPage,
  type Row as ProductRow,
  ProductInvalidRequest,
} from './gateways/product-data.gateway.js';

export {
  ProductAccessDenied,
  type ProductResourceWrite,
} from './services/product-authority.service.js';

export {
  type ProductAuditEvent,
  type ProductIdentityAuditKind,
} from './repositories/product-audit.repository.js';

export {
  type ProductAuditEnvelope,
  type ProductAuditSink,
  type ProductOutboxClaim,
  type ProductOutboxOptions,
} from './services/product-outbox.service.js';

export { type ProductStorageBindings } from './compilers/product-sql.compiler.js';

export {
  type ProductReleaseSource,
  type ProductReleaseManifest,
  type ProductRole,
} from './services/product-manifest.service.js';

export {
  type ProductIdentityService,
  rateLimitClient,
  ProductAuthenticationError,
  ProductAuthenticationUnavailable,
  canonicalLoginEmail,
  type ProductSession,
  type ProductSessionIdentity,
  type ProductPasswordHasher,
} from './services/product-identity.service.js';

export {
  type ProductOidcService,
  type ProductOidcProvider,
  type ProductOidcProviderConfig,
} from './services/product-oidc.service.js';
