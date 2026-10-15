// Constructors and low-level wiring for the product runtime. Developer boundary for composition
// roots (apps/api infrastructure, CLI, adapter tests); not process isolation.
export { ProductTransactionRunner, type ProductTransaction } from './product-transaction.js';
export {
  ProductBindingRegistry,
  type ProductResourceBinding,
  compilePlan as compileProductPlan,
  compileNamed as compileProductNamed,
} from './product-sql.js';
export { ProductDataGateway } from './product-gateway.js';
export { ProductAuthorization, readProductAuthority } from './product-authority.js';
export { verifyProductPrivileges } from './product-database.js';
export { PRODUCT_OFFLINE_ACTOR } from './product-audit.js';
export { ProductAuditOutbox } from './product-outbox.js';
export {
  productObligations,
  type ProductObligationHandler,
  type ProductObligationRegistry,
} from './product-obligations.js';
export { ProductManifestReconciler, prepareProductRelease } from './product-manifest.js';
export {
  ProductIdentityService,
  createProductPasswordHasher,
  newSessionSecret,
  purgeExpiredSessions,
  secretDigest,
  sessionDigest,
} from './product-identity.js';
export { ProductOidcService, createProductOidcProvider } from './product-oidc.js';
