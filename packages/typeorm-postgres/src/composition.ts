// Constructors and low-level wiring for the product runtime. Developer boundary for composition
// roots (apps/api infrastructure, CLI, adapter tests); not process isolation.
export {
  ProductTransactionRunner,
  type ProductTransaction,
} from './runners/product-transaction.runner.js';

export {
  ProductBindingRegistry,
  type ProductResourceBinding,
  compilePlan as compileProductPlan,
  compileNamed as compileProductNamed,
} from './compilers/product-sql.compiler.js';

export { ProductDataGateway } from './gateways/product-data.gateway.js';

export {
  ProductAuthorization,
  PRODUCT_FRESH_AUTH_SQL,
  readProductAuthority,
} from './services/product-authority.service.js';

export { verifyProductPrivileges } from './helpers/product-database.helper.js';

export { PRODUCT_OFFLINE_ACTOR } from './repositories/product-audit.repository.js';

export { ProductAuditOutbox } from './services/product-outbox.service.js';

export {
  productObligations,
  type ProductObligationHandler,
  type ProductObligationRegistry,
} from './helpers/product-obligations.helper.js';

export {
  ProductManifestReconciler,
  prepareProductRelease,
} from './services/product-manifest.service.js';

export {
  ProductIdentityService,
  createProductPasswordHasher,
  newSessionSecret,
  purgeExpiredSessions,
  secretDigest,
  sessionDigest,
} from './services/product-identity.service.js';

export { ProductOidcService, createProductOidcProvider } from './services/product-oidc.service.js';
