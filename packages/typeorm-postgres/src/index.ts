export {
  identityDataSourceOptions,
  tenantDataSourceOptions,
  type PostgresConnectionSettings,
} from './data-source-options.js';
export {
  type ConnectionPurpose,
  directoryRouteResolver,
  type TenantConnectionLease,
  TenantDataSourceRegistry,
  type TenantDataSourceRegistryOptions,
  tenantDatabaseName,
  tenantFenceOwnerName,
  tenantRoleName,
  type TenantRoute,
  TenantRoutingError,
  TenantUnavailableError,
} from './datasource-registry.js';
export { runMigrations } from './migrations.js';
export {
  type MigrationResult,
  type ProvisionTenantInput,
  TenantProvisioner,
} from './tenant-provisioner.js';
export {
  type AuthorityFacts,
  type BoundaryBindingChange,
  readAuthorityFacts,
  writeBoundaryBinding,
} from './authority-store.js';
export { DataGateway, type ListQuery, type Page, type Row } from './data-gateway.js';
export {
  BindingRegistry,
  type BoundPredicate,
  compileNamed,
  compilePlan,
  type DomainRelationBinding,
  type ResourceBinding,
  type StorageBindings,
} from './sql-compiler.js';
export { fulfillObligations, type ObligationHandler } from './obligations.js';
export {
  type AuthorityRegistry,
  AuthorityUnavailableError,
  PostgresAuthority,
  RUNTIME_CAPABILITY,
  TenantTransactionRunner,
  type TenantTransaction,
  TransactionConflictError,
  type TransactionMode,
  type TransactionOptions,
} from './tenant-transaction.js';
export {
  type BoundaryBindingRemoval,
  type BoundaryBindingSeed,
  type CodeRole,
  type DefaultGrant,
  ManifestReconciler,
  prepareRelease,
  type ReconcilerOptions,
  type RejectReason,
  ReleaseRejectedError,
  type ReleaseSource,
  type RelationSeed,
  type SeedRemoval,
  type SyncResult,
  type VerifiedReleaseManifest,
} from './manifest-reconciler.js';
export {
  productDataSourceOptions,
  productMigrations,
  provisionProductDatabase,
  verifyProductPrivileges,
  type ProductDatabasePurpose,
} from './product-database.js';
export {
  ProductTransactionRunner,
  type ProductTransaction,
  type ProductTransactionMode,
  type ProductTransactionOptions,
  type ProductConnectionPurpose,
} from './product-transaction.js';
export {
  ProductBindingRegistry,
  type ProductResourceBinding,
  type ProductStorageBindings,
  compilePlan as compileProductPlan,
  compileNamed as compileProductNamed,
} from './product-sql.js';
export {
  ProductDataGateway,
  type Page as ProductPage,
  type Row as ProductRow,
} from './product-gateway.js';
export {
  ProductAuthorization,
  ProductAccessDenied,
  readProductAuthority,
  type ProductResourceWrite,
} from './product-authority.js';
export {
  ProductManifestReconciler,
  prepareProductRelease,
  systemGrantHash,
  type ProductReleaseSource,
  type ProductReleaseManifest,
  type SystemGrant,
  type SystemGrantRemoval,
} from './product-manifest.js';
export {
  ProductIdentityService,
  ProductAuthenticationError,
  ProductAuthenticationUnavailable,
  createProductPasswordHasher,
  canonicalLoginEmail,
  newSessionSecret,
  secretDigest,
  sessionDigest,
  type ProductSession,
  type ProductSessionIdentity,
  type ProductPasswordHasher,
} from './product-identity.js';
export {
  ProductOidcService,
  createProductOidcProvider,
  type ProductOidcProvider,
  type ProductOidcProviderConfig,
} from './product-oidc.js';
export { bootstrapProductRoot, type RootBootstrapInput } from './product-manifest.js';
