// Historical tenant-per-database APIs, kept for compatibility tests and legacy tooling. Not part
// of the single-product runtime.
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
