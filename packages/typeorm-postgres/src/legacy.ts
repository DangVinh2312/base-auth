// Historical tenant-per-database APIs, kept for compatibility tests and legacy tooling. Not part
// of the single-product runtime.
export {
  identityDataSourceOptions,
  tenantDataSourceOptions,
  type PostgresConnectionSettings,
} from './helpers/data-source-options.helper.js';

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
} from './datasource.registry.js';

export { runMigrations } from './helpers/migrations.helper.js';

export {
  type MigrationResult,
  type ProvisionTenantInput,
  TenantProvisioner,
} from './services/tenant-provisioner.service.js';

export {
  type AuthorityFacts,
  type BoundaryBindingChange,
  readAuthorityFacts,
  writeBoundaryBinding,
} from './repositories/authority-store.repository.js';

export { DataGateway, type ListQuery, type Page, type Row } from './gateways/data.gateway.js';

export {
  BindingRegistry,
  type BoundPredicate,
  compileNamed,
  compilePlan,
  type DomainRelationBinding,
  type ResourceBinding,
  type StorageBindings,
} from './compilers/sql.compiler.js';

export { fulfillObligations, type ObligationHandler } from './helpers/obligations.helper.js';

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
} from './runners/tenant-transaction.runner.js';

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
} from './services/manifest-reconciler.service.js';
