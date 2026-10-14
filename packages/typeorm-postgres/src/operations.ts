// Offline capability: provisioning, migration and root bootstrap/revoke/reissue, plus the raw
// audit writer. For CLI/ops tooling only; the API process must not import this entrypoint.
export {
  productDataSourceOptions,
  productMigrations,
  provisionProductDatabase,
} from './product-database.js';
export {
  bootstrapProductRoot,
  revokeProductRoot,
  reissueRootActivation,
  type RootBootstrapInput,
  type RootReissueInput,
  type RootRevocationInput,
} from './product-manifest.js';
// PRODUCT_OFFLINE_ACTOR is also in ./composition (runtime seeds use it); same binding, re-export only.
export { appendProductAudit, PRODUCT_OFFLINE_ACTOR } from './product-audit.js';
