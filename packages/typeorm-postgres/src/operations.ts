// Offline capability: provisioning, migration and root bootstrap/revoke/reissue, plus the raw
// audit writer. For CLI/ops tooling only; the API process must not import this entrypoint.
export {
  productDataSourceOptions,
  productMigrations,
  provisionProductDatabase,
} from './helpers/product-database.helper.js';

export {
  bootstrapProductRoot,
  revokeProductRoot,
  reissueRootActivation,
  type RootBootstrapInput,
  type RootReissueInput,
  type RootRevocationInput,
} from './services/product-manifest.service.js';

// PRODUCT_OFFLINE_ACTOR is also in ./composition (runtime seeds use it); same binding, re-export only.
export {
  appendProductAudit,
  PRODUCT_OFFLINE_ACTOR,
} from './repositories/product-audit.repository.js';
