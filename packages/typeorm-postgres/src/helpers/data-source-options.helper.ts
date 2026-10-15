import type { DataSourceOptions } from 'typeorm';
import { identityEntities } from '../entities/identity.entity.js';
import { tenantEntities } from '../entities/tenant.entity.js';
import { IdentityInitial1791849600000 } from '../migrations/identity/001-initial.migration.js';
import { TenantInitial1791849600000 } from '../migrations/tenant/001-initial.migration.js';
import { TenantRelationVersion1791936000000 } from '../migrations/tenant/002-relation-version-and-fence.migration.js';
import { TenantPermissionBoundary1792022400000 } from '../migrations/tenant/003-permission-boundary.migration.js';

export interface PostgresConnectionSettings {
  readonly host: string;
  readonly port: number;
  readonly username: string;
  readonly password: string;
  readonly database: string;
}

function options(
  connection: PostgresConnectionSettings,
  entities: DataSourceOptions['entities'],
  migrations: DataSourceOptions['migrations'],
): DataSourceOptions {
  return {
    type: 'postgres',
    host: connection.host,
    port: connection.port,
    username: connection.username,
    password: connection.password,
    database: connection.database,
    entities,
    migrations,
    // Schema changes only through reviewed migrations, run explicitly by tools, never at boot.
    synchronize: false,
    migrationsRun: false,
    migrationsTransactionMode: 'each',
    logging: false,
  };
}

/** Identity/control-plane database. Independent of any Nest module. */
export function identityDataSourceOptions(
  connection: PostgresConnectionSettings,
): DataSourceOptions {
  return options(connection, identityEntities, [IdentityInitial1791849600000]);
}

/** One tenant database. Independent of any Nest module. */
export function tenantDataSourceOptions(connection: PostgresConnectionSettings): DataSourceOptions {
  return options(connection, tenantEntities, [
    TenantInitial1791849600000,
    TenantRelationVersion1791936000000,
    TenantPermissionBoundary1792022400000,
  ]);
}
