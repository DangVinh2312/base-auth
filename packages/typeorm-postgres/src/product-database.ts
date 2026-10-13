import { DataSource, type DataSourceOptions } from 'typeorm';
import type { PostgresConnectionSettings } from './data-source-options.js';
import { ProductInitial1792108800000 } from './migrations/product/001-initial.js';
import { ProductProtection1792108800001 } from './migrations/product/002-protection.js';
import { ProductUserRelationVersion1792108800003 } from './migrations/product/003-user-relation-version.js';

export type ProductDatabasePurpose =
  'data' | 'identity' | 'authority' | 'sync' | 'migration' | 'bootstrap';
export const productMigrations = [
  ProductInitial1792108800000,
  ProductProtection1792108800001,
  ProductUserRelationVersion1792108800003,
];
export function productDataSourceOptions(
  connection: PostgresConnectionSettings,
): DataSourceOptions {
  return {
    type: 'postgres',
    ...connection,
    synchronize: false,
    migrationsRun: false,
    migrationsTransactionMode: 'each',
    logging: false,
    extra: { connectionTimeoutMillis: 1000, max: 10 },
    entities: [],
    migrations: productMigrations,
  };
}
/** Offline provisioning only; this credential must never be wired into the API. */
export async function provisionProductDatabase(
  admin: PostgresConnectionSettings,
  passwords: Readonly<Record<ProductDatabasePurpose, string>>,
): Promise<Record<ProductDatabasePurpose, PostgresConnectionSettings>> {
  const source = await new DataSource(productDataSourceOptions(admin)).initialize();
  const connections = {} as Record<ProductDatabasePurpose, PostgresConnectionSettings>;
  try {
    for (const purpose of [
      'data',
      'identity',
      'authority',
      'sync',
      'migration',
      'bootstrap',
    ] as const) {
      const password = passwords[purpose];
      if (!password || password.includes('\0')) throw new TypeError('Missing product credential');
      const existing = await source.query<
        {
          rolsuper: boolean;
          rolcreatedb: boolean;
          rolcreaterole: boolean;
          rolbypassrls: boolean;
          rolreplication: boolean;
          rolcanlogin: boolean;
        }[]
      >(
        'SELECT rolsuper,rolcreatedb,rolcreaterole,rolbypassrls,rolreplication,rolcanlogin FROM pg_roles WHERE rolname=$1',
        [`product_${purpose}`],
      );
      if (
        existing[0] &&
        (existing[0].rolsuper ||
          existing[0].rolcreatedb ||
          existing[0].rolcreaterole ||
          existing[0].rolbypassrls ||
          existing[0].rolreplication ||
          !existing[0].rolcanlogin)
      )
        throw new Error('Existing product role has unsafe capabilities');
      // PostgreSQL utility statements do not accept bind parameters; quote literals explicitly.
      if (!existing[0]) {
        try {
          await source.query(
            `CREATE ROLE product_${purpose} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD E'${password.replaceAll('\\', '\\\\').replaceAll("'", "''")}'`,
          );
        } catch {
          throw new Error('Unable to provision product credential');
        }
      }
      connections[purpose] = { ...admin, username: `product_${purpose}`, password };
    }
    for (const owner of ['product_fence_owner', 'product_session_owner']) {
      const exists = await source.query<{ present: boolean }[]>(
        'SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1) AS present',
        [owner],
      );
      if (exists[0]?.present) {
        const [ownerState] = await source.query<{ unsafe: boolean }[]>(
          `SELECT (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolbypassrls OR rolreplication) unsafe FROM pg_roles WHERE rolname=$1`,
          [owner],
        );
        if (ownerState?.unsafe) throw new Error('Existing function owner has unsafe capabilities');
      }
      if (!exists[0]?.present)
        await source.query(
          `CREATE ROLE ${owner} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS`,
        );
    }
    await source.query('REVOKE CREATE ON SCHEMA public FROM PUBLIC');
    await source.query(
      'GRANT USAGE ON SCHEMA public TO product_data,product_identity,product_authority,product_sync,product_bootstrap',
    );
    await source.query(
      'GRANT USAGE,CREATE ON SCHEMA public TO product_migration,product_fence_owner,product_session_owner',
    );
    await source.query(
      'GRANT product_fence_owner,product_session_owner TO product_migration WITH ADMIN OPTION',
    );
    const migration = await new DataSource(
      productDataSourceOptions(connections.migration),
    ).initialize();
    try {
      await migration.runMigrations({ transaction: 'each' });
    } finally {
      await migration.destroy();
      await source.query('REVOKE product_fence_owner,product_session_owner FROM product_migration');
      await source.query(
        'REVOKE CREATE ON SCHEMA public FROM product_fence_owner,product_session_owner',
      );
    }
    return connections;
  } finally {
    await source.destroy();
  }
}

/** Startup probe fails closed if credentials or narrow DB capabilities drift. */
export async function verifyProductPrivileges(
  pools: Readonly<Partial<Record<Exclude<ProductDatabasePurpose, 'migration'>, DataSource>>>,
): Promise<void> {
  for (const purpose of Object.keys(pools) as Exclude<ProductDatabasePurpose, 'migration'>[]) {
    const source = pools[purpose];
    if (!source) throw new Error('Missing product pool');
    const [role] = await source.query<
      { name: string; unsafe: boolean }[]
    >(`SELECT current_user AS name,
      (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolbypassrls OR r.rolreplication
       OR has_schema_privilege(current_user,'public','CREATE')
       OR EXISTS(SELECT FROM pg_auth_members m WHERE m.member=r.oid)
       OR EXISTS(SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relowner=r.oid)) AS unsafe
       FROM pg_roles r WHERE r.rolname=current_user`);
    if (role?.name !== `product_${purpose}` || role.unsafe)
      throw new Error('Unsafe product credential');
    const denied: readonly [string, string][] =
      purpose === 'data'
        ? [
            ['local_credential', 'SELECT'],
            ['application_session', 'SELECT'],
            ['user_role', 'INSERT'],
            ['authz_state', 'UPDATE'],
          ]
        : purpose === 'identity'
          ? [
              ['user_role', 'INSERT'],
              ['policy_rule', 'UPDATE'],
              ['security_bootstrap_state', 'UPDATE'],
            ]
          : purpose === 'authority'
            ? [
                ['local_credential', 'SELECT'],
                ['application_session', 'INSERT'],
                ['permission_catalog', 'UPDATE'],
              ]
            : purpose === 'sync'
              ? [
                  ['local_credential', 'SELECT'],
                  ['application_session', 'INSERT'],
                  ['user_role', 'INSERT'],
                  ['app_user', 'UPDATE'],
                ]
              : [
                  ['application_session', 'INSERT'],
                  ['app_user', 'UPDATE'],
                ];
    for (const [table, privilege] of denied) {
      const [check] = await source.query<{ allowed: boolean }[]>(
        'SELECT has_table_privilege(current_user,$1,$2) OR has_any_column_privilege(current_user,$1,$2) AS allowed',
        [`public.${table}`, privilege],
      );
      if (check?.allowed) throw new Error('Product privilege drift');
    }
    if (purpose === 'bootstrap') {
      const [secret] = await source.query<{ allowed: boolean }[]>(
        "SELECT has_column_privilege(current_user,'public.local_credential','password_hash','SELECT') AS allowed",
      );
      if (secret?.allowed) throw new Error('Product privilege drift');
    }
    const [hardening] = await source.query<{ valid: boolean }[]>(`SELECT
      (SELECT count(*)=2 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner
        WHERE n.nspname='public' AND p.proname IN ('authz_acquire_shared_fence','resolve_session')
          AND p.prosecdef AND NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolbypassrls AND NOT r.rolreplication
          AND NOT has_schema_privilege(r.oid,'public','CREATE') AND NOT EXISTS(SELECT FROM pg_auth_members m WHERE m.member=r.oid)
          AND p.proconfig @> ARRAY['search_path=pg_catalog, pg_temp']
          AND NOT EXISTS(SELECT FROM aclexplode(p.proacl) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE'))
      AND (SELECT count(*)=6 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND t.tgname='protect_product_rows' AND t.tgenabled='O') AS valid`);
    if (!hardening?.valid) throw new Error('Product protection drift');
    const [stateProtection] = await source.query<{ valid: boolean }[]>(
      `SELECT count(*)=2 AS valid FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND t.tgname='protect_product_state' AND t.tgenabled='O'`,
    );
    if (!stateProtection?.valid) throw new Error('Product state protection drift');
    if (purpose === 'authority') {
      const [capability] = await source.query<{ valid: boolean }[]>(
        `SELECT has_function_privilege(current_user,'public.resolve_session(bytea)','EXECUTE') AND has_column_privilege(current_user,'public.authz_state','revision','UPDATE') AND has_column_privilege(current_user,'public.app_user','state','UPDATE') AND has_column_privilege(current_user,'public.app_user','auth_epoch','UPDATE') AS valid`,
      );
      if (!capability?.valid) throw new Error('Product authority functions unavailable');
    }
    if (purpose === 'data' || purpose === 'identity') {
      const [functions] = await source.query<
        { valid: boolean }[]
      >(`SELECT has_function_privilege(current_user,'public.authz_acquire_shared_fence(integer)','EXECUTE')
        AND has_function_privilege(current_user,'public.resolve_session(bytea)','EXECUTE') AS valid`);
      if (!functions?.valid) throw new Error('Product functions unavailable');
    }
  }
}
