import { DataSource, type DataSourceOptions } from 'typeorm';
import type { PostgresConnectionSettings } from './data-source-options.js';
import { ProductInitial1792108800000 } from './migrations/product/001-initial.js';
import {
  ProductProtection1792108800001,
  productStateBody,
  sharedFenceBody,
} from './migrations/product/002-protection.js';
import { ProductUserRelationVersion1792108800003 } from './migrations/product/003-user-relation-version.js';
import {
  accountLifecycleBody,
  ProductProtectionGuards1792108800004,
} from './migrations/product/004-protection-guards.js';
import { ProductOidcActivation1792108800005 } from './migrations/product/005-oidc-activation.js';
import { ProductAccountRank1792108800006 } from './migrations/product/006-account-rank.js';
import { ProductRootMarker1792108800007 } from './migrations/product/007-root-marker.js';
import {
  ProductSystemActivation1792108800008,
  tokenConsumptionBody,
} from './migrations/product/008-system-activation.js';
import { ProductSessionExpiryIndex1792108800009 } from './migrations/product/009-session-expiry-index.js';
import { ProductAuditOutboxDelivery1792108800010 } from './migrations/product/010-audit-outbox-delivery.js';
import { ProductAuditOutboxPendingIndex1792108800011 } from './migrations/product/011-audit-outbox-pending-index.js';
import {
  guardRootActivationBody,
  guardRootKindBody,
  guardRootLifecycleBody,
  guardRootNotIamSubjectBody,
  ProductIamRoot1792108800012,
  productRowsIamBody,
  requireRootMarkerKindBody,
  resolveSessionKindBody,
} from './migrations/product/012-iam-root.js';

export type ProductDatabasePurpose =
  'data' | 'identity' | 'authority' | 'sync' | 'migration' | 'bootstrap' | 'outbox';

export const productMigrations = [
  ProductInitial1792108800000,
  ProductProtection1792108800001,
  ProductUserRelationVersion1792108800003,
  ProductProtectionGuards1792108800004,
  ProductOidcActivation1792108800005,
  ProductAccountRank1792108800006,
  ProductRootMarker1792108800007,
  ProductSystemActivation1792108800008,
  ProductSessionExpiryIndex1792108800009,
  ProductAuditOutboxDelivery1792108800010,
  ProductAuditOutboxPendingIndex1792108800011,
  ProductIamRoot1792108800012,
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

/**
 * Offline provisioning only; this credential must never be wired into the API. `migrations` is
 * the forward list to run (default: all). Upgrade rehearsals pass a prefix, e.g. up to 011.
 */
export async function provisionProductDatabase(
  admin: PostgresConnectionSettings,
  passwords: Readonly<Record<ProductDatabasePurpose, string>>,
  migrations: readonly (typeof productMigrations)[number][] = productMigrations,
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
      'outbox',
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
    // Runtime logins need no temp objects; one session's temp table would otherwise trip another
    // replica's ownership probe.
    await source.query(
      "DO $$BEGIN EXECUTE format('REVOKE TEMP ON DATABASE %I FROM PUBLIC',current_database()); END$$",
    );
    await source.query(
      'GRANT USAGE ON SCHEMA public TO product_data,product_identity,product_authority,product_sync,product_bootstrap,product_outbox',
    );
    await source.query(
      'GRANT USAGE,CREATE ON SCHEMA public TO product_migration,product_fence_owner,product_session_owner',
    );
    await source.query(
      'GRANT product_fence_owner,product_session_owner TO product_migration WITH ADMIN OPTION',
    );
    const migration = await new DataSource({
      ...productDataSourceOptions(connections.migration),
      migrations: [...migrations],
    }).initialize();
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

type RuntimePurpose = Exclude<ProductDatabasePurpose, 'migration'>;
const authorityTables = [
  'resource_type',
  'permission_policy',
  'permission_catalog',
  'scope_template',
  'role_definition',
  'user_role',
  'policy_rule',
  'object_ref',
  'record_exception',
  'resource_relation_definition',
  'relation_edge',
  'user_relation',
  'permission_boundary',
  'permission_boundary_entry',
  'user_boundary',
];

const tables = (privileges: readonly string[], names: readonly string[]) =>
  names.flatMap((name) => privileges.map((p) => `table:${name}:${p}`));

const columns = (privilege: string, table: string, names: readonly string[]) =>
  names.map((name) => `column:${table}.${name}:${privilege}`);

const sharedFence = 'function:authz_acquire_shared_fence(integer):EXECUTE';
const resolveSession = 'function:resolve_session(bytea):EXECUTE';
const audit = 'table:audit_outbox:INSERT';
/** Exact grants of each runtime login after the product migrations (credential matrix, ADR0008). */
const expectedPrivileges: Readonly<Record<RuntimePurpose, readonly string[]>> = {
  data: [
    ...tables(['SELECT'], authorityTables),
    ...columns('SELECT', 'app_user', ['id', 'state', 'auth_epoch']),
    audit,
    sharedFence,
    resolveSession,
  ],
  identity: [
    ...tables(
      ['SELECT', 'INSERT', 'UPDATE', 'DELETE'],
      [
        'local_credential',
        'external_identity',
        'application_session',
        'oidc_login_attempt',
        'rate_limit',
      ],
    ),
    ...tables(['SELECT', 'INSERT'], ['one_time_token']),
    'column:one_time_token.consumed_at:UPDATE',
    ...tables(['SELECT'], ['oidc_provider', 'app_user', 'authz_state']),
    ...columns('INSERT', 'app_user', [
      'id',
      'email_canonical',
      'email_verified',
      'state',
      'auth_epoch',
    ]),
    ...columns('UPDATE', 'app_user', ['email_verified', 'state', 'auth_epoch']),
    'column:authz_state.revision:UPDATE',
    audit,
    sharedFence,
    resolveSession,
  ],
  authority: [
    ...tables(['SELECT'], [...authorityTables, 'authz_state']),
    ...columns('SELECT', 'app_user', ['id', 'state', 'auth_epoch', 'kind']),
    ...columns('UPDATE', 'app_user', ['state', 'auth_epoch']),
    'table:iam_account:SELECT',
    'column:authz_state.revision:UPDATE',
    ...tables(
      ['INSERT', 'UPDATE', 'DELETE'],
      [
        'role_definition',
        'user_role',
        'policy_rule',
        'record_exception',
        'relation_edge',
        'user_relation',
        'user_boundary',
        'object_ref',
      ],
    ),
    audit,
    resolveSession,
  ],
  sync: [
    ...tables(['SELECT'], [...authorityTables, 'oidc_provider']),
    ...tables(['SELECT', 'UPDATE'], ['authz_state']),
    ...tables(
      ['INSERT', 'UPDATE', 'DELETE'],
      [
        'resource_type',
        'permission_policy',
        'permission_catalog',
        'scope_template',
        'role_definition',
        'policy_rule',
        'resource_relation_definition',
        'permission_boundary',
        'permission_boundary_entry',
        'relation_edge',
        'user_boundary',
        'oidc_provider',
      ],
    ),
    'table:object_ref:INSERT',
    audit,
  ],
  bootstrap: [
    ...tables(['SELECT'], [...authorityTables, 'authz_state']),
    ...columns('SELECT', 'app_user', ['id', 'state', 'auth_epoch', 'email_canonical', 'kind']),
    ...columns('UPDATE', 'app_user', ['kind', 'state', 'auth_epoch']),
    'column:local_credential.user_id:SELECT',
    ...columns('SELECT', 'external_identity', [
      'issuer',
      'subject',
      'user_id',
      'enabled',
      'binding_version',
    ]),
    'column:authz_state.revision:UPDATE',
    ...tables(['SELECT', 'UPDATE'], ['security_bootstrap_state']),
    'table:one_time_token:INSERT',
    ...columns('SELECT', 'one_time_token', ['user_id', 'purpose', 'consumed_at']),
    'column:one_time_token.consumed_at:UPDATE',
    audit,
  ],
  // Audit delivery worker: reads events, writes delivery state only; no fence, no other table.
  outbox: [
    'table:audit_outbox:SELECT',
    ...columns('UPDATE', 'audit_outbox', [
      'delivered_at',
      'delivery_attempts',
      'lease_token',
      'lease_until',
      'dead_at',
    ]),
  ],
};

/** Protection functions in public: VOLATILE, owner, SECURITY DEFINER and exact migration body. */
const protectionFunctions: Readonly<Record<string, readonly [string, boolean, string]>> = {
  authz_acquire_shared_fence: ['product_fence_owner', true, sharedFenceBody],
  resolve_session: ['product_session_owner', true, resolveSessionKindBody],
  protect_product_state: ['product_migration', false, productStateBody],
  protect_product_rows: ['product_migration', false, productRowsIamBody],
  protect_account_lifecycle: ['product_migration', false, accountLifecycleBody],
  protect_token_consumption: ['product_migration', false, tokenConsumptionBody],
  guard_root_kind: ['product_session_owner', true, guardRootKindBody],
  require_root_marker_kind: ['product_session_owner', true, requireRootMarkerKindBody],
  guard_root_not_iam_subject: ['product_session_owner', true, guardRootNotIamSubjectBody],
  guard_root_activation: ['product_session_owner', true, guardRootActivationBody],
  guard_root_lifecycle: ['product_session_owner', true, guardRootLifecycleBody],
};
/** PostgreSQL 18 pg_get_viewdef output of the IAM-only projection installed by migration 012. */
const iamAccountDefinition = ` SELECT id,
    state
   FROM app_user
  WHERE (kind = 'iam'::text);`;
/**
 * Every non-internal trigger on the protected tables, as
 * table.trigger:function:tgtype:UPDATE OF columns:enabled:deferrable:initially deferred.
 * tgtype bits: 1 ROW, 2 BEFORE, 4 INSERT, 8 DELETE, 16 UPDATE.
 */
const protectionTriggers = new Set([
  ...[
    'role_definition',
    'policy_rule',
    'record_exception',
    'user_role',
    'relation_edge',
    'user_boundary',
  ].map((table) => `${table}.protect_product_rows:protect_product_rows:31::O:false:false`),
  ...['user_role', 'user_boundary', 'policy_rule', 'record_exception'].map(
    (table) => `${table}.guard_root_not_iam_subject:guard_root_not_iam_subject:23::O:false:false`,
  ),
  'security_bootstrap_state.protect_product_state:protect_product_state:19::O:false:false',
  'authz_state.protect_product_state:protect_product_state:19::O:false:false',
  'app_user.protect_account_lifecycle:protect_account_lifecycle:19::O:false:false',
  'app_user.guard_root_kind:guard_root_kind:23:kind:O:false:false',
  'app_user.require_root_marker_kind:require_root_marker_kind:17:kind:O:true:true',
  'app_user.guard_root_lifecycle:guard_root_lifecycle:19:auth_epoch,state:O:false:false',
  'one_time_token.guard_root_activation:guard_root_activation:7::O:false:false',
  'one_time_token.protect_token_consumption:protect_token_consumption:19::O:false:false',
]);
const protectedTables = [...new Set([...protectionTriggers].map((t) => t.split('.')[0]!))];
/**
 * Exact ACL of the NOLOGIN owner of resolve_session and the Root guards: the 002/008 grants with
 * the 012 delta (spec 3.2). Anything more widens what every SECURITY DEFINER guard can do.
 */
const sessionOwnerAcl: readonly string[] = [
  'schema:public:USAGE',
  ...columns('SELECT', 'app_user', ['id', 'state', 'auth_epoch', 'email_verified', 'kind']),
  'column:app_user.kind:UPDATE',
  ...columns('SELECT', 'application_session', [
    'token_hash',
    'user_id',
    'auth_epoch',
    'method',
    'assurance',
    'authenticated_at',
    'reauthenticated_at',
    'expires_at',
    'revoked_at',
    'last_seen_at',
    'credential_version',
    'external_issuer',
    'external_subject',
    'binding_version',
    'provider_version',
  ]),
  ...columns('SELECT', 'local_credential', ['user_id', 'version']),
  ...columns('SELECT', 'external_identity', [
    'issuer',
    'subject',
    'user_id',
    'enabled',
    'binding_version',
  ]),
  ...columns('SELECT', 'oidc_provider', ['issuer', 'version', 'enabled']),
  ...['user_role', 'user_boundary', 'policy_rule', 'record_exception'].map(
    (table) => `column:${table}.user_id:SELECT`,
  ),
  ...columns('SELECT', 'one_time_token', ['user_id', 'purpose', 'consumed_at', 'expires_at']),
  'table:security_bootstrap_state:SELECT',
  ...[
    'resolve_session(bytea)',
    'guard_root_kind()',
    'require_root_marker_kind()',
    'guard_root_not_iam_subject()',
    'guard_root_activation()',
    'guard_root_lifecycle()',
  ].map((fn) => `function:${fn}:EXECUTE`),
];

/**
 * `grantee`-filtered grants on every table, column and function in a non-system schema (objects
 * outside public are reported schema-qualified), plus schema grants when `withSchemas`.
 */
const grantsOf = (grantees: string, withSchemas: boolean) =>
  `WITH schemas AS (SELECT oid,nspname,CASE WHEN nspname='public' THEN '' ELSE nspname||'.' END AS prefix FROM pg_namespace
        WHERE nspname NOT IN ('pg_catalog','information_schema') AND nspname NOT LIKE 'pg\\_toast%' AND nspname NOT LIKE 'pg\\_temp\\_%'),
      acl AS (
        ${withSchemas ? `SELECT 'schema:'||q.nspname AS object,a.privilege_type,a.is_grantable,a.grantee FROM pg_namespace n JOIN schemas q ON q.oid=n.oid,aclexplode(n.nspacl) a UNION ALL` : ''}
        SELECT 'table:'||q.prefix||c.relname AS object,a.privilege_type,a.is_grantable,a.grantee
          FROM pg_class c JOIN schemas q ON q.oid=c.relnamespace,aclexplode(c.relacl) a
        UNION ALL
        SELECT 'column:'||q.prefix||c.relname||'.'||t.attname,a.privilege_type,a.is_grantable,a.grantee
          FROM pg_attribute t JOIN pg_class c ON c.oid=t.attrelid JOIN schemas q ON q.oid=c.relnamespace,
          aclexplode(t.attacl) a WHERE t.attnum>0 AND NOT t.attisdropped
        UNION ALL
        SELECT 'function:'||q.prefix||p.proname||'('||oidvectortypes(p.proargtypes)||')',a.privilege_type,a.is_grantable,a.grantee
          FROM pg_proc p JOIN schemas q ON q.oid=p.pronamespace,aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a)
      SELECT DISTINCT object||':'||privilege_type||CASE WHEN is_grantable THEN '+grant' ELSE '' END AS grant
        FROM acl WHERE grantee IN (${grantees})`;

/**
 * Startup probe fails closed if credentials or narrow DB capabilities drift. Every table, column
 * and function grant held directly or through PUBLIC in any non-system schema must equal the
 * expected set plus `additional` grants on application-owned tables. Owning any object or
 * schema, or CREATE on the database, is unsafe.
 */
export async function verifyProductPrivileges(
  pools: Readonly<Partial<Record<RuntimePurpose, DataSource>>>,
  additional: Readonly<Partial<Record<RuntimePurpose, readonly string[]>>> = {},
): Promise<void> {
  for (const purpose of Object.keys(pools) as RuntimePurpose[]) {
    const source = pools[purpose];
    if (!source) throw new Error('Missing product pool');
    const [role] = await source.query<
      { name: string; unsafe: boolean }[]
    >(`SELECT current_user AS name,
      (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolbypassrls OR r.rolreplication
       OR EXISTS(SELECT FROM pg_namespace n WHERE has_schema_privilege(current_user,n.oid,'CREATE'))
       OR has_database_privilege(current_user,current_database(),'CREATE')
       OR has_database_privilege(current_user,current_database(),'TEMP')
       -- a login must not be able to re-delegate the access it holds
       OR EXISTS(SELECT FROM pg_namespace n WHERE has_schema_privilege(current_user,n.oid,'USAGE WITH GRANT OPTION'))
       OR has_database_privilege(current_user,current_database(),'CONNECT WITH GRANT OPTION')
       -- replica mode skips every protection trigger
       OR has_parameter_privilege(current_user,'session_replication_role','SET')
       OR current_setting('session_replication_role')<>'origin'
       OR EXISTS(SELECT FROM pg_auth_members m WHERE m.member=r.oid)
       OR EXISTS(SELECT FROM pg_namespace n WHERE n.nspowner=r.oid)
       OR EXISTS(SELECT FROM pg_proc p WHERE p.proowner=r.oid)
       OR EXISTS(SELECT FROM pg_class c WHERE c.relowner=r.oid)) AS unsafe
       FROM pg_roles r WHERE r.rolname=current_user`);
    if (role?.name !== `product_${purpose}` || role.unsafe)
      throw new Error('Unsafe product credential');
    const granted = await source.query<{ grant: string }[]>(
      grantsOf('0,(SELECT oid FROM pg_roles WHERE rolname=current_user)', false),
    );
    const actual = new Set(granted.map((g) => g.grant));
    const expected = new Set([...expectedPrivileges[purpose], ...(additional[purpose] ?? [])]);
    const unexpected = [...actual].filter((g) => !expected.has(g));
    const missing = [...expected].filter((g) => !actual.has(g));
    if (unexpected.length || missing.length)
      throw new Error(
        `Product privilege drift for ${purpose}: unexpected [${unexpected.sort().join(', ')}], missing [${missing.sort().join(', ')}]`,
      );
    const [hardening] = await source.query<{ valid: boolean }[]>(`SELECT
      (SELECT count(*)=2 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner
        WHERE n.nspname='public' AND p.proname IN ('authz_acquire_shared_fence','resolve_session')
          AND p.prosecdef AND NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolbypassrls AND NOT r.rolreplication
          AND NOT has_schema_privilege(r.oid,'public','CREATE') AND NOT EXISTS(SELECT FROM pg_auth_members m WHERE m.member=r.oid)
          AND p.proconfig @> ARRAY['search_path=pg_catalog, pg_temp']) AS valid`);
    if (!hardening?.valid) throw new Error('Product protection drift');
    const ownerGrants = await source.query<{ grant: string }[]>(
      grantsOf("SELECT oid FROM pg_roles WHERE rolname='product_session_owner'", true),
    );
    const ownerActual = new Set(ownerGrants.map((g) => g.grant));
    if (
      ownerActual.size !== sessionOwnerAcl.length ||
      sessionOwnerAcl.some((g) => !ownerActual.has(g))
    )
      throw new Error('Product protection drift');
    const [view] = await source.query<{ valid: boolean }[]>(
      `SELECT pg_get_viewdef(c.oid,false)=$1 AND COALESCE(c.reloptions @> ARRAY['security_invoker=true'],false) AS valid
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relname='iam_account' AND c.relkind='v'`,
      [iamAccountDefinition],
    );
    if (!view?.valid) throw new Error('Product protection drift');
    const functions = await source.query<
      {
        name: string;
        owner: string;
        definer: boolean;
        volatility: string;
        body: string;
        config: string[] | null;
      }[]
    >(
      `SELECT p.proname AS name,r.rolname AS owner,p.prosecdef AS definer,p.provolatile AS volatility,p.prosrc AS body,p.proconfig AS config
        FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner
        WHERE n.nspname='public' AND p.proname=ANY($1)`,
      [Object.keys(protectionFunctions)],
    );
    const triggers = await source.query<{ trigger: string }[]>(
      `SELECT c.relname||'.'||t.tgname||':'
          ||CASE WHEN fn.nspname='public' AND t.tgqual IS NULL AND t.tgnargs=0 THEN p.proname ELSE '(unexpected)' END||':'
          ||t.tgtype::text||':'
          ||COALESCE((SELECT string_agg(a.attname,',' ORDER BY a.attname) FROM pg_attribute a
            WHERE a.attrelid=t.tgrelid AND a.attnum=ANY(t.tgattr)),'')||':'
          ||t.tgenabled::text||':'||t.tgdeferrable::text||':'||t.tginitdeferred::text AS trigger
        FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
        JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_namespace fn ON fn.oid=p.pronamespace
        WHERE n.nspname='public' AND NOT t.tgisinternal AND c.relname=ANY($1)`,
      [protectedTables],
    );
    const actualTriggers = new Set(triggers.map((t) => t.trigger));
    if (
      functions.length !== Object.keys(protectionFunctions).length ||
      functions.some(({ name, owner, definer, volatility, body, config }) => {
        const [expectedOwner, expectedDefiner, expectedBody] = protectionFunctions[name]!;
        return (
          owner !== expectedOwner ||
          definer !== expectedDefiner ||
          volatility !== 'v' ||
          body !== expectedBody ||
          config?.join('|') !== 'search_path=pg_catalog, pg_temp'
        );
      }) ||
      actualTriggers.size !== triggers.length ||
      actualTriggers.size !== protectionTriggers.size ||
      [...protectionTriggers].some((t) => !actualTriggers.has(t))
    )
      throw new Error('Product protection drift');
  }
}
