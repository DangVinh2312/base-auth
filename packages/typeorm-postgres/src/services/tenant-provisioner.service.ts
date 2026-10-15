import { createHash, createHmac, pbkdf2Sync, randomBytes } from 'node:crypto';
import type { TenantId } from '@base-authorization/core';
import { DataSource, type EntityManager } from 'typeorm';
import {
  identityDataSourceOptions,
  type PostgresConnectionSettings,
  tenantDataSourceOptions,
} from '../helpers/data-source-options.helper.js';
import {
  type ConnectionPurpose,
  connectionPurposes,
  parseRoutableTenant,
  tenantDatabaseName,
  tenantFenceOwnerName,
  tenantRoleName,
} from '../datasource.registry.js';
import { runMigrations } from '../helpers/migrations.helper.js';

export interface ProvisionTenantInput {
  readonly tenantId: TenantId;
  readonly displayLabel: string;
  /** Plaintext stays in this process: roles receive SCRAM verifiers computed locally. */
  readonly passwords: Readonly<Record<ConnectionPurpose, string>>;
}

export interface MigrationResult {
  readonly database: string;
  readonly applied: string[];
}

/**
 * Table privileges per credential in a tenant database ('' = none). Every table must be classified.
 * `data`: domain DML + authority reads; the fence only through `authz_acquire_shared_fence`.
 * `authority`: authority commands after invariant checks (exclusive fence, revision bump).
 * `sync`: manifest reconciliation only (code-owned catalog, seeds, fence/manifest columns); no DDL.
 */
const tenantPrivileges: Readonly<Record<string, Readonly<Record<ConnectionPurpose, string>>>> = {
  tenant_anchor: { data: 'SELECT', authority: 'SELECT', sync: 'SELECT' },
  authz_fence: {
    data: '',
    authority: 'SELECT, UPDATE (revision)',
    sync: 'SELECT, UPDATE (revision, manifest_hash, release_sequence, min_runtime_capability)',
  },
  membership: { data: 'SELECT', authority: 'SELECT, INSERT, UPDATE', sync: '' },
  resource_type: { data: 'SELECT', authority: 'SELECT', sync: 'SELECT, INSERT' },
  permission_policy: {
    data: 'SELECT',
    authority: 'SELECT',
    sync: 'SELECT, INSERT, UPDATE (lifecycle)',
  },
  permission_catalog: {
    data: 'SELECT',
    authority: 'SELECT',
    sync: 'SELECT, INSERT, UPDATE (policy_key, policy_version, lifecycle, boundary_requirement)',
  },
  scope_template: { data: 'SELECT', authority: 'SELECT', sync: 'SELECT, INSERT' },
  resource_relation_definition: {
    data: 'SELECT',
    authority: 'SELECT',
    sync: 'SELECT, INSERT, UPDATE (lifecycle)',
  },
  role_definition: {
    data: 'SELECT',
    authority: 'SELECT, INSERT, UPDATE, DELETE',
    sync: 'SELECT, INSERT, UPDATE (label, authority_level)',
  },
  member_role: { data: 'SELECT', authority: 'SELECT, INSERT, UPDATE, DELETE', sync: '' },
  policy_rule: {
    data: 'SELECT',
    authority: 'SELECT, INSERT, UPDATE, DELETE',
    sync: 'SELECT, INSERT',
  },
  record_exception: { data: 'SELECT', authority: 'SELECT, INSERT, UPDATE, DELETE', sync: '' },
  relation_edge: {
    data: 'SELECT',
    authority: 'SELECT, INSERT, UPDATE, DELETE',
    sync: 'SELECT, INSERT, UPDATE, DELETE',
  },
  identity_relation: { data: 'SELECT', authority: 'SELECT, INSERT, UPDATE, DELETE', sync: '' },
  object_ref: { data: 'SELECT, INSERT, DELETE', authority: 'SELECT', sync: 'SELECT' },
  // Boundary definitions are code-owned (sync only). Runtime binding commands cannot write
  // `seed_owner`, so they can never forge a code-owned binding.
  permission_boundary: {
    data: 'SELECT',
    authority: 'SELECT',
    sync: 'SELECT, INSERT, UPDATE (lifecycle)',
  },
  permission_boundary_entry: { data: 'SELECT', authority: 'SELECT', sync: 'SELECT, INSERT' },
  member_permission_boundary: {
    data: 'SELECT',
    authority:
      'SELECT, INSERT (tenant_id, identity_id, permission_key, boundary_key, boundary_version), UPDATE (boundary_key, boundary_version), DELETE',
    sync: 'SELECT, INSERT, UPDATE (boundary_key, boundary_version), DELETE',
  },
  audit_outbox: { data: 'INSERT', authority: 'INSERT', sync: 'INSERT' },
};
// Old signature kept for expand/contract: it fails once a tenant requires a newer runtime.
const fenceFunctions = [
  'public.authz_acquire_shared_fence(uuid)',
  'public.authz_acquire_shared_fence(uuid, integer)',
];

const purposes: readonly ConnectionPurpose[] = connectionPurposes;
const identifier = /^[a-z_][a-z0-9_]{0,62}$/;

const quote = (name: string) => {
  if (!identifier.test(name)) throw new TypeError('Unsafe SQL identifier');
  return `"${name}"`;
};

/** SCRAM-SHA-256 verifier (RFC 7677) so the plaintext password never reaches server logs. */
function scramVerifier(password: string): string {
  if (!/^[\x21-\x7e]{24,128}$/.test(password)) {
    throw new TypeError(
      'Tenant passwords must be 24-128 printable ASCII characters without spaces',
    );
  }
  const iterations = 4096;
  const salt = randomBytes(16);
  const salted = pbkdf2Sync(password, salt, iterations, 32, 'sha256');
  const storedKey = createHash('sha256')
    .update(createHmac('sha256', salted).update('Client Key').digest())
    .digest();
  const serverKey = createHmac('sha256', salted).update('Server Key').digest();
  return `SCRAM-SHA-256$${iterations}:${salt.toString('base64')}$${storedKey.toString('base64')}:${serverKey.toString('base64')}`;
}

/**
 * Provisions identity and tenant databases with a dedicated admin credential (CREATEDB, CREATEROLE;
 * not superuser). CREATE DATABASE/ROLE cannot share a transaction, so every step is idempotent and
 * a re-run with the same input resumes. The directory row is written last: a tenant becomes
 * routable only after all earlier steps succeeded. No HTTP route exposes this class.
 */
export class TenantProvisioner {
  readonly #admin: PostgresConnectionSettings;
  readonly #identityDatabase: string;

  constructor(admin: PostgresConnectionSettings, options: { identityDatabase: string }) {
    quote(options.identityDatabase);
    this.#admin = admin;
    this.#identityDatabase = options.identityDatabase;
  }

  /** Creates (if missing), locks down and migrates the identity database. */
  async provisionIdentity(): Promise<string[]> {
    const database = this.#identityDatabase;
    await this.#onAdmin(this.#admin.database, async (sql) => {
      await this.#createDatabase(sql, database);
      await sql.query(`REVOKE ALL ON DATABASE ${quote(database)} FROM PUBLIC`);
    });
    await this.#onAdmin(database, (sql) => sql.query('REVOKE ALL ON SCHEMA public FROM PUBLIC'));
    return runMigrations(identityDataSourceOptions({ ...this.#admin, database }));
  }

  async provision(input: ProvisionTenantInput): Promise<TenantId> {
    const tenant = parseRoutableTenant(input.tenantId);
    const label = input.displayLabel.trim();
    if (label.length === 0 || label.length > 120)
      throw new TypeError('Display label must be 1-120 characters');
    const verifiers = {
      data: scramVerifier(input.passwords.data),
      authority: scramVerifier(input.passwords.authority),
      sync: scramVerifier(input.passwords.sync),
    };
    const database = tenantDatabaseName(tenant);
    const roles = purposes.map((purpose) => quote(tenantRoleName(tenant, purpose)));

    await this.#assertDirectoryRoute(tenant, database, { allowMissing: true });

    // Step 1-3 (cluster level): login roles, database, database privileges.
    await this.#onAdmin(this.#admin.database, async (sql) => {
      for (const purpose of purposes) {
        const role = tenantRoleName(tenant, purpose);
        const exists = await sql.query<unknown[]>('SELECT 1 FROM pg_roles WHERE rolname = $1', [
          role,
        ]);
        await sql.query(
          exists.length > 0
            ? `ALTER ROLE ${quote(role)} WITH LOGIN PASSWORD '${verifiers[purpose]}'`
            : `CREATE ROLE ${quote(role)} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
                 NOREPLICATION NOBYPASSRLS PASSWORD '${verifiers[purpose]}'`,
        );
      }
      await this.#ensureFenceOwner(sql, tenant);
      await this.#assertUnprivileged(sql, tenant);
      await this.#createDatabase(sql, database);
      await sql.query(`REVOKE ALL ON DATABASE ${quote(database)} FROM PUBLIC`);
      await sql.query(`GRANT CONNECT ON DATABASE ${quote(database)} TO ${roles.join(', ')}`);
    });

    // Step 4-6 (tenant database): schema lock-down, migrations, fixed anchor, fence, table grants.
    await this.#onAdmin(database, (sql) => sql.query('REVOKE ALL ON SCHEMA public FROM PUBLIC'));
    await runMigrations(tenantDataSourceOptions({ ...this.#admin, database }));
    await this.#onAdmin(database, async (sql) => {
      await sql.query('INSERT INTO tenant_anchor (tenant_id) VALUES ($1) ON CONFLICT DO NOTHING', [
        tenant,
      ]);
      const anchors = await sql.query<{ tenant_id: string }[]>(
        'SELECT tenant_id::text AS tenant_id FROM tenant_anchor',
      );
      if (anchors.length !== 1 || anchors[0]?.tenant_id !== tenant) {
        throw new Error('Tenant database is anchored to a different tenant');
      }
      await sql.query(
        'INSERT INTO authz_fence (tenant_id, manifest_hash) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [tenant, Buffer.alloc(32)],
      );
      await this.#applyPrivileges(sql, tenant);
    });

    // Step 7 (identity database): publish the route; only now is the tenant routable.
    await this.#onAdmin(this.#identityDatabase, (sql) =>
      sql.query(
        `INSERT INTO tenant_directory (id, display_label, route_ref, state)
         VALUES ($1, $2, $3, 'active') ON CONFLICT (id) DO NOTHING`,
        [tenant, label, Buffer.from(database, 'utf8')],
      ),
    );
    await this.#assertDirectoryRoute(tenant, database, { allowMissing: false });
    return tenant;
  }

  /** Migrates identity and every directory tenant, then re-applies the tenant privilege matrix. */
  async migrateAll(): Promise<MigrationResult[]> {
    const identity = this.#identityDatabase;
    const results: MigrationResult[] = [
      {
        database: identity,
        applied: await runMigrations(
          identityDataSourceOptions({ ...this.#admin, database: identity }),
        ),
      },
    ];
    const tenants = await this.#onAdmin(identity, (sql) =>
      sql.query<{ id: string }[]>('SELECT id::text AS id FROM tenant_directory ORDER BY id'),
    );
    for (const row of tenants) {
      const tenant = parseRoutableTenant(row.id);
      const database = tenantDatabaseName(tenant);
      await this.#assertDirectoryRoute(tenant, database, { allowMissing: false });
      results.push({
        database,
        applied: await runMigrations(tenantDataSourceOptions({ ...this.#admin, database })),
      });
      await this.#onAdmin(database, async (sql) => {
        const missing = await sql.query<{ role: string }[]>(
          `SELECT r AS role FROM unnest($1::text[]) r WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r)`,
          [purposes.map((purpose) => tenantRoleName(tenant, purpose))],
        );
        if (missing.length > 0) {
          throw new Error(
            `Tenant ${tenant} lacks login roles (${missing.map((m) => m.role).join(', ')}); re-run provisioning for it`,
          );
        }
        await this.#ensureFenceOwner(sql, tenant);
        await this.#assertUnprivileged(sql, tenant);
        await this.#applyPrivileges(sql, tenant);
      });
    }
    return results;
  }

  /**
   * Dedicated NOLOGIN owner of the shared-fence function. The admin is a member so it can hand over
   * ownership and keep managing the function ACL (it already owns every tenant object).
   */
  async #ensureFenceOwner(sql: EntityManager, tenant: TenantId): Promise<void> {
    const fenceOwner = tenantFenceOwnerName(tenant);
    const exists = await sql.query<unknown[]>('SELECT 1 FROM pg_roles WHERE rolname = $1', [
      fenceOwner,
    ]);
    if (exists.length === 0) {
      await sql.query(
        `CREATE ROLE ${quote(fenceOwner)} WITH NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
           NOREPLICATION NOBYPASSRLS`,
      );
    }
    await sql.query(`GRANT ${quote(fenceOwner)} TO CURRENT_USER WITH INHERIT TRUE, SET TRUE`);
  }

  async #createDatabase(sql: EntityManager, database: string): Promise<void> {
    const exists = await sql.query<unknown[]>('SELECT 1 FROM pg_database WHERE datname = $1', [
      database,
    ]);
    if (exists.length === 0) {
      await sql.query(
        `CREATE DATABASE ${quote(database)} TEMPLATE template0 ENCODING 'UTF8' LOCALE 'C'`,
      );
    }
  }

  async #assertUnprivileged(sql: EntityManager, tenant: TenantId): Promise<void> {
    const elevated = await sql.query<unknown[]>(
      `SELECT rolname FROM pg_roles WHERE rolname = ANY($1)
       AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication
            OR (rolname = $2 AND rolcanlogin))`,
      [
        [
          ...purposes.map((purpose) => tenantRoleName(tenant, purpose)),
          tenantFenceOwnerName(tenant),
        ],
        tenantFenceOwnerName(tenant),
      ],
    );
    if (elevated.length > 0)
      throw new Error('Tenant role has elevated attributes; refusing to continue');
  }

  async #applyPrivileges(sql: EntityManager, tenant: TenantId): Promise<void> {
    const tables = await sql.query<{ name: string }[]>(
      `SELECT tablename AS name FROM pg_tables WHERE schemaname = 'public' AND tablename <> 'migrations'`,
    );
    const unclassified = tables.map((t) => t.name).filter((name) => !(name in tenantPrivileges));
    if (unclassified.length > 0)
      throw new Error(`Unclassified tenant tables: ${unclassified.join(', ')}`);
    const fence = quote(tenantFenceOwnerName(tenant));
    await sql.transaction(async (tx) => {
      const roles = purposes.map((purpose) => quote(tenantRoleName(tenant, purpose)));
      await tx.query(
        `REVOKE ALL ON ALL TABLES IN SCHEMA public FROM ${[...roles, fence].join(', ')}`,
      );
      await tx.query(`GRANT USAGE ON SCHEMA public TO ${[...roles, fence].join(', ')}`);
      for (const [table, grants] of Object.entries(tenantPrivileges)) {
        for (const purpose of purposes) {
          if (grants[purpose] === '') continue;
          await tx.query(
            `GRANT ${grants[purpose]} ON ${quote(table)} TO ${quote(tenantRoleName(tenant, purpose))}`,
          );
        }
      }
      // FOR SHARE needs UPDATE on one column; tenant_id cannot change (FK + single anchor).
      await tx.query(
        `GRANT SELECT (tenant_id, revision, min_runtime_capability), UPDATE (tenant_id) ON authz_fence TO ${fence}`,
      );
      await tx.query(`GRANT SELECT (tenant_id) ON tenant_anchor TO ${fence}`);
      for (const fenceFunction of fenceFunctions) {
        const fn = await tx.query<{ owner: string }[]>(
          `SELECT pg_get_userbyid(proowner) AS owner FROM pg_proc WHERE oid = to_regprocedure($1)`,
          [fenceFunction],
        );
        if (fn.length === 0) continue; // schema not yet at the migration that creates it
        await tx.query(`REVOKE ALL ON FUNCTION ${fenceFunction} FROM PUBLIC, ${roles.join(', ')}`);
        await tx.query(
          `GRANT EXECUTE ON FUNCTION ${fenceFunction} TO ${quote(tenantRoleName(tenant, 'data'))}`,
        );
        if (fn[0]?.owner !== tenantFenceOwnerName(tenant)) {
          // ALTER OWNER requires CREATE on the schema for the new owner: grant only for this statement.
          await tx.query(`GRANT CREATE ON SCHEMA public TO ${fence}`);
          await tx.query(`ALTER FUNCTION ${fenceFunction} OWNER TO ${fence}`);
          await tx.query(`REVOKE CREATE ON SCHEMA public FROM ${fence}`);
        }
      }
    });
  }

  async #assertDirectoryRoute(
    tenant: TenantId,
    database: string,
    { allowMissing }: { allowMissing: boolean },
  ): Promise<void> {
    const rows = await this.#onAdmin(this.#identityDatabase, (sql) =>
      sql.query<{ route: string }[]>(
        `SELECT convert_from(route_ref, 'UTF8') AS route FROM tenant_directory WHERE id = $1`,
        [tenant],
      ),
    );
    if (rows.length === 0 && allowMissing) return;
    if (rows[0]?.route !== database)
      throw new Error('Tenant directory route does not match provisioning');
  }

  async #onAdmin<T>(database: string, run: (sql: EntityManager) => Promise<T>): Promise<T> {
    const dataSource = await new DataSource({
      type: 'postgres',
      ...this.#admin,
      database,
      poolSize: 1,
      synchronize: false,
      migrationsRun: false,
      logging: false,
    }).initialize();
    try {
      return await run(dataSource.manager);
    } finally {
      await dataSource.destroy();
    }
  }
}
