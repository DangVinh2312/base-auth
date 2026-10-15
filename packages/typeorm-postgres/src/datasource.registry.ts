import type { TenantId } from '@base-authorization/core';
import { DataSource, type DataSourceOptions } from 'typeorm';
import { tenantEntities } from './entities/tenant.entity.js';

const routableTenant = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * Legacy tenant routing: database and role identifiers are derived from the tenant id, so this is
 * the SQL identifier grammar owned here (canonical lowercase UUID only, no aliases), not a value
 * codec. Throws instead of normalizing.
 */
export function parseRoutableTenant(value: unknown): TenantId {
  if (typeof value !== 'string' || !routableTenant.test(value))
    throw new TypeError('Tenant id must be a canonical lowercase UUID');
  return value as TenantId;
}

/**
 * Chosen by the gateway/command adapter, never taken from a client request.
 * `data`: domain DML + authority reads (shared fence). `authority`: authority commands (exclusive).
 * `sync`: manifest reconciliation at deploy/boot only (exclusive); never given to handlers.
 */
export type ConnectionPurpose = 'data' | 'authority' | 'sync';

export interface TenantRoute {
  readonly database: string;
  readonly username: string;
  readonly password: string;
  /** Part of the pool key: rotating credentials opens a new pool and retires the old one. */
  readonly credentialVersion: string;
}

export interface TenantConnectionLease {
  /** For storage adapters only; never hand it to business handlers. */
  readonly dataSource: DataSource;

  /** Idempotent. Hold the lease for the whole transaction. */
  release(): Promise<void>;
}

export interface TenantDataSourceRegistryOptions {
  readonly host: string;
  readonly port: number;
  readonly poolSize: Readonly<Record<ConnectionPurpose, number>>;
  /** Connection budget across all tenant pools of this process. */
  readonly maxConnections: number;
  readonly idleTimeoutMs: number;

  /** Resolves a verified tenant to its active route, or undefined when it is not routable. */
  resolveRoute(tenant: TenantId, purpose: ConnectionPurpose): Promise<TenantRoute | undefined>;

  /** Test seam; defaults to a TypeORM DataSource. */
  createDataSource?(options: DataSourceOptions): DataSource;
}

/** Invalid, unknown, disabled or mis-anchored tenant. Map to the same response as "not found". */
export class TenantRoutingError extends Error {}

/** Capacity exhausted or registry closed. Retryable; map to 503. */
export class TenantUnavailableError extends Error {}

interface PoolEntry {
  readonly tenant: TenantId;
  readonly purpose: ConnectionPurpose;
  readonly size: number;
  readonly ready: Promise<DataSource>;
  refs: number;
  lastReleased: number;
  idleTimer?: NodeJS.Timeout;
}

export const connectionPurposes: readonly ConnectionPurpose[] = ['data', 'authority', 'sync'];
const purposes: readonly string[] = connectionPurposes;

/**
 * Tenant pools keyed by (tenant, purpose, credential version): single-flight creation, reference
 * counted leases, idle eviction only at zero references, and a hard connection budget.
 */
export class TenantDataSourceRegistry {
  readonly #options: TenantDataSourceRegistryOptions;
  /** Pools that may hand out new leases. */
  readonly #pools = new Map<string, PoolEntry>();
  /** Every pool still holding connections (open or retired), for the budget. */
  readonly #open = new Set<PoolEntry>();
  readonly #closing = new Set<Promise<void>>();
  #closed = false;

  constructor(options: TenantDataSourceRegistryOptions) {
    this.#options = options;
  }

  async acquire(tenantInput: TenantId, purpose: ConnectionPurpose): Promise<TenantConnectionLease> {
    let tenant: TenantId;
    try {
      tenant = parseRoutableTenant(tenantInput);
    } catch {
      throw new TenantRoutingError('Tenant is not routable');
    }
    if (!purposes.includes(purpose)) throw new TenantRoutingError('Unknown connection purpose');
    if (this.#closed) throw new TenantUnavailableError('Tenant registry is closed');

    const route = await this.#options.resolveRoute(tenant, purpose);
    if (!route) throw new TenantRoutingError('Tenant is not routable');
    if (this.#closed) throw new TenantUnavailableError('Tenant registry is closed');

    // No await between lookup and insert: concurrent acquires share one entry (single-flight).
    const key = JSON.stringify([tenant, purpose, route.credentialVersion]);
    for (const [otherKey, other] of this.#pools) {
      if (other.tenant === tenant && other.purpose === purpose && otherKey !== key) {
        this.#pools.delete(otherKey);
        if (other.refs === 0) void this.#destroy(other);
      }
    }
    const entry = this.#pools.get(key) ?? this.#create(key, tenant, purpose, route);
    entry.refs++;
    clearTimeout(entry.idleTimer);

    let dataSource: DataSource;
    try {
      dataSource = await entry.ready;
    } catch (error) {
      entry.refs--;
      throw error;
    }
    let released = false;
    return {
      dataSource,

      release: async () => {
        if (released) return;
        released = true;
        await this.#release(key, entry);
      },
    };
  }

  async close(): Promise<void> {
    this.#closed = true;
    this.#pools.clear();
    for (const entry of this.#open) void this.#destroy(entry);
    await Promise.all(this.#closing);
  }

  #create(
    key: string,
    tenant: TenantId,
    purpose: ConnectionPurpose,
    route: TenantRoute,
  ): PoolEntry {
    const size = this.#options.poolSize[purpose];
    let used = [...this.#open].reduce((sum, entry) => sum + entry.size, 0);
    if (used + size > this.#options.maxConnections) {
      const idle = [...this.#open]
        .filter((entry) => entry.refs === 0)
        .sort((a, b) => a.lastReleased - b.lastReleased);
      const evict: PoolEntry[] = [];
      for (const entry of idle) {
        if (used + size <= this.#options.maxConnections) break;
        evict.push(entry);
        used -= entry.size;
      }
      if (used + size > this.#options.maxConnections) {
        throw new TenantUnavailableError('Tenant connection capacity exhausted');
      }
      for (const entry of evict) void this.#destroy(entry);
    }

    // Connect only after evicted/retiring pools have closed, so the budget is never exceeded.
    const closing = [...this.#closing];
    const entry: PoolEntry = {
      tenant,
      purpose,
      size,
      refs: 0,
      lastReleased: 0,
      ready: Promise.all(closing).then(() => this.#connect(tenant, purpose, route, size)),
    };
    entry.ready.catch(() => {
      if (this.#pools.get(key) === entry) this.#pools.delete(key);
      this.#open.delete(entry);
    });
    this.#pools.set(key, entry);
    this.#open.add(entry);
    return entry;
  }

  async #connect(
    tenant: TenantId,
    purpose: ConnectionPurpose,
    route: TenantRoute,
    size: number,
  ): Promise<DataSource> {
    const options: DataSourceOptions = {
      type: 'postgres',
      host: this.#options.host,
      port: this.#options.port,
      username: route.username,
      password: route.password,
      database: route.database,
      poolSize: size,
      applicationName: `base-authorization:${purpose}`,
      entities: tenantEntities,
      synchronize: false,
      migrationsRun: false,
      logging: false,
    };
    const dataSource = this.#options.createDataSource?.(options) ?? new DataSource(options);
    await dataSource.initialize();
    try {
      // Defends against directory tampering and mixed-up secrets: the database must belong to the tenant.
      const anchors = await dataSource.query<{ tenant_id: string }[]>(
        'SELECT tenant_id::text AS tenant_id FROM tenant_anchor',
      );
      if (anchors.length !== 1 || anchors[0]?.tenant_id !== tenant) {
        throw new TenantRoutingError('Tenant database anchor does not match the route');
      }
    } catch (error) {
      await dataSource.destroy();
      throw error;
    }
    return dataSource;
  }

  async #release(key: string, entry: PoolEntry): Promise<void> {
    entry.refs--;
    entry.lastReleased = performance.now();
    if (entry.refs > 0 || !this.#open.has(entry)) return;
    if (this.#pools.get(key) !== entry) {
      await this.#destroy(entry); // retired by credential rotation
      return;
    }
    entry.idleTimer = setTimeout(() => {
      if (entry.refs === 0 && this.#pools.get(key) === entry) {
        this.#pools.delete(key);
        void this.#destroy(entry);
      }
    }, this.#options.idleTimeoutMs).unref();
  }

  #destroy(entry: PoolEntry): Promise<void> {
    if (!this.#open.delete(entry)) return Promise.resolve();
    clearTimeout(entry.idleTimer);
    for (const [key, candidate] of this.#pools) if (candidate === entry) this.#pools.delete(key);
    const closing = entry.ready.then(
      (dataSource) => dataSource.destroy(),
      () => undefined,
    );
    this.#closing.add(closing);
    void closing.finally(() => this.#closing.delete(closing));
    return closing;
  }
}

/**
 * Routes through the identity directory: only active entries resolve. Role names are derived from
 * the tenant id; passwords come from the secret source and are never logged.
 */
export function directoryRouteResolver(
  identity: DataSource,
  secrets: (
    tenant: TenantId,
    purpose: ConnectionPurpose,
  ) => Promise<{ password: string; credentialVersion: string } | undefined>,
): TenantDataSourceRegistryOptions['resolveRoute'] {
  return async (tenant, purpose) => {
    const rows = await identity.query<{ database: string }[]>(
      `SELECT convert_from(route_ref, 'UTF8') AS database FROM tenant_directory
       WHERE id = $1 AND state = 'active'`,
      [tenant],
    );
    const database = rows[0]?.database;
    const secret = database === undefined ? undefined : await secrets(tenant, purpose);
    if (database === undefined || !secret) return undefined;
    return { database, username: tenantRoleName(tenant, purpose), ...secret };
  };
}

/** Deterministic, injection-free names derived from the canonical tenant UUID. */
export function tenantDatabaseName(tenant: TenantId): string {
  return `authz_t_${parseRoutableTenant(tenant).replaceAll('-', '')}`;
}

export function tenantRoleName(tenant: TenantId, purpose: ConnectionPurpose): string {
  if (!purposes.includes(purpose)) throw new TypeError('Unknown connection purpose');
  return `${tenantDatabaseName(tenant)}_${purpose}`;
}

/** NOLOGIN owner of the shared-fence SECURITY DEFINER function in the tenant database. */
export function tenantFenceOwnerName(tenant: TenantId): string {
  return `${tenantDatabaseName(tenant)}_fence`;
}
