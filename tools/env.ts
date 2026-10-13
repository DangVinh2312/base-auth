import type { PostgresConnectionSettings } from '@base-authorization/typeorm-postgres';

/** Reads a required variable; error messages name the variable, never its value. */
export function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

/** Provisioning/migration principal. Only CLI tools receive it; the API never does. */
export function adminConnection(): PostgresConnectionSettings {
  const raw = requireEnv('DATABASE_ADMIN_URL');
  const url = URL.canParse(raw) ? new URL(raw) : undefined;
  if (!url || !['postgres:', 'postgresql:'].includes(url.protocol) || !url.username) {
    throw new Error(
      'DATABASE_ADMIN_URL must be a postgres:// URL with user and maintenance database',
    );
  }
  return {
    host: url.hostname,
    port: Number(url.port || '5432'),
    username: decodeURIComponent(url.username),
    password: decodeURIComponent(url.password),
    database: decodeURIComponent(url.pathname.slice(1)) || 'postgres',
  };
}

export function identityDatabaseName(): string {
  return process.env.IDENTITY_DATABASE_NAME || 'authz_identity';
}
