import type { LogLevel } from '@nestjs/common';
import type { ProductOidcProviderConfig } from '../auth/services/product-oidc.service.js';

export interface AppConfig {
  readonly nodeEnv: 'development' | 'test' | 'production';
  readonly port: number;
  /** Reverse-proxy hops whose X-Forwarded-For is trusted for the client address; 0 trusts none. */
  readonly trustProxy: number;
  readonly logLevels: LogLevel[];
  readonly databases: Readonly<Record<'data' | 'identity' | 'authority' | 'sync', URL>>;
  readonly origin: URL;
  readonly localEnabled: boolean;
  readonly oidcProviders: readonly ProductOidcProviderConfig[];
}

export class ConfigError extends Error {}

export function loadConfig(env: NodeJS.ProcessEnv): AppConfig {
  const errors: string[] = [];
  const nodeEnv = env.NODE_ENV;
  if (nodeEnv !== 'development' && nodeEnv !== 'test' && nodeEnv !== 'production')
    errors.push('NODE_ENV must be development, test or production');
  const port = Number(env.PORT || '3000');
  if (!Number.isInteger(port) || port < 0 || port > 65535) errors.push('PORT must be 0–65535');
  const trustProxy = /^[0-9]$/.test(env.TRUST_PROXY || '0') ? Number(env.TRUST_PROXY || '0') : NaN;
  if (Number.isNaN(trustProxy)) errors.push('TRUST_PROXY must be a proxy hop count 0–9');
  const levels: Record<string, LogLevel[]> = {
    error: ['fatal', 'error'],
    warn: ['fatal', 'error', 'warn'],
    info: ['fatal', 'error', 'warn', 'log'],
    debug: ['fatal', 'error', 'warn', 'log', 'debug'],
  };
  const logLevels = levels[env.LOG_LEVEL || 'info'];
  if (!logLevels) errors.push('LOG_LEVEL is invalid');
  for (const key of [
    'DATABASE_ADMIN_URL',
    'PRODUCT_MIGRATION_DATABASE_URL',
    'PRODUCT_BOOTSTRAP_DATABASE_URL',
  ])
    if (env[key]) errors.push(`${key} must not be present in the API process`);
  const databases = {} as Record<'data' | 'identity' | 'authority' | 'sync', URL>;
  for (const purpose of ['data', 'identity', 'authority', 'sync'] as const) {
    const key = `PRODUCT_${purpose.toUpperCase()}_DATABASE_URL`;
    try {
      const u = new URL(env[key] || '');
      if (
        !['postgres:', 'postgresql:'].includes(u.protocol) ||
        !u.hostname ||
        u.pathname.length < 2 ||
        u.username !== `product_${purpose}`
      )
        throw new Error();
      databases[purpose] = u;
    } catch {
      errors.push(`${key} must identify its dedicated product login`);
    }
  }
  const urls = Object.values(databases);
  if (
    urls.length === 4 &&
    new Set(urls.map((u) => `${u.hostname}:${u.port || 5432}${u.pathname}`)).size !== 1
  )
    errors.push('PRODUCT database URLs must point to one database');
  let origin: URL | undefined;
  try {
    origin = new URL(env.APP_ORIGIN || '');
    if (
      origin.username ||
      origin.password ||
      origin.search ||
      origin.hash ||
      origin.pathname !== '/' ||
      (origin.protocol !== 'https:' && !(origin.protocol === 'http:' && nodeEnv !== 'production'))
    )
      throw new Error();
  } catch {
    errors.push('APP_ORIGIN must be a fixed HTTPS origin (HTTP only outside production)');
  }
  const methods = env.AUTH_METHODS?.split(',');
  if (
    !methods?.length ||
    methods.some((m) => !['local', 'oidc'].includes(m)) ||
    new Set(methods).size !== methods.length
  )
    errors.push('AUTH_METHODS must explicitly select local, oidc, or local,oidc');
  let oidcProviders: ProductOidcProviderConfig[] = [];
  if (methods?.includes('oidc')) {
    try {
      const value: unknown = JSON.parse(env.OIDC_PROVIDERS_JSON || '');
      if (!Array.isArray(value) || !value.length || value.length > 8) throw new Error();
      oidcProviders = value as ProductOidcProviderConfig[];
      for (const p of oidcProviders) {
        if (
          typeof p.issuer !== 'string' ||
          typeof p.clientId !== 'string' ||
          typeof p.redirectUri !== 'string' ||
          typeof p.version !== 'string' ||
          !Array.isArray(p.assuranceMappings)
        )
          throw new Error();
        const issuer = new URL(p.issuer);
        const callback = new URL(p.redirectUri);
        if (
          issuer.protocol !== 'https:' ||
          issuer.username ||
          issuer.password ||
          issuer.search ||
          issuer.hash ||
          callback.origin !== origin?.origin ||
          callback.pathname !== '/auth/oidc/callback'
        )
          throw new Error();
      }
      if (new Set(oidcProviders.map((p) => p.issuer)).size !== oidcProviders.length)
        throw new Error();
    } catch {
      errors.push('OIDC_PROVIDERS_JSON must contain valid trusted provider configuration');
    }
  }
  if (errors.length || !origin || !logLevels || !nodeEnv)
    throw new ConfigError(`Invalid configuration: ${errors.join('; ')}`);
  return {
    nodeEnv: nodeEnv as AppConfig['nodeEnv'],
    port,
    trustProxy,
    logLevels,
    databases,
    origin,
    localEnabled: methods!.includes('local'),
    oidcProviders,
  };
}
