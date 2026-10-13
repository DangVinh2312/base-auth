import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const apiMain = fileURLToPath(new URL('../apps/api/dist/main.js', import.meta.url));

const validEnv = {
  NODE_ENV: 'test',
  LOG_LEVEL: 'warn',
  AUTH_METHODS: 'local',
  APP_ORIGIN: 'http://127.0.0.1:3000',
  PRODUCT_DATA_DATABASE_URL: 'postgres://product_data:fixture-secret@127.0.0.1:1/product',
  PRODUCT_IDENTITY_DATABASE_URL: 'postgres://product_identity:fixture-secret@127.0.0.1:1/product',
  PRODUCT_AUTHORITY_DATABASE_URL: 'postgres://product_authority:fixture-secret@127.0.0.1:1/product',
  PRODUCT_SYNC_DATABASE_URL: 'postgres://product_sync:fixture-secret@127.0.0.1:1/product',
};

async function freePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  assert.ok(address !== null && typeof address === 'object');
  return address.port;
}

function runApiExpectingExit(env: Record<string, string>) {
  return spawnSync(process.execPath, [apiMain], {
    env: { PATH: process.env.PATH ?? '', ...env },
    encoding: 'utf8',
    timeout: 15_000,
  });
}

test('API refuses business listener when the authority database is unavailable', async () => {
  const port = await freePort();
  const result = runApiExpectingExit({ ...validEnv, PORT: String(port) });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Application startup failed/);
  await assert.rejects(fetch(`http://127.0.0.1:${port}/health/live`));
});
for (const missing of [
  'PRODUCT_DATA_DATABASE_URL',
  'PRODUCT_IDENTITY_DATABASE_URL',
  'PRODUCT_AUTHORITY_DATABASE_URL',
  'PRODUCT_SYNC_DATABASE_URL',
  'NODE_ENV',
  'APP_ORIGIN',
  'AUTH_METHODS',
] as const) {
  test(`API refuses to boot without ${missing}`, () => {
    const env: Record<string, string> = { ...validEnv };
    delete env[missing];
    const result = runApiExpectingExit(env);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, new RegExp(missing));
  });
}
test('local-only configuration needs no IdP and rejects offline credentials without leaking secrets', async () => {
  const { loadConfig } = await import('../apps/api/dist/config.js');
  assert.equal(loadConfig(validEnv).oidcProviders.length, 0);
  assert.throws(() => loadConfig({ ...validEnv, AUTH_METHODS: 'oidc' }), /OIDC_PROVIDERS_JSON/);
  const result = runApiExpectingExit({
    ...validEnv,
    PRODUCT_DATA_DATABASE_URL: 'mysql://leaky_user:do-not-print-me@127.0.0.1/product',
    PRODUCT_BOOTSTRAP_DATABASE_URL: 'do-not-print-me-either',
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /PRODUCT_DATA_DATABASE_URL/);
  assert.match(result.stderr, /PRODUCT_BOOTSTRAP_DATABASE_URL/);
  assert.doesNotMatch(result.stderr + result.stdout, /do-not-print-me|leaky_user/);
});

test('importing @base-authorization/core loads no framework, ORM or driver module', () => {
  const manifest = JSON.parse(
    readFileSync(new URL('../packages/core/package.json', import.meta.url), 'utf8'),
  ) as {
    dependencies?: object;
    peerDependencies?: object;
  };
  assert.equal(manifest.dependencies, undefined);
  assert.equal(manifest.peerDependencies, undefined);

  const probe = `
    import { registerHooks } from 'node:module';
    const loaded = [];
    registerHooks({ resolve(specifier, context, next) { const r = next(specifier, context); loaded.push(r.url); return r; } });
    const core = await import('@base-authorization/core');
    console.log(JSON.stringify({ exports: Object.keys(core), loaded }));
  `;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', probe], {
    cwd: root,
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, result.stderr);
  const { exports, loaded } = JSON.parse(result.stdout) as { exports: string[]; loaded: string[] };
  assert.ok(exports.length > 0, 'core must expose a public API');
  assert.ok(loaded.some((url) => url.includes('/packages/core/dist/')));
  const forbidden = loaded.filter((url) =>
    /node_modules\/(@nestjs|typeorm|pg|pg-[a-z]+|reflect-metadata|express)\//.test(url),
  );
  assert.deepEqual(forbidden, []);
});
