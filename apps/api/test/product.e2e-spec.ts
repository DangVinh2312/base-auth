import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { spawn, type ChildProcess } from 'node:child_process';
import { createServer } from 'node:net';
import { DataSource } from 'typeorm';
import { type IdentityId } from '@base-authorization/core';
import { type ProductDatabasePurpose } from '@base-authorization/typeorm-postgres';
import {
  ProductTransactionRunner,
  ProductIdentityService,
  createProductPasswordHasher,
  ProductManifestReconciler,
} from '@base-authorization/typeorm-postgres/composition';
import {
  provisionProductDatabase,
  productDataSourceOptions,
  bootstrapProductRoot,
} from '@base-authorization/typeorm-postgres/operations';
import { NestFactory } from '@nestjs/core';
import { startPostgres } from '../../../test/setup-postgres.ts';
import { AppModule } from '../dist/app.module.js';
import { loadConfig } from '../dist/config/app.config.js';
import { ProductRuntime } from '../dist/infrastructure/product-runtime.js';
import { ProductDocument1792108800002 } from '../dist/documents/migrations/product-document.js';
import {
  createProductAuthorizationCore,
  createProductRelease,
} from '../dist/authorization/product-manifest.js';

const core = createProductAuthorizationCore();
const productRelease = createProductRelease(core);
async function freePort() {
  const s = createServer();
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
  const address = s.address();
  assert.ok(address && typeof address === 'object');
  await new Promise<void>((r) => s.close(() => r()));
  return address.port;
}
async function stop(child: ChildProcess) {
  if (child.exitCode !== null) return;
  child.kill('SIGTERM');
  await new Promise<void>((resolve) => child.once('exit', () => resolve()));
}
test('actual API boot, activation/login, scoped read/write, Root bypass with fresh writes and revoke/reset fail closed', async (t) => {
  const pg = await startPostgres();
  const pools: DataSource[] = [];
  let child: ChildProcess | undefined;
  t.after(async () => {
    if (child) await stop(child);
    await Promise.all(pools.map((p) => p.destroy()));
    await pg.stop();
  });
  const passwords = Object.fromEntries(
    ['data', 'identity', 'authority', 'sync', 'migration', 'bootstrap', 'outbox'].map((p) => [
      p,
      randomBytes(24).toString('hex'),
    ]),
  ) as Record<ProductDatabasePurpose, string>;
  const settings = await provisionProductDatabase(pg.superuser, passwords);
  const ds = {} as Record<ProductDatabasePurpose, DataSource>;
  for (const purpose of [
    'data',
    'identity',
    'authority',
    'sync',
    'migration',
    'bootstrap',
  ] as const) {
    ds[purpose] = await new DataSource(productDataSourceOptions(settings[purpose])).initialize();
    pools.push(ds[purpose]);
  }
  const runner = new ProductTransactionRunner(ds);
  const identity = new ProductIdentityService(runner, await createProductPasswordHasher(new Set()));
  const migration = ds.migration.createQueryRunner();
  await new ProductDocument1792108800002().up(migration);
  await migration.release();
  await new ProductManifestReconciler(runner, {
    core,
    actor: randomUUID() as IdentityId,
    capabilities: { validators: ['fresh@1'], obligationHandlers: ['audit@1'] },
  }).reconcile(productRelease);
  const root = randomUUID() as IdentityId;
  const user = randomUUID() as IdentityId;
  await ds.migration.query(
    `INSERT INTO app_user(id,email_canonical,state) VALUES($1,'root@example.test','pending'),($2,'reader@example.test','pending')`,
    [root, user],
  );
  const bootstrap = await bootstrapProductRoot(runner, productRelease, {
    operationId: randomUUID(),
    userId: root,
    method: 'local',
  });
  assert.ok(bootstrap.activationSecret);
  const userToken = await runner.run('revoke', (tx) => identity.issueActivation(tx, user));
  const visible = randomUUID(),
    hidden = randomUUID();
  await ds.migration.query(
    `INSERT INTO object_ref(object_id,type_key,key_kind,key_bytes) VALUES($1,$3,'uuid',$4),($2,$3,'uuid',$5)`,
    [visible, hidden, Buffer.from('document'), Buffer.from(visible), Buffer.from(hidden)],
  );
  await ds.migration.query(
    `INSERT INTO document(id,object_id,owner_id,title,state) VALUES($1,$1,$3,'Visible','draft'),($2,$2,$4,'Hidden','draft')`,
    [visible, hidden, user, root],
  );
  // Runtime authority facts: the code-owned reviewer role (default document.read grant) and a direct update grant.
  await runner.run('admin', async (tx) => {
    await tx.manager.query('INSERT INTO user_role(user_id,role_key) VALUES($1,$2)', [
      user,
      Buffer.from('reviewer'),
    ]);
    await tx.manager.query(
      `INSERT INTO policy_rule(rule_id,permission_key,user_id,effect,template_key,template_version,parameters,managed_by) VALUES($1,$2,$3,'allow',$4,1,'{}','runtime')`,
      [randomUUID(), Buffer.from('document.update'), user, Buffer.from('ownedDocuments')],
    );
  });
  const port = await freePort();
  const origin = `http://127.0.0.1:${port}`;
  const env: Record<string, string> = {
    PATH: process.env.PATH || '',
    NODE_ENV: 'test',
    AUTH_METHODS: 'local',
    APP_ORIGIN: origin,
    PORT: String(port),
    LOG_LEVEL: 'error',
  };
  for (const purpose of ['data', 'identity', 'authority', 'sync'] as const) {
    const c = settings[purpose];
    env[`PRODUCT_${purpose.toUpperCase()}_DATABASE_URL`] =
      `postgres://${c.username}:${c.password}@${c.host}:${c.port}/${c.database}`;
  }
  const launch = () => {
    const processChild = spawn(process.execPath, ['apps/api/dist/main.js'], {
      cwd: process.cwd(),
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    processChild.stdout.on('data', (b: Buffer) => (output += b.toString()));
    processChild.stderr.on('data', (b: Buffer) => (output += b.toString()));
    return { processChild, output: () => output };
  };
  let running = launch();
  child = running.processChild;
  let live: Response | undefined;
  for (let i = 0; i < 150 && !live; i++) {
    if (child.exitCode !== null) assert.fail(`Startup failed: ${running.output()}`);
    live = await fetch(`${origin}/health/live`).catch(() => undefined);
    if (!live) await new Promise((r) => setTimeout(r, 50));
  }
  assert.equal(live?.status, 200);
  assert.equal(live?.headers.get('cache-control'), 'no-store');
  assert.equal((await fetch(`${origin}/health/ready`)).status, 200);
  const jar = new Map<string, string>();
  let csrf = '';
  async function request(path: string, method = 'GET', body?: unknown) {
    const response = await fetch(origin + path, {
      method,
      headers: {
        cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; '),
        origin,
        'x-csrf-token': csrf,
        ...(body ? { 'content-type': 'application/json' } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    for (const cookie of response.headers.getSetCookie()) {
      const first = cookie.split(';')[0]!;
      const index = first.indexOf('=');
      jar.set(first.slice(0, index), first.slice(index + 1));
    }
    return response;
  }
  const csrfResponse = await request('/auth/csrf');
  csrf = ((await csrfResponse.json()) as { csrfToken: string }).csrfToken;
  assert.equal((await request('/documents')).status, 401);
  const password = 'a long unique fixture password';
  assert.equal(
    (await request('/auth/activate', 'POST', { token: userToken, password })).status,
    200,
  );
  assert.equal(
    (await request('/auth/login', 'POST', { email: 'reader@example.test', password })).status,
    200,
  );
  const page = (await (await request('/documents')).json()) as {
    items: Record<string, unknown>[];
    total: string;
  };
  assert.equal(page.total, '1');
  assert.equal(page.items[0]?.title, 'Visible');
  assert.equal(page.items[0]?.ownerId, undefined);
  const missing = await request(`/documents/${randomUUID()}`);
  const denied = await request(`/documents/${hidden}`);
  assert.equal(missing.status, 404);
  assert.equal(denied.status, 404);
  assert.deepEqual(await missing.json(), await denied.json());
  assert.equal((await request('/documents/not-a-key')).status, 400);
  // Other apps' cookies on the same site, even malformed or repeated, do not break the session.
  jar.set('other', 'x; other=y; junk');
  assert.equal((await request('/documents')).status, 200);
  jar.delete('other');
  assert.equal(
    (
      await request(`/documents/${visible}`, 'PATCH', {
        title: "changed'; DROP TABLE document; --",
      })
    ).status,
    200,
  );
  assert.equal(
    (
      await ds.migration.query<{ title: string }[]>('SELECT title FROM document WHERE id=$1', [
        visible,
      ])
    )[0]?.title,
    "changed'; DROP TABLE document; --",
  );
  const noCsrf = await fetch(origin + '/auth/logout', {
    method: 'POST',
    headers: { cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; '), origin },
  });
  assert.equal(noCsrf.status, 403);
  const reset = await identity.requestPasswordReset('reader@example.test', 'fixture-reset');
  assert.ok(reset);
  assert.equal(
    (
      await request('/auth/recovery/reset', 'POST', {
        token: reset.token,
        password: 'replacement unique fixture password',
      })
    ).status,
    200,
  );
  assert.equal((await request('/documents')).status, 401);
  assert.equal(
    (await request('/auth/activate', 'POST', { token: bootstrap.activationSecret, password }))
      .status,
    200,
  );
  assert.equal(
    (await request('/auth/login', 'POST', { email: 'root@example.test', password })).status,
    200,
  );
  const rootPage = (await (await request('/documents')).json()) as {
    items: Record<string, unknown>[];
    total: string;
  };
  // Root is outside IAM: every document, still through the projection; writes need fresh reauth.
  assert.equal(rootPage.total, '2');
  assert.ok(rootPage.items.every((item) => !('ownerId' in item)));
  assert.equal((await request(`/documents/${hidden}`)).status, 200);
  assert.equal(
    (await request(`/documents/${hidden}`, 'PATCH', { title: 'Root edit' })).status,
    403,
  );
  assert.equal((await request(`/administration/users/${user}/suspend`, 'POST')).status, 403);
  assert.equal((await request('/auth/reauthenticate', 'POST', { password })).status, 200);
  // Root itself and an absent id look the same: 404 (the account resource holds IAM accounts only).
  assert.equal((await request(`/administration/users/${root}/suspend`, 'POST')).status, 404);
  assert.equal(
    (await request(`/administration/users/${randomUUID()}/suspend`, 'POST')).status,
    404,
  );
  assert.equal(
    (await request(`/documents/${hidden}`, 'PATCH', { title: 'Root edit' })).status,
    200,
  );
  assert.equal((await request(`/administration/users/${user}/suspend`, 'POST')).status, 200);
  assert.equal(
    (
      await ds.migration.query<{ state: string }[]>('SELECT state FROM app_user WHERE id=$1', [
        user,
      ])
    )[0]?.state,
    'suspended',
  );
  assert.equal((await request('/auth/logout', 'POST')).status, 200);
  assert.equal((await request('/auth/session')).status, 401);
  assert.equal((await request('/openapi.json')).status, 200);
  await stop(child);
  child = undefined;
  // Simulate unauthorized drift offline. The actual AppModule must fail before opening its listener.
  await ds.migration.query('ALTER TABLE role_definition DISABLE TRIGGER protect_product_rows');
  await ds.migration.query(`UPDATE role_definition SET label='drift' WHERE role_key=$1`, [
    Buffer.from('reviewer'),
  ]);
  await ds.migration.query('ALTER TABLE role_definition ENABLE TRIGGER protect_product_rows');
  running = launch();
  child = running.processChild;
  await new Promise<void>((r) => running.processChild.once('exit', () => r()));
  assert.notEqual(child.exitCode, 0);
  assert.match(running.output(), /Application startup failed/);
  await assert.rejects(fetch(`${origin}/documents`));
  await ds.migration.query('ALTER TABLE role_definition DISABLE TRIGGER protect_product_rows');
  await ds.migration.query("UPDATE role_definition SET label='Reviewer' WHERE role_key=$1", [
    Buffer.from('reviewer'),
  ]);
  await ds.migration.query('ALTER TABLE role_definition ENABLE TRIGGER protect_product_rows');
  await ds.migration.query('REVOKE UPDATE(title) ON document FROM product_data');
  running = launch();
  child = running.processChild;
  await new Promise<void>((r) => running.processChild.once('exit', () => r()));
  assert.notEqual(child.exitCode, 0);
  await assert.rejects(fetch(`${origin}/documents`));
  child = undefined;
  // The same failure in-process, with main.ts's sequence: readiness stays closed, no listener,
  // and the (repeatable) cleanup returns every connection the runtime opened.
  const sessions = async () =>
    new Set(
      (
        await ds.migration.query<{ pid: number }[]>(
          "SELECT pid FROM pg_stat_activity WHERE usename IN ('product_data','product_identity','product_authority','product_sync')",
        )
      ).map((r) => r.pid),
    );
  const before = await sessions();
  const runtime = await ProductRuntime.create(loadConfig(env));
  assert.ok([...(await sessions())].filter((pid) => !before.has(pid)).length >= 4);
  const app = await NestFactory.create(AppModule.register(runtime), {
    logger: false,
    abortOnError: false,
  });
  await assert.rejects(app.listen(port));
  assert.equal(runtime.readiness.ready, false);
  await assert.rejects(fetch(`${origin}/health/live`));
  await runtime.onApplicationShutdown();
  await runtime.onApplicationShutdown();
  let leaked: number[] = [];
  for (let i = 0; i < 50; i++) {
    const current = await sessions();
    leaked = [...current].filter((pid) => !before.has(pid));
    if (!leaked.length) break;
    await new Promise((r) => setTimeout(r, 50));
  }
  assert.deepEqual(leaked, []);
});
