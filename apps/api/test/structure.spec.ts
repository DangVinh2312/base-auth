// HTTP surface and DI boundary of the real AppModule, booted in-process with fixture pools.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import {
  Controller,
  Get,
  Inject,
  Injectable,
  RequestMethod,
  type DynamicModule,
  type INestApplication,
} from '@nestjs/common';
import { HTTP_CODE_METADATA, METHOD_METADATA, PATH_METADATA } from '@nestjs/common/constants.js';
import { DiscoveryService, NestFactory } from '@nestjs/core';
import { ProductIdentityService } from '../dist/auth/services/product-identity.service.js';
import { ProductOidcService } from '../dist/auth/services/product-oidc.service.js';
import { ProductTransactionRunner } from '../dist/database/product-transaction.runner.js';
import { AppModule } from '../dist/app.module.js';
import { loadConfig } from '../dist/config/app.config.js';
import { ProductRuntime } from '../dist/infrastructure/product-runtime.service.js';
import {
  createProductAuthorizationCore,
  createProductRelease,
  productBindings,
} from '../dist/authorization/product.manifest.js';

const purposes = ['data', 'identity', 'authority', 'sync'] as const;
const config = loadConfig({
  NODE_ENV: 'test',
  AUTH_METHODS: 'local',
  APP_ORIGIN: 'http://127.0.0.1:3000',
  ...Object.fromEntries(
    purposes.map((p) => [
      `PRODUCT_${p.toUpperCase()}_DATABASE_URL`,
      `postgres://product_${p}:fixture-secret@127.0.0.1:1/product`,
    ]),
  ),
});

/** A real ProductRuntime over pools that model TypeORM: no database, destroy() of a closed pool throws. */
function fixtureRuntime(options: { bootstrap?: 'real' } = {}) {
  const log: string[] = [];
  const pools = Object.fromEntries(
    purposes.map((p) => [
      p,
      {
        isInitialized: true,

        destroy(this: { isInitialized: boolean }) {
          if (!this.isInitialized) return Promise.reject(new Error('Pool already closed'));
          this.isInitialized = false;
          return Promise.resolve();
        },

        query: () => (log.push(`${p}.query`), Promise.reject(new Error('No database'))),

        // Transactions (manifest sync, provider rows) go through query runners.
        createQueryRunner: () => {
          log.push(`${p}.createQueryRunner`);
          throw new Error('No database');
        },
      },
    ]),
  ) as unknown as Record<(typeof purposes)[number], { isInitialized: boolean }>;
  const runner = new ProductTransactionRunner(pools as never);
  const identity = new ProductIdentityService(runner, {} as never);
  // ProductRuntime.create composes exactly this after opening the pools.
  const Runtime = ProductRuntime as unknown as new (...args: unknown[]) => ProductRuntime;
  const runtime = new Runtime(
    config,
    createProductAuthorizationCore(),
    pools,
    runner,
    identity,
    new ProductOidcService(identity, new Map()),
  );
  if (options.bootstrap !== 'real')
    Object.assign(runtime, {
      onApplicationBootstrap: () => Promise.resolve(runtime.readiness.markReady()),
    });
  return { runtime, pools, log };
}

const create = (module: DynamicModule) =>
  NestFactory.create(module, { logger: false, abortOnError: false });

function routeInventory(app: INestApplication): string[] {
  return app
    .get(DiscoveryService, { strict: false })
    .getControllers()
    .flatMap(({ metatype }) => {
      const prefix = Reflect.getMetadata(PATH_METADATA, metatype!) as string;
      const prototype = (metatype as { prototype: Record<string, unknown> }).prototype;
      return Object.getOwnPropertyNames(prototype).flatMap((name) => {
        const handler = prototype[name] as object;
        const method = Reflect.getMetadata(METHOD_METADATA, handler) as RequestMethod | undefined;
        if (method === undefined) return [];
        const path = [prefix, Reflect.getMetadata(PATH_METADATA, handler) as string]
          .filter((p) => p && p !== '/')
          .join('/');
        const status =
          (Reflect.getMetadata(HTTP_CODE_METADATA, handler) as number | undefined) ??
          (method === RequestMethod.POST ? 201 : 200);
        const key = (Reflect.getOwnMetadataKeys(handler) as unknown[]).find(
          (k) => typeof k === 'symbol' && k.description === 'PRODUCT_ROUTE_CLASSIFICATION',
        );
        const classes = (key ? Reflect.getOwnMetadata(key, handler) : []) as {
          kind: string;
          resource?: string;
          action?: string;
        }[];
        const classification = classes
          .map((c) => (c.kind === 'authorize' ? `${c.resource}.${c.action}` : c.kind))
          .join(',');
        return [`${RequestMethod[method]} /${path} ${status} ${classification}`];
      });
    })
    .sort();
}

/** Every key (own and prototype) reachable from what the controllers were injected with. */
function exposure(app: INestApplication) {
  const keys = new Set<string>();
  const operations = new Set<string>();
  const urls: string[] = [];
  const seen = new Set<object>();

  const walk = (value: unknown, depth: number) => {
    if (typeof value === 'string' && /postgres(ql)?:/i.test(value)) urls.push(value);
    if (value instanceof URL) return void urls.push(value.href);
    if (value === null || typeof value !== 'object' || seen.has(value) || depth > 5) return;
    seen.add(value);
    for (
      let o: object | null = value;
      o && o !== Object.prototype;
      o = Object.getPrototypeOf(o) as object | null
    )
      for (const key of Reflect.ownKeys(o)) {
        if (key === 'constructor') continue;
        keys.add(String(key));
        const descriptor = Object.getOwnPropertyDescriptor(o, key)!;
        if (typeof descriptor.value === 'function') operations.add(String(key));
        else if ('value' in descriptor) walk(descriptor.value, depth + 1);
      }
  };

  for (const { instance } of app.get(DiscoveryService, { strict: false }).getControllers())
    for (const injected of Object.values(instance as object)) walk(injected, 0);
  return { keys, operations: [...operations].sort(), urls };
}

const expectedRoutes = [
  'GET /auth/csrf 200 public',
  'GET /auth/oidc/callback 200 public',
  'GET /auth/session 200 authenticated',
  'GET /documents 200 document.read',
  'GET /documents/:id 200 document.read',
  'GET /health/live 200 public',
  'GET /health/metrics 200 public',
  'GET /health/ready 200 public',
  'GET /openapi.json 200 public',
  'PATCH /documents/:id 200 document.update',
  'POST /administration/users/:id/suspend 200 account.suspend',
  'POST /auth/activate 200 public',
  'POST /auth/login 200 public',
  'POST /auth/logout 200 authenticated',
  'POST /auth/logout-all 200 authenticated',
  'POST /auth/oidc/activate 200 public',
  'POST /auth/oidc/begin 200 public',
  'POST /auth/oidc/link 200 authenticated',
  'POST /auth/oidc/reauthenticate 200 authenticated',
  'POST /auth/oidc/unlink 200 authenticated',
  'POST /auth/password 200 authenticated',
  'POST /auth/reauthenticate 200 authenticated',
  'POST /auth/recovery/request 200 public',
  'POST /auth/recovery/reset 200 public',
];
const expectedOperations = [
  'activate',
  'begin',
  'callback',
  'changePassword',
  'currentSession',
  'detail',
  'list',
  'login',
  'logout',
  'markReady',
  'reauthenticate',
  'requestPasswordReset',
  'resetPassword',
  'snapshot',
  'suspendUser',
  'unlink',
  'update',
];
// Changed deliberately: the /auth/session example userId no longer equals PRODUCT_OFFLINE_ACTOR.
const openApiSha256 = 'f0f1c5c53e2057ded71ce665a98b4df713ae790299159dc5ca8b7fbd3879148f';

test('route inventory, OpenAPI, cookie/CSRF and handler exposure are pinned', async (t) => {
  const { runtime } = fixtureRuntime();
  const app = await create(AppModule.register(runtime));
  t.after(() => app.close());
  assert.deepEqual(routeInventory(app), expectedRoutes);

  const { keys, operations, urls } = exposure(app);
  assert.deepEqual(operations, expectedOperations);
  for (const forbidden of [
    'transactions',
    'manager',
    'pools',
    'runner',
    'databases',
    'release',
    'core',
    'bindings',
    'reconcile',
    'issueActivation',
    'authenticate',
    'onApplicationBootstrap',
    'onApplicationShutdown',
  ])
    assert.ok(!keys.has(forbidden), `handlers can reach ${forbidden}`);
  assert.deepEqual(urls, [config.origin.href], 'only the public origin URL is reachable');

  await app.listen(0, '127.0.0.1');
  const base = (await app.getUrl()).replace('[::1]', '127.0.0.1');
  const openapi = await fetch(`${base}/openapi.json`);
  assert.equal(openapi.status, 200);
  const document = (await openapi.json()) as { paths: Record<string, Record<string, unknown>> };
  assert.equal(createHash('sha256').update(JSON.stringify(document)).digest('hex'), openApiSha256);
  // Every route is documented and every documented operation is a route.
  assert.deepEqual(
    Object.entries(document.paths)
      .flatMap(([path, item]) =>
        Object.keys(item)
          .filter((m) => m !== 'parameters')
          .map((m) => `${m.toUpperCase()} ${path.replace(/\{(\w+)\}/g, ':$1')}`),
      )
      .sort(),
    expectedRoutes.map((r) => r.split(' ').slice(0, 2).join(' ')).sort(),
  );

  const csrf = await fetch(`${base}/auth/csrf`);
  const { csrfToken } = (await csrf.json()) as { csrfToken: string };
  assert.match(csrfToken, /^[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(csrf.headers.getSetCookie(), [
    `authz_csrf=${csrfToken}; Path=/; Max-Age=3600; SameSite=Lax; HttpOnly`,
  ]);

  const login = (headers: Record<string, string>) =>
    fetch(`${base}/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
      body: JSON.stringify({ email: 'person@example.test', password: 'x'.repeat(20) }),
    });

  const cookie = `authz_csrf=${csrfToken}`;
  const attempts: Record<string, string>[] = [
    { cookie, origin: config.origin.origin },
    { cookie, origin: 'http://attacker.test', 'x-csrf-token': csrfToken },
    { origin: config.origin.origin, 'x-csrf-token': csrfToken },
  ];
  for (const headers of attempts) {
    const response = await login(headers);
    assert.equal(response.status, 403);
    assert.deepEqual(await response.json(), { statusCode: 403, message: 'Access denied' });
  }
  assert.equal((await fetch(`${base}/health/ready`)).status, 200);
  assert.deepEqual(await (await fetch(`${base}/health/metrics`)).json(), []);
});

function unclassifiedController() {
  class Unclassified {
    handler() {
      return {};
    }
  }
  Controller('unclassified')(Unclassified);
  Get()(
    Unclassified.prototype,
    'handler',
    Object.getOwnPropertyDescriptor(Unclassified.prototype, 'handler')!,
  );
  return Unclassified;
}

/** Records runtime bootstrap calls instead of touching a database. */
function spiedRuntime() {
  const { runtime } = fixtureRuntime();
  const calls: string[] = [];
  Object.assign(runtime, {
    onApplicationBootstrap: () => {
      calls.push('runtime bootstrap');
      runtime.readiness.markReady();
      return Promise.resolve();
    },
  });
  return { runtime, calls };
}

test('a route without classification fails boot before any runtime bootstrap', async () => {
  // The runtime bootstrap publishes the manifest and opens readiness: it must never start.
  const { runtime, calls } = spiedRuntime();
  const module = AppModule.register(runtime);
  const app = await create({
    ...module,
    controllers: [...(module.controllers ?? []), unclassifiedController()],
  });
  await assert.rejects(app.init(), /exactly one classification/);
  assert.deepEqual(calls, []);
  assert.equal(runtime.readiness.ready, false);
  await app.close();
});

test('a fully classified app runs the runtime bootstrap once and becomes ready', async () => {
  const { runtime, calls } = spiedRuntime();
  const app = await create(AppModule.register(runtime));
  await app.init();
  assert.deepEqual(calls, ['runtime bootstrap']);
  assert.equal(runtime.readiness.ready, true);
  await app.close();
});

test('the composed release and storage bindings are unchanged', () => {
  // The hash is what manifest sync stores; a different hash would be a new release.
  const release = createProductRelease(createProductAuthorizationCore());
  assert.equal(release.hash, 'e11f43e8199bf70fd4a2c8e552477b682222402510fd3d0cc35b98256f15afaa');
  assert.equal(
    createHash('sha256').update(JSON.stringify(productBindings)).digest('hex'),
    '77d13233fa04e02cc2e6444fff57b7dec4f2d1f23c737ec9a6746006de1bb6f8',
  );
});

type ModuleNode = DynamicModule | (abstract new (...args: never[]) => unknown);

const moduleOf = (node: ModuleNode) => ('module' in node ? node.module : node);

const declaresControllers = (node: ModuleNode) =>
  Boolean(
    ('module' in node && node.controllers?.length) ||
    (Reflect.getMetadata('controllers', moduleOf(node)) as unknown[] | undefined)?.length,
  );

/** Same composition with `probe` added to the one module `target`. */
function withProvider(node: ModuleNode, target: unknown, probe: object): ModuleNode {
  const dynamic: DynamicModule = 'module' in node ? node : { module: node as never };
  return {
    ...dynamic,
    imports: dynamic.imports?.map((child) => withProvider(child as ModuleNode, target, probe)),
    providers: [...(dynamic.providers ?? []), ...(dynamic.module === target ? [probe] : [])],
  } as DynamicModule;
}

function controllerModules(node: ModuleNode, found = new Set<unknown>()): Set<unknown> {
  if (declaresControllers(node)) found.add(moduleOf(node));
  for (const child of ('module' in node ? node.imports : undefined) ?? [])
    controllerModules(child as ModuleNode, found);
  return found;
}

test('no module that declares controllers can resolve the raw runtime', async () => {
  class RawRuntimeProbe {
    runtime: unknown;

    constructor(runtime: unknown) {
      this.runtime = runtime;
    }
  }
  Injectable()(RawRuntimeProbe);
  Inject(ProductRuntime)(RawRuntimeProbe, undefined, 0);
  class EmptyProbe {}
  Injectable()(EmptyProbe);
  const root = AppModule.register(fixtureRuntime().runtime);
  const targets = controllerModules(root);
  assert.deepEqual([...targets].map((m) => (m as { name: string }).name).sort(), [
    'AdministrationModule',
    'AppModule',
    'AuthModule',
    'DocumentModule',
    'HealthModule',
  ]);
  for (const target of targets) {
    const name = (target as { name: string }).name;
    // Positive control: the same placement resolves a provider without the raw token.
    const control = await create(withProvider(root, target, EmptyProbe) as DynamicModule);
    await control.close();
    let app: INestApplication | undefined;
    await assert.rejects(
      (async () =>
        (app = await create(withProvider(root, target, RawRuntimeProbe) as DynamicModule)))(),
      /can't resolve dependencies of the RawRuntimeProbe/,
      `${name} resolved ProductRuntime`,
    );
    await app?.close();
  }
});

test('a failing bootstrap keeps readiness closed and never opens the listener', async () => {
  // Real onApplicationBootstrap: the privilege probe fails on the fixture pools.
  const { runtime, pools, log } = fixtureRuntime({ bootstrap: 'real' });
  const app = await create(AppModule.register(runtime));
  await assert.rejects(app.listen(0, '127.0.0.1'));
  assert.equal(runtime.readiness.ready, false);
  // Probe first: its failure stops boot before manifest sync opens a transaction.
  assert.deepEqual(log, ['data.query']);
  assert.equal((app.getHttpServer() as { listening: boolean }).listening, false);
  // main.ts cleanup after a failed start, then a later shutdown hook: both must succeed.
  await runtime.onApplicationShutdown();
  await runtime.onApplicationShutdown();
  for (const pool of Object.values(pools)) assert.equal(pool.isInitialized, false);
});
