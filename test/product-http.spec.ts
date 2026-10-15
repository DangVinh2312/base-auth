import assert from 'node:assert/strict';
import { test } from 'node:test';
import { loadConfig } from '../apps/api/dist/config/app.config.js';
import { ProductInvalidRequest, rateLimitClient } from '@base-authorization/typeorm-postgres';
import {
  bodyFields,
  enforceCsrf,
  cookieName,
  sessionSecret,
} from '../apps/api/dist/infrastructure/http-security.helper.js';
import { ProductErrorFilter } from '../apps/api/dist/infrastructure/product-error.filter.js';
import { AuthController } from '../apps/api/dist/auth/controllers/auth.controller.js';
import { ProductMetrics } from '../apps/api/dist/health/product-metrics.service.js';

const env = {
  NODE_ENV: 'test',
  AUTH_METHODS: 'local',
  APP_ORIGIN: 'http://localhost:3000',
  ...Object.fromEntries(
    ['data', 'identity', 'authority', 'sync'].map((p) => [
      `PRODUCT_${p.toUpperCase()}_DATABASE_URL`,
      `postgres://product_${p}:synthetic@localhost/product`,
    ]),
  ),
};
const config = loadConfig(env);
test('HTTP mutations require exact trusted Origin and matching canonical CSRF cookie/header', () => {
  const token = 'a'.repeat(43);
  const req = {
    headers: {
      origin: config.origin.origin,
      cookie: `${cookieName(config, 'csrf')}=${token}`,
      'x-csrf-token': token,
    },
    originalUrl: '/auth/login',
  };
  assert.doesNotThrow(() => enforceCsrf(req, config));
  assert.throws(() =>
    enforceCsrf({ ...req, headers: { ...req.headers, origin: 'https://attacker.test' } }, config),
  );
  assert.throws(() =>
    enforceCsrf({ ...req, headers: { ...req.headers, 'x-csrf-token': 'b'.repeat(43) } }, config),
  );
  assert.throws(() =>
    bodyFields({ email: 'a', password: 'b', managed_by: 'code' }, ['email', 'password']),
  );
});
test('runtime metrics keep finite mode labels and cumulative bounded histograms', () => {
  const m = new ProductMetrics();
  m.observe('lock_wait', 'read', 10);
  m.observe('lock_wait', 'read', 100);
  const [row] = m.snapshot();
  assert.equal(row?.count, 2);
  assert.equal(row?.sum, 110);
  assert.equal(row?.buckets.find((b) => b.upper === 10)?.count, 1);
  assert.equal(row?.buckets.at(-1)?.count, 2);
  assert.equal(m.snapshot().length, 1);
});
test('trusted proxy hops are explicit: direct by default, bounded count otherwise', () => {
  assert.equal(config.trustProxy, 0);
  assert.equal(loadConfig({ ...env, TRUST_PROXY: '1' }).trustProxy, 1);
  for (const value of ['true', '-1', '10', '1.5', 'loopback'])
    assert.throws(() => loadConfig({ ...env, TRUST_PROXY: value }), /TRUST_PROXY/);
});
test('only own cookies are parsed: foreign junk is ignored, a repeated own cookie fails closed', () => {
  const name = cookieName(config, 'session');

  const req = (cookie: string) => ({ headers: { cookie }, originalUrl: '/' });

  assert.equal(sessionSecret(req(`junk; a=1; a=2; ${name}=s; =x`), config), 's');
  assert.throws(() => sessionSecret(req(`${name}=s; ${name}=t`), config));
});
test('error filter: caller input is 400, programming faults are 503 and logged', async () => {
  const status = (error: unknown) => {
    let code = 0;
    new ProductErrorFilter().catch(error, {
      switchToHttp: () => ({
        getResponse: () => ({ status: (c: number) => ((code = c), { json() {} }) }),
      }),
    } as never);
    return code;
  };

  const logged: string[] = [];
  const write = process.stdout.write.bind(process.stdout);
  const writeError = process.stderr.write.bind(process.stderr);
  process.stdout.write = process.stderr.write = ((chunk: string | Uint8Array) =>
    logged.push(String(chunk)) > 0) as typeof process.stdout.write;
  try {
    assert.equal(status(new ProductInvalidRequest('bad key')), 400);
    // The deliberate 503 of an unconfigured capability, as the controller throws it.
    const unavailable: unknown = await new AuthController({
      config,
      recoveryDelivery: undefined,
    } as never)
      .requestReset(
        { email: 'a@example.test' },
        {
          headers: {
            origin: config.origin.origin,
            cookie: `${cookieName(config, 'csrf')}=${'a'.repeat(43)}`,
            'x-csrf-token': 'a'.repeat(43),
          },
          originalUrl: '/auth/recovery/request',
        },
      )
      .catch((e: unknown) => e);
    assert.equal(status(unavailable), 503);
    assert.equal(logged.length, 0, 'deliberate HTTP responses are not logged');
    const fault = new TypeError(
      'secret-value\nsecond-line person@example.test\n    at injected-frame (person@example.test)',
    );
    assert.equal(status(fault), 503);
  } finally {
    process.stdout.write = write;
    process.stderr.write = writeError;
  }
  const log = logged.join('');
  assert.match(log, /TypeError/);
  assert.match(log, / at /);
  assert.doesNotMatch(log, /secret-value|second-line|person@|injected-frame/);
});
test('recovery request answers the same whether delivery hangs or fails', async () => {
  for (const delivery of [
    () => {
      throw new Error('synchronous failure');
    },
    () => new Promise<void>(() => {}),
    () => Promise.reject(new Error('down')),
  ]) {
    const controller = new AuthController({
      config,
      recoveryDelivery: delivery,
      identity: { requestPasswordReset: () => Promise.resolve({ userId: 'u', token: 't' }) },
    } as never);
    const token = 'a'.repeat(43);
    const req = {
      headers: {
        origin: config.origin.origin,
        cookie: `${cookieName(config, 'csrf')}=${token}`,
        'x-csrf-token': token,
      },
      originalUrl: '/auth/recovery/request',
    };
    assert.deepEqual(await controller.requestReset({ email: 'a@example.test' }, req), {
      status: 'accepted',
    });
  }
});
test('limiter groups an IPv6 /64 into one client, unmaps IPv4 forms and drops ports', () => {
  assert.equal(rateLimitClient('2001:db8:1:2:aaaa::1'), '2001:db8:1:2::/64');
  assert.equal(rateLimitClient('2001:db8:1:2:bbbb:cccc:dddd:eeee'), '2001:db8:1:2::/64');
  assert.equal(rateLimitClient('2001:db8::1'), '2001:db8:0:0::/64');
  assert.equal(rateLimitClient('fe80::1%eth0'), 'fe80:0:0:0::/64');
  assert.equal(rateLimitClient('::ffff:192.0.2.1'), '192.0.2.1');
  for (const v4 of [
    '::1.2.3.4',
    '::ffff:0102:0304',
    '0:0:0:0:0:ffff:1.2.3.4',
    '64:ff9b::102:304',
    '1.2.3.4:5678',
  ])
    assert.equal(rateLimitClient(v4), '1.2.3.4', v4);
  assert.equal(rateLimitClient('[2001:db8::1]:443'), '2001:db8:0:0::/64');
  assert.equal(rateLimitClient('192.0.2.1'), '192.0.2.1');
  assert.equal(rateLimitClient('unknown'), 'unknown');
});
