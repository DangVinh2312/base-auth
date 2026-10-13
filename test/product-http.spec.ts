import assert from 'node:assert/strict';
import { test } from 'node:test';
import { loadConfig } from '../apps/api/dist/config.js';
import { bodyFields, enforceCsrf, cookieName } from '../apps/api/dist/http-security.js';
import { ProductMetrics } from '../apps/api/dist/metrics.js';
const config = loadConfig({
  NODE_ENV: 'test',
  AUTH_METHODS: 'local',
  APP_ORIGIN: 'http://localhost:3000',
  ...Object.fromEntries(
    ['data', 'identity', 'authority', 'sync'].map((p) => [
      `PRODUCT_${p.toUpperCase()}_DATABASE_URL`,
      `postgres://product_${p}:synthetic@localhost/product`,
    ]),
  ),
});
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
