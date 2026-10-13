import assert from 'node:assert/strict';
import { test } from 'node:test';
import { planUser } from '@base-authorization/core';
import {
  ProductBindingRegistry,
  compileProductPlan,
  type ProductStorageBindings,
} from '@base-authorization/typeorm-postgres';
import { alice, input, rule, snapshot, validated } from '../packages/core/test/fixtures.ts';

const declarations = validated();
const resources: ProductStorageBindings['resources'] = [
  {
    resource: 'submission',
    table: 'submission',
    objectIdColumn: 'object_id',
    keyColumn: 'id',
    columns: { status: 'status', amount: 'amount', title: 'title', priority: 'priority' },
    projection: ['status'],
  },
  {
    resource: 'site',
    table: 'site',
    objectIdColumn: 'object_id',
    keyColumn: 'id',
    columns: { name: 'name' },
    projection: ['name'],
  },
];
const domain = { table: 'site_manager', sourceColumn: 'site_id', targetColumn: 'user_id' };

test('product domain bindings reject incomplete validity windows instead of silently ignoring expiry', () => {
  for (const partial of [{ startsColumn: 'starts_at' }, { expiresColumn: 'expires_at' }]) {
    assert.throws(
      () =>
        new ProductBindingRegistry(declarations, {
          resources,
          domains: { siteManagers: { ...domain, ...partial } },
        }),
      TypeError,
    );
  }
  assert.doesNotThrow(
    () =>
      new ProductBindingRegistry(declarations, {
        resources,
        domains: { siteManagers: domain },
      }),
  );
  assert.doesNotThrow(
    () =>
      new ProductBindingRegistry(declarations, {
        resources,
        domains: {
          siteManagers: { ...domain, startsColumn: 'starts_at', expiresColumn: 'expires_at' },
        },
      }),
  );
});

test('product identity relation SQL checks source object registry type as well as exact version', () => {
  const bindings = new ProductBindingRegistry(declarations, {
    resources,
    domains: { siteManagers: domain },
  });
  const { tenant: oldTenant, membership, ...authority } = snapshot({ declarations });
  void oldTenant;
  const { tenant: requestTenant, ...request } = input();
  void requestTenant;
  const decision = planUser(request, {
    ...authority,
    user: membership && { id: membership.identity, state: membership.state },
    rules: [
      rule('submission.read', { kind: 'identity', identity: alice }, 'allow', 'assignedToMe@1'),
    ],
  });
  assert.equal(decision.effect, 'allow');
  const predicate = compileProductPlan(decision.plan, bindings);
  assert.match(predicate.sql, /object_ref/);
  assert.match(predicate.sql, /relation_version\s*=/);
  assert.match(predicate.sql, /type_key\s*=\s*CAST/);
});
