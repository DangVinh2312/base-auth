import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  ProductBindingRegistry,
  compilePlan,
} from '../apps/api/dist/authorization/product-sql.compiler.js';
import { declarations, snapshot, input, core } from './core/fixtures.ts';

const { planUser, validate } = core;

test('product SQL uses native keys and bound values without any tenant contract', () => {
  const d = validate(declarations());
  assert.ok(d.ok);
  const registry = new ProductBindingRegistry(core, d.declarations, {
    resources: [
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
    ],
    domains: {
      siteManagers: { table: 'site_manager', sourceColumn: 'site_id', targetColumn: 'user_id' },
    },
  });
  const decision = planUser(input(), snapshot({ declarations: d.declarations }));
  assert.equal(decision.effect, 'allow');
  if (decision.effect !== 'allow') return;
  const sql = compilePlan(decision.plan, registry);
  assert.doesNotMatch(sql.sql, /tenant/);
  assert.match(sql.sql, /statement_timestamp/);
  assert.match(sql.sql, /record_exception/);
  assert.ok(sql.parameters.includes(decision.plan.userId));
});
