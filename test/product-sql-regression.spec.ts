import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createAuthorizationCore } from '@base-authorization/core';
import type { ScalarCodec, ValueCodecs } from '@base-authorization/core';
import { ProductInvalidRequest } from '@base-authorization/typeorm-postgres';
import { ProductDataGateway } from '@base-authorization/typeorm-postgres/composition';
import type { ProductStorageBindings } from '@base-authorization/typeorm-postgres';
import {
  ProductBindingRegistry,
  compileProductPlan,
} from '@base-authorization/typeorm-postgres/composition';

import type { ProductTransaction } from '@base-authorization/typeorm-postgres/composition';
import { createDayjsTimestampCodec } from '@base-authorization/value-adapters';
import { createStandardValueCodecs } from '@base-authorization/value-adapters';
import {
  alice,
  declarations as source,
  input,
  rule,
  snapshot,
  validated,
  core,
} from '../packages/core/test/fixtures.ts';

const { planUser } = core;

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
        new ProductBindingRegistry(core, declarations, {
          resources,
          domains: { siteManagers: { ...domain, ...partial } },
        }),
      TypeError,
    );
  }
  assert.doesNotThrow(
    () =>
      new ProductBindingRegistry(core, declarations, {
        resources,
        domains: { siteManagers: domain },
      }),
  );
  assert.doesNotThrow(
    () =>
      new ProductBindingRegistry(core, declarations, {
        resources,
        domains: {
          siteManagers: { ...domain, startsColumn: 'starts_at', expiresColumn: 'expires_at' },
        },
      }),
  );
});

test('product identity relation SQL checks source object registry type as well as exact version', () => {
  const bindings = new ProductBindingRegistry(core, declarations, {
    resources,
    domains: { siteManagers: domain },
  });
  const decision = planUser(input(), {
    ...snapshot({ declarations }),
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

test('gateway filters and keys are normalized by the registry core, not a private parser', async () => {
  const calls: string[] = [];
  const standard = createStandardValueCodecs({ timestamp: createDayjsTimestampCodec() });

  const spy = <T extends string | boolean>(kind: string, codec: ScalarCodec<T>) => ({
    normalize: (value: unknown) => (calls.push(kind), codec.normalize(value)),

    compare: (left: T, right: T) => codec.compare(left, right),
  });

  const values = Object.fromEntries(
    Object.entries(standard).map(([kind, codec]) => [
      kind,
      spy(kind, codec as ScalarCodec<string>),
    ]),
  ) as unknown as ValueCodecs;
  const spied = createAuthorizationCore({ values });
  const result = spied.validate(source());
  assert.ok(result.ok);
  const registry = new ProductBindingRegistry(spied, result.declarations, {
    resources: resources.map((r) =>
      r.resource === 'submission' ? { ...r, projection: ['status', 'amount'] } : r,
    ),
    domains: {
      siteManagers: { table: 'site_manager', sourceColumn: 'site_id', targetColumn: 'user_id' },
    },
  });
  const facts = snapshot({
    declarations: result.declarations,
    rules: [rule('submission.read', { kind: 'role', role: 'reviewer' }, 'allow', 'all@1')],
  });
  const decision = spied.planUser(input(), facts);
  assert.equal(decision.effect, 'allow');
  if (decision.effect !== 'allow') return;
  const sent: unknown[][] = [];
  const tx = {
    mode: 'read',
    revision: decision.plan.revision,
    manager: {
      query: (_sql: string, parameters: unknown[]) => (sent.push(parameters), Promise.resolve([])),
    },
  } as unknown as ProductTransaction;
  const gateway = new ProductDataGateway(registry);
  calls.length = 0;
  await gateway.list(
    decision.plan,
    {
      filter: {
        op: 'and',
        args: [
          { op: 'eq', field: 'status', value: 'pending' },
          { op: 'lte', field: 'amount', value: '20.5' },
        ],
      },
    },
    tx,
  );
  assert.deepEqual(calls.sort(), ['decimal', 'string']);
  assert.ok(sent[0]!.includes('pending') && sent[0]!.includes('20.5'));
  calls.length = 0;
  await gateway.detail(decision.plan, { kind: 'integer', value: '9007199254740993' }, tx);
  assert.deepEqual(calls, ['integer']);
  // What the codec refuses never reaches SQL.
  const before = sent.length;
  await assert.rejects(
    gateway.list(decision.plan, { filter: { op: 'lte', field: 'amount', value: 20 } }, tx),
    ProductInvalidRequest,
  );
  assert.equal(sent.length, before);
});
