import assert from 'node:assert/strict';
import { setTimeout as sleep } from 'node:timers/promises';
import { after, before, describe, test } from 'node:test';
import type { AuthorizedPlan, RuleFact } from '@base-authorization/core';
import {
  BindingRegistry,
  compilePlan,
  type TenantConnectionLease,
} from '@base-authorization/typeorm-postgres/legacy';
import {
  alice,
  bob,
  carol,
  fixtureDeclarations,
  type GatewayEnvironment,
  readPlan,
  rule,
  startGatewayEnvironment,
  storageBindings,
  submissionFacts,
  tenantA,
  tenantB,
  core,
} from './fixtures/resources.ts';

const { canonicalTimestamp, evaluate } = core;

const read = 'submission.read';
const me = { kind: 'identity', identity: alice } as const;

describe('SQL compiler matches the evaluator on PostgreSQL', () => {
  let env: GatewayEnvironment;
  let lease: TenantConnectionLease;
  let bindings: BindingRegistry;

  before(async () => {
    env = await startGatewayEnvironment();
    lease = await env.registry.acquire(tenantA, 'data');
    bindings = new BindingRegistry(core, fixtureDeclarations(), storageBindings);
  });
  after(async () => {
    await lease?.release();
    await env?.stop();
  });

  const sqlIds = async (plan: AuthorizedPlan) => {
    const bound = compilePlan(plan, bindings);
    const rows = await lease.dataSource.query<{ id: string }[]>(
      `SELECT r.id FROM submission r WHERE ${bound.sql} ORDER BY r.id`,
      [...bound.parameters],
    );
    return rows.map((row) => row.id);
  };
  const evaluatorIds = (plan: AuthorizedPlan) => {
    const now = canonicalTimestamp(new Date().toISOString())!;
    return env.fixtures.A.submissions
      .filter((row) => evaluate(plan, submissionFacts(env.fixtures.A, row, now)).effect === 'allow')
      .map((row) => row.id)
      .sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : 1));
  };

  const scenarios: {
    name: string;
    rules: RuleFact[];
    roles?: string[];
    identity?: typeof alice;
    action?: string;
    expected?: string[];
  }[] = [
    {
      name: 'ReBAC identity edge (assignedToMe) + exceptions',
      rules: [rule(read, 'allow', 'assignedToMe')],
      expected: ['1', '2', '8'],
    },
    {
      name: 'ReBAC two-step path with domain table (managedSite)',
      rules: [rule(read, 'allow', 'managedSite', {}, { kind: 'role', role: 'manager' })],
      roles: ['manager'],
      expected: ['1', '2', '5'],
    },
    {
      name: 'many-to-many path (carol manages both sites)',
      rules: [rule(read, 'allow', 'managedSite', {}, { kind: 'identity', identity: carol })],
      roles: [],
      identity: carol,
    },
    { name: 'exact decimal lte', rules: [rule(read, 'allow', 'amountAtMost', { limit: '100.1' })] },
    {
      name: 'integer lt with nulls never matching',
      rules: [rule(read, 'allow', 'priorityBelow', { limit: '3' })],
    },
    { name: 'isNull', rules: [rule(read, 'allow', 'untitled')] },
    {
      name: 'UTF-8 exact equality',
      rules: [rule(read, 'allow', 'titleIs', { title: 'Ångström' })],
      expected: ['2', '8'],
    },
    {
      name: 'code point ordering for strings',
      rules: [rule(read, 'allow', 'titleBefore', { title: 'Zeta' })],
    },
    {
      name: 'microsecond timestamp ordering',
      rules: [rule(read, 'allow', 'submittedBefore', { at: '2025-06-01T12:00:00.123457Z' })],
    },
    { name: 'boolean literal', rules: [rule(read, 'allow', 'notArchived')] },
    { name: 'or inside a grant', rules: [rule(read, 'allow', 'pendingOrCheap')] },
    {
      name: 'personal deny wins (NOT)',
      rules: [
        rule(read, 'allow', 'all'),
        rule(read, 'deny', 'statusIs', { status: 'rejected' }, me),
      ],
    },
    {
      name: 'deny through a relation (NOT EXISTS)',
      rules: [rule(read, 'allow', 'all'), rule(read, 'deny', 'assignedToMe', {}, me)],
    },
    {
      name: 'deny with explicit null branch',
      rules: [rule(read, 'allow', 'all'), rule(read, 'deny', 'untitled')],
    },
    { name: 'no grant: only valid record allows', rules: [], expected: ['2', '8'] },
    {
      name: 'injection string is a bound value',
      rules: [rule(read, 'allow', 'titleIs', { title: "'; DROP TABLE submission; --" })],
      expected: ['2', '5', '8'],
    },
    {
      name: 'required scope outside record allow (approve)',
      rules: [rule('submission.approve', 'allow', 'all')],
      action: 'approve',
    },
  ];

  for (const scenario of scenarios) {
    test(scenario.name, async () => {
      const plan = readPlan(tenantA, scenario.rules, {
        roles: scenario.roles,
        identity: scenario.identity,
        action: scenario.action,
      });
      const fromSql = await sqlIds(plan);
      assert.deepEqual(fromSql, evaluatorIds(plan));
      if (scenario.expected) assert.deepEqual(fromSql, scenario.expected);
    });
  }

  test('required scope excludes a record allow on a non-pending record', async () => {
    const ids = await sqlIds(readPlan(tenantA, [], { action: 'approve' }));
    assert.deepEqual(ids, [], 'row 5 has an approve record allow but is not pending');
  });

  test('values never appear in SQL text; the injection target table survives', async () => {
    const plan = readPlan(tenantA, [
      rule(read, 'allow', 'titleIs', { title: "'; DROP TABLE submission; --" }),
    ]);
    const bound = compilePlan(plan, bindings);
    assert.doesNotMatch(bound.sql, /DROP|Reilly|reviewer|submission\.read/);
    await sqlIds(plan);
    const [count] = await lease.dataSource.query<{ n: string }[]>(
      'SELECT count(*)::text AS n FROM submission',
    );
    assert.equal(count?.n, String(env.fixtures.A.submissions.length));
  });

  test('a plan for tenant B selects nothing in tenant A', async () => {
    assert.deepEqual(await sqlIds(readPlan(tenantB, [rule(read, 'allow', 'all')])), []);
  });

  test('an expired plan selects nothing (checked with the database statement clock)', async () => {
    const plan = readPlan(tenantA, [rule(read, 'allow', 'all')], {
      validUntil: new Date(Date.now() + 300).toISOString(),
    });
    await sleep(1_500);
    assert.deepEqual(await sqlIds(plan), []);
  });

  test('ReBAC on a uuid-keyed resource (mySites)', async () => {
    const plan = readPlan(
      tenantA,
      [rule('site.read', 'allow', 'mySites', {}, { kind: 'identity', identity: bob })],
      {
        resource: 'site',
        identity: bob,
        roles: [],
      },
    );
    const bound = compilePlan(plan, bindings);
    const rows = await lease.dataSource.query<{ id: string }[]>(
      `SELECT r.id FROM site r WHERE ${bound.sql}`,
      [...bound.parameters],
    );
    assert.deepEqual(rows, [{ id: '5e0c2f1e-3b7a-4c1d-9f0e-1a2b3c4d5e6f' }]);
  });

  test('EXPLAIN: native PK lookups keep their indexes (no cast on the key column)', async () => {
    const cases = [
      {
        table: 'submission',
        key: 'id',
        type: 'int8',
        value: '9007199254740992',
        resource: 'submission',
        template: 'all',
        index: 'submission_pkey',
      },
      {
        table: 'site',
        key: 'id',
        type: 'uuid',
        value: 'd97eecc9-8f23-4a76-a9aa-82b9d4ef33ac',
        resource: 'site',
        template: 'allSites',
        index: 'site_pkey',
      },
      {
        table: 'tag',
        key: 'code',
        type: 'text',
        value: 'plain',
        resource: 'tag',
        template: 'allTags',
        index: 'tag_pkey',
      },
    ];
    await lease.dataSource.transaction(async (manager) => {
      await manager.query('SET LOCAL enable_seqscan = off');
      for (const c of cases) {
        const plan = readPlan(tenantA, [rule(`${c.resource}.read`, 'allow', c.template)], {
          resource: c.resource,
        });
        const bound = compilePlan(plan, bindings);
        const rows = await manager.query<{ 'QUERY PLAN': string }[]>(
          `EXPLAIN SELECT 1 FROM ${c.table} r WHERE ${bound.sql} AND r.${c.key} = CAST($${bound.parameters.length + 1} AS ${c.type})`,
          [...bound.parameters, c.value],
        );
        const text = rows.map((r) => r['QUERY PLAN']).join('\n');
        assert.match(text, new RegExp(`Index (Only )?Scan using ${c.index}`), text);
      }
    });
  });
});
