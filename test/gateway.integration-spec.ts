import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import type { AuthorizedPlan } from '@base-authorization/core';
import {
  BindingRegistry,
  DataGateway,
  readAuthorityFacts,
  type TenantTransaction,
  TenantTransactionRunner,
} from '@base-authorization/typeorm-postgres/legacy';
import {
  alice,
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
import { withClient } from './setup-postgres.ts';

const { canonicalTimestamp, evaluate, parseKey, plan: planDecision } = core;

const read = 'submission.read';

describe('data gateway', () => {
  let env: GatewayEnvironment;
  let gateway: DataGateway;
  let runner: TenantTransactionRunner;

  // Each test runs inside real tenant transactions holding the shared fence (Task 7).
  const inTx = (body: (txA: TenantTransaction, txB: TenantTransaction) => Promise<void>) => () =>
    runner.run(tenantA, 'read', (a) => runner.run(tenantB, 'read', (b) => body(a, b)));

  before(async () => {
    env = await startGatewayEnvironment();
    runner = new TenantTransactionRunner(env.registry, { deadlineMs: 10_000 });
    gateway = new DataGateway(new BindingRegistry(core, fixtureDeclarations(), storageBindings));
  });
  after(async () => {
    await env?.stop();
  });

  const allPages = async (plan: AuthorizedPlan, tx: TenantTransaction, query: object = {}) => {
    const ids: string[] = [];
    for (let offset = 0; ; offset += 2) {
      const page = await gateway.list(plan, { ...query, limit: 2, offset }, tx);
      ids.push(...page.items.map((item) => String(item.key)));
      if (page.items.length < 2) return { ids, total: page.total };
    }
  };

  const authorizedIds = (plan: AuthorizedPlan) => {
    const now = canonicalTimestamp(new Date().toISOString())!;
    return env.fixtures.A.submissions
      .filter((row) => evaluate(plan, submissionFacts(env.fixtures.A, row, now)).effect === 'allow')
      .map((row) => row.id);
  };

  test(
    'list, count and detail use the same predicate',
    inTx(async (txA) => {
      const plan = readPlan(tenantA, [rule(read, 'allow', 'assignedToMe')]);
      const expected = authorizedIds(plan).sort();
      const { ids, total } = await allPages(plan, txA, { orderBy: 'amount' });
      assert.deepEqual([...ids].sort(), expected);
      assert.equal(await gateway.count(plan, {}, txA), String(expected.length));
      assert.equal(total, String(expected.length));
      for (const row of env.fixtures.A.submissions) {
        const detail = await gateway.detail(plan, parseKey('integer', row.id), txA);
        assert.equal(detail !== null, expected.includes(row.id), `detail ${row.id}`);
      }
    }),
  );

  test(
    'integer keys beyond 2^53 round-trip exactly',
    inTx(async (txA) => {
      const plan = readPlan(tenantA, [rule(read, 'allow', 'all')]);
      const detail = await gateway.detail(plan, parseKey('integer', '9007199254740992'), txA);
      assert.equal(detail?.key, '9007199254740992');
      assert.equal(detail?.amount, '99999999.9999');
      // 9007199254740993 has a personal record deny for alice.
      assert.equal(await gateway.detail(plan, parseKey('integer', '9007199254740993'), txA), null);
    }),
  );

  test(
    'projection is an allowlist: hidden columns are never returned, filtered or sorted',
    inTx(async (txA) => {
      const plan = readPlan(tenantA, [rule(read, 'allow', 'all')]);
      const page = await gateway.list(plan, { limit: 50 }, txA);
      for (const item of page.items) {
        assert.deepEqual(Object.keys(item).sort(), [
          'amount',
          'archived',
          'key',
          'priority',
          'status',
          'submittedAt',
          'title',
        ]);
      }
      await assert.rejects(
        gateway.list(plan, { filter: { op: 'eq', field: 'internalNote', value: 'x' } }, txA),
        TypeError,
      );
      await assert.rejects(gateway.list(plan, { orderBy: 'internal_note' }, txA), TypeError);
      await assert.rejects(gateway.list(plan, { limit: 1_000 }, txA), TypeError);
      await assert.rejects(
        gateway.list(plan, { filter: { op: 'exists', relation: 'x', where: {} } }, txA),
        TypeError,
      );
    }),
  );

  test(
    'a user filter with OR cannot escape the authorization predicate',
    inTx(async (txA) => {
      const plan = readPlan(tenantA, [rule(read, 'allow', 'assignedToMe')]);
      const allowed = authorizedIds(plan);
      const filter = {
        op: 'or',
        args: [
          { op: 'eq', field: 'status', value: 'rejected' },
          { op: 'isNull', field: 'title' },
          { op: 'eq', field: 'status', value: "x' OR '1'='1" },
          { op: 'eq', field: 'status', value: 'approved' },
        ],
      };
      const { ids } = await allPages(plan, txA, { filter });
      assert.ok(
        ids.every((id) => allowed.includes(id)),
        ids.join(','),
      );
      assert.deepEqual(ids.sort(), ['2', '8']);
    }),
  );

  test(
    'query builder: .where()/.orWhere() by the handler cannot replace the predicate',
    inTx(async (txA) => {
      const plan = readPlan(tenantA, [rule(read, 'allow', 'assignedToMe')]);
      const allowed = authorizedIds(plan).sort();
      const rows = await gateway
        .queryBuilder(plan, txA, 'item')
        .select('item.key', 'key')
        .where('1 = 1')
        .orWhere('TRUE')
        .getRawMany<{ key: string }>();
      assert.deepEqual(rows.map((r) => r.key).sort(), allowed);
      await assert.rejects(
        gateway.queryBuilder(plan, txA, 'item').select('item.internal_note').getRawMany(),
      );
    }),
  );

  test(
    'nested resources come only through their own plan',
    inTx(async (txA) => {
      const submissions = readPlan(tenantA, [rule(read, 'allow', 'assignedToMe')]);
      const sites = readPlan(
        tenantA,
        [rule('site.read', 'allow', 'mySites', {}, { kind: 'identity', identity: alice })],
        {
          resource: 'site',
          roles: [],
        },
      );
      const rows = await gateway
        .queryBuilder(submissions, txA, 'item')
        .innerJoin(gateway.subQuery(sites), 'site', 'TRUE')
        .select('site.name', 'name')
        .distinct(true)
        .getRawMany<{ name: string }>();
      assert.deepEqual(rows, [{ name: 'A site A' }]);
    }),
  );

  test(
    'many-to-many relations do not duplicate rows or counts',
    inTx(async (txA) => {
      const plan = readPlan(
        tenantA,
        [rule(read, 'allow', 'managedSite', {}, { kind: 'identity', identity: carol })],
        {
          identity: carol,
          roles: [],
        },
      );
      const { ids, total } = await allPages(plan, txA);
      assert.equal(new Set(ids).size, ids.length);
      assert.equal(
        ids.filter((id) => id === '9007199254740993').length,
        1,
        'linked to two managed sites',
      );
      assert.equal(total, String(ids.length));
      assert.equal(await gateway.count(plan, {}, txA), String(ids.length));
    }),
  );

  test(
    'pagination is stable with ties broken by key',
    inTx(async (txA) => {
      const plan = readPlan(tenantA, [rule(read, 'allow', 'all')]);
      for (const direction of ['asc', 'desc'] as const) {
        const whole = (
          await gateway.list(plan, { orderBy: 'amount', direction, limit: 100 }, txA)
        ).items.map((i) => String(i.key));
        const { ids } = await allPages(plan, txA, { orderBy: 'amount', direction });
        assert.deepEqual(ids, whole);
        assert.equal(new Set(ids).size, ids.length);
      }
    }),
  );

  test(
    'string keys and filter values are data, not SQL',
    inTx(async (txA) => {
      const plan = readPlan(tenantA, [rule('tag.read', 'allow', 'allTags')], { resource: 'tag' });
      assert.equal(
        (await gateway.detail(plan, parseKey('string', "x' OR '1'='1"), txA))?.label,
        'Injection',
      );
      assert.equal((await gateway.detail(plan, parseKey('string', 'α-tag'), txA))?.label, 'Greek');
      assert.equal(await gateway.detail(plan, parseKey('string', "' OR 1=1 --"), txA), null);
      assert.equal(
        await gateway.count(
          plan,
          { filter: { op: 'eq', field: 'label', value: "' OR ''='" } },
          txA,
        ),
        '0',
      );
      await assert.rejects(gateway.detail(plan, parseKey('integer', '1'), txA), TypeError);
    }),
  );

  test(
    'zero cross-tenant results',
    inTx(async (txA, txB) => {
      const planA = readPlan(tenantA, [rule(read, 'allow', 'all')]);
      const planB = readPlan(tenantB, [rule(read, 'allow', 'all')]);
      await assert.rejects(gateway.list(planA, {}, txB), /tenant/i);
      await assert.rejects(gateway.detail(planB, parseKey('integer', '1'), txA), /tenant/i);
      const titlesB = (await gateway.list(planB, { limit: 100 }, txB)).items.map((i) =>
        String(i.title),
      );
      assert.ok(titlesB.length > 0);
      const allA = await txA.manager.query<{ title: string | null }[]>(
        'SELECT title FROM submission',
      );
      const internalB = await txB.manager.query<{ n: string }[]>(
        "SELECT count(*)::text AS n FROM submission WHERE internal_note LIKE 'A %'",
      );
      assert.equal(internalB[0]?.n, '0', 'tenant B database holds no tenant A rows');
      assert.ok(allA.length > 0);
    }),
  );

  test(
    'authority facts read from PostgreSQL drive the same plan',
    inTx(async (txA) => {
      await withClient(env.adminOn(tenantA), (client) =>
        client.query(
          `INSERT INTO policy_rule VALUES ($1, gen_random_uuid(), $2, NULL, $3, 'allow', $4, 1, $5, 'tenant')`,
          [
            tenantA,
            Buffer.from(read),
            Buffer.from('reviewer'),
            Buffer.from('statusIs'),
            JSON.stringify({ status: 'rejected' }),
          ],
        ),
      );
      const facts = await readAuthorityFacts(txA, alice, core);
      assert.deepEqual(facts.membership, { identity: alice, state: 'active' });
      assert.deepEqual(facts.roles, ['reviewer']);
      const now = new Date();
      const decision = planDecision(
        {
          tenant: tenantA,
          principal: { id: alice, assurance: 2 },
          resource: 'submission',
          action: 'read',
          context: {},
          now: now.toISOString(),
          validUntil: new Date(now.getTime() + 60_000).toISOString(),
        },
        {
          ...facts,
          declarations: fixtureDeclarations(),
          registry: { validators: {}, obligationHandlers: [] },
        },
      );
      assert.equal(decision.effect, 'allow');
      if (decision.effect !== 'allow') return;
      const { ids } = await allPages(decision.plan, txA);
      assert.deepEqual(ids.sort(), ['2', '5', '8']);
    }),
  );
});
