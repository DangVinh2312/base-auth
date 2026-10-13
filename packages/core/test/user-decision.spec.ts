import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as core from '@base-authorization/core';
import {
  alice,
  bob,
  declarations,
  facts,
  input,
  rule,
  snapshot,
  submission,
  validated,
} from './fixtures.ts';

function userInput() {
  const { tenant: _tenant, ...value } = input();
  void _tenant;
  return value;
}

function userSnapshot() {
  const { tenant: _tenant, membership: _membership, ...value } = snapshot();
  void _tenant;
  void _membership;
  return { ...value, user: { id: alice, state: 'active' as const } };
}

function userFacts(amount = '10.00') {
  const { tenant: _tenant, ...value } = facts(submission('record', '1', { amount }));
  void _tenant;
  return { ...value, edges: [], exceptions: [] };
}

test('user authorization exports a tenant-free plan and shares policy, boundary and deny algebra', () => {
  assert.equal(typeof core.planUser, 'function');
  assert.equal(typeof core.evaluateUser, 'function');
  const source = declarations();
  const authority = {
    ...userSnapshot(),
    declarations: validated({
      ...source,
      boundaries: [
        {
          key: 'limit',
          version: 1,
          entries: [
            {
              permission: 'submission.read',
              contextRequirements: [],
              requiredScope: {
                op: 'lte' as const,
                field: 'amount',
                value: { from: 'literal' as const, value: '20' },
              },
            },
          ],
        },
      ],
    }),
    roles: ['system.root'],
    boundaries: [
      {
        identity: alice,
        permission: 'submission.read',
        boundary: { key: 'limit', version: 1 },
        lifecycle: 'active' as const,
      },
    ],
    rules: [rule('submission.read', { kind: 'role', role: 'system.root' }, 'allow', 'all@1')],
  };
  const decision = core.planUser(userInput(), authority);
  assert.equal(decision.effect, 'allow');
  assert.equal(decision.plan.userId, alice);
  assert.equal(Object.hasOwn(decision.plan, 'tenant'), false);
  assert.equal(Object.hasOwn(decision.plan, 'identity'), false);
  assert.equal(core.evaluateUser(decision.plan, userFacts()).effect, 'allow');
  assert.equal(core.evaluateUser(decision.plan, userFacts('21')).effect, 'deny');
  const { amount: _amount, ...missingAmount } = userFacts().record.fields;
  void _amount;
  assert.equal(
    core.evaluateUser(decision.plan, {
      ...userFacts(),
      record: { ...userFacts().record, fields: missingAmount },
    }).effect,
    'deny',
  );
  const denied = core.planUser(userInput(), {
    ...authority,
    rules: [
      ...authority.rules,
      rule('submission.read', { kind: 'identity', identity: alice }, 'deny', 'all@1'),
    ],
  });
  assert.equal(denied.effect, 'allow');
  if (denied.effect === 'allow')
    assert.equal(core.evaluateUser(denied.plan, userFacts()).effect, 'deny');
  const ungranted = core.planUser(userInput(), { ...authority, rules: [] });
  if (ungranted.effect === 'allow') {
    assert.equal(core.evaluateUser(ungranted.plan, userFacts()).effect, 'deny');
    const exception: core.UserExceptionFact = {
      objectId: 'record',
      permission: 'submission.read',
      subject: { kind: 'identity', identity: alice },
      effect: 'allow',
      purpose: 'manual',
      startsAt: userInput().now,
      expiresAt: null,
      revokedAt: null,
    };
    assert.equal(
      core.evaluateUser(ungranted.plan, { ...userFacts(), exceptions: [exception] }).effect,
      'allow',
    );
    assert.equal(
      core.evaluateUser(ungranted.plan, { ...userFacts('21'), exceptions: [exception] }).effect,
      'deny',
    );
  }
});

test('user record allows stay inside policy; record deny wins', () => {
  const decision = core.planUser(
    { ...userInput(), action: 'approve', principal: { id: alice, assurance: 2 } },
    userSnapshot(),
  );
  if (decision.effect !== 'allow') throw new Error(decision.internalReason);
  const allow: core.UserExceptionFact = {
    objectId: 'record',
    permission: 'submission.approve',
    subject: { kind: 'identity', identity: alice },
    effect: 'allow',
    purpose: 'manual',
    startsAt: userInput().now,
    expiresAt: null,
    revokedAt: null,
  };
  const complete = { ...userFacts(), exceptions: [allow] };
  assert.equal(core.evaluateUser(decision.plan, complete).effect, 'allow');
  assert.equal(
    core.evaluateUser(decision.plan, {
      ...complete,
      record: submission('record', '1', { status: 'closed' }),
    }).effect,
    'deny',
  );
  assert.equal(
    core.evaluateUser(decision.plan, {
      ...complete,
      exceptions: [allow, { ...allow, effect: 'deny' }],
    }).effect,
    'deny',
  );
  assert.equal(
    core.evaluateUser(decision.plan, {
      ...complete,
      exceptions: [{ ...allow, purpose: 'emergency' }],
    }).effect,
    'deny',
  );
});

test('user ReBAC traverses typed edges with expiry and missing facts fail closed', () => {
  const decision = core.planUser(userInput(), {
    ...userSnapshot(),
    rules: [
      rule('submission.read', { kind: 'identity', identity: alice }, 'allow', 'assignedToMe@1'),
    ],
  });
  if (decision.effect !== 'allow') throw new Error(decision.internalReason);
  const edge: core.UserEdgeFact = {
    source: 'record',
    relation: { key: 'submission.assignee', version: 1 },
    target: { kind: 'identity', identity: alice },
    startsAt: userInput().now,
    expiresAt: null,
  };
  assert.equal(core.evaluateUser(decision.plan, { ...userFacts(), edges: [edge] }).effect, 'allow');
  assert.equal(core.evaluateUser(decision.plan, userFacts()).effect, 'deny');
  assert.equal(
    core.evaluateUser(decision.plan, {
      ...userFacts(),
      edges: [{ ...edge, expiresAt: userInput().now }],
    }).effect,
    'deny',
  );
  assert.equal(
    core.evaluateUser(decision.plan, {
      ...userFacts(),
      edges: [{ ...edge, relation: { ...edge.relation, version: 2 } }],
    }).effect,
    'deny',
  );
});

test('user facts must identify the active principal; Root has no grant bypass', () => {
  for (const user of [
    undefined,
    { id: bob, state: 'active' as const },
    { id: alice, state: 'suspended' as const },
    { id: alice, state: 'pending' as const },
  ]) {
    assert.equal(core.planUser(userInput(), { ...userSnapshot(), user }).effect, 'deny');
  }
  const decision = core.planUser(userInput(), { ...userSnapshot(), roles: ['system.root'] });
  if (decision.effect === 'allow')
    assert.equal(core.evaluateUser(decision.plan, userFacts()).effect, 'deny');
});
