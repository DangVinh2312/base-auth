import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  createAuthorizationCore,
  type UserAuthoritySnapshot,
  type UserDecision,
  type UserTrustedInput,
} from '@base-authorization/core';
import {
  createDayjsTimestampCodec,
  createStandardValueCodecs,
} from '@base-authorization/value-adapters';
import { alice, core, input, rule, snapshot, submission } from './fixtures.ts';

function userInput(overrides: Partial<UserTrustedInput> = {}): UserTrustedInput {
  const { tenant: _tenant, ...value } = input();
  void _tenant;
  return { ...value, ...overrides };
}

function userSnapshot(overrides: Partial<UserAuthoritySnapshot> = {}): UserAuthoritySnapshot {
  const { tenant: _tenant, membership: _membership, ...value } = snapshot();
  void _tenant;
  void _membership;
  return { ...value, user: { id: alice, state: 'active' }, ...overrides };
}

function allowed(decision: UserDecision) {
  assert.equal(decision.effect, 'allow');
  if (decision.effect !== 'allow') throw new Error('unreachable');
  return decision.plan;
}

const record = submission('record', '1', { amount: '999.00', status: 'closed' });
const facts = {
  now: '2026-10-13T10:00:01.000000Z',
  record,
  objects: [record],
  edges: [],
  exceptions: [],
};

test('unrestricted plan: same target, revision and validity as planUser; predicate true, no obligations', () => {
  // A direct deny on approve and an approval policy with an obligation would bind planUser.
  const plan = allowed(
    core.planUnrestricted(
      userInput({ action: 'approve' }),
      userSnapshot({
        roles: [],
        rules: [rule('submission.approve', { kind: 'identity', identity: alice }, 'deny', 'all@1')],
      }),
    ),
  );
  assert.deepEqual(plan.predicate, { op: 'constant', value: true });
  assert.deepEqual(plan.obligations, []);
  assert.deepEqual(
    [plan.userId, plan.resource, plan.action, plan.permission, plan.revision],
    [alice, 'submission', 'approve', 'submission.approve', '7'],
  );
  assert.equal(Object.isFrozen(plan), true);
  const user = allowed(
    core.planUser(
      userInput(),
      userSnapshot({
        rules: [rule('submission.read', { kind: 'role', role: 'reviewer' }, 'allow', 'all@1')],
      }),
    ),
  );
  const unrestricted = allowed(core.planUnrestricted(userInput(), userSnapshot()));
  assert.deepEqual(
    [unrestricted.resource, unrestricted.action, unrestricted.permission, unrestricted.validUntil],
    [user.resource, user.action, user.permission, user.validUntil],
  );
  // Issued by this instance: the evaluator accepts it and every record matches.
  assert.equal(core.evaluateUser(unrestricted, facts).effect, 'allow');
});

test('unrestricted plan fails closed on target, principal, user, window, revision and provenance', () => {
  const cases: (readonly [string, UserTrustedInput, UserAuthoritySnapshot])[] = [
    ['unknown_resource', userInput({ resource: 'missing' }), userSnapshot()],
    ['unknown_action', userInput({ action: 'delete' }), userSnapshot()],
    [
      'invalid_principal',
      userInput({ principal: { id: alice.toUpperCase() as typeof alice, assurance: 1 } }),
      userSnapshot(),
    ],
    ['inactive_user', userInput(), userSnapshot({ user: { id: alice, state: 'suspended' } })],
    ['invalid_now', userInput({ now: 'not-a-time' }), userSnapshot()],
    ['invalid_validity_window', userInput({ validUntil: userInput().now }), userSnapshot()],
    ['permission_not_in_catalog', userInput(), userSnapshot({ permissions: [] })],
    ...['', '0', '-1', '07', 'x'].map(
      (revision) => ['invalid_revision', userInput(), userSnapshot({ revision })] as const,
    ),
  ];
  for (const [reason, value, authority] of cases)
    assert.deepEqual(
      core.planUnrestricted(value, authority),
      { effect: 'deny', internalReason: reason },
      reason,
    );
  const other = createAuthorizationCore({
    values: createStandardValueCodecs({ timestamp: createDayjsTimestampCodec() }),
  });
  assert.deepEqual(other.planUnrestricted(userInput(), userSnapshot()), {
    effect: 'deny',
    internalReason: 'unvalidated_declarations',
  });
  const plan = allowed(core.planUnrestricted(userInput(), userSnapshot()));
  assert.deepEqual(other.evaluateUser(plan, facts), {
    effect: 'deny',
    internalReason: 'foreign_plan',
  });
});
