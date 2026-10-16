import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { UserExceptionFact } from '../../apps/api/dist/authorization/core/authorization.types.js';
import {
  alice,
  core,
  declarations,
  facts,
  input,
  rule,
  snapshot,
  submission,
  validated,
} from './fixtures.ts';

const { evaluateUser: evaluate, planUser: plan, validate } = core;

const pending = submission('53000000-0000-4000-8000-000000000001', '1', { status: 'pending' });
const approved = submission('53000000-0000-4000-8000-000000000002', '2', { status: 'approved' });

const approveAllowException = (objectId: string): UserExceptionFact => ({
  objectId,
  permission: 'submission.approve',
  subject: { kind: 'identity', identity: alice },
  effect: 'allow',
  purpose: 'manual',
  startsAt: '2026-10-01T00:00:00.000000Z',
  expiresAt: null,
  revokedAt: null,
});

const approveInput = (assurance: number) =>
  input({ action: 'approve', principal: { id: alice, assurance } });

test('record allow cannot bypass the policy required scope', () => {
  const decision = plan(approveInput(3), snapshot());
  assert.equal(decision.effect, 'allow');
  if (decision.effect !== 'allow') return;
  assert.equal(
    evaluate(
      decision.plan,
      facts(approved, { exceptions: [approveAllowException(approved.objectId)] }),
    ).effect,
    'deny',
  );
  assert.equal(
    evaluate(
      decision.plan,
      facts(pending, { exceptions: [approveAllowException(pending.objectId)] }),
    ).effect,
    'allow',
  );
});

test('context requirement (assurance) is enforced before any grant or record allow', () => {
  const rules = [rule('submission.approve', { kind: 'role', role: 'reviewer' }, 'allow', 'all@1')];
  assert.equal(plan(approveInput(1), snapshot({ rules })).effect, 'deny');
  assert.equal(plan(approveInput(2), snapshot({ rules })).effect, 'allow');
});

test('validator results other than true deny: false, unknown, throw, missing', () => {
  for (const validator of [
    () => false,
    () => 'unknown' as const,
    () => {
      throw new Error('fact source down');
    },
  ]) {
    const s = snapshot({
      registry: {
        validators: { 'minimumAssurance@1': validator },
        obligationHandlers: ['auditBeforeCommit@1'],
      },
    });
    assert.equal(plan(approveInput(5), s).effect, 'deny');
  }
  const missing = snapshot({
    registry: { validators: {}, obligationHandlers: ['auditBeforeCommit@1'] },
  });
  assert.equal(plan(approveInput(5), missing).effect, 'deny');
});

test('policy satisfied but no grant still denies', () => {
  const decision = plan(input(), snapshot());
  assert.equal(decision.effect, 'allow', 'record allows may still apply, so the plan exists');
  assert.equal(
    decision.effect === 'allow' && evaluate(decision.plan, facts(pending)).effect,
    'deny',
  );
});

test('obligations are attached whichever path grants, and merged by handler', () => {
  const decision = plan(approveInput(3), snapshot());
  assert.ok(decision.effect === 'allow');
  assert.deepEqual(decision.obligations, [{ handler: 'auditBeforeCommit@1' }]);
  assert.deepEqual(
    evaluate(
      decision.plan,
      facts(pending, { exceptions: [approveAllowException(pending.objectId)] }),
    ),
    {
      effect: 'allow',
      plan: decision.plan,
      obligations: [{ handler: 'auditBeforeCommit@1' }],
    },
  );

  const base = declarations();
  const doubled = validated(
    declarations({
      policies: base.policies.map((p) =>
        p.key === 'approval'
          ? {
              ...p,
              obligations: [{ handler: 'auditBeforeCommit@1' }, { handler: 'auditBeforeCommit@1' }],
            }
          : p,
      ),
    }),
  );
  const merged = plan(approveInput(3), snapshot({ declarations: doubled }));
  assert.ok(merged.effect === 'allow');
  assert.deepEqual(merged.obligations, [{ handler: 'auditBeforeCommit@1' }]);
});

test('absent, retired or mismatched policies fail readiness and runtime', () => {
  const base = declarations();
  const absent = validate(
    declarations({ policies: base.policies.filter((p) => p.key !== 'approval') }),
  );
  assert.equal(absent.ok, false);
  const retired = validate(
    declarations({
      policies: base.policies.map((p) =>
        p.key === 'approval' ? { ...p, lifecycle: 'retired' as const } : p,
      ),
    }),
  );
  assert.equal(retired.ok, false);

  const permissions = snapshot().permissions;
  const wrongVersion = permissions.map((p) =>
    p.key === 'submission.approve' ? { ...p, policy: { key: 'approval', version: 2 } } : p,
  );
  assert.equal(plan(approveInput(3), snapshot({ permissions: wrongVersion })).effect, 'deny');
  const retiredCatalog = permissions.map((p) =>
    p.key === 'submission.approve' ? { ...p, lifecycle: 'retired' as const } : p,
  );
  assert.equal(plan(approveInput(3), snapshot({ permissions: retiredCatalog })).effect, 'deny');
});

test('missing validator or obligation handler fails readiness and runtime', () => {
  assert.equal(
    validate(
      declarations({
        capabilities: { validators: [], obligationHandlers: ['auditBeforeCommit@1'] },
      }),
    ).ok,
    false,
  );
  assert.equal(
    validate(
      declarations({
        capabilities: { validators: ['minimumAssurance@1'], obligationHandlers: [] },
      }),
    ).ok,
    false,
  );
  const s = snapshot({ registry: { ...snapshot().registry, obligationHandlers: [] } });
  assert.equal(plan(approveInput(3), s).effect, 'deny');
});

test('no arbitrary JS, SQL strings, admin-supplied not, or unknown value sources', () => {
  const base = declarations();

  const withTemplate = (expression: unknown) =>
    validate(
      declarations({
        templates: [
          ...base.templates,
          {
            key: 'evil',
            version: 1,
            resource: 'submission',
            parameters: {},
            expression: expression as never,
          },
        ],
      }),
    );

  assert.equal(withTemplate({ op: 'sql', sql: '1=1' }).ok, false);
  assert.equal(withTemplate(() => true).ok, false);
  assert.equal(withTemplate({ op: 'eq', field: 'status', value: '1 OR 1=1' }).ok, false);
  assert.equal(
    withTemplate({ op: 'eq', field: 'status', value: { from: 'record', name: 'x' } }).ok,
    false,
  );
  assert.equal(withTemplate({ op: 'not', arg: { op: 'constant', value: false } }).ok, false);
  assert.equal(
    withTemplate({ op: 'eq', field: 'status', value: { from: 'literal', value: null } }).ok,
    false,
  );
  assert.equal(
    withTemplate({ op: 'eq', field: 'missing', value: { from: 'literal', value: 'x' } }).ok,
    false,
  );
  assert.equal(
    withTemplate({ op: 'lt', field: 'status', value: { from: 'literal', value: true } }).ok,
    false,
  );
  assert.equal(
    withTemplate({ op: 'eq', field: 'status', value: { from: 'parameter', name: 'undeclared' } })
      .ok,
    false,
  );
});
