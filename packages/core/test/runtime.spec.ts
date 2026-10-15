import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as api from '@base-authorization/core';
import {
  type AuthorizationCore,
  createAuthorizationCore,
  type ScalarCodec,
  type UserAuthoritySnapshot,
  type UserCompleteFacts,
  type UserTrustedInput,
  type ValueCodecs,
} from '@base-authorization/core';
import {
  createDayjsTimestampCodec,
  createStandardValueCodecs,
} from '@base-authorization/value-adapters';
import { alice, declarations, input, rule, snapshot, submission } from './fixtures.ts';

const standard = () => createStandardValueCodecs({ timestamp: createDayjsTimestampCodec() });
const reviewer = { kind: 'role', role: 'reviewer' } as const;

function userInput(overrides: Partial<UserTrustedInput> = {}): UserTrustedInput {
  const { tenant: _tenant, ...value } = input();
  void _tenant;
  return { ...value, ...overrides };
}

/** Snapshot whose declarations were validated by `core`; one decimal `lte` allow rule. */
function userSnapshot(core: AuthorizationCore): UserAuthoritySnapshot {
  const result = core.validate(declarations());
  assert.ok(result.ok);
  const {
    tenant: _tenant,
    membership: _membership,
    ...value
  } = snapshot({
    declarations: result.declarations,
    rules: [rule('submission.read', reviewer, 'allow', 'amountAtMost@1', { limit: '50' })],
  });
  void _tenant;
  void _membership;
  return { ...value, user: { id: alice, state: 'active' } };
}

function userFacts(amount = '10.00'): UserCompleteFacts {
  const record = submission('record', '1', { amount });
  return {
    now: '2026-10-13T10:00:01.000000Z',
    record,
    objects: [record],
    edges: [],
    exceptions: [],
  };
}

function allowedPlan(core: AuthorizationCore) {
  const decision = core.planUser(userInput(), userSnapshot(core));
  assert.equal(decision.effect, 'allow');
  if (decision.effect !== 'allow') throw new Error('unreachable');
  return decision.plan;
}

/** Wraps every codec method with a call counter; semantics stay those of `values`. */
function spy(values: ValueCodecs) {
  const calls: Record<string, number> = {};
  const count = (name: string) => (calls[name] = (calls[name] ?? 0) + 1);
  const wrap = <T extends string | boolean>(kind: string, codec: ScalarCodec<T>) => ({
    normalize: (value: unknown) => (count(`${kind}.normalize`), codec.normalize(value)),
    compare: (l: T, r: T) => (count(`${kind}.compare`), codec.compare(l, r)),
  });
  return {
    calls,
    values: {
      timestamp: wrap('timestamp', values.timestamp),
      integer: wrap('integer', values.integer),
      decimal: wrap('decimal', values.decimal),
      uuid: wrap('uuid', values.uuid),
      string: wrap('string', values.string),
      boolean: wrap('boolean', values.boolean),
    } satisfies ValueCodecs,
  };
}

test('public API: no default engine; scalar/plan/evaluate free functions are gone', () => {
  assert.equal(typeof api.createAuthorizationCore, 'function');
  for (const removed of [
    'validate',
    'isValidated',
    'plan',
    'evaluate',
    'planUser',
    'evaluateUser',
    'planUnrestricted',
    'normalizeValue',
    'compareValues',
    'canonicalTimestamp',
    'canonicalInt64',
    'parseKey',
    'isCanonicalUuid',
    'parseTenantId',
  ]) {
    assert.equal(Object.hasOwn(api, removed), false, `${removed} must not be a free export`);
  }
  assert.deepEqual(
    Object.keys(api).filter((name) => /default/i.test(name)),
    [],
  );
  // Pure, codec-free helpers stay exports.
  for (const pure of ['refKey', 'keyEquals', 'canonicalJson', 'MAX_PATH_DEPTH', 'MAX_KEY_BYTES'])
    assert.ok(Object.hasOwn(api, pure), pure);
});

test('instances are independent: declarations validated by A are refused by B', () => {
  const a = createAuthorizationCore({ values: standard() });
  const b = createAuthorizationCore({ values: standard() });
  const fromA = userSnapshot(a);
  assert.equal(a.isValidated(fromA.declarations), true);
  assert.equal(b.isValidated(fromA.declarations), false);
  assert.equal(a.planUser(userInput(), fromA).effect, 'allow');
  assert.deepEqual(b.planUser(userInput(), fromA), {
    effect: 'deny',
    internalReason: 'unvalidated_declarations',
  });
  assert.deepEqual(b.plan(input(), snapshot({ declarations: fromA.declarations })), {
    effect: 'deny',
    internalReason: 'unvalidated_declarations',
  });
});

test('a plan issued by A is refused by B evaluation (fail closed)', () => {
  const a = createAuthorizationCore({ values: standard() });
  const b = createAuthorizationCore({ values: standard() });
  const plan = allowedPlan(a);
  assert.equal(a.evaluateUser(plan, userFacts()).effect, 'allow');
  assert.deepEqual(b.evaluateUser(plan, userFacts()), {
    effect: 'deny',
    internalReason: 'foreign_plan',
  });
  // A structurally identical copy was never issued by any core.
  assert.equal(a.evaluateUser({ ...plan }, userFacts()).effect, 'deny');
});

test('each instance keeps its own value semantics', () => {
  const strict = createAuthorizationCore({ values: standard() });
  const refuseTimes = createAuthorizationCore({
    values: { ...standard(), timestamp: { normalize: () => undefined, compare: () => 0 } },
  });
  assert.equal(strict.planUser(userInput(), userSnapshot(strict)).effect, 'allow');
  assert.deepEqual(refuseTimes.planUser(userInput(), userSnapshot(refuseTimes)), {
    effect: 'deny',
    internalReason: 'invalid_now',
  });
});

test('a missing or malformed codec fails at construction', () => {
  for (const kind of ['timestamp', 'integer', 'decimal', 'uuid', 'string', 'boolean'] as const) {
    const values: Record<string, unknown> = { ...standard() };
    delete values[kind];
    assert.throws(
      () => createAuthorizationCore({ values: values as unknown as ValueCodecs }),
      new RegExp(`codec ${kind}`),
    );
    assert.throws(
      () =>
        createAuthorizationCore({
          values: { ...standard(), [kind]: { normalize: () => undefined } },
        }),
      new RegExp(`codec ${kind}`),
    );
  }
  assert.throws(
    () => createAuthorizationCore({ values: undefined as unknown as ValueCodecs }),
    TypeError,
  );
});

test('the codec table is captured at construction (no later mutation, no shared default)', () => {
  const values: { -readonly [K in keyof ValueCodecs]: ValueCodecs[K] } = { ...standard() };
  const core = createAuthorizationCore({ values });
  values.timestamp = { normalize: () => undefined, compare: () => 0 };
  assert.equal(core.planUser(userInput(), userSnapshot(core)).effect, 'allow');
  assert.ok(Object.isFrozen(core));
});

test('a throwing codec never allows', () => {
  const boom = () => {
    throw new Error('codec failure');
  };
  const throwsOnNormalize = createAuthorizationCore({
    values: { ...standard(), timestamp: { normalize: boom, compare: boom } },
  });
  assert.deepEqual(throwsOnNormalize.planUser(userInput(), userSnapshot(throwsOnNormalize)), {
    effect: 'deny',
    internalReason: 'internal_error',
  });
  const strictValues = standard();
  const throwsOnCompare = createAuthorizationCore({
    values: {
      ...strictValues,
      decimal: {
        normalize: (value: unknown) => strictValues.decimal.normalize(value),
        compare: boom,
      },
    },
  });
  assert.equal(
    throwsOnCompare.evaluateUser(allowedPlan(throwsOnCompare), userFacts()).effect,
    'deny',
  );
  // Validation through a failing codec is a configuration error result, not a pass or a throw.
  const throwsOnString = createAuthorizationCore({
    values: { ...standard(), string: { normalize: boom, compare: boom } },
  });
  const failed = throwsOnString.validate(declarations());
  assert.equal(failed.ok, false);
  assert.ok(!failed.ok && failed.errors.every((e) => !e.includes('pending')), 'no raw input echo');
  assert.equal(throwsOnString.isValidated(failed), false);
  const outOfContract = createAuthorizationCore({
    values: {
      ...standard(),
      string: { normalize: () => 7 as unknown as string, compare: () => 0 },
    },
  });
  assert.equal(outOfContract.validate(declarations()).ok, false);
});

test('canonical identity checks stay lowercase-only even if the uuid codec does not lowercase', () => {
  const anyCase = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
  const passThrough = createAuthorizationCore({
    values: {
      ...standard(),
      uuid: {
        normalize: (value: unknown) =>
          typeof value === 'string' && anyCase.test(value) ? value : undefined,
        compare: (left: string, right: string) => (left === right ? 0 : 1),
      },
    },
  });
  const upper = alice.toUpperCase();
  assert.equal(passThrough.normalizeValue('uuid', upper), upper); // the codec's own business
  assert.equal(passThrough.isCanonicalUuid(upper), false);
  assert.throws(() => passThrough.parseTenantId(upper), TypeError);
  assert.equal(passThrough.isCanonicalUuid(alice), true);
  assert.deepEqual(
    passThrough.planUser(
      userInput({ principal: { id: upper as typeof alice, assurance: 1 } }),
      userSnapshot(passThrough),
    ),
    { effect: 'deny', internalReason: 'invalid_principal' },
  );
});

test('an out-of-contract codec result never allows', () => {
  const badNormalize = createAuthorizationCore({
    values: {
      ...standard(),
      timestamp: { normalize: () => 42 as unknown as string, compare: () => 0 },
    },
  });
  assert.equal(badNormalize.planUser(userInput(), userSnapshot(badNormalize)).effect, 'deny');
  const strictValues = standard();
  const badCompare = createAuthorizationCore({
    values: {
      ...strictValues,
      decimal: {
        normalize: (value: unknown) => strictValues.decimal.normalize(value),
        compare: () => 2 as unknown as 0,
      },
    },
  });
  assert.equal(badCompare.evaluateUser(allowedPlan(badCompare), userFacts()).effect, 'deny');
  assert.throws(() => badCompare.compareValues('decimal', '1', '2'), TypeError);
});

test('validator, planner and evaluator route scalars through the injected codecs', () => {
  const { calls, values } = spy(standard());
  const core = createAuthorizationCore({ values });
  const validated = core.validate(declarations());
  assert.ok(validated.ok);
  assert.ok(calls['string.normalize']! > 0, 'validator normalizes declaration literals');
  for (const key of Object.keys(calls)) delete calls[key];

  const plan = allowedPlan(core);
  assert.ok(calls['timestamp.normalize']! >= 2, 'planner normalizes now/validUntil');
  assert.ok(calls['timestamp.compare']! >= 1, 'planner compares the validity window');
  assert.ok(calls['decimal.normalize']! >= 1, 'planner normalizes rule parameters');
  for (const key of Object.keys(calls)) delete calls[key];

  assert.equal(core.evaluateUser(plan, userFacts()).effect, 'allow');
  assert.equal(core.evaluateUser(plan, userFacts('51')).effect, 'deny');
  assert.ok(calls['timestamp.normalize']! >= 1, 'evaluator normalizes facts.now');
  assert.ok(calls['timestamp.compare']! >= 1, 'evaluator compares expiry via the codec');
  assert.ok(calls['decimal.normalize']! >= 2, 'evaluator normalizes fact values');
  assert.ok(calls['decimal.compare']! >= 2, 'evaluator compares via the codec');
});

test('timestamp validity is the codec’s: core has no regex/Date.parse fallback of its own', () => {
  // Deliberately lenient codec: accepts anything Date.parse accepts (what conformance rejects).
  const lenient: ScalarCodec<string> = {
    normalize(value) {
      if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) return undefined;
      return value;
    },
    compare: (l, r) => (l === r ? 0 : l < r ? -1 : 1),
  };
  const permissive = createAuthorizationCore({ values: { ...standard(), timestamp: lenient } });
  const strict = createAuthorizationCore({ values: standard() });
  const feb30 = userInput({ now: '2026-02-30T00:00:00Z', validUntil: '2026-03-31T00:00:00Z' });
  assert.equal(permissive.planUser(feb30, userSnapshot(permissive)).effect, 'allow');
  assert.deepEqual(strict.planUser(feb30, userSnapshot(strict)), {
    effect: 'deny',
    internalReason: 'invalid_now',
  });
  const hour24 = userInput({ now: '2026-10-13T24:00:00Z' });
  assert.equal(strict.planUser(hour24, userSnapshot(strict)).effect, 'deny');
});

test('scalar methods delegate to the instance codecs and keep their contracts', () => {
  const core = createAuthorizationCore({ values: standard() });
  assert.equal(core.canonicalTimestamp('2026-10-14T00:00:00.1Z'), '2026-10-14T00:00:00.100000Z');
  assert.equal(core.canonicalTimestamp('2026-02-30T00:00:00Z'), undefined);
  assert.equal(core.canonicalTimestamp('2026-10-14T00:00:00+07:00'), undefined);
  assert.equal(core.canonicalInt64('9223372036854775807'), '9223372036854775807');
  assert.equal(core.canonicalInt64(9007199254740993n), '9007199254740993');
  assert.equal(core.canonicalInt64(42), undefined);
  assert.equal(core.normalizeValue('uuid', 'A0000000-0000-4000-8000-000000000001'), alice);
  assert.equal(core.compareValues('decimal', '10.0', '10.00'), 0);
  assert.equal(core.compareValues('integer', '9007199254740993', '9007199254740992'), 1);
  assert.equal(core.isCanonicalUuid(alice), true);
  assert.equal(core.isCanonicalUuid(alice.toUpperCase()), false);
  assert.equal(core.parseTenantId(alice), alice);
  assert.throws(() => core.parseTenantId(alice.toUpperCase()), TypeError);
  assert.deepEqual(core.parseKey('uuid', alice.toUpperCase()), { kind: 'uuid', value: alice });
  assert.throws(() => core.parseKey('integer', 42), TypeError);
  assert.throws(() => core.parseKey('string', ''), TypeError);
  assert.throws(() => core.parseKey('string', 'a'.repeat(257)), TypeError);
  assert.throws(() => core.parseKey('other' as 'string', 'x'), TypeError);
});
