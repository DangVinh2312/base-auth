import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import type {
  UserAuthoritySnapshot,
  UserCompleteFacts,
  UserExceptionFact,
  RuleFact,
  UserTrustedInput,
} from '@base-authorization/core';
import {
  alice,
  bob,
  core,
  declarations,
  facts,
  input,
  now,
  rule,
  snapshot,
  submission,
  validated,
} from './fixtures.ts';

const { evaluateUser: evaluate, planUser: plan } = core;

function decide(
  i: UserTrustedInput,
  s: UserAuthoritySnapshot,
  f: UserCompleteFacts,
): 'allow' | 'deny' {
  const decision = plan(i, s);
  if (decision.effect === 'deny') return 'deny';
  return evaluate(decision.plan, f).effect;
}

const read = (
  subject: RuleFact['subject'],
  effect: RuleFact['effect'],
  template: string,
  parameters = {},
) => rule('submission.read', subject, effect, template, parameters);

const reviewer = { kind: 'role', role: 'reviewer' } as const;
const personal = { kind: 'identity', identity: alice } as const;

function exception(
  effect: UserExceptionFact['effect'],
  objectId: string,
  extra: Partial<UserExceptionFact> = {},
): UserExceptionFact {
  return {
    objectId,
    permission: 'submission.read',
    subject: { kind: 'identity', identity: alice },
    effect,
    purpose: 'manual',
    startsAt: '2026-10-01T00:00:00.000000Z',
    expiresAt: null,
    revokedAt: null,
    ...extra,
  };
}

const s1 = submission('51000000-0000-4000-8000-000000000001', '1', { status: 'pending' });
const s2 = submission('51000000-0000-4000-8000-000000000002', '2', { status: 'approved' });

describe('decision precedence', () => {
  const cases: {
    name: string;
    input?: Partial<UserTrustedInput>;
    snapshot?: Partial<UserAuthoritySnapshot>;
    facts: UserCompleteFacts;
    expected: 'allow' | 'deny';
  }[] = [
    {
      name: 'role grant matches',
      snapshot: { rules: [read(reviewer, 'allow', 'statusIs@1', { status: 'pending' })] },
      facts: facts(s1),
      expected: 'allow',
    },
    {
      name: 'role grant scope does not match',
      snapshot: { rules: [read(reviewer, 'allow', 'statusIs@1', { status: 'pending' })] },
      facts: facts(s2),
      expected: 'deny',
    },
    {
      name: 'inactive user even with record allow',
      snapshot: {
        user: { id: alice, state: 'suspended' },
        rules: [read(reviewer, 'allow', 'all@1')],
      },
      facts: facts(s1, { exceptions: [exception('allow', s1.objectId)] }),
      expected: 'deny',
    },
    {
      name: 'user of another identity',
      snapshot: {
        user: { id: bob, state: 'active' },
        rules: [read(reviewer, 'allow', 'all@1')],
      },
      facts: facts(s1),
      expected: 'deny',
    },
    { name: 'empty grant', facts: facts(s1), expected: 'deny' },
    {
      name: 'role allow + personal deny',
      snapshot: { rules: [read(reviewer, 'allow', 'all@1'), read(personal, 'deny', 'all@1')] },
      facts: facts(s1),
      expected: 'deny',
    },
    {
      name: 'personal allow + role deny',
      snapshot: {
        rules: [
          read(personal, 'allow', 'all@1'),
          read(reviewer, 'deny', 'statusIs@1', { status: 'pending' }),
        ],
      },
      facts: facts(s1),
      expected: 'deny',
    },
    {
      name: 'role deny outside its scope leaves allow',
      snapshot: {
        rules: [
          read(personal, 'allow', 'all@1'),
          read(reviewer, 'deny', 'statusIs@1', { status: 'pending' }),
        ],
      },
      facts: facts(s2),
      expected: 'allow',
    },
    {
      name: 'rule for an unassigned role is ignored',
      snapshot: { rules: [read({ kind: 'role', role: 'manager' }, 'allow', 'all@1')] },
      facts: facts(s1),
      expected: 'deny',
    },
    {
      name: 'record allow outside grant scope',
      snapshot: { rules: [read(reviewer, 'allow', 'statusIs@1', { status: 'pending' })] },
      facts: facts(s2, { exceptions: [exception('allow', s2.objectId)] }),
      expected: 'allow',
    },
    {
      name: 'record deny wins over role allow',
      snapshot: { rules: [read(reviewer, 'allow', 'all@1')] },
      facts: facts(s1, { exceptions: [exception('deny', s1.objectId)] }),
      expected: 'deny',
    },
    {
      name: 'record deny wins over record allow of another subject',
      facts: facts(s1, {
        exceptions: [
          exception('allow', s1.objectId),
          exception('deny', s1.objectId, { subject: { kind: 'role', role: 'reviewer' } }),
        ],
      }),
      expected: 'deny',
    },
    {
      name: 'emergency record allow never grants (until the D3 activation contract exists)',
      facts: facts(s1, {
        exceptions: [
          exception('allow', s1.objectId, {
            purpose: 'emergency',
            expiresAt: '2026-10-13T10:10:00.000000Z',
          }),
        ],
      }),
      expected: 'deny',
    },
    {
      name: 'emergency record deny still denies',
      snapshot: { rules: [read(reviewer, 'allow', 'all@1')] },
      facts: facts(s1, {
        exceptions: [
          exception('deny', s1.objectId, {
            purpose: 'emergency',
            expiresAt: '2026-10-13T10:10:00.000000Z',
          }),
        ],
      }),
      expected: 'deny',
    },
    {
      name: 'expired record allow',
      facts: facts(s1, { exceptions: [exception('allow', s1.objectId, { expiresAt: now })] }),
      expected: 'deny',
    },
    {
      name: 'revoked record allow',
      facts: facts(s1, {
        exceptions: [exception('allow', s1.objectId, { revokedAt: '2026-10-02T00:00:00.000000Z' })],
      }),
      expected: 'deny',
    },
    {
      name: 'role record allow after role removed',
      snapshot: { roles: [] },
      facts: facts(s1, {
        exceptions: [
          exception('allow', s1.objectId, { subject: { kind: 'role', role: 'reviewer' } }),
        ],
      }),
      expected: 'deny',
    },
    {
      name: 'record allow on another object',
      facts: facts(s1, { exceptions: [exception('allow', s2.objectId)] }),
      expected: 'deny',
    },
    {
      name: 'record allow for another permission',
      facts: facts(s1, {
        exceptions: [exception('allow', s1.objectId, { permission: 'submission.approve' })],
      }),
      expected: 'deny',
    },
    {
      name: 'null field never matches a grant',
      snapshot: { rules: [read(reviewer, 'allow', 'priorityBelow@1', { limit: '5' })] },
      facts: facts(s1),
      expected: 'deny',
    },
    {
      name: 'explicit null branch grants',
      snapshot: { rules: [read(reviewer, 'allow', 'untitled@1')] },
      facts: facts(submission('51000000-0000-4000-8000-000000000003', '3', { title: null })),
      expected: 'allow',
    },
    {
      name: 'exact decimal comparison',
      snapshot: { rules: [read(reviewer, 'allow', 'amountAtMost@1', { limit: '10.000' })] },
      facts: facts(submission('51000000-0000-4000-8000-000000000004', '4', { amount: '10.0001' })),
      expected: 'deny',
    },
    {
      name: 'decimal equal at different scale',
      snapshot: { rules: [read(reviewer, 'allow', 'amountAtMost@1', { limit: '10.000' })] },
      facts: facts(submission('51000000-0000-4000-8000-000000000005', '5', { amount: '10' })),
      expected: 'allow',
    },
    {
      name: 'string equality is exact (Unicode, quotes, case)',
      snapshot: { rules: [read(reviewer, 'allow', 'titleIs@1', { title: 'Ångström\'s "draft"' })] },
      facts: facts(
        submission('51000000-0000-4000-8000-000000000006', '6', { title: 'ångström\'s "draft"' }),
      ),
      expected: 'deny',
    },
    {
      name: 'string equality matches identical Unicode',
      snapshot: { rules: [read(reviewer, 'allow', 'titleIs@1', { title: 'Ångström\'s "draft"' })] },
      facts: facts(
        submission('51000000-0000-4000-8000-000000000007', '7', { title: 'Ångström\'s "draft"' }),
      ),
      expected: 'allow',
    },
    {
      name: 'plan expired before evaluation',
      snapshot: { rules: [read(reviewer, 'allow', 'all@1')] },
      facts: { ...facts(s1), now: '2026-10-13T10:00:05.000000Z' },
      expected: 'deny',
    },
  ];

  for (const c of cases) {
    test(c.name, () => {
      assert.equal(decide(input(c.input), snapshot(c.snapshot), c.facts), c.expected);
    });
  }
});

describe('fail closed', () => {
  test('a list decision is a predicate, not allow-all', () => {
    const decision = plan(
      input(),
      snapshot({ rules: [read(reviewer, 'allow', 'statusIs@1', { status: 'pending' })] }),
    );
    assert.equal(decision.effect, 'allow');
    assert.ok(decision.effect === 'allow' && decision.plan.predicate.op !== 'constant');
    assert.equal(decision.effect === 'allow' && evaluate(decision.plan, facts(s2)).effect, 'deny');
  });

  test('unknown resource, action, template, permission or rule parameter denies', () => {
    for (const [i, s] of [
      [input({ resource: 'invoice' }), snapshot()],
      [input({ action: 'export' }), snapshot()],
      [input(), snapshot({ rules: [read(reviewer, 'allow', 'nope@1')] })],
      [input(), snapshot({ rules: [read(reviewer, 'allow', 'statusIs@1', {})] })],
      [input(), snapshot({ rules: [read(reviewer, 'allow', 'statusIs@1', { status: true })] })],
      [input(), snapshot({ rules: [read(reviewer, 'allow', 'amountAtMost@1', { limit: '1e3' })] })],
      [input(), snapshot({ permissions: [] })],
    ] as const) {
      assert.equal(plan(i, s).effect, 'deny');
    }
  });

  test('a broken deny rule denies everything instead of being skipped', () => {
    const s = snapshot({
      rules: [read(reviewer, 'allow', 'all@1'), read(personal, 'deny', 'missing@1')],
    });
    assert.equal(plan(input(), s).effect, 'deny');
  });

  test('a deny rule comparing a nullable field without a null branch is rejected', () => {
    const s = snapshot({
      rules: [
        read(reviewer, 'allow', 'all@1'),
        read(personal, 'deny', 'priorityBelow@1', { limit: '3' }),
      ],
    });
    assert.equal(plan(input(), s).effect, 'deny');
  });

  test('declarations that were not validated are refused', () => {
    const s = snapshot({ declarations: { ...validated() } });
    assert.equal(plan(input(), s).effect, 'deny');
  });

  test('rule count above the manifest limit denies instead of truncating', () => {
    const decl = validated(declarations({ limits: { maxRules: 2 } }));
    const rules = [
      read(reviewer, 'allow', 'all@1'),
      read(reviewer, 'allow', 'all@1'),
      read(personal, 'deny', 'all@1'),
    ];
    assert.equal(plan(input(), snapshot({ declarations: decl, rules })).effect, 'deny');
  });

  test('integer facts given as JS numbers are rejected', () => {
    const decision = plan(
      input(),
      snapshot({ rules: [read(reviewer, 'allow', 'priorityBelow@1', { limit: '5' })] }),
    );
    assert.equal(decision.effect, 'allow');
    const record = submission('51000000-0000-4000-8000-000000000008', '8', {
      priority: 1 as unknown as string,
    });
    assert.equal(
      decision.effect === 'allow' && evaluate(decision.plan, facts(record)).effect,
      'deny',
    );
  });

  test('inputs are not mutated and plans are frozen', () => {
    const s = snapshot({ rules: [read(reviewer, 'allow', 'all@1')] });
    const before = JSON.stringify(s.rules);
    const decision = plan(input(), s);
    assert.equal(JSON.stringify(s.rules), before);
    assert.ok(
      decision.effect === 'allow' &&
        Object.isFrozen(decision.plan) &&
        Object.isFrozen(decision.plan.predicate),
    );
  });
});

describe('properties (seeded)', () => {
  // Small deterministic PRNG: no property-testing dependency needed for this invariant.
  function prng(seed: number) {
    return () => {
      seed = (seed + 0x6d2b79f5) | 0;
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  const templates: [string, Record<string, string>][] = [
    ['all@1', {}],
    ['statusIs@1', { status: 'pending' }],
    ['statusIs@1', { status: 'approved' }],
    ['amountAtMost@1', { limit: '50.5' }],
    ['untitled@1', {}],
  ];
  const subjects = [reviewer, personal, { kind: 'role', role: 'manager' } as const];

  test('adding a deny never enlarges the allowed set', () => {
    const random = prng(20261013);

    const pick = <T>(items: readonly T[]): T => items[Math.floor(random() * items.length)]!;

    for (let round = 0; round < 300; round++) {
      const rules = Array.from({ length: 1 + Math.floor(random() * 4) }, () => {
        const [template, parameters] = pick(templates);
        return read(pick(subjects), random() < 0.3 ? 'deny' : 'allow', template, parameters);
      });
      const record = submission('52000000-0000-4000-8000-000000000001', String(round), {
        status: pick(['pending', 'approved']),
        amount: pick(['10', '50.50', '50.51', '99']),
        title: pick([null, 'x']),
      });
      const exceptions =
        random() < 0.3 ? [exception(random() < 0.5 ? 'allow' : 'deny', record.objectId)] : [];
      const base = decide(input(), snapshot({ rules }), facts(record, { exceptions }));
      const [template, parameters] = pick(templates);
      const withDeny = decide(
        input(),
        snapshot({ rules: [...rules, read(pick(subjects), 'deny', template, parameters)] }),
        facts(record, { exceptions }),
      );
      if (base === 'deny') assert.equal(withDeny, 'deny', `round ${round}`);
    }
  });
});
