// Permission boundary (ADR 0003, docs/permission-boundaries.md). Three application fixtures —
// role assignment, amount approval, regional export — share one core; names are fixture data.
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  type AuthoritySnapshot,
  type BoundaryBindingFact,
  evaluate,
  type ExceptionFact,
  type Expr,
  type FactObject,
  type PermissionBoundary,
  plan,
  type RuleFact,
  type SystemDeclarations,
  type TrustedInput,
  validate,
  type ValidatedDeclarations,
} from '@base-authorization/core';
import { alice, bob, later, now, tenantA, tenantB } from './fixtures.ts';

const lit = (value: string) => ({ from: 'literal', value }) as const;
const anyOf = (field: string, values: string[]): Expr => ({
  op: 'or',
  args: values.map((value) => ({ op: 'eq', field, value: lit(value) })),
});
const baseline = { key: 'baseline', version: 1 };
const everything: Expr = { op: 'constant', value: true };
const template = (key: string, resource: string, expression: Expr, parameters = {}) => ({
  key,
  version: 1,
  resource,
  parameters,
  expression,
});

const assignOperationalRoles: PermissionBoundary = {
  key: 'assignOperationalRoles',
  version: 1,
  entries: [
    {
      permission: 'applicationRole.assign',
      contextRequirements: [],
      requiredScope: anyOf('roleKey', ['reviewer', 'editor']),
    },
  ],
};
const approvalAmount = (
  version: number,
  limit: string,
  assurance?: string,
): PermissionBoundary => ({
  key: 'approvalAmount',
  version,
  entries: [
    {
      permission: 'contract.approve',
      contextRequirements: assurance
        ? [{ validator: 'minimumAssurance@1', parameters: { minimum: assurance } }]
        : [],
      requiredScope: {
        op: 'and',
        args: [
          { op: 'eq', field: 'currency', value: lit('VND') },
          { op: 'lt', field: 'amount', value: lit(limit) },
        ],
      },
    },
  ],
});
const regionalExport: PermissionBoundary = {
  key: 'regionalExport',
  version: 1,
  entries: [
    {
      permission: 'customer.export',
      contextRequirements: [],
      requiredScope: anyOf('region', ['north', 'central']),
    },
  ],
};

function source(overrides: Partial<SystemDeclarations> = {}): SystemDeclarations {
  return {
    resources: [
      {
        key: 'applicationRole',
        keyKind: 'string',
        fields: { roleKey: { kind: 'string' } },
        actions: { assign: { policy: baseline, boundary: 'required' } },
      },
      {
        key: 'contract',
        keyKind: 'integer',
        fields: {
          amount: { kind: 'decimal' },
          currency: { kind: 'string' },
          status: { kind: 'string' },
        },
        actions: {
          approve: { policy: { key: 'contractApproval', version: 1 }, boundary: 'required' },
        },
      },
      {
        key: 'customer',
        keyKind: 'uuid',
        fields: { region: { kind: 'string' } },
        actions: { export: { policy: baseline, boundary: 'optional' } },
      },
    ],
    relations: [],
    policies: [
      { ...baseline, contextRequirements: [], requiredScope: everything, obligations: [] },
      {
        key: 'contractApproval',
        version: 1,
        contextRequirements: [{ validator: 'minimumAssurance@1', parameters: { minimum: '2' } }],
        requiredScope: { op: 'eq', field: 'status', value: lit('pending') },
        obligations: [],
      },
    ],
    templates: [
      template('allRoles', 'applicationRole', everything),
      template(
        'roleIs',
        'applicationRole',
        { op: 'eq', field: 'roleKey', value: { from: 'parameter', name: 'role' } },
        { role: 'string' },
      ),
      template('allContracts', 'contract', everything),
      template(
        'contractsBelow',
        'contract',
        { op: 'lt', field: 'amount', value: { from: 'parameter', name: 'limit' } },
        { limit: 'decimal' },
      ),
      template('allCustomers', 'customer', everything),
      template(
        'regionIs',
        'customer',
        { op: 'eq', field: 'region', value: { from: 'parameter', name: 'region' } },
        { region: 'string' },
      ),
    ],
    boundaries: [
      assignOperationalRoles,
      approvalAmount(1, '100000000'),
      approvalAmount(2, '50000000', '3'),
      regionalExport,
    ],
    capabilities: { validators: ['minimumAssurance@1'], obligationHandlers: [] },
    ...overrides,
  };
}

function validated(declarations = source()): ValidatedDeclarations {
  const result = validate(declarations);
  if (!result.ok) throw new Error(result.errors.join('; '));
  return result.declarations;
}
const declarations = validated();

const permission = (key: string, policy = baseline, boundary: 'required' | 'optional' | null) => {
  const [resource = '', action = ''] = key.split('.');
  return { key, resource, action, policy, boundary, lifecycle: 'active' as const };
};
const permissions = [
  permission('applicationRole.assign', baseline, 'required'),
  permission('contract.approve', { key: 'contractApproval', version: 1 }, 'required'),
  permission('customer.export', baseline, 'optional'),
];

function snapshot(overrides: Partial<AuthoritySnapshot> = {}): AuthoritySnapshot {
  return {
    tenant: tenantA,
    revision: '3',
    declarations,
    membership: { identity: alice, state: 'active' },
    roles: ['admin'],
    permissions,
    rules: [],
    boundaries: [],
    registry: {
      validators: {
        'minimumAssurance@1': (parameters, context) =>
          context.principal.assurance >= Number(parameters.minimum ?? Number.POSITIVE_INFINITY),
      },
      obligationHandlers: [],
    },
    ...overrides,
  };
}
const binding = (
  permission: string,
  key: string,
  version = 1,
  extra: Partial<BoundaryBindingFact> = {},
): BoundaryBindingFact => ({
  identity: alice,
  permission,
  boundary: { key, version },
  lifecycle: 'active',
  ...extra,
});
let ruleId = 0;
const rule = (
  permission: string,
  templateKey: string,
  effect: 'allow' | 'deny' = 'allow',
  subject: RuleFact['subject'] = { kind: 'role', role: 'admin' },
  parameters: RuleFact['parameters'] = {},
): RuleFact => ({
  id: `b${++ruleId}`,
  permission,
  subject,
  effect,
  template: { key: templateKey, version: 1 },
  parameters,
});
const input = (resource: string, action: string, extra: Partial<TrustedInput> = {}) => ({
  tenant: tenantA,
  principal: { id: alice, assurance: 2 },
  resource,
  action,
  context: {},
  now,
  validUntil: later,
  ...extra,
});
let objectSeq = 0;
const object = (type: string, key: FactObject['key'], fields: FactObject['fields']) => ({
  type,
  key,
  objectId: `5b000000-0000-4000-8000-${String(++objectSeq).padStart(12, '0')}`,
  fields,
});
const role = (roleKey: string) =>
  object('applicationRole', { kind: 'string', value: roleKey }, { roleKey });
const contract = (amount: string, currency = 'VND', status = 'pending') =>
  object(
    'contract',
    { kind: 'integer', value: String(objectSeq + 1) },
    {
      amount,
      currency,
      status,
    },
  );
const customer = (region: string) =>
  object(
    'customer',
    { kind: 'uuid', value: `5c000000-0000-4000-8000-${String(objectSeq + 1).padStart(12, '0')}` },
    { region },
  );
const recordException = (
  record: FactObject,
  permission: string,
  effect: 'allow' | 'deny' = 'allow',
): ExceptionFact => ({
  tenant: tenantA,
  objectId: record.objectId,
  permission,
  subject: { kind: 'identity', identity: alice },
  effect,
  purpose: 'manual',
  startsAt: '2026-10-01T00:00:00.000000Z',
  expiresAt: null,
  revokedAt: null,
});

/** Plan with authority facts, then decide one record with complete facts. */
function decide(
  request: TrustedInput,
  facts: AuthoritySnapshot,
  record: FactObject,
  exceptions: ExceptionFact[] = [],
): 'allow' | 'deny' {
  const decision = plan(request, facts);
  if (decision.effect === 'deny') return 'deny';
  return evaluate(decision.plan, {
    tenant: tenantA,
    now,
    record,
    objects: [record],
    edges: [],
    exceptions,
  }).effect;
}
const planReason = (request: TrustedInput, facts: AuthoritySnapshot) => {
  const decision = plan(request, facts);
  return decision.effect === 'deny' ? decision.internalReason : 'allow';
};

const assign = input('applicationRole', 'assign');
const approve = input('contract', 'approve');
const exportCustomers = input('customer', 'export');

describe('permission boundary declarations', () => {
  const errorsOf = (declarations: SystemDeclarations) => {
    const result = validate(declarations);
    return result.ok ? [] : result.errors;
  };
  const withEntry = (entry: Record<string, unknown>) =>
    source({
      boundaries: [{ key: 'probe', version: 1, entries: [entry as never] }],
    });

  test('every action declares its boundary requirement explicitly', () => {
    for (const boundary of [undefined, 'sometimes', true]) {
      const base = source();
      const declarations = source({
        resources: base.resources.map((r) =>
          r.key === 'customer'
            ? { ...r, actions: { export: { policy: baseline, boundary: boundary as never } } }
            : r,
        ),
      });
      assert.match(
        errorsOf(declarations).join('\n'),
        /action export needs an explicit boundary requirement/,
      );
    }
    const { boundaries, ...withoutList } = source();
    void boundaries;
    assert.notDeepEqual(errorsOf(withoutList as SystemDeclarations), []);
  });

  test('entries are typed AST on a declared permission; no parameters, no SQL, no duplicates', () => {
    const entry = (permission: string, requiredScope: unknown, contextRequirements = []) => ({
      permission,
      contextRequirements,
      requiredScope,
    });
    for (const bad of [
      withEntry(entry('customer.delete', everything)),
      withEntry(entry('customer', everything)),
      withEntry(entry('ghost.export', everything)),
      withEntry(entry('customer.export', { op: 'eq', field: 'missing', value: lit('x') })),
      withEntry(
        entry('customer.export', {
          op: 'eq',
          field: 'region',
          value: { from: 'parameter', name: 'r' },
        }),
      ),
      withEntry(entry('customer.export', { op: 'sql', sql: 'region IS NOT NULL' })),
      withEntry(entry('customer.export', { op: 'not', arg: everything })),
      withEntry(
        entry('customer.export', everything, [
          { validator: 'unregistered@1', parameters: {} },
        ] as never),
      ),
      source({ boundaries: [{ key: 'empty', version: 1, entries: [] }] }),
      source({
        boundaries: [
          {
            key: 'twice',
            version: 1,
            entries: [regionalExport.entries[0]!, regionalExport.entries[0]!],
          },
        ],
      }),
      source({ boundaries: [regionalExport, regionalExport] }),
      source({ boundaries: [{ ...regionalExport, version: 0 }] }),
    ]) {
      assert.notDeepEqual(errorsOf(bad), [], JSON.stringify(bad.boundaries));
    }
  });

  test('canonical form covers boundaries and ignores declaration order', () => {
    const reordered = source({
      boundaries: [...source().boundaries].reverse().map((b) => ({
        ...b,
        entries: [...b.entries].reverse(),
      })),
    });
    assert.equal(validated(reordered).canonical, declarations.canonical);
    const changed = source({
      boundaries: [assignOperationalRoles, approvalAmount(1, '100000001'), regionalExport],
    });
    assert.notEqual(validated(changed).canonical, declarations.canonical);
  });
});

describe('permission boundary decisions', () => {
  const [owner, reviewer, editor] = [role('owner'), role('reviewer'), role('editor')];

  test('role assignment: grant inside the boundary allows, outside denies; rank is not a bypass', () => {
    const facts = snapshot({
      rules: [rule('applicationRole.assign', 'allRoles')],
      boundaries: [binding('applicationRole.assign', 'assignOperationalRoles')],
    });
    assert.equal(decide(assign, facts, reviewer), 'allow');
    assert.equal(decide(assign, facts, editor), 'allow');
    assert.equal(decide(assign, facts, owner), 'deny');
  });

  test('a boundary never grants: boundary without assign denies', () => {
    const facts = snapshot({
      boundaries: [binding('applicationRole.assign', 'assignOperationalRoles')],
    });
    assert.equal(decide(assign, facts, reviewer), 'deny');
  });

  test('explicit deny still wins inside the boundary', () => {
    const facts = snapshot({
      rules: [
        rule('applicationRole.assign', 'allRoles'),
        rule(
          'applicationRole.assign',
          'roleIs',
          'deny',
          { kind: 'identity', identity: alice },
          {
            role: 'reviewer',
          },
        ),
      ],
      boundaries: [binding('applicationRole.assign', 'assignOperationalRoles')],
    });
    assert.equal(decide(assign, facts, reviewer), 'deny');
    assert.equal(decide(assign, facts, editor), 'allow');
  });

  test('amount approval: a record allow cannot pass the boundary or the policy', () => {
    const facts = snapshot({
      boundaries: [binding('contract.approve', 'approvalAmount')],
    });
    const above = contract('100000000');
    const below = contract('99999999.9999');
    const foreignCurrency = contract('10', 'USD');
    const approved = contract('10', 'VND', 'approved');
    for (const record of [above, foreignCurrency, approved]) {
      assert.equal(
        decide(approve, facts, record, [recordException(record, 'contract.approve')]),
        'deny',
      );
    }
    assert.equal(
      decide(approve, facts, below, [recordException(below, 'contract.approve')]),
      'allow',
      'record allow outside any grant scope still works inside the boundary',
    );
    assert.equal(decide(approve, facts, below), 'deny', 'no grant, no record allow');
  });

  test('adding grants from several roles and direct rules does not widen the boundary', () => {
    const facts = snapshot({
      roles: ['admin', 'head', 'director'],
      rules: [
        rule(
          'contract.approve',
          'contractsBelow',
          'allow',
          { kind: 'role', role: 'admin' },
          {
            limit: '1000',
          },
        ),
        rule('contract.approve', 'allContracts', 'allow', { kind: 'role', role: 'head' }),
        rule('contract.approve', 'allContracts', 'allow', { kind: 'role', role: 'director' }),
        rule('contract.approve', 'allContracts', 'allow', { kind: 'identity', identity: alice }),
      ],
      boundaries: [binding('contract.approve', 'approvalAmount')],
    });
    assert.equal(decide(approve, facts, contract('100000000')), 'deny');
    assert.equal(decide(approve, facts, contract('500000000')), 'deny');
    assert.equal(decide(approve, facts, contract('99999999')), 'allow');
  });

  test('required: missing binding denies the plan; bindings of other identities do not count', () => {
    const rules = [rule('applicationRole.assign', 'allRoles')];
    assert.equal(planReason(assign, snapshot({ rules })), 'boundary_binding_missing');
    const others = [
      binding('applicationRole.assign', 'assignOperationalRoles', 1, { identity: bob }),
    ];
    assert.equal(
      planReason(assign, snapshot({ rules, boundaries: others })),
      'boundary_binding_missing',
    );
  });

  test('optional: no binding leaves grants alone; a binding is still enforced', () => {
    const rules = [rule('customer.export', 'allCustomers')];
    const south = customer('south');
    const north = customer('north');
    assert.equal(decide(exportCustomers, snapshot({ rules }), south), 'allow');
    const bound = snapshot({ rules, boundaries: [binding('customer.export', 'regionalExport')] });
    assert.equal(decide(exportCustomers, bound, north), 'allow');
    assert.equal(decide(exportCustomers, bound, south), 'deny');
    assert.equal(
      decide(exportCustomers, bound, south, [recordException(south, 'customer.export')]),
      'deny',
      'record allow cannot pass an optional boundary that is bound',
    );
  });

  test('missing or invalid boundary facts fail closed', () => {
    const rules = [rule('contract.approve', 'allContracts')];
    const cases: [string, Partial<AuthoritySnapshot>, string][] = [
      [
        'unknown version',
        { boundaries: [binding('contract.approve', 'approvalAmount', 9)] },
        'boundary_definition_missing',
      ],
      [
        'unknown boundary',
        { boundaries: [binding('contract.approve', 'ghost')] },
        'boundary_definition_missing',
      ],
      [
        'definition without an entry for this permission',
        { boundaries: [binding('contract.approve', 'regionalExport')] },
        'boundary_entry_missing',
      ],
      [
        'retired definition',
        {
          boundaries: [binding('contract.approve', 'approvalAmount', 1, { lifecycle: 'retired' })],
        },
        'boundary_unavailable',
      ],
      [
        'unknown lifecycle',
        {
          boundaries: [
            binding('contract.approve', 'approvalAmount', 1, { lifecycle: 'paused' as never }),
          ],
        },
        'boundary_unavailable',
      ],
      [
        'two bindings for one permission',
        {
          boundaries: [
            binding('contract.approve', 'approvalAmount', 1),
            binding('contract.approve', 'approvalAmount', 2),
          ],
        },
        'ambiguous_boundary_binding',
      ],
      [
        'catalog requirement not backfilled',
        {
          permissions: permissions.map((p) =>
            p.key === 'contract.approve' ? { ...p, boundary: null } : p,
          ),
          boundaries: [binding('contract.approve', 'approvalAmount')],
        },
        'boundary_requirement_mismatch',
      ],
      [
        'catalog requirement differs from code',
        {
          permissions: permissions.map((p) =>
            p.key === 'contract.approve' ? { ...p, boundary: 'optional' as const } : p,
          ),
        },
        'boundary_requirement_mismatch',
      ],
    ];
    for (const [name, overrides, reason] of cases) {
      assert.equal(planReason(approve, snapshot({ rules, ...overrides })), reason, name);
    }
    const retiredInCode = validated(
      source({
        boundaries: [
          assignOperationalRoles,
          { ...approvalAmount(1, '100000000'), lifecycle: 'retired' },
          regionalExport,
        ],
      }),
    );
    assert.equal(
      planReason(
        approve,
        snapshot({
          declarations: retiredInCode,
          rules,
          boundaries: [binding('contract.approve', 'approvalAmount')],
        }),
      ),
      'boundary_unavailable',
    );
  });

  test('boundary context requirements use trusted facts; an exact version is enforced', () => {
    const facts = snapshot({
      rules: [rule('contract.approve', 'allContracts')],
      boundaries: [binding('contract.approve', 'approvalAmount', 2)],
    });
    assert.equal(planReason(approve, facts), 'context_requirement_failed');
    const strong = input('contract', 'approve', { principal: { id: alice, assurance: 3 } });
    assert.equal(decide(strong, facts, contract('49999999')), 'allow');
    assert.equal(decide(strong, facts, contract('50000000')), 'deny', 'v2 limit, not v1');
  });

  test('client-supplied context cannot fake boundary facts', () => {
    const facts = snapshot({
      rules: [rule('contract.approve', 'allContracts')],
      boundaries: [binding('contract.approve', 'approvalAmount')],
    });
    const forged = input('contract', 'approve', {
      context: { amount: '1', currency: 'VND', boundary: 'none', roleKey: 'reviewer' },
    });
    assert.equal(decide(forged, facts, contract('200000000')), 'deny');
  });

  test('another tenant is denied whatever the boundary', () => {
    const facts = snapshot({
      rules: [rule('customer.export', 'allCustomers')],
      boundaries: [binding('customer.export', 'regionalExport')],
    });
    assert.equal(decide({ ...exportCustomers, tenant: tenantB }, facts, customer('north')), 'deny');
  });

  test('property (seeded): a bound boundary never enlarges the allowed set', () => {
    let seed = 20261013;
    const random = () => {
      seed = (seed + 0x6d2b79f5) | 0;
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    const pick = <T>(items: readonly T[]): T => items[Math.floor(random() * items.length)]!;
    const subjects: RuleFact['subject'][] = [
      { kind: 'role', role: 'admin' },
      { kind: 'role', role: 'other' },
      { kind: 'identity', identity: alice },
      { kind: 'identity', identity: bob },
    ];
    for (let round = 0; round < 300; round++) {
      const rules = Array.from({ length: 1 + Math.floor(random() * 4) }, () =>
        random() < 0.5
          ? rule(
              'customer.export',
              'allCustomers',
              random() < 0.2 ? 'deny' : 'allow',
              pick(subjects),
            )
          : rule('customer.export', 'regionIs', random() < 0.2 ? 'deny' : 'allow', pick(subjects), {
              region: pick(['north', 'south', 'central', 'west']),
            }),
      );
      const record = customer(pick(['north', 'south', 'central', 'west']));
      const exceptions =
        random() < 0.4
          ? [recordException(record, 'customer.export', random() < 0.7 ? 'allow' : 'deny')]
          : [];
      const open = decide(exportCustomers, snapshot({ rules }), record, exceptions);
      const bound = decide(
        exportCustomers,
        snapshot({ rules, boundaries: [binding('customer.export', 'regionalExport')] }),
        record,
        exceptions,
      );
      if (open === 'deny') assert.equal(bound, 'deny', `round ${round}`);
      if (bound === 'allow')
        assert.ok(['north', 'central'].includes(String(record.fields.region)), `round ${round}`);
    }
  });
});
