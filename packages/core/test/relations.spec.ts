import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import {
  type CompleteFacts,
  type EdgeFact,
  type Expr,
  evaluate,
  type FactObject,
  plan,
  type RelationDeclaration,
  validate,
} from '@base-authorization/core';
import {
  alice,
  bob,
  declarations,
  facts,
  input,
  rule,
  snapshot,
  submission,
  tenantA,
  tenantB,
  validated,
} from './fixtures.ts';

const s1 = submission('54000000-0000-4000-8000-000000000001', '1');
const siteA: FactObject = {
  type: 'site',
  key: { kind: 'uuid', value: 'd97eecc9-8f23-4a76-a9aa-82b9d4ef33ac' },
  objectId: '54000000-0000-4000-8000-0000000000a1',
  fields: { name: 'Site A' },
};
const edge = (
  key: string,
  source: string,
  target: EdgeFact['target'],
  extra: Partial<EdgeFact> = {},
): EdgeFact => ({
  tenant: tenantA,
  relation: { key, version: 1 },
  source,
  target,
  startsAt: '2026-10-01T00:00:00.000000Z',
  expiresAt: null,
  ...extra,
});
const submissionSite = (extra: Partial<EdgeFact> = {}) =>
  edge('submission.site', s1.objectId, { kind: 'object', objectId: siteA.objectId }, extra);
const siteManager = (identity = alice, extra: Partial<EdgeFact> = {}) =>
  edge('site.manager', siteA.objectId, { kind: 'identity', identity }, extra);

function managedSite(f: CompleteFacts): 'allow' | 'deny' {
  const rules = [
    rule('submission.read', { kind: 'role', role: 'manager' }, 'allow', 'managedSite@1'),
  ];
  const decision = plan(input(), snapshot({ roles: ['manager'], rules }));
  assert.equal(decision.effect, 'allow');
  return decision.effect === 'allow' ? evaluate(decision.plan, f).effect : 'deny';
}
const graph = (edges: EdgeFact[]) => facts(s1, { objects: [s1, siteA], edges });

test('submission.site → site.manager grants the site manager only', () => {
  assert.equal(managedSite(graph([submissionSite(), siteManager()])), 'allow');
  assert.equal(managedSite(graph([submissionSite(), siteManager(bob)])), 'deny');
  assert.equal(managedSite(graph([siteManager()])), 'deny');
});

test('every edge checks tenant and validity window, including the middle step', () => {
  assert.equal(managedSite(graph([submissionSite({ tenant: tenantB }), siteManager()])), 'deny');
  assert.equal(
    managedSite(graph([submissionSite(), siteManager(alice, { tenant: tenantB })])),
    'deny',
  );
  assert.equal(
    managedSite(
      graph([submissionSite({ expiresAt: '2026-10-13T10:00:00.000000Z' }), siteManager()]),
    ),
    'deny',
  );
  assert.equal(
    managedSite(
      graph([submissionSite(), siteManager(alice, { startsAt: '2026-10-14T00:00:00.000000Z' })]),
    ),
    'deny',
  );
});

test('edges are directed: a reversed edge grants nothing', () => {
  const reversed = edge('submission.site', siteA.objectId, {
    kind: 'object',
    objectId: s1.objectId,
  });
  assert.equal(managedSite(graph([reversed, siteManager()])), 'deny');
});

test('relation type and direction are checked at validation', () => {
  const base = declarations();
  const withTemplate = (expression: Expr, resource = 'submission') =>
    validate(
      declarations({
        templates: [
          ...base.templates,
          { key: 'bad', version: 1, resource, parameters: {}, expression },
        ],
      }),
    );
  // site.manager starts at site, not submission.
  assert.equal(
    withTemplate({
      op: 'exists',
      relation: 'site.manager@1',
      where: { op: 'constant', value: true },
    }).ok,
    false,
  );
  // submission.site used from site (wrong direction).
  assert.equal(
    withTemplate(
      { op: 'exists', relation: 'submission.site@1', where: { op: 'constant', value: true } },
      'site',
    ).ok,
    false,
  );
  // Field of the wrong type in the target context.
  assert.equal(
    withTemplate({
      op: 'exists',
      relation: 'submission.site@1',
      where: { op: 'eq', field: 'status', value: { from: 'literal', value: 'x' } },
    }).ok,
    false,
  );
  // Unknown relation version.
  assert.equal(
    withTemplate({
      op: 'exists',
      relation: 'submission.site@2',
      where: { op: 'constant', value: true },
    }).ok,
    false,
  );
});

test('paths of 8 steps are accepted and 9 steps rejected', () => {
  const chain: RelationDeclaration = {
    key: 'submission.previous',
    version: 1,
    sourceType: 'submission',
    target: { kind: 'resource', type: 'submission' },
    binding: { kind: 'edgeStore' },
  };
  const path = (steps: number): Expr =>
    steps === 0
      ? { op: 'constant', value: true }
      : { op: 'exists', relation: 'submission.previous@1', where: path(steps - 1) };
  const base = declarations();
  const withDepth = (steps: number) =>
    validate(
      declarations({
        relations: [...base.relations, chain],
        templates: [
          ...base.templates,
          {
            key: 'chain',
            version: 1,
            resource: 'submission',
            parameters: {},
            expression: path(steps),
          },
        ],
      }),
    );
  assert.equal(withDepth(8).ok, true);
  assert.equal(withDepth(9).ok, false);
});

// Expr has no node that references another template/policy; this checks unsupported nodes only and
// does not claim cycle detection.
test('unsupported expression nodes (e.g. a template reference) are rejected', () => {
  const base = declarations();
  const result = validate(
    declarations({
      templates: [
        ...base.templates,
        {
          key: 'loopA',
          version: 1,
          resource: 'submission',
          parameters: {},
          expression: { op: 'ref', template: 'loopB@1' } as never,
        },
        {
          key: 'loopB',
          version: 1,
          resource: 'submission',
          parameters: {},
          expression: { op: 'ref', template: 'loopA@1' } as never,
        },
      ],
    }),
  );
  assert.equal(result.ok, false);
});

test('relations must reference declared types and be unique by key@version', () => {
  const base = declarations();
  const undeclared = validate(
    declarations({
      relations: [
        ...base.relations,
        {
          key: 'x',
          version: 1,
          sourceType: 'invoice',
          target: { kind: 'identity' },
          binding: { kind: 'edgeStore' },
        },
      ],
    }),
  );
  assert.equal(undeclared.ok, false);
  assert.equal(
    validate(declarations({ relations: [...base.relations, base.relations[0]!] })).ok,
    false,
  );
});

test('manifest canonical form and hash are independent of declaration order', () => {
  const base = declarations();
  const reordered = declarations({
    resources: [...base.resources].reverse(),
    relations: [...base.relations].reverse(),
    policies: [...base.policies].reverse(),
    templates: [...base.templates].reverse(),
    capabilities: {
      validators: [...base.capabilities.validators].reverse(),
      obligationHandlers: [...base.capabilities.obligationHandlers].reverse(),
    },
  });
  const hash = (d: ReturnType<typeof validated>) =>
    createHash('sha256').update(d.canonical).digest('hex');
  assert.equal(hash(validated(base)), hash(validated(reordered)));
  const changed = declarations({
    templates: base.templates.map((t) => (t.key === 'all' ? { ...t, version: 2 } : t)),
  });
  assert.notEqual(hash(validated(base)), hash(validated(changed)));
});
