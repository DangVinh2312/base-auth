// Synthetic declarations shared by core tests. Names are fixture data, not core concepts.
import {
  type AuthoritySnapshot,
  type CompleteFacts,
  createAuthorizationCore,
  type Expr,
  type FactObject,
  type IdentityId,
  type Key,
  type RuleFact,
  type SystemDeclarations,
  type TrustedInput,
  type ValidatedDeclarations,
} from '@base-authorization/core';
import {
  createDayjsTimestampCodec,
  createStandardValueCodecs,
} from '@base-authorization/value-adapters';

/** Test composition root: the standard codecs, as apps/api and tools compose them. */
export const core = createAuthorizationCore({
  values: createStandardValueCodecs({ timestamp: createDayjsTimestampCodec() }),
});

export const tenantA = core.parseTenantId('00000000-0000-4000-8000-00000000000a');
export const tenantB = core.parseTenantId('00000000-0000-4000-8000-00000000000b');
export const alice = 'a0000000-0000-4000-8000-000000000001' as IdentityId;
export const bob = 'b0000000-0000-4000-8000-000000000002' as IdentityId;
export const now = '2026-10-13T10:00:00.000000Z';
export const later = '2026-10-13T10:00:02.000000Z';

const principalId: Expr = {
  op: 'eq',
  field: 'identityId',
  value: { from: 'principal', name: 'id' },
};

export function declarations(overrides: Partial<SystemDeclarations> = {}): SystemDeclarations {
  return {
    resources: [
      {
        key: 'submission',
        keyKind: 'integer',
        fields: {
          status: { kind: 'string' },
          amount: { kind: 'decimal' },
          title: { kind: 'string', nullable: true },
          priority: { kind: 'integer', nullable: true },
        },
        actions: {
          read: { policy: { key: 'baseline', version: 1 }, boundary: 'optional' },
          approve: { policy: { key: 'approval', version: 1 }, boundary: 'optional' },
        },
      },
      {
        key: 'site',
        keyKind: 'uuid',
        fields: { name: { kind: 'string' } },
        actions: { read: { policy: { key: 'baseline', version: 1 }, boundary: 'optional' } },
      },
    ],
    relations: [
      {
        key: 'submission.site',
        version: 1,
        sourceType: 'submission',
        target: { kind: 'resource', type: 'site' },
        binding: { kind: 'edgeStore' },
      },
      {
        key: 'site.manager',
        version: 1,
        sourceType: 'site',
        target: { kind: 'identity' },
        binding: { kind: 'domain', key: 'siteManagers' },
      },
      {
        key: 'submission.assignee',
        version: 1,
        sourceType: 'submission',
        target: { kind: 'identity' },
        binding: { kind: 'edgeStore' },
      },
    ],
    policies: [
      {
        key: 'baseline',
        version: 1,
        contextRequirements: [],
        requiredScope: { op: 'constant', value: true },
        obligations: [],
      },
      {
        key: 'approval',
        version: 1,
        contextRequirements: [{ validator: 'minimumAssurance@1', parameters: { minimum: '2' } }],
        requiredScope: { op: 'eq', field: 'status', value: { from: 'literal', value: 'pending' } },
        obligations: [{ handler: 'auditBeforeCommit@1' }],
      },
    ],
    templates: [
      {
        key: 'all',
        version: 1,
        resource: 'submission',
        parameters: {},
        expression: { op: 'constant', value: true },
      },
      {
        key: 'assignedToMe',
        version: 1,
        resource: 'submission',
        parameters: {},
        expression: { op: 'exists', relation: 'submission.assignee@1', where: principalId },
      },
      {
        key: 'managedSite',
        version: 1,
        resource: 'submission',
        parameters: {},
        expression: {
          op: 'exists',
          relation: 'submission.site@1',
          where: { op: 'exists', relation: 'site.manager@1', where: principalId },
        },
      },
      {
        key: 'statusIs',
        version: 1,
        resource: 'submission',
        parameters: { status: 'string' },
        expression: { op: 'eq', field: 'status', value: { from: 'parameter', name: 'status' } },
      },
      {
        key: 'amountAtMost',
        version: 1,
        resource: 'submission',
        parameters: { limit: 'decimal' },
        expression: { op: 'lte', field: 'amount', value: { from: 'parameter', name: 'limit' } },
      },
      {
        key: 'priorityBelow',
        version: 1,
        resource: 'submission',
        parameters: { limit: 'integer' },
        expression: { op: 'lt', field: 'priority', value: { from: 'parameter', name: 'limit' } },
      },
      {
        key: 'titleIs',
        version: 1,
        resource: 'submission',
        parameters: { title: 'string' },
        expression: { op: 'eq', field: 'title', value: { from: 'parameter', name: 'title' } },
      },
      {
        key: 'untitled',
        version: 1,
        resource: 'submission',
        parameters: {},
        expression: { op: 'isNull', field: 'title' },
      },
    ],
    boundaries: [],
    capabilities: {
      validators: ['minimumAssurance@1'],
      obligationHandlers: ['auditBeforeCommit@1'],
    },
    ...overrides,
  };
}

export function validated(source: SystemDeclarations = declarations()): ValidatedDeclarations {
  const result = core.validate(source);
  if (!result.ok) throw new Error(`fixture declarations invalid: ${result.errors.join('; ')}`);
  return result.declarations;
}

let ruleCounter = 0;
export function rule(
  permission: string,
  subject: RuleFact['subject'],
  effect: RuleFact['effect'],
  template: string,
  parameters: RuleFact['parameters'] = {},
): RuleFact {
  const [key = '', version = '1'] = template.split('@');
  return {
    id: `rule-${++ruleCounter}`,
    permission,
    subject,
    effect,
    template: { key, version: Number(version) },
    parameters,
  };
}

export function snapshot(overrides: Partial<AuthoritySnapshot> = {}): AuthoritySnapshot {
  return {
    tenant: tenantA,
    revision: '7',
    declarations: validated(),
    membership: { identity: alice, state: 'active' },
    roles: ['reviewer'],
    permissions: [
      {
        key: 'submission.read',
        resource: 'submission',
        action: 'read',
        policy: { key: 'baseline', version: 1 },
        boundary: 'optional',
        lifecycle: 'active',
      },
      {
        key: 'submission.approve',
        resource: 'submission',
        action: 'approve',
        policy: { key: 'approval', version: 1 },
        boundary: 'optional',
        lifecycle: 'active',
      },
      {
        key: 'site.read',
        resource: 'site',
        action: 'read',
        policy: { key: 'baseline', version: 1 },
        boundary: 'optional',
        lifecycle: 'active',
      },
    ],
    rules: [],
    boundaries: [],
    registry: {
      validators: {
        'minimumAssurance@1': (parameters, context) =>
          context.principal.assurance >= Number(parameters.minimum ?? Number.POSITIVE_INFINITY),
      },
      obligationHandlers: ['auditBeforeCommit@1'],
    },
    ...overrides,
  };
}

export function input(overrides: Partial<TrustedInput> = {}): TrustedInput {
  return {
    tenant: tenantA,
    principal: { id: alice, assurance: 1 },
    resource: 'submission',
    action: 'read',
    context: {},
    now,
    validUntil: later,
    ...overrides,
  };
}

export const integerKey = (value: string): Key => ({ kind: 'integer', value });

export function submission(
  objectId: string,
  key: string,
  fields: Partial<FactObject['fields']> = {},
): FactObject {
  return {
    type: 'submission',
    key: integerKey(key),
    objectId,
    fields: { status: 'pending', amount: '10.00', title: 'Fixture', priority: null, ...fields },
  };
}

export function facts(record: FactObject, extra: Partial<CompleteFacts> = {}): CompleteFacts {
  return { tenant: tenantA, now, record, objects: [record], edges: [], exceptions: [], ...extra };
}
