// Permission boundary end to end on PostgreSQL 18 (ADR 0003): sync → authority snapshot → plan →
// SQL, runtime binding writes under the exclusive fence, revocation and sync rules. Three
// application fixtures (role assignment, amount approval, regional export) use one core.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { after, before, describe, test } from 'node:test';
import { setTimeout as sleep } from 'node:timers/promises';
import {
  type AuthorizedPlan,
  canonicalTimestamp,
  evaluate,
  type ExceptionFact,
  type Expr,
  type FactObject,
  type IdentityId,
  parseKey,
  parseTenantId,
  type PermissionBoundary,
  plan,
  type SystemDeclarations,
  type TenantId,
  validate,
} from '@base-authorization/core';
import {
  AuthorityUnavailableError,
  BindingRegistry,
  type ConnectionPurpose,
  DataGateway,
  directoryRouteResolver,
  identityDataSourceOptions,
  ManifestReconciler,
  PostgresAuthority,
  prepareRelease,
  ReleaseRejectedError,
  type ReleaseSource,
  RUNTIME_CAPABILITY,
  type StorageBindings,
  TenantDataSourceRegistry,
  tenantDatabaseName,
  TenantProvisioner,
  tenantRoleName,
  type TenantTransaction,
  TenantTransactionRunner,
  writeBoundaryBinding,
} from '@base-authorization/typeorm-postgres';
import type pg from 'pg';
import { DataSource } from 'typeorm';
import {
  type Connection,
  openClient,
  sqlState,
  startPostgres,
  type TestPostgres,
  withClient,
} from './setup-postgres.ts';

const tenantA = parseTenantId('00000000-0000-4000-8000-0000000000a9');
const tenantB = parseTenantId('00000000-0000-4000-8000-0000000000b9');
const deployer = 'd0000000-0000-4000-8000-00000000000d' as IdentityId;
const operator = 'f0000000-0000-4000-8000-00000000000f' as IdentityId;
const alice = 'a0000000-0000-4000-8000-000000000001' as IdentityId;
const bob = 'b0000000-0000-4000-8000-000000000002' as IdentityId;
const carol = 'c0000000-0000-4000-8000-000000000003' as IdentityId;
const dave = 'd0000000-0000-4000-8000-000000000004' as IdentityId;
const outsider = 'e0000000-0000-4000-8000-000000000005' as IdentityId;
const bytes = (value: string) => Buffer.from(value, 'utf8');

// ---- Declarations: application configuration only; the core knows none of these names ----

const lit = (value: string) => ({ from: 'literal', value }) as const;
const anyOf = (field: string, values: string[]): Expr => ({
  op: 'or',
  args: values.map((value) => ({ op: 'eq', field, value: lit(value) })),
});
const everything: Expr = { op: 'constant', value: true };
const baseline = { key: 'baseline', version: 1 };
const entry = (permission: string, requiredScope: Expr) => ({
  permission,
  contextRequirements: [],
  requiredScope,
});
const operationalRoles = (version: number, roles: string[]): PermissionBoundary => ({
  key: 'assignOperationalRoles',
  version,
  entries: [entry('applicationRole.assign', anyOf('roleKey', roles))],
});
const approvalAmount = (version: number, limit: string): PermissionBoundary => ({
  key: 'approvalAmount',
  version,
  entries: [
    entry('contract.approve', {
      op: 'and',
      args: [
        { op: 'eq', field: 'currency', value: lit('VND') },
        { op: 'lt', field: 'amount', value: lit(limit) },
      ],
    }),
  ],
});
const regionalExport: PermissionBoundary = {
  key: 'regionalExport',
  version: 1,
  entries: [entry('customer.export', anyOf('region', ['north', 'central']))],
};
const template = (key: string, resource: string) => ({
  key,
  version: 1,
  resource,
  parameters: {},
  expression: everything,
});

function declarations(boundaries: PermissionBoundary[]): SystemDeclarations {
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
      template('allRoles', 'applicationRole'),
      template('allContracts', 'contract'),
      template('allCustomers', 'customer'),
    ],
    boundaries,
    capabilities: { validators: ['minimumAssurance@1'], obligationHandlers: [] },
  };
}
const v1Boundaries = [
  operationalRoles(1, ['reviewer', 'editor']),
  approvalAmount(1, '100000000'),
  regionalExport,
];
const v2Boundaries = [
  ...v1Boundaries,
  operationalRoles(2, ['reviewer', 'editor', 'auditor']),
  approvalAmount(2, '50000000'),
];

function release(
  sequence: string,
  predecessor: string,
  changes: Partial<ReleaseSource> = {},
): ReleaseSource {
  return {
    sequence,
    predecessor,
    declarations: declarations(v1Boundaries),
    roles: [{ key: 'admin', authorityLevel: 100, label: 'Administrator' }],
    defaultGrants: [
      ['applicationRole.assign', 'allRoles'],
      ['contract.approve', 'allContracts'],
      ['customer.export', 'allCustomers'],
    ].map(([permission, key]) => ({
      permission: permission!,
      role: 'admin',
      template: { key: key!, version: 1 },
      parameters: {},
    })),
    seeds: [],
    removeSeeds: [],
    boundaryBindings: [
      {
        owner: 'access-module',
        identity: carol,
        permission: 'applicationRole.assign',
        boundary: { key: 'assignOperationalRoles', version: 1 },
      },
    ],
    removeBoundaryBindings: [],
    ...changes,
  };
}

const storageBindings: StorageBindings = {
  resources: [
    {
      resource: 'applicationRole',
      table: 'application_role',
      tenantColumn: 'tenant_id',
      objectIdColumn: 'object_id',
      keyColumn: 'code',
      columns: { roleKey: 'role_key' },
      projection: ['roleKey'],
    },
    {
      resource: 'contract',
      table: 'contract',
      tenantColumn: 'tenant_id',
      objectIdColumn: 'object_id',
      keyColumn: 'id',
      columns: { amount: 'amount', currency: 'currency', status: 'status' },
      projection: ['amount', 'currency', 'status'],
    },
    {
      resource: 'customer',
      table: 'customer',
      tenantColumn: 'tenant_id',
      objectIdColumn: 'object_id',
      keyColumn: 'id',
      columns: { region: 'region' },
      projection: ['region'],
    },
  ],
  domains: {},
};

// ---- Business rows (single source for PostgreSQL and evaluator facts) ----

let objectSeq = 0;
const objectId = () => `5d000000-0000-4000-8000-${String(++objectSeq).padStart(12, '0')}`;
const rows: Record<string, FactObject[]> = {
  applicationRole: ['owner', 'reviewer', 'editor'].map((roleKey) => ({
    type: 'applicationRole',
    key: { kind: 'string', value: roleKey },
    objectId: objectId(),
    fields: { roleKey },
  })),
  contract: (
    [
      ['1', '99999999.9999', 'VND', 'pending'],
      ['2', '100000000', 'VND', 'pending'],
      ['3', '10', 'USD', 'pending'],
      ['4', '10', 'VND', 'approved'],
      ['5', '500', 'VND', 'pending'],
    ] as const
  ).map(([id, amount, currency, status]) => ({
    type: 'contract',
    key: { kind: 'integer', value: id },
    objectId: objectId(),
    fields: { amount, currency, status },
  })),
  customer: ['north', 'central', 'south', 'west'].map((region, i) => ({
    type: 'customer',
    key: { kind: 'uuid', value: `5e000000-0000-4000-8000-00000000000${i + 1}` },
    objectId: objectId(),
    fields: { region },
  })),
};
const row = (resource: string, key: string) => rows[resource]!.find((r) => r.key.value === key)!;
const exceptions: ExceptionFact[] = [
  [alice, row('contract', '5'), 'contract.approve', 'deny'],
  [dave, row('contract', '1'), 'contract.approve', 'allow'],
  [dave, row('contract', '2'), 'contract.approve', 'allow'],
  [dave, row('customer', '5e000000-0000-4000-8000-000000000003'), 'customer.export', 'allow'],
].map(([identity, record, permission, effect]) => ({
  tenant: tenantA,
  objectId: (record as FactObject).objectId,
  permission: permission as string,
  subject: { kind: 'identity', identity: identity as IdentityId },
  effect: effect as 'allow' | 'deny',
  purpose: 'manual',
  startsAt: '2020-01-01T00:00:00.000000Z',
  expiresAt: null,
  revokedAt: null,
}));

const domainDdl = (dataRole: string) => `
  CREATE TABLE application_role (
    tenant_id uuid NOT NULL REFERENCES tenant_anchor (tenant_id),
    code text PRIMARY KEY, object_id uuid NOT NULL, role_key text NOT NULL,
    UNIQUE (tenant_id, object_id), FOREIGN KEY (tenant_id, object_id) REFERENCES object_ref (tenant_id, object_id)
  );
  CREATE TABLE contract (
    tenant_id uuid NOT NULL REFERENCES tenant_anchor (tenant_id),
    id bigint PRIMARY KEY, object_id uuid NOT NULL, amount numeric(20, 4) NOT NULL,
    currency text NOT NULL, status text NOT NULL,
    UNIQUE (tenant_id, object_id), FOREIGN KEY (tenant_id, object_id) REFERENCES object_ref (tenant_id, object_id)
  );
  CREATE TABLE customer (
    tenant_id uuid NOT NULL REFERENCES tenant_anchor (tenant_id),
    id uuid PRIMARY KEY, object_id uuid NOT NULL, region text NOT NULL,
    UNIQUE (tenant_id, object_id), FOREIGN KEY (tenant_id, object_id) REFERENCES object_ref (tenant_id, object_id)
  );
  GRANT SELECT ON application_role, contract, customer TO ${dataRole};
`;

describe('permission boundary on PostgreSQL', () => {
  let postgres: TestPostgres;
  let registry: TenantDataSourceRegistry;
  let identity: DataSource;
  let runner: TenantTransactionRunner;
  let reconciler: ManifestReconciler;
  let authority: PostgresAuthority;
  let gateway: DataGateway;
  let admin: pg.Client;
  let monitor: pg.Client;
  const validated = validate(declarations(v2Boundaries));
  if (!validated.ok) throw new Error(validated.errors.join('; '));
  const runtimeDeclarations = validated.declarations;
  const passwords = new Map<string, string>();
  const password = (tenant: TenantId, purpose: ConnectionPurpose) => {
    const key = `${tenant}/${purpose}`;
    if (!passwords.has(key)) passwords.set(key, randomBytes(24).toString('base64url'));
    return passwords.get(key)!;
  };
  const as = (purpose: ConnectionPurpose): Connection => ({
    ...postgres.admin,
    username: tenantRoleName(tenantA, purpose),
    password: password(tenantA, purpose),
    database: tenantDatabaseName(tenantA),
  });
  const fence = async () =>
    (
      await admin.query<{ revision: string; sequence: string; capability: number }>(
        `SELECT revision::text AS revision, release_sequence::text AS sequence,
                min_runtime_capability AS capability FROM authz_fence`,
      )
    ).rows[0]!;
  const count = async (sql: string, params: unknown[] = []) =>
    Number(
      (await admin.query<{ n: string }>(`SELECT count(*)::text AS n FROM ${sql}`, params)).rows[0]!
        .n,
    );
  const rejected = async (attempt: () => Promise<unknown>, reason: string) => {
    const before = await fence();
    await assert.rejects(
      attempt(),
      (error: unknown) => error instanceof ReleaseRejectedError && error.reason === reason,
    );
    assert.deepEqual(await fence(), before, 'rejected release changes nothing');
  };
  const bind = (member: IdentityId, permission: string, boundary: string | null, version = 1) =>
    runner.run(tenantA, 'admin', (tx) =>
      writeBoundaryBinding(tx, {
        actor: operator,
        identity: member,
        permission,
        boundary: boundary === null ? null : { key: boundary, version },
      }),
    );
  const bindingOf = async (member: IdentityId, permission: string) =>
    (
      await admin.query<{ boundary: string; owner: string | null }>(
        `SELECT convert_from(boundary_key, 'UTF8') || '@' || boundary_version AS boundary,
                convert_from(seed_owner, 'UTF8') AS owner
         FROM member_permission_boundary WHERE identity_id = $1 AND permission_key = $2`,
        [member, bytes(permission)],
      )
    ).rows[0];

  /** One authorization in one fenced transaction; every read path returns the same key set. */
  const visible = (
    member: IdentityId,
    resource: string,
    action: string,
    hold?: { acquired: () => void; gate: Promise<void> },
  ) =>
    authority.withSnapshot({ id: member, assurance: 2 }, tenantA, 'read', async (snapshot, tx) => {
      const now = new Date();
      const decision = plan(
        {
          tenant: tenantA,
          principal: { id: member, assurance: 2 },
          resource,
          action,
          context: {},
          now: now.toISOString(),
          validUntil: new Date(now.getTime() + 60_000).toISOString(),
        },
        snapshot,
      );
      if (hold) {
        hold.acquired();
        await hold.gate;
      }
      if (decision.effect === 'deny')
        return { keys: [] as string[], reason: decision.internalReason };
      const keys = await readPaths(decision.plan, tx);
      return { keys, reason: 'allow', plan: decision.plan };
    });
  async function readPaths(authorized: AuthorizedPlan, tx: TenantTransaction): Promise<string[]> {
    const listed: string[] = [];
    for (let offset = 0; ; offset += 2) {
      const page = await gateway.list(authorized, { limit: 2, offset }, tx);
      listed.push(...page.items.map((item) => String(item.key)));
      if (page.items.length < 2) break;
    }
    const kind = runtimeDeclarations.resources[authorized.resource]!.keyKind;
    const detailed: string[] = [];
    for (const record of rows[authorized.resource]!) {
      const found = await gateway.detail(authorized, parseKey(kind, record.key.value), tx);
      if (found) detailed.push(record.key.value);
    }
    const counted = await gateway.count(authorized, {}, tx);
    assert.deepEqual([...listed].sort(), [...detailed].sort(), 'list and detail agree');
    assert.equal(counted, String(listed.length), 'count agrees');
    return listed.sort();
  }
  const evaluatorKeys = (authorized: AuthorizedPlan) => {
    const now = canonicalTimestamp(new Date().toISOString())!;
    return rows[authorized.resource]!.filter(
      (record) =>
        evaluate(authorized, {
          tenant: tenantA,
          now,
          record,
          objects: [record],
          edges: [],
          exceptions,
        }).effect === 'allow',
    )
      .map((record) => record.key.value)
      .sort();
  };

  before(async () => {
    postgres = await startPostgres();
    const provisioner = new TenantProvisioner(postgres.admin, {
      identityDatabase: 'authz_identity',
    });
    await provisioner.provisionIdentity();
    for (const tenant of [tenantA, tenantB]) {
      await provisioner.provision({
        tenantId: tenant,
        displayLabel: 'Boundary fixture',
        passwords: {
          data: password(tenant, 'data'),
          authority: password(tenant, 'authority'),
          sync: password(tenant, 'sync'),
        },
      });
    }
    identity = await new DataSource(
      identityDataSourceOptions({ ...postgres.admin, database: 'authz_identity' }),
    ).initialize();
    registry = new TenantDataSourceRegistry({
      host: postgres.admin.host,
      port: postgres.admin.port,
      poolSize: { data: 3, authority: 2, sync: 2 },
      maxConnections: 14,
      idleTimeoutMs: 60_000,
      resolveRoute: directoryRouteResolver(identity, (tenant, purpose) =>
        Promise.resolve({ password: password(tenant, purpose), credentialVersion: 'v1' }),
      ),
    });
    runner = new TenantTransactionRunner(registry, { deadlineMs: 10_000, lockTimeoutMs: 5_000 });
    reconciler = new ManifestReconciler(runner, {
      actor: deployer,
      capabilities: { validators: ['minimumAssurance@1'], obligationHandlers: [] },
    });
    authority = new PostgresAuthority(runner, runtimeDeclarations, {
      validators: {
        'minimumAssurance@1': (parameters, context) =>
          context.principal.assurance >= Number(parameters.minimum ?? Number.POSITIVE_INFINITY),
      },
      obligationHandlers: [],
    });
    gateway = new DataGateway(new BindingRegistry(runtimeDeclarations, storageBindings));
    admin = await openClient({ ...postgres.admin, database: tenantDatabaseName(tenantA) });
    monitor = await openClient(postgres.superuser);
    for (const member of [alice, bob, carol, dave]) {
      await admin.query(
        `INSERT INTO membership (tenant_id, identity_id, state) VALUES ($1, $2, 'active')`,
        [tenantA, member],
      );
    }
  });
  after(async () => {
    await admin?.end();
    await monitor?.end();
    await registry?.close();
    await identity?.destroy();
    await postgres?.stop();
  });

  test('first sync publishes definitions, entries, requirements and code-owned bindings', async () => {
    const result = await reconciler.reconcile(tenantA, prepareRelease(release('1', '0')));
    assert.equal(result.changed, true);
    assert.deepEqual(await fence(), {
      revision: '2',
      sequence: '1',
      capability: RUNTIME_CAPABILITY,
    });
    assert.equal(await count('permission_boundary'), 3);
    assert.equal(await count('permission_boundary_entry'), 3);
    const requirements = await admin.query<{ p: string; r: string }>(
      `SELECT convert_from(permission_key, 'UTF8') AS p, boundary_requirement AS r
       FROM permission_catalog ORDER BY 1`,
    );
    assert.deepEqual(requirements.rows, [
      { p: 'applicationRole.assign', r: 'required' },
      { p: 'contract.approve', r: 'required' },
      { p: 'customer.export', r: 'optional' },
    ]);
    assert.deepEqual(await bindingOf(carol, 'applicationRole.assign'), {
      boundary: 'assignOperationalRoles@1',
      owner: 'access-module',
    });

    // Business rows, roles and exceptions referenced by the scenarios below.
    await admin.query(domainDdl(tenantRoleName(tenantA, 'data')));
    const tables = {
      applicationRole: 'application_role',
      contract: 'contract',
      customer: 'customer',
    };
    for (const [resource, records] of Object.entries(rows)) {
      for (const record of records) {
        await admin.query('INSERT INTO object_ref VALUES ($1, $2, $3, $4, $5)', [
          tenantA,
          record.objectId,
          bytes(resource),
          record.key.kind,
          bytes(record.key.value),
        ]);
        const values = Object.values(record.fields);
        await admin.query(
          `INSERT INTO ${tables[resource as keyof typeof tables]} VALUES ($1, $2, $3${values.map((_, i) => `, $${i + 4}`).join('')})`,
          [tenantA, record.key.value, record.objectId, ...values],
        );
      }
    }
    for (const member of [alice, bob, carol]) {
      await admin.query('INSERT INTO member_role VALUES ($1, $2, $3)', [
        tenantA,
        member,
        bytes('admin'),
      ]);
    }
    for (const x of exceptions) {
      await admin.query(
        `INSERT INTO record_exception (tenant_id, exception_id, object_id, type_key, permission_key, identity_id,
           effect, purpose, starts_at, reason, issued_by)
         SELECT $1, gen_random_uuid(), $2, type_key, $3, $4, $5, 'manual', $6, 'fixture', $7
         FROM object_ref WHERE object_id = $2`,
        [
          tenantA,
          x.objectId,
          bytes(x.permission),
          x.subject.kind === 'identity' ? x.subject.identity : null,
          x.effect,
          x.startsAt,
          alice,
        ],
      );
    }
  });

  test('runtime binding writes need the exclusive fence, are audited and never touch code-owned rows', async () => {
    const before = await fence();
    await bind(alice, 'applicationRole.assign', 'assignOperationalRoles');
    await bind(alice, 'contract.approve', 'approvalAmount');
    await bind(alice, 'customer.export', 'regionalExport');
    await bind(dave, 'contract.approve', 'approvalAmount');
    await bind(dave, 'customer.export', 'regionalExport');
    assert.equal(BigInt((await fence()).revision), BigInt(before.revision) + 5n);
    const audit = await admin.query<{ r: string; m: Record<string, unknown> }>(
      `SELECT policy_revision::text AS r, safe_metadata AS m FROM audit_outbox
       WHERE event_kind = $1 ORDER BY policy_revision DESC LIMIT 1`,
      [bytes('boundary.binding')],
    );
    assert.equal(await count('audit_outbox WHERE event_kind = $1', [bytes('boundary.binding')]), 5);
    assert.equal(audit.rows[0]!.r, (await fence()).revision, 'audit carries the new revision');
    assert.deepEqual(audit.rows[0]!.m, {
      identity: dave,
      boundary: 'regionalExport',
      version: 1,
    });

    const unchanged = await fence();
    await assert.rejects(
      runner.run(tenantA, 'write', (tx) =>
        writeBoundaryBinding(tx, {
          actor: operator,
          identity: bob,
          permission: 'customer.export',
          boundary: { key: 'regionalExport', version: 1 },
        }),
      ),
      /exclusive fence/,
    );
    await assert.rejects(
      runner.run(tenantA, 'admin', (tx) =>
        writeBoundaryBinding(tx, {
          actor: alice,
          identity: alice,
          permission: 'customer.export',
          boundary: null,
        }),
      ),
      /own permission boundary/,
    );
    await assert.rejects(bind(carol, 'applicationRole.assign', null), /code-owned/);
    await assert.rejects(
      bind(bob, 'contract.approve', 'regionalExport'),
      (error: unknown) =>
        (error as { driverError?: { code?: string } }).driverError?.code === '23503',
      'a binding must point at an entry of the same permission',
    );
    await assert.rejects(bind(outsider, 'customer.export', 'regionalExport'), /23503|foreign key/);
    assert.deepEqual(await fence(), unchanged, 'refused writes change nothing');
    assert.deepEqual(await bindingOf(carol, 'applicationRole.assign'), {
      boundary: 'assignOperationalRoles@1',
      owner: 'access-module',
    });
  });

  const scenarios: [string, IdentityId, string, string, string[] | 'deny'][] = [
    ['assign: grant + boundary', alice, 'applicationRole', 'assign', ['editor', 'reviewer']],
    ['assign: grant, required, no binding', bob, 'applicationRole', 'assign', 'deny'],
    [
      'assign: grant + code-owned binding',
      carol,
      'applicationRole',
      'assign',
      ['editor', 'reviewer'],
    ],
    ['assign: no grant, no binding', dave, 'applicationRole', 'assign', 'deny'],
    ['approve: grant + boundary, record deny wins', alice, 'contract', 'approve', ['1']],
    ['approve: grant, required, no binding', bob, 'contract', 'approve', 'deny'],
    ['approve: record allows only inside the boundary', dave, 'contract', 'approve', ['1']],
    [
      'export: grant + optional boundary bound',
      alice,
      'customer',
      'export',
      ['5e000000-0000-4000-8000-000000000001', '5e000000-0000-4000-8000-000000000002'],
    ],
    [
      'export: grant, optional, unbound',
      bob,
      'customer',
      'export',
      [
        '5e000000-0000-4000-8000-000000000001',
        '5e000000-0000-4000-8000-000000000002',
        '5e000000-0000-4000-8000-000000000003',
        '5e000000-0000-4000-8000-000000000004',
      ],
    ],
    ['export: record allow outside the boundary', dave, 'customer', 'export', []],
  ];
  for (const [name, member, resource, action, expected] of scenarios) {
    test(`three applications, one core — ${name}`, async () => {
      const result = await visible(member, resource, action);
      if (expected === 'deny') {
        assert.equal(result.reason, 'boundary_binding_missing');
        return;
      }
      assert.equal(result.reason, 'allow');
      assert.deepEqual(result.keys, evaluatorKeys(result.plan!), 'SQL matches the evaluator');
      assert.deepEqual(result.keys, expected);
    });
  }

  test('composite foreign keys keep tenant, membership and permission aligned', async () => {
    const insertBinding = (tenant: string, member: string, permission: string, boundary: string) =>
      admin.query(
        `INSERT INTO member_permission_boundary (tenant_id, identity_id, permission_key, boundary_key, boundary_version)
         VALUES ($1, $2, $3, $4, 1)`,
        [tenant, member, bytes(permission), bytes(boundary)],
      );
    assert.equal(
      await sqlState(insertBinding(tenantA, bob, 'contract.approve', 'regionalExport')),
      '23503',
    );
    assert.equal(
      await sqlState(insertBinding(tenantA, outsider, 'customer.export', 'regionalExport')),
      '23503',
    );
    assert.equal(
      await sqlState(insertBinding(tenantB, bob, 'customer.export', 'regionalExport')),
      '23503',
    );
    assert.equal(
      await sqlState(
        admin.query(`INSERT INTO permission_boundary_entry VALUES ($1, $2, 1, $3, '{}')`, [
          tenantA,
          bytes('regionalExport'),
          bytes('customer.delete'),
        ]),
      ),
      '23503',
    );
    assert.equal(
      await sqlState(
        admin.query(`INSERT INTO permission_boundary VALUES ($1, $2, 0, $3, '{}', 'active')`, [
          tenantA,
          bytes('zero'),
          Buffer.alloc(32),
        ]),
      ),
      '23514',
    );
    for (const requirement of [null, 'sometimes']) {
      assert.equal(
        await sqlState(
          admin.query(
            `INSERT INTO permission_catalog VALUES ($1, $2, $3, $4, $5, 1, 'active', $6)`,
            [
              tenantA,
              bytes('customer.audit'),
              bytes('customer'),
              bytes('audit'),
              bytes('baseline'),
              requirement,
            ],
          ),
        ),
        '23514',
      );
    }
  });

  test('credentials follow the boundary privilege matrix', async () => {
    await withClient(as('data'), async (c) => {
      await c.query('SELECT * FROM member_permission_boundary');
      await c.query('SELECT * FROM permission_boundary_entry');
      for (const statement of [
        `DELETE FROM member_permission_boundary`,
        `UPDATE member_permission_boundary SET boundary_version = 1`,
        `UPDATE permission_boundary SET lifecycle = 'retired'`,
        `UPDATE permission_catalog SET boundary_requirement = 'optional'`,
      ]) {
        assert.equal(await sqlState(c.query(statement)), '42501', statement);
      }
    });
    await withClient(as('authority'), async (c) => {
      for (const statement of [
        `INSERT INTO member_permission_boundary VALUES ('${tenantA}', '${bob}', '\\x00', '\\x00', 1, '\\x61')`,
        `UPDATE member_permission_boundary SET seed_owner = NULL`,
        `UPDATE permission_boundary SET lifecycle = 'retired'`,
        `UPDATE permission_catalog SET boundary_requirement = 'optional'`,
        `UPDATE authz_fence SET min_runtime_capability = 0`,
      ]) {
        assert.equal(await sqlState(c.query(statement)), '42501', statement);
      }
    });
    await withClient(as('sync'), async (c) => {
      for (const statement of [
        `UPDATE permission_boundary SET definition = '{}'`,
        `UPDATE permission_boundary_entry SET definition = '{}'`,
        'DELETE FROM permission_boundary',
        `UPDATE member_permission_boundary SET seed_owner = NULL`,
      ]) {
        assert.equal(await sqlState(c.query(statement)), '42501', statement);
      }
    });
  });

  /** A binding change waits for an in-flight reader, which keeps its snapshot; later reads see it. */
  async function assertFenced(
    member: IdentityId,
    resource: string,
    action: string,
    change: () => Promise<unknown>,
  ) {
    const before = await visible(member, resource, action);
    let acquired!: () => void;
    let open!: () => void;
    const ready = new Promise<void>((resolve) => (acquired = resolve));
    const gate = new Promise<void>((resolve) => (open = resolve));
    const inFlight = visible(member, resource, action, { acquired, gate });
    await ready;
    const revisionBefore = (await fence()).revision;
    let committed = false;
    const pending = change().then(() => (committed = true));
    let waited = false;
    for (let i = 0; i < 50 && !waited; i++) {
      const r = await monitor.query(
        `SELECT 1 FROM pg_stat_activity WHERE usename = $1 AND wait_event_type = 'Lock'`,
        [tenantRoleName(tenantA, 'authority')],
      );
      waited = (r.rowCount ?? 0) > 0;
      if (!waited) await sleep(20);
    }
    assert.ok(waited, 'binding change waits for the shared fence');
    assert.equal(committed, false);
    open();
    assert.deepEqual((await inFlight).keys, before.keys, 'admitted request keeps its snapshot');
    await pending;
    assert.equal(BigInt((await fence()).revision), BigInt(revisionBefore) + 1n);
    return { before, after: await visible(member, resource, action) };
  }

  test('narrowing a binding: requests after commit see the narrower version', async () => {
    // Release 2 publishes new definition versions; nobody's binding moves with it.
    await reconciler.reconcile(
      tenantA,
      prepareRelease(release('2', '1', { declarations: declarations(v2Boundaries) })),
    );
    assert.deepEqual(await bindingOf(alice, 'contract.approve'), {
      boundary: 'approvalAmount@1',
      owner: null,
    });
    const { before, after } = await assertFenced(alice, 'contract', 'approve', () =>
      bind(alice, 'contract.approve', 'approvalAmount', 2),
    );
    assert.deepEqual(before.keys, ['1']);
    assert.equal(after.reason, 'allow');
    assert.deepEqual(after.keys, [], 'contract 1 is above the v2 limit');
  });

  test('removing the binding of a required permission denies requests after commit', async () => {
    const { before, after } = await assertFenced(alice, 'applicationRole', 'assign', () =>
      bind(alice, 'applicationRole.assign', null),
    );
    assert.deepEqual(before.keys, ['editor', 'reviewer']);
    assert.equal(after.reason, 'boundary_binding_missing');
  });

  test('legacy catalog rows without a requirement deny until a release backfills them', async () => {
    // Simulates rows that predate migration 003 (the NOT VALID check only exempts old rows).
    await admin.query('ALTER TABLE permission_catalog DROP CONSTRAINT ck_boundary_requirement_set');
    await admin.query('UPDATE permission_catalog SET boundary_requirement = NULL');
    await admin.query(
      'ALTER TABLE permission_catalog ADD CONSTRAINT ck_boundary_requirement_set CHECK (boundary_requirement IS NOT NULL) NOT VALID',
    );
    assert.equal(
      (await visible(bob, 'customer', 'export')).reason,
      'boundary_requirement_mismatch',
    );
    const current = prepareRelease(release('2', '1', { declarations: declarations(v2Boundaries) }));
    await rejected(() => reconciler.reconcile(tenantA, current), 'not_ready');
    await reconciler.reconcile(
      tenantA,
      prepareRelease(release('3', '2', { declarations: declarations(v2Boundaries) })),
    );
    assert.equal(await count('permission_catalog WHERE boundary_requirement IS NULL'), 0);
    assert.equal((await visible(bob, 'customer', 'export')).keys.length, 4);
  });

  describe('boundary sync', () => {
    const v2 = (sequence: string, predecessor: string, changes: Partial<ReleaseSource> = {}) =>
      prepareRelease(
        release(sequence, predecessor, { declarations: declarations(v2Boundaries), ...changes }),
      );
    const carolSeed = (version: number, owner = 'access-module') => ({
      owner,
      identity: carol,
      permission: 'applicationRole.assign',
      boundary: { key: 'assignOperationalRoles', version },
    });

    test('a published definition version is immutable', async () => {
      const changed = [
        ...v2Boundaries.filter((b) => b.key !== 'approvalAmount' || b.version !== 1),
        approvalAmount(1, '100000001'),
      ];
      await rejected(
        () =>
          reconciler.reconcile(
            tenantA,
            prepareRelease(release('4', '3', { declarations: declarations(changed) })),
          ),
        'immutable_definition',
      );
    });

    test('a release moves code-owned bindings only; runtime bindings keep their version', async () => {
      await bind(bob, 'applicationRole.assign', 'assignOperationalRoles', 1);
      await reconciler.reconcile(tenantA, v2('4', '3', { boundaryBindings: [carolSeed(2)] }));
      assert.deepEqual(await bindingOf(carol, 'applicationRole.assign'), {
        boundary: 'assignOperationalRoles@2',
        owner: 'access-module',
      });
      assert.deepEqual(await bindingOf(bob, 'applicationRole.assign'), {
        boundary: 'assignOperationalRoles@1',
        owner: null,
      });
      assert.deepEqual(await bindingOf(dave, 'contract.approve'), {
        boundary: 'approvalAmount@1',
        owner: null,
      });
    });

    test('a definition still bound cannot be retired or dropped', async () => {
      const retired = v2Boundaries.map((b) =>
        b.key === 'approvalAmount' && b.version === 1 ? { ...b, lifecycle: 'retired' as const } : b,
      );
      const dropped = v2Boundaries.filter((b) => !(b.key === 'approvalAmount' && b.version === 1));
      for (const boundaries of [retired, dropped]) {
        await rejected(
          () =>
            reconciler.reconcile(
              tenantA,
              prepareRelease(
                release('5', '4', {
                  declarations: declarations(boundaries),
                  boundaryBindings: [carolSeed(2)],
                }),
              ),
            ),
          'definition_in_use',
        );
      }
    });

    test('binding seeds never take over runtime bindings or bind non-members', async () => {
      const bobSeed = { ...carolSeed(2), identity: bob };
      await rejected(
        () =>
          reconciler.reconcile(
            tenantA,
            v2('5', '4', { boundaryBindings: [carolSeed(2), bobSeed] }),
          ),
        'collision',
      );
      const outsiderSeed = { ...carolSeed(2), identity: outsider };
      await rejected(
        () =>
          reconciler.reconcile(
            tenantA,
            v2('5', '4', { boundaryBindings: [carolSeed(2), outsiderSeed] }),
          ),
        'missing_reference',
      );
    });

    test('a missing code-owned binding fails readiness even when the hash matches', async () => {
      const current = v2('4', '3', { boundaryBindings: [carolSeed(2)] });
      await admin.query('DELETE FROM member_permission_boundary WHERE identity_id = $1', [carol]);
      await rejected(() => reconciler.reconcile(tenantA, current), 'not_ready');
      await admin.query(`INSERT INTO member_permission_boundary VALUES ($1, $2, $3, $4, 2, $5)`, [
        tenantA,
        carol,
        bytes('applicationRole.assign'),
        bytes('assignOperationalRoles'),
        bytes('access-module'),
      ]);
      assert.equal((await reconciler.reconcile(tenantA, current)).changed, false);
    });

    test('binding seeds are removed only by an explicit removal of the same owner', async () => {
      await reconciler.reconcile(tenantA, v2('5', '4', { boundaryBindings: [] }));
      assert.ok(await bindingOf(carol, 'applicationRole.assign'), 'omitted seed is kept');
      const removal = (owner: string) => ({
        boundaryBindings: [],
        removeBoundaryBindings: [{ owner, identity: carol, permission: 'applicationRole.assign' }],
      });
      await reconciler.reconcile(tenantA, v2('6', '5', removal('other-module')));
      assert.ok(await bindingOf(carol, 'applicationRole.assign'), 'another owner cannot remove it');
      await reconciler.reconcile(tenantA, v2('7', '6', removal('access-module')));
      assert.equal(await bindingOf(carol, 'applicationRole.assign'), undefined);
    });

    test('invalid binding seeds are refused before any lock', () => {
      for (const seed of [
        { ...carolSeed(9) },
        { ...carolSeed(1), boundary: { key: 'regionalExport', version: 1 } },
        { ...carolSeed(1), permission: 'applicationRole.delete' },
        { ...carolSeed(1), identity: 'not-a-uuid' as IdentityId },
        { ...carolSeed(1), owner: 'Bad Owner' },
      ]) {
        assert.throws(
          () => v2('8', '7', { boundaryBindings: [seed] }),
          (e: unknown) => e instanceof ReleaseRejectedError && e.reason === 'invalid_release',
          JSON.stringify(seed),
        );
      }
      assert.throws(
        () => v2('8', '7', { boundaryBindings: [carolSeed(1), carolSeed(2, 'second-owner')] }),
        (e: unknown) => e instanceof ReleaseRejectedError && e.reason === 'invalid_release',
      );
    });

    test('runtimes without the required capability are refused', async () => {
      await withClient(as('data'), async (c) => {
        // The exact statement of a runtime built before permission boundaries.
        assert.equal(
          await sqlState(c.query('SELECT public.authz_acquire_shared_fence($1)::text', [tenantA])),
          'AZ001',
        );
        await c.query('BEGIN');
        await c.query('SELECT public.authz_acquire_shared_fence($1, $2)', [
          tenantA,
          RUNTIME_CAPABILITY,
        ]);
        await c.query('ROLLBACK');
      });
      await admin.query('UPDATE authz_fence SET min_runtime_capability = $1', [
        RUNTIME_CAPABILITY + 1,
      ]);
      try {
        const incompatible = (error: unknown) =>
          error instanceof AuthorityUnavailableError && error.code === 'runtime_incompatible';
        await assert.rejects(visible(bob, 'customer', 'export'), incompatible);
        await assert.rejects(bind(bob, 'customer.export', 'regionalExport'), incompatible);
        await assert.rejects(reconciler.reconcile(tenantA, v2('8', '7')), incompatible);
      } finally {
        await admin.query('UPDATE authz_fence SET min_runtime_capability = $1', [
          RUNTIME_CAPABILITY,
        ]);
      }
      assert.equal((await visible(bob, 'customer', 'export')).keys.length, 4);
    });
  });
});
