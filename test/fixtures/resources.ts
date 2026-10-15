// D1-like fixture for compiler/gateway integration tests: three native PK types (bigint, uuid, text),
// edge-store and domain-table relations, record exceptions. Synthetic data only.
import { randomBytes } from 'node:crypto';
import type {
  AuthoritySnapshot,
  CompleteFacts,
  EdgeFact,
  ExceptionFact,
  Expr,
  FactObject,
  IdentityId,
  RuleFact,
  SystemDeclarations,
  TenantId,
  TrustedInput,
  ValidatedDeclarations,
} from '@base-authorization/core';
import {
  type ConnectionPurpose,
  directoryRouteResolver,
  identityDataSourceOptions,
  type StorageBindings,
  TenantDataSourceRegistry,
  tenantDatabaseName,
  TenantProvisioner,
  tenantRoleName,
} from '@base-authorization/typeorm-postgres/legacy';
import type pg from 'pg';
import { DataSource } from 'typeorm';
import {
  type Connection,
  startPostgres,
  type TestPostgres,
  withClient,
} from '../setup-postgres.ts';
import { core } from '../../packages/core/test/fixtures.ts';

export { core };
const { parseTenantId, plan, validate } = core;

export const tenantA = parseTenantId('00000000-0000-4000-8000-00000000000a');

export const tenantB = parseTenantId('00000000-0000-4000-8000-00000000000b');

export const alice = 'a0000000-0000-4000-8000-000000000001' as IdentityId;

export const bob = 'b0000000-0000-4000-8000-000000000002' as IdentityId;

/** Manages both sites: exercises many-to-many paths. */
export const carol = 'c0000000-0000-4000-8000-000000000003' as IdentityId;

const principalId: Expr = {
  op: 'eq',
  field: 'identityId',
  value: { from: 'principal', name: 'id' },
};

const template = (key: string, resource: string, expression: Expr, parameters = {}) => ({
  key,
  version: 1,
  resource,
  parameters,
  expression,
});

const baseline = { key: 'baseline', version: 1 };
/** Existing fixture actions stay unbounded: optional requirement, no bindings. */
const read = { policy: baseline, boundary: 'optional' } as const;

export const declarationsSource: SystemDeclarations = {
  resources: [
    {
      key: 'submission',
      keyKind: 'integer',
      fields: {
        status: { kind: 'string' },
        amount: { kind: 'decimal' },
        title: { kind: 'string', nullable: true },
        priority: { kind: 'integer', nullable: true },
        submittedAt: { kind: 'timestamp' },
        archived: { kind: 'boolean' },
      },
      actions: {
        read,
        approve: { policy: { key: 'approval', version: 1 }, boundary: 'optional' },
      },
    },
    {
      key: 'site',
      keyKind: 'uuid',
      fields: { name: { kind: 'string' } },
      actions: { read },
    },
    {
      key: 'tag',
      keyKind: 'string',
      fields: { label: { kind: 'string' } },
      actions: { read },
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
      contextRequirements: [],
      requiredScope: { op: 'eq', field: 'status', value: { from: 'literal', value: 'pending' } },
      obligations: [],
    },
  ],
  templates: [
    template('all', 'submission', { op: 'constant', value: true }),
    template('allSites', 'site', { op: 'constant', value: true }),
    template('allTags', 'tag', { op: 'constant', value: true }),
    template(
      'tagLabel',
      'tag',
      { op: 'eq', field: 'label', value: { from: 'parameter', name: 'label' } },
      { label: 'string' },
    ),
    template('assignedToMe', 'submission', {
      op: 'exists',
      relation: 'submission.assignee@1',
      where: principalId,
    }),
    template('managedSite', 'submission', {
      op: 'exists',
      relation: 'submission.site@1',
      where: { op: 'exists', relation: 'site.manager@1', where: principalId },
    }),
    template('mySites', 'site', { op: 'exists', relation: 'site.manager@1', where: principalId }),
    template(
      'statusIs',
      'submission',
      { op: 'eq', field: 'status', value: { from: 'parameter', name: 'status' } },
      { status: 'string' },
    ),
    template(
      'amountAtMost',
      'submission',
      { op: 'lte', field: 'amount', value: { from: 'parameter', name: 'limit' } },
      { limit: 'decimal' },
    ),
    template(
      'priorityBelow',
      'submission',
      { op: 'lt', field: 'priority', value: { from: 'parameter', name: 'limit' } },
      { limit: 'integer' },
    ),
    template(
      'titleIs',
      'submission',
      { op: 'eq', field: 'title', value: { from: 'parameter', name: 'title' } },
      { title: 'string' },
    ),
    template(
      'titleBefore',
      'submission',
      { op: 'lt', field: 'title', value: { from: 'parameter', name: 'title' } },
      { title: 'string' },
    ),
    template('untitled', 'submission', { op: 'isNull', field: 'title' }),
    template(
      'submittedBefore',
      'submission',
      { op: 'lt', field: 'submittedAt', value: { from: 'parameter', name: 'at' } },
      { at: 'timestamp' },
    ),
    template('notArchived', 'submission', {
      op: 'eq',
      field: 'archived',
      value: { from: 'literal', value: false },
    }),
    template('pendingOrCheap', 'submission', {
      op: 'or',
      args: [
        { op: 'eq', field: 'status', value: { from: 'literal', value: 'pending' } },
        { op: 'lte', field: 'amount', value: { from: 'literal', value: '0.5' } },
      ],
    }),
  ],
  boundaries: [],
  capabilities: { validators: [], obligationHandlers: [] },
};

export function fixtureDeclarations(): ValidatedDeclarations {
  const result = validate(declarationsSource);
  if (!result.ok) throw new Error(result.errors.join('; '));
  return result.declarations;
}

export const storageBindings: StorageBindings = {
  resources: [
    {
      resource: 'submission',
      table: 'submission',
      tenantColumn: 'tenant_id',
      objectIdColumn: 'object_id',
      keyColumn: 'id',
      columns: {
        status: 'status',
        amount: 'amount',
        title: 'title',
        priority: 'priority',
        submittedAt: 'submitted_at',
        archived: 'archived',
      },
      projection: ['status', 'amount', 'title', 'priority', 'submittedAt', 'archived'],
    },
    {
      resource: 'site',
      table: 'site',
      tenantColumn: 'tenant_id',
      objectIdColumn: 'object_id',
      keyColumn: 'id',
      columns: { name: 'name' },
      projection: ['name'],
    },
    {
      resource: 'tag',
      table: 'tag',
      tenantColumn: 'tenant_id',
      objectIdColumn: 'object_id',
      keyColumn: 'code',
      columns: { label: 'label' },
      projection: ['label'],
    },
  ],
  domains: {
    siteManagers: {
      table: 'site_manager',
      tenantColumn: 'tenant_id',
      sourceColumn: 'site_id',
      targetColumn: 'identity_id',
      startsColumn: 'starts_at',
      expiresColumn: 'expires_at',
    },
  },
};

// ---- Fixture data (single source for DB rows and evaluator facts) ----

const past = '2020-01-01T00:00:00.000000Z';
const expired = '2021-01-01T00:00:00.000000Z';
const future = '2099-01-01T00:00:00.000000Z';

interface SubmissionRow {
  id: string;
  objectId: string;
  status: string;
  amount: string;
  title: string | null;
  priority: string | null;
  submittedAt: string;
  archived: boolean;
  internalNote: string;
  sites: string[];
  assignees: { identity: IdentityId; startsAt: string; expiresAt: string | null }[];
}
interface SiteRow {
  id: string;
  objectId: string;
  name: string;
  managers: { identity: IdentityId; startsAt: string; expiresAt: string | null }[];
}
interface TagRow {
  code: string;
  objectId: string;
  label: string;
}

export interface TenantFixture {
  tenant: TenantId;
  sites: SiteRow[];
  submissions: SubmissionRow[];
  tags: TagRow[];
  exceptions: Omit<ExceptionFact, 'tenant'>[];
}

const objectId = (tenantDigit: string, n: number) =>
  `${tenantDigit}0000000-0000-4000-8000-${String(n).padStart(12, '0')}`;

export function tenantFixture(tenant: TenantId, digit: string, label: string): TenantFixture {
  const o = (n: number) => objectId(digit, n);

  const siteA = {
    id: 'd97eecc9-8f23-4a76-a9aa-82b9d4ef33ac',
    objectId: o(1),
    name: `${label} site A`,
    managers: [
      { identity: alice, startsAt: past, expiresAt: null },
      { identity: carol, startsAt: past, expiresAt: null },
    ],
  };
  const siteB = {
    id: '5e0c2f1e-3b7a-4c1d-9f0e-1a2b3c4d5e6f',
    objectId: o(2),
    name: `${label} site B`,
    managers: [
      { identity: bob, startsAt: past, expiresAt: null },
      { identity: alice, startsAt: past, expiresAt: expired },
      { identity: carol, startsAt: past, expiresAt: null },
    ],
  };

  const sub = (n: number, id: string, fields: Partial<SubmissionRow>): SubmissionRow => ({
    id,
    objectId: o(n),
    status: 'pending',
    amount: '1',
    title: `${label} #${id}`,
    priority: null,
    submittedAt: '2026-01-01T00:00:00.000000Z',
    archived: false,
    internalNote: `${label} internal ${id}`,
    sites: [],
    assignees: [],
    ...fields,
  });

  return {
    tenant,
    sites: [siteA, siteB],
    submissions: [
      sub(10, '1', {
        amount: '100.10',
        title: 'Alpha',
        priority: '1',
        sites: [siteA.id],
        assignees: [{ identity: alice, startsAt: past, expiresAt: null }],
      }),
      sub(11, '2', {
        status: 'approved',
        amount: '100.1000',
        title: 'Ångström',
        sites: [siteB.id],
      }),
      sub(12, '9007199254740993', {
        amount: '0.0001',
        title: 'O\'Reilly "quoted"',
        priority: '5',
        sites: [siteA.id, siteB.id],
        assignees: [{ identity: alice, startsAt: past, expiresAt: null }],
        submittedAt: '2025-06-01T12:00:00.123456Z',
      }),
      sub(13, '9007199254740992', {
        amount: '99999999.9999',
        title: null,
        priority: '2',
        archived: true,
      }),
      sub(14, '5', {
        status: 'rejected',
        amount: '-3.5',
        title: "'; DROP TABLE submission; --",
        priority: '3',
        sites: [siteA.id],
        assignees: [{ identity: bob, startsAt: past, expiresAt: null }],
      }),
      sub(15, '6', {
        amount: '100.10',
        title: 'Alpha',
        assignees: [{ identity: alice, startsAt: past, expiresAt: expired }],
      }),
      sub(16, '7', {
        title: 'ångström',
        assignees: [{ identity: alice, startsAt: future, expiresAt: null }],
        submittedAt: '2026-03-01T00:00:00.000000Z',
      }),
      sub(17, '8', { status: 'approved', amount: '0.5', title: 'Zeta', sites: [siteB.id] }),
    ],
    tags: [
      { code: 'α-tag', objectId: o(30), label: 'Greek' },
      { code: "x' OR '1'='1", objectId: o(31), label: 'Injection' },
      { code: 'plain', objectId: o(32), label: 'Plain' },
    ],
    exceptions: [
      exception(o(11), 'allow', { kind: 'identity', identity: alice }),
      exception(o(12), 'deny', { kind: 'identity', identity: alice }),
      exception(o(17), 'allow', { kind: 'role', role: 'reviewer' }),
      exception(o(13), 'allow', { kind: 'identity', identity: alice }, { expiresAt: expired }),
      exception(o(15), 'allow', { kind: 'identity', identity: alice }, { revokedAt: past }),
      exception(
        o(16),
        'allow',
        { kind: 'identity', identity: alice },
        { purpose: 'emergency', expiresAt: future },
      ),
      exception(
        o(14),
        'allow',
        { kind: 'identity', identity: alice },
        { permission: 'submission.approve' },
      ),
    ],
  };
}

function exception(
  objectId: string,
  effect: 'allow' | 'deny',
  subject: ExceptionFact['subject'],
  extra: Partial<ExceptionFact> = {},
): Omit<ExceptionFact, 'tenant'> {
  return {
    objectId,
    permission: 'submission.read',
    subject,
    effect,
    purpose: 'manual',
    startsAt: past,
    expiresAt: null,
    revokedAt: null,
    ...extra,
  };
}

/** Evaluator facts for one submission, built from the same data that is inserted into PostgreSQL. */
export function submissionFacts(
  fixture: TenantFixture,
  row: SubmissionRow,
  now: string,
): CompleteFacts {
  const record = submissionObject(row);
  const siteObjects = fixture.sites.map((s): FactObject => ({
    type: 'site',
    key: { kind: 'uuid', value: s.id },
    objectId: s.objectId,
    fields: { name: s.name },
  }));
  const edges: EdgeFact[] = [
    ...row.sites.map((siteId): EdgeFact => ({
      tenant: fixture.tenant,
      relation: { key: 'submission.site', version: 1 },
      source: row.objectId,
      target: { kind: 'object', objectId: fixture.sites.find((s) => s.id === siteId)!.objectId },
      startsAt: past,
      expiresAt: null,
    })),
    ...row.assignees.map((a): EdgeFact => ({
      tenant: fixture.tenant,
      relation: { key: 'submission.assignee', version: 1 },
      source: row.objectId,
      target: { kind: 'identity', identity: a.identity },
      startsAt: a.startsAt,
      expiresAt: a.expiresAt,
    })),
    ...fixture.sites.flatMap((s) =>
      s.managers.map((m): EdgeFact => ({
        tenant: fixture.tenant,
        relation: { key: 'site.manager', version: 1 },
        source: s.objectId,
        target: { kind: 'identity', identity: m.identity },
        startsAt: m.startsAt,
        expiresAt: m.expiresAt,
      })),
    ),
  ];
  return {
    tenant: fixture.tenant,
    now,
    record,
    objects: [record, ...siteObjects],
    edges,
    exceptions: fixture.exceptions.map((x) => ({ ...x, tenant: fixture.tenant })),
  };
}

export function submissionObject(row: SubmissionRow): FactObject {
  return {
    type: 'submission',
    key: { kind: 'integer', value: row.id },
    objectId: row.objectId,
    fields: {
      status: row.status,
      amount: row.amount,
      title: row.title,
      priority: row.priority,
      submittedAt: row.submittedAt,
      archived: row.archived,
    },
  };
}

// ---- Database setup ----

const bytes = (value: string) => Buffer.from(value, 'utf8');

const fixtureDdl = `
  CREATE TABLE site (
    tenant_id uuid NOT NULL REFERENCES tenant_anchor (tenant_id),
    id uuid PRIMARY KEY,
    object_id uuid NOT NULL,
    name text NOT NULL,
    UNIQUE (tenant_id, object_id),
    FOREIGN KEY (tenant_id, object_id) REFERENCES object_ref (tenant_id, object_id)
  );
  CREATE TABLE submission (
    tenant_id uuid NOT NULL REFERENCES tenant_anchor (tenant_id),
    id bigint PRIMARY KEY,
    object_id uuid NOT NULL,
    status text NOT NULL,
    amount numeric(20, 4) NOT NULL,
    title text,
    priority integer,
    submitted_at timestamptz(6) NOT NULL,
    archived boolean NOT NULL,
    internal_note text NOT NULL,
    UNIQUE (tenant_id, object_id),
    FOREIGN KEY (tenant_id, object_id) REFERENCES object_ref (tenant_id, object_id)
  );
  CREATE TABLE tag (
    tenant_id uuid NOT NULL REFERENCES tenant_anchor (tenant_id),
    code text PRIMARY KEY,
    object_id uuid NOT NULL,
    label text NOT NULL,
    UNIQUE (tenant_id, object_id),
    FOREIGN KEY (tenant_id, object_id) REFERENCES object_ref (tenant_id, object_id)
  );
  CREATE TABLE site_manager (
    tenant_id uuid NOT NULL REFERENCES tenant_anchor (tenant_id),
    site_id uuid NOT NULL REFERENCES site (id),
    identity_id uuid NOT NULL,
    starts_at timestamptz(6) NOT NULL,
    expires_at timestamptz(6),
    PRIMARY KEY (tenant_id, site_id, identity_id)
  );
  CREATE INDEX ix_site_manager_identity ON site_manager (tenant_id, identity_id);
`;

/** Creates fixture tables and rows (admin connection). `grants: false` for databases without tenant roles. */
export async function seedTenant(
  client: pg.Client,
  fixture: TenantFixture,
  { grants = true }: { grants?: boolean } = {},
): Promise<void> {
  const t = fixture.tenant;
  await client.query(fixtureDdl);
  for (const [type, kind] of [
    ['submission', 'integer'],
    ['site', 'uuid'],
    ['tag', 'string'],
  ] as const) {
    await client.query('INSERT INTO resource_type VALUES ($1, $2, $3, $2)', [t, bytes(type), kind]);
  }
  const hash = Buffer.alloc(32, 7);
  await client.query(
    `INSERT INTO permission_policy VALUES ($1, $2, 1, $3, '{}', 'active'), ($1, $4, 1, $3, '{}', 'active')`,
    [t, bytes('baseline'), hash, bytes('approval')],
  );
  for (const [permission, type, action, policy] of [
    ['submission.read', 'submission', 'read', 'baseline'],
    ['submission.approve', 'submission', 'approve', 'approval'],
    ['site.read', 'site', 'read', 'baseline'],
    ['tag.read', 'tag', 'read', 'baseline'],
  ] as const) {
    await client.query(
      `INSERT INTO permission_catalog VALUES ($1, $2, $3, $4, $5, 1, 'active', 'optional')`,
      [t, bytes(permission), bytes(type), bytes(action), bytes(policy)],
    );
  }
  for (const t2 of declarationsSource.templates) {
    await client.query('INSERT INTO scope_template VALUES ($1, $2, 1, $3)', [
      t,
      bytes(t2.key),
      hash,
    ]);
  }
  for (const role of ['reviewer', 'manager']) {
    await client.query(`INSERT INTO role_definition VALUES ($1, $2, 'code', 10, $3)`, [
      t,
      bytes(role),
      role,
    ]);
  }
  for (const identity of [alice, bob, carol]) {
    await client.query(
      `INSERT INTO membership (tenant_id, identity_id, state) VALUES ($1, $2, 'active')`,
      [t, identity],
    );
  }
  await client.query('INSERT INTO member_role VALUES ($1, $2, $3)', [t, alice, bytes('reviewer')]);
  await client.query(
    `INSERT INTO resource_relation_definition VALUES ($1, $2, 1, $3, $4, 'edgeStore', $2, $5, 'active')`,
    [t, bytes('submission.site'), bytes('submission'), bytes('site'), hash],
  );

  const objectRef = (id: string, type: string, kind: string, key: string) =>
    client.query('INSERT INTO object_ref VALUES ($1, $2, $3, $4, $5)', [
      t,
      id,
      bytes(type),
      kind,
      bytes(key),
    ]);

  for (const site of fixture.sites) {
    await objectRef(site.objectId, 'site', 'uuid', site.id);
    await client.query('INSERT INTO site VALUES ($1, $2, $3, $4)', [
      t,
      site.id,
      site.objectId,
      site.name,
    ]);
    for (const m of site.managers) {
      await client.query('INSERT INTO site_manager VALUES ($1, $2, $3, $4, $5)', [
        t,
        site.id,
        m.identity,
        m.startsAt,
        m.expiresAt,
      ]);
    }
  }
  for (const s of fixture.submissions) {
    await objectRef(s.objectId, 'submission', 'integer', s.id);
    await client.query('INSERT INTO submission VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)', [
      t,
      s.id,
      s.objectId,
      s.status,
      s.amount,
      s.title,
      s.priority,
      s.submittedAt,
      s.archived,
      s.internalNote,
    ]);
    for (const siteId of s.sites) {
      const site = fixture.sites.find((x) => x.id === siteId)!;
      await client.query(
        `INSERT INTO relation_edge (tenant_id, relation_key, relation_version, source_object, source_type, target_object, target_type, starts_at)
         VALUES ($1, $2, 1, $3, $4, $5, $6, $7)`,
        [
          t,
          bytes('submission.site'),
          s.objectId,
          bytes('submission'),
          site.objectId,
          bytes('site'),
          past,
        ],
      );
    }
    for (const a of s.assignees) {
      await client.query(
        `INSERT INTO identity_relation (tenant_id, relation_key, relation_version, object_id, identity_id, starts_at, expires_at)
         VALUES ($1, $2, 1, $3, $4, $5, $6)`,
        [t, bytes('submission.assignee'), s.objectId, a.identity, a.startsAt, a.expiresAt],
      );
    }
  }
  for (const tag of fixture.tags) {
    await objectRef(tag.objectId, 'tag', 'string', tag.code);
    await client.query('INSERT INTO tag VALUES ($1, $2, $3, $4)', [
      t,
      tag.code,
      tag.objectId,
      tag.label,
    ]);
  }
  for (const x of fixture.exceptions) {
    await client.query(
      `INSERT INTO record_exception (tenant_id, exception_id, object_id, type_key, permission_key, identity_id,
         role_key, effect, purpose, starts_at, expires_at, reason, issued_by, revoked_at)
       VALUES ($1, gen_random_uuid(), $2, $3, $4, $5, $6, $7, $8, $9, $10, 'fixture', $11, $12)`,
      [
        t,
        x.objectId,
        bytes('submission'),
        bytes(x.permission),
        x.subject.kind === 'identity' ? x.subject.identity : null,
        x.subject.kind === 'role' ? bytes(x.subject.role) : null,
        x.effect,
        x.purpose,
        x.startsAt,
        x.expiresAt,
        alice,
        x.revokedAt,
      ],
    );
  }
  for (const purpose of grants ? (['data', 'authority'] as const) : []) {
    await client.query(
      `GRANT SELECT ON site, submission, tag, site_manager TO ${tenantRoleName(t, purpose)}`,
    );
  }
}

// ---- Environment: two provisioned tenants, data-credential registry ----

export interface GatewayEnvironment {
  postgres: TestPostgres;
  registry: TenantDataSourceRegistry;
  identity: DataSource;
  fixtures: Record<'A' | 'B', TenantFixture>;

  adminOn(tenant: TenantId): Connection;

  stop(): Promise<void>;
}

export async function startGatewayEnvironment(): Promise<GatewayEnvironment> {
  const postgres = await startPostgres();
  const provisioner = new TenantProvisioner(postgres.admin, { identityDatabase: 'authz_identity' });
  await provisioner.provisionIdentity();
  const passwords = new Map<string, string>();

  const password = (tenant: TenantId, purpose: ConnectionPurpose) => {
    const key = `${tenant}/${purpose}`;
    if (!passwords.has(key)) passwords.set(key, randomBytes(24).toString('base64url'));
    return passwords.get(key)!;
  };

  const fixtures = { A: tenantFixture(tenantA, 'c', 'A'), B: tenantFixture(tenantB, 'e', 'B') };

  const adminOn = (tenant: TenantId): Connection => ({
    ...postgres.admin,
    database: tenantDatabaseName(tenant),
  });

  for (const fixture of Object.values(fixtures)) {
    await provisioner.provision({
      tenantId: fixture.tenant,
      displayLabel: `Tenant ${fixture.tenant}`,
      passwords: {
        data: password(fixture.tenant, 'data'),
        authority: password(fixture.tenant, 'authority'),
        sync: password(fixture.tenant, 'sync'),
      },
    });
    await withClient(adminOn(fixture.tenant), (client) => seedTenant(client, fixture));
  }
  const identity = await new DataSource(
    identityDataSourceOptions({ ...postgres.admin, database: 'authz_identity' }),
  ).initialize();
  const registry = new TenantDataSourceRegistry({
    host: postgres.admin.host,
    port: postgres.admin.port,
    poolSize: { data: 5, authority: 2, sync: 2 },
    maxConnections: 18,
    idleTimeoutMs: 60_000,
    resolveRoute: directoryRouteResolver(identity, (tenant, purpose) =>
      Promise.resolve({ password: password(tenant, purpose), credentialVersion: 'v1' }),
    ),
  });
  return {
    postgres,
    registry,
    identity,
    fixtures,
    adminOn,

    stop: async () => {
      await registry.close();
      await identity.destroy();
      await postgres.stop();
    },
  };
}

// ---- Plans ----

export const dbNow = () => new Date().toISOString();

export function readPlan(
  tenant: TenantId,
  rules: RuleFact[],
  options: {
    resource?: string;
    action?: string;
    roles?: string[];
    identity?: IdentityId;
    validUntil?: string;
  } = {},
) {
  const now = new Date();
  const input: TrustedInput = {
    tenant,
    principal: { id: options.identity ?? alice, assurance: 2 },
    resource: options.resource ?? 'submission',
    action: options.action ?? 'read',
    context: {},
    now: now.toISOString(),
    validUntil: options.validUntil ?? new Date(now.getTime() + 3_600_000).toISOString(),
  };
  const snapshot: AuthoritySnapshot = {
    tenant,
    revision: '1',
    declarations: fixtureDeclarations(),
    membership: { identity: input.principal.id, state: 'active' },
    roles: options.roles ?? ['reviewer'],
    permissions: [
      {
        key: 'submission.read',
        resource: 'submission',
        action: 'read',
        policy: baseline,
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
        policy: baseline,
        boundary: 'optional',
        lifecycle: 'active',
      },
      {
        key: 'tag.read',
        resource: 'tag',
        action: 'read',
        policy: baseline,
        boundary: 'optional',
        lifecycle: 'active',
      },
    ],
    rules,
    boundaries: [],
    registry: { validators: {}, obligationHandlers: [] },
  };
  const decision = plan(input, snapshot);
  if (decision.effect !== 'allow')
    throw new Error(`fixture plan denied: ${decision.internalReason}`);
  return decision.plan;
}

let ruleSeq = 0;

export function rule(
  permission: string,
  effect: 'allow' | 'deny',
  template: string,
  parameters: RuleFact['parameters'] = {},
  subject: RuleFact['subject'] = { kind: 'role', role: 'reviewer' },
): RuleFact {
  return {
    id: `r${++ruleSeq}`,
    permission,
    subject,
    effect,
    template: { key: template, version: 1 },
    parameters,
  };
}
