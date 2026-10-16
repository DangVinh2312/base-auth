// Product fixture for compiler integration tests: three native PK types (bigint, uuid, text),
// edge-store and domain-table relations, record exceptions. Synthetic data only.
import { randomBytes } from 'node:crypto';
import type {
  UserAuthoritySnapshot,
  UserCompleteFacts,
  UserEdgeFact,
  UserExceptionFact,
  Expr,
  FactObject,
  UserId,
  RuleFact,
  UserTrustedInput,
} from '../../apps/api/dist/authorization/core/authorization.types.js';
import type {
  SystemDeclarations,
  ValidatedDeclarations,
} from '../../apps/api/dist/authorization/core/authorization.declarations.js';
import {
  productDataSourceOptions,
  provisionProductDatabase,
  type ProductDatabasePurpose,
} from '../../apps/api/dist/database/helpers/product-database.helper.js';
import type { ProductStorageBindings } from '../../apps/api/dist/authorization/product-sql.compiler.js';
import type pg from 'pg';
import { DataSource } from 'typeorm';
import {
  type Connection,
  startPostgres,
  type TestPostgres,
  withClient,
} from '../setup-postgres.ts';
import { core } from '../core/fixtures.ts';

export { core };
const { planUser, validate } = core;

export const alice = 'a0000000-0000-4000-8000-000000000001' as UserId;

export const bob = 'b0000000-0000-4000-8000-000000000002' as UserId;

/** Manages both sites: exercises many-to-many paths. */
export const carol = 'c0000000-0000-4000-8000-000000000003' as UserId;

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

export const storageBindings: ProductStorageBindings = {
  resources: [
    {
      resource: 'submission',
      table: 'submission',
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
      objectIdColumn: 'object_id',
      keyColumn: 'id',
      columns: { name: 'name' },
      projection: ['name'],
    },
    {
      resource: 'tag',
      table: 'tag',
      objectIdColumn: 'object_id',
      keyColumn: 'code',
      columns: { label: 'label' },
      projection: ['label'],
    },
  ],
  domains: {
    siteManagers: {
      table: 'site_manager',
      sourceColumn: 'site_id',
      targetColumn: 'user_id',
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
  assignees: { identity: UserId; startsAt: string; expiresAt: string | null }[];
}
interface SiteRow {
  id: string;
  objectId: string;
  name: string;
  managers: { identity: UserId; startsAt: string; expiresAt: string | null }[];
}
interface TagRow {
  code: string;
  objectId: string;
  label: string;
}

export interface ProductFixture {
  sites: SiteRow[];
  submissions: SubmissionRow[];
  tags: TagRow[];
  exceptions: UserExceptionFact[];
}

const objectId = (n: number) => `c0000000-0000-4000-8000-${String(n).padStart(12, '0')}`;

export function productFixture(): ProductFixture {
  const o = objectId;
  const label = 'Product';

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
  subject: UserExceptionFact['subject'],
  extra: Partial<UserExceptionFact> = {},
): UserExceptionFact {
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
  fixture: ProductFixture,
  row: SubmissionRow,
  now: string,
): UserCompleteFacts {
  const record = submissionObject(row);
  const siteObjects = fixture.sites.map((s): FactObject => ({
    type: 'site',
    key: { kind: 'uuid', value: s.id },
    objectId: s.objectId,
    fields: { name: s.name },
  }));
  const edges: UserEdgeFact[] = [
    ...row.sites.map((siteId): UserEdgeFact => ({
      relation: { key: 'submission.site', version: 1 },
      source: row.objectId,
      target: { kind: 'object', objectId: fixtureSite(fixture, siteId).objectId },
      startsAt: past,
      expiresAt: null,
    })),
    ...row.assignees.map((a): UserEdgeFact => ({
      relation: { key: 'submission.assignee', version: 1 },
      source: row.objectId,
      target: { kind: 'identity', identity: a.identity },
      startsAt: a.startsAt,
      expiresAt: a.expiresAt,
    })),
    ...fixture.sites.flatMap((s) =>
      s.managers.map((m): UserEdgeFact => ({
        relation: { key: 'site.manager', version: 1 },
        source: s.objectId,
        target: { kind: 'identity', identity: m.identity },
        startsAt: m.startsAt,
        expiresAt: m.expiresAt,
      })),
    ),
  ];
  return {
    now,
    record,
    objects: [record, ...siteObjects],
    edges,
    exceptions: fixture.exceptions,
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

function fixtureSite(fixture: ProductFixture, id: string): SiteRow {
  const site = fixture.sites.find((candidate) => candidate.id === id);
  if (!site) throw new Error('Fixture references an unknown site');
  return site;
}

const fixtureDdl = `
  CREATE TABLE site (
    id uuid PRIMARY KEY,
    object_id uuid UNIQUE NOT NULL REFERENCES object_ref (object_id),
    name text NOT NULL
  );
  CREATE TABLE submission (
    id bigint PRIMARY KEY,
    object_id uuid UNIQUE NOT NULL REFERENCES object_ref (object_id),
    status text NOT NULL,
    amount numeric(20, 4) NOT NULL,
    title text,
    priority integer,
    submitted_at timestamptz(6) NOT NULL,
    archived boolean NOT NULL,
    internal_note text NOT NULL
  );
  CREATE TABLE tag (
    code text PRIMARY KEY,
    object_id uuid UNIQUE NOT NULL REFERENCES object_ref (object_id),
    label text NOT NULL
  );
  CREATE TABLE site_manager (
    site_id uuid NOT NULL REFERENCES site (id),
    user_id uuid NOT NULL REFERENCES app_user (id),
    starts_at timestamptz(6) NOT NULL,
    expires_at timestamptz(6),
    PRIMARY KEY (site_id, user_id)
  );
  CREATE INDEX ix_site_manager_user ON site_manager (user_id);
`;

/** Synthetic rows in the current product schema; authority facts match evaluator fixtures. */
async function seedProduct(client: pg.Client, fixture: ProductFixture): Promise<void> {
  await client.query(fixtureDdl);
  for (const [type, kind] of [
    ['submission', 'integer'],
    ['site', 'uuid'],
    ['tag', 'string'],
  ] as const) {
    await client.query('INSERT INTO resource_type VALUES ($1, $2, $1)', [bytes(type), kind]);
  }
  const hash = Buffer.alloc(32, 7);
  await client.query(
    `INSERT INTO permission_policy VALUES ($1, 1, $2, '{}', 'active'), ($3, 1, $2, '{}', 'active')`,
    [bytes('baseline'), hash, bytes('approval')],
  );
  for (const [permission, type, action, policy] of [
    ['submission.read', 'submission', 'read', 'baseline'],
    ['submission.approve', 'submission', 'approve', 'approval'],
    ['site.read', 'site', 'read', 'baseline'],
    ['tag.read', 'tag', 'read', 'baseline'],
  ] as const) {
    await client.query(
      `INSERT INTO permission_catalog VALUES ($1, $2, $3, $4, 1, 'active', 'optional')`,
      [bytes(permission), bytes(type), bytes(action), bytes(policy)],
    );
  }
  for (const template of declarationsSource.templates) {
    await client.query('INSERT INTO scope_template VALUES ($1, 1, $2)', [
      bytes(template.key),
      hash,
    ]);
  }
  for (const role of ['reviewer', 'manager']) {
    await client.query(`INSERT INTO role_definition VALUES ($1, 'runtime', $2)`, [
      bytes(role),
      role,
    ]);
  }
  for (const user of [alice, bob, carol]) {
    await client.query(`INSERT INTO app_user (id, state) VALUES ($1, 'active')`, [user]);
  }
  await client.query('INSERT INTO user_role VALUES ($1, $2)', [alice, bytes('reviewer')]);
  await client.query(
    `INSERT INTO resource_relation_definition VALUES ($1, 1, $2, $3, 'edgeStore', $1, $4, 'active')`,
    [bytes('submission.site'), bytes('submission'), bytes('site'), hash],
  );

  const objectRef = (id: string, type: string, kind: string, key: string) =>
    client.query('INSERT INTO object_ref VALUES ($1, $2, $3, $4)', [
      id,
      bytes(type),
      kind,
      bytes(key),
    ]);

  for (const site of fixture.sites) {
    await objectRef(site.objectId, 'site', 'uuid', site.id);
    await client.query('INSERT INTO site VALUES ($1, $2, $3)', [site.id, site.objectId, site.name]);
    for (const manager of site.managers) {
      await client.query('INSERT INTO site_manager VALUES ($1, $2, $3, $4)', [
        site.id,
        manager.identity,
        manager.startsAt,
        manager.expiresAt,
      ]);
    }
  }
  for (const row of fixture.submissions) {
    await objectRef(row.objectId, 'submission', 'integer', row.id);
    await client.query('INSERT INTO submission VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)', [
      row.id,
      row.objectId,
      row.status,
      row.amount,
      row.title,
      row.priority,
      row.submittedAt,
      row.archived,
      row.internalNote,
    ]);
    for (const siteId of row.sites) {
      const site = fixtureSite(fixture, siteId);
      await client.query(
        `INSERT INTO relation_edge (relation_key, relation_version, source_object, source_type, target_object, target_type, starts_at)
         VALUES ($1, 1, $2, $3, $4, $5, $6)`,
        [
          bytes('submission.site'),
          row.objectId,
          bytes('submission'),
          site.objectId,
          bytes('site'),
          past,
        ],
      );
    }
    for (const assignee of row.assignees) {
      await client.query(
        `INSERT INTO user_relation (relation_key, relation_version, object_id, user_id, starts_at, expires_at)
         VALUES ($1, 1, $2, $3, $4, $5)`,
        [
          bytes('submission.assignee'),
          row.objectId,
          assignee.identity,
          assignee.startsAt,
          assignee.expiresAt,
        ],
      );
    }
  }
  for (const tag of fixture.tags) {
    await objectRef(tag.objectId, 'tag', 'string', tag.code);
    await client.query('INSERT INTO tag VALUES ($1, $2, $3)', [tag.code, tag.objectId, tag.label]);
  }
  for (const exception of fixture.exceptions) {
    await client.query(
      `INSERT INTO record_exception (exception_id, object_id, type_key, permission_key, user_id,
         role_key, effect, purpose, starts_at, expires_at, reason, issued_by, revoked_at)
       VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9, 'fixture', $10, $11)`,
      [
        exception.objectId,
        bytes('submission'),
        bytes(exception.permission),
        exception.subject.kind === 'identity' ? exception.subject.identity : null,
        exception.subject.kind === 'role' ? bytes(exception.subject.role) : null,
        exception.effect,
        exception.purpose,
        exception.startsAt,
        exception.expiresAt,
        alice,
        exception.revokedAt,
      ],
    );
  }
  await client.query('GRANT SELECT ON site, submission, tag, site_manager TO product_data');
}

export interface CompilerEnvironment {
  postgres: TestPostgres;
  data: DataSource;
  fixture: ProductFixture;

  stop(): Promise<void>;
}

/** Same product migrations/data login for default and ICU collation databases. */
export async function startCompilerEnvironment(icu = false): Promise<CompilerEnvironment> {
  const postgres = await startPostgres();
  let data: DataSource | undefined;
  try {
    const admin: Connection = icu
      ? { ...postgres.superuser, database: 'icu_product' }
      : postgres.superuser;
    if (icu) {
      await withClient(postgres.superuser, (client) =>
        client.query(
          `CREATE DATABASE icu_product TEMPLATE template0 ENCODING 'UTF8' LOCALE_PROVIDER icu ICU_LOCALE 'und' LOCALE 'C.UTF-8'`,
        ),
      );
    }
    const passwords = Object.fromEntries(
      ['data', 'identity', 'authority', 'sync', 'migration', 'bootstrap', 'outbox'].map(
        (purpose) => [purpose, randomBytes(24).toString('base64url')],
      ),
    ) as Record<ProductDatabasePurpose, string>;
    const connections = await provisionProductDatabase(admin, passwords);
    const fixture = productFixture();
    await withClient(admin, (client) => seedProduct(client, fixture));
    data = await new DataSource(productDataSourceOptions(connections.data)).initialize();
    const pool = data;
    return {
      postgres,
      data: pool,
      fixture,
      stop: async () => {
        try {
          await pool.destroy();
        } finally {
          await postgres.stop();
        }
      },
    };
  } catch (error) {
    try {
      if (data?.isInitialized) await data.destroy();
    } finally {
      await postgres.stop();
    }
    throw error;
  }
}

// ---- Plans ----

export function readPlan(
  rules: RuleFact[],
  options: {
    resource?: string;
    action?: string;
    roles?: string[];
    identity?: UserId;
    validUntil?: string;
  } = {},
) {
  const now = new Date();
  const input: UserTrustedInput = {
    principal: { id: options.identity ?? alice, assurance: 2 },
    resource: options.resource ?? 'submission',
    action: options.action ?? 'read',
    context: {},
    now: now.toISOString(),
    validUntil: options.validUntil ?? new Date(now.getTime() + 3_600_000).toISOString(),
  };
  const snapshot: UserAuthoritySnapshot = {
    revision: '1',
    declarations: fixtureDeclarations(),
    user: { id: input.principal.id, state: 'active' },
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
  const decision = planUser(input, snapshot);
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
