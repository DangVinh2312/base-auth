import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { after, before, test } from 'node:test';
import { DataSource } from 'typeorm';
import type { UserCompleteFacts, UserId } from '@base-authorization/core';
import {
  ProductAuthorization,
  ProductBindingRegistry,
  ProductDataGateway,
  ProductManifestReconciler,
  ProductTransactionRunner,
  type ProductTransaction,
  prepareProductRelease,
  readProductAuthority,
  sessionDigest,
} from '@base-authorization/typeorm-postgres/composition';
import {
  productDataSourceOptions,
  provisionProductDatabase,
} from '@base-authorization/typeorm-postgres/operations';
import { startPostgres, withClient, type TestPostgres } from './setup-postgres.ts';
import { core } from './fixtures/resources.ts';

const { evaluateUser, parseKey, planUser } = core;

let postgres: TestPostgres;
let pools: Record<'data' | 'identity' | 'authority' | 'sync' | 'bootstrap', DataSource>;
let runner: ProductTransactionRunner;
let authorization: ProductAuthorization;
let bindings: ProductBindingRegistry;
const userId = randomUUID() as UserId;
const secret = randomBytes(32).toString('base64url');
const utf8 = (value: string) => Buffer.from(value);
const injection = "' OR TRUE; DROP TABLE product_item; --";
const rows = [
  { key: '9007199254740993', amount: '10.00', status: 'pending', title: injection },
  { key: '9007199254740994', amount: '30.00', status: 'pending', title: 'over boundary' },
  { key: '9007199254740995', amount: '5.00', status: 'closed', title: 'outside policy' },
  { key: '9007199254740996', amount: '15.00', status: 'pending', title: 'denied' },
  { key: '9007199254740997', amount: '12.00', status: 'pending', title: 'record denied' },
  { key: '9007199254740998', amount: '10.00', status: 'pending', title: 'normal' },
].map((row) => ({ ...row, objectId: randomUUID() }));
const policy = { key: 'pending', version: 1 };
const boundary = { key: 'amountLimit', version: 1 };
const registry = { validators: {}, obligationHandlers: [] };
const release = prepareProductRelease(
  {
    sequence: '1',
    predecessor: '0',
    declarations: {
      resources: [
        {
          key: 'item',
          keyKind: 'integer',
          fields: {
            amount: { kind: 'decimal' },
            status: { kind: 'string' },
            title: { kind: 'string' },
          },
          actions: {
            read: { policy, boundary: 'required' },
            update: { policy, boundary: 'required' },
          },
        },
      ],
      policies: [
        {
          ...policy,
          contextRequirements: [],
          obligations: [],
          requiredScope: {
            op: 'eq',
            field: 'status',
            value: { from: 'literal', value: 'pending' },
          },
        },
      ],
      templates: [
        {
          key: 'allItems',
          version: 1,
          resource: 'item',
          parameters: {},
          expression: { op: 'constant', value: true },
        },
        {
          key: 'deniedTitle',
          version: 1,
          resource: 'item',
          parameters: {},
          expression: {
            op: 'eq',
            field: 'title',
            value: { from: 'literal', value: 'denied' },
          },
        },
        {
          key: 'assigned',
          version: 1,
          resource: 'item',
          parameters: {},
          expression: {
            op: 'exists',
            relation: 'item.assignee@1',
            where: { op: 'eq', field: 'identityId', value: { from: 'principal', name: 'id' } },
          },
        },
      ],
      relations: [
        {
          key: 'item.assignee',
          version: 1,
          sourceType: 'item',
          target: { kind: 'identity' },
          binding: { kind: 'edgeStore' },
        },
      ],
      boundaries: [1, 2].map((version) => ({
        key: boundary.key,
        version,
        entries: ['item.read', 'item.update'].map((permission) => ({
          permission,
          contextRequirements: [],
          requiredScope: {
            op: 'lte',
            field: 'amount',
            value: { from: 'literal', value: version === 1 ? '20' : '0' },
          },
        })),
      })),
      capabilities: { validators: [], obligationHandlers: [] },
    },
    roles: [
      { key: 'operator', label: 'Operator fixture', authorityLevel: 1 },
      { key: 'auditor', label: 'Code role without grants', authorityLevel: 1 },
    ],
    defaultGrants: ['read', 'update'].map((action) => ({
      permission: `item.${action}`,
      role: 'operator',
      template: { key: 'allItems', version: 1 },
      parameters: {},
    })),
    seeds: [],
    removeSeeds: [],
    boundaryBindings: [],
    removeBoundaryBindings: [],
    systemGrants: [],
    removeSystemGrants: [],
  },
  core,
);

before(async () => {
  postgres = await startPostgres();
  const passwords = Object.fromEntries(
    ['data', 'identity', 'authority', 'sync', 'bootstrap', 'migration', 'outbox'].map((purpose) => [
      purpose,
      randomBytes(20).toString('hex'),
    ]),
  ) as Record<
    'data' | 'identity' | 'authority' | 'sync' | 'bootstrap' | 'migration' | 'outbox',
    string
  >;
  const connections = await provisionProductDatabase(postgres.superuser, passwords);
  pools = {} as typeof pools;
  for (const purpose of ['data', 'identity', 'authority', 'sync', 'bootstrap'] as const)
    pools[purpose] = await new DataSource(
      productDataSourceOptions(connections[purpose]),
    ).initialize();
  runner = new ProductTransactionRunner(pools);
  await pools.identity.query(
    "INSERT INTO app_user(id,state,email_verified) VALUES($1,'active',true)",
    [userId],
  );
  // Credential/session fixtures exercise the real DB projection; password login has its own suite.
  await pools.identity.query(
    "INSERT INTO local_credential(user_id,password_hash,version) VALUES($1,'fixture-only',1)",
    [userId],
  );
  await pools.identity.query(
    "INSERT INTO application_session(token_hash,user_id,auth_epoch,credential_version,method,assurance,authenticated_at,expires_at) VALUES($1,$2,1,1,'local','password',statement_timestamp(),statement_timestamp()+interval '1 hour')",
    [sessionDigest(secret), userId],
  );
  await new ProductManifestReconciler(runner, {
    core,
    actor: userId,
    capabilities: release.declarations.capabilities,
  }).reconcile(release);
  await withClient(postgres.superuser, async (client) => {
    await client.query(
      'CREATE TABLE product_item(id bigint PRIMARY KEY,object_id uuid UNIQUE NOT NULL REFERENCES object_ref(object_id),amount numeric(20,2) NOT NULL,status text NOT NULL,title text NOT NULL,private_note text NOT NULL)',
    );
    await client.query('GRANT SELECT,UPDATE ON product_item TO product_data');
  });
  // The principal is an ordinary IAM user: the code-owned operator role carries its grants.
  await runner.run('admin', (tx) =>
    tx.manager.query('INSERT INTO user_role(user_id,role_key) VALUES($1,$2)', [
      userId,
      utf8('operator'),
    ]),
  );
  // The bootstrap credential has no assignment capability at all (ADR 0012).
  const other = randomUUID();
  await pools.identity.query("INSERT INTO app_user(id,state) VALUES($1,'active')", [other]);
  for (const role of ['operator', 'auditor'])
    await assert.rejects(
      runner.run('bootstrap', (tx) =>
        tx.manager.query('INSERT INTO user_role(user_id,role_key) VALUES($1,$2)', [
          other,
          utf8(role),
        ]),
      ),
      (e: { driverError?: { code?: string } }) => e.driverError?.code === '42501',
    );
  await runner.run('admin', async (tx) => {
    for (const permission of ['item.read', 'item.update'])
      await tx.manager.query(
        'INSERT INTO user_boundary(user_id,permission_key,boundary_key,boundary_version) VALUES($1,$2,$3,1)',
        [userId, utf8(permission), utf8(boundary.key)],
      );
    for (const row of rows)
      await tx.manager.query(
        "INSERT INTO object_ref(object_id,type_key,key_kind,key_bytes) VALUES($1,$2,'integer',$3)",
        [row.objectId, utf8('item'), utf8(row.key)],
      );
    await tx.manager.query(
      "INSERT INTO policy_rule(rule_id,permission_key,user_id,effect,template_key,template_version,parameters,managed_by) VALUES($1,$2,$3,'deny',$4,1,'{}','runtime')",
      [randomUUID(), utf8('item.read'), userId, utf8('deniedTitle')],
    );
    for (const [index, effect] of [
      [1, 'allow'],
      [4, 'deny'],
    ] as const)
      await tx.manager.query(
        "INSERT INTO record_exception(exception_id,object_id,type_key,permission_key,user_id,effect,purpose,starts_at,reason,issued_by) VALUES($1,$2,$3,$4,$5,$6,'manual',statement_timestamp()-interval '1 minute','fixture',$5)",
        [randomUUID(), rows[index]!.objectId, utf8('item'), utf8('item.read'), userId, effect],
      );
    await tx.manager.query(
      "INSERT INTO user_relation(relation_key,relation_version,object_id,user_id,starts_at) VALUES($1,1,$2,$3,statement_timestamp()-interval '1 minute')",
      [utf8('item.assignee'), rows[5]!.objectId, userId],
    );
  });
  await withClient(postgres.superuser, async (client) => {
    for (const row of rows)
      await client.query('INSERT INTO product_item VALUES($1,$2,$3,$4,$5,$6)', [
        row.key,
        row.objectId,
        row.amount,
        row.status,
        row.title,
        'never projected',
      ]);
  });
  bindings = new ProductBindingRegistry(core, release.declarations, {
    resources: [
      {
        resource: 'item',
        table: 'product_item',
        objectIdColumn: 'object_id',
        keyColumn: 'id',
        columns: { amount: 'amount', status: 'status', title: 'title' },
        projection: ['amount', 'status', 'title'],
      },
    ],
    domains: {},
  });
  authorization = new ProductAuthorization(runner, bindings, { validators: {}, obligations: {} }, [
    { resource: 'item', action: 'update', fields: ['title'] },
  ]);
});
after(async () => {
  for (const pool of Object.values(pools ?? {})) await pool.destroy();
  await postgres?.stop();
});

test('product list/detail/count share policy, boundary, deny and exact integer keys under real credentials', async () => {
  const page = await authorization.list(secret, 'item', 'read', { limit: 1 });
  assert.deepEqual(
    page.items.map((item) => item.key),
    [rows[0]!.key],
  );
  assert.equal(page.total, '2');
  assert.equal(await authorization.count(secret, 'item', 'read'), '2');
  assert.equal('private_note' in page.items[0]!, false);
  assert.equal(
    (await authorization.detail(secret, 'item', 'read', rows[0]!.key))?.key,
    rows[0]!.key,
  );
  for (const index of [1, 2, 3, 4])
    assert.equal(await authorization.detail(secret, 'item', 'read', rows[index]!.key), null);
  assert.equal(await authorization.detail(secret, 'item', 'read', '1'), null);
  const filtered = await authorization.list(secret, 'item', 'read', {
    filter: { op: 'eq', field: 'title', value: injection },
  });
  assert.deepEqual(
    filtered.items.map((item) => item.key),
    [rows[0]!.key],
  );
  await assert.rejects(
    authorization.list(secret, 'item', 'read', { orderBy: 'title; DROP TABLE product_item' }),
  );
  await assert.rejects(
    authorization.list(secret, 'item', 'read', {
      filter: { op: 'lte', field: 'amount', value: 10 },
    }),
  );
});

test('product PostgreSQL predicate matches pure evaluator including record exceptions and ReBAC', async () => {
  await runner.run('read', async (tx) => {
    const snapshot = await readProductAuthority(
      tx,
      userId,
      'item.read',
      release.declarations,
      registry,
    );
    const now = new Date().toISOString();
    const base = {
      principal: { id: userId, assurance: 1 },
      resource: 'item',
      action: 'read',
      context: {},
      now,
      validUntil: new Date(Date.now() + 1500).toISOString(),
    };
    const gateway = new ProductDataGateway(bindings);
    for (const authority of [
      snapshot,
      {
        ...snapshot,
        rules: [
          {
            id: 'fixture',
            permission: 'item.read',
            subject: { kind: 'identity' as const, identity: userId },
            effect: 'allow' as const,
            template: { key: 'assigned', version: 1 },
            parameters: {},
          },
        ],
      },
    ]) {
      const decision = planUser(base, authority);
      assert.equal(decision.effect, 'allow');
      const expected: string[] = [];
      for (const row of rows) {
        const record = {
          type: 'item',
          key: parseKey('integer', row.key),
          objectId: row.objectId,
          fields: { amount: row.amount, status: row.status, title: row.title },
        };
        const facts: UserCompleteFacts = {
          now,
          record,
          objects: [record],
          edges: [
            {
              source: rows[5]!.objectId,
              relation: { key: 'item.assignee', version: 1 },
              target: { kind: 'identity', identity: userId },
              startsAt: '2020-01-01T00:00:00Z',
              expiresAt: null,
            },
          ],
          exceptions: (
            [
              [1, 'allow'],
              [4, 'deny'],
            ] as const
          ).map(([index, effect]) => ({
            objectId: rows[index]!.objectId,
            permission: 'item.read',
            subject: { kind: 'identity', identity: userId },
            effect,
            purpose: 'manual',
            startsAt: '2020-01-01T00:00:00Z',
            expiresAt: null,
            revokedAt: null,
          })),
        };
        if (evaluateUser(decision.plan, facts).effect === 'allow') expected.push(row.key);
      }
      const actual = await gateway.list(decision.plan, {}, tx);
      assert.deepEqual(
        actual.items.map((row) => row.key),
        expected,
      );
      assert.equal(await gateway.count(decision.plan, {}, tx), String(expected.length));
    }
  });
});

/** Oracle: every catalog/rule/boundary row of the user, as read before T8 filtered by permission. */
async function readAllAuthority(tx: ProductTransaction) {
  const any = await readProductAuthority(tx, userId, 'item.read', release.declarations, registry);
  const permissions = await tx.manager.query<
    {
      key: string;
      resource: string;
      action: string;
      policy_key: string;
      policy_version: number;
      lifecycle: 'active' | 'deprecated' | 'retired';
      boundary: 'required' | 'optional' | null;
    }[]
  >(
    `SELECT convert_from(permission_key,'UTF8') key,convert_from(type_key,'UTF8') resource,convert_from(action_key,'UTF8') action,convert_from(policy_key,'UTF8') policy_key,policy_version,lifecycle,boundary_requirement boundary FROM permission_catalog`,
  );
  const rules = await tx.manager.query<
    {
      id: string;
      permission: string;
      user_id: UserId | null;
      role: string | null;
      effect: 'allow' | 'deny';
      template: string;
      version: number;
      parameters: Record<string, string>;
    }[]
  >(
    `SELECT rule_id id,convert_from(permission_key,'UTF8') permission,user_id,convert_from(role_key,'UTF8') role,effect,convert_from(template_key,'UTF8') template,template_version version,parameters FROM policy_rule WHERE user_id=$1 OR role_key IN(SELECT role_key FROM user_role WHERE user_id=$1) ORDER BY rule_id`,
    [userId],
  );
  const boundaries = await tx.manager.query<
    { permission: string; key: string; version: number; lifecycle: 'active' | 'deprecated' }[]
  >(
    `SELECT convert_from(b.permission_key,'UTF8') permission,convert_from(b.boundary_key,'UTF8') key,b.boundary_version version,d.lifecycle FROM user_boundary b JOIN permission_boundary d USING(boundary_key,boundary_version) WHERE b.user_id=$1`,
    [userId],
  );
  return {
    ...any,
    permissions: permissions.map((p) => ({
      ...p,
      policy: { key: p.policy_key, version: p.policy_version },
    })),
    rules: rules.map((r) => ({
      id: r.id,
      permission: r.permission,
      subject: r.user_id
        ? { kind: 'identity' as const, identity: r.user_id }
        : { kind: 'role' as const, role: r.role ?? '' },
      effect: r.effect,
      template: { key: r.template, version: r.version },
      parameters: r.parameters,
    })),
    boundaries: boundaries.map((b) => ({
      identity: userId,
      permission: b.permission,
      boundary: { key: b.key, version: b.version },
      lifecycle: b.lifecycle,
    })),
  };
}

test('authority read is limited to the requested permission and decides exactly like a full read', async () => {
  const malformed = randomUUID();
  const decide = async () =>
    runner.run('read', async (tx) => {
      const full = await readAllAuthority(tx);
      const out: Record<string, unknown> = {};
      for (const action of ['read', 'update']) {
        const permission = `item.${action}`;
        const scoped = await readProductAuthority(
          tx,
          userId,
          permission,
          release.declarations,
          registry,
        );
        assert.deepEqual(
          scoped.permissions.map((p) => p.key),
          [permission],
        );
        assert.ok(scoped.rules.every((r) => r.permission === permission));
        assert.ok(scoped.boundaries.every((b) => b.permission === permission));
        assert.deepEqual(scoped.roles, full.roles);
        assert.deepEqual(scoped.user, full.user);
        const input = {
          principal: { id: userId, assurance: 1 },
          resource: 'item',
          action,
          context: {},
          now: '2026-10-14T00:00:00.000000Z',
          validUntil: '2026-10-14T00:00:01.000000Z',
        };
        const decision = planUser(input, scoped);
        assert.deepEqual(decision, planUser(input, full));
        out[action] = decision.effect === 'allow' ? 'allow' : decision.internalReason;
      }
      return out;
    });
  // Direct identity deny on read, role allow on both, required boundaries bound.
  assert.deepEqual(await decide(), { read: 'allow', update: 'allow' });
  // A malformed rule of update denies update only; read never sees it.
  await runner.run('admin', (tx) =>
    tx.manager.query(
      `INSERT INTO policy_rule(rule_id,permission_key,user_id,effect,template_key,template_version,parameters,managed_by) VALUES($1,$2,$3,'allow',$4,1,'{"unexpected":"1"}','runtime')`,
      [malformed, utf8('item.update'), userId, utf8('allItems')],
    ),
  );
  assert.deepEqual(await decide(), { read: 'allow', update: 'rule_parameters_mismatch' });
  // A required boundary without binding denies that permission only.
  await runner.run('admin', async (tx) => {
    await tx.manager.query('DELETE FROM policy_rule WHERE rule_id=$1', [malformed]);
    await tx.manager.query('DELETE FROM user_boundary WHERE user_id=$1 AND permission_key=$2', [
      userId,
      utf8('item.update'),
    ]);
  });
  assert.deepEqual(await decide(), { read: 'allow', update: 'boundary_binding_missing' });
  await runner.run('admin', (tx) =>
    tx.manager.query(
      'INSERT INTO user_boundary(user_id,permission_key,boundary_key,boundary_version) VALUES($1,$2,$3,1)',
      [userId, utf8('item.update'), utf8(boundary.key)],
    ),
  );
  assert.deepEqual(await decide(), { read: 'allow', update: 'allow' });
  // A deny through an assigned role applies to its permission only.
  const roleDeny = randomUUID();
  await runner.run('admin', async (tx) => {
    // Code-owned roles cannot carry runtime rules (trigger); a runtime role can.
    await tx.manager.query(
      "INSERT INTO role_definition(role_key,managed_by,label) VALUES($1,'runtime','Runtime deny fixture')",
      [utf8('runtime.denier')],
    );
    await tx.manager.query('INSERT INTO user_role(user_id,role_key) VALUES($1,$2)', [
      userId,
      utf8('runtime.denier'),
    ]);
    await tx.manager.query(
      "INSERT INTO policy_rule(rule_id,permission_key,role_key,effect,template_key,template_version,parameters,managed_by) VALUES($1,$2,$3,'deny',$4,1,'{}','runtime')",
      [roleDeny, utf8('item.update'), utf8('runtime.denier'), utf8('allItems')],
    );
  });
  assert.deepEqual(await decide(), { read: 'allow', update: 'allow' });
  assert.equal(await authorization.count(secret, 'item', 'read'), '2');
  // Deny lowers into the predicate: the plan is allowed but matches no row.
  assert.equal(
    await authorization.update(secret, 'item', 'update', rows[0]!.key, { title: 'role denied' }),
    false,
  );
  await runner.run('admin', async (tx) => {
    await tx.manager.query('DELETE FROM policy_rule WHERE rule_id=$1', [roleDeny]);
    await tx.manager.query('DELETE FROM user_role WHERE user_id=$1 AND role_key=$2', [
      userId,
      utf8('runtime.denier'),
    ]);
    await tx.manager.query('DELETE FROM role_definition WHERE role_key=$1', [
      utf8('runtime.denier'),
    ]);
  });
});

test('an empty page past the end reports the total of the same statement despite concurrent inserts', async () => {
  const visible = await authorization.count(secret, 'item', 'read');
  const added = { key: '9007199254740999', objectId: randomUUID() };
  await runner.run('read', async (tx) => {
    const snapshot = await readProductAuthority(
      tx,
      userId,
      'item.read',
      release.declarations,
      registry,
    );
    const [clock] = await tx.manager.query<{ now: string; until: string }[]>(
      `SELECT to_char(statement_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') now,to_char((statement_timestamp()+interval '1 second') AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') until`,
    );
    const decision = planUser(
      {
        principal: { id: userId, assurance: 1 },
        resource: 'item',
        action: 'read',
        context: {},
        now: clock!.now,
        validUntil: clock!.until,
      },
      snapshot,
    );
    assert.equal(decision.effect, 'allow');
    if (decision.effect !== 'allow') return;
    let statements = 0;
    // After the page statement, another session commits one more visible row.
    const manager = new Proxy(tx.manager, {
      get(target, property, receiver) {
        if (property !== 'query') return Reflect.get(target, property, receiver) as unknown;
        return async (sql: string, parameters?: unknown[]) => {
          const result: unknown = await target.query(sql, parameters);
          if (++statements === 1)
            await withClient(postgres.superuser, async (client) => {
              await client.query(
                "INSERT INTO object_ref(object_id,type_key,key_kind,key_bytes) VALUES($1,'\\x6974656d','integer',$2)",
                [added.objectId, utf8(added.key)],
              );
              await client.query(
                "INSERT INTO product_item VALUES($1,$2,'1.00','pending','late','never projected')",
                [added.key, added.objectId],
              );
            });
          return result;
        };
      },
    });
    const page = await new ProductDataGateway(bindings).list(
      decision.plan,
      { offset: Number(visible) },
      { ...tx, manager },
    );
    assert.deepEqual(page, { items: [], total: visible });
  });
  await withClient(postgres.superuser, async (client) => {
    await client.query('DELETE FROM product_item WHERE id=$1', [added.key]);
    await client.query('DELETE FROM object_ref WHERE object_id=$1', [added.objectId]);
  });
});

test('product integer writes enforce their own action and session projection rejects unknown secrets', async () => {
  assert.equal(
    await authorization.update(secret, 'item', 'update', rows[0]!.key, {
      title: `${injection} updated`,
    }),
    true,
  );
  assert.equal(
    (await authorization.detail(secret, 'item', 'read', rows[0]!.key))?.title,
    `${injection} updated`,
  );
  assert.equal(
    await authorization.update(secret, 'item', 'update', rows[1]!.key, {
      title: 'outside boundary',
    }),
    false,
  );
  // Read's title deny is not an update deny; each action plans its own permission.
  assert.equal(
    await authorization.update(secret, 'item', 'update', rows[3]!.key, { title: 'denied' }),
    true,
  );
  await assert.rejects(
    authorization.update(secret, 'item', 'update', rows[0]!.key, { private_note: 'exfiltrate' }),
  );
  const revoked = randomBytes(32).toString('base64url');
  await assert.rejects(authorization.list(revoked, 'item', 'read'));
});

test('read action cannot be supplied to the update command', async () => {
  await assert.rejects(
    authorization.update(secret, 'item', 'read', rows[0]!.key, { title: 'read must not write' }),
  );
});
test('write values reject malformed Unicode rather than storing replacement characters', async () => {
  await assert.rejects(
    authorization.update(secret, 'item', 'update', rows[0]!.key, {
      title: 'malformed \ud800 title',
    }),
  );
});

test('boundary tightening waits for shared access; decisions after commit read fresh authority', async () => {
  let releaseRead!: () => void;
  let acquired!: () => void;
  const ready = new Promise<void>((resolve) => {
    acquired = resolve;
  });
  const hold = new Promise<void>((resolve) => {
    releaseRead = resolve;
  });
  const read = runner.run('read', async () => {
    acquired();
    await hold;
  });
  await ready;
  let mutated = false;
  const revoke = runner.run('admin', async (tx) => {
    await tx.manager.query('UPDATE user_boundary SET boundary_version=2 WHERE user_id=$1', [
      userId,
    ]);
    mutated = true;
  });
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(mutated, false);
  releaseRead();
  await read;
  await revoke;
  assert.equal(await authorization.count(secret, 'item', 'read'), '0');
  await runner.run('admin', async (tx) => {
    await tx.manager.query('UPDATE user_boundary SET boundary_version=1 WHERE user_id=$1', [
      userId,
    ]);
  });
});

test('session revocation commits before subsequent resource access is denied', async () => {
  await runner.run('revoke', async (tx) => {
    await tx.manager.query(
      'UPDATE application_session SET revoked_at=statement_timestamp() WHERE token_hash=$1',
      [sessionDigest(secret)],
    );
  });
  await assert.rejects(authorization.count(secret, 'item', 'read'));
});
