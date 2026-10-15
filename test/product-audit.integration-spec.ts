import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { after, before, test } from 'node:test';
import { DataSource } from 'typeorm';
import type { IdentityId, UserAuthorizedPlan } from '@base-authorization/core';
import { ProductAccessDenied } from '@base-authorization/typeorm-postgres';
import {
  ProductAuthorization,
  ProductBindingRegistry,
  ProductIdentityService,
  ProductManifestReconciler,
  ProductTransactionRunner,
  createProductPasswordHasher,
  prepareProductRelease,
  productObligations,
  sessionDigest,
  type ProductObligationHandler,
} from '@base-authorization/typeorm-postgres/composition';
import {
  appendProductAudit,
  productDataSourceOptions,
  provisionProductDatabase,
} from '@base-authorization/typeorm-postgres/operations';
import {
  createProductAuthorizationCore,
  productBindings,
  productDeclarations,
  productReleaseSource,
} from '../apps/api/dist/authorization/product-manifest.js';
import { ProductDocument1792108800002 } from '../apps/api/dist/documents/migrations/product-document.js';
import { startPostgres, withClient, type TestPostgres } from './setup-postgres.ts';

const core = createProductAuthorizationCore();
// Document reads also carry audit@1 here, so the access event of a read can be observed.
const release = prepareProductRelease(
  {
    ...productReleaseSource,
    declarations: {
      ...productDeclarations,
      policies: productDeclarations.policies.map((p) =>
        p.key === 'readable' ? { ...p, obligations: [{ handler: 'audit@1' }] } : p,
      ),
      boundaries: [
        ...productDeclarations.boundaries,
        {
          key: 'accountAll',
          version: 1,
          entries: [
            {
              permission: 'account.suspend',
              contextRequirements: [],
              requiredScope: { op: 'constant', value: true },
            },
          ],
        },
      ],
    },
  },
  core,
);
const validators = {
  'fresh@1': (_p: unknown, input: { context: { freshAuthentication?: unknown } }) =>
    input.context.freshAuthentication === true,
};
const operator = randomUUID() as IdentityId;
const actor = randomUUID();
const target = randomUUID();
const documentId = randomUUID();
const secret = randomBytes(32).toString('base64url');

const utf8 = (value: string) => Buffer.from(value);

let postgres: TestPostgres;
let pools: Record<'data' | 'identity' | 'authority' | 'sync' | 'bootstrap', DataSource>;
let migration: DataSource;
let runner: ProductTransactionRunner;
let bindings: ProductBindingRegistry;
let sync: Awaited<ReturnType<typeof appended>>;

const service = (obligations: Readonly<Record<string, ProductObligationHandler>>) =>
  new ProductAuthorization(runner, bindings, { validators, obligations }, [
    { resource: 'document', action: 'update', fields: ['title'] },
  ]);

interface Event {
  id: string;
  kind: string;
  actor: string;
  permission: string | null;
  revision: string;
  objectId: string | null;
  metadata: Record<string, unknown>;
}

const events = () =>
  withClient(
    postgres.superuser,
    async (client) =>
      (
        await client.query<Event>(
          `SELECT event_id id,convert_from(event_kind,'UTF8') kind,actor_id::text actor,convert_from(permission_key,'UTF8') permission,policy_revision::text revision,object_id::text "objectId",safe_metadata metadata FROM audit_outbox`,
        )
      ).rows,
  );

/** Events appended by `work` only, keyed by kind; also returns the revision before/after. */
async function appended(work: () => Promise<unknown>) {
  const seen = new Set((await events()).map((e) => e.id));
  const before = await revision();
  await work();
  const added = (await events()).filter((e) => !seen.has(e.id));
  return { before, after: await revision(), added };
}

const revision = () =>
  withClient(
    postgres.superuser,
    async (client) =>
      (await client.query<{ r: string }>('SELECT revision::text r FROM authz_state')).rows[0]!.r,
  );

const title = async () =>
  (
    await migration.query<{ title: string }[]>('SELECT title FROM document WHERE id=$1', [
      documentId,
    ])
  )[0]!.title;

before(async () => {
  postgres = await startPostgres();
  const passwords = Object.fromEntries(
    ['data', 'identity', 'authority', 'sync', 'bootstrap', 'migration', 'outbox'].map((p) => [
      p,
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
  migration = await new DataSource(productDataSourceOptions(connections.migration)).initialize();
  runner = new ProductTransactionRunner(pools);
  const qr = migration.createQueryRunner();
  await new ProductDocument1792108800002().up(qr);
  await qr.release();
  await migration.query(
    `INSERT INTO app_user(id,state,email_verified) VALUES($1,'active',true),($2,'active',true)`,
    [actor, target],
  );
  await migration.query(
    "INSERT INTO local_credential(user_id,password_hash,version) VALUES($1,'fixture-only',1)",
    [actor],
  );
  bindings = new ProductBindingRegistry(core, release.declarations, productBindings);
  sync = await appended(() =>
    new ProductManifestReconciler(runner, {
      core,
      actor: operator,
      capabilities: release.declarations.capabilities,
    }).reconcile(release),
  );
  // Fixture authority (IAM actor): direct document grants, account.suspend grant and its boundary.
  await runner.run('admin', async (tx) => {
    await tx.manager.query(
      'INSERT INTO user_boundary(user_id,permission_key,boundary_key,boundary_version) VALUES($1,$2,$3,1)',
      [actor, utf8('account.suspend'), utf8('accountAll')],
    );
    await tx.manager.query(
      "INSERT INTO policy_rule(rule_id,permission_key,user_id,effect,template_key,template_version,parameters,managed_by) VALUES($1,$2,$3,'allow',$4,1,'{}','runtime')",
      [randomUUID(), utf8('account.suspend'), actor, utf8('allAccounts')],
    );
    await tx.manager.query(
      "INSERT INTO object_ref(object_id,type_key,key_kind,key_bytes) VALUES($1,$2,'uuid',$3)",
      [documentId, utf8('document'), utf8(documentId)],
    );
    for (const permission of ['document.read', 'document.update'])
      await tx.manager.query(
        "INSERT INTO policy_rule(rule_id,permission_key,user_id,effect,template_key,template_version,parameters,managed_by) VALUES($1,$2,$3,'allow',$4,1,'{}','runtime')",
        [randomUUID(), utf8(permission), actor, utf8('ownedDocuments')],
      );
  });
  await migration.query(
    "INSERT INTO document(id,object_id,owner_id,title,state) VALUES($1,$1,$2,'Original','draft')",
    [documentId, actor],
  );
  await pools.identity.query(
    "INSERT INTO application_session(token_hash,user_id,auth_epoch,credential_version,method,assurance,authenticated_at,reauthenticated_at,expires_at) VALUES($1,$2,1,1,'local','password',statement_timestamp(),statement_timestamp(),statement_timestamp()+interval '1 hour')",
    [sessionDigest(secret), actor],
  );
});
after(async () => {
  await migration?.destroy();
  for (const pool of Object.values(pools ?? {})) await pool.destroy();
  await postgres?.stop();
});

test('manifest sync records the evaluated revision and the revision it publishes', () => {
  const { before, after, added } = sync;
  assert.equal(BigInt(after), BigInt(before) + 1n);
  assert.deepEqual(
    added.map((e) => [e.kind, e.actor, e.revision, e.metadata]),
    [
      [
        'manifest.sync',
        operator,
        before,
        { sequence: release.sequence, hash: release.hash, resultingRevision: after },
      ],
    ],
  );
});

test('read access event keeps the evaluated revision and has no resulting revision', async () => {
  const { before, after, added } = await appended(() =>
    service(productObligations).list(secret, 'document', 'read'),
  );
  assert.equal(after, before);
  assert.deepEqual(
    added.map((e) => [e.kind, e.actor, e.permission, e.revision, e.metadata]),
    [['access.read', actor, 'document.read', before, {}]],
  );
});

test('update writes one access and one mutation event with resource and typed key, no title', async () => {
  const { before, after, added } = await appended(async () =>
    assert.equal(
      await service(productObligations).update(secret, 'document', 'update', documentId, {
        title: 'Secret title',
      }),
      true,
    ),
  );
  assert.equal(after, before);
  assert.deepEqual(
    added
      .sort((a, b) => a.kind.localeCompare(b.kind))
      .map((e) => [e.kind, e.actor, e.permission, e.revision, e.objectId, e.metadata]),
    [
      ['access.update', actor, 'document.update', before, null, {}],
      [
        'data.update',
        actor,
        'document.update',
        before,
        documentId,
        { resource: 'document', keyKind: 'uuid', key: documentId, resultingRevision: before },
      ],
    ],
  );
  assert.equal(JSON.stringify(added).includes('Secret title'), false);
  assert.equal(await title(), 'Secret title');
});

test('handler failure or missing handler denies and rolls back effect and events', async () => {
  for (const [obligations, expected] of [
    [
      {
        'audit@1': () => Promise.reject(new Error('sink down')),
      },
      /sink down/,
    ],
    [{}, ProductAccessDenied],
  ] as const) {
    const original = await title();
    const { before, after, added } = await appended(() =>
      assert.rejects(
        service(obligations).update(secret, 'document', 'update', documentId, {
          title: 'Must not stick',
        }),
        expected,
      ),
    );
    assert.equal(after, before);
    assert.deepEqual(added, []);
    assert.equal(await title(), original);
  }
});

test('a replaced audit@1 implementation runs through the same generic access loop', async () => {
  const calls: UserAuthorizedPlan[] = [];
  const { added } = await appended(() =>
    service({
      'audit@1': (_tx, plan) => {
        calls.push(plan);
        return Promise.resolve();
      },
    }).update(secret, 'document', 'update', documentId, { title: 'Replaced handler' }),
  );
  assert.deepEqual(
    calls.map((p) => [p.userId, p.permission]),
    [[actor, 'document.update']],
  );
  // The fixture handler wrote nothing; the mutation event is still the writer's own.
  assert.deepEqual(
    added.map((e) => e.kind),
    ['data.update'],
  );
  assert.equal(Object.isFrozen(productObligations), true);
});

test('suspend records actor and a distinct target; admin evaluated R, resulting R+1', async () => {
  const { before, after, added } = await appended(async () =>
    assert.equal(await service(productObligations).suspendUser(secret, target), true),
  );
  assert.equal(BigInt(after), BigInt(before) + 1n);
  assert.deepEqual(
    added
      .sort((a, b) => a.kind.localeCompare(b.kind))
      .map((e) => [e.kind, e.actor, e.permission, e.revision, e.metadata]),
    [
      ['access.suspend', actor, 'account.suspend', before, {}],
      [
        'account.suspend',
        actor,
        'account.suspend',
        before,
        { targetUserId: target, resultingRevision: after },
      ],
    ],
  );
  assert.notEqual(actor, target);
});

test('revoke-mode identity event records evaluated R and resulting R+1 without token', async () => {
  const other = randomBytes(32).toString('base64url');
  await pools.identity.query(
    "INSERT INTO application_session(token_hash,user_id,auth_epoch,credential_version,method,assurance,authenticated_at,expires_at) VALUES($1,$2,1,1,'local','password',statement_timestamp(),statement_timestamp()+interval '1 hour')",
    [sessionDigest(other), actor],
  );
  const identity = new ProductIdentityService(runner, await createProductPasswordHasher(new Set()));
  const { before, after, added } = await appended(() => identity.logout(other));
  assert.equal(BigInt(after), BigInt(before) + 1n);
  assert.deepEqual(
    added.map((e) => [e.kind, e.actor, e.permission, e.revision, e.metadata]),
    [['identity.logout', actor, null, before, { resultingRevision: after }]],
  );
  assert.equal(JSON.stringify(added).includes(other), false);
});

test('a string record key never lands in audit metadata; object_id identifies the row', async () => {
  const email = 'person@example.test';
  const { added } = await appended(() =>
    runner.run('write', (tx) =>
      appendProductAudit(tx, {
        kind: 'data.update',
        actor,
        permission: 'document.update',
        target: { resource: 'document', keyKind: 'string', key: email, objectId: documentId },
      }),
    ),
  );
  assert.deepEqual(
    added.map((e) => [e.kind, e.objectId, e.metadata]),
    [
      [
        'data.update',
        documentId,
        { resource: 'document', keyKind: 'string', resultingRevision: added[0]!.revision },
      ],
    ],
  );
  assert.equal(JSON.stringify(added).includes(email), false);
});
