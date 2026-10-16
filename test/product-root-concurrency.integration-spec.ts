import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { DataSource } from 'typeorm';
import type pg from 'pg';
import type { IdentityId } from '../apps/api/dist/authorization/core/authorization.types.js';
import {
  type ProductDatabasePurpose,
  productDataSourceOptions,
  provisionProductDatabase,
} from '../apps/api/dist/database/helpers/product-database.helper.js';
import {
  ProductManifestReconciler,
  prepareProductRelease,
} from '../apps/api/dist/authorization/services/product-manifest.service.js';
import { ProductTransactionRunner } from '../apps/api/dist/database/product-transaction.runner.js';

import {
  createProductAuthorizationCore,
  productDeclarations,
  productReleaseSource,
} from '../apps/api/dist/authorization/product.manifest.js';
import { openClient, startPostgres, withClient, type TestPostgres } from './setup-postgres.ts';

const core = createProductAuthorizationCore();

const utf8 = (value: string) => Buffer.from(value);

const release = prepareProductRelease(
  {
    ...productReleaseSource,
    declarations: {
      ...productDeclarations,
      boundaries: [
        ...productDeclarations.boundaries,
        {
          key: 'documentLimit',
          version: 1,
          entries: [
            {
              permission: 'document.read',
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
const object = randomUUID();
/** One write per IAM fact kind and the activation token, by its real runtime login ($1 = subject). */
const attachments = [
  {
    name: 'user_role',
    login: 'authority',
    sql: 'INSERT INTO user_role(user_id,role_key) VALUES($1,$2)',

    params: () => [utf8('reviewer')],
  },
  {
    name: 'user_boundary',
    login: 'authority',
    sql: 'INSERT INTO user_boundary(user_id,permission_key,boundary_key,boundary_version) VALUES($1,$2,$3,1)',

    params: () => [utf8('document.read'), utf8('documentLimit')],
  },
  {
    name: 'policy_rule',
    login: 'authority',
    sql: "INSERT INTO policy_rule(rule_id,permission_key,user_id,effect,template_key,template_version,parameters,managed_by) VALUES($2,$3,$1,'allow',$4,1,'{}','runtime')",

    params: () => [randomUUID(), utf8('document.read'), utf8('ownedDocuments')],
  },
  {
    name: 'record_exception',
    login: 'authority',
    sql: "INSERT INTO record_exception(exception_id,object_id,type_key,permission_key,user_id,effect,purpose,starts_at,reason,issued_by) VALUES($2,$3,$4,$5,$1,'allow','manual',statement_timestamp(),'fixture',$1)",

    params: () => [randomUUID(), object, utf8('document'), utf8('document.read')],
  },
  {
    name: 'activation token',
    login: 'identity',
    sql: "INSERT INTO one_time_token(token_hash,user_id,purpose,expires_at) VALUES($2,$1,'activation',statement_timestamp()+interval '15 minutes')",

    params: () => [randomBytes(32)],
  },
] as const;
let fixture: TestPostgres;
let connections: Awaited<ReturnType<typeof provisionProductDatabase>>;
let migration: DataSource;
let admin: pg.Client;

before(async () => {
  fixture = await startPostgres();
  const passwords = Object.fromEntries(
    ['data', 'identity', 'authority', 'sync', 'migration', 'bootstrap', 'outbox'].map((p) => [
      p,
      randomBytes(24).toString('hex'),
    ]),
  ) as Record<ProductDatabasePurpose, string>;
  connections = await provisionProductDatabase(fixture.superuser, passwords);
  migration = await new DataSource(productDataSourceOptions(connections.migration)).initialize();
  admin = await openClient(fixture.superuser);
  const sync = await new DataSource(productDataSourceOptions(connections.sync)).initialize();
  const authority = await new DataSource(
    productDataSourceOptions(connections.authority),
  ).initialize();
  try {
    const runner = new ProductTransactionRunner({ sync, authority });
    await new ProductManifestReconciler(runner, {
      core,
      actor: randomUUID() as IdentityId,
      capabilities: release.declarations.capabilities,
    }).reconcile(release);
    await runner.run('admin', (tx) =>
      tx.manager.query(
        "INSERT INTO object_ref(object_id,type_key,key_kind,key_bytes) VALUES($1,$2,'uuid',$3)",
        [object, utf8('document'), utf8(object)],
      ),
    );
  } finally {
    await sync.destroy();
    await authority.destroy();
  }
});
after(async () => {
  await admin?.end();
  await migration?.destroy();
  await fixture?.stop();
});

const pendingUser = async () => {
  const id = randomUUID();
  await migration.query(`INSERT INTO app_user(id,email_canonical,state) VALUES($1,$2,'pending')`, [
    id,
    `${id}@example.test`,
  ]);
  return id;
};

const pidOf = async (client: pg.Client) =>
  (await client.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]!.pid;

/** Deterministic ordering: returns once the backend waits on a lock held by another one. */
async function waitUntilBlocked(pid: number): Promise<void> {
  for (let attempt = 0; attempt < 400; attempt++) {
    const { rows } = await admin.query<{ blocked: boolean }>(
      'SELECT cardinality(pg_blocking_pids($1))>0 AS blocked',
      [pid],
    );
    if (rows[0]?.blocked) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`backend ${pid} never waited for a lock`);
}

const outcome = (work: Promise<unknown>) =>
  work.then(
    () => 'committed',
    (error: { code?: string }) => error.code ?? 'error',
  );

const factCount = async (user: string) =>
  (
    await migration.query<{ n: number }[]>(
      `SELECT (SELECT count(*)::int FROM user_role WHERE user_id=$1)+(SELECT count(*)::int FROM user_boundary WHERE user_id=$1)
        +(SELECT count(*)::int FROM policy_rule WHERE user_id=$1)+(SELECT count(*)::int FROM record_exception WHERE user_id=$1)
        +(SELECT count(*)::int FROM one_time_token WHERE user_id=$1) AS n`,
      [user],
    )
  )[0]!.n;

test('a promotion waiting behind an uncommitted fact or token is refused once the writer commits', async () => {
  for (const attachment of attachments) {
    const target = await pendingUser();
    const writer = await openClient(connections[attachment.login]);
    try {
      const promoter = await openClient(connections.bootstrap);
      try {
        await writer.query('BEGIN');
        await writer.query(attachment.sql, [target, ...attachment.params()]);
        const pid = await pidOf(promoter);
        await promoter.query('BEGIN');
        const lock = promoter.query('SELECT 1 FROM app_user WHERE id=$1 FOR NO KEY UPDATE', [
          target,
        ]);
        await waitUntilBlocked(pid);
        await writer.query('COMMIT');
        await lock;
        assert.equal(
          await outcome(promoter.query(`UPDATE app_user SET kind='root' WHERE id=$1`, [target])),
          '42501',
          attachment.name,
        );
        await promoter.query('ROLLBACK');
      } finally {
        await promoter.end();
      }
    } finally {
      await writer.end();
    }
  }
});

test('a promotion outside READ COMMITTED is refused with real credentials outside the runner', async () => {
  for (const level of ['REPEATABLE READ', 'SERIALIZABLE']) {
    const target = await pendingUser();
    const promoter = await openClient(connections.bootstrap);
    try {
      await promoter.query(`BEGIN ISOLATION LEVEL ${level}`);
      await promoter.query('SELECT 1 FROM app_user WHERE id=$1 FOR NO KEY UPDATE', [target]);
      await assert.rejects(
        promoter.query(`UPDATE app_user SET kind='root' WHERE id=$1`, [target]),
        /requires READ COMMITTED/,
        level,
      );
      await promoter.query('ROLLBACK');
    } finally {
      await promoter.end();
    }
  }
});

test('ordinary IAM facts and invitations succeed with real credentials (the guard owner can lock)', async () => {
  const target = await pendingUser();
  for (const attachment of attachments)
    await withClient(connections[attachment.login], (c) =>
      c.query(attachment.sql, [target, ...attachment.params()]),
    );
  assert.equal(await factCount(target), attachments.length);
});

test('facts and tokens written while a promotion holds the target wait, then are refused', async () => {
  const target = await pendingUser();
  const promoter = await openClient(connections.bootstrap);
  const writers: pg.Client[] = [];
  try {
    for (const a of attachments) writers.push(await openClient(connections[a.login]));
    await promoter.query('BEGIN');
    await promoter.query('SELECT 1 FROM app_user WHERE id=$1 FOR NO KEY UPDATE', [target]);
    await promoter.query(`UPDATE app_user SET kind='root' WHERE id=$1`, [target]);
    const waiting: { name: string; result: Promise<string> }[] = [];
    for (const [index, writer] of writers.entries()) {
      const attachment = attachments[index]!;
      const pid = await pidOf(writer);
      const result = outcome(writer.query(attachment.sql, [target, ...attachment.params()]));
      await waitUntilBlocked(pid);
      waiting.push({ name: attachment.name, result });
    }
    await promoter.query(
      'UPDATE security_bootstrap_state SET operation_id=$1,target_user_id=$2,initialized_at=statement_timestamp() WHERE singleton',
      [randomUUID(), target],
    );
    await promoter.query('COMMIT');
    for (const { name, result } of waiting) assert.equal(await result, '42501', name);
    assert.deepEqual(await migration.query('SELECT kind FROM app_user WHERE id=$1', [target]), [
      { kind: 'root' },
    ]);
    assert.equal(await factCount(target), 0);
  } finally {
    await promoter.end();
    for (const writer of writers) await writer.end();
  }
});
