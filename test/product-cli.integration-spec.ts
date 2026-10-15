import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, stat, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DataSource } from 'typeorm';
import { ProductAuthenticationError } from '@base-authorization/typeorm-postgres';
import {
  PRODUCT_OFFLINE_ACTOR,
  ProductIdentityService,
  ProductTransactionRunner,
  createProductPasswordHasher,
} from '@base-authorization/typeorm-postgres/composition';
import { productDataSourceOptions } from '@base-authorization/typeorm-postgres/operations';
import { startPostgres, withClient } from './setup-postgres.ts';
test('offline CLI provisions, forward migrates, syncs and bootstraps once without printing activation secret', async (t) => {
  const pg = await startPostgres();
  const dir = await mkdtemp(join(tmpdir(), 'product-cli-'));
  t.after(async () => {
    await pg.stop();
    await rm(dir, { recursive: true, force: true });
  });
  const c = pg.superuser;
  const purposes = [
    'data',
    'identity',
    'authority',
    'sync',
    'migration',
    'bootstrap',
    'outbox',
  ] as const;
  const env: Record<string, string> = {
    PATH: process.env.PATH || '',
    DATABASE_ADMIN_URL: `postgres://${c.username}:${c.password}@${c.host}:${c.port}/postgres`,
    PRODUCT_DATABASE_NAME: 'cli_fixture',
  };
  for (const p of purposes) {
    const password = randomBytes(24).toString('hex');
    env[`PRODUCT_${p.toUpperCase()}_PASSWORD`] = password;
    env[`PRODUCT_${p.toUpperCase()}_DATABASE_URL`] =
      `postgres://product_${p}:${password}@${c.host}:${c.port}/cli_fixture`;
  }
  function run(command: string, ...args: string[]) {
    const result = spawnSync(process.execPath, ['tools/product.ts', command, ...args], {
      env,
      encoding: 'utf8',
      timeout: 30000,
    });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout + result.stderr;
  }
  run('provision');
  run('migrate');
  assert.match(run('migrate'), /Applied 0/);
  run('sync');
  run('sync');
  // Session purge needs an explicit retention; nothing has expired yet.
  assert.match(run('purge-sessions', '--retention-days', '30'), /Purged 0 expired sessions/);
  const noRetention = spawnSync(process.execPath, ['tools/product.ts', 'purge-sessions'], {
    env,
    encoding: 'utf8',
    timeout: 30000,
  });
  assert.notEqual(noRetention.status, 0);
  assert.match(noRetention.stderr, /Product operation failed \(Error\)/);
  // The CLI publishes exactly the release the API runtime prepares (one codec composition).
  const { createProductAuthorizationCore, createProductRelease } =
    await import('../apps/api/dist/authorization/product-manifest.js');
  await withClient({ ...c, database: 'cli_fixture' }, async (client) => {
    const state = await client.query<{ hash: string }>(
      "SELECT encode(manifest_hash,'hex') hash FROM authz_state WHERE singleton",
    );
    assert.equal(state.rows[0]?.hash, createProductRelease(createProductAuthorizationCore()).hash);
  });
  const invited = randomUUID();
  const inviteArtifact = join(dir, 'invite-proof');
  const inviteOutput = run(
    'invite',
    '--user',
    invited,
    '--method',
    'local',
    '--email',
    'invite@example.test',
    '--activation-file',
    inviteArtifact,
  );
  const inviteProof = (await readFile(inviteArtifact, 'utf8')).trim();
  assert.match(inviteProof, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(inviteOutput.includes(inviteProof), false);
  assert.equal((await stat(inviteArtifact)).mode & 0o777, 0o600);
  const oidcInvited = randomUUID();
  const oidcArtifact = join(dir, 'oidc-invite-proof');
  run(
    'invite',
    '--user',
    oidcInvited,
    '--method',
    'oidc',
    '--issuer',
    'https://idp.example.test',
    '--subject',
    'cli-subject',
    '--activation-file',
    oidcArtifact,
  );
  assert.match((await readFile(oidcArtifact, 'utf8')).trim(), /^[A-Za-z0-9_-]{43}$/);
  await withClient({ ...c, database: 'cli_fixture' }, async (client) => {
    const rows = await client.query<{ purpose: string }>(
      'SELECT purpose FROM one_time_token WHERE user_id=$1',
      [oidcInvited],
    );
    assert.deepEqual(rows.rows, [{ purpose: 'oidc-activation' }]);
  });
  // An expired or lost invitation is reissued for the existing pending account.
  const reissued = join(dir, 'oidc-reissue-proof');
  assert.match(
    run('invite', '--user', oidcInvited, '--method', 'oidc', '--activation-file', reissued),
    /reissued/,
  );
  assert.notEqual(
    (await readFile(reissued, 'utf8')).trim(),
    (await readFile(oidcArtifact, 'utf8')).trim(),
  );
  await withClient({ ...c, database: 'cli_fixture' }, async (client) => {
    // The reissue supersedes the earlier (possibly lost) invitation.
    const live = await client.query<{ n: number }>(
      'SELECT count(*)::int n FROM one_time_token WHERE user_id=$1 AND consumed_at IS NULL',
      [oidcInvited],
    );
    assert.equal(live.rows[0]?.n, 1);
  });
  const unknown = spawnSync(
    process.execPath,
    [
      'tools/product.ts',
      'invite',
      '--user',
      randomUUID(),
      '--method',
      'local',
      '--activation-file',
      join(dir, 'unknown-proof'),
    ],
    { env, encoding: 'utf8', timeout: 30000 },
  );
  assert.notEqual(unknown.status, 0, 'reissue needs an existing pending account');
  await assert.rejects(readFile(join(dir, 'unknown-proof'), 'utf8'));
  const userId = randomUUID();
  const cliRevision = () =>
    withClient(
      { ...c, database: 'cli_fixture' },
      async (client) =>
        (await client.query<{ r: string }>('SELECT revision::text r FROM authz_state')).rows[0]!.r,
    );
  const beforeEnroll = await cliRevision();
  run('enroll', '--user', userId, '--method', 'local', '--email', 'root-cli@example.test');
  const afterEnroll = await cliRevision();
  assert.equal(BigInt(afterEnroll), BigInt(beforeEnroll) + 1n);
  await withClient({ ...c, database: 'cli_fixture' }, async (client) => {
    // Offline identity events: operator sentinel as actor, the enrolled/invited account as target.
    const enrolled = await client.query<{ actor: string; revision: string; metadata: object }>(
      `SELECT actor_id::text actor,policy_revision::text revision,safe_metadata metadata FROM audit_outbox WHERE event_kind=$1 AND safe_metadata->>'targetUserId'=$2`,
      [Buffer.from('identity.enroll'), userId],
    );
    assert.deepEqual(enrolled.rows, [
      {
        actor: PRODUCT_OFFLINE_ACTOR,
        revision: beforeEnroll,
        metadata: { method: 'local', targetUserId: userId, resultingRevision: afterEnroll },
      },
    ]);
    const invites = await client.query<{ actor: string; target: string }>(
      `SELECT actor_id::text actor,safe_metadata->>'targetUserId' target FROM audit_outbox WHERE event_kind=$1`,
      [Buffer.from('identity.invite')],
    );
    assert.ok(invites.rows.length > 0);
    for (const row of invites.rows) {
      assert.equal(row.actor, PRODUCT_OFFLINE_ACTOR);
      assert.ok(row.target && row.target !== row.actor);
    }
  });
  const outputPath = join(dir, 'activation-proof');
  const operation = randomUUID();
  const output = run(
    'bootstrap',
    '--user',
    userId,
    '--operation',
    operation,
    '--method',
    'local',
    '--activation-file',
    outputPath,
  );
  const proof = (await readFile(outputPath, 'utf8')).trim();
  assert.match(proof, /^[A-Za-z0-9_-]{43}$/);
  assert.doesNotMatch(output, new RegExp(proof));
  assert.equal((await stat(outputPath)).mode & 0o777, 0o600);
  assert.match(
    run(
      'bootstrap',
      '--user',
      userId,
      '--operation',
      operation,
      '--method',
      'local',
      '--activation-file',
      join(dir, 'retry'),
    ),
    /already committed/,
  );
  await assert.rejects(readFile(join(dir, 'retry'), 'utf8'));
  await withClient({ ...c, database: 'cli_fixture' }, async (client) => {
    assert.deepEqual(
      (await client.query('SELECT kind,state FROM app_user WHERE id=$1', [userId])).rows,
      [{ kind: 'root', state: 'pending' }],
    );
  });
  // A lost proof of the still pending Root is reissued by the bootstrap credential only.
  const reissuePath = join(dir, 'root-reissue-proof');
  assert.match(
    run('reissue-root', '--user', userId, '--method', 'local', '--activation-file', reissuePath),
    /reissued/,
  );
  assert.notEqual((await readFile(reissuePath, 'utf8')).trim(), proof);
  const notRoot = spawnSync(
    process.execPath,
    [
      'tools/product.ts',
      'reissue-root',
      '--user',
      invited,
      '--method',
      'local',
      '--activation-file',
      join(dir, 'not-root-proof'),
    ],
    { env, encoding: 'utf8', timeout: 30000 },
  );
  assert.notEqual(notRoot.status, 0);
  // Diagnosable without secrets: class and reason enum only.
  assert.match(notRoot.stderr, /\(ReleaseRejectedError collision\)/);
  await assert.rejects(readFile(join(dir, 'not-root-proof'), 'utf8'));
  // enroll → bootstrap → activation (only the reissued proof works) → login.
  const identitySource = await new DataSource(
    productDataSourceOptions({
      host: c.host,
      port: c.port,
      username: 'product_identity',
      password: env['PRODUCT_IDENTITY_PASSWORD'] ?? '',
      database: 'cli_fixture',
    }),
  ).initialize();
  try {
    const identityRunner = new ProductTransactionRunner({ identity: identitySource });
    const identity = new ProductIdentityService(
      identityRunner,
      await createProductPasswordHasher(new Set()),
    );
    const rootPassword = 'a long unique cli root password';
    await assert.rejects(
      identity.activate(proof, rootPassword, 'cli-root'),
      ProductAuthenticationError,
    );
    await identity.activate((await readFile(reissuePath, 'utf8')).trim(), rootPassword, 'cli-root');
    const session = await identity.login('root-cli@example.test', rootPassword, 'cli-root');
    const revoke = (...extra: string[]) =>
      run('revoke-root', '--user', userId, '--operation', randomUUID(), ...extra);
    const refused = spawnSync(
      process.execPath,
      ['tools/product.ts', 'revoke-root', '--user', userId, '--operation', randomUUID()],
      { env, encoding: 'utf8', timeout: 30000 },
    );
    assert.notEqual(refused.status, 0, 'approval and reason are mandatory');
    assert.match(revoke('--approval', 'CHG-1', '--reason', 'Fixture handover'), /Root suspended/);
    assert.match(revoke('--approval', 'CHG-1', '--reason', 'Fixture retry'), /nothing changed/);
    await withClient({ ...c, database: 'cli_fixture' }, async (client) => {
      const rows = await client.query<{
        kind: string;
        state: string;
        marker: boolean;
        audit: number;
      }>(
        `SELECT (SELECT kind FROM app_user WHERE id=$1) kind,(SELECT state FROM app_user WHERE id=$1) state,
        (SELECT initialized_at IS NOT NULL FROM security_bootstrap_state) marker,
        (SELECT count(*)::int FROM audit_outbox WHERE event_kind=$2 AND reason='Fixture handover') audit`,
        [userId, Buffer.from('root.revoke')],
      );
      assert.deepEqual(rows.rows[0], { kind: 'root', state: 'suspended', marker: true, audit: 1 });
    });
    // The suspended Root cannot log in, and the session it held before the revocation is dead.
    await assert.rejects(
      identity.login('root-cli@example.test', rootPassword, 'cli-root'),
      ProductAuthenticationError,
    );
    await assert.rejects(
      identityRunner.run('identity', (tx) => identity.authenticate(tx, session.secret)),
      ProductAuthenticationError,
    );
    // The marker is permanent: no bootstrap after a revocation.
    const next = randomUUID();
    run('enroll', '--user', next, '--method', 'local', '--email', 'next-root@example.test');
    const again = spawnSync(
      process.execPath,
      [
        'tools/product.ts',
        'bootstrap',
        '--user',
        next,
        '--operation',
        randomUUID(),
        '--method',
        'local',
        '--activation-file',
        join(dir, 'again-proof'),
      ],
      { env, encoding: 'utf8', timeout: 30000 },
    );
    assert.notEqual(again.status, 0);
    assert.match(again.stderr, /\(ReleaseRejectedError collision\)/);
    await assert.rejects(readFile(join(dir, 'again-proof'), 'utf8'));
    // root.* audit: the offline actor acts, the Root account is the target.
    await withClient({ ...c, database: 'cli_fixture' }, async (client) => {
      const rows = await client.query<{ kind: string; actor: string; target: string }>(
        `SELECT convert_from(event_kind,'UTF8') kind,actor_id::text actor,safe_metadata->>'targetUserId' target
       FROM audit_outbox WHERE convert_from(event_kind,'UTF8') LIKE 'root.%' ORDER BY occurred_at,event_id`,
      );
      assert.deepEqual(
        rows.rows.map((r) => [r.kind, r.actor, r.target]),
        [
          ['root.bootstrap', PRODUCT_OFFLINE_ACTOR, userId],
          ['root.reissue', PRODUCT_OFFLINE_ACTOR, userId],
          ['root.revoke', PRODUCT_OFFLINE_ACTOR, userId],
        ],
      );
    });
  } finally {
    await identitySource.destroy();
  }
});

test('offline CLI refuses the offline actor id as a user for enroll, invite, bootstrap and reissue-root', async (t) => {
  const pg = await startPostgres();
  const dir = await mkdtemp(join(tmpdir(), 'product-cli-actor-'));
  t.after(async () => {
    await pg.stop();
    await rm(dir, { recursive: true, force: true });
  });
  const c = pg.superuser;
  const env: Record<string, string> = {
    PATH: process.env.PATH || '',
    DATABASE_ADMIN_URL: `postgres://${c.username}:${c.password}@${c.host}:${c.port}/postgres`,
    PRODUCT_DATABASE_NAME: 'cli_actor_fixture',
  };
  for (const p of ['data', 'identity', 'authority', 'sync', 'migration', 'bootstrap', 'outbox']) {
    const password = randomBytes(24).toString('hex');
    env[`PRODUCT_${p.toUpperCase()}_PASSWORD`] = password;
    env[`PRODUCT_${p.toUpperCase()}_DATABASE_URL`] =
      `postgres://product_${p}:${password}@${c.host}:${c.port}/cli_actor_fixture`;
  }
  const cli = (command: string, ...args: string[]) =>
    spawnSync(process.execPath, ['tools/product.ts', command, ...args], {
      env,
      encoding: 'utf8',
      timeout: 30000,
    });
  for (const setup of ['provision', 'migrate', 'sync']) assert.equal(cli(setup).status, 0, setup);
  const user = ['--user', PRODUCT_OFFLINE_ACTOR];
  const artifact = (name: string) => ['--activation-file', join(dir, name)];
  const attempts: [string, string[], RegExp][] = [
    ['enroll', [...user, '--method', 'local', '--email', 'actor@example.test'], /\(Error\)/],
    ['invite', [...user, '--method', 'local', ...artifact('invite-proof')], /\(Error\)/],
    [
      'bootstrap',
      [...user, '--operation', randomUUID(), '--method', 'local', ...artifact('b-proof')],
      /ReleaseRejectedError invalid_release/,
    ],
    [
      'reissue-root',
      [...user, '--method', 'local', ...artifact('r-proof')],
      /ReleaseRejectedError invalid_release/,
    ],
  ];
  for (const [command, args, failure] of attempts) {
    const result = cli(command, ...args);
    assert.notEqual(result.status, 0, `${command} must refuse the offline actor id`);
    assert.match(result.stderr, failure, command);
  }
  await withClient({ ...c, database: 'cli_actor_fixture' }, async (client) => {
    const rows = await client.query('SELECT 1 FROM app_user WHERE id=$1', [PRODUCT_OFFLINE_ACTOR]);
    assert.equal(rows.rowCount, 0);
  });
});
