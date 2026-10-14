import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, stat, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startPostgres, withClient } from './setup-postgres.ts';
test('offline CLI provisions, forward migrates, syncs and bootstraps once without printing activation secret', async (t) => {
  const pg = await startPostgres();
  const dir = await mkdtemp(join(tmpdir(), 'product-cli-'));
  t.after(async () => {
    await pg.stop();
    await rm(dir, { recursive: true, force: true });
  });
  const c = pg.superuser;
  const purposes = ['data', 'identity', 'authority', 'sync', 'migration', 'bootstrap'] as const;
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
  run('enroll', '--user', userId, '--method', 'local', '--email', 'root-cli@example.test');
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
    assert.equal(
      (
        await client.query<{ n: number }>(
          'SELECT count(*)::int n FROM user_role WHERE user_id=$1',
          [userId],
        )
      ).rows[0]?.n,
      1,
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
  const revoke = (...extra: string[]) =>
    run('revoke-root', '--user', userId, '--operation', randomUUID(), ...extra);
  const refused = spawnSync(
    process.execPath,
    ['tools/product.ts', 'revoke-root', '--user', userId, '--operation', randomUUID()],
    { env, encoding: 'utf8', timeout: 30000 },
  );
  assert.notEqual(refused.status, 0, 'approval and reason are mandatory');
  assert.match(
    revoke('--approval', 'CHG-1', '--reason', 'Fixture handover'),
    /Root assignment revoked/,
  );
  assert.match(revoke('--approval', 'CHG-1', '--reason', 'Fixture retry'), /nothing changed/);
  await withClient({ ...c, database: 'cli_fixture' }, async (client) => {
    const rows = await client.query<{ n: number; marker: boolean; audit: number }>(
      `SELECT (SELECT count(*)::int FROM user_role WHERE user_id=$1) n,
        (SELECT initialized_at IS NOT NULL FROM security_bootstrap_state) marker,
        (SELECT count(*)::int FROM audit_outbox WHERE event_kind=$2 AND reason='Fixture handover') audit`,
      [userId, Buffer.from('root.revoke')],
    );
    assert.deepEqual(rows.rows[0], { n: 0, marker: true, audit: 1 });
  });
});
