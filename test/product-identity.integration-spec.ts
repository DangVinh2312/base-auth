import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { randomBytes, randomUUID, createHash, generateKeyPairSync, createSign } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { DataSource } from 'typeorm';
import * as oidc from 'openid-client';
import {
  productDataSourceOptions,
  provisionProductDatabase,
} from '@base-authorization/typeorm-postgres/operations';
import { ProductTransactionRunner } from '@base-authorization/typeorm-postgres/composition';
import {
  ProductAuthenticationError,
  TransactionConflictError,
} from '@base-authorization/typeorm-postgres';
import {
  PRODUCT_OFFLINE_ACTOR,
  ProductIdentityService,
  createProductPasswordHasher,
  newSessionSecret,
  purgeExpiredSessions,
  sessionDigest,
} from '@base-authorization/typeorm-postgres/composition';
import { type ProductOidcProvider } from '@base-authorization/typeorm-postgres';
import { ProductOidcService } from '@base-authorization/typeorm-postgres/composition';
import {
  ProductAuthorization,
  ProductBindingRegistry,
  ProductManifestReconciler,
  productObligations,
} from '@base-authorization/typeorm-postgres/composition';
import type { IdentityId } from '@base-authorization/core';
import {
  createProductAuthorizationCore,
  createProductRelease,
  productBindings,
} from '../apps/api/dist/authorization/product-manifest.js';
import { ProductDocument1792108800002 } from '../apps/api/dist/documents/migrations/product-document.js';
import { startPostgres, withClient, type TestPostgres } from './setup-postgres.ts';

let postgres: TestPostgres;
let pools: Record<'data' | 'identity' | 'authority' | 'sync' | 'bootstrap', DataSource>;
let fixtureAdmin: DataSource;
let connections: Awaited<ReturnType<typeof provisionProductDatabase>>;
let identity: ProductIdentityService;
let runner: ProductTransactionRunner;
let provider: ProductOidcProvider;
let federation: ProductOidcService;
let server: Server;
const issuer = 'https://issuer.fixture';
const redirectUri = 'https://app.fixture/oidc/callback';
const subject = 'exact-subject';
const userId = randomUUID();
const core = createProductAuthorizationCore();
const productRelease = createProductRelease(core);
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = {
  ...publicKey.export({ format: 'jwk' }),
  kid: 'fixture-key',
  alg: 'RS256',
  use: 'sig',
};
const codes = new Map<
  string,
  { nonce: string; challenge: string; changes: Record<string, unknown>; badSignature: boolean }
>();
let tokenGate: (() => Promise<void>) | undefined;
function jwt(claims: Record<string, unknown>, badSignature: boolean): string {
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'fixture-key' })).toString(
    'base64url',
  );
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const signature = createSign('RSA-SHA256')
    .update(`${header}.${payload}`)
    .sign(privateKey)
    .toString('base64url');
  return `${header}.${payload}.${badSignature ? Buffer.alloc(256).toString('base64url') : signature}`;
}
function responseFor(url: URL, changes: Record<string, unknown> = {}, badSignature = false): URL {
  const code = randomBytes(16).toString('hex');
  codes.set(code, {
    nonce: url.searchParams.get('nonce')!,
    challenge: url.searchParams.get('code_challenge')!,
    changes,
    badSignature,
  });
  const response = new URL(redirectUri);
  response.searchParams.set('state', url.searchParams.get('state')!);
  response.searchParams.set('code', code);
  return response;
}
before(async () => {
  postgres = await startPostgres();
  const secrets = Object.fromEntries(
    ['data', 'identity', 'authority', 'sync', 'bootstrap', 'migration', 'outbox'].map((p) => [
      p,
      randomBytes(20).toString('hex'),
    ]),
  ) as Record<
    'data' | 'identity' | 'authority' | 'sync' | 'bootstrap' | 'migration' | 'outbox',
    string
  >;
  connections = await provisionProductDatabase(postgres.superuser, secrets);
  pools = {} as typeof pools;
  for (const purpose of ['data', 'identity', 'authority', 'sync', 'bootstrap'] as const)
    pools[purpose] = await new DataSource(
      productDataSourceOptions(connections[purpose]),
    ).initialize();
  fixtureAdmin = await new DataSource(productDataSourceOptions(connections.migration)).initialize();
  runner = new ProductTransactionRunner(pools);
  identity = new ProductIdentityService(
    runner,
    await createProductPasswordHasher(new Set(['a common bad password'])),
  );
  await fixtureAdmin.query(
    `INSERT INTO app_user(id,email_canonical,state) VALUES($1,'local@example.test','pending')`,
    [userId],
  );
  await fixtureAdmin.query(`INSERT INTO oidc_provider(issuer,version,enabled) VALUES($1,1,true)`, [
    issuer,
  ]);
  server = createServer((req, res) => {
    void (async () => {
      res.setHeader('content-type', 'application/json');
      if (req.url === '/jwks') {
        res.end(JSON.stringify({ keys: [jwk] }));
        return;
      }
      if (req.url !== '/token') {
        res.writeHead(404).end();
        return;
      }
      let body = '';
      for await (const chunk of req) body += String(chunk);
      const input = new URLSearchParams(body);
      const code = input.get('code');
      const attempt = code ? codes.get(code) : undefined;
      if (
        !attempt ||
        createHash('sha256')
          .update(input.get('code_verifier') ?? '')
          .digest('base64url') !== attempt.challenge ||
        input.get('redirect_uri') !== redirectUri
      ) {
        res.writeHead(400).end(JSON.stringify({ error: 'invalid_grant' }));
        return;
      }
      codes.delete(code!);
      await tokenGate?.();
      const now = Math.floor(Date.now() / 1000);
      res.end(
        JSON.stringify({
          access_token: 'fixture-access-token',
          token_type: 'Bearer',
          expires_in: 300,
          id_token: jwt(
            {
              iss: issuer,
              sub: subject,
              aud: 'fixture-client',
              iat: now,
              exp: now + 300,
              auth_time: now,
              nonce: attempt.nonce,
              ...attempt.changes,
            },
            attempt.badSignature,
          ),
        }),
      );
    })().catch(() => {
      res.writeHead(500).end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  const configuration = new oidc.Configuration(
    {
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      jwks_uri: `${issuer}/jwks`,
      id_token_signing_alg_values_supported: ['RS256'],
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
    },
    'fixture-client',
    { id_token_signed_response_alg: 'RS256' },
    oidc.None(),
  );
  configuration[oidc.customFetch] = (input, init) => {
    const target = new URL(input);
    assert.equal(target.origin, issuer);
    return fetch(`http://127.0.0.1:${port}${target.pathname}`, {
      ...init,
      body:
        init.body instanceof URLSearchParams
          ? init.body.toString()
          : typeof init.body === 'string'
            ? init.body
            : init.body instanceof Uint8Array
              ? new TextDecoder().decode(init.body)
              : undefined,
    });
  };
  provider = {
    settings: {
      issuer,
      clientId: 'fixture-client',
      redirectUri,
      version: '1',
      assuranceMappings: [{ acr: 'urn:fixture:mfa', amr: ['pwd', 'otp'], assurance: 'mfa' }],
    },
    configuration,
  };
  federation = new ProductOidcService(identity, new Map([[issuer, provider]]));
});
after(async () => {
  await new Promise<void>((resolve) => {
    if (server) server.close(() => resolve());
    else resolve();
  });
  for (const source of Object.values(pools ?? {})) await source.destroy();
  await fixtureAdmin?.destroy();
  await postgres?.stop();
});

test('OIDC fixture validates a signed token with actual PKCE and nonce checks', async () => {
  const verifier = oidc.randomPKCECodeVerifier();
  const state = oidc.randomState();
  const nonce = oidc.randomNonce();
  const start = oidc.buildAuthorizationUrl(provider.configuration, {
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid',
    state,
    nonce,
    code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
    code_challenge_method: 'S256',
  });
  const response = await oidc.authorizationCodeGrant(provider.configuration, responseFor(start), {
    pkceCodeVerifier: verifier,
    expectedState: state,
    expectedNonce: nonce,
    idTokenExpected: true,
  });
  assert.equal(response.claims()?.sub, subject);
});

test('local activation, opaque hash-only sessions, one-time reset races and stale login proof', async () => {
  const activation = await runner.run('revoke', (tx) => identity.issueActivation(tx, userId));
  await identity.activate(activation, 'a very strong password', 'local-fixture');
  await assert.rejects(
    identity.activate(activation, 'another long password', 'local-fixture'),
    ProductAuthenticationError,
  );
  const session = await identity.login(
    'LOCAL@EXAMPLE.TEST',
    'a very strong password',
    'local-fixture',
  );
  assert.equal(
    (await runner.run('read', (tx) => identity.authenticate(tx, session.secret))).userId,
    userId,
  );
  assert.equal(
    (
      await pools.identity.query<{ token_hash: Buffer }[]>(
        'SELECT token_hash FROM application_session',
      )
    )[0]!.token_hash.equals(sessionDigest(session.secret)),
    true,
  );
  const reset = await identity.requestPasswordReset('local@example.test', 'local-fixture');
  assert.ok(reset);
  const result = await Promise.allSettled([
    identity.resetPassword(reset.token, 'new extremely strong password', 'local-fixture'),
    identity.resetPassword(reset.token, 'new extremely strong password', 'local-fixture'),
  ]);
  assert.equal(result.filter((r) => r.status === 'fulfilled').length, 1);
  await assert.rejects(
    runner.run('read', (tx) => identity.authenticate(tx, session.secret)),
    ProductAuthenticationError,
  );
  await assert.rejects(
    identity.login('local@example.test', 'a very strong password', 'local-fixture'),
    ProductAuthenticationError,
  );
  const fresh = await identity.login(
    'local@example.test',
    'new extremely strong password',
    'local-fixture',
  );
  await identity.logout(fresh.secret, true);
  await assert.rejects(
    runner.run('read', (tx) => identity.authenticate(tx, fresh.secret)),
    ProductAuthenticationError,
  );
});

test('a limited client cannot grow the limiter or lock out other clients', async () => {
  const rows = async () =>
    (await pools.identity.query<{ n: number }[]>('SELECT count(*)::int n FROM rate_limit'))[0]!.n;
  const before = await rows();
  let rejected = 0;
  for (let i = 0; i < 100; i++)
    await identity
      .rateLimit('flooding-client', `flood${i}@example.test`, 'flood-fixture')
      .catch(() => rejected++);
  assert.equal(rejected, 80);
  // One client bucket plus the 20 identifier buckets it was allowed before being limited.
  assert.equal((await rows()) - before, 21);
  await identity.rateLimit('other-client', 'flood0@example.test', 'flood-fixture');
});

test('a full limiter evicts instead of denying every client', async () => {
  // Synthetic buckets from many sources, still inside their 15 minute window.
  await pools.identity.query(
    `INSERT INTO rate_limit(bucket_key,window_start,attempts)
     SELECT sha256(convert_to('saturation-fixture:'||g,'UTF8')),statement_timestamp()-interval '1 minute',1
     FROM generate_series(1,10000) g ON CONFLICT DO NOTHING`,
  );
  await identity.rateLimit('fresh-client', 'fresh@example.test', 'saturation-fixture');
  const [count] = await pools.identity.query<{ n: number }[]>(
    'SELECT count(*)::int n FROM rate_limit',
  );
  assert.ok(count!.n <= 10000, `limiter holds ${count!.n} rows`);
  await pools.identity.query(
    `DELETE FROM rate_limit WHERE bucket_key IN
     (SELECT sha256(convert_to('saturation-fixture:'||g,'UTF8')) FROM generate_series(1,10000) g)`,
  );
});

test('eviction drops the fewest attempts first: a flood cannot reset a used or locked bucket', async () => {
  for (let i = 0; i < 19; i++)
    await identity.rateLimit(`near-${i}`, 'near@example.test', 'lock-fixture');
  for (let i = 0; i < 20; i++)
    await identity.rateLimit(`locker-${i}`, 'locked@example.test', 'lock-fixture');
  await assert.rejects(
    identity.rateLimit('locker-next', 'locked@example.test', 'lock-fixture'),
    ProductAuthenticationError,
  );
  // Newer unlocked buckets from many sources fill the table.
  await pools.identity.query(
    `INSERT INTO rate_limit(bucket_key,window_start,attempts)
     SELECT sha256(convert_to('lock-flood:'||g,'UTF8')),statement_timestamp(),1
     FROM generate_series(1,10000) g ON CONFLICT DO NOTHING`,
  );
  await identity.rateLimit('fresh-locker', 'other@example.test', 'lock-fixture');
  // The bucket at 19 attempts survived: one more is allowed, then it locks.
  await identity.rateLimit('near-last', 'near@example.test', 'lock-fixture');
  await assert.rejects(
    identity.rateLimit('near-over', 'near@example.test', 'lock-fixture'),
    ProductAuthenticationError,
  );
  await assert.rejects(
    identity.rateLimit('another-locker', 'locked@example.test', 'lock-fixture'),
    ProductAuthenticationError,
  );
  await pools.identity.query(
    `DELETE FROM rate_limit WHERE bucket_key IN
     (SELECT sha256(convert_to('lock-flood:'||g,'UTF8')) FROM generate_series(1,10000) g)`,
  );
});

test('one IPv6 /48 shares 200 attempts across its /64 clients and all purposes', async () => {
  let accepted = 0;
  for (let i = 0; i < 220; i++)
    await identity
      .rateLimit(
        `2001:db8:48:${Math.floor(i / 19).toString(16)}::1`,
        `net${i}@example.test`,
        i % 2 ? 'net-a' : 'net-b',
      )
      .then(() => accepted++)
      .catch(() => undefined);
  assert.equal(accepted, 200);
  await identity.rateLimit('2001:db8:49::1', 'other-net@example.test', 'net-a');
});

test('reset tokens never reach the audit outbox in plaintext or digest form', async () => {
  const password = 'reset audit strong password';
  const [email] = await activeLocalUsers('resetaudit', 1, password);
  const reset = await identity.requestPasswordReset(email!, '198.51.100.60');
  assert.ok(reset);
  await identity.resetPassword(reset.token, 'reset audit newer password', '198.51.100.60');
  const digest = sessionDigest(reset.token).toString('hex');
  const leaked = await fixtureAdmin.query<{ n: number }[]>(
    `SELECT count(*)::int n FROM audit_outbox WHERE position($1 IN concat_ws(' ',reason,safe_metadata::text))>0
       OR position($2 IN concat_ws(' ',reason,safe_metadata::text))>0`,
    [reset.token, digest],
  );
  assert.equal(leaked[0]!.n, 0);
});

test('database rate limiter is shared across service replicas and generic absent login fails', async () => {
  const replica = new ProductIdentityService(runner, identity.passwords);
  for (let i = 0; i < 20; i++)
    await (i % 2 ? replica : identity).rateLimit(
      'replica-fixture',
      'limited@example.test',
      'limit-fixture',
    );
  await assert.rejects(
    replica.rateLimit('replica-fixture', 'limited@example.test', 'limit-fixture'),
    ProductAuthenticationError,
  );
  await assert.rejects(
    identity.login('absent@example.test', 'a very strong password', 'absent-fixture'),
    { message: 'Authentication failed' },
  );
});

test('limiter calls queued on the advisory lock do not hold the fence against a revoke', async () => {
  const password = 'queue strong password';
  const [email] = await activeLocalUsers('queue', 1, password);
  const session = await identity.login(email!, password, '198.51.100.30');
  await withClient(connections.identity, async (blocker) => {
    // Another session holds the limiter's advisory key, so limiter transactions queue behind it.
    await blocker.query('SELECT pg_advisory_lock(1379171467)');
    let queued: Promise<PromiseSettledResult<void>[]>;
    let revokeMs: number | undefined;
    try {
      queued = Promise.allSettled(
        [1, 2, 3].map((i) =>
          identity.rateLimit(`198.51.100.${40 + i}`, `queue${i}@example.test`, 'queue'),
        ),
      );
      await new Promise((resolve) => setTimeout(resolve, 100));
      const start = Date.now();
      const revoke = identity.logout(session.secret).then(() => (revokeMs = Date.now() - start));
      await Promise.race([revoke, new Promise((resolve) => setTimeout(resolve, 500))]);
    } finally {
      await blocker.query('SELECT pg_advisory_unlock(1379171467)');
    }
    const outcomes = await queued;
    await new Promise((resolve) => setTimeout(resolve, 0));
    assert.ok(
      revokeMs !== undefined && revokeMs < 500,
      `revoke blocked for ${revokeMs ?? '>500'} ms`,
    );
    assert.deepEqual(
      outcomes.map((o) => o.status),
      ['fulfilled', 'fulfilled', 'fulfilled'],
    );
  });
  await assert.rejects(
    runner.run('read', (tx) => identity.authenticate(tx, session.secret)),
    ProductAuthenticationError,
  );
});

test('real signed OIDC code+PKCE, claims rejection, state/browser replay, and no email linking', async () => {
  await pools.identity.query(
    `INSERT INTO external_identity(issuer,subject,user_id) VALUES($1,$2,$3)`,
    [issuer, subject, userId],
  );
  const browser = newSessionSecret();
  const authorization = await federation.begin(issuer, browser, {}, 'oidc-success');
  assert.equal(authorization.searchParams.get('code_challenge_method'), 'S256');
  const callback = responseFor(authorization);
  await assert.rejects(
    federation.callback(issuer, callback, newSessionSecret()),
    ProductAuthenticationError,
  );
  const session = await federation.callback(undefined, callback, browser);
  assert.ok(session);
  const actor = await runner.run('read', (tx) => identity.authenticate(tx, session.secret));
  assert.equal(actor.userId, userId);
  assert.equal(actor.assurance, 'oidc');
  await new ProductManifestReconciler(runner, {
    core,
    actor: userId as IdentityId,
    capabilities: { validators: ['fresh@1'], obligationHandlers: ['audit@1'] },
  }).reconcile(productRelease);
  const migration = fixtureAdmin.createQueryRunner();
  await new ProductDocument1792108800002().up(migration);
  await migration.release();
  const objectId = randomUUID();
  await runner.run('admin', async (tx) => {
    await tx.manager.query(
      "INSERT INTO object_ref(object_id,type_key,key_kind,key_bytes) VALUES($1,$2,'uuid',$3)",
      [objectId, Buffer.from('document'), Buffer.from(objectId)],
    );
    await tx.manager.query(
      "INSERT INTO policy_rule(rule_id,permission_key,user_id,effect,template_key,template_version,parameters,managed_by) VALUES($1,$2,$3,'allow',$4,1,'{}','runtime')",
      [randomUUID(), Buffer.from('document.read'), userId, Buffer.from('ownedDocuments')],
    );
  });
  await fixtureAdmin.query(
    "INSERT INTO document(id,object_id,owner_id,title,state) VALUES($1,$1,$2,'same authorization','draft')",
    [objectId, userId],
  );
  const authorizationService = new ProductAuthorization(
    runner,
    new ProductBindingRegistry(core, productRelease.declarations, productBindings),
    {
      validators: { 'fresh@1': (_parameters, input) => input.context.freshAuthentication === true },
      obligations: productObligations,
    },
  );
  const localSession = await identity.login(
    'local@example.test',
    'new extremely strong password',
    'hybrid-parity',
  );
  assert.deepEqual(
    await authorizationService.list(session.secret, 'document', 'read'),
    await authorizationService.list(localSession.secret, 'document', 'read'),
  );
  await runner.run('admin', (tx) =>
    tx.manager.query(
      "INSERT INTO policy_rule(rule_id,permission_key,user_id,effect,template_key,template_version,parameters,managed_by) VALUES($1,$2,$3,'deny',$4,1,'{}','runtime')",
      [randomUUID(), Buffer.from('document.read'), userId, Buffer.from('ownedDocuments')],
    ),
  );
  assert.equal((await authorizationService.list(session.secret, 'document', 'read')).total, '0');
  assert.equal(
    (await authorizationService.list(localSession.secret, 'document', 'read')).total,
    '0',
  );

  await assert.rejects(federation.callback(issuer, callback, browser), ProductAuthenticationError);
  for (const [index, changes, badSignature] of [
    [0, { iss: 'https://evil.fixture' }, false],
    [1, { aud: 'wrong-client' }, false],
    [2, { nonce: 'wrong-nonce' }, false],
    [3, { exp: 1 }, false],
    [4, {}, true],
    [
      5,
      {
        sub: 'unbound-subject',
        email: 'local@example.test',
        email_verified: true,
        groups: ['system.root'],
      },
      false,
    ],
    [6, { aud: ['fixture-client', 'other-client'], azp: 'other-client' }, false],
  ] as const) {
    const browserSecret = newSessionSecret();
    const start = await federation.begin(issuer, browserSecret, {}, `oidc-reject-${index}`);
    await assert.rejects(
      federation.callback(issuer, responseFor(start, changes, badSignature), browserSecret),
      ProductAuthenticationError,
    );
  }
  const mfaBrowser = newSessionSecret();
  const mfaStart = await federation.begin(issuer, mfaBrowser, {}, 'oidc-mfa');
  const mfa = await federation.callback(
    issuer,
    responseFor(mfaStart, { acr: 'urn:fixture:mfa', amr: ['pwd', 'otp'] }),
    mfaBrowser,
  );
  assert.ok(mfa);
  assert.equal(
    (await runner.run('read', (tx) => identity.authenticate(tx, mfa.secret))).assurance,
    'mfa',
  );
});

test('password reset committed while login verification is paused rejects the old proof', async () => {
  let entered!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => (entered = resolve));
  const hold = new Promise<void>((resolve) => (release = resolve));
  const delayed = new ProductIdentityService(runner, {
    ...identity.passwords,
    async verify(hash, password) {
      const result = await identity.passwords.verify(hash, password);
      entered();
      await hold;
      return result;
    },
  });
  const login = delayed.login(
    'local@example.test',
    'new extremely strong password',
    'password-race',
  );
  await ready;
  const reset = await identity.requestPasswordReset('local@example.test', 'password-race');
  assert.ok(reset);
  await identity.resetPassword(reset.token, 'the newest strong password', 'password-race');
  release();
  await assert.rejects(login, ProductAuthenticationError);
});

test('link requires recent reauthentication, rotates sessions, and unlink cannot remove the last method', async () => {
  const local = await identity.login(
    'local@example.test',
    'the newest strong password',
    'link-fixture',
  );
  await assert.rejects(
    federation.begin(
      issuer,
      newSessionSecret(),
      { purpose: 'link', sessionSecret: local.secret },
      'link-fixture',
    ),
    ProductAuthenticationError,
  );
  const fresh = await identity.reauthenticate(
    local.secret,
    'the newest strong password',
    'link-fixture',
  );
  await assert.rejects(
    runner.run('read', (tx) => identity.authenticate(tx, local.secret)),
    ProductAuthenticationError,
  );
  const browser = newSessionSecret();
  const start = await federation.begin(
    issuer,
    browser,
    { purpose: 'link', sessionSecret: fresh.secret },
    'link-fixture',
  );
  assert.equal(
    await federation.callback(
      issuer,
      responseFor(start, { sub: 'linked-subject' }),
      browser,
      fresh.secret,
    ),
    undefined,
  );
  await assert.rejects(
    runner.run('read', (tx) => identity.authenticate(tx, fresh.secret)),
    ProductAuthenticationError,
  );
  const next = await identity.login(
    'local@example.test',
    'the newest strong password',
    'unlink-fixture',
  );
  const reauthenticated = await identity.reauthenticate(
    next.secret,
    'the newest strong password',
    'unlink-fixture',
  );
  await federation.unlink(reauthenticated.secret, issuer, 'linked-subject');
  assert.equal(
    (
      await pools.identity.query<{ enabled: boolean }[]>(
        `SELECT enabled FROM external_identity WHERE issuer=$1 AND subject='linked-subject'`,
        [issuer],
      )
    )[0]!.enabled,
    false,
  );
  const relinkLogin = await identity.login(
    'local@example.test',
    'the newest strong password',
    'relink-fixture',
  );
  const relinkProof = await identity.reauthenticate(
    relinkLogin.secret,
    'the newest strong password',
    'relink-fixture',
  );
  const relinkBrowser = newSessionSecret();
  const relinkStart = await federation.begin(
    issuer,
    relinkBrowser,
    { purpose: 'link', sessionSecret: relinkProof.secret },
    'relink-fixture',
  );
  await federation.callback(
    issuer,
    responseFor(relinkStart, { sub: 'linked-subject' }),
    relinkBrowser,
    relinkProof.secret,
  );
  const relinked = (
    await pools.identity.query<{ enabled: boolean; binding_version: string }[]>(
      `SELECT enabled,binding_version FROM external_identity WHERE issuer=$1 AND subject='linked-subject'`,
      [issuer],
    )
  )[0]!;
  assert.equal(relinked.enabled, true);
  assert.equal(relinked.binding_version, '3');
  const id = randomUUID();
  await fixtureAdmin.query(
    `INSERT INTO app_user(id,email_canonical,state) VALUES($1,'last-method@example.test','active')`,
    [id],
  );
  await pools.identity.query(
    `INSERT INTO external_identity(issuer,subject,user_id) VALUES($1,'last-method',$2)`,
    [issuer, id],
  );
  const oidcBrowser = newSessionSecret();
  const oidcStart = await federation.begin(issuer, oidcBrowser, {}, 'last-fixture');
  const session = await federation.callback(
    issuer,
    responseFor(oidcStart, { sub: 'last-method' }),
    oidcBrowser,
  );
  assert.ok(session);
  const reauthBrowser = newSessionSecret();
  const reauthStart = await federation.begin(
    issuer,
    reauthBrowser,
    { purpose: 'reauth', sessionSecret: session.secret },
    'last-fixture',
  );
  const proof = await federation.callback(
    issuer,
    responseFor(reauthStart, { sub: 'last-method' }),
    reauthBrowser,
    session.secret,
  );
  assert.ok(proof);
  await assert.rejects(
    federation.unlink(proof.secret, issuer, 'last-method'),
    ProductAuthenticationError,
  );
});

test('session absolute and idle deadlines fail closed and suspended password reset does not reactivate', async () => {
  const expired = await identity.login(
    'local@example.test',
    'the newest strong password',
    'expiry-fixture',
  );
  const timing = (
    await pools.identity.query<{ lifetime: number }[]>(
      `SELECT extract(epoch FROM (expires_at-created_at))::int AS lifetime FROM application_session WHERE token_hash=$1`,
      [sessionDigest(expired.secret)],
    )
  )[0]!;
  assert.equal(timing.lifetime, 43200);
  await runner.run('revoke', (tx) =>
    tx.manager.query(
      `UPDATE application_session SET last_seen_at=statement_timestamp()-interval '31 minutes' WHERE token_hash=$1`,
      [sessionDigest(expired.secret)],
    ),
  );
  await assert.rejects(
    runner.run('read', (tx) => identity.authenticate(tx, expired.secret)),
    ProductAuthenticationError,
  );
  const absolute = await identity.login(
    'local@example.test',
    'the newest strong password',
    'expiry-fixture',
  );
  await runner.run('revoke', (tx) =>
    tx.manager.query(
      `UPDATE application_session SET created_at=statement_timestamp()-interval '13 hours',expires_at=statement_timestamp()-interval '1 hour' WHERE token_hash=$1`,
      [sessionDigest(absolute.secret)],
    ),
  );
  await assert.rejects(
    runner.run('read', (tx) => identity.authenticate(tx, absolute.secret)),
    ProductAuthenticationError,
  );
  const reset = await identity.requestPasswordReset('local@example.test', 'suspend-reset-fixture');
  assert.ok(reset);
  // Suspension is an authority decision; identity can only activate pending accounts.
  await runner.run('admin', (tx) =>
    tx.manager.query(`UPDATE app_user SET state='suspended',auth_epoch=auth_epoch+1 WHERE id=$1`, [
      userId,
    ]),
  );
  await identity.resetPassword(
    reset.token,
    'suspended strong new password',
    'suspend-reset-fixture',
  );
  assert.equal(
    (
      await pools.identity.query<{ state: string }[]>(`SELECT state FROM app_user WHERE id=$1`, [
        userId,
      ])
    )[0]!.state,
    'suspended',
  );
  await assert.rejects(
    identity.login('local@example.test', 'suspended strong new password', 'suspend-reset-fixture'),
    ProductAuthenticationError,
  );
});

test('OIDC invitation activates a pending non-Root account only with token and exact binding', async () => {
  const target = randomUUID();
  await fixtureAdmin.query(`INSERT INTO app_user(id,state) VALUES($1,'pending')`, [target]);
  await pools.identity.query(
    `INSERT INTO external_identity(issuer,subject,user_id) VALUES($1,'bootstrap-target',$2)`,
    [issuer, target],
  );
  const token = await runner.run('revoke', (tx) => identity.issueActivation(tx, target, 'oidc'));
  // An OIDC invitation never creates a local password, and a missing or wrong token cannot start.
  await assert.rejects(
    identity.activate(token, 'a very strong password', 'oidc-activation'),
    ProductAuthenticationError,
  );
  for (const options of [{}, { activationToken: newSessionSecret() }])
    await assert.rejects(
      federation.begin(
        issuer,
        newSessionSecret(),
        { purpose: 'activation', ...options },
        'oidc-activation',
      ),
      ProductAuthenticationError,
    );
  const wrongBrowser = newSessionSecret();
  const wrongStart = await federation.begin(
    issuer,
    wrongBrowser,
    { purpose: 'activation', activationToken: token },
    'oidc-activation',
  );
  await assert.rejects(
    federation.callback(
      issuer,
      responseFor(wrongStart, { sub: 'wrong-bootstrap-target' }),
      wrongBrowser,
    ),
    ProductAuthenticationError,
  );
  let entered!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => (entered = resolve));
  const hold = new Promise<void>((resolve) => (release = resolve));
  tokenGate = async () => {
    entered();
    await hold;
  };
  const browser = newSessionSecret();
  const start = await federation.begin(
    issuer,
    browser,
    { purpose: 'activation', activationToken: token },
    'oidc-activation',
  );
  const activation = federation.callback(
    issuer,
    responseFor(start, { sub: 'bootstrap-target' }),
    browser,
  );
  await ready;
  await runner.run('revoke', async (tx) => {
    await tx.manager.query(
      `UPDATE external_identity SET binding_version=binding_version+1 WHERE issuer=$1 AND subject='bootstrap-target'`,
      [issuer],
    );
  });
  release();
  await assert.rejects(activation, ProductAuthenticationError);
  tokenGate = undefined;
  assert.equal(
    (
      await pools.identity.query<{ state: string }[]>(`SELECT state FROM app_user WHERE id=$1`, [
        target,
      ])
    )[0]!.state,
    'pending',
  );
  // An attempt begun with a proof that is then reissued cannot finish with the new proof.
  const staleBrowser = newSessionSecret();
  const staleStart = await federation.begin(
    issuer,
    staleBrowser,
    { purpose: 'activation', activationToken: token },
    'oidc-activation',
  );
  const reissued = await runner.run('revoke', (tx) => identity.issueActivation(tx, target, 'oidc'));
  await assert.rejects(
    federation.callback(issuer, responseFor(staleStart, { sub: 'bootstrap-target' }), staleBrowser),
    ProductAuthenticationError,
  );
  const finalBrowser = newSessionSecret();
  const finalStart = await federation.begin(
    issuer,
    finalBrowser,
    { purpose: 'activation', activationToken: reissued },
    'oidc-activation',
  );
  const session = await federation.callback(
    issuer,
    responseFor(finalStart, { sub: 'bootstrap-target' }),
    finalBrowser,
  );
  assert.ok(session);
  assert.equal(
    (await runner.run('read', (tx) => identity.authenticate(tx, session.secret))).userId,
    target,
  );
  await assert.rejects(
    federation.callback(issuer, responseFor(finalStart, { sub: 'bootstrap-target' }), finalBrowser),
    ProductAuthenticationError,
  );
  for (const used of [token, reissued])
    await assert.rejects(
      federation.begin(
        issuer,
        newSessionSecret(),
        { purpose: 'activation', activationToken: used },
        'oidc-activation',
      ),
      ProductAuthenticationError,
    );
});

test('provider revoke racing network exchange denies new session; OIDC-only cannot reset into local', async () => {
  let entered!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => (entered = resolve));
  const hold = new Promise<void>((resolve) => (release = resolve));
  tokenGate = async () => {
    entered();
    await hold;
  };
  const browser = newSessionSecret();
  const start = await federation.begin(issuer, browser, {}, 'oidc-race');
  const login = federation.callback(issuer, responseFor(start), browser);
  await ready;
  await fixtureAdmin.transaction(async (manager) => {
    await manager.query('SELECT singleton FROM authz_state FOR UPDATE');
    await manager.query(
      `UPDATE oidc_provider SET enabled=false,version=version+1 WHERE issuer=$1`,
      [issuer],
    );
    await manager.query('UPDATE authz_state SET revision=revision+1');
  });
  release();
  await assert.rejects(login, ProductAuthenticationError);
  tokenGate = undefined;
  const id = randomUUID();
  await fixtureAdmin.query(
    `INSERT INTO app_user(id,email_canonical,email_verified,state) VALUES($1,'oidc-only@example.test',true,'active')`,
    [id],
  );
  await pools.identity.query(
    `INSERT INTO external_identity(issuer,subject,user_id) VALUES($1,'oidc-only',$2)`,
    [issuer, id],
  );
  assert.equal(
    await identity.requestPasswordReset('oidc-only@example.test', 'oidc-reset'),
    undefined,
  );
  assert.equal(
    (
      await pools.identity.query<{ n: number }[]>(
        `SELECT count(*)::int AS n FROM local_credential WHERE user_id=$1`,
        [id],
      )
    )[0]!.n,
    0,
  );
});
test('invitation issuance refuses the offline actor id even for a pending account', async () => {
  await fixtureAdmin.query(
    `INSERT INTO app_user(id,email_canonical,state) VALUES($1,'actor-collision@example.test','pending')`,
    [PRODUCT_OFFLINE_ACTOR],
  );
  await assert.rejects(
    runner.run('revoke', (tx) => identity.issueActivation(tx, PRODUCT_OFFLINE_ACTOR)),
    ProductAuthenticationError,
  );
  const tokens = await fixtureAdmin.query<unknown[]>(
    'SELECT 1 FROM one_time_token WHERE user_id=$1',
    [PRODUCT_OFFLINE_ACTOR],
  );
  assert.equal(tokens.length, 0);
});

/** Active local accounts sharing one password hash; synthetic addresses only. */
async function activeLocalUsers(prefix: string, count: number, password: string) {
  const hash = await identity.passwords.hash(password);
  const emails: string[] = [];
  for (let i = 0; i < count; i++) {
    const id = randomUUID();
    const email = `${prefix}${i}@example.test`;
    await pools.identity.query(
      "INSERT INTO app_user(id,email_canonical,email_verified,state) VALUES($1,$2,true,'active')",
      [id, email],
    );
    await pools.identity.query(
      'INSERT INTO local_credential(user_id,password_hash,version) VALUES($1,$2,1)',
      [id, hash],
    );
    emails.push(email);
  }
  return emails;
}

test('valid users behind one NAT address share its 20-attempt bucket; successes count, failures are not separate', async () => {
  // Current policy (ADR0008, operations §3): every attempt counts, not only failures.
  const password = 'nat shared strong password';
  const emails = await activeLocalUsers('nat', 21, password);
  for (const email of emails.slice(0, 20)) await identity.login(email, password, '198.51.100.7');
  await assert.rejects(
    identity.login(emails[20]!, password, '198.51.100.7'),
    ProductAuthenticationError,
  );
  // The 21st user is not locked: the client bucket, not the account, refused it.
  await identity.login(emails[20]!, password, '198.51.100.8');
  // The account bucket counts successful logins too: 20 more from distinct addresses lock it.
  for (let i = 1; i < 20; i++) await identity.login(emails[0]!, password, `203.0.113.${i}`);
  await assert.rejects(
    identity.login(emails[0]!, password, '203.0.113.200'),
    ProductAuthenticationError,
  );
});

test('replicas with separate pools enforce one shared limit under concurrent attempts', async () => {
  const replicaPool = await new DataSource(
    productDataSourceOptions(connections.identity),
  ).initialize();
  try {
    const replica = new ProductIdentityService(
      new ProductTransactionRunner({ identity: replicaPool }),
      identity.passwords,
    );
    const attempt = (i: number) =>
      (i % 2 ? replica : identity).rateLimit(
        `192.0.2.${i + 1}`,
        'replica-concurrent@example.test',
        'replica-concurrent',
      );
    const outcomes = await Promise.allSettled(Array.from({ length: 30 }, (_, i) => attempt(i)));
    // Under a loaded host a queued attempt can exceed lock_timeout: it rolls back without counting
    // and is retried here one at a time. The shared cap must still be exactly 20.
    let accepted = 0;
    let refused = 0;
    for (const [i, outcome] of outcomes.entries()) {
      if (outcome.status === 'fulfilled') accepted++;
      else if (outcome.reason instanceof ProductAuthenticationError) refused++;
      else {
        assert.ok(outcome.reason instanceof TransactionConflictError);
        await attempt(i).then(
          () => accepted++,
          (error: unknown) => {
            assert.ok(error instanceof ProductAuthenticationError);
            refused++;
          },
        );
      }
    }
    assert.deepEqual([accepted, refused], [20, 10]);
  } finally {
    await replicaPool.destroy();
  }
});

test('data-only access does not touch idle activity; identity operations touch without extending expiry', async () => {
  const password = 'activity strong password';
  const [email] = await activeLocalUsers('activity', 1, password);
  const session = await identity.login(email!, password, '198.51.100.20');
  const digest = sessionDigest(session.secret);
  const stamp = async () =>
    (
      await pools.identity.query<{ seen: string; expires: string }[]>(
        `SELECT last_seen_at::text seen,expires_at::text expires FROM application_session WHERE token_hash=$1`,
        [digest],
      )
    )[0]!;
  await runner.run('revoke', (tx) =>
    tx.manager.query(
      `UPDATE application_session SET last_seen_at=statement_timestamp()-interval '10 minutes' WHERE token_hash=$1`,
      [digest],
    ),
  );
  const before = await stamp();
  for (let i = 0; i < 3; i++)
    await runner.run('read', (tx) => identity.authenticate(tx, session.secret));
  assert.deepEqual(await stamp(), before);
  await runner.run('identity', (tx) => identity.authenticate(tx, session.secret));
  const touched = await stamp();
  assert.ok(touched.seen > before.seen);
  assert.equal(touched.expires, before.expires);
  // A data-only user idle past 30 minutes is refused even while making data requests.
  await runner.run('revoke', (tx) =>
    tx.manager.query(
      `UPDATE application_session SET last_seen_at=statement_timestamp()-interval '31 minutes' WHERE token_hash=$1`,
      [digest],
    ),
  );
  await assert.rejects(
    runner.run('read', (tx) => identity.authenticate(tx, session.secret)),
    ProductAuthenticationError,
  );
});

test('expired sessions are purged in bounded batches; live, revoked-unexpired, recent and locked rows survive', async () => {
  const owner = randomUUID();
  await pools.identity.query(
    "INSERT INTO app_user(id,email_canonical,email_verified,state) VALUES($1,'purge@example.test',true,'active')",
    [owner],
  );
  const insert = async (expires: string, revoked = false) => {
    const secret = newSessionSecret();
    await pools.identity.query(
      `INSERT INTO application_session(token_hash,user_id,auth_epoch,credential_version,method,assurance,authenticated_at,created_at,expires_at,revoked_at)
       VALUES($1,$2,1,1,'local','password',statement_timestamp()-interval '30 days',statement_timestamp()-interval '30 days',statement_timestamp()+$3::interval,CASE WHEN $4 THEN statement_timestamp() END)`,
      [sessionDigest(secret), owner, expires, revoked],
    );
    return sessionDigest(secret);
  };
  const live = await insert('1 hour');
  const revokedLive = await insert('1 hour', true);
  const recent = await insert('-1 hour');
  for (let i = 0; i < 5; i++) await insert('-3 days');
  const countOwner = async () =>
    (
      await pools.identity.query<{ n: number }[]>(
        'SELECT count(*)::int n FROM application_session WHERE user_id=$1',
        [owner],
      )
    )[0]!.n;
  for (const [retention, batch] of [
    [-1, 10],
    [1.5, 10],
    [3651, 10],
    [1, 0],
    [1, 1001],
  ] as const)
    await assert.rejects(purgeExpiredSessions(runner, retention, batch), RangeError);
  const hold = () => {
    let release!: () => void;
    let entered!: () => void;
    const inside = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    return { inside, gate, release, entered };
  };
  // A password reset holds the exclusive fence: purge waits for its commit, then runs.
  const reset = hold();
  const resetting = runner.run('revoke', async (tx) => {
    await identity.invalidate(tx, owner);
    reset.entered();
    await reset.gate;
  });
  await reset.inside;
  let purgedDuringReset: number | undefined;
  const purging = purgeExpiredSessions(runner, 1, 2).then((n) => (purgedDuringReset = n));
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.equal(purgedDuringReset, undefined);
  reset.release();
  await resetting;
  assert.equal(await purging, 2);
  // The reset revoked every session of the owner, live ones included; none of those is purged.
  assert.equal(await countOwner(), 6);
  // A shared-fence identity transaction holding a row lock: purge skips that row, never waits.
  const [busy] = await pools.identity.query<{ token_hash: Buffer }[]>(
    "SELECT token_hash FROM application_session WHERE user_id=$1 AND expires_at<statement_timestamp()-interval '2 days' LIMIT 1",
    [owner],
  );
  const lock = hold();
  const locking = runner.run('identity', async (tx) => {
    await tx.manager.query('SELECT 1 FROM application_session WHERE token_hash=$1 FOR UPDATE', [
      busy!.token_hash,
    ]);
    lock.entered();
    await lock.gate;
  });
  await lock.inside;
  try {
    assert.equal(await purgeExpiredSessions(runner, 1, 2), 2);
    assert.equal(await purgeExpiredSessions(runner, 1, 2), 0);
  } finally {
    lock.release();
    await locking;
  }
  assert.equal(await purgeExpiredSessions(runner, 1, 2), 1);
  assert.equal(await purgeExpiredSessions(runner, 1, 2), 0);
  const left = await pools.identity.query<{ token_hash: Buffer }[]>(
    'SELECT token_hash FROM application_session WHERE user_id=$1',
    [owner],
  );
  assert.deepEqual(
    left.map((r) => r.token_hash.toString('hex')).sort(),
    [live, revokedLive, recent].map((d) => d.toString('hex')).sort(),
  );
  const events = await fixtureAdmin.query<
    { actor_id: string; safe_metadata: Record<string, string> }[]
  >(
    "SELECT actor_id,safe_metadata FROM audit_outbox WHERE event_kind=convert_to('identity.session-purge','UTF8') ORDER BY occurred_at",
  );
  assert.deepEqual(
    events.map((e) => [e.actor_id, e.safe_metadata.deleted, e.safe_metadata.retentionDays]),
    [
      [PRODUCT_OFFLINE_ACTOR, '2', '1'],
      [PRODUCT_OFFLINE_ACTOR, '2', '1'],
      [PRODUCT_OFFLINE_ACTOR, '1', '1'],
    ],
  );
  const [index] = await fixtureAdmin.query<{ n: number }[]>(
    "SELECT count(*)::int n FROM pg_indexes WHERE tablename='application_session' AND indexdef LIKE '%(expires_at)'",
  );
  assert.equal(index!.n, 1);
});
