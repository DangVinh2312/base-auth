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
} from '@base-authorization/typeorm-postgres';
import { ProductTransactionRunner } from '@base-authorization/typeorm-postgres';
import {
  ProductIdentityService,
  createProductPasswordHasher,
  newSessionSecret,
  sessionDigest,
  ProductAuthenticationError,
} from '@base-authorization/typeorm-postgres';
import { ProductOidcService, type ProductOidcProvider } from '@base-authorization/typeorm-postgres';
import {
  ProductAuthorization,
  ProductBindingRegistry,
  ProductManifestReconciler,
} from '@base-authorization/typeorm-postgres';
import type { IdentityId } from '@base-authorization/core';
import { productRelease, productBindings } from '../apps/api/dist/product-manifest.js';
import { ProductDocument1792108800002 } from '../apps/api/dist/product-migration.js';
import { startPostgres, type TestPostgres } from './setup-postgres.ts';

let postgres: TestPostgres;
let pools: Record<'data' | 'identity' | 'authority' | 'sync' | 'bootstrap', DataSource>;
let fixtureAdmin: DataSource;
let identity: ProductIdentityService;
let runner: ProductTransactionRunner;
let provider: ProductOidcProvider;
let federation: ProductOidcService;
let server: Server;
const issuer = 'https://issuer.fixture';
const redirectUri = 'https://app.fixture/oidc/callback';
const subject = 'exact-subject';
const userId = randomUUID();
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
    ['data', 'identity', 'authority', 'sync', 'bootstrap', 'migration'].map((p) => [
      p,
      randomBytes(20).toString('hex'),
    ]),
  ) as Record<'data' | 'identity' | 'authority' | 'sync' | 'bootstrap' | 'migration', string>;
  const connections = await provisionProductDatabase(postgres.superuser, secrets);
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
  const activation = await runner.run('bootstrap', (tx) => identity.issueActivation(tx, userId));
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
    new ProductBindingRegistry(productRelease.declarations, productBindings),
    {
      validators: { 'fresh@1': (_parameters, input) => input.context.freshAuthentication === true },
      obligationHandlers: ['audit@1'],
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
  await runner.run('revoke', (tx) =>
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

test('OIDC Root activation requires exact bootstrap proof and rejects changed bindings', async () => {
  const target = randomUUID();
  await fixtureAdmin.query(
    `INSERT INTO app_user(id,email_canonical,state) VALUES($1,'root-fixture@example.test','pending')`,
    [target],
  );
  await fixtureAdmin.query(
    `UPDATE security_bootstrap_state SET target_user_id=$1,operation_id=$2,initialized_at=statement_timestamp()`,
    [target, randomUUID()],
  );
  await pools.identity.query(
    `INSERT INTO external_identity(issuer,subject,user_id) VALUES($1,'bootstrap-target',$2)`,
    [issuer, target],
  );
  const wrongBrowser = newSessionSecret();
  const wrongStart = await federation.begin(
    issuer,
    wrongBrowser,
    { purpose: 'activation' },
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
    { purpose: 'activation' },
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
  const finalBrowser = newSessionSecret();
  const finalStart = await federation.begin(
    issuer,
    finalBrowser,
    { purpose: 'activation' },
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
  await assert.rejects(
    federation.begin(issuer, newSessionSecret(), { purpose: 'activation' }, 'oidc-activation'),
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
