import { createHash, randomBytes, randomUUID } from 'node:crypto';
import * as argon2 from 'argon2';
import type { ProductTransaction, ProductTransactionRunner } from './product-transaction.js';

export class ProductAuthenticationError extends Error {
  constructor() {
    super('Authentication failed');
  }
}
export class ProductAuthenticationUnavailable extends Error {
  constructor() {
    super('Authentication unavailable');
  }
}
export interface ProductPasswordHasher {
  hash(password: string): Promise<string>;
  verify(hash: string, password: string): Promise<boolean>;
  dummyHash: string;
}
export interface ProductSession {
  secret: string;
  expiresAt: Date;
}
export interface ProductSessionIdentity {
  userId: string;
  authEpoch: string;
  method: 'local' | 'oidc';
  assurance: string;
  authenticatedAt: Date;
  reauthenticatedAt: Date | null;
}
export function canonicalLoginEmail(email: string): string {
  if (typeof email !== 'string' || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(email))
    throw new ProductAuthenticationError();
  return email.toLowerCase();
}
export function newSessionSecret(): string {
  return randomBytes(32).toString('base64url');
}
export function secretDigest(secret: string): Buffer {
  return createHash('sha256').update(secret).digest();
}
export function sessionDigest(secret: string): Buffer {
  if (
    typeof secret !== 'string' ||
    !/^[A-Za-z0-9_-]{43}$/u.test(secret) ||
    Buffer.from(secret, 'base64url').toString('base64url') !== secret
  )
    throw new ProductAuthenticationError();
  return secretDigest(secret);
}

export async function createProductPasswordHasher(
  blockedPasswords: ReadonlySet<string>,
): Promise<ProductPasswordHasher> {
  let active = 0;
  async function bounded<T>(work: () => Promise<T>): Promise<T> {
    if (active >= 4) throw new ProductAuthenticationUnavailable();
    active++;
    try {
      return await work();
    } finally {
      active--;
    }
  }
  function valid(password: string): boolean {
    return (
      typeof password === 'string' &&
      Buffer.byteLength(password, 'utf8') <= 512 &&
      Buffer.from(password, 'utf8').toString('utf8') === password &&
      [...password].length >= 15 &&
      [...password].length <= 128
    );
  }
  const options = {
    type: argon2.argon2id,
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1,
    hashLength: 32,
  } as const;
  const dummyHash = await argon2.hash(randomBytes(32), options);
  return {
    dummyHash,
    async hash(password) {
      if (!valid(password) || blockedPasswords.has(password))
        throw new ProductAuthenticationError();
      return bounded(() => argon2.hash(password, options));
    },
    async verify(hash, password) {
      // Bound persisted parameters too: a corrupt hash must not exhaust the process.
      const match =
        /^\$argon2id\$v=19\$((?:[mtp]=[0-9]+,){2}[mtp]=[0-9]+)\$[A-Za-z0-9+/]{16,86}\$[A-Za-z0-9+/]{32,86}$/u.exec(
          hash,
        );
      if (!valid(password) || !match) return false;
      const parameters = Object.fromEntries(
        match[1]!.split(',').map((part) => part.split('=') as [string, string]),
      );
      if (
        Object.keys(parameters).length !== 3 ||
        Number(parameters.m) < 19456 ||
        Number(parameters.m) > 65536 ||
        Number(parameters.t) < 2 ||
        Number(parameters.t) > 6 ||
        Number(parameters.p) !== 1
      )
        return false;
      return bounded(async () => {
        try {
          return await argon2.verify(hash, password);
        } catch {
          return false;
        }
      });
    },
  };
}

interface Credential {
  id: string;
  state: string;
  auth_epoch: string;
  email_verified: boolean;
  password_hash: string;
  version: string;
}
interface TokenRow {
  user_id: string;
  credential_version: string | null;
  state: string;
  auth_epoch: string;
}
interface SessionRow {
  user_id: string;
  auth_epoch: string;
  method: 'local' | 'oidc';
  assurance: string;
  authenticated_at: Date;
  reauthenticated_at: Date | null;
}

export class ProductIdentityService {
  constructor(
    readonly transactions: ProductTransactionRunner,
    readonly passwords: ProductPasswordHasher,
  ) {}

  async audit(tx: ProductTransaction, userId: string, kind: string): Promise<void> {
    await tx.manager.query(
      `INSERT INTO audit_outbox(event_id,actor_id,event_kind,policy_revision,occurred_at,safe_metadata) VALUES($1,$2,$3,$4,statement_timestamp(),'{}')`,
      [randomUUID(), userId, kind, tx.revision],
    );
  }

  async rateLimit(clientKey: string, identifier: string, purpose: string): Promise<void> {
    if (typeof clientKey !== 'string' || clientKey.length < 1 || clientKey.length > 256)
      throw new ProductAuthenticationError();
    const allowed = await this.transactions.run('identity', async (tx) => {
      // One bounded database limiter shared by replicas; expired rows never accumulate.
      await tx.manager.query('SELECT pg_advisory_xact_lock(1379171467)');
      await tx.manager.query(
        `DELETE FROM rate_limit WHERE window_start <= statement_timestamp()-interval '15 minutes'`,
      );
      const counts = await tx.manager.query<
        {
          n: number;
        }[]
      >(`SELECT count(*)::int AS n FROM rate_limit`);
      if ((counts[0]?.n ?? 10000) >= 10000) return false;
      let accept = true;
      for (const key of [`${purpose}:ip:${clientKey}`, `${purpose}:login:${identifier}`]) {
        const rows = await tx.manager.query<{ attempts: number }[]>(
          `INSERT INTO rate_limit(bucket_key,window_start,attempts) VALUES($1,statement_timestamp(),1)
          ON CONFLICT(bucket_key) DO UPDATE SET attempts=LEAST(rate_limit.attempts+1,1001) RETURNING attempts`,
          [secretDigest(key)],
        );
        if ((rows[0]?.attempts ?? 1001) > 20) accept = false;
      }
      return accept;
    });
    if (!allowed) throw new ProductAuthenticationError();
  }

  async credential(email: string): Promise<Credential | undefined> {
    return this.transactions.run('identity', async (tx) => {
      const rows = await tx.manager.query<Credential[]>(
        `SELECT u.id,u.state,u.auth_epoch,u.email_verified,c.password_hash,c.version FROM app_user u JOIN local_credential c ON c.user_id=u.id WHERE u.email_canonical=$1`,
        [email],
      );
      return rows[0];
    });
  }

  async login(email: string, password: string, clientKey: string): Promise<ProductSession> {
    const canonical = canonicalLoginEmail(email);
    await this.rateLimit(clientKey, canonical, 'login');
    const before = await this.credential(canonical);
    const verified = await this.passwords.verify(
      before?.password_hash ?? this.passwords.dummyHash,
      password,
    );
    if (!verified || !before) throw new ProductAuthenticationError();
    return this.transactions.run('identity', async (tx) => {
      const rows = await tx.manager.query<Credential[]>(
        `SELECT u.id,u.state,u.auth_epoch,u.email_verified,c.password_hash,c.version FROM app_user u JOIN local_credential c ON c.user_id=u.id WHERE u.id=$1`,
        [before.id],
      );
      const fresh = rows[0];
      if (
        !fresh ||
        fresh.state !== 'active' ||
        !fresh.email_verified ||
        fresh.version !== before.version ||
        fresh.password_hash !== before.password_hash ||
        fresh.auth_epoch !== before.auth_epoch
      )
        throw new ProductAuthenticationError();
      const session = await this.createSession(tx, {
        userId: fresh.id,
        authEpoch: fresh.auth_epoch,
        credentialVersion: fresh.version,
        method: 'local',
        assurance: 'password',
      });
      await this.audit(tx, fresh.id, 'identity.login');
      return session;
    });
  }

  async createSession(
    tx: ProductTransaction,
    input: {
      userId: string;
      authEpoch: string;
      credentialVersion?: string;
      method: 'local' | 'oidc';
      assurance: string;
      issuer?: string;
      subject?: string;
      bindingVersion?: string;
      providerVersion?: string;
      authenticatedAt?: Date;
      reauthenticated?: boolean;
    },
  ): Promise<ProductSession> {
    const secret = newSessionSecret();
    const rows = await tx.manager.query<{ expires_at: Date }[]>(
      `INSERT INTO application_session(token_hash,user_id,auth_epoch,credential_version,method,assurance,external_issuer,external_subject,binding_version,provider_version,authenticated_at,reauthenticated_at,expires_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$12,COALESCE($10,statement_timestamp()),CASE WHEN $11 THEN statement_timestamp() ELSE NULL END,statement_timestamp()+interval '12 hours') RETURNING expires_at`,
      [
        sessionDigest(secret),
        input.userId,
        input.authEpoch,
        input.credentialVersion ?? null,
        input.method,
        input.assurance,
        input.issuer ?? null,
        input.subject ?? null,
        input.bindingVersion ?? null,
        input.authenticatedAt ?? null,
        input.reauthenticated ?? false,
        input.providerVersion ?? null,
      ],
    );
    if (!rows[0]) throw new ProductAuthenticationError();
    return { secret, expiresAt: rows[0].expires_at };
  }

  async authenticate(tx: ProductTransaction, secret: string): Promise<ProductSessionIdentity> {
    const rows = await tx.manager.query<SessionRow[]>('SELECT * FROM public.resolve_session($1)', [
      sessionDigest(secret),
    ]);
    const row = rows[0];
    if (!row) throw new ProductAuthenticationError();
    // No rolling expiry: touching activity cannot extend the absolute deadline.
    if (tx.mode === 'identity' || tx.mode === 'revoke')
      await tx.manager.query(
        `UPDATE application_session SET last_seen_at=statement_timestamp() WHERE token_hash=$1`,
        [sessionDigest(secret)],
      );
    return {
      userId: row.user_id,
      authEpoch: row.auth_epoch,
      method: row.method,
      assurance: row.assurance,
      authenticatedAt: row.authenticated_at,
      reauthenticatedAt: row.reauthenticated_at,
    };
  }

  async logout(secret: string, all = false): Promise<void> {
    await this.transactions.run('revoke', async (tx) => {
      const identity = await this.authenticate(tx, secret);
      if (all)
        await tx.manager.query(
          `UPDATE application_session SET revoked_at=statement_timestamp() WHERE user_id=$1 AND revoked_at IS NULL`,
          [identity.userId],
        );
      else
        await tx.manager.query(
          `UPDATE application_session SET revoked_at=statement_timestamp() WHERE token_hash=$1`,
          [sessionDigest(secret)],
        );
      await this.audit(tx, identity.userId, all ? 'identity.logout-all' : 'identity.logout');
    });
  }

  async issueActivation(tx: ProductTransaction, userId: string): Promise<string> {
    if (tx.mode !== 'bootstrap' && tx.mode !== 'revoke') throw new ProductAuthenticationError();
    const users = await tx.manager.query<{ id: string }[]>(
      `SELECT id FROM app_user u WHERE id=$1 AND state='pending' AND email_canonical IS NOT NULL AND NOT EXISTS(SELECT 1 FROM local_credential WHERE user_id=u.id)`,
      [userId],
    );
    if (!users[0]) throw new ProductAuthenticationError();
    const token = newSessionSecret();
    await tx.manager.query(
      `INSERT INTO one_time_token(token_hash,user_id,purpose,expires_at,credential_version) VALUES($1,$2,'activation',statement_timestamp()+interval '15 minutes',NULL)`,
      [sessionDigest(token), userId],
    );
    return token;
  }

  async activate(token: string, password: string, clientKey: string): Promise<void> {
    await this.rateLimit(clientKey, secretDigest(token).toString('hex'), 'activation');
    const hash = await this.passwords.hash(password);
    await this.transactions.run('revoke', async (tx) => {
      const row = await this.loadToken(tx, token, 'activation');
      if (row.state !== 'pending') throw new ProductAuthenticationError();
      const old = await tx.manager.query<unknown[]>(
        `SELECT user_id FROM local_credential WHERE user_id=$1`,
        [row.user_id],
      );
      if (old.length) throw new ProductAuthenticationError();
      await tx.manager.query(`INSERT INTO local_credential(user_id,password_hash) VALUES($1,$2)`, [
        row.user_id,
        hash,
      ]);
      await tx.manager.query(
        `UPDATE app_user SET state='active',email_verified=true,auth_epoch=auth_epoch+1 WHERE id=$1`,
        [row.user_id],
      );
      await this.invalidate(tx, row.user_id);
      await this.audit(tx, row.user_id, 'identity.activation');
    });
  }

  async requestPasswordReset(
    email: string,
    clientKey: string,
  ): Promise<{ token: string; userId: string } | undefined> {
    const canonical = canonicalLoginEmail(email);
    await this.rateLimit(clientKey, canonical, 'reset-request');
    return this.transactions.run('identity', async (tx) => {
      const rows = await tx.manager.query<{ id: string; version: string }[]>(
        `SELECT u.id,c.version FROM app_user u JOIN local_credential c ON c.user_id=u.id WHERE u.email_canonical=$1 AND u.email_verified AND u.state='active'`,
        [canonical],
      );
      const row = rows[0];
      if (!row) return undefined;
      const token = newSessionSecret();
      await tx.manager.query(
        `UPDATE one_time_token SET consumed_at=statement_timestamp() WHERE user_id=$1 AND purpose='reset' AND consumed_at IS NULL`,
        [row.id],
      );
      await tx.manager.query(
        `INSERT INTO one_time_token(token_hash,user_id,purpose,expires_at,credential_version) VALUES($1,$2,'reset',statement_timestamp()+interval '15 minutes',$3)`,
        [sessionDigest(token), row.id, row.version],
      );
      return { token, userId: row.id };
    });
  }

  async loadToken(
    tx: ProductTransaction,
    token: string,
    purpose: 'activation' | 'reset',
  ): Promise<TokenRow> {
    const rows = await tx.manager.query<TokenRow[]>(
      `SELECT t.user_id,t.credential_version,u.state,u.auth_epoch FROM one_time_token t JOIN app_user u ON u.id=t.user_id WHERE t.token_hash=$1 AND t.purpose=$2 AND t.consumed_at IS NULL AND t.expires_at>statement_timestamp() FOR UPDATE OF u,t`,
      [sessionDigest(token), purpose],
    );
    if (!rows[0]) throw new ProductAuthenticationError();
    return rows[0];
  }
  async invalidate(tx: ProductTransaction, userId: string): Promise<void> {
    await tx.manager.query(
      `UPDATE one_time_token SET consumed_at=statement_timestamp() WHERE user_id=$1 AND consumed_at IS NULL`,
      [userId],
    );
    await tx.manager.query(
      `UPDATE application_session SET revoked_at=statement_timestamp() WHERE user_id=$1 AND revoked_at IS NULL`,
      [userId],
    );
  }
  async resetPassword(token: string, password: string, clientKey: string): Promise<void> {
    await this.rateLimit(clientKey, secretDigest(token).toString('hex'), 'reset');
    const hash = await this.passwords.hash(password);
    await this.transactions.run('revoke', async (tx) => {
      const row = await this.loadToken(tx, token, 'reset');
      const updated = await tx.manager.query<unknown[]>(
        `WITH changed AS (UPDATE local_credential SET password_hash=$1,version=version+1 WHERE user_id=$2 AND version=$3 RETURNING user_id) SELECT * FROM changed`,
        [hash, row.user_id, row.credential_version],
      );
      if (!updated.length) throw new ProductAuthenticationError();
      await tx.manager.query(`UPDATE app_user SET auth_epoch=auth_epoch+1 WHERE id=$1`, [
        row.user_id,
      ]);
      await this.invalidate(tx, row.user_id);
      await this.audit(tx, row.user_id, 'identity.password-reset');
    });
  }

  async reauthenticate(
    secret: string,
    password: string,
    clientKey: string,
  ): Promise<ProductSession> {
    const before = await this.transactions.run('identity', async (tx) => {
      const identity = await this.authenticate(tx, secret);
      if (identity.method !== 'local') throw new ProductAuthenticationError();
      const rows = await tx.manager.query<Credential[]>(
        `SELECT u.id,u.state,u.auth_epoch,u.email_verified,c.password_hash,c.version FROM app_user u JOIN local_credential c ON c.user_id=u.id WHERE u.id=$1`,
        [identity.userId],
      );
      return rows[0];
    });
    if (!before) throw new ProductAuthenticationError();
    await this.rateLimit(clientKey, before.id, 'reauth');
    if (!(await this.passwords.verify(before.password_hash, password)))
      throw new ProductAuthenticationError();
    return this.transactions.run('revoke', async (tx) => {
      const identity = await this.authenticate(tx, secret);
      const rows = await tx.manager.query<{ version: string }[]>(
        `SELECT version FROM local_credential WHERE user_id=$1 AND password_hash=$2`,
        [identity.userId, before.password_hash],
      );
      if (rows[0]?.version !== before.version || identity.authEpoch !== before.auth_epoch)
        throw new ProductAuthenticationError();
      await tx.manager.query(
        `UPDATE application_session SET revoked_at=statement_timestamp() WHERE token_hash=$1`,
        [sessionDigest(secret)],
      );
      const session = await this.createSession(tx, {
        userId: identity.userId,
        authEpoch: identity.authEpoch,
        credentialVersion: before.version,
        method: 'local',
        assurance: 'password',
        reauthenticated: true,
      });
      await this.audit(tx, identity.userId, 'identity.reauthenticate');
      return session;
    });
  }

  async changePassword(
    secret: string,
    currentPassword: string,
    password: string,
    clientKey: string,
  ): Promise<void> {
    const before = await this.transactions.run('identity', async (tx) => {
      const identity = await this.authenticate(tx, secret);
      const rows = await tx.manager.query<Credential[]>(
        `SELECT u.id,u.state,u.auth_epoch,u.email_verified,c.password_hash,c.version FROM app_user u JOIN local_credential c ON c.user_id=u.id WHERE u.id=$1`,
        [identity.userId],
      );
      return rows[0];
    });
    if (!before) throw new ProductAuthenticationError();
    await this.rateLimit(clientKey, before.id, 'password-change');
    if (!(await this.passwords.verify(before.password_hash, currentPassword)))
      throw new ProductAuthenticationError();
    const hash = await this.passwords.hash(password);
    await this.transactions.run('revoke', async (tx) => {
      const identity = await this.authenticate(tx, secret);
      if (identity.userId !== before.id || identity.authEpoch !== before.auth_epoch)
        throw new ProductAuthenticationError();
      const rows = await tx.manager.query<unknown[]>(
        `WITH changed AS (UPDATE local_credential SET password_hash=$1,version=version+1 WHERE user_id=$2 AND version=$3 RETURNING user_id) SELECT * FROM changed`,
        [hash, before.id, before.version],
      );
      if (!rows.length) throw new ProductAuthenticationError();
      await tx.manager.query(`UPDATE app_user SET auth_epoch=auth_epoch+1 WHERE id=$1`, [
        before.id,
      ]);
      await this.invalidate(tx, before.id);
      await this.audit(tx, before.id, 'identity.password-change');
    });
  }
}
