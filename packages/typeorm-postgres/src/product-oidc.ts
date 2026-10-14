import { timingSafeEqual } from 'node:crypto';
import * as oidc from 'openid-client';
import type { ProductTransaction } from './product-transaction.js';
import {
  ProductAuthenticationError,
  ProductIdentityService,
  newSessionSecret,
  rateLimitClient,
  secretDigest,
  sessionDigest,
  type ProductSession,
} from './product-identity.js';

export interface ProductOidcProviderConfig {
  issuer: string;
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
  version: string;
  assuranceMappings: readonly { acr: string; amr: readonly string[]; assurance: 'mfa' }[];
}
export interface ProductOidcProvider {
  readonly settings: ProductOidcProviderConfig;
  readonly configuration: oidc.Configuration;
}
function trustedUrl(value: string): URL {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search)
    throw new TypeError('OIDC requires a fixed trusted HTTPS URL');
  return url;
}
export async function createProductOidcProvider(
  settings: ProductOidcProviderConfig,
): Promise<ProductOidcProvider> {
  const issuer = trustedUrl(settings.issuer);
  trustedUrl(settings.redirectUri);
  if (
    !settings.clientId ||
    settings.clientId.length > 256 ||
    !/^[1-9][0-9]{0,17}$/u.test(settings.version)
  )
    throw new TypeError('Invalid OIDC configuration');
  for (const mapping of settings.assuranceMappings) {
    if (
      !mapping.acr ||
      !mapping.amr.length ||
      mapping.amr.some((value) => typeof value !== 'string' || !value) ||
      mapping.assurance !== 'mfa'
    )
      throw new TypeError('Invalid issuer assurance mapping');
  }
  const configuration = await oidc.discovery(
    issuer,
    settings.clientId,
    {
      ...(settings.clientSecret ? { client_secret: settings.clientSecret } : {}),
      id_token_signed_response_alg: 'RS256',
    },
    settings.clientSecret ? oidc.ClientSecretPost(settings.clientSecret) : oidc.None(),
    { timeout: 5, execute: [oidc.enableNonRepudiationChecks] },
  );
  if (configuration.serverMetadata().issuer !== settings.issuer)
    throw new TypeError('OIDC issuer mismatch');
  // Fixed asymmetric algorithm and signature validation also apply over trusted TLS.
  return {
    settings: Object.freeze({
      ...settings,
      assuranceMappings: settings.assuranceMappings.map((mapping) =>
        Object.freeze({ ...mapping, amr: Object.freeze([...mapping.amr]) }),
      ),
    }),
    configuration,
  };
}
interface Attempt {
  nonce: string;
  verifier: string;
  provider_issuer: string;
  provider_version: string;
  redirect_uri: string;
  linking_user_id: string | null;
  linking_session_hash: Buffer | null;
  enrollment_hash: Buffer | null;
  purpose: 'login' | 'link' | 'reauth' | 'activation';
}
interface Binding {
  user_id: string;
  binding_version: string;
  auth_epoch: string;
  state: string;
  enabled: boolean;
}
interface Invitation extends Binding {
  subject: string;
  token_hash: Buffer;
}

export class ProductOidcService {
  readonly #providers: ReadonlyMap<string, ProductOidcProvider>;
  constructor(
    readonly identity: ProductIdentityService,
    providers: ReadonlyMap<string, ProductOidcProvider>,
  ) {
    this.#providers = new Map(providers);
    for (const [issuer, provider] of this.#providers) {
      if (
        issuer !== provider.settings.issuer ||
        provider.configuration.serverMetadata().issuer !== issuer
      )
        throw new TypeError('OIDC issuer mismatch');
      trustedUrl(issuer);
      trustedUrl(provider.settings.redirectUri);
      if (provider.configuration.clientMetadata().id_token_signed_response_alg !== 'RS256')
        throw new TypeError('OIDC requires the configured asymmetric signing algorithm');
      // Never accept Configuration objects with signature checking omitted.
      oidc.enableNonRepudiationChecks(provider.configuration);
      provider.configuration.timeout = 5;
    }
  }
  provider(issuer: string): ProductOidcProvider {
    const provider = this.#providers.get(issuer);
    if (!provider) throw new ProductAuthenticationError();
    return provider;
  }
  async providerCurrent(tx: ProductTransaction, provider: ProductOidcProvider): Promise<void> {
    const rows = await tx.manager.query<{ version: string }[]>(
      `SELECT version FROM oidc_provider WHERE issuer=$1 AND enabled`,
      [provider.settings.issuer],
    );
    if (rows[0]?.version !== provider.settings.version) throw new ProductAuthenticationError();
  }
  async begin(
    issuer: string,
    browserSecret: string,
    options: {
      purpose?: 'login' | 'link' | 'reauth' | 'activation';
      sessionSecret?: string;
      /** Offline one-time invitation proof; required for activation. */
      activationToken?: string;
    },
    clientKey: string,
  ): Promise<URL> {
    const provider = this.provider(issuer);
    const browserHash = sessionDigest(browserSecret);
    await this.identity.rateLimit(clientKey, rateLimitClient(clientKey), 'oidc');
    const purpose = options.purpose ?? 'login';
    if (!['login', 'link', 'reauth', 'activation'].includes(purpose))
      throw new ProductAuthenticationError();
    const state = newSessionSecret();
    const nonce = oidc.randomNonce();
    const verifier = oidc.randomPKCECodeVerifier();
    const challenge = await oidc.calculatePKCECodeChallenge(verifier);
    await this.identity.transactions.run('identity', async (tx) => {
      await this.providerCurrent(tx, provider);
      let userId: string | null = null;
      let linkingHash: Buffer | null = null;
      let enrollmentHash: Buffer | null = null;
      if (purpose === 'activation') {
        if (!options.activationToken) throw new ProductAuthenticationError();
        const [invitation] = await this.invitation(tx, issuer, {
          token: options.activationToken,
        });
        userId = invitation!.user_id;
        // Bound to this exact token: a reissue voids an attempt begun with the old proof.
        enrollmentHash = this.enrollmentHash(invitation!, issuer);
      }
      if (purpose === 'link' || purpose === 'reauth') {
        if (!options.sessionSecret) throw new ProductAuthenticationError();
        const actor = await this.identity.authenticate(tx, options.sessionSecret);
        if (
          purpose === 'link' &&
          (!actor.reauthenticatedAt || Date.now() - actor.reauthenticatedAt.getTime() > 300000)
        )
          throw new ProductAuthenticationError();
        if (purpose === 'reauth' && actor.method !== 'oidc') throw new ProductAuthenticationError();
        userId = actor.userId;
        linkingHash = sessionDigest(options.sessionSecret);
      }
      await tx.manager.query(
        `DELETE FROM oidc_login_attempt WHERE expires_at<=statement_timestamp()`,
      );
      await tx.manager.query(
        `INSERT INTO oidc_login_attempt(state_hash,nonce,verifier,provider_issuer,provider_version,redirect_uri,expires_at,browser_hash,purpose,linking_user_id,linking_session_hash,enrollment_hash) VALUES($1,$2,$3,$4,$5,$6,statement_timestamp()+interval '5 minutes',$7,$8,$9,$10,$11)`,
        [
          sessionDigest(state),
          nonce,
          verifier,
          issuer,
          provider.settings.version,
          provider.settings.redirectUri,
          browserHash,
          purpose,
          userId,
          linkingHash,
          enrollmentHash,
        ],
      );
    });
    return oidc.buildAuthorizationUrl(provider.configuration, {
      redirect_uri: provider.settings.redirectUri,
      response_type: 'code',
      scope: 'openid',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state,
      nonce,
      ...(purpose === 'reauth' ? { max_age: '0', prompt: 'login' } : {}),
    });
  }
  async callback(
    issuer: string | undefined,
    currentUrl: URL,
    browserSecret: string,
    currentSessionSecret?: string,
  ): Promise<ProductSession | undefined> {
    if (issuer === undefined) {
      const states = currentUrl.searchParams.getAll('state');
      if (states.length !== 1) throw new ProductAuthenticationError();
      const rows = await this.identity.transactions.run<{ provider_issuer: string }[]>(
        'identity',
        (tx) =>
          tx.manager.query(
            `SELECT provider_issuer FROM oidc_login_attempt WHERE state_hash=$1 AND browser_hash=$2 AND consumed_at IS NULL AND expires_at>statement_timestamp()`,
            [sessionDigest(states[0]!), sessionDigest(browserSecret)],
          ),
      );
      if (!rows[0]) throw new ProductAuthenticationError();
      issuer = rows[0].provider_issuer;
    }
    const provider = this.provider(issuer);
    const callback = new URL(provider.settings.redirectUri);
    if (
      currentUrl.origin !== callback.origin ||
      currentUrl.pathname !== callback.pathname ||
      currentUrl.hash ||
      currentUrl.searchParams.getAll('state').length !== 1 ||
      currentUrl.searchParams.getAll('code').length !== 1
    )
      throw new ProductAuthenticationError();
    const state = currentUrl.searchParams.get('state');
    if (!state) throw new ProductAuthenticationError();
    // Consume before network exchange. A failed exchange requires a fresh attempt.
    const attempt = await this.identity.transactions.run('identity', async (tx) => {
      await this.providerCurrent(tx, provider);
      const rows = await tx.manager.query<Attempt[]>(
        `WITH changed AS (UPDATE oidc_login_attempt SET consumed_at=statement_timestamp() WHERE state_hash=$1 AND browser_hash=$2 AND provider_issuer=$3 AND provider_version=$4 AND expires_at>statement_timestamp() AND consumed_at IS NULL RETURNING nonce,verifier,provider_issuer,provider_version,redirect_uri,linking_user_id,linking_session_hash,enrollment_hash,purpose) SELECT * FROM changed`,
        [sessionDigest(state), sessionDigest(browserSecret), issuer, provider.settings.version],
      );
      if (!rows[0]) throw new ProductAuthenticationError();
      return rows[0];
    });
    let claims: ReturnType<Awaited<ReturnType<typeof oidc.authorizationCodeGrant>>['claims']>;
    try {
      const tokens = await oidc.authorizationCodeGrant(provider.configuration, currentUrl, {
        pkceCodeVerifier: attempt.verifier,
        expectedState: state,
        expectedNonce: attempt.nonce,
        idTokenExpected: true,
        ...(attempt.purpose === 'reauth' ? { maxAge: 300 } : {}),
      });
      claims = tokens.claims();
    } catch {
      throw new ProductAuthenticationError();
    }
    if (
      !claims ||
      claims.iss !== issuer ||
      typeof claims.sub !== 'string' ||
      !claims.sub ||
      claims.sub.length > 512
    )
      throw new ProductAuthenticationError();
    const verified = claims;
    const assurance =
      provider.settings.assuranceMappings.find(
        (mapping) =>
          verified.acr === mapping.acr &&
          Array.isArray(verified.amr) &&
          mapping.amr.every((value) => (verified.amr as string[]).includes(value)),
      )?.assurance ?? 'oidc';
    const authenticatedAt =
      typeof verified.auth_time === 'number' ? new Date(verified.auth_time * 1000) : new Date();
    return this.identity.transactions.run(
      attempt.purpose === 'login' ? 'identity' : 'revoke',
      async (tx) => {
        await this.providerCurrent(tx, provider);
        let actor: Awaited<ReturnType<ProductIdentityService['authenticate']>> | undefined;
        if (attempt.purpose === 'link' || attempt.purpose === 'reauth') {
          if (
            !currentSessionSecret ||
            !attempt.linking_session_hash ||
            !timingSafeEqual(sessionDigest(currentSessionSecret), attempt.linking_session_hash)
          )
            throw new ProductAuthenticationError();
          actor = await this.identity.authenticate(tx, currentSessionSecret);
          if (actor.userId !== attempt.linking_user_id) throw new ProductAuthenticationError();
        }
        if (attempt.purpose === 'link') {
          if (!actor?.reauthenticatedAt || Date.now() - actor.reauthenticatedAt.getTime() > 300000)
            throw new ProductAuthenticationError();
          const users = await tx.manager.query<{ auth_epoch: string }[]>(
            `SELECT auth_epoch FROM app_user WHERE id=$1 AND state='active' FOR UPDATE`,
            [actor.userId],
          );
          if (!users[0] || users[0].auth_epoch !== actor.authEpoch)
            throw new ProductAuthenticationError();
          const existing = await tx.manager.query<{ user_id: string; enabled: boolean }[]>(
            `SELECT user_id,enabled FROM external_identity WHERE issuer=$1 AND subject=$2`,
            [issuer, verified.sub],
          );
          if (existing[0] && (existing[0].user_id !== actor.userId || existing[0].enabled))
            throw new ProductAuthenticationError();
          if (existing[0])
            await tx.manager.query(
              `UPDATE external_identity SET enabled=true,binding_version=binding_version+1 WHERE issuer=$1 AND subject=$2 AND user_id=$3`,
              [issuer, verified.sub, actor.userId],
            );
          else
            await tx.manager.query(
              `INSERT INTO external_identity(issuer,subject,user_id) VALUES($1,$2,$3)`,
              [issuer, verified.sub, actor.userId],
            );
          await tx.manager.query(`UPDATE app_user SET auth_epoch=auth_epoch+1 WHERE id=$1`, [
            actor.userId,
          ]);
          await this.identity.invalidate(tx, actor.userId);
          await this.identity.audit(tx, actor.userId, 'identity.oidc-link');
          return undefined;
        }
        if (attempt.purpose === 'activation') {
          // The token used at begin must still be live at commit; the IdP proof must be the exact
          // pre-bound subject.
          const invitation = attempt.enrollment_hash
            ? (await this.invitation(tx, issuer, { userId: attempt.linking_user_id })).find((r) =>
                timingSafeEqual(attempt.enrollment_hash!, this.enrollmentHash(r, issuer)),
              )
            : undefined;
          if (
            !invitation ||
            invitation.subject !== verified.sub ||
            invitation.user_id !== attempt.linking_user_id
          )
            throw new ProductAuthenticationError();
          await tx.manager.query(
            `UPDATE app_user SET state='active',auth_epoch=auth_epoch+1 WHERE id=$1`,
            [invitation.user_id],
          );
          await this.identity.invalidate(tx, invitation.user_id);
          await this.identity.audit(tx, invitation.user_id, 'identity.oidc-activation');
        }
        const bindings = await tx.manager.query<Binding[]>(
          `SELECT e.user_id,e.binding_version,e.enabled,u.state,u.auth_epoch FROM external_identity e JOIN app_user u ON u.id=e.user_id WHERE e.issuer=$1 AND e.subject=$2`,
          [issuer, verified.sub],
        );
        const binding = bindings[0];
        if (
          !binding ||
          !binding.enabled ||
          binding.state !== 'active' ||
          (actor && binding.user_id !== actor.userId)
        )
          throw new ProductAuthenticationError();
        if (attempt.purpose === 'reauth') {
          if (
            !actor ||
            actor.method !== 'oidc' ||
            typeof verified.auth_time !== 'number' ||
            Date.now() / 1000 - verified.auth_time > 300 ||
            verified.auth_time > Date.now() / 1000 + 30
          )
            throw new ProductAuthenticationError();
          await tx.manager.query(
            `UPDATE application_session SET revoked_at=statement_timestamp() WHERE token_hash=$1`,
            [sessionDigest(currentSessionSecret!)],
          );
        }
        const session = await this.identity.createSession(tx, {
          userId: binding.user_id,
          authEpoch: binding.auth_epoch,
          method: 'oidc',
          assurance,
          issuer,
          subject: verified.sub,
          bindingVersion: binding.binding_version,
          providerVersion: provider.settings.version,
          authenticatedAt,
          reauthenticated: attempt.purpose === 'reauth',
        });
        await this.identity.audit(
          tx,
          binding.user_id,
          attempt.purpose === 'reauth' ? 'identity.oidc-reauth' : 'identity.oidc-login',
        );
        return session;
      },
    );
  }
  /** Live OIDC invitations of one pending account with exactly one enabled binding at this issuer. */
  async invitation(
    tx: ProductTransaction,
    issuer: string,
    by: { token: string } | { userId: string | null },
  ): Promise<Invitation[]> {
    const rows = await tx.manager.query<Invitation[]>(
      `SELECT e.user_id,e.subject,e.binding_version,e.enabled,u.state,u.auth_epoch,t.token_hash
       FROM one_time_token t JOIN app_user u ON u.id=t.user_id JOIN external_identity e ON e.user_id=u.id
       WHERE ${'token' in by ? 't.token_hash=$2' : 't.user_id=$2'} AND t.purpose='oidc-activation'
         AND t.consumed_at IS NULL AND t.expires_at>statement_timestamp()
         AND u.state='pending' AND e.issuer=$1 AND e.enabled
       FOR UPDATE OF u,t`,
      [issuer, 'token' in by ? sessionDigest(by.token) : by.userId],
    );
    // Several live invitations of one user are fine; several bindings or users are not.
    if (
      !rows[0] ||
      rows.some((r) => r.user_id !== rows[0]!.user_id || r.subject !== rows[0]!.subject)
    )
      throw new ProductAuthenticationError();
    return rows;
  }
  enrollmentHash(invitation: Invitation, issuer: string): Buffer {
    return secretDigest(
      JSON.stringify([
        invitation.user_id,
        issuer,
        invitation.subject,
        invitation.binding_version,
        invitation.auth_epoch,
        invitation.token_hash.toString('hex'),
      ]),
    );
  }
  async unlink(sessionSecret: string, issuer: string, subject: string): Promise<void> {
    this.provider(issuer);
    await this.identity.transactions.run('revoke', async (tx) => {
      const actor = await this.identity.authenticate(tx, sessionSecret);
      if (!actor.reauthenticatedAt || Date.now() - actor.reauthenticatedAt.getTime() > 300000)
        throw new ProductAuthenticationError();
      const methods = await tx.manager.query<{ remains: boolean }[]>(
        `SELECT (EXISTS(SELECT 1 FROM local_credential WHERE user_id=$1) OR EXISTS(SELECT 1 FROM external_identity e JOIN oidc_provider p ON p.issuer=e.issuer WHERE e.user_id=$1 AND e.enabled AND p.enabled AND (e.issuer<>$2 OR e.subject<>$3))) AS remains`,
        [actor.userId, issuer, subject],
      );
      if (!methods[0]?.remains) throw new ProductAuthenticationError();
      const changed = await tx.manager.query<unknown[]>(
        `WITH changed AS (UPDATE external_identity SET enabled=false,binding_version=binding_version+1 WHERE issuer=$1 AND subject=$2 AND user_id=$3 AND enabled RETURNING user_id) SELECT * FROM changed`,
        [issuer, subject, actor.userId],
      );
      if (!changed.length) throw new ProductAuthenticationError();
      await tx.manager.query(`UPDATE app_user SET auth_epoch=auth_epoch+1 WHERE id=$1`, [
        actor.userId,
      ]);
      await this.identity.invalidate(tx, actor.userId);
      await this.identity.audit(tx, actor.userId, 'identity.oidc-unlink');
    });
  }
}
