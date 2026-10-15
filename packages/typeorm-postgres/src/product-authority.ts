import {
  type AuthorizationCore,
  type KeyKind,
  type UserId,
  type UserAuthoritySnapshot,
  type UserAuthorizedPlan,
  type UserTrustedInput,
  type ValidatedDeclarations,
  type Scalar,
} from '@base-authorization/core';
import { ProductTransactionRunner, type ProductTransaction } from './product-transaction.js';
import {
  ProductBindingRegistry,
  compilePlan,
  quoteIdentifier,
  fieldPgTypes,
  keyPgTypes,
} from './product-sql.js';
import { ProductDataGateway, ProductInvalidRequest, type ListQuery } from './product-gateway.js';
import { sessionDigest, ProductAuthenticationError } from './product-identity.js';
import { appendProductAudit, type ProductAuditEvent } from './product-audit.js';
import {
  fulfillProductObligations,
  type ProductObligationRegistry,
} from './product-obligations.js';

export class ProductAccessDenied extends Error {
  constructor() {
    super('Access denied');
  }
}
/** Request keys come from callers: a malformed key is invalid input, not a server fault. */
function requestKey(core: AuthorizationCore, kind: KeyKind, key: string) {
  try {
    return core.parseKey(kind, key);
  } catch {
    throw new ProductInvalidRequest('Malformed key');
  }
}
interface SessionProjection {
  user_id: UserId;
  /** From resolve_session in this fenced transaction; never from a request or a role name. */
  kind: 'root' | 'iam';
  assurance: string;
  authenticated_at: Date;
  reauthenticated_at: Date | null;
  expires_at: Date;
  state: 'active' | 'suspended' | 'pending';
  /** PRODUCT_FRESH_AUTH_SQL, by the DB clock of the same statement. */
  fresh: boolean;
  /** DB clock of the same statement and the plan deadline (never past session expiry). */
  now: string;
  deadline: string;
}
type PrincipalKind = SessionProjection['kind'];
/**
 * Fresh reauthentication: in the past and less than 300 seconds before the statement time.
 * Evaluated in SQL so the DB clock and microseconds decide (spec 6.4).
 */
export const PRODUCT_FRESH_AUTH_SQL =
  "(reauthenticated_at IS NOT NULL AND reauthenticated_at<=statement_timestamp() AND statement_timestamp()-reauthenticated_at<interval '300 seconds')";
type Lifecycle = 'active' | 'deprecated' | 'retired';
/**
 * Facts of one user for one permission, read in one statement after the fence. The planner only
 * consults the catalog row, rules and boundary bindings of the requested permission, so rows of
 * other permissions are not loaded; user and all roles are (roles feed record exceptions).
 */
export async function readProductAuthority(
  tx: ProductTransaction,
  userId: UserId,
  permission: string,
  declarations: ValidatedDeclarations,
  registry: UserAuthoritySnapshot['registry'],
): Promise<UserAuthoritySnapshot> {
  const [facts] = await tx.manager.query<
    {
      user: { id: UserId; state: 'active' | 'suspended' | 'pending' } | null;
      roles: string[];
      permissions: {
        key: string;
        resource: string;
        action: string;
        policy_key: string;
        policy_version: number;
        lifecycle: Lifecycle;
        boundary: 'required' | 'optional' | null;
      }[];
      rules: {
        id: string;
        permission: string;
        user_id: UserId | null;
        role: string | null;
        effect: 'allow' | 'deny';
        template: string;
        version: number;
        parameters: Record<string, Scalar>;
      }[];
      boundaries: { permission: string; key: string; version: number; lifecycle: Lifecycle }[];
    }[]
  >(
    `SELECT
      (SELECT json_build_object('id',id,'state',state) FROM app_user WHERE id=$1) "user",
      ARRAY(SELECT convert_from(role_key,'UTF8') FROM user_role WHERE user_id=$1 ORDER BY role_key) roles,
      (SELECT COALESCE(json_agg(json_build_object('key',convert_from(permission_key,'UTF8'),'resource',convert_from(type_key,'UTF8'),'action',convert_from(action_key,'UTF8'),'policy_key',convert_from(policy_key,'UTF8'),'policy_version',policy_version,'lifecycle',lifecycle,'boundary',boundary_requirement)),'[]')
        FROM permission_catalog WHERE permission_key=convert_to($2,'UTF8')) permissions,
      (SELECT COALESCE(json_agg(json_build_object('id',rule_id,'permission',convert_from(permission_key,'UTF8'),'user_id',user_id,'role',convert_from(role_key,'UTF8'),'effect',effect,'template',convert_from(template_key,'UTF8'),'version',template_version,'parameters',parameters) ORDER BY rule_id),'[]')
        FROM policy_rule WHERE permission_key=convert_to($2,'UTF8') AND (user_id=$1 OR role_key IN(SELECT role_key FROM user_role WHERE user_id=$1))) rules,
      (SELECT COALESCE(json_agg(json_build_object('permission',convert_from(b.permission_key,'UTF8'),'key',convert_from(b.boundary_key,'UTF8'),'version',b.boundary_version,'lifecycle',d.lifecycle)),'[]')
        FROM user_boundary b JOIN permission_boundary d USING(boundary_key,boundary_version) WHERE b.user_id=$1 AND b.permission_key=convert_to($2,'UTF8')) boundaries`,
    [userId, permission],
  );
  if (!facts) throw new Error('Authority statement returned no row');
  return {
    revision: tx.revision,
    declarations,
    registry,
    user: facts.user ?? undefined,
    roles: facts.roles,
    permissions: facts.permissions.map((p) => ({
      ...p,
      policy: { key: p.policy_key, version: p.policy_version },
    })),
    rules: facts.rules.map((r) => ({
      id: r.id,
      permission: r.permission,
      subject: r.user_id
        ? { kind: 'identity', identity: r.user_id }
        : { kind: 'role', role: r.role ?? '' },
      effect: r.effect,
      template: { key: r.template, version: r.version },
      parameters: r.parameters,
    })),
    boundaries: facts.boundaries.map((b) => ({
      identity: userId,
      permission: b.permission,
      boundary: { key: b.key, version: b.version },
      lifecycle: b.lifecycle,
    })),
  };
}
export interface ProductResourceWrite {
  readonly resource: string;
  readonly action: string;
  readonly fields: readonly string[];
}
/** Public service owns session, facts, plan and effects in one transaction; callers cannot supply a plan. */
export class ProductAuthorization {
  private readonly gateway: ProductDataGateway;
  private readonly registry: UserAuthoritySnapshot['registry'];
  private readonly obligations: ProductObligationRegistry;
  /** Obligation handlers are fixed at composition (frozen copy); core sees exactly their names. */
  constructor(
    private readonly transactions: ProductTransactionRunner,
    private readonly bindings: ProductBindingRegistry,
    capabilities: {
      readonly validators: UserAuthoritySnapshot['registry']['validators'];
      readonly obligations: ProductObligationRegistry;
    },
    private readonly writable: readonly ProductResourceWrite[] = [],
  ) {
    this.gateway = new ProductDataGateway(bindings);
    this.obligations = Object.freeze({ ...capabilities.obligations });
    this.registry = {
      validators: capabilities.validators,
      obligationHandlers: Object.freeze(Object.keys(this.obligations)),
    };
  }
  async checkSession(secret: string): Promise<void> {
    await this.transactions.run('read', async (tx) => {
      await this.session(tx, secret);
    });
  }
  private async session(tx: ProductTransaction, secret: string): Promise<SessionProjection> {
    const [session] = await tx.manager.query<SessionProjection[]>(
      `SELECT s.*,${PRODUCT_FRESH_AUTH_SQL} fresh,to_char(statement_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') now,to_char(LEAST(s.expires_at,statement_timestamp()+interval '2 seconds') AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') deadline FROM public.resolve_session($1) s`,
      [sessionDigest(secret)],
    );
    if (
      !session ||
      !this.bindings.core.isCanonicalUuid(session.user_id) ||
      (session.kind !== 'root' && session.kind !== 'iam')
    )
      throw new ProductAuthenticationError();
    return session;
  }
  /**
   * The only Root branch (ADR 0012): `kind` comes from the verified session. Root still needs a
   * valid session, a fresh reauthentication for write/admin, a declared action, the projection
   * and writable allowlists, and leaves one audit event per committed access.
   */
  private async access<T>(
    secret: string,
    resource: string,
    action: string,
    mode: 'read' | 'write' | 'admin',
    work: (plan: UserAuthorizedPlan, tx: ProductTransaction, kind: PrincipalKind) => Promise<T>,
    rootEvent: (plan: UserAuthorizedPlan, result: T) => ProductAuditEvent,
  ): Promise<T> {
    return this.transactions.run(mode, async (tx) => {
      // Authority purpose deliberately has no session/credential read capability: use the narrow projection function.
      const session = await this.session(tx, secret);
      if (session.kind === 'root' && mode !== 'read' && !session.fresh)
        throw new ProductAccessDenied();
      const snapshot = await readProductAuthority(
        tx,
        session.user_id,
        `${resource}.${action}`,
        this.bindings.declarations,
        this.registry,
      );
      const input: UserTrustedInput = {
        principal: { id: session.user_id, assurance: session.assurance === 'mfa' ? 2 : 1 },
        resource,
        action,
        now: session.now,
        validUntil: session.deadline,
        context: { freshAuthentication: session.fresh },
      };
      const decision =
        session.kind === 'root'
          ? this.bindings.core.planUnrestricted(input, snapshot)
          : this.bindings.core.planUser(input, snapshot);
      if (decision.effect !== 'allow') throw new ProductAccessDenied();
      const result = await work(decision.plan, tx, session.kind);
      if (session.kind === 'root') await appendProductAudit(tx, rootEvent(decision.plan, result));
      await fulfillProductObligations(tx, decision.plan, this.obligations);
      return result;
    });
  }
  /** Requested key of a Root audit target (spec 6.5); parsed like the operation parsed it. */
  private requested(resource: string, key: string) {
    const keyKind = this.bindings.declarations.resources[resource]!.keyKind;
    return { resource, keyKind, key: requestKey(this.bindings.core, keyKind, key).value };
  }
  private static readonly ok = { principalKind: 'root', outcome: 'ok' } as const;
  list(secret: string, resource: string, action: string, query: ListQuery = {}) {
    return this.access(
      secret,
      resource,
      action,
      'read',
      (plan, tx) => this.gateway.list(plan, query, tx),
      (plan) => ({
        kind: `access.${plan.resource}.${plan.action}`,
        actor: plan.userId,
        permission: plan.permission,
        ...ProductAuthorization.ok,
      }),
    );
  }
  detail(secret: string, resource: string, action: string, key: string) {
    return this.access(
      secret,
      resource,
      action,
      'read',
      (plan, tx) =>
        this.gateway.detail(
          plan,
          requestKey(
            this.bindings.core,
            this.bindings.declarations.resources[resource]!.keyKind,
            key,
          ),
          tx,
        ),
      (plan, row) => ({
        kind: `access.${plan.resource}.${plan.action}`,
        actor: plan.userId,
        permission: plan.permission,
        principalKind: 'root',
        outcome: row ? 'ok' : 'absent',
        target: this.requested(resource, key),
      }),
    );
  }
  count(secret: string, resource: string, action: string) {
    return this.access(
      secret,
      resource,
      action,
      'read',
      (plan, tx) => this.gateway.count(plan, {}, tx),
      (plan) => ({
        kind: `access.${plan.resource}.${plan.action}`,
        actor: plan.userId,
        permission: plan.permission,
        ...ProductAuthorization.ok,
      }),
    );
  }
  async update(
    secret: string,
    resource: string,
    action: string,
    key: string,
    changes: Readonly<Record<string, Scalar>>,
  ): Promise<boolean> {
    const declaration = this.writable.find((r) => r.resource === resource && r.action === action);
    const fields = Object.keys(changes);
    if (!declaration || fields.length === 0 || fields.some((f) => !declaration.fields.includes(f)))
      throw new ProductAccessDenied();
    const objectId = await this.access(
      secret,
      resource,
      action,
      'write',
      async (plan, tx, kind) => {
        const binding = this.bindings.resource(resource);
        const bound = compilePlan(plan, this.bindings);
        const params = [...bound.parameters];
        const assignments = fields.map((f) => {
          const value = this.bindings.core.normalizeValue(
            this.bindings.declarations.resources[resource]!.fields[f]!.kind,
            changes[f],
          );
          if (value === undefined) throw new ProductAccessDenied();
          params.push(value);
          return `${quoteIdentifier(binding.columns[f]!)}=CAST($${params.length} AS ${fieldPgTypes[this.bindings.declarations.resources[resource]!.fields[f]!.kind]})`;
        });
        const keyKind = this.bindings.declarations.resources[resource]!.keyKind;
        const typedKey = requestKey(this.bindings.core, keyKind, key);
        params.push(typedKey.value);
        const rows = await tx.manager.query<{ object_id: string }[]>(
          `WITH updated AS(UPDATE ${quoteIdentifier(binding.table)} r SET ${assignments.join(',')} WHERE ${bound.sql} AND r.${quoteIdentifier(binding.keyColumn)}=CAST($${params.length} AS ${keyPgTypes[keyKind]}) RETURNING r.${quoteIdentifier(binding.objectIdColumn)} AS object_id) SELECT * FROM updated`,
          params,
        );
        if (rows.length && kind === 'iam')
          await appendProductAudit(tx, {
            kind: 'data.update',
            actor: plan.userId,
            permission: plan.permission,
            target: { resource, keyKind, key: typedKey.value, objectId: rows[0]!.object_id },
          });
        return rows[0]?.object_id;
      },
      (plan, updated): ProductAuditEvent =>
        updated === undefined
          ? {
              kind: 'data.update',
              actor: plan.userId,
              permission: plan.permission,
              principalKind: 'root',
              outcome: 'absent',
              target: this.requested(resource, key),
            }
          : {
              kind: 'data.update',
              actor: plan.userId,
              permission: plan.permission,
              principalKind: 'root',
              outcome: 'ok',
              target: { ...this.requested(resource, key), objectId: updated },
            },
    );
    return objectId !== undefined;
  }
  async suspendUser(secret: string, target: string): Promise<boolean> {
    if (!this.bindings.core.isCanonicalUuid(target)) throw new ProductAccessDenied();
    return this.access(
      secret,
      'account',
      'suspend',
      'admin',
      async (plan, tx, kind) => {
        if (plan.userId === target) throw new ProductAccessDenied();
        // iam_account (012) holds IAM accounts only; rank no longer exists (ADR 0012).
        const row = await this.gateway.detail(
          plan,
          this.bindings.core.parseKey('uuid', target),
          tx,
        );
        if (!row) return false;
        await tx.manager.query(
          `UPDATE app_user SET state='suspended',auth_epoch=auth_epoch+1 WHERE id=$1`,
          [target],
        );
        if (kind === 'iam')
          await appendProductAudit(tx, {
            kind: 'account.suspend',
            actor: plan.userId,
            permission: plan.permission,
            target: { userId: target },
          });
        return true;
      },
      (plan, suspended) => ({
        kind: 'account.suspend',
        actor: plan.userId,
        permission: plan.permission,
        principalKind: 'root',
        outcome: suspended ? 'ok' : 'absent',
        target: { userId: target },
      }),
    );
  }
}
