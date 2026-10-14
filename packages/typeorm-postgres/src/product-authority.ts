import {
  type UserId,
  type UserAuthoritySnapshot,
  type UserAuthorizedPlan,
  type ValidatedDeclarations,
  planUser,
  isCanonicalUuid,
  parseKey,
  normalizeValue,
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

export class ProductAccessDenied extends Error {
  constructor() {
    super('Access denied');
  }
}
const utf8 = (s: string) => Buffer.from(s, 'utf8');
/** Request keys come from callers: a malformed key is invalid input, not a server fault. */
function requestKey(kind: Parameters<typeof parseKey>[0], key: string) {
  try {
    return parseKey(kind, key);
  } catch {
    throw new ProductInvalidRequest('Malformed key');
  }
}
interface SessionProjection {
  user_id: UserId;
  assurance: string;
  authenticated_at: Date;
  reauthenticated_at: Date | null;
  expires_at: Date;
  state: 'active' | 'suspended' | 'pending';
}
export async function readProductAuthority(
  tx: ProductTransaction,
  userId: UserId,
  declarations: ValidatedDeclarations,
  registry: UserAuthoritySnapshot['registry'],
): Promise<UserAuthoritySnapshot> {
  const m = tx.manager;
  const [user] = await m.query<{ id: UserId; state: 'active' | 'suspended' | 'pending' }[]>(
    'SELECT id,state FROM app_user WHERE id=$1',
    [userId],
  );
  const roles = await m.query<{ role: string }[]>(
    `SELECT convert_from(role_key,'UTF8') role FROM user_role WHERE user_id=$1 ORDER BY role_key`,
    [userId],
  );
  const permissions = await m.query<
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
  const rules = await m.query<
    {
      id: string;
      permission: string;
      user_id: UserId | null;
      role: string | null;
      effect: 'allow' | 'deny';
      template: string;
      version: number;
      parameters: Record<string, Scalar>;
    }[]
  >(
    `SELECT rule_id id,convert_from(permission_key,'UTF8') permission,user_id,convert_from(role_key,'UTF8') role,effect,convert_from(template_key,'UTF8') template,template_version version,parameters FROM policy_rule WHERE user_id=$1 OR role_key IN(SELECT role_key FROM user_role WHERE user_id=$1)`,
    [userId],
  );
  const boundaries = await m.query<
    {
      permission: string;
      key: string;
      version: number;
      lifecycle: 'active' | 'deprecated' | 'retired';
    }[]
  >(
    `SELECT convert_from(b.permission_key,'UTF8') permission,convert_from(b.boundary_key,'UTF8') key,b.boundary_version version,d.lifecycle FROM user_boundary b JOIN permission_boundary d USING(boundary_key,boundary_version) WHERE b.user_id=$1`,
    [userId],
  );
  return {
    revision: tx.revision,
    declarations,
    registry,
    user,
    roles: roles.map((r) => r.role),
    permissions: permissions.map((p) => ({
      ...p,
      policy: { key: p.policy_key, version: p.policy_version },
    })),
    rules: rules.map((r) => ({
      id: r.id,
      permission: r.permission,
      subject: r.user_id
        ? { kind: 'identity', identity: r.user_id }
        : { kind: 'role', role: r.role ?? '' },
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
export interface ProductResourceWrite {
  readonly resource: string;
  readonly action: string;
  readonly fields: readonly string[];
}
/** Public service owns session, facts, plan and effects in one transaction; callers cannot supply a plan. */
export class ProductAuthorization {
  private readonly gateway: ProductDataGateway;
  constructor(
    private readonly transactions: ProductTransactionRunner,
    private readonly bindings: ProductBindingRegistry,
    private readonly registry: UserAuthoritySnapshot['registry'],
    private readonly writable: readonly ProductResourceWrite[] = [],
  ) {
    this.gateway = new ProductDataGateway(bindings);
  }
  async checkSession(secret: string): Promise<void> {
    await this.transactions.run('read', async (tx) => {
      await this.session(tx, secret);
    });
  }
  private async session(tx: ProductTransaction, secret: string): Promise<SessionProjection> {
    const [session] = await tx.manager.query<SessionProjection[]>(
      'SELECT * FROM public.resolve_session($1)',
      [sessionDigest(secret)],
    );
    if (!session || !isCanonicalUuid(session.user_id)) throw new ProductAuthenticationError();
    return session;
  }
  private async access<T>(
    secret: string,
    resource: string,
    action: string,
    mode: 'read' | 'write' | 'admin',
    work: (plan: UserAuthorizedPlan, tx: ProductTransaction) => Promise<T>,
  ): Promise<T> {
    return this.transactions.run(mode, async (tx) => {
      // Authority purpose deliberately has no session/credential read capability: use the narrow projection function.
      const session = await this.session(tx, secret);
      const [clock] = await tx.manager.query<{ now: string; deadline: string }[]>(
        `SELECT to_char(statement_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') now,to_char(LEAST($1::timestamptz,statement_timestamp()+interval '2 seconds') AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') deadline`,
        [session.expires_at],
      );
      const snapshot = await readProductAuthority(
        tx,
        session.user_id,
        this.bindings.declarations,
        this.registry,
      );
      const decision = planUser(
        {
          principal: { id: session.user_id, assurance: session.assurance === 'mfa' ? 2 : 1 },
          resource,
          action,
          now: clock!.now,
          validUntil: clock!.deadline,
          context: {
            freshAuthentication:
              session.reauthenticated_at !== null &&
              session.reauthenticated_at.getTime() <= Date.parse(clock!.now) &&
              Date.parse(clock!.now) - session.reauthenticated_at.getTime() < 300000,
          },
        },
        snapshot,
      );
      if (decision.effect !== 'allow') throw new ProductAccessDenied();
      const result = await work(decision.plan, tx);
      for (const obligation of decision.obligations) {
        if (obligation.handler !== 'audit@1') throw new ProductAccessDenied();
        await this.audit(tx, decision.plan, `access.${action}`);
      }
      return result;
    });
  }
  private async audit(
    tx: ProductTransaction,
    plan: UserAuthorizedPlan,
    kind: string,
  ): Promise<void> {
    await tx.manager.query(
      `INSERT INTO audit_outbox(event_id,actor_id,event_kind,permission_key,policy_revision,occurred_at,safe_metadata) VALUES(gen_random_uuid(),$1,$2,$3,$4,statement_timestamp(),'{}')`,
      [
        plan.userId,
        utf8(kind),
        utf8(plan.permission),
        tx.mode === 'admin' ? String(BigInt(tx.revision) + 1n) : tx.revision,
      ],
    );
  }
  list(secret: string, resource: string, action: string, query: ListQuery = {}) {
    return this.access(secret, resource, action, 'read', (plan, tx) =>
      this.gateway.list(plan, query, tx),
    );
  }
  detail(secret: string, resource: string, action: string, key: string) {
    return this.access(secret, resource, action, 'read', (plan, tx) =>
      this.gateway.detail(
        plan,
        requestKey(this.bindings.declarations.resources[resource]!.keyKind, key),
        tx,
      ),
    );
  }
  count(secret: string, resource: string, action: string) {
    return this.access(secret, resource, action, 'read', (plan, tx) =>
      this.gateway.count(plan, {}, tx),
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
    return this.access(secret, resource, action, 'write', async (plan, tx) => {
      const binding = this.bindings.resource(resource);
      const bound = compilePlan(plan, this.bindings);
      const params = [...bound.parameters];
      const assignments = fields.map((f) => {
        const value = normalizeValue(
          this.bindings.declarations.resources[resource]!.fields[f]!.kind,
          changes[f],
        );
        if (value === undefined) throw new ProductAccessDenied();
        params.push(value);
        return `${quoteIdentifier(binding.columns[f]!)}=CAST($${params.length} AS ${fieldPgTypes[this.bindings.declarations.resources[resource]!.fields[f]!.kind]})`;
      });
      params.push(requestKey(this.bindings.declarations.resources[resource]!.keyKind, key).value);
      const rows = await tx.manager.query<unknown[]>(
        `WITH updated AS(UPDATE ${quoteIdentifier(binding.table)} r SET ${assignments.join(',')} WHERE ${bound.sql} AND r.${quoteIdentifier(binding.keyColumn)}=CAST($${params.length} AS ${keyPgTypes[this.bindings.declarations.resources[resource]!.keyKind]}) RETURNING 1) SELECT * FROM updated`,
        params,
      );
      if (rows.length) await this.audit(tx, plan, 'data.update');
      return rows.length === 1;
    });
  }
  async suspendUser(secret: string, target: string): Promise<boolean> {
    if (!isCanonicalUuid(target)) throw new ProductAccessDenied();
    return this.access(secret, 'account', 'suspend', 'admin', async (plan, tx) => {
      if (plan.userId === target) throw new ProductAccessDenied();
      const row = await this.gateway.detail(plan, parseKey('uuid', target), tx);
      if (!row) return false;
      const rank = await tx.manager.query<{ id: string; rank: string }[]>(
        `SELECT id,authority_level::text rank FROM account_rank WHERE id=ANY($1::uuid[])`,
        [[plan.userId, target]],
      );
      const actorRank = rank.find((r) => r.id === plan.userId)?.rank;
      const targetRank = rank.find((r) => r.id === target)?.rank;
      if (!actorRank || !targetRank || BigInt(actorRank) <= BigInt(targetRank))
        throw new ProductAccessDenied();
      await tx.manager.query(
        `UPDATE app_user SET state='suspended',auth_epoch=auth_epoch+1 WHERE id=$1`,
        [target],
      );
      await this.audit(tx, plan, 'account.suspend');
      return true;
    });
  }
}
