import type { MigrationInterface, QueryRunner } from 'typeorm';
import { codeOwnedCatalogIsEmpty, protectedStateHash } from '../../protected-state.js';

/**
 * IAM without rank, Root outside IAM (ADR 0012, spec 2026-10-14):
 * - `app_user.kind` ('iam'|'root'): at most one Root, promoted once by the offline bootstrap login
 *   under READ COMMITTED together with the marker, never given an IAM fact or a foreign invitation;
 * - `account_rank`, both `authority_level` columns and the `system.*` guards (004 branch, 007, 008)
 *   are gone; `resolve_session` returns `kind`;
 * - a Root holder becomes `kind = 'root'` without IAM facts; the code-owned `system.root` role and
 *   grants leave; `materialized_hash` is republished for the converted state (drift checked first).
 * Runs offline through provisioning (product_migration with temporary owner membership).
 * Bodies are exact; the startup probe compares them.
 */
export const resolveSessionKindBody = `
        SELECT u.id,u.kind,u.state,u.auth_epoch,s.method,s.assurance,s.authenticated_at,s.reauthenticated_at,s.expires_at
        FROM public.application_session s JOIN public.app_user u ON u.id=s.user_id
        LEFT JOIN public.local_credential c ON c.user_id=u.id
        LEFT JOIN public.external_identity e ON e.issuer=s.external_issuer AND e.subject=s.external_subject AND e.user_id=u.id
        WHERE s.token_hash=p_digest AND u.state='active' AND s.auth_epoch=u.auth_epoch
          AND s.revoked_at IS NULL AND s.expires_at>statement_timestamp() AND s.last_seen_at>statement_timestamp()-interval '30 minutes'
          AND ((s.method='local' AND u.email_verified AND c.version=s.credential_version)
            OR (s.method='oidc' AND e.enabled AND e.binding_version=s.binding_version AND EXISTS (SELECT FROM public.oidc_provider p WHERE p.issuer=e.issuer AND p.enabled AND p.version=s.provider_version)))
        `;
/** 004 guard without its user_role branch; every other branch keeps its semantics. */
export const productRowsIamBody = `
      DECLARE old_code boolean:=false; new_code boolean:=false; old_role bytea; new_role bytea;
      BEGIN
        IF TG_TABLE_NAME IN ('role_definition','policy_rule') THEN
          IF TG_OP<>'INSERT' THEN old_code:=OLD.managed_by='code'; END IF;
          IF TG_OP<>'DELETE' THEN new_code:=NEW.managed_by='code'; END IF;
        ELSIF TG_TABLE_NAME IN ('relation_edge','user_boundary') THEN
          IF TG_OP<>'INSERT' THEN old_code:=OLD.seed_owner IS NOT NULL; END IF;
          IF TG_OP<>'DELETE' THEN new_code:=NEW.seed_owner IS NOT NULL; END IF;
        END IF;
        IF current_user='product_sync' THEN
          IF (TG_OP<>'INSERT' AND NOT old_code) OR (TG_OP<>'DELETE' AND NOT new_code) THEN
            RAISE EXCEPTION 'sync cannot take over runtime facts' USING ERRCODE='42501';
          END IF;
        ELSIF old_code OR new_code THEN
          RAISE EXCEPTION 'code owned facts protected' USING ERRCODE='42501';
        END IF;
        IF TG_TABLE_NAME IN ('policy_rule','record_exception')
          AND NOT (TG_TABLE_NAME='policy_rule' AND current_user='product_sync') THEN
          IF TG_OP<>'INSERT' THEN old_role:=OLD.role_key; END IF;
          IF TG_OP<>'DELETE' THEN new_role:=NEW.role_key; END IF;
          IF EXISTS(SELECT FROM public.role_definition WHERE role_key IN (old_role,new_role) AND managed_by='code') THEN
            RAISE EXCEPTION 'system role references protected' USING ERRCODE='42501';
          END IF;
        END IF;
        IF TG_OP='DELETE' THEN RETURN OLD; END IF; RETURN NEW;
      END `;
/**
 * iam→root once: bootstrap login, READ COMMITTED (each EXISTS below sees facts committed after the
 * caller locked the target), pending, unmarked, Rootless, fact-free and without a live invitation.
 */
export const guardRootKindBody = `
BEGIN
  IF TG_OP='INSERT' THEN
    IF NEW.kind='root' THEN
      RAISE EXCEPTION 'Root accounts are created only by promotion' USING ERRCODE='42501';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.kind IS NOT DISTINCT FROM OLD.kind THEN RETURN NEW; END IF;
  IF NOT (OLD.kind='iam' AND NEW.kind='root') THEN
    RAISE EXCEPTION 'account kind is immutable except the one Root promotion' USING ERRCODE='42501';
  END IF;
  IF session_user<>'product_bootstrap' THEN
    RAISE EXCEPTION 'Root promotion is offline bootstrap only' USING ERRCODE='42501';
  END IF;
  IF current_setting('transaction_isolation')<>'read committed' THEN
    RAISE EXCEPTION 'Root promotion requires READ COMMITTED' USING ERRCODE='42501';
  END IF;
  IF OLD.state<>'pending' THEN
    RAISE EXCEPTION 'Root promotion target must be pending' USING ERRCODE='42501';
  END IF;
  IF EXISTS(SELECT FROM public.security_bootstrap_state WHERE singleton AND initialized_at IS NOT NULL)
    OR EXISTS(SELECT FROM public.app_user WHERE kind='root') THEN
    RAISE EXCEPTION 'Root promotion is one-time' USING ERRCODE='42501';
  END IF;
  IF EXISTS(SELECT FROM public.user_role WHERE user_id=NEW.id)
    OR EXISTS(SELECT FROM public.user_boundary WHERE user_id=NEW.id)
    OR EXISTS(SELECT FROM public.policy_rule WHERE user_id=NEW.id)
    OR EXISTS(SELECT FROM public.record_exception WHERE user_id=NEW.id) THEN
    RAISE EXCEPTION 'Root promotion target holds IAM facts' USING ERRCODE='42501';
  END IF;
  IF EXISTS(SELECT FROM public.one_time_token WHERE user_id=NEW.id AND purpose IN ('activation','oidc-activation')
      AND consumed_at IS NULL AND expires_at>statement_timestamp()) THEN
    RAISE EXCEPTION 'Root promotion target holds a live activation token' USING ERRCODE='42501';
  END IF;
  RETURN NEW;
END`;
/** Deferred: a promotion commits only with the marker naming that account. */
export const requireRootMarkerKindBody = `
BEGIN
  IF NEW.kind='root' AND OLD.kind IS DISTINCT FROM 'root' THEN
    IF NOT EXISTS(SELECT FROM public.security_bootstrap_state
        WHERE singleton AND initialized_at IS NOT NULL AND target_user_id=NEW.id) THEN
      RAISE EXCEPTION 'Root promotion requires the bootstrap marker naming it' USING ERRCODE='42501';
    END IF;
  END IF;
  RETURN NULL;
END`;
/** FOR SHARE conflicts with the promotion's FOR NO KEY UPDATE (spec 3.3); FK KEY SHARE does not. */
export const guardRootNotIamSubjectBody = `
DECLARE v_kind text;
BEGIN
  IF NEW.user_id IS NULL THEN RETURN NEW; END IF;
  SELECT kind INTO v_kind FROM public.app_user WHERE id=NEW.user_id FOR SHARE;
  IF v_kind='root' THEN
    RAISE EXCEPTION 'Root is outside IAM: no role, boundary, rule or exception' USING ERRCODE='42501';
  END IF;
  RETURN NEW;
END`;
export const guardRootActivationBody = `
DECLARE v_kind text;
BEGIN
  IF NEW.purpose IN ('activation','oidc-activation') THEN
    SELECT kind INTO v_kind FROM public.app_user WHERE id=NEW.user_id FOR SHARE;
    IF v_kind='root' AND session_user<>'product_bootstrap' THEN
      RAISE EXCEPTION 'Root activation is issued by the bootstrap credential only' USING ERRCODE='42501';
    END IF;
  END IF;
  RETURN NEW;
END`;
/** OLD.kind decides; 004 (protect_account_lifecycle) still bounds identity and authority. */
export const guardRootLifecycleBody = `
BEGIN
  IF OLD.kind='iam' THEN
    IF session_user='product_bootstrap' THEN
      RAISE EXCEPTION 'bootstrap may not change IAM account lifecycle' USING ERRCODE='42501';
    END IF;
  ELSIF session_user='product_bootstrap' THEN
    IF NEW.state<>'suspended' OR NEW.auth_epoch<=OLD.auth_epoch THEN
      RAISE EXCEPTION 'bootstrap may only suspend Root and end its sessions' USING ERRCODE='42501';
    END IF;
  ELSIF session_user<>'product_identity' THEN
    RAISE EXCEPTION 'Root lifecycle is offline or identity only' USING ERRCODE='42501';
  END IF;
  RETURN NEW;
END`;

const root = `convert_to('system.root','UTF8')`;
const rootGrantPermissions = `SELECT permission_key FROM public.policy_rule WHERE role_key=${root} AND managed_by='code'`;
/** A former Root binding stays live while any allow fact could grant its permission (spec 4.2). */
const liveFormerRootBinding = `
  SELECT 1 FROM public.user_boundary b
  WHERE b.user_id=$1 AND b.permission_key IN (${rootGrantPermissions})
    AND (EXISTS(SELECT FROM public.policy_rule r WHERE r.permission_key=b.permission_key AND r.effect='allow'
          AND (r.user_id=$1 OR r.role_key IN (SELECT role_key FROM public.user_role WHERE user_id=$1)))
      OR EXISTS(SELECT FROM public.record_exception x WHERE x.permission_key=b.permission_key AND x.effect='allow'
          AND (x.user_id=$1 OR x.role_key IN (SELECT role_key FROM public.user_role WHERE user_id=$1))))
  LIMIT 1`;
const guards = [
  ['guard_root_kind', guardRootKindBody],
  ['require_root_marker_kind', requireRootMarkerKindBody],
  ['guard_root_not_iam_subject', guardRootNotIamSubjectBody],
  ['guard_root_activation', guardRootActivationBody],
  ['guard_root_lifecycle', guardRootLifecycleBody],
] as const;
const iamTables = ['user_role', 'user_boundary', 'policy_rule', 'record_exception'] as const;
const disabledDuringConversion = ['role_definition', 'policy_rule', 'user_role', 'user_boundary'];

export class ProductIamRoot1792108800012 implements MigrationInterface {
  name = 'ProductIamRoot1792108800012';
  async up(runner: QueryRunner): Promise<void> {
    const m = runner.manager;
    // 1. Lock and read the application state and the marker.
    const [state] = await m.query<{ sequence: string; materialized: string | null }[]>(
      `SELECT release_sequence::text sequence,encode(materialized_hash,'hex') materialized FROM public.authz_state WHERE singleton FOR UPDATE`,
    );
    const [marker] = await m.query<{ target: string | null }[]>(
      'SELECT target_user_id::text target FROM public.security_bootstrap_state WHERE singleton FOR UPDATE',
    );
    if (!state || !marker) throw new Error('application state missing; repair before migration');
    // 2. No drift: the converted state is republished in step 9, so it must start from the published one.
    if (state.sequence !== '0') {
      if ((await protectedStateHash(m)) !== state.materialized)
        throw new Error('code-owned facts drifted; repair before migration');
    } else if (!(await codeOwnedCatalogIsEmpty(m)))
      throw new Error('code-owned facts exist before the first release; repair before migration');
    // 3. Preflight (spec table 4.3).
    const [unknown] = await m.query<unknown[]>(
      `SELECT 1 FROM public.role_definition WHERE substring(role_key FROM 1 FOR 7)=convert_to('system.','UTF8') AND role_key<>${root} LIMIT 1`,
    );
    if (unknown) throw new Error('unknown system.* role; repair before migration');
    const holders = await m.query<{ id: string }[]>(
      `SELECT user_id::text id FROM public.user_role WHERE role_key=${root}`,
    );
    if (holders.length > 1) throw new Error('more than one Root holder; repair before migration');
    const holder = holders[0]?.id;
    if (holder !== undefined && holder !== marker.target)
      throw new Error('Root holder does not match the bootstrap marker; repair before migration');
    const former = holder === undefined ? marker.target : null;
    if (former !== null) {
      const [live] = await m.query<unknown[]>(liveFormerRootBinding, [former]);
      if (live)
        throw new Error('former Root boundary binding is not inert; repair before migration');
    }
    // 4. New schema.
    await runner.query(`
      ALTER TABLE public.app_user ADD COLUMN kind text NOT NULL DEFAULT 'iam' CONSTRAINT ck_app_user_kind CHECK (kind IN ('root','iam'));
      CREATE UNIQUE INDEX ux_app_user_root ON public.app_user ((true)) WHERE kind='root';
      CREATE VIEW public.iam_account WITH (security_invoker=true) AS SELECT id,state FROM public.app_user WHERE kind='iam';
      REVOKE ALL ON public.iam_account FROM PUBLIC;
    `);
    // 5. Kept guards that would block step 6 are disabled by name; replaced ones are dropped.
    for (const table of disabledDuringConversion)
      await runner.query(`ALTER TABLE public.${table} DISABLE TRIGGER protect_product_rows`);
    await runner.query(`
      DROP TRIGGER require_root_marker ON public.user_role;
      DROP TRIGGER protect_system_activation ON public.user_role;
      DROP TRIGGER protect_system_activation ON public.one_time_token;
      DROP FUNCTION public.require_root_marker();
      SET LOCAL ROLE product_session_owner;
      DROP FUNCTION public.protect_system_activation();
      RESET ROLE;
    `);
    // 6. Root conversion; user_relation is untouched on purpose (Root bypasses ReBAC).
    if (holder !== undefined) {
      await m.query(`UPDATE public.app_user SET kind='root' WHERE id=$1`, [holder]);
      for (const table of ['user_boundary', 'policy_rule', 'record_exception', 'user_role'])
        await m.query(`DELETE FROM public.${table} WHERE user_id=$1`, [holder]);
    }
    if (former !== null)
      await m.query(
        `DELETE FROM public.user_boundary WHERE user_id=$1 AND permission_key IN (${rootGrantPermissions})`,
        [former],
      );
    await m.query(`DELETE FROM public.policy_rule WHERE role_key=${root} AND managed_by='code'`);
    await m.query(`DELETE FROM public.role_definition WHERE role_key=${root}`);
    // 7. Old schema out; resolve_session recreated (return type change); grants (spec 3.2, 3.4).
    await runner.query(`
      DROP VIEW public.account_rank;
      SET LOCAL ROLE product_session_owner;
      DROP FUNCTION public.resolve_session(bytea);
      RESET ROLE;
      ALTER TABLE public.app_user DROP COLUMN authority_level;
      ALTER TABLE public.role_definition DROP COLUMN authority_level;
      CREATE FUNCTION public.resolve_session(p_digest bytea)
        RETURNS TABLE(user_id uuid,kind text,state text,auth_epoch bigint,method text,assurance text,authenticated_at timestamptz,reauthenticated_at timestamptz,expires_at timestamptz)
        LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$${resolveSessionKindBody}$fn$;
      REVOKE ALL ON FUNCTION public.resolve_session(bytea) FROM PUBLIC;
      GRANT EXECUTE ON FUNCTION public.resolve_session(bytea) TO product_data,product_identity,product_authority;
      ALTER FUNCTION public.resolve_session(bytea) OWNER TO product_session_owner;
      REVOKE SELECT(role_key) ON public.user_role FROM product_session_owner;
      GRANT SELECT(kind),UPDATE(kind) ON public.app_user TO product_session_owner;
      GRANT SELECT ON public.security_bootstrap_state TO product_session_owner;
      GRANT SELECT(user_id) ON public.user_boundary,public.policy_rule,public.record_exception TO product_session_owner;
      REVOKE INSERT,DELETE ON public.user_role FROM product_bootstrap;
      REVOKE INSERT ON public.user_boundary FROM product_bootstrap;
      GRANT SELECT(kind),UPDATE(kind,state,auth_epoch) ON public.app_user TO product_bootstrap;
      GRANT SELECT(kind) ON public.app_user TO product_authority;
      GRANT SELECT ON public.iam_account TO product_authority;
    `);
    // 8. Guards: 004 body replaced in place (owner/mode kept); Root guards created by this login
    //    (default privileges apply), triggers next, then REVOKE and owner change (002/008 order).
    await runner.query(`
      CREATE OR REPLACE FUNCTION public.protect_product_rows() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $fn$${productRowsIamBody}$fn$;
      REVOKE ALL ON FUNCTION public.protect_product_rows() FROM PUBLIC;
    `);
    for (const [name, body] of guards)
      await runner.query(
        `CREATE FUNCTION public.${name}() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$${body}$fn$`,
      );
    await runner.query(`
      CREATE TRIGGER guard_root_kind BEFORE INSERT OR UPDATE OF kind ON public.app_user
        FOR EACH ROW EXECUTE FUNCTION public.guard_root_kind();
      CREATE CONSTRAINT TRIGGER require_root_marker_kind AFTER UPDATE OF kind ON public.app_user
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.require_root_marker_kind();
      CREATE TRIGGER guard_root_lifecycle BEFORE UPDATE OF state,auth_epoch ON public.app_user
        FOR EACH ROW EXECUTE FUNCTION public.guard_root_lifecycle();
      CREATE TRIGGER guard_root_activation BEFORE INSERT ON public.one_time_token
        FOR EACH ROW EXECUTE FUNCTION public.guard_root_activation();
    `);
    for (const table of iamTables)
      await runner.query(
        `CREATE TRIGGER guard_root_not_iam_subject BEFORE INSERT OR UPDATE ON public.${table} FOR EACH ROW EXECUTE FUNCTION public.guard_root_not_iam_subject()`,
      );
    for (const [name] of guards)
      await runner.query(`
        REVOKE ALL ON FUNCTION public.${name}() FROM PUBLIC;
        ALTER FUNCTION public.${name}() OWNER TO product_session_owner;
      `);
    for (const table of disabledDuringConversion)
      await runner.query(`ALTER TABLE public.${table} ENABLE TRIGGER protect_product_rows`);
    // 9. Publish the converted state; release_sequence and manifest_hash stay. The security facts
    //    changed, so the revision advances in the same transaction (002 only forbids a decrease).
    if (state.sequence !== '0')
      await m.query(
        `UPDATE public.authz_state SET materialized_hash=decode($1,'hex'),revision=revision+1 WHERE singleton`,
        [await protectedStateHash(m)],
      );
  }
  down(): Promise<void> {
    return Promise.reject(new Error('irreversible; restore from backup'));
  }
}
