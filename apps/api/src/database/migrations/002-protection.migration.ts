import type { MigrationInterface, QueryRunner } from 'typeorm';

/** Exact bodies; the startup probe compares them so a neutralized replacement fails closed. */
export const sharedFenceBody = `
        DECLARE v_revision bigint; v_required integer;
        BEGIN
          SELECT revision,min_runtime_capability INTO v_revision,v_required FROM public.authz_state WHERE singleton FOR SHARE;
          IF NOT FOUND THEN RAISE EXCEPTION 'application fence missing' USING ERRCODE='P0002'; END IF;
          IF v_required>p_capability THEN RAISE EXCEPTION 'runtime incompatible' USING ERRCODE='AZ001'; END IF;
          RETURN v_revision;
        END `;

export const resolveSessionBody = `
        SELECT u.id,u.state,u.auth_epoch,u.authority_level,s.method,s.assurance,s.authenticated_at,s.reauthenticated_at,s.expires_at
        FROM public.application_session s JOIN public.app_user u ON u.id=s.user_id
        LEFT JOIN public.local_credential c ON c.user_id=u.id
        LEFT JOIN public.external_identity e ON e.issuer=s.external_issuer AND e.subject=s.external_subject AND e.user_id=u.id
        WHERE s.token_hash=p_digest AND u.state='active' AND s.auth_epoch=u.auth_epoch
          AND s.revoked_at IS NULL AND s.expires_at>statement_timestamp() AND s.last_seen_at>statement_timestamp()-interval '30 minutes'
          AND ((s.method='local' AND u.email_verified AND c.version=s.credential_version)
            OR (s.method='oidc' AND e.enabled AND e.binding_version=s.binding_version AND EXISTS (SELECT FROM public.oidc_provider p WHERE p.issuer=e.issuer AND p.enabled AND p.version=s.provider_version)))
        `;

export const productStateBody = `
      BEGIN
        IF TG_TABLE_NAME='security_bootstrap_state' THEN
          IF OLD.initialized_at IS NOT NULL AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'bootstrap marker is permanent' USING ERRCODE='42501';
          END IF;
        ELSIF NEW.revision<OLD.revision OR NEW.release_sequence<OLD.release_sequence OR NEW.min_runtime_capability<OLD.min_runtime_capability THEN
          RAISE EXCEPTION 'application authority state cannot downgrade' USING ERRCODE='42501';
        END IF;
        RETURN NEW;
      END `;

export class ProductProtection1792108800001 implements MigrationInterface {
  name = 'ProductProtection1792108800001';

  async up(runner: QueryRunner): Promise<void> {
    await runner.query(`
      GRANT USAGE ON SCHEMA public TO product_data,product_identity,product_authority,product_sync,product_bootstrap,product_fence_owner,product_session_owner;
      REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
      ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
      GRANT SELECT(revision,min_runtime_capability,singleton),UPDATE(singleton) ON authz_state TO product_fence_owner;
      CREATE FUNCTION public.authz_acquire_shared_fence(p_capability integer) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $fn$${sharedFenceBody}$fn$;
      REVOKE ALL ON FUNCTION public.authz_acquire_shared_fence(integer) FROM PUBLIC;
      GRANT EXECUTE ON FUNCTION public.authz_acquire_shared_fence(integer) TO product_data,product_identity;
      ALTER FUNCTION public.authz_acquire_shared_fence(integer) OWNER TO product_fence_owner;
      GRANT SELECT(id,state,auth_epoch,authority_level,email_verified) ON app_user TO product_session_owner;
      GRANT SELECT(token_hash,user_id,auth_epoch,method,assurance,authenticated_at,reauthenticated_at,expires_at,revoked_at,last_seen_at,credential_version,external_issuer,external_subject,binding_version,provider_version) ON application_session TO product_session_owner;
      GRANT SELECT(user_id,version) ON local_credential TO product_session_owner;
      GRANT SELECT(user_id) ON local_credential TO product_bootstrap;
      GRANT SELECT(issuer,subject,user_id,enabled,binding_version) ON external_identity TO product_session_owner,product_bootstrap;
      CREATE FUNCTION public.resolve_session(p_digest bytea)
        RETURNS TABLE(user_id uuid,state text,auth_epoch bigint,authority_level smallint,method text,assurance text,authenticated_at timestamptz,reauthenticated_at timestamptz,expires_at timestamptz)
        LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$${resolveSessionBody}$fn$;
      REVOKE ALL ON FUNCTION public.resolve_session(bytea) FROM PUBLIC;
      GRANT EXECUTE ON FUNCTION public.resolve_session(bytea) TO product_data,product_identity,product_authority;
      ALTER FUNCTION public.resolve_session(bytea) OWNER TO product_session_owner;
      GRANT SELECT ON resource_type,permission_policy,permission_catalog,scope_template,role_definition,user_role,policy_rule,object_ref,record_exception,resource_relation_definition,relation_edge,user_relation,permission_boundary,permission_boundary_entry,user_boundary TO product_data,product_authority,product_sync,product_bootstrap;
      GRANT SELECT(id,state,auth_epoch,authority_level) ON app_user TO product_data,product_authority,product_bootstrap;
      GRANT SELECT,INSERT,UPDATE,DELETE ON local_credential,external_identity,application_session,one_time_token,oidc_login_attempt,rate_limit TO product_identity;
      GRANT SELECT ON oidc_provider TO product_identity,product_sync;
      GRANT SELECT(issuer,version,enabled) ON oidc_provider TO product_session_owner;
      GRANT SELECT ON app_user TO product_identity;
      GRANT SELECT(email_canonical) ON app_user TO product_bootstrap;
      GRANT INSERT(id,email_canonical,email_verified,state,auth_epoch) ON app_user TO product_identity;
      GRANT UPDATE(email_canonical,email_verified,state,auth_epoch) ON app_user TO product_identity;
      GRANT UPDATE(state,auth_epoch,authority_level) ON app_user TO product_authority;
      GRANT SELECT,UPDATE(revision) ON authz_state TO product_identity,product_authority,product_bootstrap;
      GRANT SELECT,UPDATE ON authz_state TO product_sync;
      GRANT INSERT,UPDATE,DELETE ON role_definition,user_role,policy_rule,record_exception,relation_edge,user_relation,user_boundary,object_ref TO product_authority;
      GRANT INSERT,UPDATE,DELETE ON resource_type,permission_policy,permission_catalog,scope_template,role_definition,policy_rule,resource_relation_definition,permission_boundary,permission_boundary_entry,relation_edge,user_boundary,oidc_provider TO product_sync;
      GRANT INSERT ON object_ref TO product_sync;
      GRANT SELECT,UPDATE ON security_bootstrap_state TO product_bootstrap;
      GRANT SELECT(target_user_id,initialized_at) ON security_bootstrap_state TO product_identity;
      GRANT INSERT ON user_role,user_boundary,one_time_token TO product_bootstrap;
      GRANT INSERT ON audit_outbox TO product_data,product_identity,product_authority,product_sync,product_bootstrap;

      CREATE FUNCTION public.protect_product_state() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $fn$${productStateBody}$fn$;
      REVOKE ALL ON FUNCTION public.protect_product_state() FROM PUBLIC;
      CREATE TRIGGER protect_product_state BEFORE UPDATE ON public.security_bootstrap_state FOR EACH ROW EXECUTE FUNCTION public.protect_product_state();
      CREATE TRIGGER protect_product_state BEFORE UPDATE ON public.authz_state FOR EACH ROW EXECUTE FUNCTION public.protect_product_state();
      CREATE FUNCTION public.protect_product_rows() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $fn$
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
        IF TG_TABLE_NAME IN ('policy_rule','record_exception','user_role') THEN
          IF TG_OP<>'INSERT' THEN old_role:=OLD.role_key; END IF;
          IF TG_OP<>'DELETE' THEN new_role:=NEW.role_key; END IF;
          IF EXISTS(SELECT FROM public.role_definition WHERE role_key IN (old_role,new_role) AND managed_by='code')
            AND NOT (TG_TABLE_NAME='policy_rule' AND current_user='product_sync')
            AND NOT (TG_TABLE_NAME='user_role' AND current_user='product_bootstrap' AND TG_OP='INSERT') THEN
            RAISE EXCEPTION 'system role references protected' USING ERRCODE='42501';
          END IF;
        END IF;
        IF TG_OP='DELETE' THEN RETURN OLD; END IF; RETURN NEW;
      END $fn$;
      REVOKE ALL ON FUNCTION public.protect_product_rows() FROM PUBLIC;
    `);
    for (const table of [
      'role_definition',
      'policy_rule',
      'record_exception',
      'user_role',
      'relation_edge',
      'user_boundary',
    ]) {
      await runner.query(
        `CREATE TRIGGER protect_product_rows BEFORE INSERT OR UPDATE OR DELETE ON public.${table} FOR EACH ROW EXECUTE FUNCTION public.protect_product_rows()`,
      );
    }
  }

  down(): Promise<void> {
    return Promise.reject(new Error('Protected product schema requires explicit restore'));
  }
}
