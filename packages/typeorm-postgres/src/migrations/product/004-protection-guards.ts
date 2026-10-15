import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Role assignment and account lifecycle guards enforced by the database:
 * - `system.*` assignments are offline only: the bootstrap credential may add the first Root while
 *   the marker is uninitialized and nobody holds Root, and may revoke Root. Nothing else.
 * - Other assignments, including code-owned roles, are runtime facts for the authority writer.
 *   Grants and record exceptions of code-owned roles stay code-owned.
 * - Identity may only activate pending accounts; it cannot lift a suspension or change email.
 *   Authority may only suspend; it cannot activate a pending account or reopen one.
 * Each branch only reads tables its caller may read. Bodies are exact; the startup probe compares them.
 */
export const productRowsBody = `
      DECLARE old_code boolean:=false; new_code boolean:=false; old_role bytea; new_role bytea;
        root constant bytea:=convert_to('system.root','UTF8'); system_prefix constant bytea:=convert_to('system.','UTF8');
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
        END IF;
        IF TG_TABLE_NAME='user_role' THEN
          IF current_user='product_bootstrap' THEN
            IF TG_OP='DELETE' AND old_role=root THEN
              NULL;
            ELSIF TG_OP='INSERT' AND new_role=root THEN
              IF EXISTS(SELECT FROM public.security_bootstrap_state WHERE singleton AND initialized_at IS NOT NULL)
                OR EXISTS(SELECT FROM public.user_role WHERE role_key=root) THEN
                RAISE EXCEPTION 'Root enrollment is one-time' USING ERRCODE='42501';
              END IF;
            ELSE
              RAISE EXCEPTION 'bootstrap may only enroll or revoke Root' USING ERRCODE='42501';
            END IF;
          ELSIF COALESCE(substring(old_role FROM 1 FOR 7)=system_prefix,false)
            OR COALESCE(substring(new_role FROM 1 FOR 7)=system_prefix,false) THEN
            RAISE EXCEPTION 'system role assignment requires the offline command' USING ERRCODE='42501';
          END IF;
        ELSIF TG_TABLE_NAME IN ('policy_rule','record_exception')
          AND NOT (TG_TABLE_NAME='policy_rule' AND current_user='product_sync') THEN
          IF EXISTS(SELECT FROM public.role_definition WHERE role_key IN (old_role,new_role) AND managed_by='code') THEN
            RAISE EXCEPTION 'system role references protected' USING ERRCODE='42501';
          END IF;
        END IF;
        IF TG_OP='DELETE' THEN RETURN OLD; END IF; RETURN NEW;
      END `;

export const accountLifecycleBody = `
      BEGIN
        IF current_user='product_identity' AND NEW.state IS DISTINCT FROM OLD.state
          AND NOT (OLD.state='pending' AND NEW.state='active') THEN
          RAISE EXCEPTION 'identity may only activate pending accounts' USING ERRCODE='42501';
        ELSIF current_user='product_authority' AND NEW.state IS DISTINCT FROM OLD.state
          AND NEW.state<>'suspended' THEN
          RAISE EXCEPTION 'authority may only suspend accounts' USING ERRCODE='42501';
        END IF;
        RETURN NEW;
      END `;

export class ProductProtectionGuards1792108800004 implements MigrationInterface {
  name = 'ProductProtectionGuards1792108800004';

  async up(runner: QueryRunner): Promise<void> {
    await runner.query(`
      CREATE OR REPLACE FUNCTION public.protect_product_rows() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $fn$${productRowsBody}$fn$;
      REVOKE ALL ON FUNCTION public.protect_product_rows() FROM PUBLIC;
      GRANT DELETE ON public.user_role TO product_bootstrap;

      REVOKE UPDATE(email_canonical) ON public.app_user FROM product_identity;
      CREATE FUNCTION public.protect_account_lifecycle() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $fn$${accountLifecycleBody}$fn$;
      REVOKE ALL ON FUNCTION public.protect_account_lifecycle() FROM PUBLIC;
      CREATE TRIGGER protect_account_lifecycle BEFORE UPDATE ON public.app_user FOR EACH ROW EXECUTE FUNCTION public.protect_account_lifecycle();
    `);
  }

  down(): Promise<void> {
    return Promise.reject(new Error('Protection guards require explicit restore'));
  }
}
