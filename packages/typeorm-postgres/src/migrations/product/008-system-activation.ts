import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Activation proof for a `system.*` account comes only from the bootstrap credential:
 * - an activation token for a user holding a `system.*` role is inserted only by product_bootstrap;
 * - a `system.*` assignment is refused while its target holds a live activation token, so an
 *   invitation issued before the assignment cannot activate it.
 * The identity login cannot read assignments, so the check runs as the NOLOGIN session owner and
 * judges the connecting login (session_user). Tokens may only go from unconsumed to consumed now,
 * so no login can retarget, revive or delete one; a reissued proof voids its predecessors for good.
 * The bootstrap credential may supersede its own Root proof.
 * This guards operator capabilities; a compromised identity login can already write sessions and
 * credentials of any account.
 */
/** Exact bodies; the startup probe compares them so a neutralized replacement fails closed. */
export const systemActivationBody = `
DECLARE system_prefix constant bytea:=convert_to('system.','UTF8');
BEGIN
  IF TG_TABLE_NAME='one_time_token' THEN
    IF NEW.purpose IN ('activation','oidc-activation') AND session_user<>'product_bootstrap'
      AND EXISTS(SELECT FROM public.user_role WHERE user_id=NEW.user_id AND substring(role_key FROM 1 FOR 7)=system_prefix) THEN
      RAISE EXCEPTION 'system account activation is issued by the bootstrap credential only' USING ERRCODE='42501';
    END IF;
  ELSIF substring(NEW.role_key FROM 1 FOR 7)=system_prefix AND EXISTS(SELECT FROM public.one_time_token
      WHERE user_id=NEW.user_id AND purpose IN ('activation','oidc-activation')
        AND consumed_at IS NULL AND expires_at>statement_timestamp()) THEN
    RAISE EXCEPTION 'system assignment target holds a live activation token' USING ERRCODE='42501';
  END IF;
  RETURN NEW;
END`;

export const tokenConsumptionBody = `
BEGIN
  IF OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS DISTINCT FROM statement_timestamp()
    OR (NEW.token_hash,NEW.user_id,NEW.purpose,NEW.expires_at,NEW.credential_version)
       IS DISTINCT FROM (OLD.token_hash,OLD.user_id,OLD.purpose,OLD.expires_at,OLD.credential_version) THEN
    RAISE EXCEPTION 'one-time tokens may only be consumed' USING ERRCODE='42501';
  END IF;
  RETURN NEW;
END`;

export class ProductSystemActivation1792108800008 implements MigrationInterface {
  name = 'ProductSystemActivation1792108800008';

  async up(runner: QueryRunner): Promise<void> {
    await runner.query(`
      REVOKE UPDATE,DELETE ON public.one_time_token FROM product_identity;
      GRANT UPDATE(consumed_at) ON public.one_time_token TO product_identity;
      GRANT SELECT(user_id,purpose,consumed_at),UPDATE(consumed_at) ON public.one_time_token TO product_bootstrap;
      GRANT SELECT(user_id,role_key) ON public.user_role TO product_session_owner;
      GRANT SELECT(user_id,purpose,consumed_at,expires_at) ON public.one_time_token TO product_session_owner;
      CREATE FUNCTION public.protect_system_activation() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $fn$${systemActivationBody}$fn$;
      -- Triggers first: creating one needs EXECUTE, which the owner change and revoke remove.
      CREATE TRIGGER protect_system_activation BEFORE INSERT ON public.one_time_token
        FOR EACH ROW EXECUTE FUNCTION public.protect_system_activation();
      CREATE TRIGGER protect_system_activation BEFORE INSERT OR UPDATE OF user_id,role_key ON public.user_role
        FOR EACH ROW EXECUTE FUNCTION public.protect_system_activation();
      CREATE FUNCTION public.protect_token_consumption() RETURNS trigger LANGUAGE plpgsql
        SET search_path=pg_catalog,pg_temp AS $fn$${tokenConsumptionBody}$fn$;
      CREATE TRIGGER protect_token_consumption BEFORE UPDATE ON public.one_time_token
        FOR EACH ROW EXECUTE FUNCTION public.protect_token_consumption();
      REVOKE ALL ON FUNCTION public.protect_token_consumption() FROM PUBLIC;
      REVOKE ALL ON FUNCTION public.protect_system_activation() FROM PUBLIC;
      ALTER FUNCTION public.protect_system_activation() OWNER TO product_session_owner;
    `);
  }

  down(): Promise<void> {
    return Promise.reject(new Error('System activation guard requires explicit restore'));
  }
}
