import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * A Root assignment by the bootstrap credential must commit together with the bootstrap marker
 * naming that user. Checked at commit, so the marker update may follow the insert in the same
 * transaction; once initialized, the marker cannot change and 004 refuses further Root inserts.
 */
/**
 * Exact body; the startup probe compares it so a neutralized replacement fails closed.
 * The marker lookup is a nested IF: one IF condition is one query, and PostgreSQL checks table
 * privileges of every relation in it before any short-circuit, while only bootstrap may read it.
 */
export const requireRootMarkerBody = `
BEGIN
  IF NEW.role_key=convert_to('system.root','UTF8') AND current_user='product_bootstrap' THEN
    IF NOT EXISTS(SELECT FROM public.security_bootstrap_state
        WHERE singleton AND initialized_at IS NOT NULL AND target_user_id=NEW.user_id) THEN
      RAISE EXCEPTION 'Root enrollment requires the bootstrap marker' USING ERRCODE='42501';
    END IF;
  END IF;
  RETURN NULL;
END`;

export class ProductRootMarker1792108800007 implements MigrationInterface {
  name = 'ProductRootMarker1792108800007';

  async up(runner: QueryRunner): Promise<void> {
    await runner.query(`
      CREATE FUNCTION public.require_root_marker() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $fn$${requireRootMarkerBody}$fn$;
      REVOKE ALL ON FUNCTION public.require_root_marker() FROM PUBLIC;
      CREATE CONSTRAINT TRIGGER require_root_marker AFTER INSERT ON public.user_role
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.require_root_marker();
    `);
  }

  down(): Promise<void> {
    return Promise.reject(new Error('Root marker guard requires explicit restore'));
  }
}
