import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Effective account rank: the higher of the account column and its assigned roles. Account
 * boundaries and the suspend rank check read this one definition, so a Root role holder cannot
 * pass an `authorityLevel` boundary through a low column value. security_invoker keeps the
 * caller's own column/table privileges.
 */
export class ProductAccountRank1792108800006 implements MigrationInterface {
  name = 'ProductAccountRank1792108800006';
  async up(runner: QueryRunner): Promise<void> {
    await runner.query(`
      CREATE VIEW public.account_rank WITH (security_invoker=true) AS
        SELECT u.id,u.state,GREATEST(u.authority_level,COALESCE(
          (SELECT max(r.authority_level) FROM public.user_role a JOIN public.role_definition r USING(role_key) WHERE a.user_id=u.id),0
        ))::smallint AS authority_level
        FROM public.app_user u;
      REVOKE ALL ON public.account_rank FROM PUBLIC;
      GRANT SELECT ON public.account_rank TO product_authority;
    `);
  }
  async down(runner: QueryRunner): Promise<void> {
    await runner.query('DROP VIEW public.account_rank');
  }
}
