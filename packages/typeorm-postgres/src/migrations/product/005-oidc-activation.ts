import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * OIDC activation uses its own one-time token purpose, so an OIDC invitation can never create a
 * local password. Identity no longer needs to read the bootstrap marker.
 */
export class ProductOidcActivation1792108800005 implements MigrationInterface {
  name = 'ProductOidcActivation1792108800005';
  async up(runner: QueryRunner): Promise<void> {
    await runner.query(`
      ALTER TABLE public.one_time_token DROP CONSTRAINT one_time_token_purpose_check;
      ALTER TABLE public.one_time_token ADD CONSTRAINT one_time_token_purpose_check
        CHECK(purpose IN ('activation','reset','oidc-activation'));
      REVOKE SELECT ON public.security_bootstrap_state FROM product_identity;
    `);
  }
  down(): Promise<void> {
    return Promise.reject(new Error('OIDC activation purpose requires explicit restore'));
  }
}
