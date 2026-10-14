import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Delivery state for the audit outbox worker (ADR0011): lease, bounded attempts and a parked
 * (dead) marker. Schema USAGE comes from provisioning (the migration login does not own public);
 * the claim index is built concurrently in 011. The outbox login reads events and updates only these columns and delivered_at;
 * it cannot insert, delete or rewrite event content, and reads no other table.
 */
export class ProductAuditOutboxDelivery1792108800010 implements MigrationInterface {
  name = 'ProductAuditOutboxDelivery1792108800010';
  async up(runner: QueryRunner): Promise<void> {
    await runner.query(`
      ALTER TABLE public.audit_outbox
        ADD COLUMN delivery_attempts smallint NOT NULL DEFAULT 0 CHECK (delivery_attempts BETWEEN 0 AND 1000),
        ADD COLUMN lease_token uuid,
        ADD COLUMN lease_until timestamptz(6),
        ADD COLUMN dead_at timestamptz(6);
      GRANT SELECT ON public.audit_outbox TO product_outbox;
      GRANT UPDATE(delivered_at,delivery_attempts,lease_token,lease_until,dead_at) ON public.audit_outbox TO product_outbox;
    `);
  }
  down(): Promise<void> {
    return Promise.reject(new Error('Audit delivery state requires explicit restore'));
  }
}
