import type { MigrationInterface, QueryRunner } from 'typeorm';
import { createIndexConcurrently } from './009-session-expiry-index.js';

/** Claim index for the outbox worker; every audited effect inserts here, so no blocking build. */
export class ProductAuditOutboxPendingIndex1792108800011 implements MigrationInterface {
  name = 'ProductAuditOutboxPendingIndex1792108800011';
  transaction = false;

  async up(runner: QueryRunner): Promise<void> {
    await createIndexConcurrently(
      runner,
      'ix_audit_outbox_pending',
      'public.audit_outbox(occurred_at,event_id) WHERE delivered_at IS NULL AND dead_at IS NULL',
    );
  }

  async down(runner: QueryRunner): Promise<void> {
    await runner.query('DROP INDEX CONCURRENTLY IF EXISTS public.ix_audit_outbox_pending');
  }
}
