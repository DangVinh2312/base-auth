import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Builds an index without blocking writes (CONCURRENTLY, outside a transaction). A build that
 * failed earlier leaves an INVALID index behind; it is dropped and rebuilt, so a rerun converges.
 * `name` and `definition` are migration constants, never input.
 */
export async function createIndexConcurrently(
  runner: QueryRunner,
  name: string,
  definition: string,
): Promise<void> {
  const [state] = await runner.manager.query<{ valid: boolean }[]>(
    `SELECT i.indisvalid valid FROM pg_index i WHERE i.indexrelid=to_regclass($1)`,
    [`public.${name}`],
  );
  if (state && !state.valid) await runner.query(`DROP INDEX CONCURRENTLY public.${name}`);
  await runner.query(`CREATE INDEX CONCURRENTLY IF NOT EXISTS ${name} ON ${definition}`);
}

/**
 * Lets the offline session purge select expired rows in bounded batches without scanning the
 * table per batch. No grant or protection changes: identity already owns session DELETE.
 */
export class ProductSessionExpiryIndex1792108800009 implements MigrationInterface {
  name = 'ProductSessionExpiryIndex1792108800009';
  // Sessions are written on every login and touch; a plain build would block them.
  transaction = false;

  async up(runner: QueryRunner): Promise<void> {
    await createIndexConcurrently(
      runner,
      'ix_session_expiry',
      'public.application_session(expires_at)',
    );
  }

  async down(runner: QueryRunner): Promise<void> {
    await runner.query('DROP INDEX CONCURRENTLY IF EXISTS public.ix_session_expiry');
  }
}
