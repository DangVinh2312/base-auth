import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import { canonicalTimestamp, evaluate } from '@base-authorization/core';
import {
  BindingRegistry,
  compilePlan,
  runMigrations,
  tenantDataSourceOptions,
} from '@base-authorization/typeorm-postgres';
import {
  fixtureDeclarations,
  readPlan,
  rule,
  seedTenant,
  storageBindings,
  submissionFacts,
  tenantA,
  tenantFixture,
} from './fixtures/resources.ts';
import { type Connection, startPostgres, type TestPostgres, withClient } from './setup-postgres.ts';

/**
 * The tenant schema on a database whose default collation is ICU (`und`), where 'Zeta' < 'a' is
 * false but code point order says true. String ordering must still match the evaluator.
 */
describe('string ordering is independent of the database collation', () => {
  let postgres: TestPostgres;
  let db: Connection;
  const fixture = tenantFixture(tenantA, 'c', 'A');

  before(async () => {
    postgres = await startPostgres();
    await withClient(postgres.admin, (c) =>
      c.query(
        `CREATE DATABASE icu_tenant TEMPLATE template0 ENCODING 'UTF8' LOCALE_PROVIDER icu ICU_LOCALE 'und' LOCALE 'C.UTF-8'`,
      ),
    );
    db = { ...postgres.admin, database: 'icu_tenant' };
    await runMigrations(tenantDataSourceOptions(db));
    await withClient(db, async (c) => {
      await c.query('INSERT INTO tenant_anchor VALUES ($1)', [tenantA]);
      await c.query('INSERT INTO authz_fence (tenant_id, manifest_hash) VALUES ($1, $2)', [
        tenantA,
        Buffer.alloc(32),
      ]);
      await seedTenant(c, fixture, { grants: false });
    });
  });
  after(async () => {
    await postgres?.stop();
  });

  test('the database default collation really orders differently from code points', async () => {
    await withClient(db, async (c) => {
      const row = await c.query<{ icu: boolean; c: boolean }>(
        `SELECT 'Zeta' < 'a' AS icu, 'Zeta' < 'a' COLLATE "C" AS c`,
      );
      assert.deepEqual(row.rows, [{ icu: false, c: true }]);
    });
  });

  for (const bound of ['a', 'Zeta', 'ångström']) {
    test(`lt on strings matches the evaluator (bound ${bound})`, async () => {
      const authorized = readPlan(tenantA, [
        rule('submission.read', 'allow', 'titleBefore', { title: bound }),
      ]);
      const compiled = compilePlan(
        authorized,
        new BindingRegistry(fixtureDeclarations(), storageBindings),
      );
      const sqlIds = await withClient(db, async (c) =>
        (
          await c.query<{ id: string }>(
            `SELECT r.id FROM submission r WHERE ${compiled.sql} ORDER BY r.id`,
            [...compiled.parameters],
          )
        ).rows.map((r) => r.id),
      );
      const now = canonicalTimestamp(new Date().toISOString())!;
      const expected = fixture.submissions
        .filter(
          (row) => evaluate(authorized, submissionFacts(fixture, row, now)).effect === 'allow',
        )
        .map((row) => row.id)
        .sort((x, y) => (BigInt(x) < BigInt(y) ? -1 : 1));
      assert.deepEqual(sqlIds, expected);
    });
  }
});
