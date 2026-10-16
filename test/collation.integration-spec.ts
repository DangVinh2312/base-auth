import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import {
  ProductBindingRegistry,
  compileProductPlan as compilePlan,
} from '@base-authorization/typeorm-postgres/composition';
import {
  type CompilerEnvironment,
  fixtureDeclarations,
  readPlan,
  rule,
  startCompilerEnvironment,
  storageBindings,
  submissionFacts,
  core,
} from './fixtures/resources.ts';

const { canonicalTimestamp, evaluateUser } = core;

/**
 * The product schema on a database whose default collation is ICU (`und`), where 'Zeta' < 'a' is
 * false but code point order says true. String ordering must still match the evaluator.
 */
describe('string ordering is independent of the database collation', () => {
  let env: CompilerEnvironment;

  before(async () => {
    env = await startCompilerEnvironment(true);
  });
  after(async () => {
    await env?.stop();
  });

  test('the database default collation really orders differently from code points', async () => {
    const rows = await env.data.query<{ icu: boolean; c: boolean }[]>(
      `SELECT 'Zeta' < 'a' AS icu, 'Zeta' < 'a' COLLATE "C" AS c`,
    );
    assert.deepEqual(rows, [{ icu: false, c: true }]);
  });

  for (const bound of ['a', 'Zeta', 'ångström']) {
    test(`lt on strings matches the evaluator (bound ${bound})`, async () => {
      const authorized = readPlan([
        rule('submission.read', 'allow', 'titleBefore', { title: bound }),
      ]);
      const compiled = compilePlan(
        authorized,
        new ProductBindingRegistry(core, fixtureDeclarations(), storageBindings),
      );
      const rows = await env.data.query<{ id: string }[]>(
        `SELECT r.id FROM submission r WHERE ${compiled.sql} ORDER BY r.id`,
        [...compiled.parameters],
      );
      const sqlIds = rows.map((row) => row.id);
      const now = canonicalTimestamp(new Date().toISOString());
      assert.ok(now);
      const expected = env.fixture.submissions
        .filter(
          (row) =>
            evaluateUser(authorized, submissionFacts(env.fixture, row, now)).effect === 'allow',
        )
        .map((row) => row.id)
        .sort((x, y) => (BigInt(x) < BigInt(y) ? -1 : 1));
      assert.deepEqual(sqlIds, expected);
    });
  }
});
