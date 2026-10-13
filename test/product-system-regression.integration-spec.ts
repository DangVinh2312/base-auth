import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { DataSource } from 'typeorm';
import type { IdentityId } from '@base-authorization/core';
import {
  provisionProductDatabase,
  productDataSourceOptions,
  ProductTransactionRunner,
  ProductManifestReconciler,
  prepareProductRelease,
  type ProductDatabasePurpose,
} from '@base-authorization/typeorm-postgres';
import { startPostgres, withClient, type TestPostgres } from './setup-postgres.ts';
import { productDeclarations } from '../apps/api/dist/product-manifest.js';

let fixture: TestPostgres;
let fixtureNumber = 0;
const passwords = Object.fromEntries(
  ['data', 'identity', 'authority', 'sync', 'migration', 'bootstrap'].map((p) => [
    p,
    randomBytes(24).toString('hex'),
  ]),
) as Record<ProductDatabasePurpose, string>;
const actor = randomUUID() as IdentityId;
const grant = {
  owner: 'product',
  key: 'root-suspend',
  role: 'system.root',
  permission: 'account.suspend',
  template: { key: 'allAccounts', version: 1 },
  parameters: {},
};
const base = {
  sequence: '1',
  predecessor: '0',
  declarations: productDeclarations,
  roles: [{ key: 'system.root', authorityLevel: 1000, label: 'Root' }],
  defaultGrants: [],
  seeds: [],
  removeSeeds: [],
  boundaryBindings: [],
  removeBoundaryBindings: [],
  systemGrants: [grant],
  removeSystemGrants: [],
};
before(async () => {
  fixture = await startPostgres();
});
after(async () => {
  await fixture?.stop();
});
async function withProduct(
  run: (reconciler: ProductManifestReconciler, migration: DataSource) => Promise<void>,
): Promise<void> {
  const database = `system_regression_${++fixtureNumber}`;
  await withClient(fixture.superuser, (c) => c.query(`CREATE DATABASE ${database}`));
  const settings = await provisionProductDatabase({ ...fixture.superuser, database }, passwords);
  const sync = await new DataSource(productDataSourceOptions(settings.sync)).initialize();
  const migration = await new DataSource(productDataSourceOptions(settings.migration)).initialize();
  try {
    const reconciler = new ProductManifestReconciler(new ProductTransactionRunner({ sync }), {
      actor,
      capabilities: { validators: ['fresh@1'], obligationHandlers: ['audit@1'] },
    });
    await reconciler.reconcile(prepareProductRelease(base));
    await run(reconciler, migration);
  } finally {
    await migration.destroy();
    await sync.destroy();
  }
}
async function offlineAlter(
  migration: DataSource,
  sql: string,
  parameters: unknown[] = [],
): Promise<void> {
  await migration.query('ALTER TABLE policy_rule DISABLE TRIGGER protect_product_rows');
  try {
    await migration.query(sql, parameters);
  } finally {
    await migration.query('ALTER TABLE policy_rule ENABLE TRIGGER protect_product_rows');
  }
}
test('new release cannot adopt drift in a persisted grant omitted from its manifest', async () => {
  await withProduct(async (reconciler, migration) => {
    await offlineAlter(
      migration,
      "UPDATE policy_rule SET parameters='{}',effect='deny' WHERE system_owner=$1",
      [Buffer.from(grant.owner)],
    );
    const prior = prepareProductRelease(base);
    await assert.rejects(reconciler.reconcile(prior), /drift|not_ready|immutable_definition/);
    const next = prepareProductRelease({
      ...base,
      sequence: '2',
      predecessor: '1',
      systemGrants: [],
    });
    await assert.rejects(reconciler.reconcile(next), /drift|not_ready|immutable_definition/);
    assert.equal(
      (
        await migration.query<{ sequence: string }[]>(
          'SELECT release_sequence::text sequence FROM authz_state',
        )
      )[0]!.sequence,
      '1',
    );
  });
});
test('stable system owner/key with a wrong rule ID cannot silently satisfy a new release', async () => {
  await withProduct(async (reconciler, migration) => {
    await offlineAlter(migration, 'UPDATE policy_rule SET rule_id=$1 WHERE system_owner=$2', [
      randomUUID(),
      Buffer.from(grant.owner),
    ]);
    const next = prepareProductRelease({ ...base, sequence: '2', predecessor: '1' });
    await assert.rejects(
      reconciler.reconcile(next),
      /drift|not_ready|collision|immutable_definition/,
    );
    assert.equal(
      (
        await migration.query<{ sequence: string }[]>(
          'SELECT release_sequence::text sequence FROM authz_state',
        )
      )[0]!.sequence,
      '1',
    );
  });
});
test('deny effect cannot masquerade as an unchanged explicit system allow grant', async () => {
  await withProduct(async (reconciler, migration) => {
    await offlineAlter(migration, "UPDATE policy_rule SET effect='deny' WHERE system_owner=$1", [
      Buffer.from(grant.owner),
    ]);
    const next = prepareProductRelease({ ...base, sequence: '2', predecessor: '1' });
    await assert.rejects(reconciler.reconcile(next), /drift|not_ready|immutable_definition/);
    assert.equal(
      (
        await migration.query<{ sequence: string }[]>(
          'SELECT release_sequence::text sequence FROM authz_state',
        )
      )[0]!.sequence,
      '1',
    );
  });
});
