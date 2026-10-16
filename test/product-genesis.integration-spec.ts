import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { DataSource } from 'typeorm';
import type { IdentityId } from '../apps/api/dist/authorization/core/authorization.types.js';
import {
  type ProductDatabasePurpose,
  productDataSourceOptions,
  provisionProductDatabase,
} from '../apps/api/dist/database/helpers/product-database.helper.js';
import {
  ProductManifestReconciler,
  prepareProductRelease,
} from '../apps/api/dist/authorization/services/product-manifest.service.js';
import { ProductTransactionRunner } from '../apps/api/dist/database/product-transaction.runner.js';

import {
  createProductAuthorizationCore,
  productReleaseSource,
} from '../apps/api/dist/authorization/product.manifest.js';
import { startPostgres, withClient, type TestPostgres } from './setup-postgres.ts';

const core = createProductAuthorizationCore();
const passwords = Object.fromEntries(
  ['data', 'identity', 'authority', 'sync', 'migration', 'bootstrap', 'outbox'].map((p) => [
    p,
    randomBytes(24).toString('hex'),
  ]),
) as Record<ProductDatabasePurpose, string>;
let fixture: TestPostgres;
before(async () => {
  fixture = await startPostgres();
});
after(async () => {
  await fixture?.stop();
});

/** A freshly provisioned product database (release_sequence 0) and its sync reconciler. */
async function freshDatabase(name: string) {
  await withClient(fixture.superuser, (c) => c.query(`CREATE DATABASE ${name}`));
  const settings = await provisionProductDatabase(
    { ...fixture.superuser, database: name },
    passwords,
  );
  const sync = await new DataSource(productDataSourceOptions(settings.sync)).initialize();
  const reconciler = new ProductManifestReconciler(new ProductTransactionRunner({ sync }), {
    core,
    actor: randomUUID() as IdentityId,
    capabilities: { validators: ['fresh@1'], obligationHandlers: ['audit@1'] },
  });

  const sequence = async () =>
    (await sync.query<{ s: string }[]>('SELECT release_sequence::text s FROM authz_state'))[0]!.s;

  return { sync, reconciler, sequence };
}

const release = (sequence: string, predecessor: string) =>
  prepareProductRelease({ ...productReleaseSource, sequence, predecessor }, core);

test('a fresh database accepts any release as its first; later releases keep a strict predecessor', async () => {
  const { sync, reconciler, sequence } = await freshDatabase('genesis_fresh');
  try {
    assert.equal((await reconciler.reconcile(release('2', '1'))).changed, true);
    assert.equal(await sequence(), '2');
    await assert.rejects(reconciler.reconcile(release('4', '3')), /predecessor_mismatch/);
    assert.equal((await reconciler.reconcile(release('3', '2'))).changed, true);
  } finally {
    await sync.destroy();
  }
});

test('genesis needs an empty code-owned catalog; otherwise the predecessor stays strict', async () => {
  const { sync, reconciler, sequence } = await freshDatabase('genesis_dirty');
  try {
    // A code-owned fact although nothing was published yet (release_sequence is still 0).
    await sync.query(
      "INSERT INTO resource_type(type_key,key_kind,binding_key) VALUES($1,'uuid',$1)",
      [Buffer.from('stray')],
    );
    await assert.rejects(reconciler.reconcile(release('2', '1')), /predecessor_mismatch/);
    assert.equal(await sequence(), '0');
    // The ordinary first release (predecessor 0) is unchanged.
    assert.equal((await reconciler.reconcile(release('1', '0'))).changed, true);
  } finally {
    await sync.destroy();
  }
});
