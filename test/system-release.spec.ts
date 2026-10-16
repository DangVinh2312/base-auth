import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { createAuthorizationCore } from '../apps/api/dist/authorization/core/authorization.factory.js';
import type { IdentityId } from '../apps/api/dist/authorization/core/authorization.types.js';
import { ReleaseRejectedError } from '../apps/api/dist/authorization/helpers/release-content.helper.js';
import { ProductBindingRegistry } from '../apps/api/dist/authorization/product-sql.compiler.js';
import {
  ProductManifestReconciler,
  prepareProductRelease,
} from '../apps/api/dist/authorization/services/product-manifest.service.js';
import type { ProductTransactionRunner } from '../apps/api/dist/database/product-transaction.runner.js';
import { createDayjsTimestampCodec } from '../apps/api/dist/authorization/values/codecs/dayjs-timestamp.codec.js';
import { createStandardValueCodecs } from '../apps/api/dist/authorization/values/codecs/standard-values.codec.js';
import { core, declarations } from './core/fixtures.ts';

test('product release v2: roles are key and label, system.* is reserved, no system grant fields', async () => {
  const { productReleaseSource } =
    await import('../apps/api/dist/authorization/product.manifest.js');
  const prepared = prepareProductRelease(productReleaseSource, core);
  assert.deepEqual(prepared.roles, [{ key: 'reviewer', label: 'Reviewer' }]);
  for (const field of ['systemGrants', 'removeSystemGrants'])
    assert.equal(Object.hasOwn(prepared, field), false, field);
  for (const key of ['system.root', 'system.audit'])
    assert.throws(
      () =>
        prepareProductRelease(
          { ...productReleaseSource, roles: [{ key, label: 'Reserved' }] },
          core,
        ),
      (error) =>
        error instanceof ReleaseRejectedError &&
        error.reason === 'invalid_release' &&
        /reserved/.test(error.message),
      key,
    );
});

test('product releases reject duplicate role keys and blank labels', async () => {
  const { productReleaseSource } =
    await import('../apps/api/dist/authorization/product.manifest.js');
  const role = { key: 'reviewer', label: 'Reviewer' };
  for (const roles of [[role, role], [{ ...role, label: '   ' }]]) {
    assert.throws(
      () => prepareProductRelease({ ...productReleaseSource, roles }, core),
      (error) => error instanceof ReleaseRejectedError && error.reason === 'invalid_release',
    );
  }
});

test('product manifest hash is unchanged by the codec refactor (data only, no adapter in hash)', async () => {
  const { createProductAuthorizationCore, createProductRelease } =
    await import('../apps/api/dist/authorization/product.manifest.js');
  // Release 2 (ADR 0012): product roles are key + label, no system grant fields.
  const expected = 'e11f43e8199bf70fd4a2c8e552477b682222402510fd3d0cc35b98256f15afaa';
  const first = createProductRelease(createProductAuthorizationCore());
  const second = createProductRelease(createProductAuthorizationCore());
  assert.equal(first.hash, expected);
  assert.equal(second.hash, expected);
  assert.equal(
    createHash('sha256').update(first.declarations.canonical).digest('hex'),
    '528137d7eaf0aeb8599f473611acb0a3e9101377bf57c7d1f19352bbdcb25701',
  );
});

test('releases and declarations are only accepted by the core that prepared them', async () => {
  const { createProductAuthorizationCore, createProductRelease, productBindings } =
    await import('../apps/api/dist/authorization/product.manifest.js');
  const other = createProductAuthorizationCore();
  const release = createProductRelease(core);
  const runner = {} as ProductTransactionRunner; // never reached: provenance is checked first
  const options = {
    actor: '00000000-0000-4000-8000-000000000001' as IdentityId,
    capabilities: release.declarations.capabilities,
  };
  await assert.rejects(
    new ProductManifestReconciler(runner, { ...options, core: other }).reconcile(release),
    (error) => error instanceof ReleaseRejectedError && error.reason === 'invalid_release',
  );
  assert.throws(
    () => new ProductBindingRegistry(other, release.declarations, productBindings),
    /this authorization core/,
  );
  assert.ok(new ProductBindingRegistry(core, release.declarations, productBindings));
});

test('a failing value codec rejects a release with the normal release error', () => {
  const failing = createAuthorizationCore({
    values: {
      ...createStandardValueCodecs({ timestamp: createDayjsTimestampCodec() }),
      string: {
        normalize: () => {
          throw new Error('codec failure');
        },

        compare: () => 0,
      },
    },
  });
  assert.throws(
    () =>
      prepareProductRelease(
        {
          sequence: '1',
          predecessor: '0',
          declarations: declarations(),
          roles: [],
          defaultGrants: [],
          seeds: [],
          removeSeeds: [],
          boundaryBindings: [],
          removeBoundaryBindings: [],
        },
        failing,
      ),
    (error) => error instanceof ReleaseRejectedError && error.reason === 'invalid_release',
  );
});
