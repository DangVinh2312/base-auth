import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { createAuthorizationCore } from '@base-authorization/core';
import type { IdentityId } from '@base-authorization/core';
import { ReleaseRejectedError } from '@base-authorization/typeorm-postgres';
import type { ProductReleaseSource } from '@base-authorization/typeorm-postgres';
import { ProductBindingRegistry } from '@base-authorization/typeorm-postgres/composition';
import {
  ProductManifestReconciler,
  prepareProductRelease,
} from '@base-authorization/typeorm-postgres/composition';
import type { ProductTransactionRunner } from '@base-authorization/typeorm-postgres/composition';
import { createDayjsTimestampCodec } from '@base-authorization/value-adapters';
import { createStandardValueCodecs } from '@base-authorization/value-adapters';
import { alice, core, declarations } from '../packages/core/test/fixtures.ts';

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

test('product boundary binding seeds validate identity, owner, references and uniqueness', () => {
  const entry = (permission: string) => ({
    permission,
    contextRequirements: [],
    requiredScope: { op: 'constant' as const, value: true },
  });

  const source: ProductReleaseSource = {
    sequence: '1',
    predecessor: '0',
    declarations: declarations({
      boundaries: [
        { key: 'readLimit', version: 1, entries: [entry('submission.read')] },
        { key: 'approveLimit', version: 1, entries: [entry('submission.approve')] },
        {
          key: 'retiredRead',
          version: 1,
          lifecycle: 'retired',
          entries: [entry('submission.read')],
        },
      ],
    }),
    roles: [],
    defaultGrants: [],
    seeds: [],
    removeSeeds: [],
    boundaryBindings: [],
    removeBoundaryBindings: [],
  };
  const seed = {
    owner: 'review-module',
    identity: alice,
    permission: 'submission.read',
    boundary: { key: 'readLimit', version: 1 },
  };
  assert.deepEqual(
    prepareProductRelease({ ...source, boundaryBindings: [seed] }, core).boundaryBindings,
    [seed],
  );
  for (const boundaryBindings of [
    [{ ...seed, boundary: { key: 'readLimit', version: 9 } }],
    [{ ...seed, boundary: { key: 'approveLimit', version: 1 } }],
    [{ ...seed, boundary: { key: 'retiredRead', version: 1 } }],
    [{ ...seed, permission: 'submission.delete' }],
    [{ ...seed, identity: 'not-a-uuid' as IdentityId }],
    [{ ...seed, owner: 'Bad Owner' }],
    [seed, { ...seed, owner: 'second-owner' }],
  ]) {
    assert.throws(
      () => prepareProductRelease({ ...source, boundaryBindings }, core),
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
