import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { createAuthorizationCore, type IdentityId } from '@base-authorization/core';
import { ReleaseRejectedError } from '@base-authorization/typeorm-postgres';
import {
  ProductBindingRegistry,
  ProductManifestReconciler,
  type ProductTransactionRunner,
  prepareProductRelease,
} from '@base-authorization/typeorm-postgres/composition';
import {
  ManifestReconciler,
  PostgresAuthority,
  prepareRelease,
  type TenantTransactionRunner,
} from '@base-authorization/typeorm-postgres/legacy';
import {
  createDayjsTimestampCodec,
  createStandardValueCodecs,
} from '@base-authorization/value-adapters';
import { core, declarations } from '../packages/core/test/fixtures.ts';

test('stable dotted system role keys are valid manifest roles without wildcard permissions', () => {
  const release = prepareRelease(
    {
      sequence: '1',
      predecessor: '0',
      declarations: declarations(),
      roles: [{ key: 'system.root', label: 'Root', authorityLevel: 1000 }],
      defaultGrants: [],
      seeds: [],
      removeSeeds: [],
      boundaryBindings: [],
      removeBoundaryBindings: [],
    },
    core,
  );
  assert.equal(release.roles[0]?.key, 'system.root');
  assert.deepEqual(release.defaultGrants, []);
});

test('system grants require exact declared permission/template and unique stable ownership', async () => {
  const product = await import('@base-authorization/typeorm-postgres/composition');
  const source = {
    sequence: '1',
    predecessor: '0',
    declarations: declarations(),
    roles: [{ key: 'system.root', label: 'Root', authorityLevel: 1000 }],
    defaultGrants: [],
    seeds: [],
    removeSeeds: [],
    boundaryBindings: [],
    removeBoundaryBindings: [],
    systemGrants: [
      {
        owner: 'product',
        key: 'root-read',
        permission: 'submission.read',
        role: 'system.root',
        template: { key: 'all', version: 1 },
        parameters: {},
      },
    ],
    removeSystemGrants: [],
  };
  const prepared = product.prepareProductRelease(source, core);
  assert.equal(prepared.systemGrants[0]?.key, 'root-read');
  assert.throws(() =>
    product.prepareProductRelease(
      {
        ...source,
        systemGrants: [{ ...source.systemGrants[0]!, permission: '*' }],
      },
      core,
    ),
  );
  assert.throws(() =>
    product.prepareProductRelease(
      {
        ...source,
        systemGrants: [...source.systemGrants, ...source.systemGrants],
      },
      core,
    ),
  );
  // A system grant on a runtime-assignable role would escape the offline-only rule.
  assert.throws(() =>
    product.prepareProductRelease(
      {
        ...source,
        roles: [...source.roles, { key: 'reviewer', label: 'Reviewer', authorityLevel: 10 }],
        systemGrants: [{ ...source.systemGrants[0]!, role: 'reviewer' }],
      },
      core,
    ),
  );
});

test('product manifest hash is unchanged by the codec refactor (data only, no adapter in hash)', async () => {
  const { createProductAuthorizationCore, createProductRelease } =
    await import('../apps/api/dist/authorization/product-manifest.js');
  // Release 2 data (ADR 0012) with the pre-v2 product envelope; Task 4 removes the system grant fields.
  const expected = 'ba878a4b746edefaf548dc8c26e864d9a8ca5f7e1a01cac9e9fd7db51234170b';
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
    await import('../apps/api/dist/authorization/product-manifest.js');
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
  // A legacy release from one core is refused by a reconciler bound to another.
  const legacy = prepareRelease(
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
    core,
  );
  await assert.rejects(
    new ManifestReconciler({} as TenantTransactionRunner, {
      ...options,
      capabilities: legacy.declarations.capabilities,
      core: other,
    }).reconcile(core.parseTenantId('00000000-0000-4000-8000-00000000000a'), legacy),
    (error) => error instanceof ReleaseRejectedError && error.reason === 'invalid_release',
  );
  assert.throws(
    () =>
      new PostgresAuthority(other, {} as TenantTransactionRunner, legacy.declarations, {
        validators: {},
        obligationHandlers: [],
      }),
    /this authorization core/,
  );
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
          systemGrants: [],
          removeSystemGrants: [],
        },
        failing,
      ),
    (error) => error instanceof ReleaseRejectedError && error.reason === 'invalid_release',
  );
});

test('legacy release hash and validation are unchanged by the product/legacy split', () => {
  const source = {
    sequence: '1',
    predecessor: '0',
    declarations: declarations(),
    roles: [
      { key: 'reviewer', label: 'Reviewer', authorityLevel: 10 },
      { key: 'system.root', label: 'Root', authorityLevel: 1000 },
    ],
    defaultGrants: [
      {
        permission: 'submission.read',
        role: 'reviewer',
        template: { key: 'all', version: 1 },
        parameters: {},
      },
    ],
    seeds: [],
    removeSeeds: [],
    boundaryBindings: [],
    removeBoundaryBindings: [],
  };
  // Computed from the 50d6053 build, before the split: the legacy envelope stays byte-for-byte.
  assert.equal(
    prepareRelease(source, core).hash,
    'b8fef6264647e605444e39f908addf9822cbed066c57323fd556c0354301361b',
  );
  for (const authorityLevel of [-1, 1001, 1.5])
    assert.throws(
      () =>
        prepareRelease(
          {
            ...source,
            roles: [{ key: 'reviewer', label: 'Reviewer', authorityLevel }],
            defaultGrants: [],
          },
          core,
        ),
      /authority level/,
    );
  assert.throws(
    () => prepareRelease({ ...source, roles: [...source.roles, source.roles[0]!] }, core),
    /role reviewer/,
  );
  assert.throws(
    () =>
      prepareRelease(
        { ...source, roles: [{ key: 'reviewer', label: ' ', authorityLevel: 10 }] },
        core,
      ),
    /label/,
  );
  // Several faults at once: the first error is the same as before the split.
  assert.throws(
    () =>
      prepareRelease(
        {
          ...source,
          roles: [
            { key: 'a', label: ' ', authorityLevel: 10 },
            { key: 'b', label: 'B', authorityLevel: -1 },
          ],
          defaultGrants: [{ ...source.defaultGrants[0]!, role: 'missing' }],
        },
        core,
      ),
    /role a label/,
  );
  assert.throws(
    () =>
      prepareRelease(
        {
          ...source,
          roles: [{ key: 'a', label: 'A', authorityLevel: -1 }],
          defaultGrants: [{ ...source.defaultGrants[0]!, role: 'missing' }],
        },
        core,
      ),
    /role a authority level/,
  );
});
