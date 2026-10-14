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
  // Computed from the pre-refactor build (productRelease constant, regex + Date.parse parser).
  const expected = 'c1fbb3451d9292477ae24ed1d342f581612b68d9519ffccce6f08a9a3c874fa9';
  const first = createProductRelease(createProductAuthorizationCore());
  const second = createProductRelease(createProductAuthorizationCore());
  assert.equal(first.hash, expected);
  assert.equal(second.hash, expected);
  assert.equal(
    createHash('sha256').update(first.declarations.canonical).digest('hex'),
    'b374c0057e1ac10b41bf93b65b7ebcb6cc3f218532670025d81a33a4bc1fceec',
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
