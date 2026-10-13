import assert from 'node:assert/strict';
import { test } from 'node:test';
import { prepareRelease } from '@base-authorization/typeorm-postgres';
import { declarations } from '../packages/core/test/fixtures.ts';

test('stable dotted system role keys are valid manifest roles without wildcard permissions', () => {
  const release = prepareRelease({
    sequence: '1',
    predecessor: '0',
    declarations: declarations(),
    roles: [{ key: 'system.root', label: 'Root', authorityLevel: 1000 }],
    defaultGrants: [],
    seeds: [],
    removeSeeds: [],
    boundaryBindings: [],
    removeBoundaryBindings: [],
  });
  assert.equal(release.roles[0]?.key, 'system.root');
  assert.deepEqual(release.defaultGrants, []);
});

test('system grants require exact declared permission/template and unique stable ownership', async () => {
  const product = await import('../packages/typeorm-postgres/dist/product-manifest.js');
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
  const prepared = product.prepareProductRelease(source);
  assert.equal(prepared.systemGrants[0]?.key, 'root-read');
  assert.throws(() =>
    product.prepareProductRelease({
      ...source,
      systemGrants: [{ ...source.systemGrants[0]!, permission: '*' }],
    }),
  );
  assert.throws(() =>
    product.prepareProductRelease({
      ...source,
      systemGrants: [...source.systemGrants, ...source.systemGrants],
    }),
  );
});
