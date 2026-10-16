import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));

test('the application and test tooling need no internal workspace libraries', () => {
  for (const path of ['package.json', 'apps/api/package.json']) {
    const manifest = JSON.parse(readFileSync(new URL(`../${path}`, import.meta.url), 'utf8')) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    for (const name of Object.keys({ ...manifest.dependencies, ...manifest.devDependencies })) {
      assert.ok(
        !/^@base-authorization\/(core|nest|typeorm-postgres|value-adapters)$/.test(name),
        name,
      );
    }
  }
  for (const name of ['core', 'nest', 'typeorm-postgres', 'value-adapters']) {
    assert.equal(existsSync(new URL(`../packages/${name}/package.json`, import.meta.url)), false);
  }
  assert.equal(
    existsSync(new URL('../apps/api/src/authorization/core/index.ts', import.meta.url)),
    false,
    'core consumers import the owning module directly',
  );
});

test('the HTTP application loads without tenant runtime implementation', () => {
  const probe = `
    import { registerHooks } from 'node:module';
    const loaded = [];
    registerHooks({ resolve(specifier, context, next) { const r = next(specifier, context); loaded.push(r.url); return r; } });
    const { AppModule } = await import('./apps/api/dist/app.module.js');
    const { createProductAuthorizationCore, createProductRelease } = await import('./apps/api/dist/authorization/product.manifest.js');
    const release = createProductRelease(createProductAuthorizationCore());
    console.log(JSON.stringify({ app: typeof AppModule.register, sequence: release.sequence, loaded }));
  `;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', probe], {
    cwd: root,
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, result.stderr);
  const { app, sequence, loaded } = JSON.parse(result.stdout) as {
    app: string;
    sequence: string;
    loaded: string[];
  };
  assert.equal(app, 'function');
  assert.equal(sequence, '2');
  assert.deepEqual(
    loaded.filter((url) => /\/(packages|legacy)\//.test(url) && !url.includes('/node_modules/')),
    [],
  );
});
