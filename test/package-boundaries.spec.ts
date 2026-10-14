import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { ESLint } from 'eslint';
import tseslint from 'typescript-eslint';

const pkg = '@base-authorization/typeorm-postgres';

const keys = async (specifier: string): Promise<string[]> =>
  Object.keys((await import(specifier)) as Record<string, unknown>).sort();

describe('typeorm-postgres public entrypoints', () => {
  test('root exposes only errors and pure helpers', async () => {
    assert.deepEqual(await keys(pkg), [
      'ProductAccessDenied',
      'ProductAuthenticationError',
      'ProductAuthenticationUnavailable',
      'ProductInvalidRequest',
      'ReleaseRejectedError',
      'TransactionConflictError',
      'canonicalLoginEmail',
      'rateLimitClient',
    ]);
  });

  test('root excludes privileged and legacy capability', async () => {
    const root = await keys(pkg);
    const forbidden = [
      // raw transaction runners / authority loaders
      'ProductTransactionRunner',
      'TenantTransactionRunner',
      'PostgresAuthority',
      'ProductAuthorization',
      'readProductAuthority',
      // pools and DataSource factories
      'productDataSourceOptions',
      'identityDataSourceOptions',
      'tenantDataSourceOptions',
      'TenantDataSourceRegistry',
      // provision / bootstrap / migration entrypoints
      'provisionProductDatabase',
      'verifyProductPrivileges',
      'productMigrations',
      'bootstrapProductRoot',
      'revokeProductRoot',
      'reissueRootActivation',
      'runMigrations',
      'TenantProvisioner',
      // audit writer and obligation registry
      'appendProductAudit',
      'PRODUCT_OFFLINE_ACTOR',
      'productObligations',
      'fulfillObligations',
      // constructors / wiring
      'ProductIdentityService',
      'ProductOidcService',
      'ProductManifestReconciler',
      'prepareProductRelease',
      'ProductBindingRegistry',
      'ProductDataGateway',
    ];
    for (const name of forbidden) assert.ok(!root.includes(name), `root must not export ${name}`);
  });

  const subpaths: Record<string, { present: string[]; absent: string[] }> = {
    composition: {
      present: [
        'ProductTransactionRunner',
        'ProductAuthorization',
        'ProductBindingRegistry',
        'ProductDataGateway',
        'ProductIdentityService',
        'ProductOidcService',
        'ProductManifestReconciler',
        'createProductPasswordHasher',
        'verifyProductPrivileges',
        'productObligations',
        'PRODUCT_OFFLINE_ACTOR',
        'purgeExpiredSessions',
      ],
      absent: [
        'provisionProductDatabase',
        'productDataSourceOptions',
        'bootstrapProductRoot',
        'appendProductAudit',
        'TenantProvisioner',
      ],
    },
    operations: {
      present: [
        'provisionProductDatabase',
        'productDataSourceOptions',
        'productMigrations',
        'bootstrapProductRoot',
        'revokeProductRoot',
        'reissueRootActivation',
        'appendProductAudit',
        'PRODUCT_OFFLINE_ACTOR',
      ],
      absent: ['ProductTransactionRunner', 'productObligations', 'TenantProvisioner'],
    },
    legacy: {
      present: [
        'TenantProvisioner',
        'TenantDataSourceRegistry',
        'TenantTransactionRunner',
        'PostgresAuthority',
        'DataGateway',
        'BindingRegistry',
        'fulfillObligations',
        'runMigrations',
        'ManifestReconciler',
      ],
      absent: ['ProductTransactionRunner', 'provisionProductDatabase', 'productObligations'],
    },
  };

  for (const [name, { present, absent }] of Object.entries(subpaths)) {
    test(`./${name} resolves with declarations and the intended surface`, async () => {
      const specifier = `${pkg}/${name}`;
      const js = fileURLToPath(import.meta.resolve(specifier));
      assert.ok(existsSync(js.replace(/\.js$/, '.d.ts')), `${name}.d.ts must be built`);
      const exported = await keys(specifier);
      for (const key of present) assert.ok(exported.includes(key), `${name} must export ${key}`);
      for (const key of absent)
        assert.ok(!exported.includes(key), `${name} must not export ${key}`);
    });
  }

  test('undeclared subpaths and private dist paths do not resolve', () => {
    assert.throws(() => import.meta.resolve(`${pkg}/dist/product-sql.js`));
    assert.throws(() => import.meta.resolve(`${pkg}/product-sql`));
  });
});

describe('ESLint import boundaries', () => {
  // Type information is disabled so hypothetical paths outside any tsconfig can be linted;
  // no-restricted-imports does not need it.
  const eslint = new ESLint({
    cwd: fileURLToPath(new URL('..', import.meta.url)),
    overrideConfig: tseslint.configs.disableTypeChecked,
  });
  const abs = (path: string) => fileURLToPath(new URL(`../${path}`, import.meta.url));

  // One existing handler file per feature folder; lintText never writes to disk.
  const featureFiles = [
    'apps/api/src/auth/auth.controller.ts',
    'apps/api/src/documents/documents.controller.ts',
    'apps/api/src/administration/users.controller.ts',
    'apps/api/src/health/health.controller.ts',
    'apps/api/src/openapi/openapi.controller.ts',
    'apps/api/src/documents/documents.http-port.ts',
  ];
  const forbidden: Record<string, string> = {
    typeorm: "import { DataSource } from 'typeorm';",
    'typeorm subpath': "import { Pool } from 'typeorm/driver/postgres/PostgresDriver.js';",
    pg: "import { Pool } from 'pg';",
    composition: `import { ProductTransactionRunner } from '${pkg}/composition';`,
    operations: `import { provisionProductDatabase } from '${pkg}/operations';`,
    legacy: `import { TenantProvisioner } from '${pkg}/legacy';`,
    'runtime provider': "import { ProductRuntime } from '../infrastructure/product-runtime.js';",
    'runtime module': "import { RuntimeModule } from '../infrastructure/runtime.module.js';",
    'private dist': `import { x } from '${pkg}/dist/product-sql.js';`,
    'private source (relative)':
      "import { x } from '../../../../packages/typeorm-postgres/src/product-sql.js';",
    'private dist (relative)':
      "import { x } from '../../../../packages/typeorm-postgres/dist/product-sql.js';",
  };
  const allowed = [
    `import type { ProductPage } from '${pkg}';`,
    "import { enforceCsrf } from '../infrastructure/http-security.js';",
  ];

  const violations = async (filePath: string, code: string) => {
    const [result] = await eslint.lintText(`${code}\n`, { filePath: abs(filePath) });
    assert.ok(result);
    return result.messages.filter((m) => m.ruleId === 'no-restricted-imports');
  };

  for (const [label, code] of Object.entries(forbidden)) {
    test(`feature handlers cannot import ${label}`, async () => {
      for (const file of featureFiles) {
        assert.equal((await violations(file, code)).length, 1, `${file}: ${code}`);
      }
    });
  }

  test('nested feature subfolders are restricted too', async () => {
    for (const file of [
      'apps/api/src/auth/nested/strategy.ts',
      'apps/api/src/documents/deep/er/handler.ts',
    ]) {
      for (const code of Object.values(forbidden)) {
        assert.equal((await violations(file, code)).length, 1, `${file}: ${code}`);
      }
    }
  });

  test('document migrations stay exempt', async () => {
    const code = "import { DataSource } from 'typeorm';";
    assert.deepEqual(
      await violations('apps/api/src/documents/migrations/product-document.ts', code),
      [],
    );
  });

  test('feature handlers may import root contracts and http-security', async () => {
    for (const code of allowed) {
      assert.deepEqual(await violations(featureFiles[1] as string, code), [], code);
    }
  });

  test('infrastructure keeps composition but cannot import operations or legacy', async () => {
    const file = 'apps/api/src/infrastructure/product-runtime.ts';
    for (const code of [
      `import { ProductTransactionRunner } from '${pkg}/composition';`,
      "import { Pool } from 'pg';",
    ])
      assert.deepEqual(await violations(file, code), [], code);
    for (const code of [forbidden.operations!, forbidden.legacy!])
      assert.equal((await violations(file, code)).length, 1, code);
  });

  test('CLI keeps its privileged imports', async () => {
    for (const code of [
      `import { ProductTransactionRunner } from '${pkg}/composition';`,
      `import { provisionProductDatabase } from '${pkg}/operations';`,
      `import { TenantProvisioner } from '${pkg}/legacy';`,
      "import { Pool } from 'pg';",
    ])
      assert.deepEqual(await violations('tools/product.ts', code), [], code);
  });
});
