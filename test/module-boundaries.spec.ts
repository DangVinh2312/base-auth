import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { ESLint } from 'eslint';
import tseslint from 'typescript-eslint';

const eslint = new ESLint({
  cwd: fileURLToPath(new URL('..', import.meta.url)),
  // Hypothetical nested files need no TypeScript project for import/syntax rules.
  overrideConfig: tseslint.configs.disableTypeChecked,
});

async function violations(file: string, code: string, rule = 'no-restricted-imports') {
  const [result] = await eslint.lintText(`${code}\n`, {
    filePath: fileURLToPath(new URL(`../${file}`, import.meta.url)),
  });
  assert.ok(result);
  return result.messages.filter((message) => message.ruleId === rule);
}

const featureFiles = [
  'apps/api/src/auth/controllers/auth.controller.ts',
  'apps/api/src/document/document.controller.ts',
  'apps/api/src/administration/user.controller.ts',
  'apps/api/src/health/health.controller.ts',
  'apps/api/src/openapi/openapi.controller.ts',
  'apps/api/src/document/document.http-port.ts',
  'apps/api/src/auth/nested/strategy.ts',
  'apps/api/src/document/deep/er/handler.ts',
];

describe('application module boundaries', () => {
  const forbidden = {
    typeorm: "import { DataSource } from 'typeorm';",
    'typeorm subpath': "import { Pool } from 'typeorm/driver/postgres/PostgresDriver.js';",
    pg: "import { Pool } from 'pg';",
    transaction:
      "import { ProductTransactionRunner } from '../database/product-transaction.runner.js';",
    gateway: "import { ProductDataGateway } from '../authorization/product-data.gateway.js';",
    compiler: "import { compilePlan } from '../authorization/product-sql.compiler.js';",
    authority:
      "import { ProductAuthorization } from '../authorization/services/product-authority.service.js';",
    identity:
      "import { ProductIdentityService } from '../auth/services/product-identity.service.js';",
    oidc: "import { ProductOidcService } from '../auth/services/product-oidc.service.js';",
    bootstrap:
      "import { bootstrapProductRoot } from '../authorization/services/product-manifest.service.js';",
    provisioning:
      "import { provisionProductDatabase } from '../database/helpers/product-database.helper.js';",
    audit: "import { appendProductAudit } from '../audit/product-audit.repository.js';",
    'runtime provider':
      "import { ProductRuntime } from '../infrastructure/product-runtime.service.js';",
    'runtime module': "import { RuntimeModule } from '../infrastructure/runtime.module.js';",
  };

  for (const [label, code] of Object.entries(forbidden)) {
    test(`HTTP handlers cannot import ${label}`, async () => {
      for (const file of featureFiles) {
        assert.equal((await violations(file, code)).length, 1, `${file}: ${code}`);
      }
    });
  }

  test('HTTP handlers can import implementation types, HTTP helpers and facade tokens', async () => {
    for (const code of [
      "import type { Row } from '../authorization/product-data.gateway.js';",
      "import type { ProductIdentityService } from '../auth/services/product-identity.service.js';",
      "import { enforceCsrf } from '../infrastructure/http-security.helper.js';",
      "import { DOCUMENT_HTTP_PORT } from './document.http-port.js';",
    ]) {
      assert.deepEqual(await violations(featureFiles[1] as string, code), [], code);
    }
  });

  test('services and migrations may use TypeORM directly', async () => {
    for (const file of [
      'apps/api/src/auth/services/product-identity.service.ts',
      'apps/api/src/authorization/services/product-authority.service.ts',
      'apps/api/src/document/migrations/product-document.migration.ts',
    ]) {
      assert.deepEqual(await violations(file, "import { DataSource } from 'typeorm';"), []);
    }
  });

  test('runtime may compose services, but cannot import offline commands', async () => {
    const file = 'apps/api/src/infrastructure/product-runtime.service.ts';
    for (const code of [forbidden.transaction, "import { Pool } from 'pg';"]) {
      assert.deepEqual(await violations(file, code), [], code);
    }
    for (const code of [forbidden.bootstrap, forbidden.provisioning]) {
      assert.equal((await violations(file, code)).length, 1, code);
      assert.deepEqual(await violations('tools/product.ts', code), [], code);
    }
  });

  test('core stays pure and HTTP enforcement has no database driver', async () => {
    for (const specifier of ['typeorm', 'pg', '@nestjs/common', 'node:fs', 'dayjs']) {
      const code = `import { x } from '${specifier}';`;
      assert.equal(
        (await violations('apps/api/src/authorization/core/authorization.factory.ts', code)).length,
        1,
      );
    }
    assert.equal(
      (
        await violations(
          'apps/api/src/authorization/enforcement/product-authorization.module.ts',
          forbidden.pg,
        )
      ).length,
      1,
    );
  });

  test('specialized core and enforcement rules retain application isolation', async () => {
    for (const code of [
      "import { createProductRelease } from '../product.manifest.js';",
      "import { releaseContentHash } from '../helpers/release-content.helper.js';",
    ]) {
      assert.equal(
        (await violations('apps/api/src/authorization/core/authorization.factory.ts', code)).length,
        1,
      );
    }
    for (const code of [forbidden.bootstrap, forbidden.provisioning]) {
      assert.equal(
        (
          await violations(
            'apps/api/src/authorization/enforcement/product-authorization.module.ts',
            code,
          )
        ).length,
        1,
      );
    }
  });

  test('only the authority service and core unit tests may reach planUnrestricted', async () => {
    const code =
      'declare const core: { planUnrestricted(a: unknown, b: unknown): unknown };\ncore.planUnrestricted({}, {});';
    const destructured =
      'declare const core: { planUnrestricted: unknown };\nconst { planUnrestricted } = core;\nexport { planUnrestricted };';
    const directImport =
      "import { planUnrestricted as bypass } from '../authorization/core/authorization.planner.js';";
    const directExport =
      "export { planUnrestricted as bypass } from '../authorization/core/authorization.planner.js';";
    for (const file of [
      'apps/api/src/authorization/product-data.gateway.ts',
      'apps/api/src/auth/services/product-identity.service.ts',
      ...featureFiles,
      'apps/api/src/infrastructure/product-runtime.service.ts',
      'tools/product.ts',
      'test/product-root.integration-spec.ts',
    ]) {
      for (const probe of [code, destructured, directImport, directExport]) {
        assert.equal((await violations(file, probe, 'no-restricted-syntax')).length, 1, file);
      }
    }
    for (const file of [
      'apps/api/src/authorization/services/product-authority.service.ts',
      'test/core/unrestricted.spec.ts',
    ]) {
      assert.deepEqual(await violations(file, code, 'no-restricted-syntax'), []);
    }
    assert.deepEqual(
      await violations(
        'apps/api/src/authorization/core/authorization.factory.ts',
        directImport,
        'no-restricted-syntax',
      ),
      [],
    );
  });
});
