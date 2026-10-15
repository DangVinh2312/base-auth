import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import formatConfig from './eslint.format.config.js';

const driverImports = [
  {
    group: ['typeorm', 'typeorm/*', 'pg', 'pg-*'],
    message: 'Storage drivers belong to typeorm-postgres.',
  },
];

export default tseslint.config(
  { ignores: ['**/dist/**', '**/node_modules/**', 'coverage/**'] },
  ...formatConfig,
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: { parserOptions: { projectService: true } },
    rules: {
      '@typescript-eslint/no-floating-promises': [
        'error',
        {
          allowForKnownSafeCalls: [
            { from: 'package', package: 'node:test', name: ['test', 'describe', 'it', 'suite'] },
          ],
        },
      ],
    },
  },
  {
    files: ['eslint.config.js', 'eslint.format.config.js'],
    ...tseslint.configs.disableTypeChecked,
  },
  {
    files: ['packages/core/src/**/*.ts'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            ...driverImports,
            {
              group: ['@nestjs/*', 'express', '@base-authorization/*', 'node:*'],
              message:
                'Core is pure: no framework, driver, platform I/O or other workspace package.',
            },
          ],
        },
      ],
    },
  },
  {
    files: ['packages/nest/**/*.ts'],
    rules: { 'no-restricted-imports': ['error', { patterns: driverImports }] },
  },
  {
    // Infrastructure composes through ./composition only; operations/legacy are offline/legacy.
    files: ['apps/api/src/infrastructure/**/*.ts'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: [
                '@base-authorization/typeorm-postgres/operations',
                '@base-authorization/typeorm-postgres/legacy',
              ],
              message:
                'API infrastructure imports only the root contracts and ./composition; operations is for tools/, legacy is retired tenancy.',
            },
          ],
        },
      ],
    },
  },
  {
    // Developer boundary for HTTP handlers (not process isolation): handlers see facade tokens and
    // adapter root contracts only. Composition lives in infrastructure/, offline work in tools/.
    files: ['apps/api/src/{auth,document,administration,health,openapi}/**/*.ts'],
    ignores: ['apps/api/src/document/migrations/**'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            ...driverImports,
            {
              group: ['@base-authorization/typeorm-postgres/*'],
              message:
                'Handlers use root contracts and facade tokens; composition/operations/legacy and private paths are for infrastructure and tools.',
            },
            {
              group: [
                '**/infrastructure/product-runtime*',
                '**/infrastructure/runtime.module*',
                '**/product-runtime*',
              ],
              message: 'The runtime provider is private to RuntimeModule; inject a facade token.',
            },
            {
              group: ['**/packages/*/src/**', '**/packages/*/dist/**'],
              message:
                'Import packages by public entrypoint, never by private source or dist path.',
            },
          ],
        },
      ],
    },
  },
  {
    // planUnrestricted is the Root branch of ProductAuthorization.access only (ADR 0012); core
    // unit tests exercise it directly. Developer boundary, not process isolation.
    files: ['**/*.ts'],
    ignores: [
      'packages/typeorm-postgres/src/services/product-authority.service.ts',
      'packages/core/test/**',
    ],
    rules: {
      'no-restricted-syntax': [
        'error',
        {
          selector: "MemberExpression[property.name='planUnrestricted']",
          message: 'Only ProductAuthorization.access may plan unrestricted access (ADR 0012).',
        },
        {
          selector: "ObjectPattern > Property[key.name='planUnrestricted']",
          message: 'Only ProductAuthorization.access may plan unrestricted access (ADR 0012).',
        },
      ],
    },
  },
);
