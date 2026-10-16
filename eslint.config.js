import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import formatConfig from './eslint.format.config.js';

const driverImports = [
  {
    group: ['typeorm', 'typeorm/*', 'pg', 'pg-*'],
    message: 'Storage drivers belong to services/database, never HTTP handlers or the pure core.',
  },
];

const offlineImports = [
  {
    group: ['**/product-manifest.service*'],
    importNames: ['bootstrapProductRoot', 'revokeProductRoot', 'reissueRootActivation'],
    message: 'Root lifecycle commands are offline tools only.',
  },
  {
    group: ['**/product-database.helper*'],
    importNames: ['provisionProductDatabase', 'productDataSourceOptions', 'productMigrations'],
    message: 'Provisioning and migration are offline tools only.',
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
    // Offline functions stay in the same app source, but HTTP runtime cannot import them.
    files: ['apps/api/src/**/*.ts'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: offlineImports,
        },
      ],
    },
  },
  {
    files: ['apps/api/src/authorization/core/**/*.ts'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              regex: '^(?:[^.]|\\.\\./)',
              message: 'Authorization core uses only its own pure source modules.',
            },
            {
              group: [
                '**/values/**',
                '**/services/**',
                '**/enforcement/**',
                '**/database/**',
                '**/auth/**',
                '**/audit/**',
              ],
              message:
                'Authorization core must remain independent of application services and adapters.',
            },
          ],
        },
      ],
    },
  },
  {
    files: ['apps/api/src/authorization/enforcement/**/*.ts'],
    rules: {
      'no-restricted-imports': ['error', { patterns: [...driverImports, ...offlineImports] }],
    },
  },
  {
    // HTTP handlers receive bound operations; services may use TypeORM directly.
    files: ['apps/api/src/{auth,document,administration,health,openapi}/**/*.ts'],
    ignores: ['apps/api/src/document/migrations/**', 'apps/api/src/auth/services/**'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            ...driverImports,
            {
              group: [
                '**/database/**',
                '**/audit/**',
                '**/authorization/services/**',
                '**/authorization/helpers/**',
                '**/product-data.gateway*',
                '**/product-sql.compiler*',
              ],
              allowTypeImports: true,
              message:
                'HTTP handlers use bound facade operations; implementation types may be imported without runtime access.',
            },
            {
              group: [
                '**/auth/services/**',
                '**/services/product-identity.service*',
                '**/services/product-oidc.service*',
              ],
              allowTypeImports: true,
              allowImportNames: [
                'rateLimitClient',
                'canonicalLoginEmail',
                'ProductAuthenticationError',
                'ProductAuthenticationUnavailable',
              ],
              message: 'Identity service operations are private; inject AUTH_HTTP_PORT.',
            },
            {
              group: [
                '**/infrastructure/product-runtime*',
                '**/infrastructure/runtime.module*',
                '**/product-runtime*',
              ],
              message: 'The runtime provider is private to RuntimeModule; inject a facade token.',
            },
          ],
        },
      ],
    },
  },
  {
    // Root access uses the factory-issued plan only (ADR 0012); the factory owns the raw planner.
    // Core unit tests exercise both directly. Developer boundary, not process isolation.
    files: ['**/*.ts'],
    ignores: [
      'apps/api/src/authorization/services/product-authority.service.ts',
      'apps/api/src/authorization/core/authorization.factory.ts',
      'test/core/**',
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
        {
          selector: "ImportSpecifier[imported.name='planUnrestricted']",
          message:
            'The unrestricted planner is internal to the core factory and authority service.',
        },
        {
          selector:
            "ExportNamedDeclaration[source] > ExportSpecifier[local.name='planUnrestricted']",
          message:
            'The unrestricted planner is internal to the core factory and authority service.',
        },
      ],
    },
  },
);
