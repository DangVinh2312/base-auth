import js from '@eslint/js';
import tseslint from 'typescript-eslint';

const driverImports = [
  {
    group: ['typeorm', 'typeorm/*', 'pg', 'pg-*'],
    message: 'Storage drivers belong to typeorm-postgres.',
  },
];

export default tseslint.config(
  { ignores: ['**/dist/**', '**/node_modules/**', 'coverage/**'] },
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
    files: ['eslint.config.js'],
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
);
