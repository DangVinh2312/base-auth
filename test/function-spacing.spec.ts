import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ESLint } from 'eslint';
import tseslint from 'typescript-eslint';

const cases = [
  [
    'exported constants and documented interfaces',
    "export const PORT = Symbol('PORT');\n/** Trusted commands. */\nexport interface Port {\n  run(): void;\n}",
    "export const PORT = Symbol('PORT');\n\n/** Trusted commands. */\nexport interface Port {\n  run(): void;\n}",
  ],
  [
    'exported constants',
    'export const a = 1;\nexport const b = 2;',
    'export const a = 1;\n\nexport const b = 2;',
  ],
  [
    'named and default exports',
    'export type A = string;\nexport default class B {}',
    'export type A = string;\n\nexport default class B {}',
  ],
  ['imports and a class', "import 'a';\nclass A {}", "import 'a';\n\nclass A {}"],
  [
    'imports and an exported decorated class',
    "import { Controller } from '@nestjs/common';\n@Controller('users')\nexport class A {}",
    "import { Controller } from '@nestjs/common';\n\n@Controller('users')\nexport class A {}",
  ],
  [
    'multiline imports and a class with documentation',
    "import {\n  A,\n  B,\n} from 'a';\n/** Controller */\nclass C {}",
    "import {\n  A,\n  B,\n} from 'a';\n\n/** Controller */\nclass C {}",
  ],
  [
    'an import group and an interface',
    "import 'a';\nimport 'b';\nexport interface A {}",
    "import 'a';\nimport 'b';\n\nexport interface A {}",
  ],
  ['functions', 'function a() {}\nfunction b() {}', 'function a() {}\n\nfunction b() {}'],
  [
    'exported functions',
    'export function a() {}\nexport async function b() {}',
    'export function a() {}\n\nexport async function b() {}',
  ],
  [
    'arrow functions',
    'const a = () => 1;\nconst b = () => 2;',
    'const a = () => 1;\n\nconst b = () => 2;',
  ],
  [
    'class methods and decorators',
    'class A {\n  a() {}\n  /** B */\n  @decorator()\n  b() {}\n}',
    'class A {\n  a() {}\n\n  /** B */\n  @decorator()\n  b() {}\n}',
  ],
  [
    'interface methods',
    'interface A {\n  a(): void;\n  b(): void;\n}',
    'interface A {\n  a(): void;\n\n  b(): void;\n}',
  ],
  [
    'class arrow methods',
    'class A {\n  a = () => 1;\n  b = () => 2;\n}',
    'class A {\n  a = () => 1;\n\n  b = () => 2;\n}',
  ],
  [
    'type callbacks',
    'type A = {\n  a: () => void;\n  b: () => void;\n};',
    'type A = {\n  a: () => void;\n\n  b: () => void;\n};',
  ],
  [
    'functions with trailing comments',
    'function a() {} // A\n/** B */\nfunction b() {}',
    'function a() {} // A\n\n/** B */\nfunction b() {}',
  ],
  [
    'functions on the same line',
    'function a() {} function b() {}',
    'function a() {} \n\nfunction b() {}',
  ],
] as const;

for (const [name, input, expected] of cases) {
  test(`format inserts a blank line between ${name}`, async () => {
    const eslint = new ESLint({ overrideConfig: tseslint.configs.disableTypeChecked });
    const [result] = await eslint.lintText(input, { filePath: 'tools/format-fixture.ts' });
    assert.ok(result);
    assert.equal(result.messages.filter((m) => m.ruleId === 'format/function-spacing').length, 1);

    const fixer = new ESLint({ overrideConfig: tseslint.configs.disableTypeChecked, fix: true });
    const [fixed] = await fixer.lintText(input, { filePath: 'tools/format-fixture.ts' });
    assert.ok(fixed);
    assert.equal(fixed.output, expected);
    assert.equal(fixed.messages.filter((m) => m.ruleId === 'format/function-spacing').length, 0);
    const [again] = await fixer.lintText(expected, { filePath: 'tools/format-fixture.ts' });
    assert.ok(again);
    assert.equal(again.output, undefined);
  });
}

test('format leaves object properties together, including nested callbacks and methods', async () => {
  const eslint = new ESLint({ overrideConfig: tseslint.configs.disableTypeChecked, fix: true });
  for (const input of [
    'const a = {\n  a() {},\n  b() {},\n};',
    `const provider = {
  provide: PORT,
  useFactory: () => ({
    config,
    list: () => authorization.list(),
    detail: function () { return authorization.detail(); },
    update() { return authorization.update(); },
  }),
};`,
  ]) {
    const [result] = await eslint.lintText(input, { filePath: 'tools/format-fixture.ts' });
    assert.ok(result);
    assert.equal(result.messages.filter((m) => m.ruleId === 'format/function-spacing').length, 0);
    assert.equal(result.output, undefined);
  }
});

test('format preserves existing spacing and leaves ordinary variables together', async () => {
  const eslint = new ESLint({ overrideConfig: tseslint.configs.disableTypeChecked, fix: true });
  for (const input of [
    'function a() {}\n\nfunction b() {}',
    'const a = 1;\nconst b = 2;',
    'type A = string;\nconst a = 1;',
    "import 'a';\nimport 'b';",
    "import 'a';\n\nclass A {}",
    'export const a = 1;\n\nexport const b = 2;',
  ]) {
    const [result] = await eslint.lintText(input, { filePath: 'tools/format-fixture.ts' });
    assert.ok(result);
    assert.equal(result.output, undefined);
    assert.equal(result.messages.filter((m) => m.ruleId === 'format/function-spacing').length, 0);
  }
});
