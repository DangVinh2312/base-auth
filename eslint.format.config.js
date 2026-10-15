import tseslint from 'typescript-eslint';

const functionTypes = new Set([
  'FunctionDeclaration',
  'FunctionExpression',
  'ArrowFunctionExpression',
  'MethodDefinition',
  'TSAbstractMethodDefinition',
  'TSDeclareFunction',
  'TSMethodSignature',
  'TSCallSignatureDeclaration',
  'TSConstructSignatureDeclaration',
]);

function isFunction(node) {
  const declaration = node.declaration ?? node;
  return (
    functionTypes.has(declaration.type) ||
    functionTypes.has(declaration.value?.type) ||
    declaration.typeAnnotation?.typeAnnotation?.type === 'TSFunctionType' ||
    declaration.declarations?.some((item) => functionTypes.has(item.init?.type))
  );
}

const functionSpacing = {
  meta: {
    type: 'layout',
    fixable: 'whitespace',
    schema: [],
    messages: { blankLine: 'Expected a blank line after imports or between exports/functions.' },
  },

  create(context) {
    const source = context.sourceCode;

    return {
      ':matches(Program, BlockStatement, ClassBody, TSInterfaceBody, TSTypeLiteral, ObjectExpression):exit'(
        node,
      ) {
        const members = node.body ?? node.members ?? node.properties;
        for (let i = 1; i < members.length; i++) {
          const previous = members[i - 1];
          const next = members[i];
          const endsImports =
            previous.type === 'ImportDeclaration' && next.type !== 'ImportDeclaration';
          const separatesExports =
            previous.type.startsWith('Export') && next.type.startsWith('Export');
          if (!endsImports && !separatesExports && !isFunction(previous) && !isFunction(next))
            continue;

          const between = source.getTokensBetween(previous, next, { includeComments: true });
          const boundaries = [previous, ...between, next];
          if (
            boundaries.some(
              (item, index) =>
                index > 0 && item.loc.start.line - boundaries[index - 1].loc.end.line > 1,
            )
          )
            continue;

          const anchor =
            between.find((item) => item.loc.start.line > previous.loc.end.line) ?? next;
          context.report({
            node: next,
            messageId: 'blankLine',

            fix(fixer) {
              if (anchor.loc.start.line === previous.loc.end.line)
                return fixer.insertTextBefore(anchor, '\n\n');
              const lineStart = source.text.lastIndexOf('\n', anchor.range[0] - 1) + 1;
              return fixer.insertTextBeforeRange([lineStart, lineStart], '\n');
            },
          });
        }
      },
    };
  },
};

export default [
  {
    ignores: [
      '**/dist/**',
      '**/node_modules/**',
      'coverage/**',
      '.superpowers/**',
      '.pnpm-store/**',
    ],
  },
  {
    files: ['**/*.{ts,js}'],
    languageOptions: { parser: tseslint.parser },
    plugins: { format: { rules: { 'function-spacing': functionSpacing } } },
    rules: { 'format/function-spacing': 'error' },
  },
];
