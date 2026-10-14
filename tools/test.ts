// Runs a node:test suite against built packages. Usage: node tools/test.ts <suite> [files...]
import { spawnSync } from 'node:child_process';
import { statSync } from 'node:fs';

const suites: Record<string, { patterns: string[]; flags: string[] }> = {
  unit: {
    patterns: ['test/**/*.spec.ts', 'test/**/*.smoke-spec.ts', 'packages/*/test/**/*.spec.ts'],
    flags: [],
  },
  e2e: { patterns: ['apps/api/test/**/*.e2e-spec.ts'], flags: ['--test-timeout=300000'] },
  // Each integration file starts its own PostgreSQL container; unbounded parallel files starve
  // the product runner's fixed 2s transaction deadline on small Docker hosts.
  integration: {
    patterns: ['test/**/*.integration-spec.ts'],
    flags: ['--test-timeout=300000', '--test-concurrency=3'],
  },
};

const [name = '', ...args] = process.argv.slice(2);
const suite = suites[name];
if (!suite) {
  console.error(`Unknown test suite "${name}". Expected one of: ${Object.keys(suites).join(', ')}`);
  process.exit(2);
}
// A directory filter runs every spec file of this suite below it.
const files = args
  .filter((arg) => arg !== '--')
  .map((arg) =>
    statSync(arg, { throwIfNoEntry: false })?.isDirectory()
      ? `${arg.replace(/\/$/, '')}/**/*${name === 'unit' ? '.spec.ts' : '.integration-spec.ts'}`
      : arg,
  );
const result = spawnSync(
  process.execPath,
  ['--test', ...suite.flags, ...(files.length > 0 ? files : suite.patterns)],
  { stdio: 'inherit' },
);
process.exit(result.status ?? 1);
