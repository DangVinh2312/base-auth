import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import dayjs from 'dayjs';
import { createAuthorizationCore } from '../../apps/api/dist/authorization/core/authorization.factory.js';
import type { ScalarCodec } from '../../apps/api/dist/authorization/core/ports/value-codecs.port.js';
import { createDayjsTimestampCodec } from '../../apps/api/dist/authorization/values/codecs/dayjs-timestamp.codec.js';
import { createStandardValueCodecs } from '../../apps/api/dist/authorization/values/codecs/standard-values.codec.js';

// ponytail: kept inside the spec (no test-helper export convention in this repo); a future
// Moment adapter imports nothing here — copy the cases or promote them when a second adapter exists.
interface Case {
  readonly name: string;

  readonly holds: (codec: ScalarCodec<string>) => boolean;
}

const invalidTimestamps: readonly [string, unknown][] = [
  ['nonexistent date 2026-02-30', '2026-02-30T00:00:00Z'],
  ['invalid leap year 2025-02-29', '2025-02-29T00:00:00Z'],
  ['century non-leap 1900-02-29', '1900-02-29T00:00:00Z'],
  ['month 0', '2026-00-10T00:00:00Z'],
  ['day 0', '2026-10-00T00:00:00Z'],
  ['month 13', '2026-13-10T00:00:00Z'],
  ['hour 24', '2026-10-14T24:00:00Z'],
  ['hour 24 with minutes', '2026-10-14T24:00:01Z'],
  ['leap second', '2026-06-30T23:59:60Z'],
  ['missing Z', '2026-10-14T00:00:00'],
  ['offset +07:00', '2026-10-14T07:00:00+07:00'],
  ['offset +00:00', '2026-10-14T00:00:00+00:00'],
  ['seven fractional digits', '2026-10-14T00:00:00.1234567Z'],
  ['empty fraction', '2026-10-14T00:00:00.Z'],
  ['lowercase z', '2026-10-14T00:00:00z'],
  ['lowercase t', '2026-10-14t00:00:00Z'],
  ['space separator', '2026-10-14 00:00:00Z'],
  ['leading whitespace', ' 2026-10-14T00:00:00Z'],
  ['trailing whitespace', '2026-10-14T00:00:00Z '],
  ['trailing junk', '2026-10-14T00:00:00Zjunk'],
  ['year 0000', '0000-01-01T00:00:00Z'],
  ['date only', '2026-10-14'],
  ['no seconds', '2026-10-14T00:00Z'],
  ['non-ASCII digits', '２０２６-10-14T00:00:00Z'],
  ['empty string', ''],
  ['Date object', new Date(0)],
  ['number', 0],
  ['null', null],
  ['undefined', undefined],
];

const timestampCases: readonly Case[] = [
  {
    name: 'pads fractional digits to six places',

    holds: (c) => c.normalize('2026-10-14T00:00:00.1Z') === '2026-10-14T00:00:00.100000Z',
  },
  {
    name: 'adds a six-digit fraction to whole seconds',

    holds: (c) => c.normalize('2026-10-14T00:00:00Z') === '2026-10-14T00:00:00.000000Z',
  },
  {
    name: 'keeps full microsecond precision',

    holds: (c) => c.normalize('2026-10-14T00:00:00.123456Z') === '2026-10-14T00:00:00.123456Z',
  },
  {
    name: 'accepts valid leap day 2024-02-29',

    holds: (c) => c.normalize('2024-02-29T12:00:00Z') === '2024-02-29T12:00:00.000000Z',
  },
  {
    name: 'accepts 2000-02-29 (400-year leap)',

    holds: (c) => c.normalize('2000-02-29T12:00:00Z') === '2000-02-29T12:00:00.000000Z',
  },
  {
    name: 'accepts 23:59:59.999999',

    holds: (c) => c.normalize('2026-10-14T23:59:59.999999Z') === '2026-10-14T23:59:59.999999Z',
  },
  ...['0001', '0099', '0100', '9999'].map((year): Case => ({
    name: `year ${year} round-trips`,

    holds: (c) =>
      c.normalize(`${year}-12-31T23:59:59.000001Z`) === `${year}-12-31T23:59:59.000001Z` &&
      c.normalize(`${year}-01-01T00:00:00Z`) === `${year}-01-01T00:00:00.000000Z`,
  })),
  {
    name: 'years 0004 and 0096 keep leap day (proleptic Gregorian)',

    holds: (c) =>
      c.normalize('0004-02-29T00:00:00Z') === '0004-02-29T00:00:00.000000Z' &&
      c.normalize('0096-02-29T00:00:00Z') === '0096-02-29T00:00:00.000000Z' &&
      c.normalize('0100-02-29T00:00:00Z') === undefined &&
      c.normalize('0001-02-29T00:00:00Z') === undefined,
  },
  {
    name: '.000001 sorts before .000002 and not equal',

    holds: (c) => {
      const a = c.normalize('2026-10-14T00:00:00.000001Z');
      const b = c.normalize('2026-10-14T00:00:00.000002Z');
      return (
        a !== undefined &&
        b !== undefined &&
        a !== b &&
        c.compare(a, b) === -1 &&
        c.compare(b, a) === 1 &&
        c.compare(a, a) === 0
      );
    },
  },
  {
    name: 'compare orders across seconds, days and years',

    holds: (c) => {
      const lo = c.normalize('0099-12-31T23:59:59.999999Z')!;
      const hi = c.normalize('0100-01-01T00:00:00Z')!;
      return c.compare(lo, hi) === -1 && c.compare(hi, lo) === 1;
    },
  },
  {
    name: 'normalize is idempotent',

    holds: (c) => {
      const once = c.normalize('2026-10-14T00:00:00.5Z')!;
      return c.normalize(once) === once;
    },
  },
  ...invalidTimestamps.map(([name, input]): Case => ({
    name: `rejects ${name}`,

    holds: (c) => c.normalize(input) === undefined,
  })),
];

function timestampConformance(label: string, make: () => ScalarCodec<string>): void {
  describe(`timestamp conformance: ${label}`, () => {
    for (const testCase of timestampCases) {
      test(testCase.name, () => assert.ok(testCase.holds(make())));
    }
  });
}

timestampConformance('dayjs', createDayjsTimestampCodec);

// A lenient Date.parse codec: must be caught by the same cases.
const permissive: ScalarCodec<string> = {
  normalize(input) {
    if (typeof input !== 'string') return undefined;
    const ms = Date.parse(input);
    return Number.isNaN(ms) ? undefined : new Date(ms).toISOString().replace('Z', '000Z');
  },

  compare: (l, r) => (l === r ? 0 : l < r ? -1 : 1),
};

test('a permissive Date.parse codec fails the conformance cases', () => {
  const failed = timestampCases.filter((c) => !c.holds(permissive)).map((c) => c.name);
  for (const name of [
    'rejects nonexistent date 2026-02-30',
    'rejects hour 24',
    'rejects offset +07:00',
    'rejects missing Z',
    'rejects seven fractional digits',
    'keeps full microsecond precision',
    'year 0001 round-trips',
  ]) {
    assert.ok(failed.includes(name), `permissive codec should fail "${name}"`);
  }
});

const values = createStandardValueCodecs({ timestamp: createDayjsTimestampCodec() });
const { isCanonicalUuid, parseKey } = createAuthorizationCore({ values });

describe('integer codec', () => {
  const { integer } = values;
  test('accepts canonical strings and bigint, int64 bounds inclusive', () => {
    assert.equal(integer.normalize('0'), '0');
    assert.equal(integer.normalize(42n), '42');
    assert.equal(integer.normalize('9007199254740993'), '9007199254740993');
    assert.equal(integer.normalize('-9223372036854775808'), '-9223372036854775808');
    assert.equal(integer.normalize('9223372036854775807'), '9223372036854775807');
    assert.equal(integer.normalize(2n ** 63n - 1n), '9223372036854775807');
  });
  test('rejects JS numbers, out-of-range and non-canonical text', () => {
    for (const bad of [
      1,
      0,
      1.5,
      NaN,
      '9223372036854775808',
      '-9223372036854775809',
      2n ** 63n,
      '01',
      '-0',
      '+1',
      '1.0',
      ' 1',
      '1 ',
      '',
      null,
      undefined,
    ]) {
      assert.equal(integer.normalize(bad), undefined, String(bad));
    }
  });
  test('compares exactly beyond 2^53', () => {
    assert.equal(integer.compare('9007199254740993', '9007199254740992'), 1);
    assert.equal(integer.compare('-9223372036854775808', '9223372036854775807'), -1);
    assert.equal(integer.compare('5', '5'), 0);
  });
});

describe('decimal codec', () => {
  const { decimal } = values;
  test('keeps the literal (no scale rewrite) and rejects numbers and bad syntax', () => {
    assert.equal(decimal.normalize('10.0'), '10.0');
    assert.equal(decimal.normalize('10.00'), '10.00');
    assert.equal(decimal.normalize('-0'), '-0');
    assert.equal(decimal.normalize('0.1'), '0.1');
    for (const bad of [10, 0.1, '1e3', '.5', '5.', '+1', '01', '1,5', ' 1', '', '-', 'NaN', null]) {
      assert.equal(decimal.normalize(bad), undefined, String(bad));
    }
  });
  test('10.0 equals 10.00 on compare, different scales order correctly', () => {
    assert.equal(decimal.compare('10.0', '10.00'), 0);
    assert.equal(decimal.compare('10.0', '10'), 0);
    assert.equal(decimal.compare('10.01', '10.1'), -1);
    assert.equal(decimal.compare('9.99', '10'), -1);
    assert.equal(decimal.compare('0.1', '0.10000000000000001'), -1);
  });
  test('large values compare without floating point', () => {
    const big = '123456789012345678901234567890.123456789012345678901234567890';
    const bigger = '123456789012345678901234567890.123456789012345678901234567891';
    assert.equal(decimal.compare(big, bigger), -1);
    assert.equal(decimal.compare(bigger, big), 1);
    assert.equal(decimal.compare(big, `${big}000`), 0);
    assert.equal(decimal.compare('99999999999999999999', '100000000000000000000'), -1);
  });
  test('negatives and negative zero', () => {
    assert.equal(decimal.compare('-1', '-2'), 1);
    assert.equal(decimal.compare('-2.5', '-2.50'), 0);
    assert.equal(decimal.compare('-1', '1'), -1);
    assert.equal(decimal.compare('-0', '0'), 0);
    assert.equal(decimal.compare('-0.00', '0'), 0);
    assert.equal(decimal.compare('-0', '0.001'), -1);
    assert.equal(decimal.compare('-0.001', '-0'), -1);
  });
});

describe('uuid codec', () => {
  const { uuid } = values;
  const lower = '0190a5c2-7b1e-7c3a-8f55-0123456789ab';
  test('normalizes to lowercase; canonical identity check still rejects uppercase', () => {
    const upper = lower.toUpperCase();
    assert.equal(uuid.normalize(upper), lower);
    assert.equal(uuid.normalize(lower), lower);
    assert.equal(isCanonicalUuid(upper), false);
    assert.equal(isCanonicalUuid(uuid.normalize(upper)), true);
  });
  test('negative control: an uppercase-preserving codec fails the lowercase case', () => {
    const upper = lower.toUpperCase();

    const lowercases = (codec: ScalarCodec<string>) => codec.normalize(upper) === lower;

    const passThrough: ScalarCodec<string> = {
      normalize: (value) => (typeof value === 'string' ? value : undefined),

      compare: (l, r) => (l === r ? 0 : 1),
    };
    assert.equal(lowercases(uuid), true);
    assert.equal(lowercases(passThrough), false);
  });
  test('rejects malformed values', () => {
    for (const bad of [
      '',
      'not-a-uuid',
      lower.slice(1),
      `${lower}0`,
      lower.replaceAll('-', ''),
      `{${lower}}`,
      ` ${lower}`,
      lower.replace('a', 'g'),
      1,
      null,
    ]) {
      assert.equal(uuid.normalize(bad), undefined, String(bad));
    }
  });
  test('equality only: equal is 0, different is not 0', () => {
    assert.equal(uuid.compare(lower, lower), 0);
    assert.notEqual(uuid.compare(lower, '0190a5c2-7b1e-7c3a-8f55-0123456789ac'), 0);
  });
});

describe('string codec', () => {
  const { string } = values;
  test('does not trim or normalize Unicode', () => {
    assert.equal(string.normalize('  padded  '), '  padded  ');
    assert.equal(string.normalize('é'), 'é');
    assert.notEqual(string.normalize('é'), 'é');
    assert.equal(string.normalize(''), '');
    assert.equal(string.normalize('\u{1F600}'), '\u{1F600}');
  });
  test('rejects lone surrogates and non-strings', () => {
    for (const bad of ['\ud800', 'a\udc00b', '\udc00\ud800', 1, null, undefined]) {
      assert.equal(string.normalize(bad), undefined, JSON.stringify(bad));
    }
  });
  test('compares by code point (not UTF-16 unit)', () => {
    assert.equal(string.compare('\u{10000}', '￿'), 1);
    assert.equal(string.compare('￿', '\u{10000}'), -1);
    assert.equal(string.compare('a', 'ab'), -1);
    assert.equal(string.compare('ab', 'a'), 1);
    assert.equal(string.compare('same', 'same'), 0);
  });
  test('the 256-byte key limit is enforced by core parseKey, not by the string codec', () => {
    const long = 'a'.repeat(257);
    assert.equal(string.normalize(long), long);
    assert.throws(() => parseKey('string', long), TypeError);
    assert.deepEqual(parseKey('string', 'a'.repeat(256)).kind, 'string');
  });
});

describe('boolean codec', () => {
  const { boolean } = values;
  test('accepts only booleans', () => {
    assert.equal(boolean.normalize(true), true);
    assert.equal(boolean.normalize(false), false);
    for (const bad of ['true', 1, 0, null, undefined]) {
      assert.equal(boolean.normalize(bad), undefined, String(bad));
    }
  });
  test('equality only', () => {
    assert.equal(boolean.compare(true, true), 0);
    assert.notEqual(boolean.compare(true, false), 0);
  });
});

test('createStandardValueCodecs wires the supplied timestamp codec and freezes the table', () => {
  assert.equal(values.timestamp.normalize('2026-10-14T00:00:00.1Z'), '2026-10-14T00:00:00.100000Z');
  assert.ok(Object.isFrozen(values));
  const marker: ScalarCodec<string> = {
    normalize: () => 'x',

    compare: () => 0,
  };
  assert.equal(createStandardValueCodecs({ timestamp: marker }).timestamp, marker);
});

test('standard scalar codecs are frozen: mutation throws and never leaks into later tables', () => {
  const first = createStandardValueCodecs({ timestamp: createDayjsTimestampCodec() });
  for (const key of ['integer', 'decimal', 'uuid', 'string', 'boolean'] as const) {
    assert.ok(Object.isFrozen(first[key]), `${key} codec must be frozen`);
  }
  assert.throws(() => {
    (first.uuid as { normalize: unknown }).normalize = (input: unknown) => input;
  }, TypeError);
  const later = createStandardValueCodecs({ timestamp: createDayjsTimestampCodec() });
  assert.equal(
    later.uuid.normalize('AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA'),
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  );
});

test('timestamp codec ignores a host global locale with postformat', () => {
  const previous = dayjs.locale();
  // Declared apart from the call: Day.js typings omit `postformat`, which locales may still carry.
  const hostLocale = {
    name: 'x-postformat',
    months: dayjs.Ls.en!.months as string[],
    weekdays: dayjs.Ls.en!.weekdays as string[],

    postformat: (text: string) => text.replace(/\d/g, 'x'),
  };
  dayjs.locale('x-postformat', hostLocale);
  dayjs.locale('x-postformat');
  try {
    assert.equal(
      createDayjsTimestampCodec().normalize('2026-10-14T00:00:00Z'),
      '2026-10-14T00:00:00.000000Z',
    );
  } finally {
    dayjs.locale(previous);
  }
});
