import type { Comparison, ScalarCodec, ValueCodecs } from '@base-authorization/core';

const INT64_MIN = -(2n ** 63n);
const INT64_MAX = 2n ** 63n - 1n;
const canonicalInteger = /^(0|-?[1-9][0-9]*)$/;
const decimalPattern = /^(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?$/;
const anyUuid = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const loneSurrogate = /\p{Cs}/u;

const sign = (n: number | bigint): Comparison => (n === 0 || n === 0n ? 0 : n < 0 ? -1 : 1);

// Never goes through JS number; JS numbers are rejected.
const integer: ScalarCodec<string> = {
  normalize(input) {
    const text = typeof input === 'bigint' ? input.toString() : input;
    if (typeof text !== 'string' || !canonicalInteger.test(text)) return undefined;
    const value = BigInt(text);
    return value >= INT64_MIN && value <= INT64_MAX ? text : undefined;
  },
  compare: (left, right) => sign(BigInt(left) - BigInt(right)),
};

function parseDecimal(text: string) {
  const [, minus = '', whole = '0', fraction = ''] = decimalPattern.exec(text) ?? [];
  const digits = fraction.replace(/0+$/, '');
  return { negative: minus === '-' && (whole !== '0' || digits !== ''), whole, digits };
}

// Literal is kept as given (10.0 and 10.00 stay distinct); compare ignores scale and -0.
const decimal: ScalarCodec<string> = {
  normalize: (input) =>
    typeof input === 'string' && decimalPattern.test(input) ? input : undefined,
  compare(left, right) {
    const x = parseDecimal(left);
    const y = parseDecimal(right);
    if (x.negative !== y.negative) return x.negative ? -1 : 1;
    let magnitude: Comparison;
    if (x.whole.length !== y.whole.length) magnitude = x.whole.length < y.whole.length ? -1 : 1;
    else if (x.whole !== y.whole) magnitude = x.whole < y.whole ? -1 : 1;
    else {
      const width = Math.max(x.digits.length, y.digits.length);
      const xf = x.digits.padEnd(width, '0');
      const yf = y.digits.padEnd(width, '0');
      magnitude = xf === yf ? 0 : xf < yf ? -1 : 1;
    }
    return x.negative ? sign(-magnitude) : magnitude; // sign() avoids returning -0
  },
};

// Equality only (no ordering is defined for uuid); unequal reports 1, as core does today.
const uuid: ScalarCodec<string> = {
  normalize: (input) =>
    typeof input === 'string' && anyUuid.test(input) ? input.toLowerCase() : undefined,
  compare: (left, right) => (left === right ? 0 : 1),
};

// Exact code points: no trim, no NFC/NFD. Code point order equals UTF-8 byte order / COLLATE "C".
// The 256-byte key limit belongs to core's parseKey, not to this value codec.
const string: ScalarCodec<string> = {
  normalize: (input) =>
    typeof input === 'string' && !loneSurrogate.test(input) ? input : undefined,
  compare(left, right) {
    const a = [...left];
    const b = [...right];
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
      const diff = sign(a[i]!.codePointAt(0)! - b[i]!.codePointAt(0)!);
      if (diff !== 0) return diff;
    }
    return sign(a.length - b.length);
  },
};

// Equality only; unequal reports 1, as core does today.
const boolean: ScalarCodec<boolean> = {
  normalize: (input) => (typeof input === 'boolean' ? input : undefined),
  compare: (left, right) => (left === right ? 0 : 1),
};

// Module-level codecs are shared by every table; freezing keeps them from becoming a mutable singleton.
for (const codec of [integer, decimal, uuid, string, boolean]) Object.freeze(codec);

export function createStandardValueCodecs(options: {
  readonly timestamp: ScalarCodec<string>;
}): ValueCodecs {
  return Object.freeze({
    timestamp: options.timestamp,
    integer,
    decimal,
    uuid,
    string,
    boolean,
  });
}
