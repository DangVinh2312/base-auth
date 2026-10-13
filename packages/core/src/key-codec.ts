import type { Key, KeyKind } from './types.js';

const INT64_MIN = -(2n ** 63n);
const INT64_MAX = 2n ** 63n - 1n;
const canonicalInteger = /^(0|-?[1-9][0-9]*)$/;
const anyUuid = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const loneSurrogate = /\p{Cs}/u;
export const MAX_KEY_BYTES = 256;

/** Canonical signed 64-bit integer string, or undefined. Never goes through JS number. */
export function canonicalInt64(raw: unknown): string | undefined {
  const text = typeof raw === 'bigint' ? raw.toString() : raw;
  if (typeof text !== 'string' || !canonicalInteger.test(text)) return undefined;
  const value = BigInt(text);
  return value >= INT64_MIN && value <= INT64_MAX ? text : undefined;
}

export function isWellFormedText(value: unknown): value is string {
  return typeof value === 'string' && !loneSurrogate.test(value);
}

export function utf8ByteLength(value: string): number {
  let bytes = 0;
  for (const char of value) {
    const code = char.codePointAt(0)!;
    bytes += code < 0x80 ? 1 : code < 0x800 ? 2 : code < 0x10000 ? 3 : 4;
  }
  return bytes;
}

/** Code point order, identical to UTF-8 byte order and to PostgreSQL `COLLATE "C"`. */
export function compareText(a: string, b: string): number {
  const left = [...a];
  const right = [...b];
  for (let i = 0; i < Math.min(left.length, right.length); i++) {
    const diff = left[i]!.codePointAt(0)! - right[i]!.codePointAt(0)!;
    if (diff !== 0) return diff;
  }
  return left.length - right.length;
}

/**
 * Parses an external key. Integers: bigint or canonical decimal string within int64 (JS numbers
 * are rejected). UUIDs: normalized to lowercase. Strings: exact code points, 1..256 UTF-8 bytes.
 */
export function parseKey(kind: KeyKind, raw: unknown): Key {
  if (kind === 'integer') {
    const value = canonicalInt64(raw);
    if (value === undefined)
      throw new TypeError('Integer key must be a canonical int64 decimal string or bigint');
    return { kind, value };
  }
  if (kind === 'uuid') {
    if (typeof raw !== 'string' || !anyUuid.test(raw)) throw new TypeError('UUID key is malformed');
    return { kind, value: raw.toLowerCase() };
  }
  if (kind === 'string') {
    if (!isWellFormedText(raw) || raw.length === 0 || utf8ByteLength(raw) > MAX_KEY_BYTES) {
      throw new TypeError(`String key must be well-formed text of 1-${MAX_KEY_BYTES} UTF-8 bytes`);
    }
    return { kind, value: raw };
  }
  throw new TypeError('Unknown key kind');
}

export function keyEquals(a: Key, b: Key): boolean {
  return a.kind === b.kind && a.value === b.value;
}

export function keyToString(key: Key): string {
  return `${key.kind}:${key.value}`;
}
