import type { Key } from './authorization.types.js';

export const MAX_KEY_BYTES = 256;

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

export function keyEquals(a: Key, b: Key): boolean {
  return a.kind === b.kind && a.value === b.value;
}

export function keyToString(key: Key): string {
  return `${key.kind}:${key.value}`;
}
