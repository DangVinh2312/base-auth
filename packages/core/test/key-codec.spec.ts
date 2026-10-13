import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  compareText,
  keyEquals,
  keyToString,
  parseKey,
  utf8ByteLength,
} from '@base-authorization/core';

test('integer keys keep full precision as canonical decimal strings', () => {
  assert.deepEqual(parseKey('integer', '9007199254740993'), {
    kind: 'integer',
    value: '9007199254740993',
  });
  assert.deepEqual(parseKey('integer', 9007199254740993n), {
    kind: 'integer',
    value: '9007199254740993',
  });
  assert.deepEqual(parseKey('integer', '-9223372036854775808'), {
    kind: 'integer',
    value: '-9223372036854775808',
  });
  assert.notDeepEqual(
    parseKey('integer', '9007199254740993'),
    parseKey('integer', '9007199254740992'),
  );
});

test('integer keys reject JS numbers and non-canonical or out-of-range spellings', () => {
  for (const raw of [
    42,
    Number('9007199254740993'),
    '042',
    '+42',
    '-0',
    ' 42',
    '42 ',
    '4.2',
    '1e3',
    '',
    '9223372036854775808',
    '0x10',
    null,
    undefined,
  ]) {
    assert.throws(() => parseKey('integer', raw), TypeError, String(raw));
  }
});

test('integer:42 and string:42 are different references', () => {
  const integer = parseKey('integer', '42');
  const string = parseKey('string', '42');
  assert.equal(keyEquals(integer, string), false);
  assert.notEqual(keyToString(integer), keyToString(string));
  assert.equal(keyEquals(integer, parseKey('integer', 42n)), true);
});

test('UUID keys are normalized to lowercase and validated', () => {
  const upper = parseKey('uuid', 'D97EECC9-8F23-4A76-A9AA-82B9D4EF33AC');
  assert.deepEqual(upper, { kind: 'uuid', value: 'd97eecc9-8f23-4a76-a9aa-82b9d4ef33ac' });
  assert.equal(keyEquals(upper, parseKey('uuid', 'd97eecc9-8f23-4a76-a9aa-82b9d4ef33ac')), true);
  for (const raw of [
    'd97eecc98f234a76a9aa82b9d4ef33ac',
    '{d97eecc9-8f23-4a76-a9aa-82b9d4ef33ac}',
    'not-a-uuid',
    1,
  ]) {
    assert.throws(() => parseKey('uuid', raw), TypeError);
  }
});

test('string keys keep exact bytes: no trim, no case folding, quotes and Unicode intact', () => {
  for (const raw of [
    'O\'Reilly "x"',
    ' padded ',
    'Ångström',
    'ångström',
    'é',
    'é',
    '😀',
    "'; DROP TABLE x; --",
  ]) {
    assert.equal(parseKey('string', raw).value, raw);
  }
  assert.equal(keyEquals(parseKey('string', 'Ångström'), parseKey('string', 'ångström')), false);
  assert.equal(keyEquals(parseKey('string', 'é'), parseKey('string', 'é')), false);
});

test('string keys reject empty, lone surrogates and more than 256 UTF-8 bytes', () => {
  assert.throws(() => parseKey('string', ''), TypeError);
  assert.throws(() => parseKey('string', '\ud800'), TypeError);
  assert.equal(utf8ByteLength('é'.repeat(128)), 256);
  assert.equal(parseKey('string', 'é'.repeat(128)).value.length, 128);
  assert.throws(() => parseKey('string', 'é'.repeat(128) + 'a'), TypeError);
  assert.equal(utf8ByteLength('😀'), 4);
});

test('text ordering is by code point, matching UTF-8 byte order', () => {
  assert.ok(compareText('Z', 'a') < 0);
  assert.ok(compareText('￿', '😀') < 0, 'UTF-16 order would put the surrogate pair first');
  assert.equal(compareText('Å', 'Å'), 0);
});
