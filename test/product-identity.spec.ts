import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  createProductPasswordHasher,
  canonicalLoginEmail,
  sessionDigest,
} from '../packages/typeorm-postgres/dist/product-identity.js';

test('password profile counts code points, preserves spaces and rejects blocklist', async () => {
  const hasher = await createProductPasswordHasher(new Set(['compromised password']));
  await assert.rejects(hasher.hash('compromised password'));
  await assert.rejects(hasher.hash('short'));
  await assert.rejects(hasher.hash('🙂'.repeat(14)));
  await assert.rejects(hasher.hash('🙂'.repeat(129)));
  await assert.rejects(hasher.hash('long malformed password \ud800'));
  const hash = await hasher.hash('  valid long password  ');
  assert.match(hash, /^\$argon2id\$v=19\$m=19456,(?:t=2,p=1|p=1,t=2)\$/);
  assert.equal(await hasher.verify(hash, '  valid long password  '), true);
  assert.equal(await hasher.verify(hash, 'valid long password'), false);
  assert.equal(
    await hasher.verify('$argon2id$v=19$m=999999999,t=2,p=1$bad$bad', 'valid long password'),
    false,
  );
});

test('login email canonicalization does not remove dots or plus tags', () => {
  assert.equal(canonicalLoginEmail('A.B+Tag@Example.COM'), 'a.b+tag@example.com');
  assert.throws(() => canonicalLoginEmail('no-email'));
  assert.throws(() => sessionDigest('not-a-session'));
});
