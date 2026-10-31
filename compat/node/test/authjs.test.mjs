// Milestone 3: Auth.js tokens made with a handle decrypt on a server holding the real secret.
// That needs the token's `kid` (a JWK thumbprint of the derived key) to match the real one.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { decode } from '@auth/core/jwt';
import { startKeeper, runApp, real } from '../lib/harness.mjs';

let keeper, r;
before(async () => { keeper = await startKeeper(); r = runApp('authjs.mjs', { keeper }).results; });
after(() => keeper?.stop());

test('no errors', () => assert.deepEqual(r.errors, {}));

test('Auth.js token decrypts on an unshimmed server with the real AUTH_SECRET (kid matches)', async () => {
  const back = await decode({ token: r.token, secret: real('AUTH_SECRET').toString(), salt: 'authjs.session-token' });
  assert.equal(back?.name, 'Alice');
  assert.equal(r.decoded, 'Alice');
  assert.match(JSON.parse(Buffer.from(r.token.split('.')[0], 'base64url')).kid, /^[A-Za-z0-9_-]{86}$/);
});

test('ordinary hashes are untouched', () => {
  assert.equal(r.plainHash, crypto.createHash('sha256').update('hello').digest('hex'));
  assert.equal(r.plainThumbprintLike, crypto.createHash('sha256').update('{"k":"AAAA","kty":"oct"}').digest('hex'));
});

test('hash over salt + handle returns a handle, never the derived key', () => {
  assert.match(r.derivedHandle, /^dk1:[0-9a-f]{16}\.{12}$/);
});
