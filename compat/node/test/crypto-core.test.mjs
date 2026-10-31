import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { startKeeper, runApp, real } from '../lib/harness.mjs';

let keeper, r;
before(async () => { keeper = await startKeeper(); r = runApp('crypto-core.mjs', { keeper }).results; });
after(() => keeper?.stop());

const iv12 = Buffer.alloc(12, 7), iv16 = Buffer.alloc(16, 9);
const hmacHex = (k, d, alg = 'sha256') => crypto.createHmac(alg, k).update(d).digest('hex');
const gcmDecrypt = (key, ctWithTag, aad) => {
  const d = crypto.createDecipheriv(`aes-${key.length * 8}-gcm`, key, iv12);
  if (aad) d.setAAD(Buffer.from(aad));
  d.setAuthTag(ctWithTag.subarray(-16));
  return Buffer.concat([d.update(ctWithTag.subarray(0, -16)), d.final()]).toString();
};
const EXPECTED_ERRORS = ['gcmTampered', 'gcmWrongKeyLength', 'cbcBadPadding', 'hkdfTooShort', 'scrypt', 'chacha', 'md5', 'aesKw', 'policy'];

test('no unexpected errors', () => {
  const unexpected = Object.fromEntries(Object.entries(r.errors).filter(([k]) => !EXPECTED_ERRORS.includes(k)));
  assert.deepEqual(unexpected, {});
});

test('streaming HMAC (.write/.end and .pipe) matches the real key', () => {
  const want = hmacHex(real('JWT_SECRET'), 'hello');
  assert.equal(r.hmacWriteEnd, want);
  assert.equal(r.hmacPipe, want);
  assert.equal(r.hmacSecondDigest, '', 'second digest() returns empty, like node');
});

test('Buffer keys and KeyObjects carry the handle', () => {
  assert.equal(r.hmacBufferKey, crypto.createHmac('sha512', real('JWT_SECRET')).update('hello').digest('base64'));
  assert.equal(r.hmacKeyObject, hmacHex(real('JWT_SECRET'), 'hello'));
  assert.match(r.keyObjectExport, /^dk1:NOT-A-SECRET/, 'export() of a decoy returns the handle, never decoy bytes');
  assert.equal(r.keyObjectSize, Buffer.byteLength(r.keyObjectExport));
});

test('AES-256-GCM with a compact handle key decrypts under the real key; round trip and tamper detection work', () => {
  const ct = Buffer.concat([Buffer.from(r.gcm.ct, 'base64'), Buffer.from(r.gcm.tag, 'base64')]);
  assert.equal(gcmDecrypt(real('ENCRYPTION_KEY'), ct, 'header'), 'field-level secret');
  assert.equal(r.gcmRoundTrip, 'field-level secret');
  assert.equal(r.errors.gcmTampered, 'Unsupported state or unable to authenticate data');
  assert.equal(r.errors.gcmWrongKeyLength, 'Invalid key length');
});

test('AES-256-CBC with a hex-encoded handle (streamed) decrypts under the real key', () => {
  const d = crypto.createDecipheriv('aes-256-cbc', real('ENCRYPTION_KEY_HEX'), iv16);
  assert.equal(Buffer.concat([d.update(Buffer.from(r.cbcHex, 'base64')), d.final()]).toString(), 'stream me');
  assert.equal(r.cbcRoundTrip, 'stream me');
  assert.equal(r.errors.cbcBadPadding, 'bad decrypt');
});

test('hex text of an encoded handle used as an HMAC key = hex text of the real key', () => {
  assert.equal(r.hmacHexText, hmacHex(real('ENCRYPTION_KEY_HEX').toString('hex'), 'hello'));
});

test('HKDF returns a deterministic handle; the derived key works under the real derivation', () => {
  assert.match(r.hkdfHandle, /^dk1:[0-9a-f]{16}\.+$/);
  assert.equal(r.hkdfHandle.length, 32);
  assert.equal(r.hkdfAsyncSame, true);
  const k = Buffer.from(crypto.hkdfSync('sha256', real('AUTH_SECRET'), 'salt', 'enc', 32));
  assert.equal(gcmDecrypt(k, Buffer.from(r.hkdfThenGcm, 'base64')), 'derived');
  assert.match(r.errors.hkdfTooShort, /too short to carry a handle/);
});

test('PBKDF2 (node and WebCrypto) returns handles that work under the real derivation', () => {
  assert.equal(r.pbkdf2ThenHmac, hmacHex(crypto.pbkdf2Sync(real('SESSION_PASSWORD'), 'salt', 1000, 32, 'sha256'), 'hello'));
  assert.equal(r.subtlePbkdf2Bits, hmacHex(crypto.pbkdf2Sync(real('SESSION_PASSWORD'), 'salt', 1, 32, 'sha1'), 'hello'));
});

test('WebCrypto HMAC sign/verify/export with a decoy CryptoKey', () => {
  assert.equal(r.subtleHmac.sig, hmacHex(real('COOKIE_SECRET'), 'hello'));
  assert.equal(r.subtleHmac.ok, true);
  assert.equal(r.subtleHmac.bad, false);
  assert.equal(r.subtleHmac.instance, true);
  assert.match(Buffer.from(r.subtleHmac.jwk, 'base64url').toString(), /^dk1:NOT-A-SECRET/);
});

test('WebCrypto HKDF deriveKey -> AES-GCM decrypts under the real derived key', () => {
  const k = Buffer.from(crypto.hkdfSync('sha256', real('AUTH_SECRET'), 's', 'session', 32));
  assert.equal(gcmDecrypt(k, Buffer.from(r.subtleHkdfDeriveKey.ct, 'base64'), 'aad'), '{"user":"alice"}');
  assert.equal(r.subtleHkdfDeriveKey.back, '{"user":"alice"}');
});

test('WebCrypto AES-CBC with a hex-encoded handle decrypts under the real key', () => {
  const d = crypto.createDecipheriv('aes-256-cbc', real('ENCRYPTION_KEY_HEX'), iv16);
  assert.equal(Buffer.concat([d.update(Buffer.from(r.subtleCbc, 'base64')), d.final()]).toString(), 'webcrypto cbc');
});

test('fail closed: unsupported algorithms refuse instead of using the handle text', () => {
  for (const k of ['scrypt', 'chacha', 'aesKw']) assert.match(r.errors[k], /not supported with a doppelkey handle yet/, k);
  assert.match(r.errors.md5, /hash "md5" is not supported with a doppelkey handle/);
});

test('policy refusal names the command to run', () => {
  assert.equal(r.errors.policy, 'doppelkey: hmac is not allowed for AUTH_SECRET. Run "doppelkey policy AUTH_SECRET --allow hmac".');
});

test('non-handle keys are untouched', () => {
  assert.equal(r.plainKeyUntouched, hmacHex('not-a-handle', 'hello'));
});
