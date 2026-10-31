// node:crypto and WebCrypto surface beyond HMAC: streaming, ciphers, derivation, key objects,
// encoded handles, and fail-closed refusals.
import crypto, { createHmac, createCipheriv, createDecipheriv, createSecretKey, hkdf, hkdfSync, pbkdf2Sync, scryptSync } from 'node:crypto';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { attempt, finish, results } from './_finish.mjs';

const env = process.env;
const iv12 = Buffer.alloc(12, 7), iv16 = Buffer.alloc(16, 9);

// Streaming HMAC: .write/.end and .pipe
await attempt('hmacWriteEnd', () => { const h = createHmac('sha256', env.JWT_SECRET); h.write('hel'); h.end('lo'); return h.read().toString('hex'); });
await attempt('hmacPipe', async () => { const h = createHmac('sha256', env.JWT_SECRET); const chunks = []; h.on('data', (c) => chunks.push(c)); await pipeline(Readable.from(['he', 'll', 'o']), h); return Buffer.concat(chunks).toString('hex'); });
await attempt('hmacSecondDigest', () => { const h = createHmac('sha256', env.JWT_SECRET).update('x'); h.digest(); return h.digest('hex'); });
await attempt('hmacBufferKey', () => createHmac('sha512', Buffer.from(env.JWT_SECRET)).update('hello').digest('base64'));
await attempt('hmacKeyObject', () => createHmac('sha256', createSecretKey(Buffer.from(env.JWT_SECRET))).update('hello').digest('hex'));
await attempt('keyObjectExport', () => createSecretKey(env.JWT_SECRET, 'utf8').export().toString());
await attempt('keyObjectSize', () => createSecretKey(Buffer.from(env.JWT_SECRET)).symmetricKeySize);

// AES-256-GCM with a 32-byte compact handle used directly as the key
await attempt('gcm', () => {
  const c = createCipheriv('aes-256-gcm', env.ENCRYPTION_KEY, iv12); c.setAAD(Buffer.from('header'));
  const ct = Buffer.concat([c.update('field-level secret', 'utf8'), c.final()]);
  return { ct: ct.toString('base64'), tag: c.getAuthTag().toString('base64') };
});
await attempt('gcmRoundTrip', () => {
  const d = createDecipheriv('aes-256-gcm', env.ENCRYPTION_KEY, iv12); d.setAAD(Buffer.from('header')); d.setAuthTag(Buffer.from(results.gcm.tag, 'base64'));
  return d.update(results.gcm.ct, 'base64', 'utf8') + d.final('utf8');
});
await attempt('gcmTampered', () => {
  const d = createDecipheriv('aes-256-gcm', env.ENCRYPTION_KEY, iv12); d.setAAD(Buffer.from('header')); d.setAuthTag(Buffer.alloc(16));
  return d.update(results.gcm.ct, 'base64', 'utf8') + d.final('utf8');
});
await attempt('gcmWrongKeyLength', () => createCipheriv('aes-128-gcm', env.ENCRYPTION_KEY, iv12));

// AES-256-CBC with a hex-encoded handle the app decodes itself, piped as a stream
await attempt('cbcHex', async () => {
  const c = createCipheriv('aes-256-cbc', Buffer.from(env.ENCRYPTION_KEY_HEX, 'hex'), iv16); const chunks = [];
  c.on('data', (x) => chunks.push(x)); await pipeline(Readable.from([Buffer.from('stream '), Buffer.from('me')]), c);
  return Buffer.concat(chunks).toString('base64');
});
await attempt('cbcRoundTrip', () => { const d = createDecipheriv('aes-256-cbc', Buffer.from(env.ENCRYPTION_KEY_HEX, 'hex'), iv16); return Buffer.concat([d.update(Buffer.from(results.cbcHex, 'base64')), d.final()]).toString(); });
await attempt('cbcBadPadding', () => { const d = createDecipheriv('aes-256-cbc', Buffer.from(env.ENCRYPTION_KEY_HEX, 'hex'), iv16); d.update(Buffer.alloc(16)); return d.final(); });
// The hex text itself used as an HMAC key (key_encoding: hex)
await attempt('hmacHexText', () => createHmac('sha256', env.ENCRYPTION_KEY_HEX).update('hello').digest('hex'));

// HKDF -> handle -> AES-GCM; async hkdf; PBKDF2 -> handle -> HMAC
await attempt('hkdfHandle', () => Buffer.from(hkdfSync('sha256', env.AUTH_SECRET, 'salt', 'enc', 32)).toString('latin1'));
await attempt('hkdfThenGcm', () => {
  const k = Buffer.from(hkdfSync('sha256', env.AUTH_SECRET, 'salt', 'enc', 32));
  const c = createCipheriv('aes-256-gcm', k, iv12); return Buffer.concat([c.update('derived'), c.final(), c.getAuthTag()]).toString('base64');
});
await attempt('hkdfAsyncSame', () => new Promise((res, rej) => hkdf('sha256', env.AUTH_SECRET, 'salt', 'enc', 32, (e, k) => (e ? rej(e) : res(Buffer.from(k).toString('latin1') === results.hkdfHandle)))));
await attempt('hkdfTooShort', () => hkdfSync('sha256', env.AUTH_SECRET, '', 'x', 16));
await attempt('pbkdf2ThenHmac', () => createHmac('sha256', pbkdf2Sync(env.SESSION_PASSWORD, 'salt', 1000, 32, 'sha256')).update('hello').digest('hex'));

// WebCrypto
const subtle = crypto.webcrypto.subtle;
const te = new TextEncoder();
await attempt('subtleHmac', async () => {
  const k = await subtle.importKey('raw', te.encode(env.COOKIE_SECRET), { name: 'HMAC', hash: 'SHA-256' }, true, ['sign', 'verify']);
  const sig = Buffer.from(await subtle.sign('HMAC', k, te.encode('hello')));
  return { sig: sig.toString('hex'), ok: await subtle.verify('HMAC', k, sig, te.encode('hello')), bad: await subtle.verify('HMAC', k, Buffer.alloc(32), te.encode('hello')),
    instance: k instanceof CryptoKey, jwk: (await subtle.exportKey('jwk', k)).k };
});
await attempt('subtleHkdfDeriveKey', async () => {
  const base = await subtle.importKey('raw', te.encode(env.AUTH_SECRET), 'HKDF', false, ['deriveKey']);
  const aes = await subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: te.encode('s'), info: te.encode('session') }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const ct = Buffer.from(await subtle.encrypt({ name: 'AES-GCM', iv: iv12, additionalData: te.encode('aad') }, aes, te.encode('{"user":"alice"}')));
  const back = new TextDecoder().decode(await subtle.decrypt({ name: 'AES-GCM', iv: iv12, additionalData: te.encode('aad') }, aes, ct));
  return { ct: ct.toString('base64'), back };
});
await attempt('subtlePbkdf2Bits', async () => {
  const base = await subtle.importKey('raw', te.encode(env.SESSION_PASSWORD), 'PBKDF2', false, ['deriveBits']);
  const bits = Buffer.from(await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-1', salt: te.encode('salt'), iterations: 1 }, base, 256));
  return createHmac('sha256', bits).update('hello').digest('hex');
});
await attempt('subtleCbc', async () => {
  const k = await subtle.importKey('raw', Buffer.from(env.ENCRYPTION_KEY_HEX, 'hex'), 'AES-CBC', false, ['encrypt']);
  return Buffer.from(await subtle.encrypt({ name: 'AES-CBC', iv: iv16 }, k, te.encode('webcrypto cbc'))).toString('base64');
});

// Fail closed: refuse instead of computing with the handle text
await attempt('scrypt', () => scryptSync(env.JWT_SECRET, 'salt', 32));
await attempt('chacha', () => createCipheriv('chacha20-poly1305', env.ENCRYPTION_KEY, iv12, { authTagLength: 16 }));
await attempt('md5', () => createHmac('md5', env.JWT_SECRET).update('x').digest());
await attempt('aesKw', () => subtle.importKey('raw', Buffer.from(env.ENCRYPTION_KEY), 'AES-KW', false, ['wrapKey']));
await attempt('policy', () => createHmac('sha256', env.AUTH_SECRET).update('x').digest());
await attempt('plainKeyUntouched', () => createHmac('sha256', 'not-a-handle').update('hello').digest('hex'));
finish();
