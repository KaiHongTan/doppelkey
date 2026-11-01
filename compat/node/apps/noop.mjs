// No handles anywhere: the shim must not change any result, and must never start its worker.
import crypto, { createHmac, createCipheriv, hkdfSync, pbkdf2Sync, createSecretKey } from 'node:crypto';
import { attempt, finish, results } from './_finish.mjs';

const key = Buffer.alloc(32, 3), iv = Buffer.alloc(12, 1);
await attempt('hmac', () => createHmac('sha256', 'plain-key').update('hello').digest('hex'));
await attempt('hmacKeyObject', () => createHmac('sha256', createSecretKey(key)).update('hello').digest('hex'));
await attempt('exportKeyObject', () => createSecretKey(key).export().toString('hex'));
await attempt('gcm', () => { const c = createCipheriv('aes-256-gcm', key, iv); return Buffer.concat([c.update('x'), c.final(), c.getAuthTag()]).toString('hex'); });
await attempt('hkdf', () => Buffer.from(hkdfSync('sha256', key, 's', 'i', 32)).toString('hex'));
await attempt('pbkdf2', () => pbkdf2Sync('pw', 's', 10, 32, 'sha256').toString('hex'));
await attempt('scrypt', () => crypto.scryptSync('pw', 's', 16).toString('hex'));
await attempt('subtle', async () => {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, true, ['sign']);
  return { sig: Buffer.from(await crypto.subtle.sign('HMAC', k, Buffer.from('hello'))).toString('hex'), jwk: (await crypto.subtle.exportKey('jwk', k)).k };
});
const state = globalThis[Symbol.for('doppelkey.shim')];
results.shim = state ? { loaded: true, ...state.stats() } : { loaded: false };
finish();
