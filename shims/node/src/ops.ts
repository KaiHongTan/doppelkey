// Typed wrappers over keeper ops (docs/protocol.md). Every function takes a KeyRef and
// returns bytes: a digest, ciphertext/plaintext, or the bytes of a new handle.
import { KeyRef, refFields } from './handle';
import { call, DoppelkeyError } from './keeper';

const HASHES = new Set(['sha1', 'sha256', 'sha384', 'sha512']);

/** "SHA-256", "sha256", "RSA-SHA256", {name:"SHA-256"} -> "sha256". */
export function normHash(h: unknown): string {
  const name = typeof h === 'string' ? h : h && typeof h === 'object' && 'name' in h ? String((h as any).name) : '';
  const n = name.toLowerCase().replace(/^rsa-/, '').replace('-', '');
  if (!HASHES.has(n)) throw new DoppelkeyError('bad_request', `hash "${name}" is not supported with a doppelkey handle (supported: SHA-1, SHA-256, SHA-384, SHA-512)`);
  return n;
}

const b64 = (b: Buffer | Uint8Array) => Buffer.from(b.buffer, b.byteOffset, b.byteLength).toString('base64');

function handleBytes(r: any, length: number): Buffer {
  const out = Buffer.from(String(r.handle), 'latin1');
  if (out.length !== length) throw new DoppelkeyError('bad_reply', `keeper returned a ${out.length}-byte handle, expected ${length}`, 'doppelkey doctor');
  return out;
}

export function hmac(ref: KeyRef, alg: string, data: Buffer): Buffer {
  const r = call('hmac', { ...refFields(ref), alg, data: b64(data) });
  // The keeper answers with a handle when the output is itself a key (SigV4 intermediates).
  return r.handle !== undefined ? Buffer.from(r.handle, 'latin1') : Buffer.from(r.digest, 'base64');
}

export function hkdf(ref: KeyRef, hash: string, salt: Buffer, info: Buffer, length: number): Buffer {
  return handleBytes(call('hkdf', { ...refFields(ref), hash, salt: b64(salt), info: b64(info), length }), length);
}

export function pbkdf2(ref: KeyRef, hash: string, salt: Buffer, iterations: number, length: number): Buffer {
  return handleBytes(call('pbkdf2', { ...refFields(ref), hash, salt: b64(salt), iterations, length }), length);
}

export function hashDerive(ref: KeyRef, hash: string, prefixData: Buffer, suffixData: Buffer, length: number): Buffer {
  return handleBytes(call('hash_derive', { ...refFields(ref), hash, prefix_data: b64(prefixData), suffix_data: b64(suffixData), length }), length);
}

export interface AesArgs { mode: 'encrypt' | 'decrypt'; iv: Buffer; data: Buffer; aad?: Buffer; keyBits?: number; padding?: boolean }

export function aesGcm(ref: KeyRef, a: AesArgs): Buffer {
  const p: Record<string, unknown> = { ...refFields(ref), mode: a.mode, iv: b64(a.iv), data: b64(a.data) };
  if (a.aad && a.aad.length) p.aad = b64(a.aad);
  if (a.keyBits) p.key_bits = a.keyBits;
  return Buffer.from(call('aes_gcm', p).out, 'base64');
}

export function aesCbc(ref: KeyRef, a: AesArgs): Buffer {
  const p: Record<string, unknown> = { ...refFields(ref), mode: a.mode, iv: b64(a.iv), data: b64(a.data) };
  if (a.padding === false) p.padding = false;
  if (a.keyBits) p.key_bits = a.keyBits;
  return Buffer.from(call('aes_cbc', p).out, 'base64');
}

/** Thrown when an app uses a handle with an algorithm the keeper can't perform. Fail closed. */
export function unsupported(what: string): never {
  throw new DoppelkeyError('unsupported', `${what} is not supported with a doppelkey handle yet, so the call was refused instead of computing with the handle text`, 'If you need it, open an issue: https://github.com/KaiHongTan/dopplekey/issues');
}
