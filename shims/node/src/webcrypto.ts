// Patches for WebCrypto (globalThis.crypto.subtle). importKey with handle bytes returns a real
// CryptoKey made from random decoy bytes (so `instanceof CryptoKey` and type checks pass); every
// method that takes a key looks the decoy up and forwards to the keeper.
import crypto from 'node:crypto';
import { asBuffer, materialOf, refOfKeyMaterial, KeyRef } from './handle';
import { DoppelkeyError } from './keeper';
import * as ops from './ops';
import { decoys } from './refs';

const SUPPORTED = new Set(['HMAC', 'AES-GCM', 'AES-CBC', 'HKDF', 'PBKDF2']);
const algName = (a: any): string => String(typeof a === 'string' ? a : a?.name ?? '').toUpperCase();
const ab = (b: Buffer): ArrayBuffer => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;
const domError = (message: string, name: string) =>
  typeof DOMException === 'function' ? new DOMException(message, name) : Object.assign(new Error(message), { name });

function bytes(x: unknown, what: string): Buffer {
  if (x === undefined || x === null) return Buffer.alloc(0);
  const b = asBuffer(x);
  if (!b) throw new TypeError(`Failed to execute: "${what}" is not a BufferSource`);
  return Buffer.from(b);
}

function aesArgs(algorithm: any, key: CryptoKey, mode: 'encrypt' | 'decrypt', data: unknown) {
  const name = algName(algorithm);
  if (name !== algName(key.algorithm)) throw domError('The requested operation is not valid for the provided key', 'InvalidAccessError');
  const iv = bytes(algorithm.iv, 'iv');
  const keyBits = (key.algorithm as AesKeyAlgorithm).length;
  return { name, iv, args: { mode, iv, data: bytes(data, 'data'), keyBits } };
}

export function installWebCrypto() {
  const subtle: any = (globalThis as any).crypto?.subtle;
  if (!subtle) return;
  // Methods live on SubtleCrypto.prototype in Node and Bun; patching there covers every instance.
  const target = Object.prototype.hasOwnProperty.call(subtle, 'importKey') ? subtle : Object.getPrototypeOf(subtle);
  const real: Record<string, Function> = {};
  for (const m of ['importKey', 'exportKey', 'sign', 'verify', 'encrypt', 'decrypt', 'deriveBits', 'deriveKey', 'wrapKey', 'unwrapKey'])
    real[m] = target[m];

  target.importKey = async function importKey(this: any, format: string, keyData: any, algorithm: any, extractable: boolean, usages: KeyUsage[]) {
    let ref: KeyRef | null = null;
    if (format === 'raw' || format === 'raw-secret') ref = refOfKeyMaterial(keyData);
    else if (format === 'jwk' && keyData && keyData.kty === 'oct' && typeof keyData.k === 'string')
      ref = refOfKeyMaterial(Buffer.from(keyData.k, 'base64url'));
    if (!ref) return real.importKey.apply(this, arguments);
    const name = algName(algorithm);
    if (!SUPPORTED.has(name)) ops.unsupported(`WebCrypto ${name}`);
    const decoyAlg = name === 'HMAC' ? { name, hash: algorithm.hash } : algorithm; // HMAC `length` would have to match decoy bits
    const decoy = await real.importKey.call(this, 'raw', crypto.randomBytes(ref.length), decoyAlg, extractable, usages);
    decoys.set(decoy, ref);
    return decoy;
  };

  target.exportKey = async function exportKey(this: any, format: string, key: CryptoKey) {
    const ref = decoys.get(key);
    if (!ref || !key.extractable) return real.exportKey.apply(this, arguments); // non-extractable: native error
    const m = materialOf(ref);
    if (format === 'raw' || format === 'raw-secret') return ab(m);
    if (format === 'jwk') {
      const a: any = key.algorithm;
      const alg = a.name === 'HMAC' ? `HS${a.hash.name.replace('SHA-', '')}` : a.name === 'AES-GCM' ? `A${a.length}GCM` : a.name === 'AES-CBC' ? `A${a.length}CBC` : undefined;
      return { kty: 'oct', k: m.toString('base64url'), ...(alg ? { alg } : {}), ext: true, key_ops: [...key.usages] };
    }
    return real.exportKey.apply(this, arguments);
  };

  const hmacOf = (key: CryptoKey, ref: KeyRef, data: unknown) => {
    if (key.algorithm.name !== 'HMAC') ops.unsupported(`WebCrypto sign/verify with ${key.algorithm.name}`);
    return ops.hmac(ref, ops.normHash((key.algorithm as HmacKeyAlgorithm).hash), bytes(data, 'data'));
  };
  target.sign = async function sign(this: any, algorithm: any, key: CryptoKey, data: unknown) {
    const ref = decoys.get(key);
    if (!ref) return real.sign.apply(this, arguments);
    return ab(hmacOf(key, ref, data));
  };
  target.verify = async function verify(this: any, algorithm: any, key: CryptoKey, signature: unknown, data: unknown) {
    const ref = decoys.get(key);
    if (!ref) return real.verify.apply(this, arguments);
    const mac = hmacOf(key, ref, data);
    const sig = bytes(signature, 'signature');
    return sig.length === mac.length && crypto.timingSafeEqual(sig, mac);
  };

  for (const mode of ['encrypt', 'decrypt'] as const) {
    target[mode] = async function (this: any, algorithm: any, key: CryptoKey, data: unknown) {
      const ref = decoys.get(key);
      if (!ref) return real[mode].apply(this, arguments);
      const { name, iv, args } = aesArgs(algorithm, key, mode, data);
      try {
        if (name === 'AES-GCM') {
          if (iv.length !== 12) ops.unsupported(`AES-GCM with a ${iv.length}-byte IV (only 12-byte IVs)`);
          if ((algorithm.tagLength ?? 128) !== 128) ops.unsupported(`AES-GCM with a ${algorithm.tagLength}-bit tag (only 128-bit tags)`);
          return ab(ops.aesGcm(ref, { ...args, aad: algorithm.additionalData ? bytes(algorithm.additionalData, 'additionalData') : undefined }));
        }
        if (name === 'AES-CBC') return ab(ops.aesCbc(ref, args));
      } catch (e) {
        if ((e as DoppelkeyError).code === 'crypto_error') throw domError('The operation failed for an operation-specific reason', 'OperationError');
        throw e;
      }
      ops.unsupported(`WebCrypto ${mode} with ${name}`);
    };
  }

  // Derivation from a handle returns the bytes of a new handle; the derived key stays in the keeper.
  const deriveRemote = (algorithm: any, ref: KeyRef, length: number): Buffer => {
    if (!Number.isInteger(length) || length <= 0 || length % 8) throw domError('length must be a positive multiple of 8', 'OperationError');
    const name = algName(algorithm);
    const hash = ops.normHash(algorithm.hash);
    if (name === 'HKDF') return ops.hkdf(ref, hash, bytes(algorithm.salt, 'salt'), bytes(algorithm.info, 'info'), length / 8);
    if (name === 'PBKDF2') return ops.pbkdf2(ref, hash, bytes(algorithm.salt, 'salt'), Number(algorithm.iterations), length / 8);
    return ops.unsupported(`WebCrypto deriveBits with ${name}`);
  };
  target.deriveBits = async function deriveBits(this: any, algorithm: any, baseKey: CryptoKey, length: number) {
    const ref = decoys.get(baseKey);
    if (!ref) return real.deriveBits.apply(this, arguments);
    return ab(deriveRemote(algorithm, ref, length));
  };
  target.deriveKey = async function deriveKey(this: any, algorithm: any, baseKey: CryptoKey, derivedKeyType: any, extractable: boolean, usages: KeyUsage[]) {
    const ref = decoys.get(baseKey);
    if (!ref) return real.deriveKey.apply(this, arguments);
    const t = algName(derivedKeyType);
    let bits: number;
    if (t === 'HMAC') bits = derivedKeyType.length ?? (/(384|512)/.test(algName(derivedKeyType.hash)) ? 1024 : 512);
    else if (t === 'AES-GCM' || t === 'AES-CBC') bits = derivedKeyType.length;
    else return ops.unsupported(`WebCrypto deriveKey to ${t}`);
    const derived = deriveRemote(algorithm, ref, bits);
    return target.importKey.call(this, 'raw', derived, derivedKeyType, extractable, usages);
  };

  target.wrapKey = async function wrapKey(this: any, format: string, key: CryptoKey, wrappingKey: CryptoKey) {
    if (decoys.has(key) || decoys.has(wrappingKey)) ops.unsupported('WebCrypto wrapKey');
    return real.wrapKey.apply(this, arguments);
  };
  target.unwrapKey = async function unwrapKey(this: any, format: string, wrapped: unknown, unwrappingKey: CryptoKey) {
    if (decoys.has(unwrappingKey)) ops.unsupported('WebCrypto unwrapKey');
    return real.unwrapKey.apply(this, arguments);
  };
}
