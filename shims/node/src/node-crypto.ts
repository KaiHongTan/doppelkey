// Patches for node:crypto. Each wrapper checks its key argument for a handle and, if there is
// none, calls the original function with the original arguments: non-handle calls are untouched.
import crypto from 'node:crypto';
import nodeModule from 'node:module';
import { Transform, TransformCallback, TransformOptions } from 'node:stream';
import { KeyRef, asBuffer, materialOf, refOfKeyMaterial } from './handle';
import { DoppelkeyError } from './keeper';
import * as ops from './ops';
import { decoys, refOf } from './refs';

function bytes(x: unknown, encoding: BufferEncoding = 'utf8', what = 'data'): Buffer {
  if (typeof x === 'string') return Buffer.from(x, encoding);
  const b = asBuffer(x);
  if (!b) throw new TypeError(`The "${what}" argument must be of type string or an instance of Buffer, TypedArray, DataView, or ArrayBuffer.`);
  return Buffer.from(b); // copy: the caller may reuse its buffer
}
const nodeErr = (code: string | undefined, message: string, Kind: ErrorConstructor = Error) =>
  Object.assign(new Kind(message), code ? { code } : {});
const asOutput = (out: Buffer, enc?: string) => (enc && enc !== 'buffer' ? out.toString(enc as BufferEncoding) : out);

// ---------- HMAC (also a Transform stream, like crypto.Hmac) ----------
class RemoteHmac extends Transform {
  #chunks: Buffer[] = [];
  #done = false;
  constructor(private readonly alg: string, private readonly ref: KeyRef, options?: TransformOptions) {
    super(options);
  }
  update(data: unknown, inputEncoding?: BufferEncoding): this {
    if (this.#done) throw nodeErr('ERR_CRYPTO_HASH_FINALIZED', 'Digest already called');
    this.#chunks.push(bytes(data, inputEncoding));
    return this;
  }
  digest(outputEncoding?: string): Buffer | string {
    if (this.#done) return asOutput(Buffer.alloc(0), outputEncoding); // same as node's Hmac
    this.#done = true;
    return asOutput(ops.hmac(this.ref, this.alg, Buffer.concat(this.#chunks)), outputEncoding);
  }
  _transform(chunk: any, enc: BufferEncoding, cb: TransformCallback) {
    try { this.update(chunk, enc); cb(); } catch (e) { cb(e as Error); }
  }
  _flush(cb: TransformCallback) {
    try { this.push(this.digest()); cb(); } catch (e) { cb(e as Error); }
  }
}

// ---------- AES-GCM / AES-CBC ciphers (also Transform streams) ----------
const AES_RE = /^(?:id-)?aes-?(128|192|256)-(gcm|cbc)$/i;
const AES_CBC_ALIAS = /^aes(128|192|256)$/i;
const AUTH_FAIL = 'Unsupported state or unable to authenticate data';

class RemoteCipher extends Transform {
  #chunks: Buffer[] = [];
  #done = false;
  #aad?: Buffer;
  #tag?: Buffer;
  #padding = true;
  constructor(
    private readonly mode: 'encrypt' | 'decrypt',
    private readonly kind: 'gcm' | 'cbc',
    private readonly bits: number,
    private readonly ref: KeyRef,
    private readonly iv: Buffer,
    options?: TransformOptions & { authTagLength?: number },
  ) {
    super(options);
    if (!ref.keyEncoding && ref.length * 8 !== bits) throw nodeErr('ERR_CRYPTO_INVALID_KEYLEN', 'Invalid key length', RangeError);
    if (kind === 'cbc' && iv.length !== 16) throw nodeErr('ERR_CRYPTO_INVALID_IV', 'Invalid initialization vector', TypeError);
    if (kind === 'gcm' && iv.length !== 12) ops.unsupported(`AES-GCM with a ${iv.length}-byte IV (only 12-byte IVs)`);
    if (kind === 'gcm' && options?.authTagLength !== undefined && options.authTagLength !== 16)
      ops.unsupported(`AES-GCM with a ${options.authTagLength}-byte tag (only 16-byte tags)`);
  }
  // Like OpenSSL, update() returns output as soon as it is determined, and final() the rest.
  // Libraries rely on this: jose v4 discards final() for GCM. The output for a prefix of the
  // input is a prefix of the full output (GCM is counter mode; CBC chains block by block), so
  // update() asks the keeper for the output over everything so far and returns the new bytes.
  update(data: unknown, inputEncoding?: BufferEncoding, outputEncoding?: string): Buffer | string {
    if (this.#done) throw nodeErr('ERR_CRYPTO_INVALID_STATE', 'Invalid state for operation update');
    this.#chunks.push(bytes(data, inputEncoding));
    return asOutput(this.#emit(this.#partial()), outputEncoding);
  }
  final(outputEncoding?: string): Buffer | string {
    if (this.#done) throw nodeErr('ERR_CRYPTO_INVALID_STATE', 'Invalid state');
    this.#done = true;
    const data = Buffer.concat(this.#chunks);
    const args = { mode: this.mode, iv: this.iv, keyBits: this.#keyBits() };
    let out: Buffer;
    try {
      if (this.kind === 'gcm') {
        if (this.mode === 'encrypt') {
          const r = ops.aesGcm(this.ref, { ...args, data, aad: this.#aad });
          out = r.subarray(0, r.length - 16);
          this.#tag = r.subarray(r.length - 16);
        } else {
          if (!this.#tag) throw new Error(AUTH_FAIL);
          out = ops.aesGcm(this.ref, { ...args, data: Buffer.concat([data, this.#tag]), aad: this.#aad });
        }
      } else {
        out = ops.aesCbc(this.ref, { ...args, data, padding: this.#padding });
      }
    } catch (e) {
      if ((e as DoppelkeyError).code === 'crypto_error') {
        if (this.kind === 'gcm') throw new Error(AUTH_FAIL);
        throw nodeErr('ERR_OSSL_BAD_DECRYPT', 'bad decrypt');
      }
      throw e;
    }
    return asOutput(this.#emit(out), outputEncoding);
  }
  #emitted = 0;
  /** Return the part of `full` not yet handed out. */
  #emit(full: Buffer): Buffer {
    const out = full.subarray(this.#emitted);
    this.#emitted = Math.max(this.#emitted, full.length);
    return Buffer.from(out);
  }
  #keyBits() { return this.ref.keyEncoding ? undefined : this.bits; }
  /** Output determined by the input so far (no tag check, no final padding). */
  #partial(): Buffer {
    const data = Buffer.concat(this.#chunks);
    if (this.kind === 'gcm') {
      if (!data.length) return Buffer.alloc(0);
      // Counter-mode keystream XOR: "encrypting" ciphertext yields the plaintext, so decrypt's
      // update() also uses encrypt. The tag is still checked in final(), as in OpenSSL.
      const r = ops.aesGcm(this.ref, { mode: 'encrypt', iv: this.iv, data, keyBits: this.#keyBits() });
      return r.subarray(0, r.length - 16);
    }
    let n = data.length - (data.length % 16);
    if (this.mode === 'decrypt' && this.#padding && n === data.length) n -= 16; // hold back the padded block
    if (n <= 0) return Buffer.alloc(0);
    return ops.aesCbc(this.ref, { mode: this.mode, iv: this.iv, data: data.subarray(0, n), padding: false, keyBits: this.#keyBits() });
  }
  setAAD(aad: unknown): this {
    if (this.kind !== 'gcm' || this.#done) throw nodeErr('ERR_CRYPTO_INVALID_STATE', 'Invalid state for operation setAAD');
    this.#aad = bytes(aad, 'utf8', 'buffer');
    return this;
  }
  getAuthTag(): Buffer {
    if (this.kind !== 'gcm' || this.mode !== 'encrypt' || !this.#tag)
      throw nodeErr('ERR_CRYPTO_INVALID_STATE', 'Invalid state for operation getAuthTag');
    return Buffer.from(this.#tag);
  }
  setAuthTag(tag: unknown): this {
    if (this.kind !== 'gcm' || this.mode !== 'decrypt' || this.#done)
      throw nodeErr('ERR_CRYPTO_INVALID_STATE', 'Invalid state for operation setAuthTag');
    const t = bytes(tag, 'utf8', 'buffer');
    if (t.length !== 16) ops.unsupported(`AES-GCM with a ${t.length}-byte tag (only 16-byte tags)`);
    this.#tag = t;
    return this;
  }
  setAutoPadding(autoPadding = true): this {
    this.#padding = !!autoPadding;
    return this;
  }
  _transform(chunk: any, enc: BufferEncoding, cb: TransformCallback) {
    try { const out = this.update(chunk, enc) as Buffer; if (out.length) this.push(out); cb(); } catch (e) { cb(e as Error); }
  }
  _flush(cb: TransformCallback) {
    try { const out = this.final() as Buffer; if (out.length) this.push(out); cb(); } catch (e) { cb(e as Error); }
  }
}

const toArrayBuffer = (b: Buffer): ArrayBuffer => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;

export function installNodeCrypto() {
  const c = crypto as any;
  const real = {
    createHmac: c.createHmac,
    createSecretKey: c.createSecretKey,
    hkdf: c.hkdf,
    hkdfSync: c.hkdfSync,
    pbkdf2: c.pbkdf2,
    pbkdf2Sync: c.pbkdf2Sync,
    scrypt: c.scrypt,
    scryptSync: c.scryptSync,
    createCipheriv: c.createCipheriv,
    createDecipheriv: c.createDecipheriv,
    keyFrom: (crypto.KeyObject as any).from,
  };

  c.createHmac = function createHmac(this: unknown, alg: string, key: unknown, options?: TransformOptions) {
    const ref = refOf(key);
    if (!ref) return real.createHmac.apply(this, arguments);
    return new RemoteHmac(ops.normHash(alg), ref, options);
  };

  const decoyKeyObject = (ref: KeyRef) => {
    const ko = real.createSecretKey(crypto.randomBytes(ref.length)); // random bytes; reveal nothing
    decoys.set(ko, ref);
    return ko;
  };
  c.createSecretKey = function createSecretKey(this: unknown, key: unknown, encoding?: BufferEncoding) {
    const ref = refOfKeyMaterial(key, encoding || 'utf8');
    if (!ref) return real.createSecretKey.apply(this, arguments);
    return decoyKeyObject(ref);
  };
  // Exporting a decoy gives back the handle (what the app put in), never the random decoy bytes.
  // Node defines export() on the SecretKeyObject subclass, so patch that prototype.
  const secretProto = Object.getPrototypeOf(real.createSecretKey(Buffer.alloc(1)));
  const realExport = secretProto.export;
  secretProto.export = function exportKey(this: crypto.KeyObject, options?: any) {
    const ref = decoys.get(this);
    if (!ref) return realExport.apply(this, arguments as any);
    const m = materialOf(ref);
    return options && options.format === 'jwk' ? { kty: 'oct', k: m.toString('base64url') } : m;
  } as any;
  if (typeof real.keyFrom === 'function') {
    (crypto.KeyObject as any).from = function from(this: unknown, key: object) {
      const ref = decoys.get(key);
      if (!ref) return real.keyFrom.apply(this, arguments);
      return decoyKeyObject(ref);
    };
  }

  // HKDF from a handle returns the bytes of a new handle; the derived key stays in the keeper.
  const hkdfRemote = (ref: KeyRef, digest: string, salt: unknown, info: unknown, keylen: number) =>
    toArrayBuffer(ops.hkdf(ref, ops.normHash(digest), bytes(salt, 'utf8', 'salt'), bytes(info, 'utf8', 'info'), keylen));
  c.hkdfSync = function hkdfSync(this: unknown, digest: string, ikm: unknown, salt: unknown, info: unknown, keylen: number) {
    const ref = refOf(ikm);
    if (!ref) return real.hkdfSync.apply(this, arguments);
    return hkdfRemote(ref, digest, salt, info, keylen);
  };
  c.hkdf = function hkdf(this: unknown, digest: string, ikm: unknown, salt: unknown, info: unknown, keylen: number, cb: Function) {
    const ref = refOf(ikm);
    if (!ref) return real.hkdf.apply(this, arguments);
    if (typeof cb !== 'function') throw nodeErr('ERR_INVALID_ARG_TYPE', 'The "callback" argument must be of type function', TypeError);
    let out: ArrayBuffer | undefined, err: unknown = null;
    try { out = hkdfRemote(ref, digest, salt, info, keylen); } catch (e) { err = e; }
    process.nextTick(() => cb(err, out));
  };

  c.pbkdf2Sync = function pbkdf2Sync(this: unknown, password: unknown, salt: unknown, iterations: number, keylen: number, digest: string) {
    const ref = refOf(password);
    if (!ref) return real.pbkdf2Sync.apply(this, arguments);
    return ops.pbkdf2(ref, ops.normHash(digest), bytes(salt, 'utf8', 'salt'), iterations, keylen);
  };
  c.pbkdf2 = function pbkdf2(this: unknown, password: unknown, salt: unknown, iterations: number, keylen: number, digest: string, cb: Function) {
    const ref = refOf(password);
    if (!ref) return real.pbkdf2.apply(this, arguments);
    if (typeof cb !== 'function') throw nodeErr('ERR_INVALID_ARG_TYPE', 'The "callback" argument must be of type function', TypeError);
    let out: Buffer | undefined, err: unknown = null;
    try { out = ops.pbkdf2(ref, ops.normHash(digest), bytes(salt, 'utf8', 'salt'), iterations, keylen); } catch (e) { err = e; }
    process.nextTick(() => cb(err, out));
  };

  // scrypt over a handle: not supported yet. Refuse rather than derive from the handle text.
  c.scryptSync = function scryptSync(this: unknown, password: unknown) {
    if (refOf(password)) ops.unsupported('scrypt');
    return real.scryptSync.apply(this, arguments);
  };
  c.scrypt = function scrypt(this: unknown, password: unknown) {
    if (refOf(password)) ops.unsupported('scrypt');
    return real.scrypt.apply(this, arguments);
  };

  const cipherFactory = (mode: 'encrypt' | 'decrypt', realFn: Function) =>
    function (this: unknown, algorithm: string, key: unknown, iv: unknown, options?: any) {
      const ref = refOf(key);
      if (!ref) return realFn.apply(this, arguments);
      const m = AES_RE.exec(String(algorithm)) ?? (AES_CBC_ALIAS.test(String(algorithm)) ? [, AES_CBC_ALIAS.exec(String(algorithm))![1], 'cbc'] : null);
      if (!m) ops.unsupported(`cipher "${algorithm}"`);
      return new RemoteCipher(mode, String(m![2]).toLowerCase() as 'gcm' | 'cbc', Number(m![1]), ref, bytes(iv, 'utf8', 'iv'), options);
    };
  c.createCipheriv = cipherFactory('encrypt', real.createCipheriv);
  c.createDecipheriv = cipherFactory('decrypt', real.createDecipheriv);

  // Make `import { createHmac } from 'node:crypto'` in ESM code see the patched versions.
  nodeModule.syncBuiltinESMExports();
}
