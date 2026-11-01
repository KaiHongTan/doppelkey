// Hashes whose input contains a handle. Two cases:
//  - an RFC 7638 thumbprint of an "oct" JWK whose `k` is a handle (Auth.js and jose compute the
//    JWT `kid` this way): the keeper computes the real thumbprint, a public identifier;
//  - any other input containing a handle (e.g. salt + secret key derivation): the keeper
//    computes the digest over the real key and returns it as a new handle.
// Ordinary hashing stays native; the check per update() is one substring search.
import crypto from 'node:crypto';
import nodeModule from 'node:module';
import { asBuffer, KeyRef, parseKeyText, refOfKeyMaterial } from './handle';
import { call } from './keeper';
import * as ops from './ops';

const THUMB_RE = /^\{"k":"([A-Za-z0-9_-]+)","kty":"oct"\}$/;
const HANDLE_IN_RE = /dk1:(?:NOT-A-SECRET-load-doppelkey-shim:[0-9a-f]{12}:|[0-9a-f]{12})[0-9a-f]{4}(?:\.*dk1:(?:NOT-A-SECRET-load-doppelkey-shim:[0-9a-f]{12}:|[0-9a-f]{12})[0-9a-f]{4})*\.*/;
const OUT_LEN: Record<string, number> = { sha1: 20, sha256: 32, sha384: 48, sha512: 64 };
const MAX_TRACKED = 4096; // bytes of input remembered per hash, in case a handle shows up later

// "dk1:" in raw input, or thumbprint JSON (where the handle appears base64url-encoded).
const mayMatter = (b: Buffer) => b.indexOf('dk1:') !== -1 || b.indexOf('"kty":"oct"') !== -1;

/** The keeper's answer for a hash over `input` that involves a handle, or null if none does. */
export function remoteDigest(alg: string, input: Buffer): Buffer | null {
  if (!mayMatter(input)) return null;
  const text = input.toString('latin1');
  const t = input.length < 1024 ? THUMB_RE.exec(text) : null;
  if (t) {
    const ref = refOfKeyMaterial(Buffer.from(t[1], 'base64url'));
    if (ref && !ref.prefix && !ref.keyEncoding) {
      const hash = ops.normHash(alg);
      if (hash === 'sha1') ops.unsupported('a SHA-1 JWK thumbprint');
      return Buffer.from(call('jwk_thumbprint', { handle: ref.handle, hash }).digest, 'base64');
    }
  }
  const m = HANDLE_IN_RE.exec(text);
  if (!m) return null;
  const p = parseKeyText(m[0]);
  if (!p) return null;
  const hash = ops.normHash(alg);
  const ref: KeyRef = { handle: p.handle, length: m[0].length };
  return ops.hashDerive(ref, hash, input.subarray(0, m.index), input.subarray(m.index + m[0].length), OUT_LEN[hash]);
}

const ALG = Symbol('doppelkey.alg');
const SEEN = Symbol('doppelkey.seen');
const SEEN_LEN = Symbol('doppelkey.seenLen');
const OPTS = Symbol('doppelkey.opts');
const REMOTE = Symbol('doppelkey.remote');

function toBytes(data: unknown, enc?: BufferEncoding): Buffer | null {
  if (typeof data === 'string') return Buffer.from(data, enc || 'utf8');
  return asBuffer(data);
}

export function installHash() {
  const c = crypto as any;
  const realCreateHash = c.createHash;
  const proto = Object.getPrototypeOf(realCreateHash('sha256'));
  const realUpdate = proto.update;
  const realDigest = proto.digest;

  c.createHash = function createHash(this: unknown, algorithm: string, options?: unknown) {
    const h = options === undefined ? realCreateHash(algorithm) : realCreateHash(algorithm, options);
    h[ALG] = algorithm;
    if (options !== undefined) h[OPTS] = options;
    return h;
  };
  // Fast path: one substring search per chunk. Small inputs are remembered by reference (no
  // copy) in case a handle shows up in a later chunk, e.g. update(salt).update(secret).
  proto.update = function update(this: any, data: unknown, enc?: BufferEncoding) {
    const remote = this[REMOTE];
    if (remote !== undefined) {
      const b = toBytes(data, enc);
      if (b) remote.push(Buffer.from(b));
      return this;
    }
    if (this[ALG] === undefined) return enc === undefined ? realUpdate.call(this, data) : realUpdate.call(this, data, enc);
    let hit = false;
    let len = 0;
    if (typeof data === 'string') {
      hit = data.includes('dk1:') || (data.length < 1024 && data.includes('"kty":"oct"'));
      len = data.length;
    } else {
      const b = asBuffer(data);
      if (b) {
        hit = b.indexOf('dk1:') !== -1 || (b.length < 1024 && b.indexOf('"kty":"oct"') !== -1);
        len = b.length;
      }
    }
    let seen = this[SEEN];
    if (seen !== null) {
      const total = (this[SEEN_LEN] ?? 0) + len;
      if (total > MAX_TRACKED) {
        seen = this[SEEN] = null;
      } else {
        if (seen === undefined) seen = this[SEEN] = [];
        seen.push(data, enc);
        this[SEEN_LEN] = total;
      }
    }
    if (hit) {
      if (seen === null) ops.unsupported('hashing a doppelkey handle inside more than 4 KiB of data');
      const chunks: Buffer[] = [];
      for (let i = 0; i < seen.length; i += 2) chunks.push(Buffer.from(toBytes(seen[i], seen[i + 1])!));
      this[REMOTE] = chunks;
      return this;
    }
    return enc === undefined ? realUpdate.call(this, data) : realUpdate.call(this, data, enc);
  };
  proto.digest = function digest(this: any, enc?: BufferEncoding) {
    if (!this[REMOTE]) return realDigest.apply(this, arguments);
    const input = Buffer.concat(this[REMOTE]);
    const alg = this[ALG], options = this[OPTS];
    const out = remoteDigest(String(alg), input);
    if (!out) {
      // Matched the cheap check but involves no handle (e.g. the thumbprint of an ordinary key):
      // hash the whole input natively in a fresh hash.
      this[REMOTE] = [];
      return realDigest.apply(realUpdate.call(options === undefined ? realCreateHash(alg) : realCreateHash(alg, options), input), arguments);
    }
    this[REMOTE] = [];
    return enc && enc !== ('buffer' as BufferEncoding) ? out.toString(enc) : out;
  };

  if (typeof c.hash === 'function') {
    const realHash = c.hash;
    c.hash = function hash(this: unknown, algorithm: string, data: unknown, outputEncoding?: string) {
      const b = typeof data === 'string' ? Buffer.from(data, 'utf8') : asBuffer(data);
      const out = b && mayMatter(b) ? remoteDigest(algorithm, b) : null;
      if (!out) return realHash.apply(this, arguments);
      const encOut = outputEncoding === undefined ? 'hex' : outputEncoding;
      return encOut === 'buffer' ? out : out.toString(encOut as BufferEncoding);
    };
  }

  // WebCrypto digest
  const subtle: any = (globalThis as any).crypto?.subtle;
  if (subtle) {
    const target = Object.prototype.hasOwnProperty.call(subtle, 'digest') ? subtle : Object.getPrototypeOf(subtle);
    const realSubtleDigest = target.digest;
    target.digest = async function digest(this: any, algorithm: any, data: unknown) {
      const b = asBuffer(data);
      const out = b && mayMatter(b) ? remoteDigest(typeof algorithm === 'string' ? algorithm : algorithm?.name, b) : null;
      if (!out) return realSubtleDigest.apply(this, arguments);
      return out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength);
    };
  }
  nodeModule.syncBuiltinESMExports();
}
