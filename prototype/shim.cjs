// shim.cjs — preload with `node --require ./shim.cjs app.js` (works for CJS and ESM apps).
// Env vars hold handles ("KH1:<id>...") instead of real secrets. Crypto calls made with a
// handle are forwarded to the keeper process; the real key never enters this process.
'use strict';
const crypto = require('node:crypto');
const { Worker, MessageChannel, receiveMessageOnPort } = require('node:worker_threads');
const nodeModule = require('node:module');

const SOCK = process.env.KEEPER_SOCK || '/tmp/keeper.sock';
const HANDLE_RE = /^KH1:[0-9a-f]{16}/;

// ---------- synchronous call to the keeper (worker thread + Atomics.wait) ----------
let worker, port, signal;
function startWorker() {
  const ch = new MessageChannel();
  port = ch.port1;
  signal = new Int32Array(new SharedArrayBuffer(4));
  worker = new Worker(`
    const { workerData } = require('node:worker_threads');
    const net = require('node:net');
    const { port, signal, sock } = workerData;
    let conn, buf = '', pending = null;
    function connect() {
      conn = net.connect(sock);
      conn.on('data', (c) => {
        buf += c; let i;
        while ((i = buf.indexOf('\\n')) >= 0) {
          const line = buf.slice(0, i); buf = buf.slice(i + 1);
          port.postMessage(JSON.parse(line));
          Atomics.store(signal, 0, 1); Atomics.notify(signal, 0);
        }
      });
      conn.on('error', (e) => { port.postMessage({ ok: false, error: 'keeper unreachable: ' + e.message }); Atomics.store(signal, 0, 1); Atomics.notify(signal, 0); });
    }
    connect();
    port.on('message', (req) => conn.write(JSON.stringify(req) + '\\n'));
  `, { eval: true, workerData: { port: ch.port2, signal, sock: SOCK }, transferList: [ch.port2] });
  worker.unref();
}
function callKeeper(req) {
  if (!worker) startWorker();
  Atomics.store(signal, 0, 0);
  port.postMessage(req);
  Atomics.wait(signal, 0, 0, 5000);
  const msg = receiveMessageOnPort(port);
  if (!msg) throw new Error('keeper timeout');
  if (!msg.message.ok) throw new Error('keeper: ' + msg.message.error);
  return msg.message;
}

// ---------- recognising handles ----------
const keyObjectHandles = new WeakMap();   // node KeyObject -> handle
const cryptoKeyHandles = new WeakMap();   // WebCrypto CryptoKey -> { handle, algorithm }
function toBuf(x) {
  if (typeof x === 'string') return Buffer.from(x, 'latin1');
  if (Buffer.isBuffer(x)) return x;
  if (ArrayBuffer.isView(x)) return Buffer.from(x.buffer, x.byteOffset, x.byteLength);
  if (x instanceof ArrayBuffer) return Buffer.from(x);
  return null;
}
function handleOf(key) {
  if (key && typeof key === 'object' && keyObjectHandles.has(key)) return keyObjectHandles.get(key);
  const b = toBuf(key);
  if (!b) return null;
  const s = b.toString('latin1');
  return HANDLE_RE.test(s) ? s : null;
}
const b64 = (x) => toBuf(x).toString('base64');
// A key that is a short prefix followed by a handle, e.g. AWS SigV4's "AWS4" + secret.
const PREFIXED_RE = /^([\s\S]{1,8}?)(KH1:[0-9a-f]{16}[.]*)$/;
function prefixedHandleOf(key) {
  const b = toBuf(key);
  const m = b && b.toString('latin1').match(PREFIXED_RE);
  return m ? { prefix: Buffer.from(m[1], 'latin1').toString('base64'), handle: m[2] } : null;
}

// ---------- node:crypto ----------
const realCreateHmac = crypto.createHmac;
crypto.createHmac = function createHmac(alg, key, options) {
  let handle = handleOf(key), prefix;
  if (!handle) { const p = prefixedHandleOf(key); if (p) ({ handle, prefix } = p); }
  if (!handle) return realCreateHmac.apply(this, arguments);
  const chunks = [];
  let done = false;
  const h = {
    update(data, enc) { chunks.push(typeof data === 'string' ? Buffer.from(data, enc || 'utf8') : toBuf(data)); return h; },
    digest(enc) {
      if (done) throw new Error('Digest already called');
      done = true;
      const req = { op: 'hmac', handle, alg, data: Buffer.concat(chunks).toString('base64') };
      if (prefix !== undefined) req.prefix = prefix;
      const r = callKeeper(req);
      // The keeper answers with a handle when the output is itself a key (SigV4 intermediate keys).
      const out = r.handle ? Buffer.from(r.handle, 'latin1') : Buffer.from(r.digest, 'base64');
      return enc ? out.toString(enc) : out;
    },
  };
  return h;
};
const realCreateSecretKey = crypto.createSecretKey;
crypto.createSecretKey = function createSecretKey(key, enc) {
  const handle = handleOf(typeof key === 'string' && enc ? Buffer.from(key, enc) : key);
  if (!handle) return realCreateSecretKey.apply(this, arguments);
  const ko = realCreateSecretKey(crypto.randomBytes(32)); // decoy bytes; exporting it reveals nothing
  keyObjectHandles.set(ko, handle);
  return ko;
};
// HKDF from a handle returns a handle (the derived key stays in the keeper).
function hkdfRemote(digest, ikm, salt, info, keylen) {
  const handle = handleOf(ikm);
  const r = callKeeper({ op: 'hkdf', handle, hash: digest, salt: b64(typeof salt === 'string' ? Buffer.from(salt) : salt), info: b64(typeof info === 'string' ? Buffer.from(info) : info), length: keylen });
  const out = Buffer.from(r.handle, 'latin1');
  return out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength);
}
const realHkdf = crypto.hkdf, realHkdfSync = crypto.hkdfSync;
crypto.hkdfSync = function (digest, ikm, salt, info, keylen) {
  if (!handleOf(ikm)) return realHkdfSync.apply(this, arguments);
  return hkdfRemote(digest, ikm, salt, info, keylen);
};
crypto.hkdf = function (digest, ikm, salt, info, keylen, cb) {
  if (!handleOf(ikm)) return realHkdf.apply(this, arguments);
  let out, err; try { out = hkdfRemote(digest, ikm, salt, info, keylen); } catch (e) { err = e; }
  process.nextTick(() => cb(err || null, out));
};
// Make `import { createHmac } from 'node:crypto'` in ESM code see the patched versions.
nodeModule.syncBuiltinESMExports();

// ---------- WebCrypto (globalThis.crypto.subtle) ----------
const subtle = globalThis.crypto.subtle;
const real = {
  importKey: subtle.importKey.bind(subtle), sign: subtle.sign.bind(subtle), verify: subtle.verify.bind(subtle),
  deriveBits: subtle.deriveBits.bind(subtle), encrypt: subtle.encrypt.bind(subtle), decrypt: subtle.decrypt.bind(subtle),
  exportKey: subtle.exportKey.bind(subtle),
};
const hashName = (a) => (typeof a === 'string' ? a : a.name).toUpperCase().replace('SHA-', 'sha');
subtle.importKey = async function (format, keyData, algorithm, extractable, usages) {
  const handle = format === 'raw' ? handleOf(keyData) : null;
  if (!handle) return real.importKey(format, keyData, algorithm, extractable, usages);
  const algName = (typeof algorithm === 'string' ? algorithm : algorithm.name).toUpperCase();
  // A real CryptoKey of the same type, built from decoy bytes, so `instanceof CryptoKey` and type checks pass.
  let decoy;
  if (algName === 'HKDF') decoy = await real.importKey('raw', crypto.randomBytes(32), 'HKDF', false, usages);
  else decoy = await real.importKey('raw', crypto.randomBytes(algName === 'HMAC' ? 32 : 32), algorithm, false, usages);
  cryptoKeyHandles.set(decoy, { handle, algorithm });
  return decoy;
};
subtle.sign = async function (algorithm, key, data) {
  const h = cryptoKeyHandles.get(key);
  if (!h) return real.sign(algorithm, key, data);
  const r = callKeeper({ op: 'hmac', handle: h.handle, alg: hashName(h.algorithm.hash), data: b64(data) });
  const out = Buffer.from(r.digest, 'base64');
  return out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength);
};
subtle.verify = async function (algorithm, key, signature, data) {
  const h = cryptoKeyHandles.get(key);
  if (!h) return real.verify(algorithm, key, signature, data);
  const mac = Buffer.from(await subtle.sign(algorithm, key, data));
  const sig = toBuf(signature);
  return sig.length === mac.length && crypto.timingSafeEqual(sig, mac);
};
subtle.deriveBits = async function (algorithm, baseKey, length) {
  const h = cryptoKeyHandles.get(baseKey);
  if (!h) return real.deriveBits(algorithm, baseKey, length);
  // The derived key stays in the keeper; we get back a new handle of the requested length.
  const r = callKeeper({ op: 'hkdf', handle: h.handle, hash: hashName(algorithm.hash), salt: b64(algorithm.salt), info: b64(algorithm.info), length: length / 8 });
  const out = Buffer.from(r.handle, 'latin1');
  return out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength);
};
for (const mode of ['encrypt', 'decrypt']) {
  subtle[mode] = async function (algorithm, key, data) {
    const h = cryptoKeyHandles.get(key);
    if (!h) return real[mode](algorithm, key, data);
    const name = (typeof algorithm === 'string' ? algorithm : algorithm.name).toUpperCase();
    if (name === 'AES-CBC') {
      const r = callKeeper({ op: 'aescbc', mode, handle: h.handle, iv: b64(algorithm.iv), data: b64(data) });
      const out = Buffer.from(r.out, 'base64');
      return out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength);
    }
    const r = callKeeper({ op: 'aesgcm', mode, handle: h.handle, iv: b64(algorithm.iv), aad: algorithm.additionalData ? b64(algorithm.additionalData) : undefined, tagLength: algorithm.tagLength, data: b64(data) });
    const out = Buffer.from(r.out, 'base64');
    return out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength);
  };
}
