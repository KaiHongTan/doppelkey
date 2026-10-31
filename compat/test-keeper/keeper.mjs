#!/usr/bin/env node
// Test keeper: a Node implementation of wire protocol v1 (docs/protocol.md), ported from
// prototype/keeper.mjs so shim work isn't blocked on doppelkeyd. TEST USE ONLY: it reads real
// key bytes from a JSON vault file. doppelkeyd (Milestone 2) replaces it.
//
//   node keeper.mjs --vault <vault.json> [--socket <path>] [--audit <audit.jsonl>]
//
// Prints "doppelkey test keeper listening on <path>" when ready.
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { parseHandle, keyBytes } from './handles.mjs';

const VERSION = 'test-keeper-0.1';
const args = Object.fromEntries(process.argv.slice(2).reduce((a, v, i, all) => (v.startsWith('--') ? [...a, [v.slice(2), all[i + 1]]] : a), []));
const defaultSocket = () =>
  process.env.DOPPELKEY_SOCK ||
  (process.env.XDG_RUNTIME_DIR ? path.join(process.env.XDG_RUNTIME_DIR, 'doppelkey', 'doppelkeyd.sock') : path.join(os.tmpdir(), `doppelkey-${process.getuid()}`, 'doppelkeyd.sock'));
const SOCK = args.socket || defaultSocket();
const AUDIT = args.audit || null;
if (!args.vault) { console.error('usage: keeper.mjs --vault <vault.json> [--socket <path>] [--audit <file>]'); process.exit(2); }
const vault = JSON.parse(fs.readFileSync(args.vault, 'utf8'));

// ---------- key table ----------
// id -> { name, key: Buffer, allow: string[], prefix?, profile?, accessKeyId?, services?, sigv2?, sigv4Stage?, scope? }
const keys = new Map();
for (const [name, e] of Object.entries(vault.keys)) {
  keys.set(e.id, { name, key: keyBytes(e), allow: e.allow, prefix: e.prefix, profile: e.profile, accessKeyId: e.access_key_id, services: e.services, sigv2: !!e.sigv2 });
}
const SALT = vault.salt ? Buffer.from(vault.salt, 'base64') : crypto.randomBytes(32);
const DERIVED_ALLOW = ['hmac', 'aes_gcm', 'aes_cbc'];
const HASHES = new Set(['sha1', 'sha256', 'sha384', 'sha512']);

class KErr extends Error {
  constructor(code, message, hint) { super(message); this.code = code; this.hint = hint; }
}
const b = (x, field) => {
  if (x === undefined || x === null) return Buffer.alloc(0);
  if (typeof x !== 'string') throw new KErr('bad_request', `${field} must be base64`);
  return Buffer.from(x, 'base64');
};
const needHash = (h, field = 'hash') => {
  if (!HASHES.has(h)) throw new KErr('bad_request', `${field} "${h}" is not supported (sha1, sha256, sha384, sha512)`);
  return h;
};
const needLen = (n) => {
  if (!Number.isInteger(n) || n <= 0 || n > 1024) throw new KErr('bad_request', 'length must be an integer between 1 and 1024');
  return n;
};

/** Resolve the request's handle (+ prefix, key_encoding) to a key entry and check policy. */
function resolve(req, op) {
  const ids = parseHandle(req.handle);
  if (!ids) throw new KErr('unknown_handle', 'not a valid doppelkey handle', 'doppelkey doctor');
  const parts = ids.map((id) => keys.get(id));
  if (parts.some((p) => !p)) throw new KErr('unknown_handle', 'this handle is not in the keeper', 'doppelkey doctor');
  let k = parts[0];
  if (parts.length > 1) {
    k = { name: parts.map((p) => p.name).join('+'), key: Buffer.concat(parts.map((p) => p.key)), allow: parts.reduce((a, p) => a.filter((x) => p.allow.includes(x)), parts[0].allow) };
  }
  const allowed = k.allow.includes(op) || (op === 'hash_derive' && k.allow.includes('hmac'));
  if (!allowed) throw new KErr('op_not_allowed', `${op} is not allowed for ${k.name}`, `doppelkey policy ${k.name} --allow ${op}`);
  let key = k.key;
  if (req.key_encoding !== undefined) {
    if (req.key_encoding !== 'hex' && req.key_encoding !== 'base64') throw new KErr('bad_request', 'key_encoding must be "hex" or "base64"');
    key = Buffer.from(key.toString(req.key_encoding), 'latin1');
  }
  const prefix = req.prefix !== undefined ? b(req.prefix, 'prefix').toString('latin1') : '';
  if (prefix && !(k.prefix && prefix === k.prefix) && !(k.profile === 'aws-sigv4' && prefix === 'AWS4' && op === 'hmac'))
    throw new KErr('op_not_allowed', `a key of the form <prefix><handle> is not allowed for ${k.name}`);
  // Encoded forms store the decoded bytes without the vendor prefix; the text key is prefix + encoding.
  if (prefix && req.key_encoding !== undefined) key = Buffer.concat([Buffer.from(prefix, 'latin1'), key]);
  return { k, key, prefix, ids };
}

// Derived keys become new handles; their bytes never leave the keeper.
const idFor = (seed) => crypto.createHmac('sha256', SALT).update(seed).digest('hex').slice(0, 12);
const compact = (id) => `dk1:${id}${crypto.createHash('sha256').update('dk1:' + id).digest('hex').slice(0, 4)}`;
function newHandle(bytes, seed, meta = {}) {
  const len = bytes.length;
  if (len < 20) throw new KErr('bad_request', `a derived key of ${len} bytes is too short to carry a handle (minimum 20)`);
  if (len >= 64 && len % 2 === 0) {
    const half = len / 2;
    const a = idFor(seed + '|A'), c = idFor(seed + '|B');
    keys.set(a, { name: `derived:${a}`, key: bytes.subarray(0, half), allow: DERIVED_ALLOW });
    keys.set(c, { name: `derived:${c}`, key: bytes.subarray(half), allow: DERIVED_ALLOW });
    return compact(a).padEnd(half, '.') + compact(c).padEnd(half, '.');
  }
  const id = idFor(seed);
  keys.set(id, { name: `derived:${id}`, key: bytes, allow: DERIVED_ALLOW, ...meta });
  return compact(id).padEnd(len, '.');
}

// AWS SigV4: kDate = HMAC("AWS4" + secret, date), then region, service, "aws4_request".
// Each intermediate key is returned as a handle; only the final signature leaves the keeper.
const SIGV4_STAGES = ['date', 'region', 'service', 'aws4_request'];
function sigv4Step(parent, ids, alg, msg, stage) {
  if (alg !== 'sha256') throw new KErr('bad_request', 'SigV4 uses sha256');
  const text = msg.toString('utf8');
  if (SIGV4_STAGES[stage - 1] === 'service' && parent.services && !parent.services.includes(text))
    throw new KErr('op_not_allowed', `service "${text}" is not allowed for ${parent.rootName ?? parent.name} (allowed: ${parent.services.join(', ')})`, `doppelkey policy ${parent.rootName ?? parent.name} --allow-service ${text}`);
  if (stage === 4 && text !== 'aws4_request') throw new KErr('op_not_allowed', 'not a SigV4 key derivation');
  const keyBytes_ = stage === 1 ? Buffer.concat([Buffer.from('AWS4'), parent.key]) : parent.key;
  const out = crypto.createHmac(alg, keyBytes_).update(msg).digest();
  return newHandle(out, ['sigv4', ids.join('+'), text].join('|'), {
    sigv4Stage: stage, scope: [...(parent.scope || []), text], services: parent.services, rootName: parent.rootName ?? parent.name, allow: ['hmac'],
  });
}

const ops = {
  hmac(req) {
    const alg = needHash(req.alg, 'alg');
    const { k, key, prefix, ids } = resolve(req, 'hmac');
    const msg = b(req.data, 'data');
    if (prefix === 'AWS4' && k.profile === 'aws-sigv4') return { result: { handle: sigv4Step(k, ids, alg, msg, 1) } };
    if (k.sigv4Stage && k.sigv4Stage < 4) return { result: { handle: sigv4Step(k, ids, alg, msg, k.sigv4Stage + 1) } };
    if (k.profile === 'aws-sigv4' && msg.toString() !== k.accessKeyId) {
      // Legacy SigV2 (boto3's default for S3 presigned URLs) signs with the raw secret.
      if (!/^(GET|PUT|HEAD|POST|DELETE)\n/.test(msg.toString()))
        throw new KErr('op_not_allowed', `raw HMAC with ${k.name} is only allowed over its access key ID (the SDK's cache key)`);
      if (!k.sigv2) throw new KErr('op_not_allowed', `legacy SigV2 signing is refused for ${k.name}`, `Use signature_version="s3v4", or run "doppelkey policy ${k.name} --allow sigv2".`);
      return { result: { digest: crypto.createHmac(alg, key).update(msg).digest('base64') }, audit: { scope: 'sigv2' } };
    }
    const digest = crypto.createHmac(alg, key).update(msg).digest('base64');
    return { result: { digest }, audit: k.sigv4Stage === 4 ? { scope: k.scope.join('/') } : {} };
  },
  hash_derive(req) {
    const hash = needHash(req.hash);
    const { key, ids } = resolve(req, 'hash_derive');
    const full = crypto.createHash(hash).update(Buffer.concat([b(req.prefix_data, 'prefix_data'), key, b(req.suffix_data, 'suffix_data')])).digest();
    const length = needLen(req.length ?? full.length);
    if (length > full.length) throw new KErr('bad_request', `length ${length} exceeds the ${hash} output`);
    return { result: { handle: newHandle(full.subarray(0, length), ['hash', ids.join('+'), req.key_encoding ?? '', hash, req.prefix_data, req.suffix_data, length].join('|')) } };
  },
  hkdf(req) {
    const hash = needHash(req.hash);
    const { key, ids } = resolve(req, 'hkdf');
    const length = needLen(req.length);
    const out = Buffer.from(crypto.hkdfSync(hash, key, b(req.salt, 'salt'), b(req.info, 'info'), length));
    return { result: { handle: newHandle(out, ['hkdf', ids.join('+'), req.key_encoding ?? '', hash, req.salt ?? '', req.info ?? '', length].join('|')) } };
  },
  pbkdf2(req) {
    const hash = needHash(req.hash);
    const { key, ids } = resolve(req, 'pbkdf2');
    const length = needLen(req.length);
    if (!Number.isInteger(req.iterations) || req.iterations < 1 || req.iterations > 10_000_000) throw new KErr('bad_request', 'iterations must be an integer between 1 and 10000000');
    const out = crypto.pbkdf2Sync(key, b(req.salt, 'salt'), req.iterations, length, hash);
    return { result: { handle: newHandle(out, ['pbkdf2', ids.join('+'), req.key_encoding ?? '', hash, req.salt ?? '', req.iterations, length].join('|')) } };
  },
  aes_gcm(req) {
    const { key } = resolve(req, 'aes_gcm');
    const iv = b(req.iv, 'iv'), data = b(req.data, 'data');
    checkAesKey(key, req.key_bits);
    if (iv.length !== 12) throw new KErr('bad_request', 'AES-GCM needs a 12-byte IV in protocol v1');
    const alg = `aes-${key.length * 8}-gcm`;
    if (req.mode === 'encrypt') {
      const c = crypto.createCipheriv(alg, key, iv, { authTagLength: 16 });
      if (req.aad) c.setAAD(b(req.aad, 'aad'));
      return { result: { out: Buffer.concat([c.update(data), c.final(), c.getAuthTag()]).toString('base64') } };
    }
    if (req.mode !== 'decrypt') throw new KErr('bad_request', 'mode must be "encrypt" or "decrypt"');
    if (data.length < 16) throw new KErr('crypto_error', 'ciphertext shorter than the tag');
    try {
      const d = crypto.createDecipheriv(alg, key, iv, { authTagLength: 16 });
      if (req.aad) d.setAAD(b(req.aad, 'aad'));
      d.setAuthTag(data.subarray(data.length - 16));
      return { result: { out: Buffer.concat([d.update(data.subarray(0, data.length - 16)), d.final()]).toString('base64') } };
    } catch { throw new KErr('crypto_error', 'AES-GCM authentication failed'); }
  },
  aes_cbc(req) {
    const { key } = resolve(req, 'aes_cbc');
    const iv = b(req.iv, 'iv'), data = b(req.data, 'data');
    checkAesKey(key, req.key_bits);
    if (iv.length !== 16) throw new KErr('bad_request', 'AES-CBC needs a 16-byte IV');
    if (req.mode !== 'encrypt' && req.mode !== 'decrypt') throw new KErr('bad_request', 'mode must be "encrypt" or "decrypt"');
    try {
      const f = req.mode === 'encrypt' ? crypto.createCipheriv : crypto.createDecipheriv;
      const c = f(`aes-${key.length * 8}-cbc`, key, iv);
      if (req.padding === false) c.setAutoPadding(false);
      return { result: { out: Buffer.concat([c.update(data), c.final()]).toString('base64') } };
    } catch (e) { throw new KErr(req.mode === 'decrypt' ? 'crypto_error' : 'bad_request', req.mode === 'decrypt' ? 'AES-CBC decryption failed' : e.message); }
  },
  status() {
    return { result: { version: VERSION, protocol: 1, keys: Object.keys(vault.keys) } };
  },
};
function checkAesKey(key, bits) {
  if (![16, 24, 32].includes(key.length)) throw new KErr('bad_request', `key is ${key.length} bytes; AES needs 16, 24 or 32`);
  if (bits !== undefined && bits !== key.length * 8) throw new KErr('bad_request', `AES-${bits} requested but the key is ${key.length * 8} bits`);
}

// ---------- audit ----------
function audit(req, k, extra) {
  if (!AUDIT) return;
  const entry = { ts: new Date().toISOString(), op: req.op, key: k, ok: extra.ok, ...(extra.scope ? { scope: extra.scope } : {}), ...(extra.code ? { code: extra.code } : {}) };
  fs.appendFileSync(AUDIT, JSON.stringify(entry) + '\n');
}
function keyName(req) {
  const ids = parseHandle(req.handle);
  return ids ? ids.map((id) => keys.get(id)?.rootName ?? keys.get(id)?.name ?? `unknown:${id}`).join('+') : undefined;
}

// ---------- server ----------
function handle(req) {
  if (!req || typeof req !== 'object') return { v: 1, id: 0, ok: false, error: { code: 'bad_request', message: 'request must be a JSON object' } };
  const id = Number.isInteger(req.id) ? req.id : 0;
  if (req.v !== 1) return { v: 1, id, ok: false, error: { code: 'version_mismatch', message: `protocol version ${req.v} is not supported (this keeper speaks v1)`, hint: 'doppelkey doctor' } };
  const fn = Object.prototype.hasOwnProperty.call(ops, req.op) ? ops[req.op] : null;
  try {
    if (!fn) throw new KErr('bad_request', `unknown op "${req.op}"`);
    const { result, audit: a = {} } = fn(req);
    audit(req, keyName(req), { ok: true, ...a });
    return { v: 1, id, ok: true, result };
  } catch (e) {
    const err = e instanceof KErr ? e : new KErr('bad_request', e.message);
    audit(req, keyName(req), { ok: false, code: err.code });
    return { v: 1, id, ok: false, error: { code: err.code, message: err.message, ...(err.hint ? { hint: err.hint } : {}) } };
  }
}

const MAX_FRAME = 16 << 20;
fs.mkdirSync(path.dirname(SOCK), { recursive: true, mode: 0o700 });
try { fs.unlinkSync(SOCK); } catch {}
const server = net.createServer((sock) => {
  let buf = Buffer.alloc(0);
  sock.on('data', (chunk) => {
    buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
    while (buf.length >= 4) {
      const n = buf.readUInt32BE(0);
      if (n > MAX_FRAME) { sock.destroy(); return; }
      if (buf.length < 4 + n) break;
      let req;
      try { req = JSON.parse(buf.subarray(4, 4 + n).toString('utf8')); } catch { req = null; }
      buf = buf.subarray(4 + n);
      const body = Buffer.from(JSON.stringify(handle(req)), 'utf8');
      const head = Buffer.alloc(4);
      head.writeUInt32BE(body.length, 0);
      sock.write(Buffer.concat([head, body]));
    }
  });
  sock.on('error', () => {});
});
server.listen(SOCK, () => {
  fs.chmodSync(SOCK, 0o600);
  console.log(`doppelkey test keeper listening on ${SOCK}`);
});
for (const s of ['SIGINT', 'SIGTERM']) process.on(s, () => { try { fs.unlinkSync(SOCK); } catch {} process.exit(0); });
