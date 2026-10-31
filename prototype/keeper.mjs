// keeper.mjs — holds the real secrets; only ever returns results of operations.
// Runs as a separate process (in real use: a separate OS user or launchd/systemd service,
// started outside the agent's process tree). Speaks newline-delimited JSON over a Unix socket.
import net from 'node:net';
import fs from 'node:fs';
import crypto from 'node:crypto';

const SOCK = process.env.KEEPER_SOCK || '/tmp/keeper.sock';
// For the PoC, real secrets come from a JSON file the app/agent never reads.
const vault = JSON.parse(fs.readFileSync(process.env.KEEPER_VAULT || './vault.json', 'utf8'));
// vault: { "<handle string>": { "key": "<real secret>", "allow": ["hmac", ...] } }
const keys = new Map(Object.entries(vault).map(([h, v]) => [h, { ...v, key: Buffer.from(v.key) }]));
const audit = [];

const HANDLE_RE = /^KH1:[0-9a-f]{16}/;
function handleFromBytes(b64) {
  const s = Buffer.from(b64, 'base64').toString('latin1');
  const m = s.match(HANDLE_RE);
  return m ? s : null;
}
function lookup(handle, op) {
  const k = keys.get(handle);
  if (!k) throw new Error('unknown handle');
  if (!k.allow.includes(op)) throw new Error(`op ${op} not allowed for this key`);
  return k.key;
}
// Derived keys become new handles; their bytes never leave the keeper.
// Handles are deterministic (same parent + parameters => same handle) so key IDs stay stable,
// and a 64-byte key is two 32-byte handles back to back, because libraries such as jose split
// AES-CBC-HMAC keys in half.
const KEEPER_SALT = crypto.randomBytes(32);
const DERIVED_OPS = ['hmac', 'aes-gcm', 'aes-cbc'];
const idFor = (seed) => crypto.createHmac('sha256', KEEPER_SALT).update(seed).digest('hex').slice(0, 16);
const handleStr = (id, len) => `KH1:${id}`.padEnd(len, '.');
function newHandle(bytes, len, allow, seed, meta = {}) {
  if (len < 20) throw new Error('derived key too short to carry a handle');
  if (len >= 64 && len % 2 === 0) {
    const half = len / 2;
    const a = handleStr(idFor(seed + '|A'), half), b = handleStr(idFor(seed + '|B'), half);
    keys.set(a, { key: bytes.subarray(0, half), allow });
    keys.set(b, { key: bytes.subarray(half), allow });
    keys.set(a + b, { key: bytes, allow });
    return a + b;
  }
  const h = handleStr(idFor(seed), len);
  keys.set(h, { key: bytes, allow, ...meta });
  return h;
}

// AWS SigV4: kDate = HMAC("AWS4" + secret, date), then region, service, "aws4_request".
// Every intermediate key is returned as a handle; only the final signature leaves the keeper.
// Policy: the vault entry can limit which services the key may sign for.
const SIGV4_STAGES = ['date', 'region', 'service', 'aws4_request'];
function sigv4Step(parent, parentHandle, alg, msg, stage) {
  if (alg !== 'sha256') throw new Error('SigV4 uses sha256');
  const text = msg.toString('utf8');
  if (SIGV4_STAGES[stage - 1] === 'service' && parent.services && !parent.services.includes(text))
    throw new Error(`service "${text}" not allowed for this AWS key (allowed: ${parent.services.join(', ')})`);
  if (stage === 4 && text !== 'aws4_request') throw new Error('not a SigV4 derivation');
  const keyBytes = stage === 1 ? Buffer.concat([Buffer.from('AWS4'), parent.key]) : parent.key;
  const out = crypto.createHmac(alg, keyBytes).update(msg).digest();
  const scope = [...(parent.scope || []), text];
  return newHandle(out, 32, ['hmac'], ['sigv4', parentHandle, text].join('|'),
    { sigv4Stage: stage, scope, services: parent.services });
}

const ops = {
  hmac({ handle, alg, data, prefix }) {
    const k = keys.get(handle);
    if (!k) throw new Error('unknown handle');
    if (!k.allow.includes('hmac')) throw new Error('op hmac not allowed for this key');
    const msg = Buffer.from(data, 'base64');
    if (prefix !== undefined) {
      // A key of the form <prefix><handle>. Only "AWS4" on an AWS key is allowed.
      if (k.profile !== 'aws-sigv4' || Buffer.from(prefix, 'base64').toString('latin1') !== 'AWS4')
        throw new Error('prefixed key not allowed for this handle');
      return { handle: sigv4Step(k, handle, alg, msg, 1) };
    }
    if (k.sigv4Stage && k.sigv4Stage < 4) return { handle: sigv4Step(k, handle, alg, msg, k.sigv4Stage + 1) };
    if (k.profile === 'aws-sigv4' && msg.toString() !== k.accessKeyId) {
      // Legacy SigV2 (boto3's default for S3 presigned URLs) signs with the raw secret.
      const isV2 = /^(GET|PUT|HEAD|POST|DELETE)\n/.test(msg.toString());
      if (!isV2) throw new Error('raw HMAC with an AWS secret is only allowed over its access key ID (SDK cache key)');
      if (!k.sigv2) throw new Error('legacy SigV2 signing refused for this AWS key. Use signature_version="s3v4", or allow it with: doppelkey policy AWS_SECRET_ACCESS_KEY --allow sigv2');
      return { digest: crypto.createHmac(alg, k.key).update(msg).digest('base64'), _scope: 'sigv2' };
    }
    const digest = crypto.createHmac(alg, k.key).update(msg).digest('base64');
    return k.sigv4Stage === 4 ? { digest, _scope: k.scope.join('/') } : { digest };
  },
  // A plain hash over (prefix + secret + suffix) — how Django and itsdangerous derive signing keys.
  hashDerive({ handle, hash, prefix, suffix, length }) {
    const key = lookup(handle, 'hmac');
    const out = crypto.createHash(hash).update(Buffer.concat([Buffer.from(prefix, 'base64'), key, Buffer.from(suffix, 'base64')])).digest();
    return { handle: newHandle(out, length || out.length, DERIVED_OPS, ['hash', handle, hash, prefix, suffix].join('|')) };
  },
  hkdf({ handle, hash, salt, info, length }) {
    const key = lookup(handle, 'hkdf');
    const out = Buffer.from(crypto.hkdfSync(hash, key, Buffer.from(salt, 'base64'), Buffer.from(info, 'base64'), length));
    return { handle: newHandle(out, length, DERIVED_OPS, ['hkdf', handle, hash, salt, info, length].join('|')) };
  },
  aescbc({ handle, mode, iv, data }) {
    const key = lookup(handle, 'aes-cbc');
    const alg = `aes-${key.length * 8}-cbc`;
    const f = mode === 'encrypt' ? crypto.createCipheriv : crypto.createDecipheriv;
    const c = f(alg, key, Buffer.from(iv, 'base64'));
    return { out: Buffer.concat([c.update(Buffer.from(data, 'base64')), c.final()]).toString('base64') };
  },
  aesgcm({ handle, mode, iv, data, aad, tagLength }) {
    const key = lookup(handle, 'aes-gcm');
    const alg = `aes-${key.length * 8}-gcm`;
    const tagBytes = (tagLength || 128) / 8;
    if (mode === 'encrypt') {
      const c = crypto.createCipheriv(alg, key, Buffer.from(iv, 'base64'), { authTagLength: tagBytes });
      if (aad) c.setAAD(Buffer.from(aad, 'base64'));
      const ct = Buffer.concat([c.update(Buffer.from(data, 'base64')), c.final(), c.getAuthTag()]);
      return { out: ct.toString('base64') };
    }
    const buf = Buffer.from(data, 'base64');
    const d = crypto.createDecipheriv(alg, key, Buffer.from(iv, 'base64'), { authTagLength: tagBytes });
    if (aad) d.setAAD(Buffer.from(aad, 'base64'));
    d.setAuthTag(buf.subarray(buf.length - tagBytes));
    const pt = Buffer.concat([d.update(buf.subarray(0, buf.length - tagBytes)), d.final()]);
    return { out: pt.toString('base64') };
  },
};

try { fs.unlinkSync(SOCK); } catch {}
const server = net.createServer((sock) => {
  let buf = '';
  sock.on('data', (chunk) => {
    buf += chunk;
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i); buf = buf.slice(i + 1);
      let reply;
      try {
        const req = JSON.parse(line);
        if (req.handleB64) req.handle = handleFromBytes(req.handleB64);
        reply = { ok: true, ...ops[req.op](req) };
        const scope = reply._scope; delete reply._scope;
        audit.push({ t: Date.now(), op: req.op, handle: String(req.handle).slice(0, 20), ...(scope ? { sigv4: scope } : {}) });
        fs.appendFileSync(process.env.KEEPER_AUDIT || './audit.log', JSON.stringify(audit.at(-1)) + '\n');
      } catch (e) {
        reply = { ok: false, error: e.message };
      }
      sock.write(JSON.stringify(reply) + '\n');
    }
  });
});
server.listen(SOCK, () => { fs.chmodSync(SOCK, 0o600); console.log('keeper listening on', SOCK); });
