// The keeper has no export operation: no response to any request, including unknown ops and
// odd parameters, contains real key bytes in any common encoding. Plus protocol error codes.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startKeeper, real, vault, forms } from '../lib/harness.mjs';
import { connect } from '../lib/client.mjs';
import { envValue, compactCore } from '../../test-keeper/handles.mjs';

let keeper, c;
before(async () => { keeper = await startKeeper(); c = await connect(keeper.sock); });
after(async () => { c?.close(); await keeper?.stop(); });

/** The handle string the shim would send for a vault entry. */
function keeperHandle(e) {
  const v = envValue(e).slice((e.prefix ?? '').length);
  return e.form === 'hex' ? Buffer.from(v, 'hex').toString('latin1') : e.form === 'base64' ? Buffer.from(v, 'base64').toString('latin1') : v;
}
const b64 = (s) => Buffer.from(s).toString('base64');

function leaks(response, needles) {
  const found = [];
  const strings = [];
  (function walk(x) { if (typeof x === 'string') strings.push(x); else if (x && typeof x === 'object') Object.values(x).forEach(walk); })(response);
  const hay = [Buffer.from(JSON.stringify(response)), ...strings.map((s) => Buffer.from(s, 'base64')), ...strings.map((s) => Buffer.from(s, 'latin1'))];
  for (const [name, n] of Object.entries(needles)) if (forms(n).some((f) => hay.some((h) => h.indexOf(f) !== -1))) found.push(name);
  return found;
}

test('no response to any op leaks a real key', async () => {
  const needles = Object.fromEntries(Object.keys(vault.keys).map((k) => [k, real(k)]));
  const ops = ['hmac', 'hash_derive', 'hkdf', 'pbkdf2', 'aes_gcm', 'aes_cbc', 'status', 'export', 'export_key', 'get', 'read', 'dump', 'key', 'unwrap', 'debug', '__proto__', 'constructor', 'toString', ''];
  const variants = [{}, { key_encoding: 'hex' }, { key_encoding: 'base64' }, { prefix: b64('AWS4') }, { prefix: b64('whsec_') }];
  const params = { alg: 'sha256', hash: 'sha256', data: b64('x'.repeat(48)), salt: '', info: '', length: 32, iterations: 1, prefix_data: '', suffix_data: '', mode: 'encrypt', iv: b64('i'.repeat(12)) };
  let n = 0, ok = 0;
  for (const [name, e] of Object.entries(vault.keys)) {
    for (const op of ops) for (const v of variants) for (const mode of ['encrypt', 'decrypt']) {
      const iv = op === 'aes_cbc' ? b64('i'.repeat(16)) : params.iv;
      const res = await c.request({ op, handle: keeperHandle(e), ...params, mode, iv, ...v });
      n++; if (res.ok) ok++;
      assert.deepEqual(leaks(res, needles), [], `${name} ${op} ${JSON.stringify(v)} ${mode}: ${JSON.stringify(res).slice(0, 200)}`);
      // Derived handles in results must not carry key bytes either; use one to be sure.
      if (res.ok && res.result.handle) {
        const again = await c.request({ op: 'hmac', handle: res.result.handle.replace(/^(.{32}).*$/s, '$1'), alg: 'sha256', data: b64('y') });
        assert.deepEqual(leaks(again, needles), []);
      }
    }
  }
  assert.ok(n > 1000 && ok > 50, `ran ${n} requests, ${ok} succeeded`);
});

test('status lists key names only', async () => {
  const r = await c.request({ op: 'status' });
  assert.equal(r.ok, true);
  assert.equal(r.result.protocol, 1);
  assert.deepEqual(r.result.keys.sort(), Object.keys(vault.keys).sort());
});

test('protocol errors use the documented codes', async () => {
  const jwt = keeperHandle(vault.keys.JWT_SECRET);
  const cases = [
    [{ op: 'status', v: 2 }, 'version_mismatch'],
    [{ op: 'nope' }, 'bad_request'],
    [{ op: 'hmac', handle: jwt.replace(/[0-9a-f]{4}$/, '0000'), alg: 'sha256', data: '' }, 'unknown_handle'],
    [{ op: 'hmac', handle: compactCore('0123456789ab'), alg: 'sha256', data: '' }, 'unknown_handle'],
    [{ op: 'hmac', handle: jwt, alg: 'md5', data: '' }, 'bad_request'],
    [{ op: 'hkdf', handle: jwt, hash: 'sha256', length: 32 }, 'op_not_allowed'],
    [{ op: 'hkdf', handle: keeperHandle(vault.keys.AUTH_SECRET), hash: 'sha256', length: 16 }, 'bad_request'],
    [{ op: 'aes_gcm', handle: keeperHandle(vault.keys.ENCRYPTION_KEY), mode: 'decrypt', iv: b64('i'.repeat(12)), data: b64('z'.repeat(40)) }, 'crypto_error'],
    [{ op: 'aes_gcm', handle: keeperHandle(vault.keys.ENCRYPTION_KEY), mode: 'encrypt', iv: b64('i'.repeat(12)), data: '', key_bits: 128 }, 'bad_request'],
  ];
  for (const [req, code] of cases) {
    const r = await c.request(req);
    assert.equal(r.ok, false, JSON.stringify(req));
    assert.equal(r.error.code, code, `${JSON.stringify(req)} -> ${JSON.stringify(r.error)}`);
  }
  const bad = await c.raw(Buffer.from('{not json'));
  assert.equal(bad.error.code, 'bad_request');
});

test('op_not_allowed carries a hint naming the policy command', async () => {
  const r = await c.request({ op: 'hkdf', handle: keeperHandle(vault.keys.JWT_SECRET), hash: 'sha256', length: 32 });
  assert.equal(r.error.hint, 'doppelkey policy JWT_SECRET --allow hkdf');
});

test('derived handles are deterministic and 64-byte keys split into two 32-byte handles', async () => {
  const req = { op: 'hkdf', handle: keeperHandle(vault.keys.AUTH_SECRET), hash: 'sha256', salt: '', info: b64('i'), length: 64 };
  const a = await c.request(req), b = await c.request(req);
  assert.equal(a.result.handle, b.result.handle);
  assert.equal(a.result.handle.length, 64);
  assert.match(a.result.handle, /^dk1:[0-9a-f]{16}\.{12}dk1:[0-9a-f]{16}\.{12}$/);
});
