// Java agent shim (JCA provider), oracle pattern: the app runs with -javaagent and handles; this
// process verifies outputs with the real keys.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import path from 'node:path';
import { ROOT, startKeeper, handleEnv, real, tmpdir } from '../lib/harness.mjs';

const noJava = spawnSync('javac', ['-version']).status !== 0 && 'no JDK';
let keeper, r;
before(async () => {
  if (noJava) return;
  const b = spawnSync('sh', [path.join(ROOT, 'shims/java/build.sh')], { encoding: 'utf8' });
  if (b.status !== 0) throw new Error(b.stderr);
  const classes = tmpdir('dk-java');
  const c = spawnSync('javac', ['-d', classes, path.join(ROOT, 'compat/java/App.java')], { encoding: 'utf8' });
  if (c.status !== 0) throw new Error(c.stderr);
  keeper = await startKeeper();
  const run = spawnSync('java', [`-javaagent:${path.join(ROOT, 'shims/java/dist/doppelkey-agent.jar')}`, '-cp', classes, 'App'], {
    encoding: 'utf8', env: { PATH: process.env.PATH, HOME: process.env.HOME, ...handleEnv, DOPPELKEY_SOCK: keeper.sock },
  });
  r = JSON.parse(run.stdout.trim().split('\n').pop());
});
after(() => keeper?.stop());

const b64hmac = (alg, key, data) => crypto.createHmac(alg, key).update(data).digest('base64');
const gcmOpen = (key, iv, ct, aad) => { const d = crypto.createDecipheriv(`aes-${key.length * 8}-gcm`, key, iv); if (aad) d.setAAD(Buffer.from(aad)); d.setAuthTag(ct.subarray(-16)); return Buffer.concat([d.update(ct.subarray(0, -16)), d.final()]).toString(); };

test('no unexpected errors', { skip: noJava }, () => {
  assert.deepEqual(Object.keys(r.errors).filter((k) => k !== 'policy'), []);
});

test('HmacSHA256/512 via the Doppelkey provider match the real key (a HS256 JWT verifies)', { skip: noJava }, () => {
  const [h, p, s] = r.jwt.split('.');
  assert.equal(s, crypto.createHmac('sha256', real('JWT_SECRET')).update(`${h}.${p}`).digest('base64url'));
  assert.equal(r.hmac512, b64hmac('sha512', real('COOKIE_SECRET'), 'hello'));
  assert.equal(r.provider, 'Doppelkey');
});

test('ordinary keys fall through to the JDK provider unchanged', { skip: noJava }, () => {
  assert.equal(r.plainHmac, b64hmac('sha256', 'not-a-handle', 'hello'));
  assert.notEqual(r.plainProvider, 'Doppelkey');
  const c = crypto.createCipheriv('aes-128-gcm', Buffer.alloc(16), Buffer.alloc(12));
  assert.equal(r.plainGcm, Buffer.concat([c.update('x'), c.final(), c.getAuthTag()]).toString('base64'));
});

test('PBKDF2WithHmacSHA256 -> AES/GCM decrypts under the real derived key', { skip: noJava }, () => {
  const k = crypto.pbkdf2Sync(real('SESSION_PASSWORD'), 'salt', 1000, 32, 'sha256');
  assert.equal(gcmOpen(k, Buffer.alloc(12), Buffer.from(r.pbkdf2Gcm, 'base64')), 'derived');
});

test('AES/GCM with AAD (update + doFinal) decrypts under the real key; tamper detected', { skip: noJava }, () => {
  const iv = Buffer.alloc(12); iv[0] = 7;
  assert.equal(gcmOpen(real('ENCRYPTION_KEY'), iv, Buffer.from(r.gcm.ct, 'base64'), 'hdr'), 'field secret');
  assert.equal(r.gcm.back, 'field secret');
  assert.equal(r.gcm.tamper, 'AEADBadTagException');
});

test('AES/CBC/PKCS5Padding with a hex-encoded handle decrypts under the real key', { skip: noJava }, () => {
  const d = crypto.createDecipheriv('aes-256-cbc', real('ENCRYPTION_KEY_HEX'), Buffer.alloc(16));
  assert.equal(Buffer.concat([d.update(Buffer.from(r.cbc, 'base64')), d.final()]).toString(), 'java cbc');
});

test('policy refusal names the command to run', { skip: noJava }, () => {
  assert.match(r.errors.policy, /doppelkey: hmac is not allowed for AUTH_SECRET\. Run "doppelkey policy AUTH_SECRET --allow hmac"\./);
});
