import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { decode as nextAuthDecode } from 'next-auth/jwt';
import { unsealData } from 'iron-session';
import { Webhook } from 'svix';
import { startKeeper, runApp, real } from '../lib/harness.mjs';

// Pure-JS adapters use module.registerHooks (Node >= 22.15). Where it is missing (Bun, Node 20)
// the shim warns at startup instead (checked below).
const ADAPTER_KEYS = ['svixSign', 'svixVerifyReal', 'svixForged', 'nobleExtract'];
const NO_ADAPTERS = 'no module.registerHooks in this runtime (Bun, Node < 22.15): the shim warns instead';
const adapters = () => r.adapters.length > 0;

let keeper, run, r;
const svixReal = () => 'whsec_' + real('SVIX_SECRET').toString('base64');
before(async () => {
  keeper = await startKeeper();
  const payload = '{"type":"user.created"}';
  const id = 'msg_real', ts = new Date();
  const sig = new Webhook(svixReal()).sign(id, ts, payload); // signed by "the provider" with the real secret
  const headers = { 'svix-id': id, 'svix-timestamp': String(Math.floor(ts / 1000)), 'svix-signature': sig };
  run = runApp('more-libs.mjs', { keeper, env: { SVIX_PAYLOAD: payload, SVIX_HEADERS: JSON.stringify(headers) } });
  r = run.results;
});
after(() => keeper?.stop());
const hmacHex = (k, d, alg = 'sha256') => crypto.createHmac(alg, k).update(d).digest('hex');

test('no unexpected errors', () => {
  const rest = Object.fromEntries(Object.entries(r.errors).filter(([k]) => !(adapters() ? ['nobleExtract', 'svixForged'] : ADAPTER_KEYS).includes(k)));
  assert.deepEqual(rest, {});
});

test('next-auth v4 JWE (HKDF + jose node createCipheriv) decrypts with the real secret', async () => {
  assert.equal((await nextAuthDecode({ token: r.nextAuthV4, secret: real('AUTH_SECRET').toString() }))?.name, 'Alice');
  assert.equal(r.nextAuthV4Decode, 'Alice');
});

test('iron-session (WebCrypto PBKDF2 + AES-CBC + HMAC) unseals with the real password', async () => {
  assert.equal((await unsealData(r.ironSeal, { password: real('SESSION_PASSWORD').toString(), ttl: 0 }))?.user, 'alice');
  assert.equal(r.ironUnseal, 'alice');
});

test('svix (pure-JS fast-sha256, base64 handle) signs and verifies like the real secret', (t) => {
  if (!adapters()) return t.skip(NO_ADAPTERS);
  assert.equal(r.svixSign, new Webhook(svixReal()).sign('msg_1', new Date(1700000000000), '{"a":1}'));
  assert.equal(r.svixVerifyReal, 'verified');
  assert.match(r.errors.svixForged, /No matching signature/i);
});

test('@noble/hashes hmac (one-shot and streaming) and hkdf go to the keeper', (t) => {
  if (!adapters()) return t.skip(NO_ADAPTERS);
  assert.equal(r.nobleHmac, hmacHex(real('JWT_SECRET'), 'hello'));
  assert.equal(r.nobleHmacStream, hmacHex(real('JWT_SECRET'), 'hello', 'sha512'));
  assert.equal(r.nobleHkdfThenHmac, hmacHex(Buffer.from(crypto.hkdfSync('sha256', real('AUTH_SECRET'), 'salt', 'info', 32)), 'hello'));
  assert.match(r.errors.nobleExtract, /HKDF-Extract \(pure JS\) is not supported/);
  assert.equal(r.noblePlain, hmacHex('plain', 'hello'));
});

test('@oslojs/crypto hmac goes to the keeper', (t) => {
  if (!adapters()) return t.skip(NO_ADAPTERS);
  assert.equal(r.osloHmac, hmacHex(real('JWT_SECRET'), 'hello'));
});

test('@octokit/webhooks-methods signs with the real secret', () => {
  assert.equal(r.octokit, 'sha256=' + hmacHex(real('COOKIE_SECRET'), '{"action":"opened"}'));
  assert.equal(r.octokitVerify, true);
});

test('hono/jwt token verifies under the real key', () => {
  assert.equal(jwt.verify(r.hono, real('JWT_SECRET')).sub, 'user1');
  assert.equal(r.honoVerify, 'user1');
});

test('pure-JS packages: no warning where adapters cover them; a warning where they cannot', () => {
  if (!adapters()) assert.match(run.stderr, /bypass the shim: .*fast-sha256/);
  else assert.doesNotMatch(run.stderr, /fast-sha256|@noble\/hashes|@oslojs\/crypto/);
});
