// Core libraries: jsonwebtoken, jose, cookie-signature, stripe (sync + async) and the
// AWS SDK v3 (S3) run unchanged with handles; every output verifies under the real key; the
// app's heap and environment hold none of the real keys or derived signing keys.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import jwt from 'jsonwebtoken';
import { startKeeper, runApp, real, scan, stripeHeader, vault, isBun, handleEnv } from '../lib/harness.mjs';
import { verifyAws } from '../lib/aws-oracle.mjs';

let keeper, run;
const payload = JSON.stringify({ id: 'evt_1', type: 'payment_intent.succeeded' });
const AWS_ENV = { AWS_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE', AWS_REGION: 'ap-southeast-1' };

before(async () => {
  keeper = await startKeeper();
  run = runApp('core-libs.mjs', { keeper, heap: true, env: { ...AWS_ENV, STRIPE_PAYLOAD: payload, STRIPE_HEADER: await stripeHeader(payload), STRIPE_HEADER_B64: await stripeHeader(payload, 'whsec_' + real('STRIPE_WEBHOOK_SECRET_B64').toString('base64')) } });
});
after(() => keeper?.stop());

const r = () => run.results;
const JWT = () => real('JWT_SECRET');

test('no unexpected errors', () => {
  const { stripeForged, cookieTampered, dynamodb, stripeSync, stripeB64Form, ...rest } = r().errors;
  assert.deepEqual(rest, {});
  if (!isBun) assert.equal(stripeSync, undefined);
});

test('the app only ever saw the handle', () => {
  assert.match(r().envJwtSecret, /^dk1:NOT-A-SECRET-load-doppelkey-shim:/);
});

test('node:crypto createHmac via ESM named import', () => {
  assert.equal(r().rawHmac, crypto.createHmac('sha256', JWT()).update('hello').digest('hex'));
});

test('jsonwebtoken HS256 and HS512 tokens verify under the real key', () => {
  assert.equal(jwt.verify(r().jsonwebtoken, JWT()).sub, 'user1');
  assert.equal(jwt.verify(r().jsonwebtokenHS512, JWT()).sub, 'user1');
  assert.equal(r().jsonwebtokenVerify, 'user1');
});

test('jose (WebCrypto) token verifies under the real key', () => {
  assert.equal(jwt.verify(r().jose, JWT()).sub, 'user1');
  assert.equal(r().joseVerify, 'user1');
});

test('cookie-signature signs with the real key and rejects tampering', () => {
  const mac = crypto.createHmac('sha256', real('COOKIE_SECRET')).update('session-id-123').digest('base64').replace(/=+$/, '');
  assert.equal(r().cookie, `session-id-123.${mac}`);
  assert.equal(r().cookieUnsign, 'session-id-123');
  assert.equal(r().cookieTampered, false);
});

test('stripe webhooks verify a header signed with the real secret (sync and async) and reject forgeries', () => {
  if (!isBun) assert.equal(r().stripeSync, 'payment_intent.succeeded'); // Bun gets Stripe's edge build: async only
  assert.equal(r().stripeAsync, 'payment_intent.succeeded');
  assert.match(r().errors.stripeForged, /signature/i);
});

test('stripe webhook secret written in the whsec_ + base64 handle form (used as text by Stripe)', { skip: isBun && 'sync Stripe API not available on Bun' }, () => {
  assert.match(handleEnv.STRIPE_WEBHOOK_SECRET_B64, /^whsec_ZGsxO/);
  assert.equal(r().stripeB64Form, 'payment_intent.succeeded');
});

test('AWS SDK v3: S3 request and presigned URL verify under the real secret; DynamoDB refused by policy', () => {
  const secret = real('AWS_SECRET_ACCESS_KEY');
  const reqs = [...r().s3Requests.map((x) => ({ kind: 'header', ...x })), { kind: 'presigned', method: 'GET', url: r().s3Presigned }];
  assert.ok(reqs.length >= 2);
  for (const req of reqs) {
    const v = verifyAws(secret, req);
    assert.ok(v.ok, `${req.kind} signature invalid: ${v.why ?? ''}`);
    assert.match(v.scope, /\/ap-southeast-1\/s3\/aws4_request$/);
  }
  assert.match(r().errors.dynamodb, /service "dynamodb" is not allowed for AWS_SECRET_ACCESS_KEY/);
});

test('audit log records the SigV4 scope of each S3 signature', () => {
  const scopes = keeper.auditEntries().filter((e) => e.scope).map((e) => e.scope);
  assert.ok(scopes.some((s) => /^\d{8}\/ap-southeast-1\/s3\/aws4_request$/.test(s)), JSON.stringify(scopes));
});

function needles() {
  const n = Object.fromEntries(Object.keys(vault.keys).map((k) => [k, real(k)]));
  // AWS derived signing keys for every scope the app signed.
  for (const req of [...r().s3Requests, { method: 'GET', url: r().s3Presigned }]) {
    const v = verifyAws(real('AWS_SECRET_ACCESS_KEY'), req);
    for (const [k, b] of Object.entries(v.keys || {})) n[`aws ${k} ${v.scope}`] = b;
  }
  return n;
}

test('heap snapshot of the app holds 0 real keys and 0 derived signing keys', { skip: isBun && 'no V8 heap snapshot in Bun' }, () => {
  assert.deepEqual(scan(run.heapFile, needles()), []);
});

test('/proc/self/environ of the app holds 0 real keys', { skip: process.platform !== 'linux' && 'Linux only' }, () => {
  assert.deepEqual(scan(run.environFile, needles()), []);
});

test('control: the scanner does find a real key when one is present', () => {
  const file = run.heapFile + '.control';
  fs.writeFileSync(file, Buffer.concat([Buffer.from('noise'), Buffer.from(real('JWT_SECRET').toString('latin1'), 'utf16le')]));
  assert.deepEqual(scan(file, { JWT_SECRET: real('JWT_SECRET') }), ['JWT_SECRET']);
});
