// oracle.mjs — plays "the real world" that knows the real secrets (Stripe's servers, a verifier).
// Run WITHOUT the shim. Mode "prep" makes the Stripe header; mode "check" verifies the app's outputs.
import fs from 'node:fs';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import Stripe from 'stripe';
const v = JSON.parse(fs.readFileSync('./vault.json', 'utf8'));
const real = Object.fromEntries(Object.entries(v).map(([h, x]) => [h.slice(0, 20), x.key]));
const JWT = real['KH1:a1b2c3d4e5f60718'], COOKIE = real['KH1:0f1e2d3c4b5a6978'], WH = real['KH1:1122334455667788'], AUTH = real['KH1:99aabbccddeeff00'];
const payload = JSON.stringify({ id: 'evt_1', type: 'payment_intent.succeeded' });
if (process.argv[2] === 'prep') {
  fs.writeFileSync('./stripe_header.txt', new Stripe('sk_test_dummy').webhooks.generateTestHeaderString({ payload, secret: WH }));
  console.log('stripe header written');
} else {
  const r = JSON.parse(fs.readFileSync('/tmp/app.results.json', 'utf8'));
  const checks = {
    rawHmac: r.rawHmac === crypto.createHmac('sha256', JWT).update('hello').digest('hex'),
    jsonwebtokenValidWithRealKey: jwt.verify(r.jsonwebtoken, JWT).sub === 'user1',
    joseValidWithRealKey: jwt.verify(r.jose, JWT).sub === 'user1',
    cookieMatchesRealKey: r.cookie === 'session-id-123.' + crypto.createHmac('sha256', COOKIE).update('session-id-123').digest('base64').replace(/=+$/, ''),
    stripeVerified: r.stripeSync === 'payment_intent.succeeded' && r.stripeAsync === 'payment_intent.succeeded',
    aesDecryptsWithRealDerivedKey: (() => {
      const k = Buffer.from(crypto.hkdfSync('sha256', AUTH, Buffer.alloc(0), 'session-enc', 32));
      const buf = Buffer.from(r.aesCiphertext, 'base64');
      const d = crypto.createDecipheriv('aes-256-gcm', k, Buffer.alloc(12));
      d.setAuthTag(buf.subarray(buf.length - 16));
      return Buffer.concat([d.update(buf.subarray(0, buf.length - 16)), d.final()]).toString() === '{"user":"alice"}';
    })(),
  };
  const heap = fs.readFileSync('/tmp/app.heapsnapshot', 'latin1');
  const environ = fs.readFileSync('/tmp/app.environ', 'latin1');
  const derivedKeyHex = Buffer.from(crypto.hkdfSync('sha256', AUTH, Buffer.alloc(0), 'session-enc', 32));
  checks.realSecretsInAppHeap = [JWT, COOKIE, WH, AUTH].filter((s) => heap.includes(s)).length;
  checks.realSecretsInAppEnviron = [JWT, COOKIE, WH, AUTH].filter((s) => environ.includes(s)).length;
  checks.derivedKeyInAppHeap = heap.includes(derivedKeyHex.toString('latin1')) || heap.includes(derivedKeyHex.toString('hex'));
  console.log(JSON.stringify(checks, null, 2));
}
