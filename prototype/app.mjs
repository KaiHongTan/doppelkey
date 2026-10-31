// An unmodified "app": uses popular libraries exactly as their docs say.
import { createHmac } from 'node:crypto';          // ESM named import (tests syncBuiltinESMExports)
import jwt from 'jsonwebtoken';
import * as jose from 'jose';
import signature from 'cookie-signature';
import Stripe from 'stripe';
import v8 from 'node:v8';
import fs from 'node:fs';

const env = process.env;
const results = {};

// 1. raw node:crypto via ESM named import
results.rawHmac = createHmac('sha256', env.JWT_SECRET).update('hello').digest('hex');

// 2. jsonwebtoken (CJS, crypto.createHmac under the hood)
const t1 = jwt.sign({ sub: 'user1', role: 'admin' }, env.JWT_SECRET, { algorithm: 'HS256', noTimestamp: true });
results.jsonwebtoken = t1;
results.jsonwebtokenVerify = jwt.verify(t1, env.JWT_SECRET).sub;

// 3. jose (WebCrypto subtle.importKey + subtle.sign)
const key = new TextEncoder().encode(env.JWT_SECRET);
const t2 = await new jose.SignJWT({ sub: 'user1', role: 'admin' }).setProtectedHeader({ alg: 'HS256' }).sign(key);
results.jose = t2;
results.joseVerify = (await jose.jwtVerify(t2, key)).payload.sub;

// 4. cookie-signature (express-session / cookie-parser use this)
const signed = signature.sign('session-id-123', env.COOKIE_SECRET);
results.cookie = signed;
results.cookieUnsign = signature.unsign(signed, env.COOKIE_SECRET);

// 5. Stripe webhook verification, sync (createHmac) and async (SubtleCrypto)
const stripe = new Stripe('sk_test_dummy');
const payload = JSON.stringify({ id: 'evt_1', type: 'payment_intent.succeeded' });
const header = fs.readFileSync('./stripe_header.txt', 'utf8').trim(); // produced by the "real Stripe" (oracle)
results.stripeSync = stripe.webhooks.constructEvent(payload, header, env.STRIPE_WEBHOOK_SECRET).type;
results.stripeAsync = (await stripe.webhooks.constructEventAsync(payload, header, env.STRIPE_WEBHOOK_SECRET, undefined, Stripe.createSubtleCryptoProvider())).type;

// 6. Auth.js-style key derivation: HKDF from AUTH_SECRET, then AES-GCM (WebCrypto)
const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.AUTH_SECRET), 'HKDF', false, ['deriveBits']);
const derived = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('session-enc') }, base, 256);
const aes = await crypto.subtle.importKey('raw', derived, 'AES-GCM', false, ['encrypt', 'decrypt']);
const iv = new Uint8Array(12);
const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aes, new TextEncoder().encode('{"user":"alice"}'));
results.aesCiphertext = Buffer.from(ct).toString('base64');
results.aesRoundTrip = new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aes, ct));
results.derivedBytesSeenByApp = Buffer.from(derived).toString('latin1').slice(0, 24) + '…';

// 7. What can a curious agent see from inside the app process?
results.envJwtSecret = env.JWT_SECRET;
v8.writeHeapSnapshot('/tmp/app.heapsnapshot');
fs.writeFileSync('/tmp/app.environ', fs.readFileSync('/proc/self/environ'));
fs.writeFileSync('/tmp/app.results.json', JSON.stringify(results, null, 2));
console.log(JSON.stringify(results, null, 2));
