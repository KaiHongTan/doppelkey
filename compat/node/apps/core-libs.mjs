// Core libraries (JWT, cookies, Stripe, AWS), used exactly as their docs say. Nothing here knows about doppelkey.
import { createHmac, createHash } from 'node:crypto'; // ESM named import (tests syncBuiltinESMExports)
import { Readable } from 'node:stream';
import jwt from 'jsonwebtoken';
import * as jose from 'jose';
import signature from 'cookie-signature';
import Stripe from 'stripe';
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { DynamoDBClient, ListTablesCommand } from '@aws-sdk/client-dynamodb';
import { attempt, finish, results } from './_finish.mjs';

const env = process.env;
await attempt('rawHmac', () => createHmac('sha256', env.JWT_SECRET).update('hello').digest('hex'));

await attempt('jsonwebtoken', () => jwt.sign({ sub: 'user1', role: 'admin' }, env.JWT_SECRET, { algorithm: 'HS256', noTimestamp: true }));
await attempt('jsonwebtokenVerify', () => jwt.verify(results.jsonwebtoken, env.JWT_SECRET).sub);
await attempt('jsonwebtokenHS512', () => jwt.sign({ sub: 'user1' }, env.JWT_SECRET, { algorithm: 'HS512', noTimestamp: true }));

const key = new TextEncoder().encode(env.JWT_SECRET);
await attempt('jose', () => new jose.SignJWT({ sub: 'user1', role: 'admin' }).setProtectedHeader({ alg: 'HS256' }).sign(key));
await attempt('joseVerify', async () => (await jose.jwtVerify(results.jose, key)).payload.sub);

await attempt('cookie', () => signature.sign('session-id-123', env.COOKIE_SECRET));
await attempt('cookieUnsign', () => signature.unsign(results.cookie, env.COOKIE_SECRET));
await attempt('cookieTampered', () => signature.unsign(results.cookie.replace(/.$/, (c) => (c === 'A' ? 'B' : 'A')), env.COOKIE_SECRET));

const stripe = new Stripe('sk_test_dummy');
const payload = env.STRIPE_PAYLOAD, header = env.STRIPE_HEADER;
await attempt('stripeSync', () => stripe.webhooks.constructEvent(payload, header, env.STRIPE_WEBHOOK_SECRET).type);
await attempt('stripeAsync', async () => (await stripe.webhooks.constructEventAsync(payload, header, env.STRIPE_WEBHOOK_SECRET, undefined, Stripe.createSubtleCryptoProvider())).type);
await attempt('stripeB64Form', () => stripe.webhooks.constructEvent(payload, env.STRIPE_HEADER_B64, env.STRIPE_WEBHOOK_SECRET_B64).type);
await attempt('stripeForged', async () => (await stripe.webhooks.constructEventAsync(payload.replace('succeeded', 'failed'), header, env.STRIPE_WEBHOOK_SECRET, undefined, Stripe.createSubtleCryptoProvider())).type);

// AWS SDK v3: a stub request handler captures signed requests; nothing is sent to AWS.
const captured = [];
const requestHandler = {
  async handle(req) {
    const q = new URLSearchParams(req.query || {}).toString();
    captured.push({ method: req.method, url: `${req.protocol}//${req.hostname}${req.path}${q ? '?' + q : ''}`, headers: req.headers,
      bodySha256: createHash('sha256').update(typeof req.body === 'string' ? req.body : Buffer.from(req.body || '')).digest('hex') });
    return { response: { statusCode: 200, headers: { etag: '"x"' }, body: Readable.from([]) } };
  },
};
const s3 = new S3Client({ requestHandler });
await attempt('s3Put', async () => { await s3.send(new PutObjectCommand({ Bucket: 'doppelkey-test', Key: 'hello.txt', Body: 'hello from doppelkey' })); return 'sent'; });
await attempt('s3Presigned', () => getSignedUrl(s3, new GetObjectCommand({ Bucket: 'doppelkey-test', Key: 'hello.txt' }), { expiresIn: 600 }));
results.s3Requests = captured.slice();
await attempt('dynamodb', async () => { await new DynamoDBClient({ requestHandler }).send(new ListTablesCommand({})); return 'signed'; });

results.envJwtSecret = env.JWT_SECRET;
finish();
