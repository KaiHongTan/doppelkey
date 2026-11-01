// Libraries that compute crypto in ways a naive shim misses (see docs/research.md).
import { encode as nextAuthEncode, decode as nextAuthDecode } from 'next-auth/jwt';
import { sealData, unsealData } from 'iron-session';
import { Webhook } from 'svix';
import { hmac as nobleHmac } from '@noble/hashes/hmac.js';
import { hkdf as nobleHkdf, extract as nobleExtract } from '@noble/hashes/hkdf.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { hmac as osloHmac } from '@oslojs/crypto/hmac';
import { SHA256 } from '@oslojs/crypto/sha2';
import { sign as octoSign, verify as octoVerify } from '@octokit/webhooks-methods';
import { sign as honoSign, verify as honoVerify } from 'hono/jwt';
import { attempt, finish, results } from './_finish.mjs';

const env = process.env, te = new TextEncoder(), hex = (u) => Buffer.from(u).toString('hex');

await attempt('nextAuthV4', () => nextAuthEncode({ token: { sub: 'user1', name: 'Alice' }, secret: env.AUTH_SECRET }));
await attempt('nextAuthV4Decode', async () => (await nextAuthDecode({ token: results.nextAuthV4, secret: env.AUTH_SECRET }))?.name);

await attempt('ironSeal', () => sealData({ user: 'alice' }, { password: env.SESSION_PASSWORD, ttl: 0 }));
await attempt('ironUnseal', async () => (await unsealData(results.ironSeal, { password: env.SESSION_PASSWORD, ttl: 0 }))?.user);

const wh = new Webhook(env.SVIX_SECRET);
await attempt('svixSign', () => wh.sign('msg_1', new Date(1700000000000), '{"a":1}'));
await attempt('svixVerifyReal', () => { wh.verify(env.SVIX_PAYLOAD, JSON.parse(env.SVIX_HEADERS)); return 'verified'; });
await attempt('svixForged', () => { wh.verify(env.SVIX_PAYLOAD.replace('created', 'deleted'), JSON.parse(env.SVIX_HEADERS)); return 'verified'; });

await attempt('nobleHmac', () => hex(nobleHmac(sha256, te.encode(env.JWT_SECRET), te.encode('hello'))));
await attempt('nobleHmacStream', () => hex(nobleHmac.create(sha512, te.encode(env.JWT_SECRET)).update(te.encode('hel')).update(te.encode('lo')).digest()));
await attempt('nobleHkdfThenHmac', () => hex(nobleHmac(sha256, nobleHkdf(sha256, te.encode(env.AUTH_SECRET), te.encode('salt'), te.encode('info'), 32), te.encode('hello'))));
await attempt('nobleExtract', () => nobleExtract(sha256, te.encode(env.AUTH_SECRET), te.encode('salt')));
await attempt('noblePlain', () => hex(nobleHmac(sha256, te.encode('plain'), te.encode('hello'))));

await attempt('osloHmac', () => hex(osloHmac(SHA256, te.encode(env.JWT_SECRET), te.encode('hello'))));

await attempt('octokit', () => octoSign(env.COOKIE_SECRET, '{"action":"opened"}'));
await attempt('octokitVerify', () => octoVerify(env.COOKIE_SECRET, '{"action":"opened"}', results.octokit));

await attempt('hono', () => honoSign({ sub: 'user1' }, env.JWT_SECRET, 'HS256'));
await attempt('honoVerify', async () => (await honoVerify(results.hono, env.JWT_SECRET, 'HS256')).sub);
results.adapters = globalThis[Symbol.for('doppelkey.shim')].adapters;
finish();
