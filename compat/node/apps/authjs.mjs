// Auth.js (@auth/core) session token encode/decode, unchanged.
import { encode, decode } from '@auth/core/jwt';
import { createHash } from 'node:crypto';
import { attempt, finish, results } from './_finish.mjs';
const secret = process.env.AUTH_SECRET, salt = 'authjs.session-token';
await attempt('token', () => encode({ token: { sub: 'user1', name: 'Alice' }, secret, salt }));
await attempt('decoded', async () => (await decode({ token: results.token, secret, salt }))?.name);
// Ordinary hashing still works and isn't routed anywhere.
await attempt('plainHash', () => createHash('sha256').update('hello').digest('hex'));
await attempt('plainThumbprintLike', () => createHash('sha256').update('{"k":"AAAA","kty":"oct"}').digest('hex'));
// Hash-based key derivation from a handle returns a handle (stays in the keeper).
await attempt('derivedHandle', () => createHash('sha256').update('salt').update(process.env.JWT_SECRET).digest().toString('latin1'));
finish();
