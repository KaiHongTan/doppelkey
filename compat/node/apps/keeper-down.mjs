import { createHmac } from 'node:crypto';
import { attempt, finish } from './_finish.mjs';
await attempt('hmac', () => createHmac('sha256', process.env.JWT_SECRET).update('x').digest('hex'));
await attempt('subtle', async () => {
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(process.env.JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return crypto.subtle.sign('HMAC', k, new Uint8Array(1));
});
finish();
