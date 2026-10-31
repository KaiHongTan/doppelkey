import { createHmac } from 'node:crypto';
const N = 300000, key = 'plain-local-key-0123456789abcdef'; let best = Infinity;
for (let r = 0; r < 7; r++) { const t = performance.now(); for (let i = 0; i < N; i++) createHmac('sha256', key).update('x' + i).digest('hex'); best = Math.min(best, (performance.now() - t) / N * 1e3); }
const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
let t = performance.now(); for (let i = 0; i < 50000; i++) await crypto.subtle.sign('HMAC', k, new TextEncoder().encode('x' + i));
console.log(`createHmac ${best.toFixed(3)} µs/op, subtle.sign ${((performance.now() - t) / 50000 * 1e3).toFixed(3)} µs/op`);
