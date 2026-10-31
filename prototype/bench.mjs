import { createHmac } from 'node:crypto';
const s = process.env.JWT_SECRET; const N = 2000;
let t = performance.now(); for (let i = 0; i < N; i++) createHmac('sha256', s).update('x' + i).digest('hex');
console.log('handle HMAC: ' + ((performance.now() - t) / N * 1000).toFixed(0) + ' µs/op');
t = performance.now(); for (let i = 0; i < N; i++) createHmac('sha256', 'plain-local-key').update('x' + i).digest('hex');
console.log('normal HMAC: ' + ((performance.now() - t) / N * 1000).toFixed(1) + ' µs/op');
