import { createHmac } from 'node:crypto';
try { createHmac('sha256', process.env.AUTH_SECRET).update('x').digest('hex'); console.log('UNEXPECTED: hmac with hkdf-only key worked'); }
catch (e) { console.log('policy refusal OK ->', e.message); }
