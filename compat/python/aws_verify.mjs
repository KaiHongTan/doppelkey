// Verify AWS signatures from the Python app with the real secret (reads JSON on stdin).
import { verifyAws } from '../node/lib/aws-oracle.mjs';
const input = JSON.parse(await new Promise((r) => { let s = ''; process.stdin.on('data', (d) => (s += d)); process.stdin.on('end', () => r(s)); }));
const secret = process.env.REAL_AWS_SECRET;
console.log(JSON.stringify(input.map((req) => { const v = verifyAws(secret, req); return { ok: v.ok, scope: v.scope, keys: Object.values(v.keys || {}).map((k) => k.toString('hex')) }; })));
