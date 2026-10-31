import { encode, decode } from '@auth/core/jwt';
import fs from 'node:fs';
const secret = process.env.AUTH_SECRET, salt = 'authjs.session-token';
const token = await encode({ token: { sub: 'user1', name: 'Alice' }, secret, salt });
const back = await decode({ token, secret, salt });
console.log(JSON.stringify({ tokenPrefix: token.slice(0, 40) + '…', decodedName: back?.name }));
fs.writeFileSync('/tmp/authjs.token', token);
