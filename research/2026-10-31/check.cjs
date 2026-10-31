const jwt = require('jsonwebtoken'); const J = 'real-jwt-secret-3f9c1e7a5b2d8c4e6f1a9b3d7e5c2a8f';
const c = require('crypto');
for (const [k, v] of Object.entries(JSON.parse(process.argv[2]))) {
  if (k === 'raw') { console.log(k, v === c.createHmac('sha256', J).update('hello').digest('hex')); continue; }
  try { console.log(k, 'valid under real key:', jwt.verify(v, J).sub); } catch (e) { console.log(k, 'INVALID under real key:', e.message); }
}
