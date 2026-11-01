// Writes crates/proto/vectors/handles.json: inputs as an app would pass them as a key, and
// what a shim must recognise. Run after changing the handle format; Rust, Node and Python tests read it.
import fs from 'node:fs';
import { longCore, compactCore, crc } from './handles.mjs';

const id1 = 'a1b2c3d4e5f6', id2 = '0123456789ab';
const v = (input, expect, note) => ({ input, ...expect, note });
const ok = (handle, prefix = '', keyEncoding = null, ids) => ({ valid: true, handle, prefix, key_encoding: keyEncoding, ids });
const no = { valid: false };
const half = (id) => compactCore(id).padEnd(32, '.');
const vectors = [
  v(longCore(id1), ok(longCore(id1), '', null, [id1]), 'long form'),
  v(longCore(id1) + '....', ok(longCore(id1) + '....', '', null, [id1]), 'long form, padded'),
  v(compactCore(id1), ok(compactCore(id1), '', null, [id1]), 'compact form (20 bytes, fits SHA-1-derived keys)'),
  v(half(id1), ok(half(id1), '', null, [id1]), 'compact, padded to 32 bytes (AES-256 key)'),
  v(half(id1) + half(id2), ok(half(id1) + half(id2), '', null, [id1, id2]), 'split-half: 64-byte key as two handles'),
  v('whsec_' + longCore(id1), ok(longCore(id1), 'whsec_', null, [id1]), 'vendor prefix'),
  v('AWS4' + longCore(id1), ok(longCore(id1), 'AWS4', null, [id1]), 'SigV4 key-schedule prefix'),
  v('12345678' + longCore(id1), ok(longCore(id1), '12345678', null, [id1]), 'prefix of 8 bytes (maximum)'),
  v(Buffer.from(half(id1)).toString('hex'), ok(half(id1), '', 'hex', [id1]), 'hex text of a compact handle'),
  v(Buffer.from(half(id1)).toString('base64'), ok(half(id1), '', 'base64', [id1]), 'base64 text of a compact handle'),
  v('whsec_' + Buffer.from(half(id1)).toString('base64'), ok(half(id1), 'whsec_', 'base64', [id1]), 'vendor prefix + base64 handle (svix and Stripe whsec_ secrets)'),
  v('123456789' + longCore(id1), no, 'prefix longer than 8 bytes'),
  v('123456789' + Buffer.from(half(id1)).toString('hex'), no, 'prefix longer than 8 bytes before an encoded handle'),
  v(longCore(id1).slice(0, -4) + (crc(id1) === '0000' ? '0001' : '0000'), no, 'bad checksum'),
  v(longCore(id1).toUpperCase(), no, 'uppercase'),
  v(longCore(id1) + 'x', no, 'trailing garbage'),
  v(longCore(id1) + ' ', no, 'trailing space'),
  v(`dk1:NOT-A-SECRET-load-doppelkey-shim:${id1.slice(0, 11)}:${crc(id1)}`, no, 'short id'),
  v(`dk1:NOT-A-SECRET-load-doppelkey-shimX${id1}:${crc(id1)}`, no, 'label typo'),
  v('dk1:', no, 'marker only'),
  v('real-jwt-secret-3f9c1e7a5b2d8c4e6f1a9b3d7e5c2a8f', no, 'an ordinary secret'),
  v('KH1:a1b2c3d4e5f60718.......................', no, 'an old KH1-style handle is not a v1 handle'),
];
fs.mkdirSync(new URL('../../crates/proto/vectors/', import.meta.url), { recursive: true });
fs.writeFileSync(new URL('../../crates/proto/vectors/handles.json', import.meta.url), JSON.stringify({ format: 'doppelkey handle vectors v1', spec: 'docs/protocol.md', vectors }, null, 2) + '\n');
console.log(`wrote ${vectors.length} vectors`);
