// Handle format v1 (docs/protocol.md), written independently of the shim's TypeScript so the
// two implementations cross-check each other. Used by the test keeper and the compat harness.
import crypto from 'node:crypto';

export const LABEL = 'NOT-A-SECRET-load-doppelkey-shim';
export const crc = (id) => crypto.createHash('sha256').update('dk1:' + id).digest('hex').slice(0, 4);
export const longCore = (id) => `dk1:${LABEL}:${id}:${crc(id)}`;
export const compactCore = (id) => `dk1:${id}${crc(id)}`;
export const newId = () => crypto.randomBytes(6).toString('hex');

/** Split a handle string (padded cores back to back, no prefix) into ids. Null if invalid. */
export function parseHandle(s) {
  if (typeof s !== 'string') return null;
  const ids = [];
  let i = 0;
  while (i < s.length) {
    if (!s.startsWith('dk1:', i)) return null;
    i += 4;
    let id, sum;
    if (s.startsWith(LABEL + ':', i)) {
      i += LABEL.length + 1;
      id = s.slice(i, i + 12); i += 12;
      if (s[i] !== ':') return null;
      i += 1;
    } else {
      id = s.slice(i, i + 12); i += 12;
    }
    sum = s.slice(i, i + 4); i += 4;
    if (!/^[0-9a-f]{12}$/.test(id) || !/^[0-9a-f]{4}$/.test(sum) || crc(id) !== sum) return null;
    while (s[i] === '.') i++;
    ids.push(id);
  }
  return ids.length ? ids : null;
}

/** Real key bytes of a vault entry. */
export const keyBytes = (e) => (e.value_b64 !== undefined ? Buffer.from(e.value_b64, 'base64') : Buffer.from(e.value, 'utf8'));

/** What goes into .env for a vault entry (what `doppelkey protect` would write). */
export function envValue(e) {
  const prefix = e.prefix ?? '';
  const len = keyBytes(e).length - (e.form === 'hex' || e.form === 'base64' ? 0 : prefix.length);
  const form = e.form ?? 'long';
  if (form === 'long') return prefix + (e.pad ? longCore(e.id).padEnd(len, '.') : longCore(e.id));
  const core = compactCore(e.id);
  if (len < core.length) throw new Error(`${e.id}: secret too short (${len} bytes) to hold a handle`);
  const padded = core.padEnd(len, '.');
  if (form === 'compact') return prefix + padded;
  if (form === 'hex') return prefix + Buffer.from(padded, 'latin1').toString('hex');
  if (form === 'base64') return prefix + Buffer.from(padded, 'latin1').toString('base64');
  throw new Error(`unknown form ${form}`);
}
