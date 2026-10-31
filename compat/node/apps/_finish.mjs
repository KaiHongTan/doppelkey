// Shared by every app: record a result (or the error), then write results, and on request a
// heap snapshot and a copy of /proc/self/environ for the oracle to scan.
import fs from 'node:fs';
import v8 from 'node:v8';

export const results = { errors: {} };
export async function attempt(name, fn) {
  try { results[name] = await fn(); } catch (e) { results.errors[name] = String(e && e.message); }
}
export function finish() {
  if (process.env.DOPPELKEY_HEAP && typeof v8.writeHeapSnapshot === 'function' && !process.versions.bun) v8.writeHeapSnapshot(process.env.DOPPELKEY_HEAP);
  if (process.env.DOPPELKEY_ENVIRON && fs.existsSync('/proc/self/environ')) fs.writeFileSync(process.env.DOPPELKEY_ENVIRON, fs.readFileSync('/proc/self/environ'));
  fs.writeFileSync(process.env.DOPPELKEY_RESULTS, JSON.stringify(results, null, 2));
}
