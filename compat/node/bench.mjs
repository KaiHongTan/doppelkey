// Overhead of the shim when no handle is involved: createHmac and subtle.sign with plain keys.
// Usage: node bench.mjs            (spawns itself with and without the shim and compares)
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { SHIM } from './lib/harness.mjs';

export function measure() {
  const { createHmac } = globalThis.process.getBuiltinModule('node:crypto');
  const N = 200000, key = 'plain-local-key-0123456789abcdef';
  let best = Infinity;
  for (let r = 0; r < 7; r++) {
    const t = performance.now();
    for (let i = 0; i < N; i++) createHmac('sha256', key).update('x' + i).digest('hex');
    best = Math.min(best, ((performance.now() - t) / N) * 1e3);
  }
  return best;
}
if (process.argv[2] === '--child') {
  console.log(JSON.stringify({ usPerHmac: measure() }));
} else {
  const self = fileURLToPath(import.meta.url);
  const run = (pre) => JSON.parse(spawnSync(process.execPath, [...pre, self, '--child'], { encoding: 'utf8' }).stdout).usPerHmac;
  const res = { plain: [], shim: [] };
  for (let i = 0; i < 5; i++) { res.plain.push(run([])); res.shim.push(run(['--require', SHIM])); }
  const plain = Math.min(...res.plain), shim = Math.min(...res.shim);
  const out = { node: process.version, plainUsPerHmac: +plain.toFixed(3), shimUsPerHmac: +shim.toFixed(3), overheadUs: +(shim - plain).toFixed(3), ratio: +(shim / plain).toFixed(3) };
  console.log(JSON.stringify(out));
}
