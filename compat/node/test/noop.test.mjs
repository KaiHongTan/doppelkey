// With no handles present the shim is a no-op: identical results, no worker thread, no measurable cost.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { runApp, ROOT } from '../lib/harness.mjs';

test('results are identical with and without the shim, and the keeper worker never starts', () => {
  const withShim = runApp('noop.mjs', { handles: false });
  const without = runApp('noop.mjs', { handles: false, shim: false });
  assert.deepEqual(withShim.results.errors, {});
  const strip = ({ shim, ...rest }) => rest;
  assert.deepEqual(strip(withShim.results), strip(without.results));
  assert.equal(withShim.results.shim.loaded, true);
  assert.equal(withShim.results.shim.workerStarted, false);
  assert.equal(withShim.results.shim.calls, 0);
  assert.equal(withShim.stderr, '', 'no warnings without handles');
});

test('DOPPELKEY_SHIM=off disables the shim entirely', () => {
  const r = runApp('noop.mjs', { handles: false, env: { DOPPELKEY_SHIM: 'off' } });
  assert.equal(r.results.shim.loaded, false);
});

test('benchmark: createHmac overhead with a plain key is negligible', (t) => {
  const r = spawnSync(process.execPath, [path.join(ROOT, 'compat/node/bench.mjs')], { encoding: 'utf8' });
  const b = JSON.parse(r.stdout);
  t.diagnostic(JSON.stringify(b));
  // Lenient bound so CI noise does not flake; locally the overhead is 0-0.1 µs (ratio ~1.0-1.1).
  assert.ok(b.ratio < 1.5, `shim makes createHmac ${b.ratio}x slower`);
});
