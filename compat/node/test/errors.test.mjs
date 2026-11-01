// Fail closed, and say what to do.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import path from 'node:path';
import { runApp, tmpdir } from '../lib/harness.mjs';

test('keeper not running: crypto with a handle fails and names "doppelkey doctor"', () => {
  const sock = path.join(tmpdir(), 'missing.sock');
  const r = runApp('keeper-down.mjs', { env: { DOPPELKEY_SOCK: sock } }).results;
  assert.equal(r.errors.hmac, `doppelkey: keeper not running (no keeper at ${sock}). Run "doppelkey doctor".`);
  assert.equal(r.errors.subtle, r.errors.hmac);
});

test('keeper not answering: times out and names "doppelkey doctor"', async () => {
  const sock = path.join(tmpdir(), 'silent.sock');
  const server = net.createServer(() => {}).listen(sock);
  await new Promise((res) => server.once('listening', res));
  try {
    const r = await new Promise((res) => setImmediate(() => res(runApp('keeper-down.mjs', { env: { DOPPELKEY_SOCK: sock, DOPPELKEY_TIMEOUT_MS: '300' } }).results)));
    assert.equal(r.errors.hmac, 'doppelkey: keeper did not answer within 300 ms. Run "doppelkey doctor".');
  } finally { server.close(); }
});
