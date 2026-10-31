// `doppelkey mcp`: JSON-RPC over stdio. Tools return names and health only, never values.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { ROOT, tmpdir, startKeeper, vault, real } from '../lib/harness.mjs';

const BIN = path.join(ROOT, 'target/debug/doppelkey');
const missing = !fs.existsSync(BIN) && 'build the CLI first: cargo build';

test('initialize, list tools, call each tool; no values leak', { skip: missing }, async () => {
  const keeper = await startKeeper();
  const dir = tmpdir('dk-mcp');
  fs.mkdirSync(path.join(dir, '.doppelkey'));
  fs.writeFileSync(path.join(dir, '.doppelkey/manifest.json'), JSON.stringify({ version: 1, secrets: [{ name: 'JWT_SECRET', file: '.env', id: vault.keys.JWT_SECRET.id }], files: [] }));
  const msgs = [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '0' } } },
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { jsonrpc: '2.0', id: 2, method: 'tools/list' },
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'status', arguments: {} } },
    { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'list_secrets', arguments: {} } },
    { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'doctor', arguments: {} } },
    { jsonrpc: '2.0', id: 6, method: 'nope' },
  ];
  const r = spawnSync(BIN, ['mcp'], { cwd: dir, input: msgs.map((m) => JSON.stringify(m)).join('\n') + '\n', encoding: 'utf8', env: { PATH: process.env.PATH, HOME: dir, DOPPELKEY_SOCK: keeper.sock, DOPPELKEY_HOME: path.join(dir, 'dk') } });
  await keeper.stop();
  const out = r.stdout.trim().split('\n').map((l) => JSON.parse(l));
  assert.equal(out.length, 6, 'one reply per request, none for the notification');
  assert.equal(out[0].result.serverInfo.name, 'doppelkey');
  assert.deepEqual(out[1].result.tools.map((t) => t.name).sort(), ['doctor', 'list_secrets', 'status']);
  assert.match(out[2].result.content[0].text, /JWT_SECRET/);
  assert.match(out[3].result.content[0].text, /^JWT_SECRET \(\.env\)$/);
  assert.match(out[4].result.content[0].text, /keeper running/);
  assert.equal(out[5].error.code, -32601);
  for (const k of Object.keys(vault.keys)) assert.ok(!r.stdout.includes(real(k).toString('latin1')), `${k} value leaked`);
});
