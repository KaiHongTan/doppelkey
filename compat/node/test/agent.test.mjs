// Milestone 4 acceptance, automated: after `doppelkey init`, an agent running as the same user
// can run the app, but none of the things a curious or prompt-injected agent would try reveal a
// real secret. (The memory checks need a non-root user: root bypasses PR_SET_DUMPABLE.)
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { ROOT, tmpdir } from '../lib/harness.mjs';
import { connect } from '../lib/client.mjs';

const BIN = path.join(ROOT, 'target/debug');
const missing = !fs.existsSync(path.join(BIN, 'doppelkey')) && 'build the CLI first: cargo build';
const SECRETS = { JWT_SECRET: 'agent-test-jwt-secret-value-0123456789', STRIPE_WEBHOOK_SECRET: 'whsec_agentTestWebhookSecret0123456789AB' };
let dir, home, env;
const sh = (cmd, args, extra = {}) => spawnSync(cmd, args, { cwd: dir, env: { ...env, ...extra }, encoding: 'utf8' });
const leaks = (text) => Object.values(SECRETS).filter((s) => text.includes(s) || text.includes(Buffer.from(s).toString('base64').slice(0, 20)));

before(() => {
  if (missing) return;
  dir = tmpdir('dk-agent-project');
  home = tmpdir('dk-agent-home');
  fs.writeFileSync(path.join(dir, '.env'), Object.entries(SECRETS).map(([k, v]) => `${k}=${v}`).join('\n') + '\n');
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'a', private: true, scripts: { test: 'node test.js' } }));
  fs.writeFileSync(path.join(dir, 'test.js'), `const fs=require('fs'),c=require('crypto');for(const l of fs.readFileSync('.env','utf8').split('\\n')){const m=l.match(/^(\\w+)=(.*)$/);if(m)process.env[m[1]]=m[2]}
console.log(c.createHmac('sha256',process.env.JWT_SECRET).update('t').digest('hex'))`);
  env = { PATH: `${BIN}:${process.env.PATH}`, HOME: home, DOPPELKEY_HOME: path.join(home, 'dk'), DOPPELKEY_SOCK: path.join(home, 'k.sock'), DOPPELKEY_PASSPHRASE: 'human-only passphrase', DOPPELKEY_SERVICE: 'detached',
    // The keeper inherits this at start: the human says no to every confirmation.
    DOPPELKEY_ASKPASS: 'false' };
  const init = sh('doppelkey', ['init', '--yes']);
  if (init.status !== 0) throw new Error(init.stdout + init.stderr);
  delete env.DOPPELKEY_PASSPHRASE; // the agent doesn't know it
});
after(() => { if (!missing) spawnSync(path.join(BIN, 'doppelkey'), ['service', 'uninstall'], { env, encoding: 'utf8' }); });

test('the agent can run the app and its tests', { skip: missing }, () => {
  const r = sh('npm', ['test', '-s']);
  assert.equal(r.status, 0, r.stderr);
  const want = spawnSync('node', ['-e', `console.log(require('crypto').createHmac('sha256',${JSON.stringify(SECRETS.JWT_SECRET)}).update('t').digest('hex'))`], { encoding: 'utf8' }).stdout;
  assert.equal(r.stdout, want);
});

test('reading .env, printing the environment, or grepping the project reveals no secret', { skip: missing }, () => {
  assert.deepEqual(leaks(fs.readFileSync(path.join(dir, '.env'), 'utf8')), []);
  assert.deepEqual(leaks(sh('node', ['-e', 'require("fs").readFileSync(".env","utf8").split("\\n").forEach(l=>{const m=l.match(/^(\\w+)=(.*)$/);if(m)process.env[m[1]]=m[2]});console.log(JSON.stringify(process.env))']).stdout), []);
  assert.deepEqual(leaks(sh('grep', ['-r', '-a', '', dir]).stdout), []);
});

test('the vault is encrypted and the passphrase is needed to open it', { skip: missing }, () => {
  const raw = fs.readFileSync(path.join(home, 'dk/vault.dk'), 'latin1');
  assert.deepEqual(leaks(raw), []);
  const p = sh('doppelkey', ['policy']);
  assert.notEqual(p.status, 0);
  assert.match(p.stderr, /passphrase/);
});

test('eject and policy loosening are refused without a human, even if the agent sets DOPPELKEY_ASKPASS', { skip: missing }, () => {
  const e = sh('doppelkey', ['eject'], { DOPPELKEY_ASKPASS: 'true' });
  assert.notEqual(e.status, 0);
  assert.equal(fs.readFileSync(path.join(dir, '.env'), 'utf8').includes(SECRETS.JWT_SECRET), false);
  const pol = sh('doppelkey', ['policy', 'JWT_SECRET', '--allow', 'aes_gcm'], { DOPPELKEY_PASSPHRASE: 'human-only passphrase', DOPPELKEY_ASKPASS: 'true' });
  assert.notEqual(pol.status, 0);
  assert.match(pol.stderr, /needs a human/);
});

test('the keeper has no export: unknown and export-like ops are refused', { skip: missing }, async () => {
  const c = await connect(env.DOPPELKEY_SOCK);
  const handle = fs.readFileSync(path.join(dir, '.env'), 'utf8').match(/JWT_SECRET=(.*)/)[1];
  for (const op of ['export', 'get', 'read', 'dump', 'key', 'value']) {
    const r = await c.request({ op, handle });
    assert.equal(r.ok, false);
    assert.deepEqual(leaks(JSON.stringify(r)), []);
  }
  c.close();
});

test('MCP tools and status give names only', { skip: missing }, () => {
  const s = sh('doppelkey', ['status']);
  assert.match(s.stdout, /JWT_SECRET/);
  assert.deepEqual(leaks(s.stdout + s.stderr), []);
  const m = spawnSync(path.join(BIN, 'doppelkey'), ['mcp'], { cwd: dir, env, encoding: 'utf8', input: ['initialize', 'tools/list'].map((method, i) => JSON.stringify({ jsonrpc: '2.0', id: i + 1, method, params: {} })).concat(['status', 'list_secrets', 'doctor'].map((name, i) => JSON.stringify({ jsonrpc: '2.0', id: 10 + i, method: 'tools/call', params: { name } }))).join('\n') + '\n' });
  assert.deepEqual(leaks(m.stdout), []);
});

test("the keeper's memory and environment are unreadable", { skip: missing || (process.platform !== 'linux' && 'Linux only') || (process.getuid() === 0 && 'root bypasses this; CI runs it as a normal user') }, () => {
  const pid = Number(fs.readFileSync(path.join(home, 'dk/doppelkeyd.pid'), 'utf8'));
  for (const f of ['mem', 'environ', 'maps']) assert.throws(() => fs.readFileSync(`/proc/${pid}/${f}`), /EACCES|EPERM/, f);
});
