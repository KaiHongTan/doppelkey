// After `doppelkey init`, an agent running as the same user can run the app, but nothing a
// curious or prompt-injected agent would try reveals a real secret. (The memory checks need a
// non-root user: root bypasses PR_SET_DUMPABLE.)
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
// Run a command under a pseudo-terminal, typing `input`: what an agent can do to look interactive.
const hasScript = spawnSync('script', ['--version']).error === undefined || process.platform === 'darwin';
const pty = (command, input) => spawnSync('script', process.platform === 'darwin' ? ['-q', '/dev/null', 'sh', '-c', command] : ['-qfec', command, '/dev/null'], { cwd: dir, env, input, encoding: 'utf8', timeout: 30000 });
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

test('the vault is encrypted, and the CLI shows names and policies but never values', { skip: missing }, () => {
  const raw = fs.readFileSync(path.join(home, 'dk/vault.dk'), 'latin1');
  assert.deepEqual(leaks(raw), []);
  const p = sh('doppelkey', ['policy']);
  assert.equal(p.status, 0, p.stderr);
  assert.match(p.stdout, /JWT_SECRET/);
  assert.deepEqual(leaks(p.stdout + p.stderr), []);
});

const envIntact = () => assert.equal(fs.readFileSync(path.join(dir, '.env'), 'utf8').includes(SECRETS.JWT_SECRET), false, 'no real value written back');

test('eject and policy loosening are refused without a human, even if the agent sets DOPPELKEY_ASKPASS', { skip: missing }, () => {
  const e = sh('doppelkey', ['eject'], { DOPPELKEY_ASKPASS: 'true' });
  assert.notEqual(e.status, 0);
  assert.match(e.stderr, /needs a human/);
  envIntact();
  const pol = sh('doppelkey', ['policy', 'JWT_SECRET', '--allow', 'aes_gcm'], { DOPPELKEY_ASKPASS: 'true' });
  assert.notEqual(pol.status, 0);
  assert.match(pol.stderr, /needs a human/);
});

test('a pseudo-terminal does not make the agent a human: eject and loosening still need the passphrase', { skip: missing || (!hasScript && 'no script(1)') }, () => {
  for (const input of ['y\n', 'yes\n', 'not the passphrase\n']) {
    const e = pty('doppelkey eject', input);
    assert.match(e.stdout + e.stderr, /refused/, `eject with input ${JSON.stringify(input)}`);
    envIntact();
  }
  const pol = pty('doppelkey policy JWT_SECRET --allow aes_gcm --no-rate --no-confirm', 'y\n');
  assert.match(pol.stdout + pol.stderr, /not changed/);
  const after = sh('doppelkey', ['policy', 'JWT_SECRET']);
  assert.doesNotMatch(after.stdout, /aes_gcm/, 'policy unchanged');
});

test('the keeper drops keys only after an approved eject, and tightening needs no approval', { skip: missing }, async () => {
  const id = fs.readFileSync(path.join(dir, '.env'), 'utf8').match(/JWT_SECRET=dk1:NOT-A-SECRET-load-doppelkey-shim:([0-9a-f]{12})/)[1];
  const c = await connect(env.DOPPELKEY_SOCK);
  const f = await c.request({ op: 'forget', ids: [id] });
  assert.equal(f.ok, false);
  assert.equal(f.error.code, 'op_not_allowed');
  const ej = await c.request({ op: 'eject', ids: [id], passphrase: 'a guess' });
  assert.equal(ej.ok, false);
  assert.equal(ej.error.code, 'confirm_denied');
  assert.deepEqual(leaks(JSON.stringify(ej)), []);
  c.close();
  const t = sh('doppelkey', ['policy', 'JWT_SECRET', '--rate', '1000']);
  assert.equal(t.status, 0, t.stderr);
  assert.match(t.stdout, /rate_per_minute = 1000/);
  assert.equal(sh('npm', ['test', '-s']).status, 0, 'the app still works');
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

// Last, because it ejects. With the human's passphrase the keeper restores .env itself; the
// reply on the socket still holds no key material (the keeper has no export, even for eject).
test('an approved eject: the keeper writes the files itself and its reply holds no key material', { skip: missing }, async () => {
  const text = fs.readFileSync(path.join(dir, '.env'), 'utf8');
  const ids = [...text.matchAll(/:([0-9a-f]{12}):/g)].map((m) => m[1]);
  const c = await connect(env.DOPPELKEY_SOCK);
  const r = await c.request({ op: 'eject', ids, passphrase: 'human-only passphrase' });
  c.close();
  assert.equal(r.ok, true, JSON.stringify(r.error));
  assert.deepEqual(leaks(JSON.stringify(r)), []);
  assert.ok(fs.readFileSync(path.join(dir, '.env'), 'utf8').includes(SECRETS.JWT_SECRET), 'restored on disk by the keeper');
});
