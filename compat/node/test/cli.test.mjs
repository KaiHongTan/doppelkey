// End to end with the real CLI and doppelkeyd: init a sample project, run it the normal way
// (npm start), check doctor, then eject and get the original .env back byte for byte.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { ROOT, tmpdir } from '../lib/harness.mjs';

const BIN = path.join(ROOT, 'target/debug');
const missing = !fs.existsSync(path.join(BIN, 'doppelkey')) && 'build the CLI first: cargo build';
const ENV = `# app secrets
JWT_SECRET=my-super-secret-jwt-signing-key-1234
export STRIPE_WEBHOOK_SECRET="whsec_realStripeB64Secret0123456789abc"
OPENAI_API_KEY=sk-proj-abcdefghijklmnop
ENCRYPTION_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
AUTH_SECRET='aGVsbG8gd29ybGQgdGhpcyBpcyBiYXNlNjQgc2VjcmV0IQ=='
NODE_ENV=development
`;
const APP = `const fs = require('fs'), crypto = require('crypto');
for (const l of fs.readFileSync('.env', 'utf8').split('\\n')) { const m = l.match(/^(?:export )?([A-Z_]+)=["']?(.*?)["']?$/); if (m) process.env[m[1]] = m[2]; }
const e = process.env;
console.log(JSON.stringify({
  jwt: crypto.createHmac('sha256', e.JWT_SECRET).update('hello').digest('hex'),
  stripe: crypto.createHmac('sha256', e.STRIPE_WEBHOOK_SECRET).update('payload').digest('hex'),
  enc: (() => { const c = crypto.createCipheriv('aes-256-gcm', Buffer.from(e.ENCRYPTION_KEY, 'hex'), Buffer.alloc(12)); return Buffer.concat([c.update('x'), c.final(), c.getAuthTag()]).toString('hex'); })(),
  seen: e.JWT_SECRET,
}));
`;

let dir, home, env;
const sh = (cmd, args, extra = {}) => spawnSync(cmd, args, { cwd: dir, env: { ...env, ...extra }, encoding: 'utf8' });

before(() => {
  if (missing) return;
  dir = tmpdir('dk-cli-project');
  home = tmpdir('dk-cli-home');
  fs.writeFileSync(path.join(dir, '.env'), ENV);
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'sample', private: true, scripts: { start: 'node app.js' } }));
  fs.writeFileSync(path.join(dir, 'app.js'), APP);
  env = { PATH: `${BIN}:${process.env.PATH}`, HOME: home, DOPPELKEY_HOME: path.join(home, 'dk'), DOPPELKEY_SOCK: path.join(home, 'k.sock'), DOPPELKEY_PASSPHRASE: 'correct horse battery staple' };
});
after(() => { if (!missing) spawnSync(path.join(BIN, 'doppelkey'), ['service', 'uninstall'], { env, encoding: 'utf8' }); });

test('init, normal npm start, doctor, eject', { skip: missing }, () => {
  const plain = JSON.parse(sh('node', ['app.js']).stdout);
  const preview = sh('doppelkey', ['init']);
  assert.match(preview.stdout, /\+ JWT_SECRET/);
  assert.match(preview.stdout, /- OPENAI_API_KEY +skip: network credential/);
  assert.equal(fs.readFileSync(path.join(dir, '.env'), 'utf8'), ENV, 'preview changes nothing');

  const init = sh('doppelkey', ['init', '--yes']);
  assert.equal(init.status, 0, init.stderr);
  const protectedEnv = fs.readFileSync(path.join(dir, '.env'), 'utf8');
  for (const secret of ['my-super-secret', 'realStripeB64', '0123456789abcdef0123', 'aGVsbG8']) assert.ok(!protectedEnv.includes(secret), secret);
  assert.match(protectedEnv, /OPENAI_API_KEY=sk-proj-abcdefghijklmnop/, 'network credentials untouched');
  assert.match(fs.readFileSync(path.join(dir, 'AGENTS.md'), 'utf8'), /doppelkey handles/);

  const run = sh('npm', ['start', '-s']);
  assert.equal(run.status, 0, run.stderr);
  const shimmed = JSON.parse(run.stdout);
  assert.match(shimmed.seen, /^dk1:NOT-A-SECRET/);
  for (const k of ['jwt', 'stripe', 'enc']) assert.equal(shimmed[k], plain[k], `${k} computed through the keeper equals the real key's result`);

  const doctor = sh('doppelkey', ['doctor']);
  assert.equal(doctor.status, 0, doctor.stdout);
  assert.match(doctor.stdout, /keeper memory is protected/);

  const vault = fs.readFileSync(path.join(home, 'dk/vault.dk'));
  assert.ok(!vault.includes('my-super-secret') && !vault.includes(Buffer.from('my-super-secret').toString('base64').slice(0, 12)), 'vault is encrypted');

  assert.equal(sh('doppelkey', ['eject']).status, 1, 'eject needs a human');
  const ej = sh('doppelkey', ['eject'], { DOPPELKEY_ASKPASS: '/bin/true' });
  assert.equal(ej.status, 0, ej.stderr);
  assert.equal(fs.readFileSync(path.join(dir, '.env'), 'utf8'), ENV, '.env restored byte for byte');
  for (const f of ['.npmrc', 'AGENTS.md', '.claude', '.doppelkey']) assert.ok(!fs.existsSync(path.join(dir, f)), `${f} removed`);
});
