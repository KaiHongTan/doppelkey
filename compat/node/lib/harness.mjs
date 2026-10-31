// Test harness for the oracle pattern. The test process is the oracle: it holds the real keys
// (from the fixture vault) and never loads the shim. Apps run in child processes with handles
// in their environment and the shim preloaded; their outputs are verified here.
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { envValue, keyBytes } from '../../test-keeper/handles.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
export const ROOT = path.resolve(here, '../../..');
export const SHIM = path.join(ROOT, 'shims/node/dist/register.cjs');
export const APPS = path.resolve(here, '../apps');
const VAULT_FILE = path.join(ROOT, 'compat/fixtures/vault.json');
export const vault = JSON.parse(fs.readFileSync(VAULT_FILE, 'utf8'));

/** Real key bytes by env name (oracle side only). */
export const real = (name) => keyBytes(vault.keys[name]);
/** The handles the app sees instead, by env name. */
export const handleEnv = Object.fromEntries(Object.entries(vault.keys).map(([n, e]) => [n, envValue(e)]));

/** Runtime for apps: node by default; DOPPELKEY_TEST_RUNTIME=/path/to/node or "bun". */
const RUNTIME = process.env.DOPPELKEY_TEST_RUNTIME || process.execPath;
export const isBun = path.basename(RUNTIME).startsWith('bun');

if (!fs.existsSync(SHIM)) {
  const r = spawnSync('npm', ['--prefix', path.join(ROOT, 'shims/node'), 'run', 'build'], { stdio: 'inherit' });
  if (r.status !== 0) throw new Error('shim build failed; run "npm run build" in shims/node');
}

export function tmpdir(tag = 'dk') {
  return fs.mkdtempSync(path.join(os.tmpdir(), `${tag}-`));
}

/**
 * Start a keeper. Default: the Node test keeper. DOPPELKEY_KEEPER_CMD overrides it (e.g. with
 * doppelkeyd in Milestone 2); it gets --vault/--socket/--audit appended.
 */
/** True when the suite runs against doppelkeyd (DOPPELKEY_KEEPER_CMD) rather than the Node test keeper. */
export const isRustKeeper = !!process.env.DOPPELKEY_KEEPER_CMD;

export async function startKeeper({ vaultFile = VAULT_FILE, env = {} } = {}) {
  const dir = tmpdir('dk-keeper');
  fs.chmodSync(dir, 0o700);
  const sock = path.join(dir, 'k.sock');
  const audit = path.join(dir, 'audit.jsonl');
  const cmd = process.env.DOPPELKEY_KEEPER_CMD ? process.env.DOPPELKEY_KEEPER_CMD.split(' ') : [process.execPath, path.join(ROOT, 'compat/test-keeper/keeper.mjs')];
  const child = spawn(cmd[0], [...cmd.slice(1), '--vault', vaultFile, '--socket', sock, '--audit', audit], { stdio: ['ignore', 'pipe', 'inherit'], env: { ...process.env, ...env } });
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('keeper did not start')), 10000);
    child.stdout.on('data', (d) => { if (String(d).includes('listening')) { clearTimeout(t); resolve(); } });
    child.on('exit', (code) => reject(new Error(`keeper exited with ${code}`)));
  });
  return {
    sock,
    audit,
    pid: child.pid,
    auditEntries: () => (fs.existsSync(audit) ? fs.readFileSync(audit, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []),
    stop: () => new Promise((r) => { child.once('exit', r); child.kill('SIGTERM'); }),
  };
}

/**
 * Run an app. Returns { results, stderr, code, heapFile, environFile }.
 * The app calls finish() from apps/_finish.mjs, which writes results (and optionally a heap snapshot).
 */
export function runApp(app, { keeper, env = {}, shim = true, handles = true, heap = false, args = [], timeoutMs = 120000 } = {}) {
  const dir = tmpdir('dk-app');
  const out = path.join(dir, 'results.json');
  const childEnv = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    ...(handles ? handleEnv : {}),
    ...(keeper ? { DOPPELKEY_SOCK: keeper.sock } : {}),
    DOPPELKEY_RESULTS: out,
    ...(heap ? { DOPPELKEY_HEAP: path.join(dir, 'app.heapsnapshot'), DOPPELKEY_ENVIRON: path.join(dir, 'app.environ') } : {}),
    ...env,
  };
  for (const [k, v] of Object.entries(childEnv)) if (v === undefined) delete childEnv[k];
  const preload = shim ? (isBun ? ['--preload', SHIM] : ['--require', SHIM]) : [];
  const r = spawnSync(RUNTIME, [...preload, path.join(APPS, app), ...args], { env: childEnv, encoding: 'utf8', timeout: timeoutMs, cwd: path.join(ROOT, 'compat/node') });
  let results = null;
  try { results = JSON.parse(fs.readFileSync(out, 'utf8')); } catch { /* app crashed */ }
  if (!results) throw new Error(`${app} produced no results (exit ${r.status}${r.signal ? ', ' + r.signal : ''})\n--- stdout\n${r.stdout}\n--- stderr\n${r.stderr}`);
  return { results, stdout: r.stdout, stderr: r.stderr, code: r.status, heapFile: childEnv.DOPPELKEY_HEAP, environFile: childEnv.DOPPELKEY_ENVIRON };
}

/** Every form a key could take in memory: raw, hex, base64, base64url, UTF-16. */
export function forms(needle) {
  const b = Buffer.from(needle);
  const f = [b, Buffer.from(b.toString('hex')), Buffer.from(b.toString('base64').replace(/=+$/, '')), Buffer.from(b.toString('base64url'))];
  if (/^[\x20-\x7e]+$/.test(b.toString('latin1'))) f.push(Buffer.from(b.toString('latin1'), 'utf16le'));
  return f.filter((x) => x.length >= 16);
}

/** Names of needles found (in any form) in a file. */
export function scan(file, needles) {
  const data = fs.readFileSync(file);
  return Object.entries(needles).filter(([, n]) => forms(n).some((f) => data.indexOf(f) !== -1)).map(([name]) => name);
}

/** Generate a fresh Stripe-format signature header with the real secret (Stripe's side). */
export async function stripeHeader(payload) {
  const { default: Stripe } = await import('stripe');
  return new Stripe('sk_test_dummy').webhooks.generateTestHeaderString({ payload, secret: real('STRIPE_WEBHOOK_SECRET').toString() });
}
