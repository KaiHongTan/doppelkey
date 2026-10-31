// Claude Code plugin: the SessionStart hook and the skill files.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { ROOT, tmpdir } from '../lib/harness.mjs';

const HOOK = path.join(ROOT, 'integrations/claude-code/scripts/session-start.sh');
const BIN = path.join(ROOT, 'target/debug');
const missing = !fs.existsSync(path.join(BIN, 'doppelkey')) && 'build the CLI first: cargo build';

function runHook(files) {
  const dir = tmpdir('dk-hook');
  for (const [f, c] of Object.entries(files)) fs.writeFileSync(path.join(dir, f), c);
  const envFile = path.join(dir, 'claude-env');
  fs.writeFileSync(envFile, '');
  const r = spawnSync('sh', [HOOK], { encoding: 'utf8', env: { PATH: `${BIN}:${process.env.PATH}`, HOME: dir, DOPPELKEY_HOME: path.join(dir, 'dk'), CLAUDE_PROJECT_DIR: dir, CLAUDE_ENV_FILE: envFile } });
  return { ...r, env: fs.readFileSync(envFile, 'utf8') };
}

test('protected project: shims loaded via CLAUDE_ENV_FILE, handles explained, no values printed', { skip: missing }, () => {
  const r = runHook({ '.env': 'JWT_SECRET=dk1:NOT-A-SECRET-load-doppelkey-shim:a1b2c3d4e5f6:d3ae\n', 'package.json': '{}' });
  assert.equal(r.status, 0);
  assert.match(r.env, /^export NODE_OPTIONS="\$\{NODE_OPTIONS:\+\$NODE_OPTIONS \}"'--require .*register\.cjs'$/m);
  assert.match(r.stdout, /handles, not broken secrets/);
});

test('plain secrets: suggests the skill, writes no env', () => {
  const r = runHook({ '.env': 'SESSION_SECRET=abcdefabcdefabcdef\nOPENAI_API_KEY=sk-x\n' });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /npx doppelkey init/);
  assert.ok(!r.stdout.includes('abcdefabcdef'));
  assert.equal(r.env, '');
});

test('no secrets: silent', () => {
  const r = runHook({ '.env': 'NODE_ENV=development\n' });
  assert.equal(r.status, 0);
  assert.equal(r.stdout, '');
  assert.equal(r.env, '');
});

test('skill files follow the Agent Skills format', () => {
  for (const f of ['integrations/skills/doppelkey/SKILL.md', 'integrations/claude-code/skills/doppelkey/SKILL.md']) {
    const text = fs.readFileSync(path.join(ROOT, f), 'utf8');
    const fm = /^---\n([\s\S]*?)\n---\n/.exec(text);
    assert.ok(fm, `${f}: frontmatter on line 1`);
    const name = /^name: (.*)$/m.exec(fm[1])[1];
    const desc = /^description: (.*)$/m.exec(fm[1])[1];
    assert.match(name, /^[a-z0-9]+(-[a-z0-9]+)*$/);
    assert.equal(name, path.basename(path.dirname(f)));
    assert.ok(desc.length > 0 && desc.length <= 1024);
  }
});
