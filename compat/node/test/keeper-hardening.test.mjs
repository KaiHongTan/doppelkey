// doppelkeyd only: a same-user process that is not root cannot read the keeper's memory or
// environment (PR_SET_DUMPABLE=0), and per-key rate limits and confirm prompts are enforced.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { startKeeper, isRustKeeper, vault, real, tmpdir } from '../lib/harness.mjs';
import { connect } from '../lib/client.mjs';
import { envValue } from '../../test-keeper/handles.mjs';

const onlyRust = !isRustKeeper && 'needs doppelkeyd (set DOPPELKEY_KEEPER_CMD)';
const b64 = (s) => Buffer.from(s).toString('base64');

test('a same-user process cannot read keeper memory or environment', { skip: onlyRust || (process.platform !== 'linux' && 'Linux only') || (process.getuid() === 0 && 'root bypasses this (CAP_SYS_PTRACE); run as a normal user') }, async () => {
  const keeper = await startKeeper();
  try {
    for (const f of ['mem', 'environ']) {
      assert.throws(() => fs.readFileSync(`/proc/${keeper.pid}/${f}`), /EACCES|EPERM/, f);
    }
    // /proc/<pid>/* files of a non-dumpable process are owned by root.
    assert.equal(fs.statSync(`/proc/${keeper.pid}/mem`).uid, 0);
  } finally { await keeper.stop(); }
});

function policyVault(extra) {
  const v = structuredClone(vault);
  Object.assign(v.keys.JWT_SECRET, extra);
  const file = path.join(tmpdir('dk-vault'), 'vault.json');
  fs.writeFileSync(file, JSON.stringify(v));
  return file;
}
const jwtHandle = envValue(vault.keys.JWT_SECRET);
const hmacReq = { op: 'hmac', handle: jwtHandle, alg: 'sha256', data: b64('x') };

test('rate limit per key', { skip: onlyRust }, async () => {
  const keeper = await startKeeper({ vaultFile: policyVault({ rate_per_minute: 3 }) });
  const c = await connect(keeper.sock);
  try {
    const codes = [];
    for (let i = 0; i < 5; i++) codes.push((await c.request(hmacReq)).error?.code ?? 'ok');
    assert.deepEqual(codes, ['ok', 'ok', 'ok', 'rate_limited', 'rate_limited']);
    const r = await c.request(hmacReq);
    assert.equal(r.error.hint, 'doppelkey policy JWT_SECRET --rate <per-minute>');
  } finally { c.close(); await keeper.stop(); }
});

test('confirm prompt: denied, then allowed and cached', { skip: onlyRust }, async () => {
  const dir = tmpdir('dk-askpass');
  const answer = path.join(dir, 'answer');
  const askpass = path.join(dir, 'askpass.sh');
  fs.writeFileSync(askpass, `#!/bin/sh\necho "$1" >> ${dir}/prompts\n[ "$(cat ${answer})" = yes ]\n`, { mode: 0o755 });
  fs.writeFileSync(answer, 'no');
  const keeper = await startKeeper({ vaultFile: policyVault({ confirm: true }), env: { DOPPELKEY_ASKPASS: askpass } });
  const c = await connect(keeper.sock);
  try {
    const denied = await c.request(hmacReq);
    assert.equal(denied.error.code, 'confirm_denied');
    fs.writeFileSync(answer, 'yes');
    const ok = await c.request(hmacReq);
    assert.equal(ok.ok, true);
    fs.writeFileSync(answer, 'no');
    assert.equal((await c.request(hmacReq)).ok, true, 'approval is cached');
    const prompts = fs.readFileSync(path.join(dir, 'prompts'), 'utf8').trim().split('\n');
    assert.equal(prompts.length, 2);
    assert.match(prompts[0], /Allow a program to use JWT_SECRET \(hmac\)\?/);
  } finally { c.close(); await keeper.stop(); }
});

test('audit log records the calling process', { skip: onlyRust }, async () => {
  const keeper = await startKeeper();
  const c = await connect(keeper.sock);
  try {
    await c.request(hmacReq);
    const e = keeper.auditEntries().find((x) => x.op === 'hmac');
    assert.equal(e.key, 'JWT_SECRET');
    assert.equal(e.pid, process.pid);
    if (process.platform === 'linux') assert.equal(e.exe, fs.realpathSync(process.execPath));
    assert.ok(!JSON.stringify(keeper.auditEntries()).includes(real('JWT_SECRET').toString()));
  } finally { c.close(); await keeper.stop(); }
});
