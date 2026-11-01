#!/usr/bin/env node
// `npx doppelkey ...`: runs the native doppelkey CLI (Rust). Looks for, in order:
//   $DOPPELKEY_BIN, the platform package @doppelkey/cli-<platform>-<arch> (an optional
//   dependency, installed automatically for your OS/CPU), then `doppelkey` on PATH.
'use strict';
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');

function find() {
  if (process.env.DOPPELKEY_BIN) return process.env.DOPPELKEY_BIN;
  const pkg = `@doppelkey/cli-${process.platform}-${process.arch}`;
  try {
    const dir = path.dirname(require.resolve(`${pkg}/package.json`));
    const bin = path.join(dir, 'bin', 'doppelkey');
    if (fs.existsSync(bin)) return bin;
  } catch { /* not installed for this platform */ }
  for (const d of (process.env.PATH || '').split(path.delimiter)) {
    const bin = path.join(d, 'doppelkey');
    if (d && fs.existsSync(bin) && fs.realpathSync(bin) !== fs.realpathSync(__filename)) return bin;
  }
  return null;
}

const bin = find();
if (!bin) {
  console.error(`doppelkey: no native binary for ${process.platform}-${process.arch}. Install it with:\n  curl -fsSL https://raw.githubusercontent.com/KaiHongTan/doppelkey/main/install.sh | sh\nor set DOPPELKEY_BIN to its path.`);
  process.exit(1);
}
// Tell the CLI which Node shim to reference when it writes auto-load lines.
const env = { ...process.env, DOPPELKEY_NODE_SHIM: process.env.DOPPELKEY_NODE_SHIM || path.join(__dirname, '..', 'dist', 'register.cjs') };
const r = spawnSync(bin, process.argv.slice(2), { stdio: 'inherit', env });
if (r.error) { console.error(`doppelkey: cannot run ${bin}: ${r.error.message}`); process.exit(1); }
process.exit(r.status === null ? 1 : r.status);
