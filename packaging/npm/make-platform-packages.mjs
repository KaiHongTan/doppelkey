// Turn release archives into npm packages @doppelkey/cli-<platform>-<arch>, each holding the
// native binaries and shims for one platform (installed via optionalDependencies).
// Usage: node make-platform-packages.mjs <version> <dist-dir> <out-dir>
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const [version, dist, out] = process.argv.slice(2);
const targets = {
  'x86_64-unknown-linux-gnu': ['linux', 'x64'],
  'aarch64-unknown-linux-gnu': ['linux', 'arm64'],
  'x86_64-apple-darwin': ['darwin', 'x64'],
  'aarch64-apple-darwin': ['darwin', 'arm64'],
};
for (const [target, [os, cpu]] of Object.entries(targets)) {
  const archive = path.join(dist, `doppelkey-${version}-${target}.tar.gz`);
  if (!fs.existsSync(archive)) { console.warn(`skipping ${target}: ${archive} missing`); continue; }
  const dir = path.join(out, `cli-${os}-${cpu}`);
  fs.mkdirSync(dir, { recursive: true });
  execFileSync('tar', ['xzf', archive, '-C', dir, '--strip-components=1']);
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
    name: `@doppelkey/cli-${os}-${cpu}`,
    version,
    description: `doppelkey CLI and keeper for ${os}-${cpu}`,
    license: 'Apache-2.0',
    repository: { type: 'git', url: 'git+https://github.com/KaiHongTan/doppelkey.git' },
    os: [os],
    cpu: [cpu],
    files: ['bin', 'share', 'LICENSE', 'README.md'],
  }, null, 2) + '\n');
  console.log(`prepared ${dir}`);
}
