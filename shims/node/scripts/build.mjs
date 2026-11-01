// Bundles src/register.ts into a single dependency-free dist/register.cjs, plus an ESM entry.
import { build } from 'esbuild';
import fs from 'node:fs';
const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url)));
fs.rmSync(new URL('../dist', import.meta.url), { recursive: true, force: true });
await build({
  entryPoints: [new URL('../src/register.ts', import.meta.url).pathname],
  outfile: new URL('../dist/register.cjs', import.meta.url).pathname,
  bundle: true,
  platform: 'node',
  format: 'cjs',
  target: 'node22',
  legalComments: 'none',
  define: { __VERSION__: JSON.stringify(pkg.version) },
  banner: { js: `// doppelkey ${pkg.version} - https://github.com/KaiHongTan/doppelkey - zero runtime dependencies` },
});
fs.writeFileSync(new URL('../dist/register.mjs', import.meta.url),
  `// ESM entry for \`node --import doppelkey/register\`.\nimport { createRequire } from 'node:module';\ncreateRequire(import.meta.url)('./register.cjs');\n`);
const size = fs.statSync(new URL('../dist/register.cjs', import.meta.url)).size;
console.log(`built dist/register.cjs (${(size / 1024).toFixed(1)} KiB) and dist/register.mjs`);
