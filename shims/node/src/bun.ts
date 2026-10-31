// Pure-JS adapters on Bun, which has no module.registerHooks: a runtime plugin rewrites the same
// modules at load time (see purejs.ts for what the wrappers do).
import fs from 'node:fs';

const FILTER = /node_modules[\\/](?:fast-sha256[\\/]sha256(?:\.min)?|@noble[\\/]hashes[\\/](?:esm[\\/])?(?:hmac|hkdf)|@oslojs[\\/]crypto[\\/]dist[\\/]hmac[\\/]index)\.js$/;
const G = `const __dkG = globalThis[Symbol.for('doppelkey.purejs')];\n`;

/** Rewrite one module's source so its exports go through the doppelkey wrappers. */
export function rewrite(file: string, src: string): string {
  const p = file.replace(/\\/g, '/');
  if (/fast-sha256\/sha256(\.min)?\.js$/.test(p)) {
    // UMD/CommonJS: evaluate it with our own module object, wrap, re-export by name.
    return `${G}const module = { exports: {} }; const exports = module.exports;\n(function (module, exports) {\n${src}\n}).call(undefined, module, exports);\nif (__dkG) __dkG.wrapFastSha256(module.exports);\nconst m = module.exports;\nexport default m;\nexport const hmac = m.hmac, HMAC = m.HMAC, hkdf = m.hkdf, pbkdf2 = m.pbkdf2, hash = m.hash, Hash = m.Hash, digestLength = m.digestLength, blockSize = m.blockSize;\n`;
  }
  // ESM: keep the local names (other code in the module uses them), export wrapped versions.
  const exportsTo: string[] = [];
  let out = src;
  const unexport = (re: RegExp, decl: string, name: string, wrap: string) => {
    if (!re.test(out)) return;
    out = out.replace(re, decl);
    exportsTo.push(`const __dk_${name} = __dkG ? ${wrap} : ${name};\nexport { __dk_${name} as ${name} };`);
  };
  if (/@noble\/hashes\/(esm\/)?hmac\.js$/.test(p)) {
    unexport(/export const hmac\s*=/, 'const hmac =', 'hmac', '__dkG.nobleHmac(hmac)');
  } else if (/@noble\/hashes\/(esm\/)?hkdf\.js$/.test(p)) {
    unexport(/export const hkdf\s*=/, 'const hkdf =', 'hkdf', '__dkG.nobleHkdf(hkdf)');
    unexport(/export function extract\(/, 'function extract(', 'extract', "__dkG.refuse(extract, 'HKDF-Extract (pure JS)')");
    unexport(/export function expand\(/, 'function expand(', 'expand', "__dkG.refuse(expand, 'HKDF-Expand (pure JS)')");
  } else {
    unexport(/export function hmac\(/, 'function hmac(', 'hmac', '__dkG.osloHmac(hmac)');
    unexport(/export class HMAC\b/, 'class HMAC', 'HMAC', '__dkG.osloHMAC(HMAC)');
  }
  return exportsTo.length ? `${G}${out}\n${exportsTo.join('\n')}\n` : src;
}

export function installBunAdapters(): boolean {
  const B = (globalThis as any).Bun;
  if (!B || typeof B.plugin !== 'function') return false;
  B.plugin({
    name: 'doppelkey-purejs',
    setup(build: any) {
      // Synchronous on purpose: require() cannot wait for an async loader.
      build.onLoad({ filter: FILTER }, (args: { path: string }) => ({ contents: rewrite(args.path, fs.readFileSync(args.path, 'utf8')), loader: 'js' }));
    },
  });
  return true;
}
