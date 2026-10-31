// Pure-JavaScript crypto packages never call node:crypto, so the core patches can't see them and
// a handle would silently be used as key bytes. Two defences:
//  1. Adapters: on Node >= 22.15, module.registerHooks wraps the HMAC/HKDF entry points of
//     known packages so a handle key goes to the keeper (fast-sha256 for svix/standardwebhooks,
//     @noble/hashes for Better Auth and others, @oslojs/crypto for the Lucia ecosystem).
//  2. A one-time startup warning listing pure-JS crypto packages that have no adapter.
import fs from 'node:fs';
import nodeModule from 'node:module';
import path from 'node:path';
import { refOfKeyMaterial } from './handle';
import * as ops from './ops';

const API = Symbol.for('doppelkey.purejs');

/** Packages with an adapter, and the files the adapter wraps. */
const ADAPTED = ['fast-sha256', '@noble/hashes', '@oslojs/crypto'];
/** Pure-JS crypto with no adapter yet. A handle used with these gives wrong results. */
const UNADAPTED = [
  'crypto-js', 'jssha', 'js-sha256', 'js-sha1', 'js-sha512', 'hash.js', 'sjcl', 'node-forge',
  '@stablelib/hmac', '@stablelib/hkdf', 'tweetnacl', '@noble/ciphers',
];

const FAST_SHA256 = /\/node_modules\/fast-sha256\/sha256(?:\.min)?\.js$/;
const NOBLE = /\/node_modules\/@noble\/hashes\/(?:esm\/)?(hmac|hkdf)\.js$/;
const OSLO = /\/node_modules\/@oslojs\/crypto\/dist\/hmac\/index\.js$/;
const ORIG = 'doppelkey-orig';
const WRAP = 'doppelkey-wrap';

// ---------- the functions adapters call (reached through a global symbol) ----------
const u8 = (b: Buffer) => new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
const bin = (x: unknown): Buffer => (typeof x === 'string' ? Buffer.from(x, 'utf8') : x == null ? Buffer.alloc(0) : Buffer.from(x as Uint8Array));

/** Hash name from a noble hash (outputLen/blockLen) or an oslo algorithm (size/blockSize). */
function hashOf(out: number, block: number): string {
  const n = ({ '20/64': 'sha1', '32/64': 'sha256', '48/128': 'sha384', '64/128': 'sha512' } as Record<string, string>)[`${out}/${block}`];
  return n ?? ops.unsupported(`a pure-JS hash with ${out}-byte output`);
}
const nobleHash = (h: any) => hashOf(h?.outputLen, h?.blockLen);
const osloHash = (Alg: any) => { const a = new Alg(); return hashOf(a.size, a.blockSize); };

function remoteMac(ref: NonNullable<ReturnType<typeof refOfKeyMaterial>>, alg: string, initial: Buffer[] = []) {
  const chunks = initial;
  let done = false;
  const obj = {
    update(d: unknown) { chunks.push(bin(d)); return obj; },
    digest() { if (done) throw new Error('Hash#digest() has already been called'); done = true; return u8(ops.hmac(ref, alg, Buffer.concat(chunks))); },
    digestInto(out: Uint8Array) { out.set(obj.digest()); },
    clone() { return remoteMac(ref, alg, chunks.slice()); },
    _cloneInto() { return obj.clone(); },
    destroy() {},
  };
  return obj;
}

const api = {
  wrapFastSha256(e: any) {
    if (!e || e.__doppelkey) return;
    const { hmac, HMAC, hkdf, pbkdf2 } = e;
    e.hmac = function (key: Uint8Array, data: Uint8Array) {
      const ref = refOfKeyMaterial(key);
      return ref ? u8(ops.hmac(ref, 'sha256', bin(data))) : hmac.apply(this, arguments);
    };
    e.HMAC = function (key: Uint8Array) {
      const ref = refOfKeyMaterial(key);
      return ref ? remoteMac(ref, 'sha256') : new HMAC(key);
    };
    e.hkdf = function (key: Uint8Array, salt: Uint8Array | undefined, info: Uint8Array | undefined, length = 32) {
      const ref = refOfKeyMaterial(key);
      return ref ? u8(ops.hkdf(ref, 'sha256', bin(salt), bin(info), length)) : hkdf.apply(this, arguments);
    };
    e.pbkdf2 = function (password: Uint8Array, salt: Uint8Array, iterations: number, dkLen: number) {
      const ref = refOfKeyMaterial(password);
      return ref ? u8(ops.pbkdf2(ref, 'sha256', bin(salt), iterations, dkLen)) : pbkdf2.apply(this, arguments);
    };
    Object.defineProperty(e, '__doppelkey', { value: true });
  },
  nobleHmac(orig: any) {
    const w: any = (hash: any, key: unknown, message: unknown) => {
      const ref = refOfKeyMaterial(key);
      return ref ? u8(ops.hmac(ref, nobleHash(hash), bin(message))) : orig(hash, key, message);
    };
    w.create = (hash: any, key: unknown) => {
      const ref = refOfKeyMaterial(key);
      return ref ? remoteMac(ref, nobleHash(hash)) : orig.create(hash, key);
    };
    return w;
  },
  nobleHkdf(orig: any) {
    return (hash: any, ikm: unknown, salt: unknown, info: unknown, length: number) => {
      const ref = refOfKeyMaterial(ikm);
      return ref ? u8(ops.hkdf(ref, nobleHash(hash), bin(salt), bin(info), length)) : orig(hash, ikm, salt, info, length);
    };
  },
  /** Wrap a function whose `argIndex` argument is key material: refuse if it is a handle. */
  refuse(orig: any, what: string, argIndex = 1) {
    if (typeof orig !== 'function') return orig;
    return function (this: unknown, ...args: unknown[]) {
      if (refOfKeyMaterial(args[argIndex])) ops.unsupported(what);
      return orig.apply(this, args);
    };
  },
  osloHmac(orig: any) {
    return (Alg: any, key: unknown, message: unknown) => {
      const ref = refOfKeyMaterial(key);
      return ref ? u8(ops.hmac(ref, osloHash(Alg), bin(message))) : orig(Alg, key, message);
    };
  },
  osloHMAC(Orig: any) {
    return function HMAC(Alg: any, key: unknown) {
      const ref = refOfKeyMaterial(key);
      return ref ? remoteMac(ref, osloHash(Alg)) : new Orig(Alg, key);
    };
  },
};

// ---------- module hooks ----------
const typeCache = new Map<string, boolean>();
/** Is this file ESM? Looks at the nearest package.json, as Node does (stops at node_modules). */
function isEsmFile(url: string): boolean {
  const file = new URL(url).pathname;
  let dir = path.dirname(file);
  for (; path.basename(dir) !== 'node_modules' && path.dirname(dir) !== dir; dir = path.dirname(dir)) {
    const pj = path.join(dir, 'package.json');
    if (typeCache.has(pj)) return typeCache.get(pj)!;
    try {
      const t = JSON.parse(fs.readFileSync(pj, 'utf8')).type === 'module';
      typeCache.set(pj, t);
      return t;
    } catch { /* keep looking */ }
  }
  return false;
}

const G = `globalThis[Symbol.for('doppelkey.purejs')]`;
function cjsAppendix(url: string): string | null {
  if (FAST_SHA256.test(url)) return `\n;${G} && ${G}.wrapFastSha256(module.exports);\n`;
  const m = NOBLE.exec(url);
  if (m && m[1] === 'hmac') return `\n;if (${G}) exports.hmac = ${G}.nobleHmac(exports.hmac);\n`;
  if (m && m[1] === 'hkdf')
    return `\n;if (${G}) { exports.hkdf = ${G}.nobleHkdf(exports.hkdf); exports.extract = ${G}.refuse(exports.extract, 'HKDF-Extract (pure JS)'); exports.expand = ${G}.refuse(exports.expand, 'HKDF-Expand (pure JS)'); }\n`;
  return null;
}
function esmWrapper(origUrl: string): string {
  const o = JSON.stringify(`${origUrl}?${ORIG}`);
  const head = `import * as o from ${o};\nexport * from ${o};\nconst dk = ${G};\n`;
  const m = NOBLE.exec(origUrl);
  if (m && m[1] === 'hmac') return head + `export const hmac = dk ? dk.nobleHmac(o.hmac) : o.hmac;\n`;
  if (m && m[1] === 'hkdf')
    return head + `export const hkdf = dk ? dk.nobleHkdf(o.hkdf) : o.hkdf;\nexport const extract = dk ? dk.refuse(o.extract, 'HKDF-Extract (pure JS)') : o.extract;\nexport const expand = dk ? dk.refuse(o.expand, 'HKDF-Expand (pure JS)') : o.expand;\n`;
  // @oslojs/crypto/hmac
  return head + `export const hmac = dk ? dk.osloHmac(o.hmac) : o.hmac;\nexport const HMAC = dk ? dk.osloHMAC(o.HMAC) : o.HMAC;\n`;
}

function installHooks(): boolean {
  const registerHooks = (nodeModule as any).registerHooks;
  if (typeof registerHooks !== 'function') return false;
  registerHooks({
    resolve(specifier: string, context: any, nextResolve: Function) {
      const r = nextResolve(specifier, context);
      const url: string = r && r.url;
      if (url && url.startsWith('file:') && !url.includes('?') && (NOBLE.test(url) || OSLO.test(url)) && isEsmFile(url))
        return { ...r, url: `${url}?${WRAP}`, shortCircuit: true };
      return r;
    },
    load(url: string, context: any, nextLoad: Function) {
      if (url.endsWith(`?${WRAP}`)) {
        return { format: 'module', source: esmWrapper(url.slice(0, -WRAP.length - 1)), shortCircuit: true };
      }
      const r = nextLoad(url, context);
      if (url.startsWith('file:') && !url.includes('?')) {
        const add = cjsAppendix(url);
        if (add && (r.format === 'commonjs' || r.format === undefined || r.format === null) && !isEsmFile(url)) {
          const src = r.source != null ? String(r.source) : fs.readFileSync(new URL(url), 'utf8');
          return { ...r, format: 'commonjs', source: src + add, shortCircuit: true };
        }
      }
      return r;
    },
  });
  return true;
}

// ---------- discovery ----------
function nodeModulesDirs(start: string): string[] {
  const out: string[] = [];
  for (let dir = start; ; dir = path.dirname(dir)) {
    const nm = path.join(dir, 'node_modules');
    if (fs.existsSync(nm)) out.push(nm);
    if (path.dirname(dir) === dir) return out;
  }
}
/** Installed packages from `names` (direct, hoisted, or under pnpm's .pnpm store). */
function findInstalled(names: string[], dirs: string[]): Set<string> {
  const found = new Set<string>();
  for (const nm of dirs) {
    for (const n of names) if (!found.has(n) && fs.existsSync(path.join(nm, n, 'package.json'))) found.add(n);
    let pnpm: string[] = [];
    try { pnpm = fs.readdirSync(path.join(nm, '.pnpm')); } catch { /* not pnpm */ }
    for (const entry of pnpm) for (const n of names) if (entry.startsWith(n.replace('/', '+') + '@')) found.add(n);
  }
  return found;
}

/** True if handles appear in the environment or in .env files in the working directory. */
function handlesLikelyInUse(): boolean {
  for (const v of Object.values(process.env)) if (v && (v.includes('dk1:') || v.includes('646b313a') || v.includes('ZGsxO'))) return true;
  try {
    for (const f of fs.readdirSync(process.cwd())) {
      if (!f.startsWith('.env')) continue;
      const p = path.join(process.cwd(), f);
      if (fs.statSync(p).size < 1 << 20 && /dk1:|646b313a|ZGsxO/.test(fs.readFileSync(p, 'latin1'))) return true;
    }
  } catch { /* unreadable cwd */ }
  return false;
}

export function installPureJs(): { adapters: string[]; warned: string[] } {
  (globalThis as any)[API] = api;
  let dirs: string[] = [];
  try { dirs = nodeModulesDirs(process.cwd()); } catch { /* no cwd */ }
  const adapted = findInstalled(ADAPTED, dirs);
  const hooks = adapted.size > 0 && installHooks();
  const result = { adapters: hooks ? [...adapted] : [], warned: [] as string[] };

  if (process.env.DOPPELKEY_QUIET === '1' || process.env.DOPPELKEY_PUREJS_CHECKED === '1') return result;
  process.env.DOPPELKEY_PUREJS_CHECKED = '1'; // child processes inherit this: warn once per process tree
  const bypass = [...findInstalled(UNADAPTED, dirs), ...(hooks ? [] : adapted)];
  if (bypass.length && handlesLikelyInUse()) {
    result.warned = bypass;
    process.stderr.write(
      `doppelkey: warning: these packages compute crypto in pure JavaScript and bypass the shim: ${bypass.join(', ')}.\n` +
      `doppelkey: if they are given a doppelkey handle as a key, results will be wrong. Run "doppelkey doctor" for details, or set DOPPELKEY_QUIET=1.\n`,
    );
  }
  return result;
}
