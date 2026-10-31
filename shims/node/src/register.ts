// doppelkey/register: preload with `node --require doppelkey/register` (or --import, or
// NODE_OPTIONS). Crypto calls made with a doppelkey handle go to the keeper; every other call
// runs unchanged. Patching is unconditional because frameworks such as Next.js load .env files
// after preload; for non-handle keys the cost is one indexOf per call.
import { isMainThread, workerData } from 'node:worker_threads';
import { WORKER_MARK, keeperStats, socketPath } from './keeper';
import { installNodeCrypto } from './node-crypto';
import { installWebCrypto } from './webcrypto';
import { installHash } from './hash';
import { installPureJs } from './purejs';
import { refOfKeyMaterial } from './handle';

declare const __VERSION__: string;
const STATE = Symbol.for('doppelkey.shim');

function main() {
  const g = globalThis as any;
  if (g[STATE]) return; // loaded twice (e.g. --require and --import)
  if (!isMainThread && workerData && workerData[WORKER_MARK]) return; // our own keeper thread
  if (process.env.DOPPELKEY_SHIM === 'off') return;
  installNodeCrypto();
  installWebCrypto();
  installHash();
  const purejs = installPureJs();
  g[STATE] = Object.freeze({
    version: __VERSION__,
    socket: socketPath(),
    adapters: purejs.adapters,
    stats: keeperStats,
    /** Is this key a handle? For `doppelkey doctor` and tests; never touches the keeper. */
    recognise(key: unknown) {
      const r = refOfKeyMaterial(key);
      return r && { handle: r.handle, prefix: r.prefix?.toString('latin1') ?? '', keyEncoding: r.keyEncoding ?? null, length: r.length };
    },
  });
}

main();
