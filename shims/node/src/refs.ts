// Decoy key objects (node KeyObject and WebCrypto CryptoKey) made from random bytes, mapped to
// the handle they stand for. Code that inspects them sees a normal key of the right type/length.
import { KeyRef, refOfKeyMaterial } from './handle';

export const decoys = new WeakMap<object, KeyRef>();

/** Handle behind any key argument: string, bytes, KeyObject or CryptoKey. Null if none. */
export function refOf(key: unknown, encoding: BufferEncoding = 'utf8'): KeyRef | null {
  if (key !== null && typeof key === 'object' && !ArrayBuffer.isView(key) && !(key instanceof ArrayBuffer)) {
    return decoys.get(key) ?? null;
  }
  return refOfKeyMaterial(key, encoding);
}
