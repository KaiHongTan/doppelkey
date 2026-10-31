// Handle recognition (docs/protocol.md, "Handles"). Kept free of any patched function:
// it uses the real createHash captured before the shim installs anything.
import { createHash } from 'node:crypto';

export const LABEL = 'NOT-A-SECRET-load-doppelkey-shim';
const MARK = 'dk1:';
const HEX_MARK = '646b313a'; // hex("dk1:")
const B64_MARK = 'ZGsxO'; // base64("dk1:") without the ambiguous last char
const MAX_PREFIX = 8;
const KEY_RE = new RegExp(
  `^([\\s\\S]{0,${MAX_PREFIX}}?)((?:dk1:(?:${LABEL}:[0-9a-f]{12}:|[0-9a-f]{12})[0-9a-f]{4}\\.*)+)$`,
);
const CORE_RE = new RegExp(`dk1:(?:${LABEL}:([0-9a-f]{12}):|([0-9a-f]{12}))([0-9a-f]{4})`, 'g');

export interface KeyRef {
  /** The handle string (one or more padded cores), as sent to the keeper. */
  handle: string;
  /** Bytes before the handle, e.g. "AWS4" or "whsec_". */
  prefix?: Buffer;
  /** Set when the app used the hex/base64 text of an encoded handle as the key. */
  keyEncoding?: 'hex' | 'base64';
  /** Length in bytes of the key as the app passed it. */
  length: number;
}

const crcCache = new Map<string, string>();
export function crc(id: string): string {
  let c = crcCache.get(id);
  if (c === undefined) {
    c = createHash('sha256').update(MARK + id).digest('hex').slice(0, 4);
    if (crcCache.size > 4096) crcCache.clear();
    crcCache.set(id, c);
  }
  return c;
}

export const longCore = (id: string) => `${MARK}${LABEL}:${id}:${crc(id)}`;
export const compactCore = (id: string) => `${MARK}${id}${crc(id)}`;

/** Parse latin1 text as [prefix] handle. Returns null unless every core has a valid crc. */
export function parseKeyText(s: string): { prefix: string; handle: string; ids: string[] } | null {
  const m = KEY_RE.exec(s);
  if (!m) return null;
  const ids: string[] = [];
  CORE_RE.lastIndex = 0;
  let c: RegExpExecArray | null;
  while ((c = CORE_RE.exec(m[2])) !== null) {
    const id = c[1] ?? c[2];
    if (crc(id) !== c[3]) return null;
    ids.push(id);
  }
  return { prefix: m[1], handle: m[2], ids };
}

/** View any binary-ish value as a Buffer without copying. Strings return null. */
export function asBuffer(x: unknown): Buffer | null {
  if (Buffer.isBuffer(x)) return x;
  if (ArrayBuffer.isView(x)) return Buffer.from(x.buffer, x.byteOffset, x.byteLength);
  if (x instanceof ArrayBuffer || (typeof SharedArrayBuffer !== 'undefined' && x instanceof SharedArrayBuffer))
    return Buffer.from(x as ArrayBuffer);
  return null;
}

function refFromText(text: string, length: number): KeyRef | null {
  const p = parseKeyText(text);
  if (!p) return null;
  const ref: KeyRef = { handle: p.handle, length };
  if (p.prefix) ref.prefix = Buffer.from(p.prefix, 'latin1');
  return ref;
}

function refFromEncodedText(text: string): KeyRef | null {
  let enc: 'hex' | 'base64' | null = null;
  if (text.startsWith(HEX_MARK) && /^[0-9a-f]+$/.test(text) && text.length % 2 === 0) enc = 'hex';
  else if (text.startsWith(B64_MARK) && /^[A-Za-z0-9+/]+={0,2}$/.test(text)) enc = 'base64';
  if (!enc) return null;
  const decoded = Buffer.from(text, enc).toString('latin1');
  const p = parseKeyText(decoded);
  if (!p || p.prefix) return null;
  return { handle: p.handle, keyEncoding: enc, length: Buffer.byteLength(text) };
}

/**
 * Recognise a handle in a key given as string or bytes. Cheap for non-handles: one indexOf.
 * `encoding` is the string encoding the caller's API would apply (Node's createHmac uses utf8).
 */
export function refOfKeyMaterial(key: unknown, encoding: BufferEncoding = 'utf8'): KeyRef | null {
  if (typeof key === 'string') {
    if (key.includes(MARK)) {
      const b = Buffer.from(key, encoding);
      return refFromText(b.toString('latin1'), b.length);
    }
    if (key.startsWith(HEX_MARK) || key.startsWith(B64_MARK)) return refFromEncodedText(key);
    return null;
  }
  const b = asBuffer(key);
  if (!b || b.length < 20) return null;
  if (b.indexOf(MARK) !== -1) return refFromText(b.toString('latin1'), b.length);
  // Encoded-handle text passed as bytes (e.g. TextEncoder output of a hex string).
  if (b[0] === 0x36 || b[0] === 0x5a) {
    const t = b.toString('latin1');
    if (t.startsWith(HEX_MARK) || t.startsWith(B64_MARK)) return refFromEncodedText(t);
  }
  return null;
}

/** Fields every keeper request about a key carries. */
export function refFields(ref: KeyRef): Record<string, unknown> {
  const f: Record<string, unknown> = { handle: ref.handle };
  if (ref.prefix) f.prefix = ref.prefix.toString('base64');
  if (ref.keyEncoding) f.key_encoding = ref.keyEncoding;
  return f;
}

/** The key bytes the app originally passed (prefix + handle, or its encoded text). Safe to reveal. */
export function materialOf(ref: KeyRef): Buffer {
  const raw = Buffer.concat([ref.prefix ?? Buffer.alloc(0), Buffer.from(ref.handle, 'latin1')]);
  return ref.keyEncoding ? Buffer.from(raw.toString(ref.keyEncoding), 'latin1') : raw;
}
