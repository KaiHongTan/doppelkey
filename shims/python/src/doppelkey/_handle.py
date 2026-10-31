"""Handle format v1 (docs/protocol.md). Mirrors shims/node/src/handle.ts."""
import base64
import binascii
import hashlib
import re

# Captured before the shim patches hashlib, so checksums never route to the keeper.
_sha256 = hashlib.sha256

LABEL = "NOT-A-SECRET-load-doppelkey-shim"
MAX_PREFIX = 8
_KEY_RE = re.compile(
    rb"^([\s\S]{0,%d}?)((?:dk1:(?:%s:[0-9a-f]{12}:|[0-9a-f]{12})[0-9a-f]{4}\.*)+)$" % (MAX_PREFIX, LABEL.encode())
)
_CORE_RE = re.compile(rb"dk1:(?:%s:([0-9a-f]{12}):|([0-9a-f]{12}))([0-9a-f]{4})" % LABEL.encode())
_HEX_MARK = b"646b313a"
_B64_MARK = b"ZGsxO"
_crc_cache = {}


def crc(id_):
    c = _crc_cache.get(id_)
    if c is None:
        c = _sha256(b"dk1:" + id_.encode()).hexdigest()[:4]
        _crc_cache[id_] = c
    return c


class KeyRef(object):
    __slots__ = ("handle", "prefix", "key_encoding", "length")

    def __init__(self, handle, prefix=b"", key_encoding=None, length=0):
        self.handle, self.prefix, self.key_encoding, self.length = handle, prefix, key_encoding, length

    def fields(self):
        f = {"handle": self.handle}
        if self.prefix:
            f["prefix"] = base64.b64encode(self.prefix).decode()
        if self.key_encoding:
            f["key_encoding"] = self.key_encoding
        return f

    def material(self):
        """The key bytes the app passed (safe to reveal)."""
        body = self.handle.encode("latin-1")
        if self.key_encoding == "hex":
            body = binascii.hexlify(body)
        elif self.key_encoding == "base64":
            body = base64.b64encode(body)
        return self.prefix + body


def _parse(b):
    m = _KEY_RE.match(b)
    if not m:
        return None
    for c in _CORE_RE.finditer(m.group(2)):
        id_ = (c.group(1) or c.group(2)).decode()
        if crc(id_) != c.group(3).decode():
            return None
    return m.group(1), m.group(2).decode("latin-1")


def _encoded(b):
    starts = [i for i in (b.find(_HEX_MARK), b.find(_B64_MARK)) if 0 <= i <= MAX_PREFIX]
    if not starts:
        return None
    start = min(starts)
    body = b[start:]
    try:
        if body.startswith(_HEX_MARK) and re.match(rb"^[0-9a-f]+$", body) and len(body) % 2 == 0:
            enc, decoded = "hex", binascii.unhexlify(body)
        elif body.startswith(_B64_MARK) and re.match(rb"^[A-Za-z0-9+/]+={0,2}$", body):
            enc, decoded = "base64", base64.b64decode(body, validate=True)
        else:
            return None
    except (binascii.Error, ValueError):
        return None
    p = _parse(decoded)
    if not p or p[0]:
        return None
    return KeyRef(p[1], b[:start], enc, len(b))


def recognise(key):
    """KeyRef if `key` (bytes-like or str) is a doppelkey handle, else None. Cheap for non-handles."""
    if isinstance(key, str):
        if "dk1:" not in key and "646b313a" not in key and "ZGsxO" not in key:
            return None
        key = key.encode("utf-8")
    elif isinstance(key, (bytearray, memoryview)):
        key = bytes(key)
    elif not isinstance(key, bytes):
        return None
    if len(key) < 20:
        return None
    if b"dk1:" in key:
        p = _parse(key)
        return KeyRef(p[1], p[0], None, len(key)) if p else None
    if _HEX_MARK in key or _B64_MARK in key:
        return _encoded(key)
    return None


def find_in(data):
    """Locate a handle inside hash input (e.g. salt + secret): (start, end, KeyRef) or None."""
    i = data.find(b"dk1:")
    if i == -1:
        return None
    m = re.match(rb"(?:dk1:(?:%s:[0-9a-f]{12}:|[0-9a-f]{12})[0-9a-f]{4}\.*)+" % LABEL.encode(), data[i:])
    if not m:
        return None
    p = _parse(m.group(0))
    if not p:
        return None
    return i, i + len(m.group(0)), KeyRef(p[1], b"", None, len(m.group(0)))
