"""Patches for hmac, hashlib and (lazily) cryptography's AESGCM.

A call made with a doppelkey handle goes to the keeper; every other call runs unchanged.
Derivations (hash over salt + secret, PBKDF2) return a new handle: the derived key stays in
the keeper.
"""
import base64
import hashlib
import hmac
import importlib.abc
import importlib.util
import sys

from ._handle import find_in, recognise
from ._keeper import DoppelkeyError, call

_HASHES = ("sha1", "sha256", "sha384", "sha512")
_real = {
    "new": hmac.new,
    "HMAC": hmac.HMAC,
    "digest": getattr(hmac, "digest", None),
    "pbkdf2_hmac": hashlib.pbkdf2_hmac,
    "hashlib_new": hashlib.new,
}
_real_ctors = {n: getattr(hashlib, n) for n in _HASHES}
_b64 = lambda b: base64.b64encode(bytes(b)).decode()


def unsupported(what):
    raise DoppelkeyError(
        "unsupported",
        "%s is not supported with a doppelkey handle yet, so the call was refused instead of computing with the handle text" % what,
        "See docs/research.md or open an issue.",
    )


def _hash_name(digestmod):
    if digestmod is None or digestmod == "":
        raise TypeError("Missing required parameter 'digestmod'.")
    if isinstance(digestmod, str):
        name = digestmod
    elif callable(digestmod):
        name = digestmod().name
    else:
        name = digestmod.new().name
    name = name.lower().replace("-", "").replace("_", "")
    if name not in _HASHES:
        raise DoppelkeyError("bad_request", 'hash "%s" is not supported with a doppelkey handle (supported: SHA-1, SHA-256, SHA-384, SHA-512)' % name)
    return name


def _handle_bytes(r, length=None):
    out = r["handle"].encode("latin-1")
    if length is not None and len(out) != length:
        raise DoppelkeyError("bad_reply", "keeper returned a %d-byte handle, expected %d" % (len(out), length), "doppelkey doctor")
    return out


class RemoteHMAC(object):
    """Stands in for hmac.HMAC when the key is a handle."""

    def __init__(self, ref, msg, name, buf=None):
        self._ref, self._alg = ref, name
        self._buf = bytearray(buf or b"")
        h = _real_ctors[name]()
        self.digest_size, self.block_size = h.digest_size, h.block_size
        if msg is not None:
            self.update(msg)

    @property
    def name(self):
        return "hmac-" + self._alg

    def update(self, msg):
        self._buf += msg

    def copy(self):
        return RemoteHMAC(self._ref, None, self._alg, self._buf)

    def digest(self):
        r = call("hmac", dict(self._ref.fields(), alg=self._alg, data=_b64(self._buf)))
        # A handle comes back when the output is itself a key (AWS SigV4 intermediate keys).
        return r["handle"].encode("latin-1") if "handle" in r else base64.b64decode(r["digest"])

    def hexdigest(self):
        return self.digest().hex()


def _ref_of(key):
    return recognise(key) if isinstance(key, (bytes, bytearray, memoryview)) else None


def new(key, msg=None, digestmod=""):
    ref = _ref_of(key)
    if ref is None:
        return _real["new"](key, msg, digestmod)
    return RemoteHMAC(ref, msg, _hash_name(digestmod))


class HMAC(_real["HMAC"]):
    __slots__ = ()

    def __new__(cls, key, msg=None, digestmod=""):
        ref = _ref_of(key)
        if ref is not None:
            return RemoteHMAC(ref, msg, _hash_name(digestmod))
        return super(HMAC, cls).__new__(cls)


def digest(key, msg, digest):
    ref = _ref_of(key)
    if ref is None:
        return _real["digest"](key, msg, digest)
    return RemoteHMAC(ref, msg, _hash_name(digest)).digest()


class DerivingHash(object):
    """A hash whose input contains a handle: digest() is computed by the keeper over the real
    key and returned as a new handle (how Django and itsdangerous derive signing keys)."""

    def __init__(self, name, data=b""):
        self.name = name
        self._buf = bytearray(data)
        h = _real_ctors[name]()
        self.digest_size, self.block_size = h.digest_size, h.block_size

    def update(self, data):
        self._buf += data

    def copy(self):
        return DerivingHash(self.name, self._buf)

    def digest(self):
        buf = bytes(self._buf)
        found = find_in(buf)
        if not found:
            return _real_ctors[self.name](buf).digest()
        start, end, ref = found
        r = call("hash_derive", dict(ref.fields(), hash=self.name, prefix_data=_b64(buf[:start]), suffix_data=_b64(buf[end:]), length=self.digest_size))
        return _handle_bytes(r, self.digest_size)

    def hexdigest(self):
        return self.digest().hex()


def _make_ctor(name):
    real = _real_ctors[name]

    def ctor(data=b"", **kw):
        if "string" in kw:
            data = kw.pop("string")
        if data and b"dk1:" in bytes(data) and find_in(bytes(data)):
            return DerivingHash(name, data)
        return real(data, **kw)

    ctor.__name__ = ctor.__qualname__ = name
    return ctor


def hashlib_new(name, data=b"", **kw):
    n = name.lower().replace("-", "")
    if n in _HASHES and data and b"dk1:" in bytes(data) and find_in(bytes(data)):
        return DerivingHash(n, data)
    return _real["hashlib_new"](name, data, **kw)


def pbkdf2_hmac(hash_name, password, salt, iterations, dklen=None):
    ref = _ref_of(password)
    if ref is None:
        return _real["pbkdf2_hmac"](hash_name, password, salt, iterations, dklen)
    name = _hash_name(hash_name)
    length = dklen or _real_ctors[name]().digest_size
    r = call("pbkdf2", dict(ref.fields(), hash=name, salt=_b64(salt), iterations=int(iterations), length=length))
    return _handle_bytes(r, length)


# ---------- cryptography's AESGCM (wrapped when the app imports it) ----------
_AEAD_MODULE = "cryptography.hazmat.primitives.ciphers.aead"


def _wrap_aead(mod):
    Real = getattr(mod, "AESGCM", None)
    if Real is None or getattr(Real, "_doppelkey", False):
        return
    from cryptography.exceptions import InvalidTag

    class AESGCM(object):
        _doppelkey = True
        generate_key = staticmethod(Real.generate_key)

        def __init__(self, key):
            self._ref = _ref_of(key)
            if self._ref is None:
                self._inner = Real(key)
            else:
                if len(key) not in (16, 24, 32):
                    raise ValueError("AESGCM key must be 128, 192, or 256 bits.")
                self._bits = len(key) * 8

        def _remote(self, mode, nonce, data, aad):
            if len(nonce) != 12:
                unsupported("AES-GCM with a %d-byte nonce (only 12-byte nonces)" % len(nonce))
            p = dict(self._ref.fields(), mode=mode, iv=_b64(nonce), data=_b64(data), key_bits=self._bits)
            if aad:
                p["aad"] = _b64(aad)
            try:
                return base64.b64decode(call("aes_gcm", p)["out"])
            except DoppelkeyError as e:
                if e.code == "crypto_error":
                    raise InvalidTag()
                raise

        def encrypt(self, nonce, data, associated_data):
            if self._ref is None:
                return self._inner.encrypt(nonce, data, associated_data)
            return self._remote("encrypt", nonce, data, associated_data)

        def decrypt(self, nonce, data, associated_data):
            if self._ref is None:
                return self._inner.decrypt(nonce, data, associated_data)
            return self._remote("decrypt", nonce, data, associated_data)

    AESGCM.__name__ = AESGCM.__qualname__ = "AESGCM"
    AESGCM.__module__ = Real.__module__
    mod.AESGCM = AESGCM


class _PostImport(importlib.abc.MetaPathFinder):
    """Wrap a module's attributes right after it is first imported."""

    def find_spec(self, fullname, path, target=None):
        if fullname != _AEAD_MODULE:
            return None
        sys.meta_path.remove(self)
        try:
            spec = importlib.util.find_spec(fullname)
        finally:
            sys.meta_path.insert(0, self)
        if spec is None or spec.loader is None:
            return spec
        loader = spec.loader
        orig_exec = loader.exec_module

        def exec_module(module):
            orig_exec(module)
            try:
                _wrap_aead(module)
            except Exception:  # never break the import itself
                pass

        loader.exec_module = exec_module
        return spec


def install():
    if getattr(sys, "_doppelkey_installed", False):
        return
    sys._doppelkey_installed = True
    hmac.new = new
    hmac.HMAC = HMAC
    if _real["digest"] is not None:
        hmac.digest = digest
    for n in _HASHES:
        setattr(hashlib, n, _make_ctor(n))
    hashlib.new = hashlib_new
    hashlib.pbkdf2_hmac = pbkdf2_hmac
    if _AEAD_MODULE in sys.modules:
        _wrap_aead(sys.modules[_AEAD_MODULE])
    else:
        sys.meta_path.insert(0, _PostImport())
