# sitecustomize.py — Python counterpart of shim.cjs. Put its folder on PYTHONPATH.
import hashlib, hmac, json, os, re, socket, base64
SOCK = os.environ.get('KEEPER_SOCK', '/tmp/keeper.sock')
H = re.compile(rb'KH1:[0-9a-f]{16}[.]*')
_f = None
def _call(req):
    global _f
    if _f is None:
        c = socket.socket(socket.AF_UNIX); c.connect(SOCK); _f = c.makefile('rwb')
    _f.write(json.dumps(req).encode() + b'\n'); _f.flush()
    r = json.loads(_f.readline())
    if not r['ok']: raise RuntimeError('keeper: ' + r['error'])
    return r
b64 = lambda b: base64.b64encode(b).decode()
def _as_bytes(k):
    return k.encode('latin1') if isinstance(k, str) else bytes(k) if isinstance(k, (bytes, bytearray, memoryview)) else None

_real_new = hmac.new
class _RemoteHMAC:
    def __init__(self, handle, msg, digestmod, prefix=None):
        self.handle, self.buf, self.prefix = handle, bytearray(msg or b''), prefix
        self.alg = digestmod if isinstance(digestmod, str) else digestmod().name
        self.digest_size = hashlib.new(self.alg).digest_size
    def update(self, m): self.buf += m
    def copy(self): c = _RemoteHMAC(self.handle, bytes(self.buf), self.alg, self.prefix); return c
    def digest(self):
        req = {'op': 'hmac', 'handle': self.handle, 'alg': self.alg, 'data': b64(bytes(self.buf))}
        if self.prefix is not None: req['prefix'] = b64(self.prefix)
        r = _call(req)
        # A handle comes back when the output is itself a key (SigV4 intermediate keys).
        return r['handle'].encode('latin1') if 'handle' in r else base64.b64decode(r['digest'])
    def hexdigest(self): return self.digest().hex()
PREFIXED = re.compile(rb'(.{1,8}?)(KH1:[0-9a-f]{16}[.]*)', re.S)
def _new(key, msg=None, digestmod=''):
    kb = _as_bytes(key)
    if kb is not None:
        if H.fullmatch(kb): return _RemoteHMAC(kb.decode('latin1'), msg, digestmod)
        p = PREFIXED.fullmatch(kb)  # e.g. AWS SigV4's b"AWS4" + secret
        if p: return _RemoteHMAC(p.group(2).decode('latin1'), msg, digestmod, p.group(1))
    return _real_new(key, msg, digestmod)
hmac.new = _new

# Hash-based key derivation: hasher(salt + SECRET).digest() — the result becomes a new handle.
class _DerivingHash:
    def __init__(self, name, data=b''):
        self.name, self.buf = name, bytearray(data)
        self.digest_size = hashlib.new(name).digest_size; self.block_size = hashlib.new(name).block_size
    def update(self, d): self.buf += d
    def copy(self): return _DerivingHash(self.name, bytes(self.buf))
    def digest(self):
        m = H.search(bytes(self.buf))
        if not m: h = hashlib.new(self.name); h.update(bytes(self.buf)); return h.digest()
        r = _call({'op': 'hashDerive', 'handle': m.group().decode('latin1'), 'hash': self.name,
                   'prefix': b64(bytes(self.buf[:m.start()])), 'suffix': b64(bytes(self.buf[m.end():])), 'length': self.digest_size})
        return r['handle'].encode('latin1')
    def hexdigest(self): return self.digest().hex()
for _name in ('sha1', 'sha256', 'sha512'):
    _orig = getattr(hashlib, _name)
    def _make(name, orig):
        def ctor(data=b'', **kw):
            if H.search(bytes(data)): return _DerivingHash(name, data)
            o = orig(data, **kw)
            return o
        return ctor
    setattr(hashlib, _name, _make(_name, _orig))
