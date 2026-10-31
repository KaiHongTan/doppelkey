"""Oracle-pattern tests for the Python shim.

Apps run with handles in their environment and the shim on PYTHONPATH; this process holds the
real keys (fixture vault, fake secrets), never loads the shim, and verifies every output. It
also scans the live app's memory (/proc/<pid>/mem, what a same-user agent could read).

    python3 -m unittest -v test_compat        (uses .venv if present)
    DOPPELKEY_KEEPER_CMD="target/debug/doppelkeyd insecure-test-keeper" ...   (Rust keeper)
"""
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "../.."))
VAULT_FILE = os.path.join(ROOT, "compat/fixtures/vault.json")
def read_json(path):
    with open(path) as f:
        return json.load(f)


VAULT = read_json(VAULT_FILE)
PY = os.path.join(HERE, ".venv/bin/python") if os.path.exists(os.path.join(HERE, ".venv/bin/python")) else sys.executable
LABEL = "NOT-A-SECRET-load-doppelkey-shim"


def real(name):
    e = VAULT["keys"][name]
    return base64.b64decode(e["value_b64"]) if "value_b64" in e else e["value"].encode()


def crc(i):
    return hashlib.sha256(("dk1:" + i).encode()).hexdigest()[:4]


def env_value(e):
    """What `doppelkey protect` writes (same as compat/test-keeper/handles.mjs envValue)."""
    prefix, form = e.get("prefix", ""), e.get("form", "long")
    key_len = len(base64.b64decode(e["value_b64"])) if "value_b64" in e else len(e["value"].encode())
    if form == "long":
        return prefix + "dk1:%s:%s:%s" % (LABEL, e["id"], crc(e["id"]))
    n = key_len if form in ("hex", "base64") else key_len - len(prefix)
    padded = ("dk1:%s%s" % (e["id"], crc(e["id"]))).ljust(n, ".")
    if form == "compact":
        return prefix + padded
    if form == "hex":
        return prefix + binascii.hexlify(padded.encode()).decode()
    return prefix + base64.b64encode(padded.encode()).decode()


HANDLES = {n: env_value(e) for n, e in VAULT["keys"].items()}


def forms(needle):
    out = [needle, binascii.hexlify(needle), base64.b64encode(needle).rstrip(b"="), base64.urlsafe_b64encode(needle).rstrip(b"=")]
    try:
        out.append(needle.decode("ascii").encode("utf-16-le"))
    except UnicodeDecodeError:
        pass
    return [f for f in out if len(f) >= 16]


def scan_process(pid, needles):
    """Names of needles found anywhere in the live process's readable memory."""
    found = set()
    with open("/proc/%d/maps" % pid) as f:
        maps = f.read().splitlines()
    mem = open("/proc/%d/mem" % pid, "rb", 0)
    for line in maps:
        addr, perms = line.split()[:2]
        if not perms.startswith("r") or "[vvar" in line or "[vsyscall" in line:
            continue
        lo, hi = (int(x, 16) for x in addr.split("-"))
        try:
            mem.seek(lo)
            chunk = mem.read(hi - lo)
        except (OSError, OverflowError, ValueError):
            continue
        for name, n in needles.items():
            if name not in found and any(f in chunk for f in forms(n)):
                found.add(name)
    mem.close()
    return sorted(found)


class Keeper(object):
    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="dk-pykeeper-")
        os.chmod(self.dir, 0o700)
        self.sock = os.path.join(self.dir, "k.sock")
        cmd = os.environ.get("DOPPELKEY_KEEPER_CMD", "").split() or ["node", os.path.join(ROOT, "compat/test-keeper/keeper.mjs")]
        self.proc = subprocess.Popen(cmd + ["--vault", VAULT_FILE, "--socket", self.sock, "--audit", os.path.join(self.dir, "audit.jsonl")], stdout=subprocess.PIPE)
        line = self.proc.stdout.readline().decode()
        assert "listening" in line, line

    def stop(self):
        self.proc.stdout.close()
        self.proc.terminate()
        self.proc.wait()
        shutil.rmtree(self.dir, ignore_errors=True)


def run_app(keeper, scan_needles=None):
    out = os.path.join(tempfile.mkdtemp(prefix="dk-pyapp-"), "results.json")
    env = dict(PATH=os.environ["PATH"], HOME=os.environ.get("HOME", "/tmp"), PYTHONPATH=os.path.join(ROOT, "shims/python/src"),
               DOPPELKEY_SOCK=keeper.sock, DOPPELKEY_RESULTS=out, DOPPELKEY_WAIT="60",
               AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE", AWS_DEFAULT_REGION="ap-southeast-1", **HANDLES)
    p = subprocess.Popen([PY, os.path.join(HERE, "apps/libs.py")], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    line = p.stdout.readline().decode()
    if not line.startswith("READY"):
        p.kill()
        raise AssertionError("app failed: " + line + p.stderr.read().decode())
    results = read_json(out)
    found = scan_process(p.pid, scan_needles(results)) if scan_needles and sys.platform.startswith("linux") else None
    p.kill()
    p.wait()
    p.stdout.close()
    p.stderr.close()
    return results, found


def hx(key, msg, alg="sha256"):
    return hmac.new(key, msg, alg).hexdigest()


class PythonShim(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keeper = Keeper()
        cls.aws = None
        cls.r, cls.found = run_app(cls.keeper, cls.needles)

    @classmethod
    def tearDownClass(cls):
        cls.keeper.stop()

    @classmethod
    def needles(cls, r):
        n = {k: real(k) for k in VAULT["keys"]}
        c = real("COOKIE_SECRET")
        n["django derived key"] = hashlib.sha256(b"django.core.signing" + b"signer" + c).digest()
        n["itsdangerous derived key"] = hashlib.sha1(b"cookie-session" + b"signer" + c).digest()
        n["pbkdf2 derived key"] = hashlib.pbkdf2_hmac("sha256", real("SESSION_PASSWORD"), b"salt", 1000)
        cls.aws = cls.verify_aws(r)
        for i, v in enumerate(cls.aws):
            for j, k in enumerate(v.get("keys", [])):
                n["aws signing key %d.%d" % (i, j)] = bytes.fromhex(k)
        return n

    @staticmethod
    def verify_aws(r):
        a = r.get("aws") or {}
        reqs = [dict(kind="header", **x) for x in a.get("requests", [])]
        for k in ("presigned_v2", "presigned_v4"):
            if k in a:
                reqs.append({"kind": k, "method": "GET", "url": a[k], "headers": {}})
        out = subprocess.run(["node", os.path.join(HERE, "aws_verify.mjs")], input=json.dumps(reqs).encode(), capture_output=True, env=dict(os.environ, REAL_AWS_SECRET=real("AWS_SECRET_ACCESS_KEY").decode()))
        return json.loads(out.stdout or b"[]")

    def test_no_unexpected_errors(self):
        self.assertEqual({k: v for k, v in self.r["errors"].items() if k != "md5_refused"}, {})
        self.assertTrue(self.r["shim_active"])
        self.assertTrue(self.r["env_jwt_secret"].startswith("dk1:NOT-A-SECRET"))

    def test_stdlib_hmac(self):
        J = real("JWT_SECRET")
        self.assertEqual(self.r["hmac_new"], hx(J, b"hello"))
        self.assertEqual(self.r["hmac_digest"], hx(J, b"hello", "sha512"))
        self.assertEqual(self.r["hmac_class"], hx(J, b"hello"))
        self.assertEqual(self.r["hmac_copy"], hx(J, b"hello"))
        self.assertEqual(self.r["plain_untouched"], hx(b"not-a-handle", b"hello"))
        self.assertEqual(self.r["plain_hash_untouched"], hashlib.sha256(b"hello").hexdigest())
        self.assertIn('hash "md5" is not supported with a doppelkey handle', self.r["errors"]["md5_refused"])

    def test_pbkdf2(self):
        self.assertEqual(self.r["pbkdf2_then_hmac"], hx(hashlib.pbkdf2_hmac("sha256", real("SESSION_PASSWORD"), b"salt", 1000), b"hello"))

    def test_pyjwt(self):
        import jwt
        self.assertEqual(jwt.decode(self.r["pyjwt"]["token"], real("JWT_SECRET").decode(), algorithms=["HS256"])["sub"], "user1")
        self.assertEqual(self.r["pyjwt"]["verify"], "user1")

    def test_itsdangerous(self):
        import itsdangerous
        s = itsdangerous.URLSafeSerializer(real("COOKIE_SECRET").decode(), salt="cookie-session")
        self.assertEqual(s.loads(self.r["itsdangerous"]["cookie"])["user"], "alice")

    def test_django_signing(self):
        from django.conf import settings
        if not settings.configured:
            settings.configure(SECRET_KEY=real("COOKIE_SECRET").decode())
        from django.core import signing
        self.assertEqual(signing.loads(self.r["django"]["signed"])["user"], "alice")

    def test_flask_session(self):
        import flask
        from flask.sessions import SecureCookieSessionInterface
        app = flask.Flask("oracle")
        app.secret_key = real("COOKIE_SECRET").decode()
        s = SecureCookieSessionInterface().get_signing_serializer(app)
        self.assertEqual(s.loads(self.r["flask"]["cookie"])["user"], "alice")

    def test_cryptography_aesgcm(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        a = self.r["aesgcm"]
        self.assertEqual(AESGCM(real("ENCRYPTION_KEY_HEX")).decrypt(b"\x01" * 12, base64.b64decode(a["ct"]), b"aad"), b"field secret")
        self.assertEqual(AESGCM(real("ENCRYPTION_KEY")).decrypt(b"\x02" * 12, base64.b64decode(a["raw"]), None), b"raw key")
        self.assertEqual(a["back"], "field secret")
        self.assertEqual(a["tamper"], "InvalidTag")
        self.assertTrue(a["plain_ok"])

    def test_boto3(self):
        self.assertTrue(self.aws, "no AWS requests verified")
        for v in self.aws:
            self.assertTrue(v["ok"], v)
        scopes = [v["scope"] for v in self.aws]
        self.assertIn("sigv2", scopes)
        self.assertTrue(any(re.search(r"/ap-southeast-1/s3/aws4_request$", s or "") for s in scopes), scopes)
        self.assertIn('service "dynamodb" is not allowed', self.r["aws"]["dynamodb"])

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux only")
    def test_memory_holds_no_real_or_derived_keys(self):
        self.assertEqual(self.found, [])


class Vectors(unittest.TestCase):
    def test_shared_handle_vectors(self):
        sys.path.insert(0, os.path.join(ROOT, "shims/python/src"))
        from doppelkey._handle import recognise
        for v in read_json(os.path.join(ROOT, "crates/proto/vectors/handles.json"))["vectors"]:
            got = recognise(v["input"])
            if not v["valid"]:
                self.assertIsNone(got, v["note"])
                continue
            self.assertIsNotNone(got, v["note"])
            self.assertEqual(got.handle, v["handle"], v["note"])
            self.assertEqual(got.prefix.decode("latin-1"), v["prefix"], v["note"])
            self.assertEqual(got.key_encoding, v["key_encoding"], v["note"])


if __name__ == "__main__":
    unittest.main()
