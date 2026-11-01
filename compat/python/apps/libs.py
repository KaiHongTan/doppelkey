# Unmodified uses of popular Python libraries. Writes results, then waits so the oracle can
# scan this process's memory.
import base64, hashlib, hmac, json, os, sys, time

env = os.environ
results = {"errors": {}}


def attempt(name, fn):
    try:
        results[name] = fn()
    except Exception as e:  # record the error text
        results["errors"][name] = "%s: %s" % (type(e).__name__, e)


JWT, COOKIE = env["JWT_SECRET"], env["COOKIE_SECRET"]
attempt("hmac_new", lambda: hmac.new(JWT.encode(), b"hello", hashlib.sha256).hexdigest())
attempt("hmac_digest", lambda: hmac.digest(JWT.encode(), b"hello", "sha512").hex())
attempt("hmac_class", lambda: hmac.HMAC(JWT.encode(), b"hello", "sha256").hexdigest())
attempt("hmac_copy", lambda: (lambda h: (h.update(b"lo"), h.copy().hexdigest())[1])(hmac.new(JWT.encode(), b"hel", "sha256")))
attempt("pbkdf2_then_hmac", lambda: hmac.new(hashlib.pbkdf2_hmac("sha256", env["SESSION_PASSWORD"].encode(), b"salt", 1000), b"hello", "sha256").hexdigest())
attempt("plain_untouched", lambda: hmac.new(b"not-a-handle", b"hello", "sha256").hexdigest())
attempt("plain_hash_untouched", lambda: hashlib.sha256(b"hello").hexdigest())
attempt("md5_refused", lambda: hmac.new(JWT.encode(), b"x", "md5").hexdigest())


def pyjwt():
    import jwt
    t = jwt.encode({"sub": "user1"}, JWT, algorithm="HS256")
    return {"token": t, "verify": jwt.decode(t, JWT, algorithms=["HS256"])["sub"]}


attempt("pyjwt", pyjwt)


def its():
    import itsdangerous
    s = itsdangerous.URLSafeSerializer(COOKIE, salt="cookie-session")  # SHA-1 key derivation: 20-byte keys
    c = s.dumps({"user": "alice"})
    return {"cookie": c, "loads": s.loads(c)["user"]}


attempt("itsdangerous", its)


def dj():
    from django.conf import settings
    settings.configure(SECRET_KEY=COOKIE)
    from django.core import signing
    v = signing.dumps({"user": "alice"})
    return {"signed": v, "loads": signing.loads(v)["user"]}


attempt("django", dj)


def fl():
    import flask
    app = flask.Flask("app")
    app.secret_key = COOKIE

    @app.route("/")
    def index():
        flask.session["user"] = "alice"
        return "ok"

    c = app.test_client()
    resp = c.get("/")
    cookie = resp.headers["Set-Cookie"].split(";")[0].split("=", 1)[1]
    return {"cookie": cookie}


attempt("flask", fl)


def aes():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    k = AESGCM(bytes.fromhex(env["ENCRYPTION_KEY_HEX"]))
    ct = k.encrypt(b"\x01" * 12, b"field secret", b"aad")
    back = k.decrypt(b"\x01" * 12, ct, b"aad")
    try:
        k.decrypt(b"\x01" * 12, ct[:-1] + bytes([ct[-1] ^ 1]), b"aad")
        tamper = "accepted"
    except InvalidTag:
        tamper = "InvalidTag"
    raw = AESGCM(env["ENCRYPTION_KEY"].encode()).encrypt(b"\x02" * 12, b"raw key", None)
    plain = AESGCM(AESGCM.generate_key(bit_length=128))
    return {"ct": base64.b64encode(ct).decode(), "back": back.decode(), "tamper": tamper, "raw": base64.b64encode(raw).decode(), "plain_ok": plain.decrypt(b"\x03" * 12, plain.encrypt(b"\x03" * 12, b"x", None), None) == b"x"}


attempt("aesgcm", aes)


def aws():
    import boto3
    from botocore.awsrequest import AWSResponse
    from botocore.config import Config

    captured = []

    class _Raw:
        def stream(self, **kw):
            yield b""

        def read(self, *a, **kw):
            return b""

    def capture(request, **kw):
        body = request.body or b""
        body = body.encode() if isinstance(body, str) else (body.read() if hasattr(body, "read") else bytes(body))
        captured.append({"method": request.method, "url": request.url, "headers": {k: (v.decode() if isinstance(v, bytes) else v) for k, v in request.headers.items()}, "bodySha256": hashlib.sha256(body).hexdigest()})
        return AWSResponse(request.url, 200, {"ETag": '"x"'}, _Raw())

    s3 = boto3.client("s3")
    s3.meta.events.register("before-send.s3.*", capture)
    s3.put_object(Bucket="doppelkey-test", Key="hello.txt", Body=b"hello from doppelkey")
    out = {"requests": captured, "presigned_v2": s3.generate_presigned_url("get_object", Params={"Bucket": "doppelkey-test", "Key": "hello.txt"}, ExpiresIn=600)}
    v4 = boto3.client("s3", config=Config(signature_version="s3v4"))
    out["presigned_v4"] = v4.generate_presigned_url("get_object", Params={"Bucket": "doppelkey-test", "Key": "hello.txt"}, ExpiresIn=600)
    try:
        ddb = boto3.client("dynamodb")
        ddb.meta.events.register("before-send.dynamodb.*", capture)
        ddb.list_tables()
        out["dynamodb"] = "signed"
    except Exception as e:
        out["dynamodb"] = str(e)[:300]
    return out


attempt("aws", aws)
results["env_jwt_secret"] = JWT
import doppelkey
results["shim_active"] = doppelkey.is_active()
with open(env["DOPPELKEY_RESULTS"], "w") as f:
    json.dump(results, f, indent=1)
print("READY", os.getpid(), flush=True)
if env.get("DOPPELKEY_WAIT"):
    time.sleep(float(env["DOPPELKEY_WAIT"]))
