"""Blocking wire-protocol v1 client: 4-byte big-endian length + JSON, over a Unix socket."""
import json
import os
import socket
import struct
import tempfile
import threading


class DoppelkeyError(RuntimeError):
    def __init__(self, code, message, hint=None):
        self.code, self.hint = code, hint
        if hint and hint.startswith("doppelkey "):
            advice = ' Run "%s".' % hint
        elif hint:
            advice = " " + hint
        else:
            advice = ""
        RuntimeError.__init__(self, "doppelkey: %s.%s" % (message.rstrip(". "), advice))


def socket_path():
    if os.environ.get("DOPPELKEY_SOCK"):
        return os.environ["DOPPELKEY_SOCK"]
    if os.environ.get("XDG_RUNTIME_DIR"):
        return os.path.join(os.environ["XDG_RUNTIME_DIR"], "doppelkey", "doppelkeyd.sock")
    uid = os.getuid() if hasattr(os, "getuid") else "user"
    return os.path.join(tempfile.gettempdir(), "doppelkey-%s" % uid, "doppelkeyd.sock")


_lock = threading.Lock()
_conn = None
_pid = None
_seq = 0


def _connect():
    global _conn, _pid
    path = socket_path()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(float(os.environ.get("DOPPELKEY_TIMEOUT_MS", "30000")) / 1000)
    try:
        s.connect(path)
    except OSError:
        s.close()
        raise DoppelkeyError("keeper_unreachable", "keeper not running (no keeper at %s)" % path, "doppelkey doctor")
    _conn, _pid = s, os.getpid()


def _recv_exact(n):
    buf = b""
    while len(buf) < n:
        chunk = _conn.recv(n - len(buf))
        if not chunk:
            raise OSError("keeper closed the connection")
        buf += chunk
    return buf


def call(op, params):
    """Send one request and return its result. Raises DoppelkeyError."""
    global _seq, _conn
    with _lock:
        if _conn is None or _pid != os.getpid():  # reconnect after fork
            _connect()
        _seq += 1
        req = dict(params, v=1, id=_seq, op=op)
        body = json.dumps(req).encode()
        try:
            _conn.sendall(struct.pack(">I", len(body)) + body)
            while True:
                (n,) = struct.unpack(">I", _recv_exact(4))
                msg = json.loads(_recv_exact(n).decode())
                if msg.get("id") == _seq:
                    break
        except socket.timeout:
            _conn.close()
            _conn = None
            raise DoppelkeyError("keeper_timeout", "keeper did not answer in time", "doppelkey doctor")
        except OSError as e:
            _conn.close()
            _conn = None
            raise DoppelkeyError("keeper_unreachable", "keeper connection failed: %s" % e, "doppelkey doctor")
    if msg.get("ok"):
        return msg.get("result", {})
    e = msg.get("error") or {}
    code = e.get("code", "error")
    hint = e.get("hint") or ("doppelkey doctor" if code in ("unknown_handle", "version_mismatch") else None)
    raise DoppelkeyError(code, e.get("message", "keeper error"), hint)
