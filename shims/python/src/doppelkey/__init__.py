"""doppelkey: an ssh-agent for app secrets (Python shim).

Values in your environment are doppelkey handles; hmac, hashlib and cryptography's AESGCM
calls made with a handle are performed by the doppelkey keeper. Loaded automatically by the
doppelkey.pth file this package installs, or by `doppelkey run -- python ...`.
"""
from ._handle import recognise
from ._keeper import DoppelkeyError, socket_path

__version__ = "0.1.0"
__all__ = ["recognise", "DoppelkeyError", "socket_path", "__version__", "is_active"]


def is_active():
    import sys

    return bool(getattr(sys, "_doppelkey_installed", False))
