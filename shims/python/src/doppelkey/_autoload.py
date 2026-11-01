"""Imported at interpreter start (doppelkey.pth or sitecustomize). Patches crypto entry points."""
import os

if os.environ.get("DOPPELKEY_SHIM") != "off":
    from . import _patch

    _patch.install()
