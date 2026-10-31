# doppelkey (Python shim)

Pure Python, zero dependencies. Installing the package drops `doppelkey.pth` into site-packages, so every Python process in the environment loads the shim. It does nothing unless a doppelkey handle is used as a key.

| Patched | With a handle |
| --- | --- |
| `hmac.new`, `hmac.HMAC`, `hmac.digest` | keeper `hmac` |
| `hashlib.sha1/sha256/sha384/sha512`, `hashlib.new` over input containing a handle | a new handle (how Django and itsdangerous derive keys) |
| `hashlib.pbkdf2_hmac` | a new handle |
| `cryptography`'s `AESGCM` (wrapped when imported) | keeper `aes_gcm` |

Covers PyJWT, itsdangerous (Flask sessions), Django signing, boto3 SigV4 (and SigV2 presigning if the key's policy allows it), and AES-GCM field encryption. `doppelkey init` writes the `.pth` into your project's venv for you; `doppelkey run -- python app.py` loads it for one command.

Part of [doppelkey](https://github.com/KaiHongTan/dopplekey), an ssh-agent for app secrets.
