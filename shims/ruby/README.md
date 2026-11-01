# doppelkey (Ruby shim)

Pure Ruby, zero dependencies. When a key passed to OpenSSL is a doppelkey handle, the operation is performed by the doppelkey keeper; every other call runs unchanged.

| Patched | With a handle |
| --- | --- |
| `OpenSSL::HMAC.new`, `.digest`, `.hexdigest`, `.base64digest` | keeper `hmac` |
| `OpenSSL::PKCS5.pbkdf2_hmac`, `pbkdf2_hmac_sha1`, `OpenSSL::KDF.pbkdf2_hmac` | a new handle (derived key stays in the keeper) |
| `OpenSSL::KDF.hkdf` | a new handle |
| `OpenSSL::Cipher` (AES-128/192/256 GCM and CBC) | keeper `aes_gcm` / `aes_cbc` |
| `OpenSSL::KDF.scrypt`, other ciphers | refused |

This covers Rails: `secret_key_base` → `ActiveSupport::KeyGenerator` (PBKDF2) → `MessageVerifier` (HMAC) and `MessageEncryptor` (AES-256-GCM), plus the `jwt` gem. `RAILS_MASTER_KEY` can't be protected: it is a 16-byte AES key, too short to hold a handle.

## Loading

- Rails: `doppelkey init` adds a guarded `require` to `config/boot.rb`.
- Anything else: `RUBYOPT="-r/path/to/doppelkey/register.rb"` (`eval "$(doppelkey env)"` prints it), or `doppelkey run -- ruby app.rb`.
