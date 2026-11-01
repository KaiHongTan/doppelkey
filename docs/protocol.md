# doppelkey wire protocol v1 and handle format v1

The contract between the shims (`shims/*`) and a keeper: `doppelkeyd`, or the Node test keeper in `compat/test-keeper`. Shared test vectors live in `crates/proto/vectors/`; every shim and both keepers are tested against them.

## Handles

### Core forms

A **core** is the smallest unit that names one key in the keeper.

| Form | Text | Bytes | Use |
| --- | --- | --- | --- |
| long | `dk1:NOT-A-SECRET-load-doppelkey-shim:<id>:<crc>` | 58 | default for values in `.env`: self-explaining |
| compact | `dk1:<id><crc>` | 20 | derived keys, secrets shorter than 58 bytes, encoded variants |

- `<id>`: 12 lowercase hex characters (48 bits). The same id may appear in either form.
- `<crc>`: the first 4 lowercase hex characters of `SHA-256("dk1:" + id)`. A string with a bad crc is **not** a handle.
- 20 bytes is the floor because itsdangerous derives 20-byte (SHA-1) keys. A derived key shorter than 20 bytes cannot carry a handle; the keeper refuses to derive it (`bad_request`).

### Padding and concatenation

- **Padding:** a core may be followed by any number of `.` characters. Padding lets a handle match the original secret's length, or a derived key's length.
- **Concatenation:** a **handle** is one or more padded cores back to back. A concatenation names the concatenation of the keys' bytes. A 64-byte derived key is returned as two 32-byte handles, because libraries such as jose split AES-CBC-HMAC keys in half.

### Recognising a key

A shim looks at the bytes of a key, read as latin1 text:

```
^(?<prefix>[\s\S]{0,8}?)(?<handle>(?:dk1:(?:NOT-A-SECRET-load-doppelkey-shim:[0-9a-f]{12}:|[0-9a-f]{12})[0-9a-f]{4}\.*)+)$
```

- Every core must have a valid crc.
- The prefix (at most 8 bytes) is sent to the keeper. It covers vendor prefixes such as `whsec_` (when the keeper stores the full value) and key-schedule prefixes such as AWS SigV4's `"AWS4"`. The keeper decides which prefixes are allowed for which key.

### Encoded handles (format-preserving variants)

Some apps validate the format of a secret, or decode it before use. For these, `.env` holds an **encoding of the compact core**, padded to the real key's decoded length:

| Variant | `.env` value | What the app's crypto call sees |
| --- | --- | --- |
| hex | `hex(core + padding)` | decoded bytes = the core, or the hex text |
| base64 | `base64(core + padding)` | decoded bytes = the core, or the base64 text |
| vendor + base64 | e.g. `whsec_` + base64(core) for svix | decoded bytes = the core |

The keeper stores the real **decoded** bytes. When the app decodes, the shim sees core bytes and the keeper uses the bytes. When the app instead uses the encoded *text* as the key, the shim recognises hex text starting `646b313a` or base64 text starting `ZGsxO`. It sends `key_encoding: "hex"` or `"base64"`, and the keeper uses the same encoding of the real bytes as the key. Both paths produce the same result as the real secret.

## Transport

- **Socket:** a Unix domain socket, mode 0600, in a directory with mode 0700. Path, first match wins:
  1. `$DOPPELKEY_SOCK`
  2. `$XDG_RUNTIME_DIR/doppelkey/doppelkeyd.sock`
  3. `<os tmpdir>/doppelkey-<uid>/doppelkeyd.sock`
- **Frame:** a 4-byte big-endian length, then that many bytes of UTF-8 JSON. Maximum frame size is 16 MiB.
- **Ordering:** a connection may carry many requests. Responses carry the request `id` and may arrive in any order.
- Binary fields are standard base64 with padding.

## Messages

```jsonc
// request
{ "v": 1, "id": 7, "op": "hmac", "handle": "dk1:…", "alg": "sha256", "data": "aGVsbG8=" }
// success
{ "v": 1, "id": 7, "ok": true, "result": { "digest": "…" } }
// failure
{ "v": 1, "id": 7, "ok": false, "error": { "code": "op_not_allowed", "message": "…", "hint": "doppelkey policy JWT_SECRET --allow hkdf" } }
```

Common optional request fields for any op with a `handle`:

- `prefix`: base64 bytes found before the handle.
- `key_encoding`: `"hex"` or `"base64"` (see above).

| op | params | result |
| --- | --- | --- |
| `hmac` | `alg` (`sha1` `sha256` `sha384` `sha512`), `data` | `digest`, **or** `handle` when the output is itself a key (AWS SigV4 intermediate keys) |
| `hash_derive` | `hash`, `prefix_data`, `suffix_data`, `length` | `handle`: a key = `hash(prefix_data ‖ key ‖ suffix_data)` truncated to `length` |
| `hkdf` | `hash`, `salt`, `info`, `length` | `handle` (split-half rule for 64 bytes) |
| `pbkdf2` | `hash`, `salt`, `iterations`, `length` | `handle` (split-half rule for 64 bytes) |
| `aes_gcm` | `mode` (`encrypt`/`decrypt`), `iv` (12 bytes), `data`, `aad?`, `key_bits?` | `out`. Ciphertext ends with the 16-byte tag; decrypt input must include it |
| `aes_cbc` | `mode`, `iv` (16 bytes), `data`, `padding?` (default `true`, PKCS#7), `key_bits?` | `out` |
| `status` | none | `version`, `keys` (names only), `protocol`, `locked`, `vault` (`passphrase`, `keychain`, `file`, `test` or null) |

- `key_bits`, when present, must equal the real key's length in bits. Otherwise the request fails with `bad_request`. This catches an app using `aes-128-gcm` with a 32-byte key.
- v1 restricts AES-GCM to 12-byte IVs and 16-byte tags, so every keeper can implement it with a fixed RustCrypto type.

### Admin ops

Used by the `doppelkey` CLI, which never decrypts the vault itself. None of them returns key material.

| op | params | result |
| --- | --- | --- |
| `unlock` | `passphrase` | unlocks a passphrase vault |
| `lock` | none | wipes keys from memory |
| `reload` | none | re-reads the vault file |
| `vault_create` | `protect` (`passphrase`, `keychain`, `file`), `passphrase?` | creates and unlocks a new vault |
| `import` | `name`, `value_b64`, `form`, `prefix`, `policy`, `project`, `file`, `original` | `id`, `written` (the handle text to put in the file). The same value in the same project reuses its id |
| `backup_put` | `path`, `content_b64` | keeps the first backup of a project file `init` changes |
| `policies` | `name?`, `ids?` | `keys`: `id`, `name`, `policy` |
| `set_policy` | `ids`, `edit`, `passphrase?` | `keys`. An edit that loosens a policy needs a human (below) |
| `eject` | `ids`, `targets?` (`id`, `file`), `paths`, `project`, `passphrase?` | needs a human. The keeper writes the original values back into the files (the recorded file, or a target inside the key's project) and returns `restored` (ids and names), `problems` and the requested file `backups` |
| `forget` | `ids`, `paths` | removes keys (only ones just ejected) and backups |

**Human approval** is decided by the keeper. Passphrase vault: `passphrase` must open the vault, and nothing else counts. Keychain vault: the keeper's own `/usr/bin/osascript` dialog. Key-file vault: any keeper prompt, including `DOPPELKEY_ASKPASS`. A refusal is `confirm_denied`.

### Error codes

| code | meaning | hint names |
| --- | --- | --- |
| `unknown_handle` | no such key, or a bad crc | `doppelkey doctor` |
| `op_not_allowed` | policy refuses this op, service or prefix for this key | `doppelkey policy <NAME> --allow <op>` |
| `rate_limited` | per-key rate limit hit | `doppelkey policy <NAME>` |
| `confirm_denied` | the human refused a prompt, or approval (passphrase or dialog) is missing or wrong | none |
| `bad_request` | malformed request, unsupported algorithm, wrong key size, or derived key too short | the fix |
| `crypto_error` | e.g. AES-GCM authentication failed | none |
| `version_mismatch` | `v` is not 1 | `doppelkey doctor` |
| `locked` | the keeper's vault is locked | `doppelkey unlock` |

Shims add `keeper_unreachable`, `keeper_timeout` and `unsupported` (an algorithm the shim refuses to run with a handle) locally. Every message a shim throws names the next command to run.

### No export

There is no op that returns key material, and keepers must not add one. Every result is one of: a MAC, a ciphertext or plaintext, a new handle, or names. Even an approved `eject` returns none: the keeper writes the values to disk itself. The test suite checks that no response to any op (including unknown ops) contains a real key in raw, hex, base64 or base64url form.

## Derived handles

- Derived handles are **deterministic** per keeper: the id is `HMAC-SHA256(keeper_salt, seed)`, truncated to 12 hex characters.
- The seed encodes the parent handle id(s), the op and every parameter.
- Same parent + same parameters → same handle, so key IDs stay stable for the life of the keeper salt.
- A derived key's allowed ops are `hmac`, `aes_gcm` and `aes_cbc`.
