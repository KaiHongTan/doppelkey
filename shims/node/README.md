# doppelkey (Node shim)

`doppelkey/register` keeps signing and encryption keys out of your Node process. Values in your environment are doppelkey **handles**. When a crypto call receives a handle as its key, the shim forwards the operation to the doppelkey keeper over a Unix socket and returns the result. Calls with any other key run unchanged.

```bash
node --require doppelkey/register app.js       # CommonJS or ESM apps
node --import doppelkey/register app.mjs       # ESM entry
NODE_OPTIONS="--require doppelkey/register" npm run dev
```

**Zero runtime dependencies.** The build is a single file, `dist/register.cjs`, plus a one-line ESM entry `dist/register.mjs`.

## What it patches

| Area | Functions | With a handle |
| --- | --- | --- |
| node:crypto | `createHmac` (incl. stream use) | keeper `hmac` |
| | `createCipheriv`, `createDecipheriv` (AES-128/192/256 GCM and CBC) | keeper `aes_gcm` / `aes_cbc` |
| | `hkdf`, `hkdfSync`, `pbkdf2`, `pbkdf2Sync` | keeper returns a new handle |
| | `createSecretKey`, `KeyObject.from`, `KeyObject#export` | decoy `KeyObject` of random bytes; `export()` gives back the handle |
| | `scrypt`, `scryptSync` | refused (not supported yet) |
| node:crypto | `createHash`, `crypto.hash` over a handle | a new handle; RFC 7638 JWK thumbprints of a handle are computed by the keeper (Auth.js `kid`) |
| WebCrypto | `importKey` (raw, jwk) | decoy `CryptoKey` of random bytes |
| | `sign`, `verify` (HMAC) | keeper `hmac` |
| | `encrypt`, `decrypt` (AES-GCM, AES-CBC) | keeper |
| | `deriveBits`, `deriveKey` (HKDF, PBKDF2) | new handle |
| | `exportKey` | the handle |
| | `digest` | same rules as `createHash` |
| | `wrapKey`, `unwrapKey`, other algorithms | refused |
| Pure JS | `fast-sha256` (svix), `@noble/hashes` `hmac` / `hkdf`, `@oslojs/crypto` `hmac` | keeper, via `module.registerHooks` (Node ≥ 22.15) or a runtime plugin (Bun) |

Other pure-JS crypto packages bypass the shim. When handles are in use, the shim prints a one-time warning naming them. On Node < 22.15 (no `module.registerHooks`) the adapted packages fall back to that warning too.

## Behaviour

- **Always patches.** Frameworks such as Next.js load `.env` after preload, so the shim can't tell in advance whether handles will appear. For non-handle keys the cost is one `indexOf` per call. `npm run bench` in `compat/node` measures it, and locally it is within noise.
- **Synchronous.** `createHmac(...).digest()` must return immediately. A worker thread owns the socket; the calling thread waits on `Atomics.wait`. The worker starts on the first handle call only.
- **Fails closed.** An unsupported algorithm or hash used with a handle throws instead of computing with the handle text. Every error message names the next step, e.g. `doppelkey: keeper not running (no keeper at …). Run "doppelkey doctor".`

## Environment variables

| Variable | Default | Meaning |
| --- | --- | --- |
| `DOPPELKEY_SOCK` | `$XDG_RUNTIME_DIR/doppelkey/doppelkeyd.sock`, else `<tmpdir>/doppelkey-<uid>/doppelkeyd.sock` | keeper socket |
| `DOPPELKEY_TIMEOUT_MS` | `30000` | how long to wait for the keeper |
| `DOPPELKEY_SHIM=off` | | don't patch anything |
| `DOPPELKEY_QUIET=1` | | no pure-JS warning |

The protocol and handle format are in [`docs/protocol.md`](../../docs/protocol.md).
