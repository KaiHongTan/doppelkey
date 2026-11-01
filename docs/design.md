# Design

How doppelkey works and why it is built this way. For usage, see the [README](../README.md). For the threat model, see [SECURITY.md](../SECURITY.md).

## The problem

Apps under development hold keys they compute with:

- **Token signing keys:** `JWT_SECRET`, `AUTH_SECRET`/`NEXTAUTH_SECRET`
- **Session and cookie secrets:** express-session, Django `SECRET_KEY`, Rails `secret_key_base`
- **Webhook signing secrets:** Stripe and svix `whsec_…`, GitHub, Slack
- **Encryption keys** and **AWS secret access keys**

When a coding agent runs the dev server or the tests, those processes hold the real values. The agent runs as the same OS user, so it can read them: by opening `.env`, printing the environment, or reading `/proc/<pid>/environ`. A leaked signing key lets anyone mint sessions and forge webhooks; a leaked encryption key decrypts everything written with it.

Tools that keep API keys away from agents work at the network edge: a proxy swaps a placeholder for the real key on the way out. That can't work for these keys. They never leave the process, and the app needs the real bytes to produce a correct signature or ciphertext.

## Prior art

| Approach | Examples | In-process app keys? |
| --- | --- | --- |
| Placeholder proxies | Veil, agent-vault, Phantom, Infisical Agent Proxy, Deno Sandbox | No: outbound requests only |
| Credential brokers | Secretless Broker | No: database, SSH and HTTP connections |
| Runtime injection | `infisical run`, 1Password Environments, dotenvx | No: the real value ends up in memory |
| "Blind" vaults | Blindkey, blind-vault, Keyblind | No: the child process holds the secret |
| KMS APIs | Vault Transit, cloud KMS | Yes, but the app must call an API |
| Signing agents | ssh-agent, gpg-agent | Yes, for SSH and GPG keys only |
| OS sandboxes | Anthropic `srt` | Partly: they can block reads of `.env`, but the app still loads the value |

doppelkey is the in-process piece that sits next to the network-side proxies. Moving crypto into a separate, hardened process is not new: PKCS#11 providers, HSM-backed JCA providers and Vault Transit have done it for decades, and doppelkey's Java shim is a JCA provider. What we didn't find, as of late 2026, is a tool that does this for development apps without code changes: driven by `.env`, across several runtimes, with format-preserving handles and derived keys that never leave the keeper. See [comparison.md](comparison.md) for more.

## Architecture

```
 Same OS user as the agent                          Separate user service
 ┌──────────────────────────────────────┐           ┌──────────────────────────┐
 │ .env:  JWT_SECRET=dk1:… (handle)     │           │ doppelkeyd (Rust)        │
 │                                      │  handle   │  RustCrypto operations   │
 │ app + shim ──────────────────────────┼─ + data ─▶│  policy, audit log       │
 │  (jsonwebtoken, Stripe, Django, …) ◀─┼─ result ──┤  non-dumpable memory     │
 │                                      │   only    │        ▲ unlocks         │
 └──────────────────────────────────────┘           │  encrypted vault         │
                                                    └──────────────────────────┘
```

doppelkey has three parts:

1. **Handles.** Each secret in `.env` is replaced by a handle string. Handles are safe to read, log or commit, and meaningless off the user's machine.
2. **Shims.** A small library preloaded into the app wraps the crypto entry points. A call made with a handle goes to the keeper; every other call runs unchanged.
3. **The keeper (`doppelkeyd`).** A separate user service that holds the real keys, performs operations, enforces per-key policy and writes an audit log. It has no export operation.

### Handles

The format is specified in [protocol.md](protocol.md). In short:

- The **long form** explains itself to anyone who reads it: `dk1:NOT-A-SECRET-load-doppelkey-shim:<id>:<crc>`.
- The **compact form** is 20 bytes: `dk1:<id><crc>`. It fits keys that must keep a fixed length, and keys derived with SHA-1 (itsdangerous derives 20-byte keys).
- **Format-preserving forms** (hex, base64, `whsec_` + base64) keep working when an app decodes the value, or uses its text as-is.
- A 4-hex checksum stops random strings from matching by accident.

**Derived keys stay in the keeper.** HKDF, PBKDF2 and hash-based derivation over a handle return a new handle, never key bytes. Derived handles are deterministic: the same parent and parameters give the same handle, so key IDs stay stable. A 64-byte derived key is returned as two 32-byte handles back to back, because libraries such as jose split AES-CBC-HMAC keys in half.

### Shims

| Runtime | How it loads | What it wraps |
| --- | --- | --- |
| Node, Bun | `--require` via `.npmrc` / `NODE_OPTIONS`; `bunfig.toml` preload | `node:crypto`, WebCrypto, hashes over handles, pure-JS adapters |
| Python | `doppelkey.pth` in the venv | `hmac`, `hashlib`, `pbkdf2_hmac`, `cryptography` AESGCM |
| Ruby | `config/boot.rb` or `RUBYOPT` | `OpenSSL::HMAC`, PKCS5/KDF, `OpenSSL::Cipher` |
| Java | `-javaagent` | a JCA provider for `Mac`, `Cipher` and PBKDF2 |

Notes:

- **Synchronous calls.** `createHmac(...).digest()` must return immediately. The Node shim keeps the socket in a worker thread, blocks on `Atomics.wait` and reads the reply with `receiveMessageOnPort`. A keeper round trip costs about 250 µs, against 6 µs for a local HMAC.
- **Always installed.** Frameworks such as Next.js load `.env` after preload, so the shim can't know in advance whether handles will appear. For ordinary keys its cost is one substring check per call, which is within measurement noise (`compat/node/bench.mjs`). Calls with a handle cost a keeper round trip, about 40 times a local HMAC: fine for development, not for hot loops in production.
- **Pure-JS crypto** (`@noble/hashes`, `fast-sha256`, `@oslojs/crypto`) never calls `node:crypto`. The Node shim wraps those packages at load time, with `module.registerHooks` on Node 22.15+ or a runtime plugin on Bun, and warns about any others it finds.
- **Fail closed.** An unsupported algorithm used with a handle throws instead of computing with the handle text. Every error names the next command to run.

### The keeper

- **Transport.** A Unix socket (0600 in a 0700 directory) carries length-prefixed JSON ([protocol.md](protocol.md)). The keeper checks the caller's uid with `peer_cred`, and the audit log records the caller's pid and executable.
- **Keys at rest.** An encrypted vault (XChaCha20-Poly1305) holds the keys. Its key-encryption key comes from one of three places:
  - a passphrase through Argon2id, the default on Linux;
  - the macOS Keychain, whose access rules bind to the signed binary;
  - a 0600 file, for throwaway development keys only.

  The Linux Secret Service isn't used, because any process running as the same user can read it.
- **Keys in memory** are zeroized on drop and `mlock`ed.
- **Hardening.** Memory protection depends on the platform:
  - **Linux:** `PR_SET_DUMPABLE=0`, which on its own blocks same-user reads of the keeper's memory and environment, even when Yama is off.
  - **macOS:** `PT_DENY_ATTACH`, plus code signing with a hardened runtime (not yet verified on a real Mac).
  - **Both:** no core dumps, and the keeper refuses to start with `LD_PRELOAD` or `DYLD_*` set.
- **Policy** is stored inside the vault, so editing a file can't loosen it. Each key has allowed operations, optional AWS service limits, a rate limit, and optional confirm prompts.
- **The CLI never decrypts the vault.** Creating the vault, importing keys, storing file backups, changing policies and eject are keeper operations. The CLI is a program any agent can run, with any arguments, environment or terminal, so it can't be trusted to hold the vault or to decide that a human approved.
- **Human gates.** `eject` (real values back on disk) and loosening a policy need a human, and the keeper decides. With a passphrase vault, approval is the passphrase, checked by the keeper; it works without a display, and nothing an agent can plant in a terminal or the keeper's environment stands in for it. With the macOS Keychain, approval is a dialog the keeper runs from `/usr/bin/osascript`. After approval the keeper writes the values back into the files they came from itself, so key material never crosses the socket.
- **Service.** The keeper runs as a systemd or launchd user service, started outside any agent's process tree. Where neither exists, it falls back to a detached process.

### Why Rust for the keeper

V8 strings can't be wiped, and Go strings are immutable and get copied. Rust gives wipe-on-drop buffers, no garbage-collector copies, and one static binary. The shims stay in their host language with zero runtime dependencies, so they are small enough to audit.

## Developer experience

`doppelkey init` is the entry point. It:

1. finds `.env` files and classifies each secret, skipping network credentials, which a proxy should cover;
2. shows a preview, then moves the values into the vault;
3. writes format-preserving handles;
4. adds the auto-load lines and an `AGENTS.md` note, and installs the keeper service.

After that, the normal commands (`npm run dev`, `pytest`, `rails s`) load the shim by themselves. `eject` restores every file byte for byte.

| Runner | How the shim loads |
| --- | --- |
| npm, pnpm | `node-options` in `.npmrc` (also `nodeOptions` in `pnpm-workspace.yaml` for pnpm 11+) |
| Yarn 2+ | `NODE_OPTIONS` in `.env.yarn` (Yarn ignores `.npmrc`) |
| Yarn 1 | no hook: use `doppelkey run -- yarn …` |
| Bun | `preload` and `[test] preload` in `bunfig.toml` |
| Python | `doppelkey.pth` in the project's venv |
| Rails | a guarded `require` at the top of `config/boot.rb` |
| Claude Code | `env.NODE_OPTIONS` in `.claude/settings.json`, or the plugin's SessionStart hook |
| Anything else | `eval "$(doppelkey env)"` or `doppelkey run -- <cmd>` |

Security doesn't depend on the shim loading. A process without the shim never sees a real key; its crypto just fails, with a handle in place of the key. Auto-loading only affects convenience.

## Testing: the oracle pattern

Every compatibility test runs the app with handles and the shim. A separate process holding the real key then verifies each output: signatures, tokens, ciphertexts, AWS requests. The tests also scan the app's heap or live memory for the real and derived keys.

The suites in `compat/` cover Node, Bun, Python, Ruby and Java. They run against both the Node test keeper and `doppelkeyd`, and their results generate [compatibility.md](compatibility.md).

## Limits

- doppelkey stops key **theft**, not **misuse** while the keeper runs: like ssh-agent, a process that can reach the keeper can ask it to sign.
- Languages without a shim (PHP, Go, .NET) aren't covered. PHP can't override built-in functions without an extension, and Go has no preload hook.
- Private-key signing (RS256 and ES256 JWTs, `.p8` keys) needs `crypto.sign` support, which isn't built yet.
- `RAILS_MASTER_KEY` is a 16-byte AES key: too short to hold a handle.

## Open questions

- Do hardened-runtime rules fully stop same-user memory reads on macOS? This needs a test on a real Mac with a signed build.
- Should Vault, OpenBao, 1Password or Infisical be offered as storage backends? Vault and OpenBao Transit could keep the key out of the keeper entirely.
- AWS: a live check with temporary credentials (session tokens) and SigV4a.
- How to protect the keeper's own service definition and binary from same-user tampering beyond read-only install (see [SECURITY.md](../SECURITY.md)).
