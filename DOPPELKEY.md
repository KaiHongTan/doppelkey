# doppelkey: design and build brief

> **For coding agents: start here.** This file is the complete brief for building doppelkey. It holds the research, locked decisions, specs, milestones with acceptance criteria, and the working prototype code (Appendix A). Read sections 1 to 6 before writing code. Then start with Milestone 1.
>
> Last updated: 1 November 2026.

## 0. Ground rules for anyone working on this repo

1. **Never handle real secrets.** Tests use fake secrets only. Never print, log, commit or paste a real key, even while debugging.
2. **Shims stay dependency-free.** `shims/node` and `shims/python` must have zero runtime dependencies. They load into every process, so they must be small and auditable.
3. **The keeper has no export operation.** No code path may return key bytes to a client, ever. Add a test that proves it.
4. **Fail closed, and say what to do.** Every error message names the next command to run, e.g. `Keeper not running. Run "doppelkey doctor".`
5. **Correctness is checked against the real key.** Every compatibility test uses the oracle pattern (section 13): outputs made through the shim must verify in a separate process that holds the real key.
6. **Don't "fix" handles.** Values like `dk1:...` or `KH1:...` in env files are handles, not broken secrets. Never replace them with generated values.

## 1. Summary

doppelkey is an ssh-agent for app secrets. Apps under development need signing and encryption keys in memory (JWT secrets, cookie secrets, webhook signing secrets, encryption keys), and AI coding agents running as the same user can read them. doppelkey replaces each secret in `.env` with a look-alike **handle**. A preloaded **shim** recognises handles inside crypto calls and forwards the operation to a separate **keeper** process (`doppelkeyd`), which holds the real key and returns only the result. App code doesn't change.

- **Novelty:** every agent-secrets tool found (Nov 2026) protects secrets that travel over a network (placeholder proxies). None protects keys an app computes with in-process. Vault Transit does this but needs code changes and a server; ssh-agent does it only for SSH keys.
- **Proven:** a ~400-line prototype (Appendix A) ran 10 popular libraries unchanged, including the AWS SDKs; a heap snapshot of the app held 0 of 4 real secrets.
- **Limit:** this stops key **theft**, not **misuse** while the keeper runs. Anything that can reach the keeper can ask it to sign (same as ssh-agent).

## 2. The problem

Placeholder proxies work because an API key only matters when it reaches the remote server, so it can be swapped in at the network edge. An HMAC or encryption key never leaves the process: the app needs the real bytes to produce a correct signature or ciphertext.

Secrets in this gap:

- **Token signing keys:** `JWT_SECRET`, Supabase JWT secret, `AUTH_SECRET` / `NEXTAUTH_SECRET` (Auth.js derives its encryption key from it).
- **Cookie and session secrets:** express-session / cookie-signature, Django `SECRET_KEY`, Rails `secret_key_base`.
- **Webhook signing secrets:** Stripe `whsec_...`, GitHub and Slack signing secrets.
- **Data encryption keys:** field-level or file keys, often AES-256-GCM.

When an agent runs the dev server or tests, those processes hold the real values. The agent can print them from a test, read `.env`, or read `/proc/<pid>/environ`. A leaked signing key lets anyone mint sessions and forge webhooks; a leaked encryption key decrypts everything written with it.

## 3. Prior art (checked November 2026)

| Tool or pattern | Protects | How | In-process app keys? |
| --- | --- | --- | --- |
| Placeholder proxies: Veil, agent-vault, Keys on the Wire, Phantom, Infisical Agent Proxy, Deno Sandbox | API keys in outbound requests | Swap placeholder for real key at the network edge | No (outbound only) |
| Secretless Broker, coffer | DB, SSH, HTTP connections | Local proxy authenticates on the app's behalf | No |
| Runtime injection: `infisical run`, 1Password Environments, dotenvx | Secrets in files on disk | Inject into the process environment at start | No: real value is in memory |
| "Blind" vaults: Blindkey, blind-vault, Keyblind, Ownkube keyseal | Values in the agent transcript | Inject into a child command's environment | No: child process holds the secret |
| Vault Transit, cloud KMS | Encryption, HMAC, signing keys | App calls an API | Yes, but requires code changes and a server |
| ssh-agent, gpg-agent | SSH/GPG private keys | Signing oracle behind a socket | Yes, SSH/GPG only |
| Cloudflare Code Mode | API access from agent-written code | Isolate gets bindings, never keys | No: sandboxes agent scripts, not your app |
| OS sandboxes (Anthropic `srt`) | Files and network | Deny reads, allowlist hosts | Partly: blocks reading `.env`, app still loads the value |

Positioning: doppelkey is the **in-process** piece that sits next to the network-side proxies, not a rival to them.

## 4. Design

Three parts:

1. **Handles.** Each secret in `.env` becomes a handle string. Safe to read, log or commit; meaningless off this machine.
2. **Shim** (preloaded into the app). Wraps crypto entry points. A call made with a handle goes to the keeper; every other call runs normally. With no handles in the environment, it does nothing.
3. **Keeper** (`doppelkeyd`, separate user service). Holds real keys in the OS keychain, performs operations, enforces per-key policy, writes an audit log, and has no export operation.

```
 Agent-reachable (same OS user)                        Protected user service
 ┌──────────────────────────────────────────┐          ┌──────────────────────────┐
 │ .env:  JWT_SECRET=dk1:... (handle)        │          │ doppelkeyd (Rust, tokio)  │
 │                                           │  socket  │  RustCrypto ops           │
 │ App process + shim ──── handle + data ───────────────▶  policy.toml, audit.jsonl │
 │   (jsonwebtoken, jose, Stripe... as is) ◀── result only ── non-dumpable, wiped   │
 └──────────────────────────────────────────┘          │         ▲ unlocks         │
                                                        │   OS keychain (keyring)   │
                                                        └──────────────────────────┘
```

**Node shim details (proven in the prototype):**

- `node:crypto`: wrap `createHmac`, `createSecretKey`, `hkdf`, `hkdfSync`; call `module.syncBuiltinESMExports()` so ESM `import { createHmac }` sees the wrappers.
- WebCrypto: `importKey('raw', <handle bytes>)` returns a real `CryptoKey` made from random decoy bytes, recorded in a `WeakMap`. `sign`, `verify`, `deriveBits`, `encrypt`, `decrypt` look the decoy up and forward. `instanceof CryptoKey` checks pass.
- **Synchronous calls:** `createHmac(...).digest()` must return immediately. The shim keeps a socket in a worker thread and blocks the main thread on `Atomics.wait`, then reads the reply with `receiveMessageOnPort` (the `synckit` pattern). Measured: ~247 µs per HMAC vs 6 µs locally.

**Python shim details (proven):** replace `hmac.new`; wrap `hashlib.sha1/sha256/sha512` so a hash over (salt + handle) is computed by the keeper and returns a new handle. This is how Django and itsdangerous derive keys.

**Derived keys stay inside the keeper.** HKDF or hash derivation from a handle returns a new handle, never key bytes. Two details make real libraries work:

- Derived handles are **deterministic** (same parent + parameters give the same handle), so key IDs stay stable.
- A **64-byte derived key is two 32-byte handles back to back**, because jose splits AES-CBC-HMAC keys in half.

## 5. Locked decisions

### 5.1 Stack

| Component | Stack | Main pieces | Why |
| --- | --- | --- | --- |
| Keeper daemon `doppelkeyd` | Rust, tokio | Unix socket server (Windows named pipes later) | No GC copies of keys; wipe-on-drop; one static binary |
| Crypto in the keeper | RustCrypto crates | `hmac`, `sha1`, `sha2`, `hkdf`, `aes-gcm`, `aes` + `cbc` | Pure Rust, cross-compiles; SHA-1 needed for itsdangerous |
| Key storage | `keyring` v3 | macOS Keychain, Windows Credential Manager, Linux Secret Service / keyutils | Standard per-user store; binary secrets since v3 |
| Memory hygiene | `zeroize` / `secrecy`, plus `memsafe` or `memsec` | Wipe on drop, `mlock`, core-dump exclusion | Keys stay out of swap and crash dumps |
| Process hardening | `libc` or `nix` | Linux `prctl(PR_SET_DUMPABLE, 0)`, `RLIMIT_CORE=0`; macOS hardened-runtime signing | Blocks same-user debuggers |
| Caller identity | tokio `UnixStream::peer_cred()` | uid + pid per connection | Refuse other users; log which program asked |
| CLI | same Rust binary, `clap` | `doppelkey init/protect/set/eject/doctor/run/log/policy/mcp` | One thing to install |
| Node shim | TypeScript bundled to one JS file, zero deps | `doppelkey/register` via `--require` / `--import` | No native addon matrix |
| Python shim | pure Python, autoloaded via `.pth` | patches `hmac`, `hashlib` | Nothing to compile |
| Wire protocol | length-prefixed JSON, versioned | see section 7 | Trivial in both shims |
| Policy + audit | TOML policy, JSON Lines audit | per-key ops, rate limits, confirm prompts | Human-readable |
| Releases | cargo-dist, npm, PyPI | GitHub Releases, Homebrew tap, shell/PowerShell installers | One tag publishes all |

Rust over Node/Go for the keeper: V8 strings can't be wiped (agent-vault lists this as its own limitation); Go strings are immutable and get copied.

### 5.2 Architecture decisions

1. **The keeper is a user service** (launchd / systemd), started outside the agent's process tree. That is what makes the Linux Yama ptrace protection hold. Socket in `$XDG_RUNTIME_DIR` (Linux), mode 0700.
2. **Normal commands are the entry point.** `doppelkey init` (once) writes the auto-load lines; afterwards `npm run dev` and `pytest` load the shim unchanged. `doppelkey run -- <cmd>` is only an escape hatch.
3. **Handles are versioned, format-preserving and checksummed** (section 8).
4. **Sign the macOS binary with a Developer ID.** Keychain ACLs bind to the creating program's code signature; unsigned builds get a new identity per compile and "Always Allow" stops sticking after upgrades.
5. **macOS and Linux first.** Windows after v0.1.

## 6. Repository layout

```
crates/
  doppelkeyd/        # daemon + CLI (single binary: doppelkey, doppelkeyd)
  proto/             # wire types; generates JSON Schema and test vectors for the shims
shims/
  node/              # TypeScript source -> single dist/register.cjs (+ register.mjs for --import)
  python/            # pure-Python package; installs doppelkey.pth
integrations/
  claude-code/       # plugin: skill, SessionStart hook, .mcp.json
  skills/            # SKILL.md (agentskills.io format) for Codex, Cursor, Gemini CLI, Copilot
compat/              # oracle-style tests per library (Node 20-24, Python 3.10-3.13)
prototype/           # Appendix A code, kept for reference
docs/                # README source, llms.txt, comparison page
```

## 7. Wire protocol v1 (proposal; implement in `crates/proto`)

- Transport: Unix domain socket. Frame = 4-byte big-endian length + UTF-8 JSON.
- Request: `{"v":1,"id":<u64>,"op":"<op>","handle":"<handle>", ...params}`. Binary fields are base64.
- Response: `{"v":1,"id":<u64>,"ok":true,"result":{...}}` or `{"v":1,"id":<u64>,"ok":false,"error":{"code":"<code>","message":"...","hint":"<command to run>"}}`.

| op | params | result |
| --- | --- | --- |
| `hmac` | `alg` (sha1/sha256/sha384/sha512), `data` | `digest` |
| `hash_derive` | `hash`, `prefix`, `suffix`, `length` | `handle` (new) |
| `hkdf` | `hash`, `salt`, `info`, `length` | `handle` (new; split-half rule for 64 bytes) |
| `aes_gcm` | `mode` (encrypt/decrypt), `iv`, `data`, `aad?`, `tag_length?` | `out` (ciphertext includes tag) |
| `aes_cbc` | `mode`, `iv`, `data` | `out` |
| `status` | none | keeper version, key count (names only) |

Error codes: `unknown_handle`, `op_not_allowed`, `rate_limited`, `confirm_denied`, `bad_request`, `version_mismatch`. There is no op that returns key material.

The prototype uses newline-delimited JSON and `KH1:` handles; v1 changes both.

## 8. Handle format (proposal)

- Default: `dk1:NOT-A-SECRET-load-doppelkey-shim:<id16>:<crc4>`, padded to the original secret's length when a library checks length. The visible text tells any human or agent what it is.
- Format-preserving variants when a library validates format: hex-only, base64, or keep a vendor prefix (`whsec_` + handle body).
- `<id16>` = 16 hex characters; `<crc4>` = checksum so random strings never match by accident.
- Derived handles carry the same prefix and are deterministic per (parent, operation, parameters).
- Matching rule in shims: exact handle or exact concatenation of handles (split-half rule).

## 9. CLI surface

| Command | Does |
| --- | --- |
| `doppelkey init` | Detect stack, find `.env` files, classify secrets, preview, move values to keychain, write handles + auto-load lines + `AGENTS.md`/`CLAUDE.md` note, install keeper service |
| `doppelkey protect NAME` | Convert one secret |
| `doppelkey set NAME` | Prompt the human for a value (teammate onboarding) |
| `doppelkey eject` | Restore real values to `.env`, remove everything `init` added |
| `doppelkey doctor` | Check keeper socket, each auto-load path, handle validity; print the fix |
| `doppelkey run -- <cmd>` | Escape hatch: run one command with the shim |
| `doppelkey log` | Show the audit log |
| `doppelkey policy` | Edit per-key operations, rate limits, confirm prompts |
| `doppelkey mcp` | MCP server: `status`, `doctor`, `list_secrets` (names only) |

## 10. Developer experience

Security doesn't depend on the shim loading: with handles in `.env`, a process without the shim never sees a real key; its crypto just fails. Auto-loading is a convenience problem.

| Runner | How the shim loads | Notes |
| --- | --- | --- |
| npm scripts | project `.npmrc`: `node-options=--require doppelkey/register` | npm passes it as `NODE_OPTIONS`. pnpm and Yarn need checking |
| Bun | `bunfig.toml`: `preload = ["doppelkey/register"]` | Bun's docs say a project bunfig isn't always loaded by `bun run`; test it |
| Python | `pip install doppelkey` drops a `.pth` in the venv | Every Python process in the venv loads it |
| Claude Code | `.claude/settings.json` `env.NODE_OPTIONS`, or the plugin's `SessionStart` hook writing to `CLAUDE_ENV_FILE` | Covers the agent running `node app.js` directly |
| Anything else | `import "doppelkey/register"` in the entry file, or Next.js `instrumentation.ts` | `doppelkey run` as last resort |

The shim is a no-op without handles, so it is safe in CI and production. Guard against silent failure: self-explaining handles (section 8) and `doppelkey doctor`.

## 11. Adoption and agent distribution

**Developers:** `npx doppelkey init` (one command, preview first); `protect` for gradual rollout; `eject` to undo; safe to leave in place; team flow via `doppelkey.toml` (names only) and `doppelkey set`; optional storage backends (1Password, Infisical, dotenvx via `init --from`); recommend Veil or Infisical Agent Proxy for outbound API keys.

**Agents:**

- **Claude Code plugin** (`integrations/claude-code`): a skill that proposes `npx doppelkey init` when it sees `.env` secrets or is asked to set up auth, JWTs or webhooks; a `SessionStart` hook that appends `NODE_OPTIONS` to `CLAUDE_ENV_FILE`; optional MCP server. Submit to Anthropic's `claude-plugins-official` directory via its submission form.
- **Codex and others:** the same SKILL.md (agentskills.io open standard, supported by Codex, Gemini CLI, Cursor, Copilot); Codex packages skills as plugins; MCP server via `~/.codex/config.toml`.
- **`AGENTS.md` / `CLAUDE.md` note written by `init`:** "Values starting with `dk1:` are doppelkey handles. Never replace them or ask for real values. To add a secret, ask the user to run `doppelkey set NAME`."
- **Errors written for agents:** every failure names the next command.
- **Getting recommended:** `llms.txt`; README opening with the problem and the one-line install; a comparison page vs placeholder proxies; awesome-lists; threads about agents leaking `.env`.

## 12. Threat model

| Attack by a curious or prompt-injected agent | Without | With doppelkey |
| --- | --- | --- |
| Read `.env` / print `process.env.JWT_SECRET` | Real key | Handle, useless off this machine |
| Read `/proc/<pid>/environ` or dump app memory | Real key | No key (prototype heap check: 0 of 4) |
| Paste key into chat, commit, log | Leaks for good | Handle leaks; nothing to rotate |
| Ask keeper to sign/decrypt while it runs | n/a | **Works**: can forge local tokens; logged |
| Ask keeper to export a key | n/a | No such operation |
| Read keeper memory with a debugger | n/a | Blocked if keeper is outside the agent's tree and non-dumpable (Linux Yama mode 1); macOS needs testing |
| Replace the keeper binary, wait for restart | n/a | Possible if user-writable; install read-only and signed |

Misuse mitigations: per-key operations (enforced in prototype), `ssh-add -c` style confirm prompts, rate limits + audit log, separate development keys. Out of scope: a human reading the keychain; an agent with root.

## 13. Framework coverage and testing

| Library | Crypto path | Prototype result |
| --- | --- | --- |
| `jsonwebtoken` HS256 | `crypto.createHmac` | Works; valid under real key |
| `jose` HS256 | WebCrypto `importKey` + `sign` | Works; valid under real key |
| `cookie-signature` (express-session) | `crypto.createHmac` | Works |
| `stripe` webhooks, sync + async | `createHmac`, `SubtleCrypto` | Works with real Stripe-format headers |
| `@auth/core` (Auth.js) | `crypto.hkdf`, jose A256CBC-HS512 | Works between shimmed processes; real-key server rejects token because the `kid` is a thumbprint of key bytes |
| PyJWT HS256 | `hmac.new` | Works |
| itsdangerous (Flask) | SHA-1(salt + secret) then HMAC | Works via hash-derived handles |
| Django `signing` | SHA-256(salt + secret) then HMAC | Works |
| AWS SDK for JavaScript v3 (S3, DynamoDB) | SigV4: chained `createHmac` from `"AWS4" + secret` | Works; signed and presigned requests valid under real key; DynamoDB refused by policy |
| boto3 (S3, DynamoDB) | SigV4 via `hmac.new`; S3 presigned URLs use SigV2 by default | Works; SigV2 needs a policy opt-in |

**Known gaps:** pure-JS crypto (`@noble/hashes`, `crypto-js`) bypasses the shim and silently signs with the handle (detect and warn at startup); key fingerprints hash key bytes in-app (fix: route hashes over handles to the keeper); `createCipheriv`, `crypto.sign` with private keys, and streaming HMAC not yet patched; format checks (Rails hex, Laravel `base64:`); Ruby, Go, PHP, Java need their own shims; Bun and Deno untested.

**Test strategy (the oracle pattern):** run the app with handles + shim; a separate process holding the real keys (no shim) verifies every output; then scan the app's V8 heap snapshot and `/proc/self/environ` for real and derived keys. CI matrix: Node 20, 22, 24; Python 3.10 to 3.13; Linux and macOS.

## 13b. Key coverage and market fit

The key types doppelkey handles are in almost every web app with its own login, sessions or webhooks. What's narrower today is who feels the risk: developers who let agents run apps with real (not throwaway) keys.

| Key type | Examples | Coverage |
| --- | --- | --- |
| HMAC signing secrets | JWT HS256, session cookies, CSRF, Django/Flask `SECRET_KEY`, webhook secrets (Stripe, GitHub, Slack, Shopify, Svix/Clerk) | High: proven in the prototype |
| Keys derived from a secret | Auth.js `AUTH_SECRET`, Django and itsdangerous salted keys | High once the Auth.js key-ID fix lands (Milestone 3) |
| Symmetric encryption | Field encryption keys, iron-session, encrypted cookies | Medium: WebCrypto works; `createCipheriv` planned for Milestone 1 |
| Private signing keys | RS256/ES256 JWTs, GitHub App keys, Google service-account keys, Apple `.p8` | Not yet: needs `crypto.sign`; a large category |
| AWS secret access keys | AWS SDK request signing (SigV4) | Works in the prototype: AWS SDK v3 and boto3, signed and presigned requests |
| Network credentials | OpenAI and Anthropic keys, Stripe `sk_`, database passwords | Out of scope: placeholder proxies such as Veil cover these |

Rough estimate: a typical SaaS `.env` holds 10 to 25 secrets, of which 3 to 6 are in-process keys doppelkey covers. Position it as the other half of a proxy, not a full `.env` replacement.

**AWS SigV4 works in the prototype (tested 1 Nov 2026).** The AWS SDK for JavaScript v3 and boto3 ran unchanged with a handle as `AWS_SECRET_ACCESS_KEY`. SigV4 derives four signing keys in a chain (date, region, service, `aws4_request`); the keeper returns each as a handle, so only final signatures leave it. This makes doppelkey relevant to nearly every backend, not just apps with their own auth.

- **Correct:** S3 uploads and presigned download URLs from both SDKs verified against the real key, checked the way AWS checks them (`aws_oracle.mjs`).
- **Not in memory:** a scan of each live app's whole memory (250 MB Node, 78 MB Python; `memscan.py`) found neither the secret nor any derived signing key. The same scan of a control run without doppelkey did find the secret.
- **Policy:** the key was limited to S3, and a DynamoDB call from the same app was refused. The audit log records each signature's scope, e.g. `20261031/ap-southeast-1/s3`. The raw secret can only HMAC its own access key ID (the SDK's cache key).
- **Catch:** boto3 signs S3 presigned URLs with legacy SigV2 by default, which uses the raw secret. The keeper refuses it unless the policy allows it (`"sigv2": true`), and the error says to set `signature_version="s3v4"`.
- **Not yet tested:** a live request to AWS (no AWS access from the test machine), temporary credentials with session tokens, and SigV4a.

**Projects by fit:**

- **Best fit:** Node (Next.js, Express, Nest) and Python (Django, Flask, FastAPI) apps that do their own auth, receive webhooks or encrypt data.
- **Partial fit:** apps on hosted auth (Clerk, Auth0, Supabase); they still hold webhook secrets and often a JWT secret.
- **Not covered yet:** Rails, Laravel, Go, Java, .NET; each needs its own shim, and Go has no preload hook.

**Who needs it first:** solo developers and small teams who reuse keys across environments or point local at staging or production; people running agents unattended (background agents, auto-approve modes); companies writing agent-security policies. Teams with separate throwaway dev keys gain less today, so urgency grows with agent autonomy.

## 14. Milestones and acceptance criteria

### Milestone 1: Node shim package (`shims/node`)
- [x] Port `prototype/shim.cjs` to TypeScript; build `dist/register.cjs` and `dist/register.mjs`; zero dependencies.
- [x] Implement wire protocol v1 client and `dk1:` handle parsing (sections 7 and 8). *Refined in `docs/protocol.md`: 12-hex ids, a 20-byte compact form, encoded (hex/base64) handles, `pbkdf2` op.*
- [x] Add `createCipheriv`/`createDecipheriv` (GCM, CBC), streaming HMAC (`.write`/`.pipe`), and a startup warning listing pure-JS crypto packages found in `node_modules`. *Plus: pure-JS adapters for fast-sha256 (svix), @noble/hashes and @oslojs/crypto via `module.registerHooks`; PBKDF2; fail-closed refusals for unsupported algorithms.*
- [x] Port the prototype keeper as a test keeper (Node) speaking v1, so shim work isn't blocked on Rust. *`compat/test-keeper`.*
- **Done when:** `compat/node` passes for jsonwebtoken, jose, cookie-signature, stripe (sync and async), AWS SDK v3 (S3) on Node 20, 22, 24, with the heap scan finding 0 real keys; shim is a no-op when no handles are present (benchmark shows no measurable overhead).
  - *Status (31 Oct 2026): met locally on Node 22, 24 and 26 (47/47 tests), and on Bun 1.4 (43 pass, 4 skipped: no V8 heap snapshot, no `registerHooks`). Node 20 is end-of-life since April 2026 and lacks `module.registerHooks`; on it everything passes except the pure-JS adapters, which fall back to the startup warning. CI (`.github/workflows/ci.yml`) runs Node 22/24/26 on Linux and macOS plus Bun; it hasn't run on GitHub yet.*

### Milestone 2: Rust keeper (`crates/doppelkeyd`)
- [x] tokio Unix socket server implementing every v1 op with RustCrypto; `peer_cred()` uid check; JSON Lines audit log. *Audit entries include the caller's pid and executable.*
- [x] Keys from `keyring` v3; held in `zeroize`/`memsafe` buffers; `prctl(PR_SET_DUMPABLE,0)` and no core dumps on Linux. *Changed after research: keys live in an encrypted vault file (XChaCha20-Poly1305) whose key comes from a passphrase (Argon2id), the macOS Keychain (`macos-keychain` feature, via `keyring`), or a 0600 file. Linux Secret Service was rejected because any same-user process can read it. In memory: zeroized, `mlock`ed buffers; `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, `PT_DENY_ATTACH` on macOS; refuses to start with `LD_PRELOAD`/`DYLD_*` set.*
- [x] Policy TOML: per-key allowed ops, rate limits, confirm prompts. *Policy is stored inside the encrypted vault so an agent can't loosen it by editing a file; `doppelkey policy` shows and edits it as TOML, and loosening needs a human (terminal or askpass).*
- [x] launchd and systemd user-service install/uninstall. *`doppelkey service install|uninstall`, with a hardened systemd unit; falls back to a detached keeper where neither exists.*
- [x] Test vectors from `crates/proto` shared with both shims. *`crates/proto/vectors/handles.json`, checked by Rust, Node and Python.*
- **Done when:** the Milestone 1 compat suite passes against `doppelkeyd` instead of the test keeper; a test proves no op returns key bytes; a non-descendant process cannot read keeper memory on Linux.
  - *Status (31 Oct 2026): met. The compat suite passes against doppelkeyd; a fuzz test of every op finds no key bytes in any response; run as a non-root user, reading `/proc/<pid>/mem` and `environ` of doppelkeyd fails with EACCES, while the same read succeeds against the unhardened Node test keeper.*

### Milestone 3: onboarding CLI and Python
- [x] `init` (stack detection, `.env` discovery, preview, keychain migration, auto-load writers for `.npmrc`, `bunfig.toml`, venv `.pth`, `.claude/settings.json`, `AGENTS.md`/`CLAUDE.md` note), `protect`, `set`, `eject`, `doctor`, `run`, `log`. *Also `pnpm-workspace.yaml`, `.env.yarn` (Yarn 2+), `policy`, `status`, `list`, `unlock`/`lock`, `service`. `init` classifies secrets (network credentials are skipped) and picks format-preserving handle forms.*
- [x] Python package `doppelkey` installing `doppelkey.pth`; port `prototype/pyshim/sitecustomize.py`. *`shims/python`; also wraps `cryptography`'s AESGCM.*
- [x] Route hashes whose input contains a handle to the keeper (fixes Auth.js `kid`). *New `jwk_thumbprint` op; other hashes over a handle return a handle (`hash_derive`).*
- **Done when:** on a fresh Next.js + Auth.js app and a fresh Django app, `npx doppelkey init` then the normal dev command works; Auth.js tokens made locally verify on an unshimmed server holding the real secret; `eject` restores the original files byte for byte.
  - *Status (31 Oct 2026): met with the `doppelkey` binary (the `npx` launcher arrives with Milestone 4 packaging). Next.js 16 + @auth/core 0.41: `doppelkey init` then `npm run dev`; the token decrypts on a real-key server. Django 6.1: `doppelkey init` then `manage.py runserver`; signatures verify under the real `SECRET_KEY`. `eject` restores `.env` byte for byte (automated in `compat/node/test/cli.test.mjs`).*

### Milestone 4: agent integrations and launch
- [ ] Claude Code plugin (skill, `SessionStart` hook, `.mcp.json`); generic SKILL.md for Codex and others; `doppelkey mcp`.
- [ ] README, `llms.txt`, comparison page, 60-second demo, CI-generated compatibility table.
- [ ] Releases via cargo-dist (Homebrew tap, installers) plus npm and PyPI; macOS binary signed and notarized.
- **Done when:** in a fresh Claude Code session on a sample repo with a plain `.env`, the plugin proposes `init`, and after it the agent can run the app and tests but cannot print any real secret.

## 15. Open questions

Researched 31 Oct 2026; full findings, sources and proposed plan changes in [`docs/research.md`](docs/research.md).

- [ ] Do macOS hardened-runtime rules stop a same-user agent from reading the keeper's memory? Test on a real Mac. *Docs say yes if Developer ID + hardened runtime, no `get-task-allow`, SIP on; unsigned builds are readable on typical dev Macs. Use the data-protection keychain. Still needs a real-Mac test.*
- [x] Does Bun's `node:crypto` compatibility honour the patched functions? Does a project `bunfig.toml` preload load under `bun run`? *Yes and yes (Bun 1.4.4, verified against the real key). Not for `bun test` (needs `[test] preload`), not for scripts that call `node`; Bun ignores `NODE_OPTIONS`.*
- [x] Do pnpm and Yarn honour `node-options` in `.npmrc`? *pnpm 10 and 11: yes (also `nodeOptions` in `pnpm-workspace.yaml`). Yarn 1: no. Yarn 4: no, but `.env.yarn` with `NODE_OPTIONS` works. npm/pnpm replace an inherited `NODE_OPTIONS`.*
- [ ] Would Vault, 1Password or Infisical accept integrations as keeper storage backends? *Technically all workable (Vault/OpenBao Transit can even keep the key out of the keeper); partner programs exist for Vault and 1Password. Contacting vendors remains.*
- [ ] Confirm the AWS result against live S3 with a scratch IAM key (signatures already verify offline against the real key; see 13b). *Re-confirmed offline on current SDKs; live test still needs credentials.*
- [ ] Name check: search github.com for "doppelkey" (registries and web were clear on 1 Nov 2026), then reserve npm, PyPI, crates.io, the GitHub org and a domain. *npm/PyPI/crates.io free for both spellings; one inactive 2021 GitHub repo. Note this repo is spelled `dopplekey`; "Doppler" is a confusion risk. Reservation remains.*

New issues found (details in `docs/research.md`): the shim must patch even with no handles in `process.env` (Next.js loads `.env` late); iron-session, svix, Better Auth, @oslojs/crypto and next-auth v4 currently give silently wrong results (fix: `pbkdf2` op, `createCipheriv`, pure-JS adapters via `module.registerHooks`, which needs Node ≥ 22.15, so the CI matrix becomes Node 22/24/26); derived handles must fit in 20 bytes (itsdangerous), so section 8 needs a compact form; on Linux `PR_SET_DUMPABLE=0` alone protects keeper memory, but Secret Service storage and the user-owned service unit are open same-user attack paths.

## 16. Sources

- Placeholder proxies: [Phantom](https://github.com/ashlrai/phantom-secrets/wiki), [agent-vault](https://github.com/CrimsonWorks-Inc/agent-vault), [Keys on the Wire](https://pypi.org/project/keys-on-the-wire/), [Veil](https://gh.r-mj.com/getveil/veil), [Infisical](https://infisical.com/ai/platform/secrets-management), [Deno Sandbox](https://docs.deno.com/sandbox/security/)
- Blind vaults: [Blindkey](https://glama.ai/mcp/servers/AlexanderBorysenko/blindkey/tree), [blind-vault](https://github.com/AnYejun/blind-vault), [Keyblind](https://github.com/aarifmms/keyblind), [Ownkube keyseal](https://github.com/ownkube/keyseal)
- Others: [Secretless Broker](https://www.github.com/cyberark/secretless-broker), [coffer](https://skills.cat/skills/huang-hf/coffer), [dotenvx](https://www.dotenvx.com), [Vault Transit](https://oneuptime.com/blog/post/2026-01-26-vault-transit-secrets/view), [Cloudflare Code Mode](https://joshuaberkowitz.us/blog/news-1/cloudflare-s-code-mode-improves-ai-agent-tool-integration-1264), [Anthropic sandbox-runtime](https://x-cmd.com/install/sandbox-runtime/), [Klavex](https://dev.to/klavex/how-to-stop-your-coding-agent-from-reading-your-env-secrets-5g6o)
- Security model: [ssh_config ForwardAgent](https://gist.github.com/mritzmann/e3bb997a445fd232c36470a23d746c6e), [ssh-add -c](https://www.endpointdev.com/blog/2022/11/ssh-askpass-on-mac-os-for-agent-confirmation/), [Linux Yama](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- Stack: [keyring](https://docs.rs/crate/keyring/latest), [memsafe](https://docs.rs/crate/memsafe/1.0.2), [tokio peer_cred](https://mozilla-services.github.io/merino/rustdoc/src/tokio/net/unix/ucred.rs.html), [cargo-dist](https://github.com/axodotdev/cargo-dist/releases/tag/v0.32.0), [macOS keychain ACLs](https://github.huabts.workers.dev/DataDog/pup/issues/542)
- DX and agents: [Bun bunfig](https://bun.com/docs/runtime/bunfig), [Node --import](https://dev.to/cloudx/nodejs-v20-env-files-import-modules-and-permission-model-2fd9), [Claude Code settings](https://docs.claude.com/en/docs/claude-code/settings), [Claude Code hooks](https://docs.claude.com/en/docs/claude-code/hooks), [claude-plugins-official](https://github.com/anthropics/claude-plugins-official/wiki), [Codex skills](https://developers.openai.com/codex/skills.md), [SKILL.md standard](https://codex.danielvaughan.com/2026/03/26/writing-effective-skillmd-files/)

---

# Appendix A: Prototype code

The proof-of-concept behind the results in the main tab: a keeper, a Node shim, a Python shim and the tests, about 400 lines of core code. It predates the doppelkey name, so handles use a `KH1:` prefix and the process is called keeper; the production design uses `dk1:` handles and `doppelkeyd`. All secrets here are fake.

### How to run

```bash
npm install jsonwebtoken jose cookie-signature stripe @auth/core @aws-sdk/client-s3 @aws-sdk/s3-request-presigner @aws-sdk/client-dynamodb
pip install pyjwt itsdangerous django boto3
./restart_keeper.sh                        # starts keeper.mjs (holds vault.json)
node oracle.mjs prep                       # makes a Stripe-format webhook header (valid 5 minutes)
E="$(cat .env.handles | xargs)"
env $E node --require ./shim.cjs app.mjs   # unmodified app using five Node libraries
node oracle.mjs check                      # verifies outputs with the real keys, scans heap
env $E node --require ./shim.cjs authjs.mjs
env $E PYTHONPATH=./pyshim python3 app.py
env $E PYTHONPATH=./pyshim python3 dj.py
env $E node --require ./shim.cjs bench.mjs
env $E node --require ./shim.cjs negative.mjs
./run_aws.sh node shim                     # AWS SDK v3: verify SigV4 with the real key, scan process memory
./run_aws.sh node control                  # same app WITHOUT the shim and WITH the real key (scanner sanity check)
./run_aws.sh python shim                   # boto3
./run_aws.sh python control
```

### keeper.mjs

The keeper: holds real keys, performs operations, writes the audit log. Production replaces this with doppelkeyd in Rust.

```js
// keeper.mjs — holds the real secrets; only ever returns results of operations.
// Runs as a separate process (in real use: a separate OS user or launchd/systemd service,
// started outside the agent's process tree). Speaks newline-delimited JSON over a Unix socket.
import net from 'node:net';
import fs from 'node:fs';
import crypto from 'node:crypto';

const SOCK = process.env.KEEPER_SOCK || '/tmp/keeper.sock';
// For the PoC, real secrets come from a JSON file the app/agent never reads.
const vault = JSON.parse(fs.readFileSync(process.env.KEEPER_VAULT || './vault.json', 'utf8'));
// vault: { "<handle string>": { "key": "<real secret>", "allow": ["hmac", ...] } }
const keys = new Map(Object.entries(vault).map(([h, v]) => [h, { ...v, key: Buffer.from(v.key) }]));
const audit = [];

const HANDLE_RE = /^KH1:[0-9a-f]{16}/;
function handleFromBytes(b64) {
  const s = Buffer.from(b64, 'base64').toString('latin1');
  const m = s.match(HANDLE_RE);
  return m ? s : null;
}
function lookup(handle, op) {
  const k = keys.get(handle);
  if (!k) throw new Error('unknown handle');
  if (!k.allow.includes(op)) throw new Error(`op ${op} not allowed for this key`);
  return k.key;
}
// Derived keys become new handles; their bytes never leave the keeper.
// Handles are deterministic (same parent + parameters => same handle) so key IDs stay stable,
// and a 64-byte key is two 32-byte handles back to back, because libraries such as jose split
// AES-CBC-HMAC keys in half.
const KEEPER_SALT = crypto.randomBytes(32);
const DERIVED_OPS = ['hmac', 'aes-gcm', 'aes-cbc'];
const idFor = (seed) => crypto.createHmac('sha256', KEEPER_SALT).update(seed).digest('hex').slice(0, 16);
const handleStr = (id, len) => `KH1:${id}`.padEnd(len, '.');
function newHandle(bytes, len, allow, seed, meta = {}) {
  if (len < 20) throw new Error('derived key too short to carry a handle');
  if (len >= 64 && len % 2 === 0) {
    const half = len / 2;
    const a = handleStr(idFor(seed + '|A'), half), b = handleStr(idFor(seed + '|B'), half);
    keys.set(a, { key: bytes.subarray(0, half), allow });
    keys.set(b, { key: bytes.subarray(half), allow });
    keys.set(a + b, { key: bytes, allow });
    return a + b;
  }
  const h = handleStr(idFor(seed), len);
  keys.set(h, { key: bytes, allow, ...meta });
  return h;
}

// AWS SigV4: kDate = HMAC("AWS4" + secret, date), then region, service, "aws4_request".
// Every intermediate key is returned as a handle; only the final signature leaves the keeper.
// Policy: the vault entry can limit which services the key may sign for.
const SIGV4_STAGES = ['date', 'region', 'service', 'aws4_request'];
function sigv4Step(parent, parentHandle, alg, msg, stage) {
  if (alg !== 'sha256') throw new Error('SigV4 uses sha256');
  const text = msg.toString('utf8');
  if (SIGV4_STAGES[stage - 1] === 'service' && parent.services && !parent.services.includes(text))
    throw new Error(`service "${text}" not allowed for this AWS key (allowed: ${parent.services.join(', ')})`);
  if (stage === 4 && text !== 'aws4_request') throw new Error('not a SigV4 derivation');
  const keyBytes = stage === 1 ? Buffer.concat([Buffer.from('AWS4'), parent.key]) : parent.key;
  const out = crypto.createHmac(alg, keyBytes).update(msg).digest();
  const scope = [...(parent.scope || []), text];
  return newHandle(out, 32, ['hmac'], ['sigv4', parentHandle, text].join('|'),
    { sigv4Stage: stage, scope, services: parent.services });
}

const ops = {
  hmac({ handle, alg, data, prefix }) {
    const k = keys.get(handle);
    if (!k) throw new Error('unknown handle');
    if (!k.allow.includes('hmac')) throw new Error('op hmac not allowed for this key');
    const msg = Buffer.from(data, 'base64');
    if (prefix !== undefined) {
      // A key of the form <prefix><handle>. Only "AWS4" on an AWS key is allowed.
      if (k.profile !== 'aws-sigv4' || Buffer.from(prefix, 'base64').toString('latin1') !== 'AWS4')
        throw new Error('prefixed key not allowed for this handle');
      return { handle: sigv4Step(k, handle, alg, msg, 1) };
    }
    if (k.sigv4Stage && k.sigv4Stage < 4) return { handle: sigv4Step(k, handle, alg, msg, k.sigv4Stage + 1) };
    if (k.profile === 'aws-sigv4' && msg.toString() !== k.accessKeyId) {
      // Legacy SigV2 (boto3's default for S3 presigned URLs) signs with the raw secret.
      const isV2 = /^(GET|PUT|HEAD|POST|DELETE)\n/.test(msg.toString());
      if (!isV2) throw new Error('raw HMAC with an AWS secret is only allowed over its access key ID (SDK cache key)');
      if (!k.sigv2) throw new Error('legacy SigV2 signing refused for this AWS key. Use signature_version="s3v4", or allow it with: doppelkey policy AWS_SECRET_ACCESS_KEY --allow sigv2');
      return { digest: crypto.createHmac(alg, k.key).update(msg).digest('base64'), _scope: 'sigv2' };
    }
    const digest = crypto.createHmac(alg, k.key).update(msg).digest('base64');
    return k.sigv4Stage === 4 ? { digest, _scope: k.scope.join('/') } : { digest };
  },
  // A plain hash over (prefix + secret + suffix) — how Django and itsdangerous derive signing keys.
  hashDerive({ handle, hash, prefix, suffix, length }) {
    const key = lookup(handle, 'hmac');
    const out = crypto.createHash(hash).update(Buffer.concat([Buffer.from(prefix, 'base64'), key, Buffer.from(suffix, 'base64')])).digest();
    return { handle: newHandle(out, length || out.length, DERIVED_OPS, ['hash', handle, hash, prefix, suffix].join('|')) };
  },
  hkdf({ handle, hash, salt, info, length }) {
    const key = lookup(handle, 'hkdf');
    const out = Buffer.from(crypto.hkdfSync(hash, key, Buffer.from(salt, 'base64'), Buffer.from(info, 'base64'), length));
    return { handle: newHandle(out, length, DERIVED_OPS, ['hkdf', handle, hash, salt, info, length].join('|')) };
  },
  aescbc({ handle, mode, iv, data }) {
    const key = lookup(handle, 'aes-cbc');
    const alg = `aes-${key.length * 8}-cbc`;
    const f = mode === 'encrypt' ? crypto.createCipheriv : crypto.createDecipheriv;
    const c = f(alg, key, Buffer.from(iv, 'base64'));
    return { out: Buffer.concat([c.update(Buffer.from(data, 'base64')), c.final()]).toString('base64') };
  },
  aesgcm({ handle, mode, iv, data, aad, tagLength }) {
    const key = lookup(handle, 'aes-gcm');
    const alg = `aes-${key.length * 8}-gcm`;
    const tagBytes = (tagLength || 128) / 8;
    if (mode === 'encrypt') {
      const c = crypto.createCipheriv(alg, key, Buffer.from(iv, 'base64'), { authTagLength: tagBytes });
      if (aad) c.setAAD(Buffer.from(aad, 'base64'));
      const ct = Buffer.concat([c.update(Buffer.from(data, 'base64')), c.final(), c.getAuthTag()]);
      return { out: ct.toString('base64') };
    }
    const buf = Buffer.from(data, 'base64');
    const d = crypto.createDecipheriv(alg, key, Buffer.from(iv, 'base64'), { authTagLength: tagBytes });
    if (aad) d.setAAD(Buffer.from(aad, 'base64'));
    d.setAuthTag(buf.subarray(buf.length - tagBytes));
    const pt = Buffer.concat([d.update(buf.subarray(0, buf.length - tagBytes)), d.final()]);
    return { out: pt.toString('base64') };
  },
};

try { fs.unlinkSync(SOCK); } catch {}
const server = net.createServer((sock) => {
  let buf = '';
  sock.on('data', (chunk) => {
    buf += chunk;
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i); buf = buf.slice(i + 1);
      let reply;
      try {
        const req = JSON.parse(line);
        if (req.handleB64) req.handle = handleFromBytes(req.handleB64);
        reply = { ok: true, ...ops[req.op](req) };
        const scope = reply._scope; delete reply._scope;
        audit.push({ t: Date.now(), op: req.op, handle: String(req.handle).slice(0, 20), ...(scope ? { sigv4: scope } : {}) });
        fs.appendFileSync(process.env.KEEPER_AUDIT || './audit.log', JSON.stringify(audit.at(-1)) + '\n');
      } catch (e) {
        reply = { ok: false, error: e.message };
      }
      sock.write(JSON.stringify(reply) + '\n');
    }
  });
});
server.listen(SOCK, () => { fs.chmodSync(SOCK, 0o600); console.log('keeper listening on', SOCK); });
```

### shim.cjs

Node shim, preloaded with `--require`: wraps node:crypto and WebCrypto, forwards handle calls to the keeper synchronously.

```js
// shim.cjs — preload with `node --require ./shim.cjs app.js` (works for CJS and ESM apps).
// Env vars hold handles ("KH1:<id>...") instead of real secrets. Crypto calls made with a
// handle are forwarded to the keeper process; the real key never enters this process.
'use strict';
const crypto = require('node:crypto');
const { Worker, MessageChannel, receiveMessageOnPort } = require('node:worker_threads');
const nodeModule = require('node:module');

const SOCK = process.env.KEEPER_SOCK || '/tmp/keeper.sock';
const HANDLE_RE = /^KH1:[0-9a-f]{16}/;

// ---------- synchronous call to the keeper (worker thread + Atomics.wait) ----------
let worker, port, signal;
function startWorker() {
  const ch = new MessageChannel();
  port = ch.port1;
  signal = new Int32Array(new SharedArrayBuffer(4));
  worker = new Worker(`
    const { workerData } = require('node:worker_threads');
    const net = require('node:net');
    const { port, signal, sock } = workerData;
    let conn, buf = '', pending = null;
    function connect() {
      conn = net.connect(sock);
      conn.on('data', (c) => {
        buf += c; let i;
        while ((i = buf.indexOf('\\n')) >= 0) {
          const line = buf.slice(0, i); buf = buf.slice(i + 1);
          port.postMessage(JSON.parse(line));
          Atomics.store(signal, 0, 1); Atomics.notify(signal, 0);
        }
      });
      conn.on('error', (e) => { port.postMessage({ ok: false, error: 'keeper unreachable: ' + e.message }); Atomics.store(signal, 0, 1); Atomics.notify(signal, 0); });
    }
    connect();
    port.on('message', (req) => conn.write(JSON.stringify(req) + '\\n'));
  `, { eval: true, workerData: { port: ch.port2, signal, sock: SOCK }, transferList: [ch.port2] });
  worker.unref();
}
function callKeeper(req) {
  if (!worker) startWorker();
  Atomics.store(signal, 0, 0);
  port.postMessage(req);
  Atomics.wait(signal, 0, 0, 5000);
  const msg = receiveMessageOnPort(port);
  if (!msg) throw new Error('keeper timeout');
  if (!msg.message.ok) throw new Error('keeper: ' + msg.message.error);
  return msg.message;
}

// ---------- recognising handles ----------
const keyObjectHandles = new WeakMap();   // node KeyObject -> handle
const cryptoKeyHandles = new WeakMap();   // WebCrypto CryptoKey -> { handle, algorithm }
function toBuf(x) {
  if (typeof x === 'string') return Buffer.from(x, 'latin1');
  if (Buffer.isBuffer(x)) return x;
  if (ArrayBuffer.isView(x)) return Buffer.from(x.buffer, x.byteOffset, x.byteLength);
  if (x instanceof ArrayBuffer) return Buffer.from(x);
  return null;
}
function handleOf(key) {
  if (key && typeof key === 'object' && keyObjectHandles.has(key)) return keyObjectHandles.get(key);
  const b = toBuf(key);
  if (!b) return null;
  const s = b.toString('latin1');
  return HANDLE_RE.test(s) ? s : null;
}
const b64 = (x) => toBuf(x).toString('base64');
// A key that is a short prefix followed by a handle, e.g. AWS SigV4's "AWS4" + secret.
const PREFIXED_RE = /^([\s\S]{1,8}?)(KH1:[0-9a-f]{16}[.]*)$/;
function prefixedHandleOf(key) {
  const b = toBuf(key);
  const m = b && b.toString('latin1').match(PREFIXED_RE);
  return m ? { prefix: Buffer.from(m[1], 'latin1').toString('base64'), handle: m[2] } : null;
}

// ---------- node:crypto ----------
const realCreateHmac = crypto.createHmac;
crypto.createHmac = function createHmac(alg, key, options) {
  let handle = handleOf(key), prefix;
  if (!handle) { const p = prefixedHandleOf(key); if (p) ({ handle, prefix } = p); }
  if (!handle) return realCreateHmac.apply(this, arguments);
  const chunks = [];
  let done = false;
  const h = {
    update(data, enc) { chunks.push(typeof data === 'string' ? Buffer.from(data, enc || 'utf8') : toBuf(data)); return h; },
    digest(enc) {
      if (done) throw new Error('Digest already called');
      done = true;
      const req = { op: 'hmac', handle, alg, data: Buffer.concat(chunks).toString('base64') };
      if (prefix !== undefined) req.prefix = prefix;
      const r = callKeeper(req);
      // The keeper answers with a handle when the output is itself a key (SigV4 intermediate keys).
      const out = r.handle ? Buffer.from(r.handle, 'latin1') : Buffer.from(r.digest, 'base64');
      return enc ? out.toString(enc) : out;
    },
  };
  return h;
};
const realCreateSecretKey = crypto.createSecretKey;
crypto.createSecretKey = function createSecretKey(key, enc) {
  const handle = handleOf(typeof key === 'string' && enc ? Buffer.from(key, enc) : key);
  if (!handle) return realCreateSecretKey.apply(this, arguments);
  const ko = realCreateSecretKey(crypto.randomBytes(32)); // decoy bytes; exporting it reveals nothing
  keyObjectHandles.set(ko, handle);
  return ko;
};
// HKDF from a handle returns a handle (the derived key stays in the keeper).
function hkdfRemote(digest, ikm, salt, info, keylen) {
  const handle = handleOf(ikm);
  const r = callKeeper({ op: 'hkdf', handle, hash: digest, salt: b64(typeof salt === 'string' ? Buffer.from(salt) : salt), info: b64(typeof info === 'string' ? Buffer.from(info) : info), length: keylen });
  const out = Buffer.from(r.handle, 'latin1');
  return out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength);
}
const realHkdf = crypto.hkdf, realHkdfSync = crypto.hkdfSync;
crypto.hkdfSync = function (digest, ikm, salt, info, keylen) {
  if (!handleOf(ikm)) return realHkdfSync.apply(this, arguments);
  return hkdfRemote(digest, ikm, salt, info, keylen);
};
crypto.hkdf = function (digest, ikm, salt, info, keylen, cb) {
  if (!handleOf(ikm)) return realHkdf.apply(this, arguments);
  let out, err; try { out = hkdfRemote(digest, ikm, salt, info, keylen); } catch (e) { err = e; }
  process.nextTick(() => cb(err || null, out));
};
// Make `import { createHmac } from 'node:crypto'` in ESM code see the patched versions.
nodeModule.syncBuiltinESMExports();

// ---------- WebCrypto (globalThis.crypto.subtle) ----------
const subtle = globalThis.crypto.subtle;
const real = {
  importKey: subtle.importKey.bind(subtle), sign: subtle.sign.bind(subtle), verify: subtle.verify.bind(subtle),
  deriveBits: subtle.deriveBits.bind(subtle), encrypt: subtle.encrypt.bind(subtle), decrypt: subtle.decrypt.bind(subtle),
  exportKey: subtle.exportKey.bind(subtle),
};
const hashName = (a) => (typeof a === 'string' ? a : a.name).toUpperCase().replace('SHA-', 'sha');
subtle.importKey = async function (format, keyData, algorithm, extractable, usages) {
  const handle = format === 'raw' ? handleOf(keyData) : null;
  if (!handle) return real.importKey(format, keyData, algorithm, extractable, usages);
  const algName = (typeof algorithm === 'string' ? algorithm : algorithm.name).toUpperCase();
  // A real CryptoKey of the same type, built from decoy bytes, so `instanceof CryptoKey` and type checks pass.
  let decoy;
  if (algName === 'HKDF') decoy = await real.importKey('raw', crypto.randomBytes(32), 'HKDF', false, usages);
  else decoy = await real.importKey('raw', crypto.randomBytes(algName === 'HMAC' ? 32 : 32), algorithm, false, usages);
  cryptoKeyHandles.set(decoy, { handle, algorithm });
  return decoy;
};
subtle.sign = async function (algorithm, key, data) {
  const h = cryptoKeyHandles.get(key);
  if (!h) return real.sign(algorithm, key, data);
  const r = callKeeper({ op: 'hmac', handle: h.handle, alg: hashName(h.algorithm.hash), data: b64(data) });
  const out = Buffer.from(r.digest, 'base64');
  return out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength);
};
subtle.verify = async function (algorithm, key, signature, data) {
  const h = cryptoKeyHandles.get(key);
  if (!h) return real.verify(algorithm, key, signature, data);
  const mac = Buffer.from(await subtle.sign(algorithm, key, data));
  const sig = toBuf(signature);
  return sig.length === mac.length && crypto.timingSafeEqual(sig, mac);
};
subtle.deriveBits = async function (algorithm, baseKey, length) {
  const h = cryptoKeyHandles.get(baseKey);
  if (!h) return real.deriveBits(algorithm, baseKey, length);
  // The derived key stays in the keeper; we get back a new handle of the requested length.
  const r = callKeeper({ op: 'hkdf', handle: h.handle, hash: hashName(algorithm.hash), salt: b64(algorithm.salt), info: b64(algorithm.info), length: length / 8 });
  const out = Buffer.from(r.handle, 'latin1');
  return out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength);
};
for (const mode of ['encrypt', 'decrypt']) {
  subtle[mode] = async function (algorithm, key, data) {
    const h = cryptoKeyHandles.get(key);
    if (!h) return real[mode](algorithm, key, data);
    const name = (typeof algorithm === 'string' ? algorithm : algorithm.name).toUpperCase();
    if (name === 'AES-CBC') {
      const r = callKeeper({ op: 'aescbc', mode, handle: h.handle, iv: b64(algorithm.iv), data: b64(data) });
      const out = Buffer.from(r.out, 'base64');
      return out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength);
    }
    const r = callKeeper({ op: 'aesgcm', mode, handle: h.handle, iv: b64(algorithm.iv), aad: algorithm.additionalData ? b64(algorithm.additionalData) : undefined, tagLength: algorithm.tagLength, data: b64(data) });
    const out = Buffer.from(r.out, 'base64');
    return out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength);
  };
}
```

### pyshim/sitecustomize.py

Python shim: wraps `hmac.new` and the SHA constructors (for Django and itsdangerous key derivation).

```python
# sitecustomize.py — Python counterpart of shim.cjs. Put its folder on PYTHONPATH.
import hashlib, hmac, json, os, re, socket, base64
SOCK = os.environ.get('KEEPER_SOCK', '/tmp/keeper.sock')
H = re.compile(rb'KH1:[0-9a-f]{16}[.]*')
_f = None
def _call(req):
    global _f
    if _f is None:
        c = socket.socket(socket.AF_UNIX); c.connect(SOCK); _f = c.makefile('rwb')
    _f.write(json.dumps(req).encode() + b'\n'); _f.flush()
    r = json.loads(_f.readline())
    if not r['ok']: raise RuntimeError('keeper: ' + r['error'])
    return r
b64 = lambda b: base64.b64encode(b).decode()
def _as_bytes(k):
    return k.encode('latin1') if isinstance(k, str) else bytes(k) if isinstance(k, (bytes, bytearray, memoryview)) else None

_real_new = hmac.new
class _RemoteHMAC:
    def __init__(self, handle, msg, digestmod, prefix=None):
        self.handle, self.buf, self.prefix = handle, bytearray(msg or b''), prefix
        self.alg = digestmod if isinstance(digestmod, str) else digestmod().name
        self.digest_size = hashlib.new(self.alg).digest_size
    def update(self, m): self.buf += m
    def copy(self): c = _RemoteHMAC(self.handle, bytes(self.buf), self.alg, self.prefix); return c
    def digest(self):
        req = {'op': 'hmac', 'handle': self.handle, 'alg': self.alg, 'data': b64(bytes(self.buf))}
        if self.prefix is not None: req['prefix'] = b64(self.prefix)
        r = _call(req)
        # A handle comes back when the output is itself a key (SigV4 intermediate keys).
        return r['handle'].encode('latin1') if 'handle' in r else base64.b64decode(r['digest'])
    def hexdigest(self): return self.digest().hex()
PREFIXED = re.compile(rb'(.{1,8}?)(KH1:[0-9a-f]{16}[.]*)', re.S)
def _new(key, msg=None, digestmod=''):
    kb = _as_bytes(key)
    if kb is not None:
        if H.fullmatch(kb): return _RemoteHMAC(kb.decode('latin1'), msg, digestmod)
        p = PREFIXED.fullmatch(kb)  # e.g. AWS SigV4's b"AWS4" + secret
        if p: return _RemoteHMAC(p.group(2).decode('latin1'), msg, digestmod, p.group(1))
    return _real_new(key, msg, digestmod)
hmac.new = _new

# Hash-based key derivation: hasher(salt + SECRET).digest() — the result becomes a new handle.
class _DerivingHash:
    def __init__(self, name, data=b''):
        self.name, self.buf = name, bytearray(data)
        self.digest_size = hashlib.new(name).digest_size; self.block_size = hashlib.new(name).block_size
    def update(self, d): self.buf += d
    def copy(self): return _DerivingHash(self.name, bytes(self.buf))
    def digest(self):
        m = H.search(bytes(self.buf))
        if not m: h = hashlib.new(self.name); h.update(bytes(self.buf)); return h.digest()
        r = _call({'op': 'hashDerive', 'handle': m.group().decode('latin1'), 'hash': self.name,
                   'prefix': b64(bytes(self.buf[:m.start()])), 'suffix': b64(bytes(self.buf[m.end():])), 'length': self.digest_size})
        return r['handle'].encode('latin1')
    def hexdigest(self): return self.digest().hex()
for _name in ('sha1', 'sha256', 'sha512'):
    _orig = getattr(hashlib, _name)
    def _make(name, orig):
        def ctor(data=b'', **kw):
            if H.search(bytes(data)): return _DerivingHash(name, data)
            o = orig(data, **kw)
            return o
        return ctor
    setattr(hashlib, _name, _make(_name, _orig))
```

### app.mjs

Test app: five Node libraries used exactly as their docs say, plus the heap and environment dump.

```js
// An unmodified "app": uses popular libraries exactly as their docs say.
import { createHmac } from 'node:crypto';          // ESM named import (tests syncBuiltinESMExports)
import jwt from 'jsonwebtoken';
import * as jose from 'jose';
import signature from 'cookie-signature';
import Stripe from 'stripe';
import v8 from 'node:v8';
import fs from 'node:fs';

const env = process.env;
const results = {};

// 1. raw node:crypto via ESM named import
results.rawHmac = createHmac('sha256', env.JWT_SECRET).update('hello').digest('hex');

// 2. jsonwebtoken (CJS, crypto.createHmac under the hood)
const t1 = jwt.sign({ sub: 'user1', role: 'admin' }, env.JWT_SECRET, { algorithm: 'HS256', noTimestamp: true });
results.jsonwebtoken = t1;
results.jsonwebtokenVerify = jwt.verify(t1, env.JWT_SECRET).sub;

// 3. jose (WebCrypto subtle.importKey + subtle.sign)
const key = new TextEncoder().encode(env.JWT_SECRET);
const t2 = await new jose.SignJWT({ sub: 'user1', role: 'admin' }).setProtectedHeader({ alg: 'HS256' }).sign(key);
results.jose = t2;
results.joseVerify = (await jose.jwtVerify(t2, key)).payload.sub;

// 4. cookie-signature (express-session / cookie-parser use this)
const signed = signature.sign('session-id-123', env.COOKIE_SECRET);
results.cookie = signed;
results.cookieUnsign = signature.unsign(signed, env.COOKIE_SECRET);

// 5. Stripe webhook verification, sync (createHmac) and async (SubtleCrypto)
const stripe = new Stripe('sk_test_dummy');
const payload = JSON.stringify({ id: 'evt_1', type: 'payment_intent.succeeded' });
const header = fs.readFileSync('./stripe_header.txt', 'utf8').trim(); // produced by the "real Stripe" (oracle)
results.stripeSync = stripe.webhooks.constructEvent(payload, header, env.STRIPE_WEBHOOK_SECRET).type;
results.stripeAsync = (await stripe.webhooks.constructEventAsync(payload, header, env.STRIPE_WEBHOOK_SECRET, undefined, Stripe.createSubtleCryptoProvider())).type;

// 6. Auth.js-style key derivation: HKDF from AUTH_SECRET, then AES-GCM (WebCrypto)
const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.AUTH_SECRET), 'HKDF', false, ['deriveBits']);
const derived = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('session-enc') }, base, 256);
const aes = await crypto.subtle.importKey('raw', derived, 'AES-GCM', false, ['encrypt', 'decrypt']);
const iv = new Uint8Array(12);
const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aes, new TextEncoder().encode('{"user":"alice"}'));
results.aesCiphertext = Buffer.from(ct).toString('base64');
results.aesRoundTrip = new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aes, ct));
results.derivedBytesSeenByApp = Buffer.from(derived).toString('latin1').slice(0, 24) + '…';

// 7. What can a curious agent see from inside the app process?
results.envJwtSecret = env.JWT_SECRET;
v8.writeHeapSnapshot('/tmp/app.heapsnapshot');
fs.writeFileSync('/tmp/app.environ', fs.readFileSync('/proc/self/environ'));
fs.writeFileSync('/tmp/app.results.json', JSON.stringify(results, null, 2));
console.log(JSON.stringify(results, null, 2));
```

### authjs.mjs

Auth.js session token encode and decode.

```js
import { encode, decode } from '@auth/core/jwt';
import fs from 'node:fs';
const secret = process.env.AUTH_SECRET, salt = 'authjs.session-token';
const token = await encode({ token: { sub: 'user1', name: 'Alice' }, secret, salt });
const back = await decode({ token, secret, salt });
console.log(JSON.stringify({ tokenPrefix: token.slice(0, 40) + '…', decodedName: back?.name }));
fs.writeFileSync('/tmp/authjs.token', token);
```

### oracle.mjs

Plays the real world (Stripe, a verifier). Run without the shim; checks outputs with the real keys and scans the heap.

```js
// oracle.mjs — plays "the real world" that knows the real secrets (Stripe's servers, a verifier).
// Run WITHOUT the shim. Mode "prep" makes the Stripe header; mode "check" verifies the app's outputs.
import fs from 'node:fs';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import Stripe from 'stripe';
const v = JSON.parse(fs.readFileSync('./vault.json', 'utf8'));
const real = Object.fromEntries(Object.entries(v).map(([h, x]) => [h.slice(0, 20), x.key]));
const JWT = real['KH1:a1b2c3d4e5f60718'], COOKIE = real['KH1:0f1e2d3c4b5a6978'], WH = real['KH1:1122334455667788'], AUTH = real['KH1:99aabbccddeeff00'];
const payload = JSON.stringify({ id: 'evt_1', type: 'payment_intent.succeeded' });
if (process.argv[2] === 'prep') {
  fs.writeFileSync('./stripe_header.txt', new Stripe('sk_test_dummy').webhooks.generateTestHeaderString({ payload, secret: WH }));
  console.log('stripe header written');
} else {
  const r = JSON.parse(fs.readFileSync('/tmp/app.results.json', 'utf8'));
  const checks = {
    rawHmac: r.rawHmac === crypto.createHmac('sha256', JWT).update('hello').digest('hex'),
    jsonwebtokenValidWithRealKey: jwt.verify(r.jsonwebtoken, JWT).sub === 'user1',
    joseValidWithRealKey: jwt.verify(r.jose, JWT).sub === 'user1',
    cookieMatchesRealKey: r.cookie === 'session-id-123.' + crypto.createHmac('sha256', COOKIE).update('session-id-123').digest('base64').replace(/=+$/, ''),
    stripeVerified: r.stripeSync === 'payment_intent.succeeded' && r.stripeAsync === 'payment_intent.succeeded',
    aesDecryptsWithRealDerivedKey: (() => {
      const k = Buffer.from(crypto.hkdfSync('sha256', AUTH, Buffer.alloc(0), 'session-enc', 32));
      const buf = Buffer.from(r.aesCiphertext, 'base64');
      const d = crypto.createDecipheriv('aes-256-gcm', k, Buffer.alloc(12));
      d.setAuthTag(buf.subarray(buf.length - 16));
      return Buffer.concat([d.update(buf.subarray(0, buf.length - 16)), d.final()]).toString() === '{"user":"alice"}';
    })(),
  };
  const heap = fs.readFileSync('/tmp/app.heapsnapshot', 'latin1');
  const environ = fs.readFileSync('/tmp/app.environ', 'latin1');
  const derivedKeyHex = Buffer.from(crypto.hkdfSync('sha256', AUTH, Buffer.alloc(0), 'session-enc', 32));
  checks.realSecretsInAppHeap = [JWT, COOKIE, WH, AUTH].filter((s) => heap.includes(s)).length;
  checks.realSecretsInAppEnviron = [JWT, COOKIE, WH, AUTH].filter((s) => environ.includes(s)).length;
  checks.derivedKeyInAppHeap = heap.includes(derivedKeyHex.toString('latin1')) || heap.includes(derivedKeyHex.toString('hex'));
  console.log(JSON.stringify(checks, null, 2));
}
```

### app.py

Python test: PyJWT and itsdangerous.

```python
import os, json, jwt, itsdangerous
r = {}
s = os.environ['JWT_SECRET']
tok = jwt.encode({'sub': 'user1'}, s, algorithm='HS256')
r['pyjwt'] = tok; r['pyjwtVerify'] = jwt.decode(tok, s, algorithms=['HS256'])['sub']
signer = itsdangerous.URLSafeSerializer(os.environ['COOKIE_SECRET'], salt='cookie-session')
cookie = signer.dumps({'user': 'alice'}); r['itsdangerous'] = cookie; r['itsdangerousLoads'] = signer.loads(cookie)['user']
print(json.dumps(r, indent=1))
json.dump(r, open('/tmp/py.results.json', 'w'))
```

### dj.py

Django signing test.

```python
import os, django
from django.conf import settings
settings.configure(SECRET_KEY=os.environ['COOKIE_SECRET'])
from django.core import signing
v = signing.dumps({'user': 'alice'}); print('django signed:', v)
print('django loads:', signing.loads(v)['user'])
open('/tmp/dj.txt','w').write(v)
```

### bench.mjs

Latency benchmark.

```js
import { createHmac } from 'node:crypto';
const s = process.env.JWT_SECRET; const N = 2000;
let t = performance.now(); for (let i = 0; i < N; i++) createHmac('sha256', s).update('x' + i).digest('hex');
console.log('handle HMAC: ' + ((performance.now() - t) / N * 1000).toFixed(0) + ' µs/op');
t = performance.now(); for (let i = 0; i < N; i++) createHmac('sha256', 'plain-local-key').update('x' + i).digest('hex');
console.log('normal HMAC: ' + ((performance.now() - t) / N * 1000).toFixed(1) + ' µs/op');
```

### negative.mjs

Policy refusal test.

```js
import { createHmac } from 'node:crypto';
try { createHmac('sha256', process.env.AUTH_SECRET).update('x').digest('hex'); console.log('UNEXPECTED: hmac with hkdf-only key worked'); }
catch (e) { console.log('policy refusal OK ->', e.message); }
```

### aws.mjs

Unmodified AWS SDK for JavaScript v3 app: an S3 PutObject (header auth), a presigned URL, and a DynamoDB call the policy should refuse. A stub request handler captures signed requests; nothing is sent to AWS.

```js
// An unmodified app using the AWS SDK for JavaScript v3. Credentials come from the
// environment as usual. Nothing is sent to AWS: a stub request handler captures the
// signed request so the oracle can verify it the way AWS would.
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { DynamoDBClient, ListTablesCommand } from '@aws-sdk/client-dynamodb';
import { Readable } from 'node:stream';
import fs from 'node:fs';
import { createHash } from 'node:crypto';

const captured = [];
const requestHandler = {
  async handle(req) {
    const q = new URLSearchParams(req.query || {}).toString();
    captured.push({
      method: req.method,
      url: `${req.protocol}//${req.hostname}${req.path}${q ? '?' + q : ''}`,
      headers: req.headers,
      bodySha256: createHash('sha256').update(typeof req.body === 'string' ? req.body : Buffer.from(req.body || '')).digest('hex'),
    });
    return { response: { statusCode: 200, headers: { etag: '"x"' }, body: Readable.from([]) } };
  },
};
const results = { errors: {} };
const s3 = new S3Client({ requestHandler });

// 1. A normal signed request (Authorization header)
await s3.send(new PutObjectCommand({ Bucket: 'doppelkey-test', Key: 'hello.txt', Body: 'hello from doppelkey' }));
// 2. A presigned URL (signature in the query string)
results.presignedUrl = await getSignedUrl(s3, new GetObjectCommand({ Bucket: 'doppelkey-test', Key: 'hello.txt' }), { expiresIn: 600 });
results.headerRequests = captured.slice(); // S3 only

// 3. Policy: this key may only sign for S3. Try DynamoDB with the same credentials.
try {
  await new DynamoDBClient({ requestHandler }).send(new ListTablesCommand({}));
  results.dynamodbSigned = true;
} catch (e) { results.errors.dynamodb = e.message; }

results.envSecretSeenByApp = process.env.AWS_SECRET_ACCESS_KEY;
fs.writeFileSync(process.env.OUT || '/tmp/aws.results.json', JSON.stringify(results, null, 2));
console.log('READY', process.pid);
setTimeout(() => {}, 60000); // stay alive so the oracle can scan this process's memory
```

### aws.py

The same with boto3. boto3 makes S3 presigned URLs with legacy SigV2 by default, which the keeper refuses unless the policy allows it.

```python
# An unmodified app using boto3. Credentials come from the environment as usual.
# Nothing is sent to AWS: a before-send hook captures the signed request.
import json, os, sys, time, hashlib
import boto3
from botocore.awsrequest import AWSResponse

captured = []
class _Raw:
    def stream(self, **kw): yield b''
    def read(self, *a, **kw): return b''
def capture(request, **kw):
    body = request.body or b''
    body = body.encode() if isinstance(body, str) else (body.read() if hasattr(body, 'read') else bytes(body))
    captured.append({'method': request.method, 'url': request.url,
                     'headers': {k: (v.decode() if isinstance(v, bytes) else v) for k, v in request.headers.items()},
                     'bodySha256': hashlib.sha256(body).hexdigest()})
    return AWSResponse(request.url, 200, {'ETag': '"x"'}, _Raw())

s3 = boto3.client('s3')
s3.meta.events.register('before-send.s3.*', capture)
results = {'errors': {}}
s3.put_object(Bucket='doppelkey-test', Key='hello.txt', Body=b'hello from doppelkey')
results['presignedUrl'] = s3.generate_presigned_url('get_object', Params={'Bucket': 'doppelkey-test', 'Key': 'hello.txt'}, ExpiresIn=600)
results['headerRequests'] = captured
try:
    ddb = boto3.client('dynamodb')
    ddb.meta.events.register('before-send.dynamodb.*', capture)
    ddb.list_tables()
    results['dynamodbSigned'] = True
except Exception as e:
    results['errors']['dynamodb'] = str(e)[:160]
results['envSecretSeenByApp'] = os.environ['AWS_SECRET_ACCESS_KEY']
json.dump(results, open(os.environ.get('OUT', '/tmp/aws_py.results.json'), 'w'), indent=2)
print('READY', os.getpid(), flush=True)
time.sleep(60)
```

### aws_oracle.mjs

Plays AWS: holds the real secret and verifies each signature by rebuilding the SigV4 (or SigV2) canonical request. Writes the secret and derived signing keys as needles for the memory scan.

```js
// aws_oracle.mjs: plays AWS. Run WITHOUT the shim. Holds the real secret and checks every
// signature from a results file by rebuilding the SigV4 canonical request, as AWS does.
// Usage: node aws_oracle.mjs <results.json>   -> prints checks + writes /tmp/aws.needles (hex, one per line)
import fs from 'node:fs';
import crypto from 'node:crypto';
const v = JSON.parse(fs.readFileSync('./vault.json', 'utf8'));
const SECRET = Object.values(v).find((x) => x.profile === 'aws-sigv4').key;
const r = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));

const hmac = (k, d) => crypto.createHmac('sha256', k).update(d).digest();
const sha = (d) => crypto.createHash('sha256').update(d).digest('hex');
const enc = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
function signingKeys(date, region, service) {
  const kDate = hmac('AWS4' + SECRET, date), kRegion = hmac(kDate, region), kService = hmac(kRegion, service);
  return { kDate, kRegion, kService, kSigning: hmac(kService, 'aws4_request') };
}
function verify({ method, url, headers, bodySha256 }) {
  const u = new URL(url);
  if (u.searchParams.has('AWSAccessKeyId')) {
    // Legacy SigV2 query auth: base64(HMAC-SHA1(secret, "GET\n\n\n<Expires>\n/<bucket>/<key>"))
    const bucket = u.hostname.split('.s3')[0];
    const sts = `${method}\n\n\n${u.searchParams.get('Expires')}\n/${bucket}${u.pathname}`;
    return { ok: crypto.createHmac('sha1', SECRET).update(sts).digest('base64') === u.searchParams.get('Signature'), scope: 'sigv2', keys: {} };
  }
  const h = Object.fromEntries(Object.entries(headers).map(([k, x]) => [k.toLowerCase(), String(x)]));
  if (!h.host) h.host = u.host;
  let cred, signed, sig, amzDate, payload;
  const params = [...u.searchParams.entries()];
  if (h.authorization) {
    const m = h.authorization.match(/^AWS4-HMAC-SHA256 Credential=([^,]+), ?SignedHeaders=([^,]+), ?Signature=([0-9a-f]+)$/);
    [, cred, signed, sig] = m; amzDate = h['x-amz-date']; payload = h['x-amz-content-sha256'] || bodySha256;
    if (h['x-amz-content-sha256'] && h['x-amz-content-sha256'] !== bodySha256 && !h['x-amz-content-sha256'].includes('UNSIGNED-PAYLOAD')) return { ok: false, why: 'body hash mismatch' };
  } else {
    const q = Object.fromEntries(params);
    cred = q['X-Amz-Credential']; signed = q['X-Amz-SignedHeaders']; sig = q['X-Amz-Signature']; amzDate = q['X-Amz-Date']; payload = 'UNSIGNED-PAYLOAD';
  }
  const [akid, date, region, service] = cred.split('/');
  const query = params.filter(([k]) => k !== 'X-Amz-Signature').map(([k, x]) => [enc(k), enc(x)]).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : 1)).map(([k, x]) => `${k}=${x}`).join('&');
  const names = signed.split(';');
  const canon = [method, u.pathname, query, names.map((n) => `${n}:${h[n].trim().replace(/\s+/g, ' ')}\n`).join(''), signed, payload].join('\n');
  const scope = `${date}/${region}/${service}/aws4_request`;
  const sts = ['AWS4-HMAC-SHA256', amzDate, scope, sha(canon)].join('\n');
  const keys = signingKeys(date, region, service);
  const expected = hmac(keys.kSigning, sts).toString('hex');
  return { ok: expected === sig, akid, scope, keys };
}

const all = [...r.headerRequests.map((x) => ({ kind: 'header', ...x })), { kind: 'presigned', method: 'GET', url: r.presignedUrl, headers: {} }];
const out = { signaturesValidUnderRealKey: [], scopes: [] };
const needles = new Set([Buffer.from(SECRET).toString('hex')]);
for (const req of all) {
  const res = verify(req);
  out.signaturesValidUnderRealKey.push(`${req.kind}: ${res.ok}`);
  out.scopes.push(res.scope);
  for (const k of Object.values(res.keys || {})) needles.add(k.toString('hex'));
}
out.dynamodbRefused = r.errors.dynamodb || 'NOT refused';
out.secretSeenByApp = r.envSecretSeenByApp === SECRET ? 'REAL SECRET' : r.envSecretSeenByApp;
fs.writeFileSync('/tmp/aws.needles', [...needles].join('\n'));
console.log(JSON.stringify(out, null, 2));
```

### memscan.py

Reads every readable region of the live app process through /proc/<pid>/mem, as a same-user agent could, and looks for the secret and derived keys as raw bytes, hex and UTF-16.

```python
# memscan.py <pid> <needles-file>: reads every readable region of a live process
# (/proc/<pid>/mem, what a same-user agent could do) and counts needles found.
# Each needle is searched as raw bytes, as lowercase hex text, and as UTF-16 text.
import sys, re
pid, needles = sys.argv[1], [bytes.fromhex(l) for l in open(sys.argv[2]).read().split()]
forms = []
for i, n in enumerate(needles):
    label = 'secret' if i == 0 else f'derived key {i}'
    fs = [n, n.hex().encode()]
    if i == 0: fs.append(n.decode('latin1').encode('utf-16-le'))
    forms.append((label, fs))
found, scanned = {}, 0
mem = open(f'/proc/{pid}/mem', 'rb', 0)
for line in open(f'/proc/{pid}/maps'):
    addr, perms = line.split()[:2]
    if not perms.startswith('r') or '[vvar' in line or '[vsyscall' in line: continue
    lo, hi = (int(x, 16) for x in addr.split('-'))
    pos = lo
    while pos < hi:
        size = min(hi - pos, 64 << 20)
        try:
            mem.seek(pos); chunk = mem.read(size)
        except OSError:
            pos += size; continue
        scanned += len(chunk)
        for label, fs in forms:
            if any(f in chunk for f in fs): found[label] = True
        pos += size if pos + size >= hi else size - 256  # overlap so no needle is split
print({'bytesScanned': f'{scanned/1e6:.0f} MB', 'found': sorted(found) or 'nothing'})
```

### run_aws.sh

Runs one AWS app (Node or Python, shim or control), then the oracle and the memory scan.

```bash
#!/bin/sh
# run_aws.sh <node|python> <shim|control>: run an AWS app, verify its signatures, scan its memory.
# "control" runs WITHOUT the shim and WITH the real secret, to show the scanner does find it.
cd "$(dirname "$0")"
LANG_=$1; MODE=$2; OUT=/tmp/aws.$LANG_.$MODE.json; rm -f $OUT
E="$(cat .env.aws | xargs)"
if [ "$MODE" = control ]; then E="$(echo $E | sed 's#AWS_SECRET_ACCESS_KEY=[^ ]*#AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY#')"; fi
if [ "$LANG_" = node ]; then
  if [ "$MODE" = shim ]; then CMD="node --require ./shim.cjs aws.mjs"; else CMD="node aws.mjs"; fi
else
  if [ "$MODE" = shim ]; then CMD="env PYTHONPATH=./pyshim python3 aws.py"; else CMD="python3 aws.py"; fi
fi
env $E OUT=$OUT $CMD > /tmp/aws.app.out 2>&1 &
APP=$!
for i in $(seq 1 100); do [ -f $OUT ] && break; sleep 0.2; done
sleep 0.5
PID=$(grep READY /tmp/aws.app.out | awk '{print $2}')
[ -z "$PID" ] && { cat /tmp/aws.app.out; kill $APP; exit 1; }
node aws_oracle.mjs $OUT
python3 memscan.py $PID /tmp/aws.needles
kill $APP 2>/dev/null
```

### restart_keeper.sh

Starts the keeper with a pidfile.

```bash
#!/bin/sh
[ -f /tmp/keeper.pid ] && kill "$(cat /tmp/keeper.pid)" 2>/dev/null
sleep 0.3
node keeper.mjs > /tmp/keeper.out 2>&1 &
echo $! > /tmp/keeper.pid
sleep 0.5
```

### vault.json

Demo secrets (fake). A real keeper reads the OS keychain.

```json
{
  "KH1:a1b2c3d4e5f60718.......................": {"key": "real-jwt-secret-3f9c1e7a5b2d8c4e6f1a9b3d7e5c2a8f", "allow": ["hmac"]},
  "KH1:0f1e2d3c4b5a6978.......................": {"key": "real-cookie-secret-8e2b4d6f1a3c5e7b9d0f2a4c6e8b1d3f", "allow": ["hmac"]},
  "KH1:1122334455667788.......................": {"key": "whsec_realStripeSigningSecret1234567890abcd", "allow": ["hmac"]},
  "KH1:99aabbccddeeff00.......................": {"key": "real-auth-secret-for-hkdf-7c1e3a5b9d2f4e6a8c0b", "allow": ["hkdf"]},
  "KH1:a0a0b1b1c2c2d3d3....................": {"key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "allow": ["hmac"], "profile": "aws-sigv4", "accessKeyId": "AKIAIOSFODNN7EXAMPLE", "services": ["s3"], "sigv2": true}
}
```

### .env.handles

What the app's environment holds instead of secrets.

```bash
JWT_SECRET=KH1:a1b2c3d4e5f60718.......................
COOKIE_SECRET=KH1:0f1e2d3c4b5a6978.......................
STRIPE_WEBHOOK_SECRET=KH1:1122334455667788.......................
AUTH_SECRET=KH1:99aabbccddeeff00.......................
```

### .env.aws

What the AWS apps see. The access key ID is public; the secret is a handle.

```bash
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=KH1:a0a0b1b1c2c2d3d3....................
AWS_REGION=ap-southeast-1
AWS_DEFAULT_REGION=ap-southeast-1
```
