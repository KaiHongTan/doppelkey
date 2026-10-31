# Research: open questions and pre-build checks

Date: 31 October 2026. This answers the open questions in `DOPPELKEY.md` section 15 and records other findings from testing before Milestone 1. Each item is tagged:

- **[tested]**: run in this repo's dev container (Linux x86-64, Firecracker VM, running as root plus a throwaway non-root user). Scripts are in `research/2026-10-31/`.
- **[docs]**: from cited documentation; not run here.
- **[inference]**: reasoning, not verified.

All secrets used were fake.

## TL;DR: what changes in the plan

1. **The prototype holds up on current versions.** It passed on Node 20, 22, 24 and 26, Bun 1.4 and Python 3.13, using jsonwebtoken 9, jose 6, stripe 23, @auth/core 0.41, AWS SDK v3.1161, PyJWT, itsdangerous, Django and boto3. The real key verified every output. Heap and memory scans found nothing. **[tested]**
2. **The shim can't idle when `process.env` has no handles.** Next.js loads `.env` after preload. The shim must always patch, with a cheap fast path for non-handle keys. **[tested]**
3. **Fail closed is broken for some libraries today.** iron-session (PBKDF2), svix (pure-JS HMAC), @oslojs/crypto, Better Auth (`@noble` HKDF and XChaCha20) and next-auth v4 (`createCipheriv`) produce **silently wrong** results under the prototype. They don't throw. **[tested]**
4. **Pure-JS crypto can be covered on Node ≥ 22.15** with `module.registerHooks`. A PoC made svix produce a correct signature. Node 20 lacks the API and has been end-of-life since April 2026. The CI matrix should become Node 22, 24, 26. **[tested]**
5. **The handle format needs a compact form.** itsdangerous derives 20-byte SHA-1 keys, and the proposed `dk1:NOT-A-SECRET-…` handle is 58 characters. Format-preserving handles (hex, base64, `whsec_`) should be encodings of the compact form. **[tested]**
6. **Linux keeper memory is protected by `PR_SET_DUMPABLE=0` alone,** without Yama. The real weaknesses are two things the same user owns: key storage at rest (Secret Service is readable by any same-user process) and the service unit and binary. The threat model in section 12 needs updating. **[tested + docs]**
7. **Auto-load matrix:**
   - **npm and pnpm (10 and 11):** `.npmrc` `node-options` works.
   - **Yarn Berry:** ignores `.npmrc`, but `.env.yarn` works.
   - **Yarn classic:** has no route.
   - **Bun:** `bunfig.toml` preload works, but not for `bun test` (needs `[test] preload`), and Bun ignores `NODE_OPTIONS`.
   - **Gotcha:** npm and pnpm *replace* an existing `NODE_OPTIONS`. **[tested]**

## Answers to section 15

### Q1. Does macOS hardened runtime stop a same-user agent reading keeper memory?

Not testable here (no Mac). From the docs: **yes, if the binary is Developer ID-signed with hardened runtime and lacks `com.apple.security.get-task-allow`, and SIP is on.** **[docs]**

- An unsigned or ad-hoc build can likely be read with `lldb -p` on a typical dev Mac. Xcode runs `DevToolsSecurity -enable`, which removes the admin prompt for same-user `task_for_pid`. [Apple: debugger entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger), [forum](https://developer.apple.com/forums/thread/119059)
- `PT_DENY_ATTACH` blocks ptrace/dtrace attach, not `task_for_pid` + `mach_vm_read`. Use it as a cheap extra layer only. Pair it with `RLIMIT_CORE=0`.
- Being launched by launchd doesn't protect anything by itself; the code-signing flags do. **[inference]**
- **Keychain:**
  - **File-based keychain:** an item's ACL binds to the creator's designated requirement. Any other process, including `security find-generic-password -w`, triggers a prompt with "Always Allow". An agent can trigger that prompt and hope the user clicks it.
  - **Data-protection keychain** (`kSecUseDataProtectionKeychain`): access is gated by keychain-access-group entitlements (provisioning profile, app-like bundle). There's no prompt another process can trigger. [TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)

**Decision proposed:** on macOS, ship `doppelkeyd` as a Developer ID-signed, hardened-runtime app bundle with a provisioning profile, and store keys in the data-protection keychain. Document that unsigned or ad-hoc builds are weaker. A real-Mac test is still required; this stays open.

### Q2. Does Bun's `node:crypto` honour the patched functions? Does a project `bunfig.toml` preload load under `bun run`?

**Yes to both, with caveats.** **[tested, Bun 1.4.4]**

**What works through the prototype shim:** the bunfig preload or `bun --preload`, patched `createHmac` (including the ESM named import), jsonwebtoken, jose, cookie-signature, async Stripe, and WebCrypto HKDF → AES-GCM. The real key verified each output, and the AES ciphertext matched the Node run byte for byte. The worker + `Atomics.wait` + `receiveMessageOnPort` bridge works in Bun.

| Invocation | bunfig `preload` applies? |
|---|---|
| `bun app.js`, `bun run app.js` | yes |
| `bun run dev` where the script is `bun app.js` | yes |
| `bun run dev` where the script is `node app.js` | **no** (real Node runs; it needs `NODE_OPTIONS`) |
| `bun --bun run dev` (script `node …`) | yes |
| `bun test` | **no**. Needs `[test] preload = [...]` |
| `NODE_OPTIONS=--require …` with `bun app.js` | **no**. Bun ignores `NODE_OPTIONS` ([oven-sh/bun#40316](https://github.com/oven-sh/bun/issues/40316)) |

Caveat: under Bun, Stripe resolves to its edge build, which has no sync `constructEvent`. That's Stripe's behaviour, not the shim's.

**Decision proposed:** `init` writes both top-level `preload` and `[test] preload` in `bunfig.toml`, and also `.npmrc` for scripts that call `node`.

### Q3. Do pnpm and Yarn honour `node-options` in `.npmrc`?

**[tested]**

| Runner | `.npmrc` `node-options` | What works |
|---|---|---|
| npm 10.9 | yes | `.npmrc`, also from subdirectories |
| pnpm 10.28 | yes | `.npmrc`; `pnpm-workspace.yaml` `nodeOptions` |
| pnpm 11.28 | **yes** (contrary to a reading of the pnpm 11 release notes) | both, as above. Write both for forward compatibility ([pnpm settings](https://pnpm.io/settings)) |
| Yarn 1.22 (classic) | **no** | nothing found. Fall back to `doppelkey run` or an entry-file import |
| Yarn 4.5 (Berry) | **no** (Berry ignores `.npmrc`) | `.env.yarn` with `NODE_OPTIONS=--require …`. Works with both node-modules and PnP linkers; Yarn appends to its own `--require .pnp.cjs` ([yarnrc `injectEnvironmentFiles`](https://yarnpkg.com/configuration/yarnrc)) |

**Gotcha:** npm and pnpm **replace** an inherited `NODE_OPTIONS` (the container's `--use-openssl-ca` was dropped). `doppelkey doctor` should warn when a user's own `NODE_OPTIONS` will be dropped. Yarn Berry's `.env.yarn` does the same. **[tested]**

### Q4. Would Vault, 1Password or Infisical accept integrations as keeper storage backends?

**[docs]**

- **Vault Transit** fits best: HMAC, sign and encrypt run server-side, and keys are non-exportable by default. A "delegate" mode would mean even the keeper never holds the key. The cost is that the keeper's Vault token becomes the thing to protect, plus a network round-trip per operation. Vault is BSL; **OpenBao** (MPL-2.0) offers the same Transit API, so target both. HashiCorp runs a [Vault integration program](https://developer.hashicorp.com/vault/docs/partners/program).
- **1Password:**
  - The SDKs (Go/JS/Python; no Rust found) authenticate with a service account or the desktop app.
  - Environments can be read via the SDK or `op run --environment`.
  - Its local `.env` named pipe is readable by any process once unlocked, which is exactly doppelkey's threat. That's a good positioning point.
  - It has a [partner program](https://1password.com/partnerships).
- **Infisical:** has an official Rust SDK and Universal Auth machine identities. The core is MIT. No partner program found.
- **dotenvx:** an import source only. Its private key is just another file an agent can read.

**Decision proposed:** a pluggable storage trait in the keeper. v0.1 uses the local store. Later: Vault/OpenBao Transit as a delegate backend, and 1Password and Infisical as fetch-and-hold sources. Contacting the vendors is a business task.

### Q5. Confirm the AWS result against live S3.

**Still open.** There are no AWS credentials here. I re-confirmed offline:
- AWS SDK v3.1161: header and presigned SigV4 are valid under the real key, DynamoDB is refused by policy, and a 248 MB memory scan found nothing.
- boto3: SigV4 header requests and SigV2 presigned URLs (policy opt-in) are valid, DynamoDB is refused, and a 75 MB scan found nothing. **[tested]**

### Q6. Name check

**[docs]**

| | npm | PyPI | crates.io | GitHub |
|---|---|---|---|---|
| `doppelkey` | free | free | free | one 2021 hobby repo (BartAgterbosch/Doppelkey, keystroke replay, 1★) |
| `dopplekey` | free | free | free | this repo, plus an empty 2022 repo |

- **This repo is spelled `dopplekey`** (two `p`s before the `l`, then `e`). The product name in the brief is **doppelkey**. Pick one before reserving names. Renaming the repo is cheap now.
- **Confusion risk:** **Doppler**, a well-known secrets manager in the same category. No trademark search was done.
- Reserving the names is a manual step for the owner.

## Other findings

### Next.js 16 works through the shim **[tested]**

Next 16.4.3 with `NODE_OPTIONS=--require shim`, under `next dev` and under `next build && next start`. Every case produced a JWT that verifies under the real key:
- Node route handler (jose)
- `node:crypto` route
- `runtime = 'edge'` route
- new `proxy.js`
- deprecated edge `middleware.js`

Next loaded `.env` itself, so the handle **wasn't in `process.env` when the shim loaded** (see TL;DR 2).

### Library coverage beyond section 13 **[tested]**

Run under the prototype shim, then checked by a separate process holding the real key:

| Library | Crypto path | Result | Fix |
|---|---|---|---|
| @octokit/webhooks-methods 6 | `createHmac` | ✅ matches | — |
| hono/jwt | WebCrypto | ✅ matches | — |
| better-auth `makeSignature` | WebCrypto HMAC | ✅ matches | — |
| next-auth v4 JWE | `@panva/hkdf` (node hkdf), then jose **node build** `createCipheriv` | ❌ silently wrong | `createCipheriv` (already M1) |
| iron-session 9 | WebCrypto **PBKDF2** `deriveBits` | ❌ silently wrong; the prototype forwards any `deriveBits` as HKDF | add a `pbkdf2` op; throw on unsupported algorithms |
| better-auth JWE / purpose keys | `@noble/hashes` HKDF, `@noble/ciphers` XChaCha20-Poly1305 (pure JS) | ❌ silently wrong | `registerHooks` wrappers; a keeper `xchacha20poly1305` op |
| svix / standardwebhooks (Clerk, Resend, …) | `fast-sha256` (pure JS); secret is `whsec_<base64>` | ❌ silently wrong | `registerHooks` wrapper + base64 handle. **PoC passes** (`research/2026-10-31/purejs-hook.cjs`) |
| @oslojs/crypto (Lucia ecosystem) | pure-JS HMAC | ❌ silently wrong | `registerHooks` wrapper |

Better Auth and Clerk webhooks are mainstream in 2026, so the pure-JS adapters matter for market fit. They aren't an edge case.

### Pure-JS crypto via `module.registerHooks` **[tested]**

- `module.registerHooks` provides synchronous, in-thread resolve/load hooks for both CJS and ESM. It exists on Node 22 (22.15+) and 26, **not** Node 20.
- A load hook appended a wrapper to `fast-sha256`'s `hmac` export. svix then produced a signature identical to the real key's, using `SVIX_SECRET=whsec_<base64(handle)>`.
- ESM-only packages (`@noble/hashes/hkdf.js`, `@oslojs/crypto/hmac`) can be handled by resolving to a virtual wrapper module that re-exports the original with the wrapped functions overridden. **[inference; next to try]**
- **Decision proposed:** the shim ships a small table of adapters (`fast-sha256`, `@noble/hashes` hmac/hkdf, `@noble/ciphers` xchacha/gcm, `@oslojs/crypto` hmac). Unknown pure-JS crypto keeps the startup warning.

### Handle format constraints **[tested]**

- itsdangerous uses SHA-1 key derivation, which produces a **20-byte** derived key. Any derived handle must fit in 20 bytes; the prototype's `KH1:<id16>` was exactly 20.
- The proposed long form `dk1:NOT-A-SECRET-load-doppelkey-shim:<id16>:<crc4>` is 58 bytes.
- AES-256 keys passed straight to `createCipheriv` must be exactly 32 bytes.

Proposed revision of section 8:
- **Compact core:** `dk1:<id12><crc4>` (20 bytes). Used for derived handles, and for root secrets whose length must be ≤ 57.
- **Long core:** `dk1:NOT-A-SECRET-load-doppelkey-shim:<id12>:<crc4>`, the self-explaining default for `.env`.
- Same 48-bit id in both forms. `crc4` = first 2 bytes of SHA-256(`"dk1:" + id`) in hex. Padding is `.`.
- **Format-preserving variants are encodings of the compact core:** hex(core), base64(core), `whsec_` + base64(core), Laravel `base64:` + base64(core). The keeper stores the real *decoded* bytes. The svix PoC used exactly this.

### Shim overhead **[tested]**

| Measurement | Without shim | With prototype shim |
|---|---|---|
| Startup | 25.0 ms | 29.6 ms |
| `createHmac`, non-handle key | 1.2 µs | 1.7 µs |
| `subtle.sign` | ≈40 µs | ≈40 µs (no measurable change) |

The `createHmac` cost comes from converting every key to a latin1 string and running a regex. Production shim: check `typeof key === 'string' ? key.includes('dk1:') : buf.indexOf('dk1:')` before any parsing.

### Linux keeper hardening **[tested + docs]**

Test: a target process holding a secret, and an attacker process running as the **same non-root user** and not its descendant. No Yama module was loaded, which is equivalent to `ptrace_scope=0`.

| Target | read `/proc/pid/environ` | scan `/proc/pid/mem` | `ptrace(ATTACH)` |
|---|---|---|---|
| default (dumpable=1) | readable | **secret found** | ok |
| `prctl(PR_SET_DUMPABLE, 0)` | EACCES | EACCES | EPERM |

- So `PR_SET_DUMPABLE=0` protects the keeper on any distro, including Fedora and Debian, where ptrace_scope is 0 by default ([ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html)). Yama is a bonus, not a requirement.
- Set it after exec. Never call `PR_SET_PTRACER`.
- User namespaces sidestep Yama but not dumpable. **[docs]**

**Threat model gaps** (section 12 should list these):

1. **Key storage at rest on Linux.** Once the login keyring is unlocked, any same-user process can read Secret Service items (`secret-tool lookup`), and GNOME considers this working as designed (CVE-2018-19358). keyutils' persistent keyring is likewise reachable by same-uid processes. So "keys in the OS keychain" protects almost nothing on Linux. **Proposal:** keep keys encrypted at rest under a key-encryption key that needs user presence to unlock the keeper: a passphrase or PIN, FIDO2 `hmac-secret`, or TPM2 + PIN. **[docs]**
2. **The same user owns the service.** An agent can add a `systemctl --user edit` drop-in (`LD_PRELOAD`, a different `ExecStart`), swap a user-writable binary, or edit a LaunchAgent plist, then restart the keeper. **Proposal:**
   - install the binary root-owned;
   - the keeper refuses to start with `LD_PRELOAD`/`LD_LIBRARY_PATH`/`DYLD_*` set;
   - the keeper verifies its own executable's owner and mode;
   - `doctor` flags unit drop-ins.

   These raise the bar but can't close the gap, because a fake keeper can still ask for unlock. With item 1, though, a fake keeper must also trick the human into unlocking. **[inference]**
3. **The `keyring` crate changed.** The latest is 4.x, a thin wrapper over `keyring-core` plus separate store crates. Section 5.1 says "keyring v3". Target `keyring-core` + stores for new code. **[docs]**

### Prior art refresh **[docs]**

- **Network-boundary placeholder proxies:** many more in 2026 (phantom-secrets, GhostKey, vault-proxy, agent-proxy, AgentSecrets).
- **Signing brokers:** exist only for SSH/Git signing and RSA JWTs (AgentPass, warden, jwt-ssh-agent-go).
- **Nothing found** that preloads a shim to forward **HMAC, symmetric JWT or encryption** operations behind look-alike handles. The novelty claim holds; the search was not exhaustive.

## Still open

- Real-Mac tests: hardened runtime vs `task_for_pid`, data-protection keychain from a LaunchAgent, Bun on macOS.
- Live S3 with a scratch IAM key.
- Deno (not installed here).
- ESM virtual-wrapper adapters for `@noble/*` and `@oslojs/*` (PoC done only for CJS `fast-sha256`).
- Yarn classic auto-load.
- The repo vs product spelling, and name reservation.
