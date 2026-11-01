# Background research

Findings, from October 2026, that explain several design choices. "Tested" means run on Linux, as root and as a separate non-root user. "Docs" means taken from the cited documentation.

## Same-user memory protection

**Linux (tested).** A process running as the same non-root user tried to read another process's memory. The target was not its descendant, and Yama was off (equivalent to `ptrace_scope=0`):

| Target | read `/proc/pid/environ` | scan `/proc/pid/mem` | `ptrace(ATTACH)` |
| --- | --- | --- | --- |
| default (dumpable) | readable | secret found | allowed |
| after `prctl(PR_SET_DUMPABLE, 0)` | EACCES | EACCES | EPERM |

So `PR_SET_DUMPABLE=0` protects the keeper on every distribution, including Fedora and Debian, where `ptrace_scope` defaults to 0. Yama is a bonus, not a requirement ([ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html)). Root and `CAP_SYS_PTRACE` bypass it. The compat suite checks this on every CI run.

**macOS (docs).**
- A binary signed with a Developer ID, using the hardened runtime and lacking the `com.apple.security.get-task-allow` entitlement, can't have its task port taken while SIP is on, so debuggers can't read its memory ([Apple](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger)).
- Unsigned or ad-hoc builds are likely readable with `lldb -p` on a typical developer Mac, because Xcode runs `DevToolsSecurity -enable`.
- `PT_DENY_ATTACH` blocks ptrace attach but not `task_for_pid`, so it is only an extra layer.
- Not yet verified on a real Mac.

## Keys at rest

- **Linux Secret Service:** once the login keyring is unlocked, any process running as the same user can read its items (`secret-tool lookup`). GNOME considers this intended behaviour ([CVE-2018-19358](https://wiki.archlinux.org/title/GNOME/Keyring)). The kernel's persistent keyring is likewise reachable by same-uid processes.
- **doppelkey's choice:** it keeps keys in its own encrypted vault, unlocked by a passphrase (Argon2id), and doesn't use the Secret Service.
- **macOS Keychain:** an item's access rules bind to the code signature of the program that created it, and any other program triggers a prompt. That makes the Keychain useful there, provided builds are signed.
- **The `keyring` Rust crate:** version 4 split into `keyring-core` plus separate store crates. doppelkeyd uses it only for the macOS Keychain.

## Loading the shim without changing commands (tested)

| Runner | Works | How |
| --- | --- | --- |
| npm 10 | yes | `node-options` in `.npmrc` |
| pnpm 10 and 11 | yes | `.npmrc`, or `nodeOptions` in `pnpm-workspace.yaml` |
| Yarn 1 | no | ignores `node-options` |
| Yarn 4 | yes | ignores `.npmrc`; `NODE_OPTIONS` in `.env.yarn` works, with both PnP and node-modules |
| Bun 1.4 | yes | `bunfig.toml` `preload`. `bun test` needs `[test] preload`; scripts that call `node` need `NODE_OPTIONS`; Bun itself ignores `NODE_OPTIONS` ([oven-sh/bun#40316](https://github.com/oven-sh/bun/issues/40316)) |
| Python | yes | a `.pth` file in site-packages. It loads even under `python -I`; only `-S` skips it |
| Next.js 16 | yes | `NODE_OPTIONS` reaches Node routes, edge routes and middleware in `next dev` and `next start` |

npm and pnpm **replace** an inherited `NODE_OPTIONS` with the `.npmrc` value; `doppelkey doctor` warns about this. Next.js loads `.env` after preload, which is why the Node shim always installs its patches.

## Libraries that bypass naive patching (tested)

Patching only `createHmac` and WebCrypto left several popular libraries giving **silently wrong** results:

| Library | Why | Fix in doppelkey |
| --- | --- | --- |
| svix (Clerk, Resend webhooks) | pure-JS `fast-sha256`; secret is `whsec_<base64>` | load-time adapter; `whsec_` + base64 handle form |
| `@oslojs/crypto`, `@noble/hashes` | pure-JS HMAC and HKDF | load-time adapters (`module.registerHooks` on Node ≥ 22.15, runtime plugin on Bun) |
| iron-session | WebCrypto PBKDF2 | `pbkdf2` keeper op |
| next-auth v4 | jose's Node build uses `createCipheriv` and discards `final()` output | cipher support that returns output from `update()` |
| Auth.js (`@auth/core`) | the token `kid` is a JWK thumbprint of the derived key | `jwk_thumbprint` keeper op |
| itsdangerous | derives 20-byte SHA-1 keys | 20-byte compact handle form |

Not yet covered: Better Auth's encryption (`@noble/ciphers` XChaCha20-Poly1305).

## Prior art (docs)

- **Network-boundary placeholder tools** are now common: Veil, agent-vault, Phantom, GhostKey, Infisical Agent Proxy and others.
- **Signing brokers** exist only for SSH or Git signing and RSA JWTs.
- **No tool found** forwards HMAC, symmetric JWT or encryption operations from unmodified apps to a separate process. The search was not exhaustive.

## Storage backends (docs)

- **Vault / OpenBao Transit:** perform HMAC and encryption server-side with non-exportable keys. A future backend could keep keys out of the keeper entirely, at the cost of a network round trip per operation. Vault is BSL-licensed; OpenBao is MPL-2.0.
- **1Password and Infisical:** offer SDKs and machine identities, so either could serve as a fetch-and-hold key source.
- **dotenvx:** keeps its decryption key in a file next to the data, so it is suitable only as an import source.
