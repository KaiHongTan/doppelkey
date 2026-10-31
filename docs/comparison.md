# doppelkey compared

doppelkey protects keys your app **computes with**: JWT and session signing secrets, webhook signing secrets, encryption keys, AWS secret keys. Most "secrets for AI agents" tools protect keys that **travel over the network**. The two kinds of tool complement each other.

## The gap

An API key only matters when it reaches the remote server, so a proxy can hold the real key and swap it in at the network edge. A signing or encryption key never leaves your process: the app needs the real bytes to produce a correct signature or ciphertext. Once the dev server or test runner has the key in memory, anything running as you can read it, coding agents included. They can read `.env`, print `process.env`, or read `/proc/<pid>/environ`.

doppelkey swaps each such secret for a **handle**. A preloaded shim sends crypto calls made with a handle to a separate **keeper** process, which holds the real key and returns only the result. App code doesn't change.

## Side by side

| Approach | Examples | Protects | Real key in your app's memory? | App changes |
| --- | --- | --- | --- | --- |
| **doppelkey** | | signing, webhook, encryption, AWS SigV4 keys used in-process | **No**: only handles | None (preloaded shim) |
| Placeholder proxy | Veil, agent-vault, Phantom, Infisical Agent Proxy, Deno Sandbox | API keys in outbound HTTP | No, but only for outbound requests; in-process keys aren't covered | Proxy settings |
| Runtime injection | `infisical run`, 1Password Environments, dotenvx | secrets on disk | **Yes**: injected into the environment | None |
| "Blind" vault | Blindkey, blind-vault, Keyblind | values in the agent transcript | **Yes**: the child process holds them | None |
| KMS / Vault Transit | HashiCorp Vault, OpenBao, cloud KMS | encryption, HMAC, signing | No | **Yes**: call an API instead of `crypto` |
| ssh-agent / gpg-agent | | SSH and GPG keys | No | None, but SSH/GPG only |
| OS sandbox | Anthropic `srt` | files and network | Partly: can block reading `.env`, but the app still loads the value | Sandbox config |

Use doppelkey **with** a placeholder proxy: the proxy covers outbound API keys (OpenAI, Stripe `sk_…`, database passwords), and doppelkey covers the keys your code signs and encrypts with. `doppelkey init` skips network credentials and says so.

## What doppelkey does not do

- **Misuse while the keeper runs.** Anything that can reach the keeper can ask it to sign or decrypt, as with ssh-agent. Mitigations: per-key allowed operations, rate limits, confirm prompts, an audit log naming the calling program, and separate development keys.
- **Root, or a human at the keyboard.** Out of scope.
- **Languages without a shim.** Node and Python today (see [compatibility](compatibility.md)). Rails `secret_key_base` and Laravel `APP_KEY` are left alone by `init`.
- **Pure-JavaScript crypto without an adapter.** `crypto-js` and similar never call `node:crypto`. The shim warns about them at startup; `@noble/hashes`, `fast-sha256` (svix) and `@oslojs/crypto` have adapters on Node ≥ 22.15.

## Same-user threat model in one table

| A same-user agent tries to… | Without doppelkey | With doppelkey |
| --- | --- | --- |
| read `.env` or print `process.env.JWT_SECRET` | real key | a handle, useless off this machine |
| read `/proc/<pid>/environ` or dump app memory | real key | no key (tests scan the heap and live memory) |
| paste the key into chat, a commit or a log | leaked for good | a handle leaks; nothing to rotate |
| read the keeper's memory | n/a | blocked: the keeper is non-dumpable (Linux); signed with hardened runtime (macOS) |
| read the vault file | n/a | encrypted; the passphrase is needed (Argon2id) |
| run `doppelkey eject` or loosen a policy | n/a | needs a human to confirm |
| ask the keeper to export a key | n/a | no such operation |
| ask the keeper to sign while it runs | n/a | works, within policy, and logged |
| edit the user service or binary, then wait for a restart | n/a | possible if the files are user-writable: install the binary read-only (see [SECURITY.md](../SECURITY.md)) |
