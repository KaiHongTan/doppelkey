# doppelkey compared

doppelkey protects keys your app **computes with**: JWT and session secrets, webhook signing secrets, encryption keys, AWS secret keys. Most "secrets for AI agents" tools protect keys that **travel over the network**. The two kinds of tool complement each other.

## The gap

An API key only matters when it reaches the remote server, so a proxy can hold the real key and swap it in at the network edge.

A signing or encryption key never leaves your process: the app needs the real bytes to produce a correct signature or ciphertext. Once the dev server or test runner holds the key, anything running as you can read it, coding agents included.

doppelkey swaps each such secret for a **handle**. A preloaded shim sends crypto calls made with a handle to a separate **keeper** process, which holds the real key and returns only the result.

## Side by side

| Approach | Examples | Protects | Real key in app memory? | App changes |
| --- | --- | --- | --- | --- |
| **doppelkey** | | signing, webhook, encryption and AWS keys used in-process | **No**, only handles | None |
| Placeholder proxy | Veil, agent-vault, Phantom, Infisical Agent Proxy | API keys in outbound HTTP | Not for outbound keys; in-process keys aren't covered | Proxy settings |
| Runtime injection | `infisical run`, 1Password Environments, dotenvx | secrets on disk | **Yes**, injected into the environment | None |
| "Blind" vault | Blindkey, blind-vault, Keyblind | values in the agent transcript | **Yes**, the child process holds them | None |
| KMS API | Vault Transit, OpenBao, cloud KMS | encryption, HMAC, signing | No | **Yes**, call an API instead of `crypto` |
| ssh-agent, gpg-agent | | SSH and GPG keys | No | None, but SSH and GPG only |
| OS sandbox | Anthropic `srt` | files and network | Partly: can block reading `.env`, but the app still loads the value | Sandbox config |

Use doppelkey **together with** a placeholder proxy. The proxy covers outbound API keys (OpenAI, Stripe `sk_…`, database passwords); doppelkey covers the keys your code signs and encrypts with. `doppelkey init` skips network credentials and says why.

## What a same-user agent can do

| The agent tries to… | Without doppelkey | With doppelkey |
| --- | --- | --- |
| read `.env` or print `process.env.JWT_SECRET` | real key | a handle, useless off this machine |
| read `/proc/<pid>/environ` or dump the app's memory | real key | no key |
| paste the key into chat, a commit or a log | leaked for good | a handle leaks; nothing to rotate |
| read the keeper's memory | n/a | blocked (non-dumpable on Linux; signed hardened runtime on macOS) |
| read the vault file | n/a | encrypted; needs your passphrase |
| run `doppelkey eject` or loosen a policy | n/a | needs your vault passphrase (or the keeper's dialog with the macOS Keychain); a pseudo-terminal doesn't count |
| ask the keeper to export a key | n/a | no such operation |
| ask the keeper to sign while it runs | n/a | works within policy, and is logged |
| replace the keeper's binary or service file | n/a | possible if they're user-writable; install read-only |

## What doppelkey doesn't do

- **Prevent misuse while the keeper runs.** As with ssh-agent, a process that can reach the keeper can ask it to sign. Per-key allowed operations, rate limits, confirm prompts and the audit log limit and expose this. Separate development keys help too.
- **Cover every language.** Node, Bun, Python, Ruby and Java have shims. PHP, Go and .NET don't yet (see [compatibility](compatibility.md)).
- **See pure-JavaScript crypto without an adapter.** Packages like `crypto-js` never call `node:crypto`. The shim warns about them at startup. `@noble/hashes`, `fast-sha256` (svix) and `@oslojs/crypto` have adapters.
- **Protect against root** or a person at the keyboard.
