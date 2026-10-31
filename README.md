# doppelkey

**An ssh-agent for app secrets.** Keep your app's signing and encryption keys out of its memory, and out of reach of the AI coding agents and tools that run as you.

[![ci](https://github.com/KaiHongTan/dopplekey/actions/workflows/ci.yml/badge.svg)](https://github.com/KaiHongTan/dopplekey/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

```bash
# .env before: any tool running as you can read this, and so can your coding agent
JWT_SECRET=3f9c1e7a5b2d8c4e6f1a9b3d7e5c2a8f…
# .env after: safe to read, log or commit, and useless off this machine
JWT_SECRET=dk1:NOT-A-SECRET-load-doppelkey-shim:a1b2c3d4e5f6:d3ae
```

Your app keeps working: `npm run dev`, `pytest` and `rails s` run unchanged, and signatures and ciphertexts are identical to what the real key produces.

> **Status: alpha (v0.1).** Everything below works and is tested (see [compatibility](docs/compatibility.md)), but doppelkey has not had an independent security review. Start with development keys.

## Why

Coding agents run your dev server and tests, so they can read every key your app holds: by opening `.env`, printing `process.env`, or reading `/proc/<pid>/environ`. Tools that keep *API keys* away from agents swap them in at the network edge. That can't work for keys your code **computes with**, like JWT and session signing secrets, webhook secrets, encryption keys and AWS secret keys: the app needs the real bytes to produce a correct signature.

doppelkey works like ssh-agent. Each such secret in `.env` becomes a **handle**. A small preloaded **shim** spots handles in crypto calls and forwards the operation to the **keeper** (`doppelkeyd`), a separate process that holds the real key, checks a per-key policy, writes an audit log, and returns only the result. There is no operation that exports a key.

```
 your app (and anything that can read it)              doppelkeyd (separate user service)
 ┌──────────────────────────────────────┐              ┌──────────────────────────────────┐
 │ .env: JWT_SECRET=dk1:… (a handle)     │   handle +   │ real keys, from an encrypted vault │
 │ app + shim ── createHmac(handle, …) ──┼──── data ───▶│ policy, rate limits, confirm      │
 │ (jsonwebtoken, Stripe, Django… as is) │◀── result ───┤ audit log; non-dumpable memory    │
 └──────────────────────────────────────┘              └──────────────────────────────────┘
```

## Quick start

```bash
# 1. Install (macOS, Linux)
curl -fsSL https://raw.githubusercontent.com/KaiHongTan/dopplekey/main/install.sh | sh
#    or run it through npm: npx doppelkey <command>

# 2. In your project: preview, then protect. Asks for a vault passphrase the first time.
cd my-app
doppelkey init

# 3. Run things as usual
npm run dev          # or pytest, python manage.py runserver, bin/rails s, …

# Anytime
doppelkey doctor     # check everything; prints the fix for each problem
doppelkey log        # what used which key, and when
doppelkey eject      # put the real values back (asks you to confirm)
```

`doppelkey init` finds `.env` files and protects signing, webhook, encryption and AWS secret keys. It leaves API keys and database URLs alone; pair doppelkey with a placeholder proxy for those ([comparison](docs/comparison.md)). It writes the auto-load lines your tools need (`.npmrc`, `pnpm-workspace.yaml`, `.env.yarn`, `bunfig.toml`, a venv `.pth`, Rails `config/boot.rb`, `.claude/settings.json`) and a note in `AGENTS.md`, then installs the keeper as a systemd or launchd user service. Everything it changes is listed first, and `eject` restores your files byte for byte.

## What works

| Runtime | How the shim loads | Covered |
| --- | --- | --- |
| **Node** 22, 24, 26 | `--require` via `.npmrc` / `NODE_OPTIONS` | `node:crypto` (HMAC incl. streams, AES-GCM/CBC ciphers, HKDF, PBKDF2, KeyObject, hashes), WebCrypto, pure-JS `@noble/hashes`, `fast-sha256`, `@oslojs/crypto` |
| **Bun** 1.4 | `bunfig.toml` preload | as Node |
| **Python** 3.10–3.13 | `doppelkey.pth` in the venv | `hmac`, `hashlib` (key derivation), `pbkdf2_hmac`, `cryptography` AESGCM |
| **Ruby** 3.2+ | `config/boot.rb` / `RUBYOPT` | `OpenSSL::HMAC`, PKCS5/KDF, `OpenSSL::Cipher` |
| **Java** 17+ | `-javaagent` (`JAVA_TOOL_OPTIONS`) | JCA `Mac`, `Cipher` (AES-GCM/CBC), PBKDF2 |

Verified against the real key, library by library: jsonwebtoken, jose, Auth.js (`@auth/core`) and NextAuth v4, iron-session, express-session (cookie-signature), hono/jwt, Stripe and svix (Clerk, Resend) webhooks, @octokit/webhooks, AWS SDK v3 and boto3 (SigV4, with per-service policy), PyJWT, itsdangerous, Django, Flask, Rails `secret_key_base` (MessageVerifier, MessageEncryptor), the `jwt` gem, and JCA HMAC/AES. The full table is in [docs/compatibility.md](docs/compatibility.md). Next.js 16 (`next dev`, `next start`, edge routes and middleware) was also checked by hand.

Unsupported algorithms used with a handle are **refused**, not computed with the handle text. Every error names the next command to run.

## Security model

doppelkey stops **theft** of keys by anything running as you: reading `.env`, the environment, the app's memory, the vault file, or the keeper's memory. It does not stop **misuse** while the keeper runs: like ssh-agent, a process that can reach the keeper can ask it to sign. Per-key allowed operations, rate limits, confirm prompts and the audit log (which names the calling program) limit and expose that.

- **Keeper memory.** On Linux the keeper is non-dumpable, so other processes of the same user can't read its memory or environment, even where Yama is off. On macOS that protection needs a signed, hardened-runtime build. Keys are zeroized and `mlock`ed.
- **Keys at rest.** Keys sit in an encrypted vault (XChaCha20-Poly1305). Its key comes from your passphrase (Argon2id), the macOS Keychain, or a plain file for throwaway dev boxes. doppelkey doesn't use the Linux Secret Service, because any same-user process can read it.
- **Human gates.** `eject` and loosening a policy need a human: a terminal or a GUI prompt.
- **Out of scope.** Root, a human at the keyboard, and an agent that can rewrite the keeper's service file or binary. Install the binary read-only.

Details: [SECURITY.md](SECURITY.md), [comparison and threat table](docs/comparison.md), [research notes](docs/research.md).

## Commands

| Command | Does |
| --- | --- |
| `doppelkey init [--yes] [--protect passphrase\|keychain\|file]` | Preview, then protect the project's secrets and set up auto-loading |
| `doppelkey protect NAME` | Protect one more secret already in `.env` |
| `doppelkey set NAME` | Type a secret's value (teammate onboarding); it never touches disk |
| `doppelkey eject [--keep-keys]` | Restore real values and remove everything `init` added |
| `doppelkey doctor` | Check keeper, vault, handles, auto-load, pure-JS packages |
| `doppelkey policy [NAME] [--allow/--deny OP] [--rate N] [--confirm]` | Show or change per-key policy (TOML) |
| `doppelkey log [-n N] [--json]` | Show the audit log |
| `doppelkey status` / `list` | Keeper and vault status / this project's secrets |
| `doppelkey unlock` / `lock` | Unlock a passphrase vault / wipe keys from memory |
| `doppelkey run -- CMD` | Run one command with every shim loaded |
| `doppelkey env` | Print `export` lines that load the shims (for shells and agent hooks) |
| `doppelkey service install\|uninstall` | Manage the keeper user service |
| `doppelkey mcp` | MCP server for coding agents (status, doctor, secret names) |

## Coding agents

- **Claude Code:** `claude plugin marketplace add KaiHongTan/dopplekey && claude plugin install doppelkey@doppelkey`. The plugin adds a skill that proposes `doppelkey init` when it sees secrets in `.env`, a session hook that loads the shims and explains handles, and the MCP server.
- **Codex, Cursor, Gemini CLI, Copilot:** the same skill in the open [Agent Skills](integrations/skills/doppelkey/SKILL.md) format, plus `doppelkey mcp`.
- **Every repo:** `init` writes a note to `AGENTS.md`. Values starting with `dk1:` are handles; never replace them; ask the user to run `doppelkey set NAME`.

See [integrations/](integrations/README.md). For a scripted 60-second tour: `sh docs/demo.sh`.

## Build and test

```bash
cargo build                                   # doppelkey + doppelkeyd (Rust 1.80+)
(cd shims/node && npm ci && npm run build)    # Node shim
sh shims/java/build.sh                        # Java agent (JDK 17+)

cd compat/node && npm ci && npm test          # oracle-pattern suite against the Node test keeper
DOPPELKEY_KEEPER_CMD="$PWD/../../target/debug/doppelkeyd insecure-test-keeper" npm test
cd ../python && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt && .venv/bin/python -m unittest test_compat
cd ../ruby && gem install --install-dir .gems activesupport jwt && ruby test_compat.rb
node compat/report.mjs                        # regenerate docs/compatibility.md
```

Every compatibility test follows the **oracle pattern**. The app runs with handles and the shim, a separate process holding the real keys verifies each output, and the app's heap or live memory is scanned for the real and derived keys.

| Path | What |
| --- | --- |
| `crates/doppelkeyd` | Keeper daemon and CLI (Rust) |
| `crates/proto` | Wire protocol and handle format; shared test vectors |
| `shims/{node,python,ruby,java}` | Language shims (no runtime dependencies) |
| `compat/` | Oracle-pattern test suites, test keeper, fake fixtures |
| `integrations/` | Claude Code plugin, Agent Skills SKILL.md, Codex guide |
| `docs/` | Protocol, comparison, compatibility, research notes, demo |
| `DOPPELKEY.md` | Design brief, decisions and milestones |
| `prototype/` | The original proof of concept |

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
