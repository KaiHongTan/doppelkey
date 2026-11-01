# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

Fixes from an independent review:

- The CLI no longer decrypts the vault. Vault creation, key import, policy changes and eject are now keeper operations, and the keeper alone decides whether a human approved. Before this, eject's confirmation was a branch in the CLI, which any program could satisfy by running it under a pseudo-terminal; with the macOS Keychain, that meant no approval at all.
- A human now approves eject and policy loosening with the vault passphrase, which the keeper checks, so it works without a display. On Keychain vaults, the keeper's own dialog approves.
- After approval, the keeper writes the restored values itself, so no key material crosses the socket.
- `DOPPELKEY_ASKPASS` no longer approves eject or policy loosening (except on key-file vaults). Prompt programs run by absolute path, so a fake `osascript` on `PATH` can't answer.
- The macOS Keychain item is now created by `doppelkeyd`, so the CLI isn't on its access list.
- Docs: doppelkey resists exfiltration, not use (stated on the first screen); headless limits, `DOPPELKEY_PASSPHRASE` and unverified macOS memory protection are documented; the prior-art claim is narrowed.

### Added

- `doppelkeyd`, the keeper (Rust):
  - Unix-socket server implementing wire protocol v1: `hmac`, `hash_derive`, `hkdf`, `pbkdf2`, `aes_gcm`, `aes_cbc`, `jwk_thumbprint`, `status`
  - Encrypted vault, unlocked by a passphrase (Argon2id), the macOS Keychain, or a key file
  - Per-key policy: allowed ops, AWS service limits, rate limits, confirm prompts
  - JSON Lines audit log naming the caller's pid and executable
  - Hardening: non-dumpable process, no core dumps, zeroized and `mlock`ed keys, refuses `LD_PRELOAD`, `peer_cred` uid check
- `doppelkey` CLI:
  - Commands: `init` (stack detection, secret classification, format-preserving handles, auto-load writers, agent note, service install), `protect`, `set`, `eject` (byte-for-byte restore), `doctor`, `policy`, `log`, `status`, `list`, `unlock`/`lock`, `run`, `env`, `service`
  - MCP server
- Shims with zero runtime dependencies:
  - **Node and Bun:** `node:crypto`, WebCrypto, hash routing (Auth.js `kid`), pure-JS adapters for `fast-sha256`, `@noble/hashes` and `@oslojs/crypto`
  - **Python:** `hmac`, `hashlib`, `pbkdf2_hmac`, `cryptography` AESGCM
  - **Ruby:** `OpenSSL::HMAC`, PKCS5/KDF, Cipher; covers Rails `secret_key_base`
  - **Java:** JCA provider agent for `Mac`, `Cipher` and PBKDF2
- Agent integrations: Claude Code plugin (skill, SessionStart hook, MCP), an Agent Skills SKILL.md, a Codex guide.
- Oracle-pattern compatibility suites for Node, Python, Ruby and Java, run against both keepers; generated `docs/compatibility.md`.
- Release tooling: per-platform archives with bundled shims, npm launcher and platform packages, PyPI wheel, `install.sh`, Homebrew formula.
