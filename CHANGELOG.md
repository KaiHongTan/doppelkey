# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
