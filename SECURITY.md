# Security

doppelkey is security software, so security reports are especially welcome.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through GitHub: [Security → Report a vulnerability](https://github.com/KaiHongTan/doppelkey/security/advisories/new). Include what you found, how to reproduce it, and the impact you expect. We'll acknowledge reports within a few days, keep you informed, and credit you in the fix (unless you prefer otherwise).

Never include real secrets in a report. Use fake keys like those in `compat/fixtures/vault.json`.

## Supported versions

doppelkey is pre-1.0. Security fixes go into the latest release only.

## Threat model

doppelkey protects keys an app computes with (signing, webhook, encryption and AWS secret keys) from **theft by processes running as the same OS user**, in particular AI coding agents and the tools they run.

| An attacker running as you tries to… | Result |
| --- | --- |
| Read `.env`, print the environment, read `/proc/<pid>/environ`, or dump the app's memory | Gets only handles. The app never holds the real key; the tests scan its heap and live memory |
| Paste a key into chat, a commit or a log | Only a handle leaks, and it is useless without your keeper |
| Read the vault file | It is encrypted (XChaCha20-Poly1305); the key-encryption key comes from your passphrase (Argon2id) or the macOS Keychain |
| Read the keeper's memory | Linux: blocked, because the keeper is non-dumpable (`PR_SET_DUMPABLE=0`), even with Yama off. macOS: blocked only for a Developer ID-signed, hardened-runtime build |
| Inject code into the keeper with `LD_PRELOAD` / `DYLD_*` | The keeper refuses to start with those set; the systemd unit unsets them |
| Run `doppelkey eject` or loosen a policy | Needs a human: a terminal confirmation, or a prompt the **keeper** shows using its own environment. The caller's environment can't approve the request (for example by setting `DOPPELKEY_ASKPASS`), and a dialog that times out counts as a refusal |
| Ask the keeper to export a key | No such operation exists; a test checks every response for key bytes |
| Ask the keeper to sign or decrypt while it runs | **Works**, like ssh-agent. Limited by per-key allowed ops, rate limits and optional confirm prompts, and recorded in the audit log with the caller's pid and executable |

### Known limits

See also [docs/design.md](docs/design.md) and [docs/research.md](docs/research.md).


- **Misuse is not prevented.** Anything that can reach the socket can use the keys within policy. Use separate development keys, and turn on `--confirm` for sensitive keys.
- **The keeper's own files.** An agent that can edit your user service definition or replace a user-writable binary can make a fake keeper ask for your passphrase. Install `doppelkeyd` read-only (`install.sh` sets mode 0555; root-owned is better).
- **The keeper's environment.** The keeper takes its prompt program (`DOPPELKEY_ASKPASS`) from its own environment, set when the service was installed. An agent that can restart the keeper with its own environment (for example by editing the user service) could change that. This is the same class of risk as replacing the binary above.
- **`--protect file`** keeps the vault key in a plain file next to the vault. That is convenient for throwaway keys only; a same-user process can read both files.
- **macOS memory protection** relies on code signing. Unsigned or ad-hoc builds can be read with a debugger on a typical development Mac.
- **Pure-JavaScript crypto** packages without an adapter bypass the shim. Their results are wrong rather than leaking the key, and the shim warns about them at startup.
- **Out of scope:** root, physical access, and a human reading their own keychain.

## Design notes for reviewers

- The wire protocol is in `docs/protocol.md`. Every op result is a MAC, a ciphertext/plaintext, a new handle or names, never key material. `jwk_thumbprint` returns an RFC 7638 thumbprint the keeper builds itself (a public identifier).
- Keys in memory: `LockedKey` (zeroized on drop, `mlock`ed) in `crates/doppelkeyd/src/state.rs`.
- Hardening: `crates/doppelkeyd/src/harden.rs`. Socket: 0600 in a 0700 directory, plus a `peer_cred` uid check.
- Shims have zero runtime dependencies, so they can be audited.
