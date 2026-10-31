# doppelkey

**An ssh-agent for app secrets.** AI coding agents run your dev server and tests as you, so they can read every key your app holds in memory. doppelkey replaces each signing or encryption secret in `.env` with a look-alike **handle**. A preloaded shim forwards crypto calls made with a handle to a separate keeper process, which holds the real key and returns only the result. App code doesn't change.

```bash
# .env before
JWT_SECRET=3f9c1e7a5b2d8c4e6f1a9b3d7e5c2a8f...
# .env after: safe to read, log or commit; useless off this machine
JWT_SECRET=dk1:NOT-A-SECRET-load-doppelkey-shim:a1b2c3d4e5f6:d3ae
```

> **Status: pre-alpha, Milestone 1 of 4.** The Node shim works against a Node *test* keeper. The production keeper (`doppelkeyd`, Rust), the `doppelkey` CLI and the Python shim are not built yet. Do not use with real secrets.

## What works today

The Node shim (`shims/node`) runs these unchanged. A separate process holding the real keys verifies every output (the oracle pattern), and the app's V8 heap and `/proc/self/environ` hold none of the real keys:

- **JWTs:** jsonwebtoken (HS256/HS512), jose, hono/jwt
- **Cookies and webhooks:** cookie-signature (express-session), Stripe webhooks (sync and async), @octokit/webhooks, svix (Clerk, Resend, …)
- **AWS SDK v3:** S3 signed and presigned requests; DynamoDB refused by per-key policy
- **Session encryption:** next-auth v4 sessions, iron-session
- **Pure-JS primitives:** `@noble/hashes` HMAC and HKDF, `@oslojs/crypto`
- **node:crypto:** `createHmac` (including streaming), `createCipheriv` / `createDecipheriv` (AES-GCM, AES-CBC), `hkdf`, `pbkdf2`, `createSecretKey` / `KeyObject`
- **WebCrypto:** HMAC, AES-GCM/CBC, HKDF and PBKDF2 (`deriveBits` and `deriveKey`)

Tested on Node 22, 24 and 26 and on Bun 1.4. Unsupported algorithms used with a handle **refuse** rather than silently computing with the handle text. Every error names the next command to run.

## Layout

| Path | What |
| --- | --- |
| `DOPPELKEY.md` | Design and build brief: decisions, threat model, milestones |
| `docs/protocol.md` | Wire protocol v1 and handle format v1 |
| `docs/research.md` | Answers to the brief's open questions; pre-build findings |
| `shims/node` | The Node shim (`doppelkey/register`), TypeScript, zero runtime dependencies |
| `compat/test-keeper` | Node test keeper speaking protocol v1 (stand-in for `doppelkeyd`) |
| `compat/node` | Oracle-pattern compatibility suite |
| `compat/fixtures` | Fake secrets for tests |
| `crates/proto/vectors` | Shared handle test vectors |
| `prototype/` | The original proof of concept (Appendix A of the brief) |
| `research/` | Scripts behind `docs/research.md` |

## Run the tests

```bash
cd shims/node && npm ci && npm run build
cd ../../compat/node && npm ci && npm test
node bench.mjs                                                # shim overhead with no handles
DOPPELKEY_TEST_RUNTIME="$(which bun)" npm test                # apps under Bun
```

## Try the shim by hand

```bash
node compat/test-keeper/keeper.mjs --vault compat/fixtures/vault.json --socket /tmp/dk.sock &
DOPPELKEY_SOCK=/tmp/dk.sock JWT_SECRET='dk1:NOT-A-SECRET-load-doppelkey-shim:a1b2c3d4e5f6:d3ae' \
  node --require ./shims/node/dist/register.cjs -e \
  "console.log(require('crypto').createHmac('sha256', process.env.JWT_SECRET).update('hello').digest('hex'))"
```

## Limits

doppelkey stops key **theft**, not **misuse** while the keeper runs: anything that can reach the keeper can ask it to sign, just as with ssh-agent. Requests are subject to per-key policy and are audit-logged. See the threat model in `DOPPELKEY.md` section 12 and the gaps found in `docs/research.md`.
