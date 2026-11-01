# Contributing to doppelkey

Thanks for helping. Bug reports, compatibility results for untested libraries, and pull requests are all welcome. Start with [docs/design.md](docs/design.md) for how the pieces fit together.

## Ground rules

These apply to every change:

1. **Never handle real secrets.** Tests use fake secrets only (`compat/fixtures/vault.json`). Never print, log, commit or paste a real key.
2. **Shims stay dependency-free.** `shims/*` load into every process, so they must be small and auditable.
3. **The keeper has no export operation.** No code path may return key bytes to a client. `compat/node/test/keeper-protocol.test.mjs` checks this; keep it passing.
4. **Fail closed, and say what to do.** Every error names the next command (`Run "doppelkey doctor".`). Unsupported algorithms with a handle must throw, never compute with the handle text.
5. **Correctness is checked against the real key.** New library support needs an oracle-pattern test: the app runs with handles, and a separate process holding the real key verifies the output.
6. **Don't "fix" handles.** `dk1:…`, `646b313a…` and `ZGsxO…` values are handles, not broken secrets.

## Development setup

```bash
cargo build && cargo test                       # keeper + CLI (Rust stable)
(cd shims/node && npm ci && npm run build)      # Node shim (TypeScript → dist/register.cjs)
sh shims/java/build.sh                          # Java agent (optional, JDK 17+)
(cd compat/node && npm ci && npm test)          # compatibility suite (Node test keeper)
```

Run the suite against the Rust keeper with `DOPPELKEY_KEEPER_CMD="$PWD/target/debug/doppelkeyd insecure-test-keeper"`. Python and Ruby suites live in `compat/python` and `compat/ruby` (see the README). Memory-protection tests are skipped as root; CI runs them as a normal user.

Before opening a pull request:

- `cargo fmt --all && cargo clippy --all-targets -- -D warnings`
- `npm run typecheck` in `shims/node`
- the relevant compatibility suites
- `node compat/report.mjs` if you changed what's supported (it regenerates `docs/compatibility.md`)

## Adding support for a library

1. Write an app in `compat/<lang>/` that uses the library exactly as its docs say, with keys from the environment.
2. In the test, verify each output in the test process with the real key from the fixture vault.
3. If the library computes crypto in a way the shim doesn't see (pure-JS crypto, an unusual API), add an adapter in the shim, and make sure unsupported paths throw.

## Protocol changes

Changes to `docs/protocol.md` must land in the Rust keeper (`crates/doppelkeyd/src/ops.rs`), the Node test keeper (`compat/test-keeper/keeper.mjs`) and every shim, with vectors in `crates/proto/vectors/` where relevant.

## Commit and PR style

Keep pull requests small and focused, and explain *why* in the description. Call out any change to the threat model or to what leaves the keeper.

By contributing you agree that your contributions are licensed under the Apache License 2.0, and you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
