## What and why

<!-- What does this change, and why? Link issues. -->

## Checklist

- [ ] Tests use fake secrets only
- [ ] New library support has an oracle-pattern test (verified with the real key in a separate process)
- [ ] Unsupported paths fail closed with an error that names the next command
- [ ] Nothing new leaves the keeper (or the threat model in SECURITY.md is updated)
- [ ] `cargo fmt`, `cargo clippy -D warnings`, shim typecheck and the relevant compat suites pass
