# doppelkey-proto

Wire protocol v1 and handle format v1, shared by the keeper and the CLI. The specification is [docs/protocol.md](../../docs/protocol.md).

`vectors/handles.json` lists key inputs and what a shim must recognise. The Rust, Node and Python tests all check against it; regenerate it with `node compat/test-keeper/gen-vectors.mjs`.
