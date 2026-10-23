# Contributing to The Grid

Thank you. Three rules keep the Atlas interoperable:

1. **The spec is the source of truth**, not this code. Anything that changes bytes on the wire or in a signature
   (`alp-grid-core`) is a protocol change: open an issue first, update `test-vectors/v1.json` and `openapi.json`
   in the same pull request (CI checks both).
2. **Never trust a node.** New code that receives data from the network validates signatures and recomputes what
   can be recomputed before storing anything.
3. **Don't rewrite what exists.** libp2p, ed25519-dalek, blake3, redb, reed-solomon-erasure do their job; we write
   the Atlas.

## Contributor License Agreement

By submitting a pull request you agree to the project's CLA: you certify that you wrote the contribution or have
the right to submit it, and you grant the project a perpetual, worldwide, royalty-free licence to use, modify and
relicense it. The grid is AGPL-3.0; the CLA lets the project publish the documentation, SDKs and conformance
tests under Apache-2.0 and protect the trademarks. The CLA bot will ask you to sign on your first PR.

## Development

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -q -p alp-grid-core --bin gen-test-vectors     # after any change to signed objects
cargo run -q -p alp-grid-node --bin grid -- openapi > openapi.json
```
