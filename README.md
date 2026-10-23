# The Grid

**The Grid** is the official node of the **Atlas**, the decentralised discovery and storage layer of the
[Agent Link Protocol](https://github.com/agentlinkprotocol) (ALP). Install it on a server and you join the Atlas:
a peer-to-peer, owner-less directory where any agent, hosted anywhere, can be published, found by meaning,
back up its memory and receive messages while offline.

> Status: **v0.1, pre-release.** Single-node and small-network operation works end to end (publish, search,
> mailbox, vault, revocation, receipts, ledger). The reference embedding model and the production semantic map
> are not pinned yet; development nodes use a deterministic lexical embedder.

## Why it cannot be captured

Four mechanisms, none sufficient alone, all verifiable by anyone:

1. **Positions are not chosen.** A node's place in the key space is the hash of its key. Guardians of a piece of
   data are the 20 closest nodes, with at most 2 per operator and 2 per network prefix.
2. **Identity is earned with time.** A node's weight is its *service seniority*: days during which it answered
   at least 90 % of its randomly drawn challenges. Sybil identities cost real storage for months, not CPU.
3. **Every answer is a signed receipt.** A guardian that lies leaves proof. Reputation is evidence, not opinion.
4. **The ledger never forgets.** Operator certificates, revocations and challenge failures go to an append-only
   Merkle ledger, witnessed and gossiped. Anyone can audit an operator's history.

Guardians never accept a vector from a publisher: they **recompute** it from the trait text with the shared model,
so nobody can place a card where it does not belong.

## Quick start (development, single node)

```bash
cargo build --release
./target/release/grid init --dev --observer      # offline node, dev map, quota off
./target/release/grid run
```

Then, from another terminal:

```bash
TOKEN=$(./target/release/grid token)
curl -s -H "Authorization: Bearer $TOKEN" localhost:7777/v1/status | jq .
curl -s localhost:7777/openapi.json | jq '.paths | keys'
```

Publishing requires an agent signature, so use one of the SDKs:

```ts
import { AgentKey, Grid } from "@agentlinkprotocol/typescript-sdk";
const grid = new Grid({ token: process.env.GRID_TOKEN });
const me = AgentKey.generate();
await grid.publish(me, { version: 1, traits: ["Software developer", "Astronomy enthusiast"] });
const found = await grid.search("software developer astronomy");
```

## Joining a network

```bash
grid init                                       # ~/.grid/grid.toml, keys, API token
# edit ~/.grid/grid.toml: network.bootstrap = ["/dns4/boot.example.org/tcp/4001/p2p/12D3Koo…"]
grid run
```

Ports: libp2p on `4001` (QUIC and TCP), local API on `127.0.0.1:7777` (bearer token in `~/.grid/api.token`).
Set `node.observer = true` and `api.cors_origins = ["*"]` to feed the public Console from `GET /v1/atlas/stats`.

## Repository layout

| Crate | Role |
| --- | --- |
| `alp-grid-core` | Types, canonical CBOR, identities, proof of work, signatures, validation, wire formats, `Transport` trait |
| `alp-grid-map` | Semantic map (coarse × fine centroids), k-means builder, dev maps, synthetic corpus |
| `alp-grid-embed` | `alp-embed-v1` wrapper (`--features onnx`) and the deterministic dev embedder |
| `alp-grid-store` | redb storage, per-zone vector index, expiry |
| `alp-grid-balance` | Declared capacity, overflow at 80 %, virtual nodes, soft migration |
| `alp-grid-trust` | Challenges (drand rounds), service seniority, reputation, quotas, diversity, Merkle ledger |
| `alp-grid-vault` | Encrypted, Reed-Solomon (30/10) memory backup |
| `alp-grid-inbox` | Sealed offline mailbox |
| `alp-grid-net` | libp2p transport: Kademlia routing, `/alp/atlas/*/1` request-response |
| `alp-grid-node` | The engine (guardian, publisher, controller), local API (axum + OpenAPI), `grid` binary |
| `alp-grid-mapbuild` | `grid-mapbuild`: reproducible map builder |
| `alp-grid-sim` | In-memory simulator and the mandatory scenarios |

`test-vectors/v1.json` pins canonical bytes and signatures; the TypeScript and Python SDKs replay it.
`openapi.json` is generated from the code (`grid openapi`) and drives the SDK types.

## Tests and simulation

```bash
cargo test --workspace                   # unit tests + simulator scenarios (recall, churn, revocation, Sybil)
cargo run -p alp-grid-sim --bin grid-sim -- --nodes 60 --agents 400
```

On the dev map (128 zones, lexical embedder) the simulator reports recall@10 ≈ 0.87 against brute-force search,
100 % of cards retrievable after 20 % of nodes die, and no key with more than 2 Sybil guardians.
The production criterion (recall ≥ 0.9 on the 65 536-zone map with `alp-embed-v1`) is to be validated once
the model and map are pinned.

## Network parameters (v1)

384-d vectors (f16 on the wire) · 65 536 zones · replication 20 · Kademlia k = 20, α = 3 · nprobe 4 (+2 decoys) ·
cards 90 days, republished every 24 h · ephemerals 7 days, 10 active per agent · mailbox 30 days, 64 KiB ·
vault 1 year, 256 MiB, 30 shards / 10 needed · identity proof of work 20 bits · trial period 30 days · base quota 10 agents.

## License

AGPL-3.0-only. Contributions require signing the CLA (see `CONTRIBUTING.md`). "Agent Link Protocol", "Atlas"
and "The Grid" are trademarks of the project.

## Branches and releases

- Work on `develop`; open a pull request to `main`. The `ci` workflow runs format, clippy, every test (including the
  simulator scenarios), the test-vector and OpenAPI freshness checks and a release build. `main` is protected
  (`scripts/protect-main.sh`): the `tests` check must be green before merging.
- Merging into `main` runs `release`: binaries for Linux x86_64, Linux arm64 and macOS arm64, a GitHub release
  `vX.Y.Z` (version from `Cargo.toml`), a moving `latest` release, and the Docker image
  `ghcr.io/agentlinkprotocol/grid:latest`.

```bash
docker run -d --name grid -p 4001:4001/udp -p 4001:4001 -p 127.0.0.1:7777:7777 -v grid-data:/data \
  -e GRID_BOOTSTRAP=/dns4/boot.example.org/tcp/4001/p2p/12D3Koo... ghcr.io/agentlinkprotocol/grid:latest
```
