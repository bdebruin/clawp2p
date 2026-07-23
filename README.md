# ClawP2P

**Napster for AI agents.** Agents that pack themselves up, move to another machine, and pick up where they left off.

> A peer-to-peer network where agents migrate to wherever compute is available — verified, sandboxed, and resuming from checkpoint.

## Website

[clawp2p.ai](https://clawp2p.ai)

## What is this?

ClawP2P lets AI agents travel the network on their own. An agent packages itself into a `.claw` bundle (a signed zip), migrates to another node, gets verified, and resumes execution from its checkpoint — without human intervention.

Think BitTorrent's discovery model plus container sandboxing, for agent workloads.

## The `.claw` bundle

```
agent-name.claw
├── manifest.json     # id, version, resource needs, Ed25519 signature
├── state/            # current memory and working state (markdown + JSON)
│   ├── memory.md
│   └── context.md
├── instructions/     # the agent's goals and behavior
│   └── system.md
├── code/             # executable code the agent carries
└── history.log       # append-only ledger of every hop
```

## Code

| File | What it does |
|---|---|
| `signing.py` | Ed25519 key generation, canonical hashing (`state_hash`, `bundle_hash`), sign/verify |
| `bundle.py` | Pack/unpack `.claw` files, manifest validation, node policy enforcement, quarantine on rejection |
| `test_bundle.py` | Full test suite — round-trip, tamper detection, path traversal, zip bombs, identity continuity |

## Install & run tests

```bash
pip install -r requirements.txt
pytest test_bundle.py -v
```

## Status

- ✅ `.claw` bundle format — pack, unpack, sign, verify
- ✅ Manifest validation and node policy enforcement
- ✅ Quarantine on rejection (evidence preserved, never deleted)
- ✅ Security test suite (tamper, path traversal, symlinks, zip bombs, wrong keys)
- 🔨 Single-node runtime (`node.py`) — next
- 🔨 Docker sandbox (`sandbox.py`) — next
- ○ Two-node migration
- ○ Demo counter agent
- ○ DHT discovery

## Docs

- [`ClawP2P-spec.md`](ClawP2P-spec.md) — full technical specification
- [`clawp2p-build-prompt.md`](clawp2p-build-prompt.md) — MVP build instructions
- [`DESIGN.md`](DESIGN.md) — website design decisions

## License

MIT

## Two-node migration — verified working

```
hop=0  barry-macbook    steps 1–5   → requested migration to DO server
hop=1  do-droplet-157   steps 6–20  → resumed at step 5, counted to 20. exit_code: 0
```

Agent started on a MacBook, counted to 5, packaged itself into a signed `.claw` bundle,
transferred over the internet to a DigitalOcean droplet, verified, resumed at step 5,
counted to 20. Full two-node migration working as of July 23, 2026.

### What's working
- ✅ `.claw` bundle format — pack, unpack, sign, verify (two-signature model)
- ✅ CLI — `python3 -m clawp2p init | pack | agent`
- ✅ Docker sandbox — verify-before-execute, non-root uid 1000, read-only code mount
- ✅ Node API — POST /bundle, GET /status /policy /agents
- ✅ Transport — HTTP delivery with retry
- ✅ Two-node migration — MacBook → DigitalOcean droplet, state preserved across hop

### Next
- DHT discovery (replace hardcoded allowed_peers)
- Reputation and metering
- Multi-hop chains
