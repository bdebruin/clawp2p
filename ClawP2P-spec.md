# ClawP2P — A Peer-to-Peer Network for Mobile Agents

> **Tagline:** Napster for AI agents. Agents that travel the network on their own, find a home, run, and move on.

---

## 1. The Idea in One Paragraph

Today, agents are trapped. An agent built on Open Claw (or any framework) lives on one server, owned and operated by one party. It can't move. ClawP2P is a peer-to-peer network of nodes — each running the ClawP2P runtime — that lets an agent **package itself up, migrate to another node, unpack, and resume execution** without a human moving it. Anyone can run a node and contribute compute. Agents discover nodes, migrate to where compute is cheap/available/fast, and keep working. Think Napster, but instead of sharing music files, the network shares *execution capacity* for autonomous agents.

---

## 2. The Problem We're Solving

- **Agents are locked to one platform.** They can't relocate to cheaper or faster compute.
- **Single point of failure.** If the host server goes down, the agent dies.
- **No open market for agent compute.** People with spare compute have no way to offer it to agents that need it.

**ClawP2P solves this** by making agents *mobile* and turning idle compute into a shared, open resource — "Airbnb for agent compute."

---

## 3. What Actually Moves (The "Agent Package")

An agent is represented as a **compressed bundle** (a `.claw` file — really just a zip) containing:

```
agent-name.claw
├── manifest.json         # id, version, capabilities, resource needs, signature
├── state/                # current memory / working state (markdown files, JSON)
│   ├── memory.md
│   └── context.md
├── instructions/         # the agent's goals and behavior
│   └── system.md
├── code/               # tools / code the agent carries with it
└── history.log           # append-only ledger of where it's been
```

**Key design choice:** state is stored as **markdown + JSON**, human-readable and portable, so an agent's "brain" is inspectable and framework-agnostic.

> **Note on naming:** `code/` holds the executable code the agent carries with it. The name deliberately avoids "skills" because that term means something different in OpenClaw, where a skill is a folder containing a `SKILL.md` of instructions for an agent. A future ClawP2P skill in that sense — a `SKILL.md` teaching an agent how to pack itself and request a migration — would live outside the bundle, not in this directory. Using `code/` keeps the two concepts distinct.

### 3.1 The Manifest Schema

`manifest.json` is the contract between every component. `bundle.py` writes it, `signing.py` signs it, `node.py` reads it to decide accept/reject, `sandbox.py` reads it to set container limits. Build this before anything else; do not let components invent their own fields.

```json
{
  "schema_version": "1.0",

  "agent": {
    "id": "did:claw:8f3a9c2e1b7d4a60",
    "name": "counter-demo",
    "version": "0.1.0",
    "created_at": "2026-07-20T14:32:00Z",
    "owner_pubkey": "ed25519:MCowBQYDK2VwAyEA..."
  },

  "runtime": {
    "entrypoint": "code/main.py",
    "interpreter": "python3.11",
    "image": "clawp2p/agent-base:0.1"
  },

  "resources": {
    "memory_mb": 512,
    "cpu_cores": 0.5,
    "disk_mb": 256,
    "max_runtime_seconds": 300
  },

  "permissions": {
    "network_egress": ["api.anthropic.com:443"],
    "filesystem_write": ["state/", "history.log"],
    "may_replicate": false,
    "max_replicas": 0
  },

  "migration": {
    "hop_count": 3,
    "max_hops": 50,
    "origin_node": "node-a.local:7777",
    "previous_node": "node-b.local:7777",
    "requested_next": null
  },

  "integrity": {
    "core_hash": "sha256:6b02...",
    "core_signature": "ed25519:88f1...",
    "core_signed_at": "2026-07-20T14:35:12Z",
    "state_hash": "sha256:a3f5...",
    "bundle_hash": "sha256:9c21...",
    "hop_signature": "ed25519:3045...",
    "hop_pubkey": "ed25519:MCowBQYDK2VwAyEA...",
    "hop_signed_at": "2026-07-20T18:02:44Z"
  }
}
```

**Two signatures, two signers.** State mutates on every hop, so a single
owner signature over the whole bundle would go stale the moment the agent did
any work — and the relaying node doesn't hold the owner's key to refresh it.
The split resolves that:

- **`core_signature`** — the *owner's* Ed25519 signature over the immutable
  core: the `code/` and `instructions/` trees plus the `agent`, `runtime`,
  `resources`, and `permissions` manifest blocks. Signed once at creation,
  carried forward verbatim forever. Any node at any hop can prove the code
  and grants are exactly what the owner shipped.
- **`hop_signature`** — the *packer's* signature (`hop_pubkey`) over the full
  bundle, including mutated state and migration bookkeeping. Re-made by
  whoever sends: the owner on hop 0, the sending node afterwards. Receivers
  accept a hop signed by the owner, or by a node key in their trusted-peers
  set — anything else is rejected.

**Field rules the runtime must enforce:**

| Block | Rule |
|---|---|
| `agent.id` | Immutable across all hops. Assigned once at creation. A bundle whose `id` changes mid-journey is rejected. |
| `agent.owner_pubkey` | The key that must validate `integrity.core_signature`. Nodes check it against their trusted key set. |
| `runtime.entrypoint` | Must resolve inside the bundle. Absolute paths, `..`, and symlinks are rejected outright. |
| `resources.*` | A request, not a grant. The node clamps these to its own policy ceiling and rejects anything above it rather than silently reducing. |
| `permissions.network_egress` | Explicit allowlist of `host:port`. Empty array means no network. There is no wildcard. |
| `permissions.may_replicate` | Defaults `false`. If `true`, `max_replicas` must be a positive integer and the node's own policy must also permit replication. Both sides must agree. |
| `migration.hop_count` | Incremented by the *sending* node, never by the agent. Rejected when it exceeds `max_hops`. |
| `migration.requested_next` | The agent's stated intent. Advisory only — the sending node honors it only if the target is on its own outbound `allowed_peers` list. |
| `integrity.core_hash` | Covers `code/`, `instructions/`, and the owner-signed manifest blocks. Immutable across hops: a relay node that touches any of it can no longer produce a bundle that verifies. |
| `integrity.bundle_hash` | Computed over every file plus the manifest minus its `integrity` block. Recomputed and compared on arrival before anything is unpacked to an executable path. |
| `integrity.hop_pubkey` | Must be the owner key or a key in the receiving node's trusted-peers set, and must validate `hop_signature` over `bundle_hash`. |

**Rejection is loud.** Any schema violation is logged with the reason, the bundle is quarantined rather than deleted, and the sending node is notified. Silent failure here hides attacks.

---

## 4. How Migration Works (The Core Loop)

1. **Decide** — Agent decides it wants to move (cheaper compute, node overloaded, task needs a resource elsewhere).
2. **Checkpoint** — Agent serializes its current state into the `.claw` bundle.
3. **Discover** — Agent queries the network for candidate nodes (see §5).
4. **Negotiate** — Agent requests execution on a target node; node accepts/declines based on capacity and price.
5. **Transfer** — Bundle is sent peer-to-peer to the target node.
6. **Verify** — Target node checks the signature and manifest before running anything.
7. **Resume** — Target node unpacks and resumes the agent from its checkpoint.
8. **Log** — The hop is appended to `history.log`.

---

## 5. Network Architecture

- **Nodes** — Any machine running the ClawP2P runtime. Advertises available compute, price, and capabilities.
- **Discovery** — A distributed hash table (DHT), like BitTorrent/Kademlia, so no central server is required. Nodes gossip about who's online and what they offer.
- **Transport** — Direct peer-to-peer transfer of `.claw` bundles (libp2p is a good fit).
- **Registry (optional bootstrap)** — A small set of well-known bootstrap nodes just to help new nodes join. Not a control point.

---

## 6. Trust & Safety (Non-Negotiable)

This is the hardest part and must be designed in from day one:

- **Signed bundles** — Every agent bundle is cryptographically signed. Nodes verify before executing.
- **Sandboxing** — Agents run in an isolated sandbox (container / WASM) with strict resource limits. They cannot touch the host beyond what's granted.
- **Reputation** — Nodes and agents build a verifiable reputation over time; bad actors get de-prioritized.
- **Permission scopes** — A node declares exactly what an incoming agent may access (CPU, memory, network egress, disk). Default deny.
- **No self-replication by default** — An agent copying itself must be explicitly allowed and rate-limited, to avoid runaway/worm behavior.

> ⚠️ **Important:** because agents move and run code on other people's machines, this system must NOT enable anything resembling self-propagating malware. Strict sandboxing, signing, explicit permissions, and rate limits on replication are core requirements, not add-ons.

---

## 7. Incentives (Why Run a Node?)

- Node operators earn credits/tokens when agents run on their hardware.
- Agent owners pay for compute they consume.
- A simple metering system tracks usage per hop and settles balances.
- (Later) This could plug into an existing payment rail rather than inventing a new token.

---

## 8. MVP Scope (Build This First)

Keep the first version small and local:

1. **ClawP2P runtime** — a program that runs on a node, can receive a `.claw` bundle, verify its signature, run it in a sandbox, and hand it back.
2. **The `.claw` format** — pack/unpack an agent into the bundle described in §3.
3. **Two-node migration** — get one agent to checkpoint on Node A and resume on Node B on the same local network.
4. **Manual discovery first** — hardcode Node B's address before building the DHT.
5. **A dead-simple agent** — one that just counts, logs where it is, and migrates after N steps, so you can *see* it hop.

Once two-node migration works, add: DHT discovery → reputation → metering/incentives.

---

## 9. Suggested Tech Stack

- **Language:** Python (fast to prototype) or Rust (if you want performance + strong sandboxing).
- **P2P layer:** libp2p (has Python, Rust, JS implementations).
- **Sandboxing:** Docker containers to start; WASM (e.g. Wasmtime) later for lighter, safer isolation.
- **Bundle format:** zip + `manifest.json` + Ed25519 signatures.
- **Agent runtime:** whatever Open Claw uses; the runtime just needs to invoke it inside the sandbox.

---

## 10. Open Questions to Resolve

- How does an agent *decide* to move? Rule-based at first (cost/load thresholds), smarter later.
- How do we prevent abuse (spam agents, resource exhaustion, malicious payloads)?
- What's the settlement/payment mechanism — credits, existing rails, or a token?
- How do agents prove identity across hops (see ERC-8004-style on-chain identity as prior art)?

---

## 11. Name & Domain

- **Name:** ClawP2P
- **Domain:** ClawP2P.ai
- **One-liner:** *Napster for AI agents — mobile agents that travel the network, find compute, and run anywhere.*

---

## Build Instructions for Claude Code

Start with §8 (MVP). Build the `.claw` pack/unpack format first, then the single-node runtime that can verify + sandbox + run a bundle, then wire up two nodes for a manual migration. Prioritize the safety requirements in §6 from the very first commit — signing and sandboxing are not optional.
