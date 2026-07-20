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
├── skills/           # tools and code the agent carries
└── history.log       # append-only ledger of every hop
```

## Status

Early prototype. MVP in progress. No running network yet.

See [`ClawP2P-spec.md`](ClawP2P-spec.md) for the full technical spec.

## Docs

- [`ClawP2P-spec.md`](ClawP2P-spec.md) — full technical specification
- [`clawp2p-build-prompt.md`](clawp2p-build-prompt.md) — MVP build instructions
- [`DESIGN.md`](DESIGN.md) — website design decisions

## License

MIT
