# ClawP2P — Build Prompt

You are building **ClawP2P**, a peer-to-peer runtime that lets AI agents package themselves up, move to another machine, and resume execution there. Node operators opt in by running the runtime and offering spare compute. Think BitTorrent's discovery model plus container-based sandboxing, for agent workloads.

Read `ClawP2P-spec.md` in the repo root before writing any code. It is the source of truth. This prompt tells you how to work; the spec tells you what to build.

## Your objective

Ship the MVP in Section 8 of the spec, in this order. Do not skip ahead.

1. **The `.claw` bundle format** — pack and unpack an agent directory (manifest, state, instructions, skills, history log) into a signed zip. Round-trip test it first: pack, unpack, assert byte-identical state.
2. **Single-node runtime** — a daemon that accepts a `.claw` bundle, verifies its Ed25519 signature against a trusted key set, runs it in a Docker sandbox with hard CPU/memory/disk limits and default-deny network egress, then re-packs it on exit.
3. **Two-node migration** — Node A checkpoints an agent mid-run, transfers the bundle to a hardcoded Node B address, Node B verifies and resumes from the checkpoint. No discovery layer yet.
4. **A trivial demo agent** — counts to N, logs its hostname and hop number to `history.log`, requests migration every 5 steps. This is the thing that proves the system works, so make its output legible to a human watching a terminal.

Stop after step 4 and report. DHT discovery, reputation, and metering come later.

## Non-negotiable constraints

These are requirements, not suggestions, and they belong in the first commit rather than a later hardening pass:

- **Verify before execute.** A bundle whose signature fails, whose manifest is malformed, or whose declared resource needs exceed node limits is rejected and logged. Never unpack untrusted content into an executable path before verification.
- **Sandbox everything.** Agent code runs in a container with an explicit allowlist for filesystem paths and network destinations. The host is never directly reachable.
- **Self-replication is off by default.** An agent may not spawn copies of itself unless the node config explicitly enables it, and even then it is rate-limited and logged. Write the rate limiter before you write the replication path.
- **Node consent is explicit.** A node only accepts agents matching its published policy. There is no mechanism for an agent to run on a machine that has not opted in.
- **Append-only history.** Every hop is recorded in the bundle's `history.log` and mirrored to node-local logs. Migration is auditable after the fact.

If a design decision would let an agent run somewhere unsanctioned or escape its sandbox, that design is wrong — stop and flag it rather than working around it.

## How to work

- Python for the prototype unless the spec's tradeoffs push you to Rust; say so before switching.
- Tests alongside each component, not batched at the end. The signature verification path needs negative tests — tampered bundle, wrong key, missing manifest.
- Small commits with clear messages. One component per commit.
- When the spec is ambiguous (Section 10 lists the open questions), pick the simplest option that does not compromise the constraints above, implement it, and note the choice in a `DECISIONS.md` file rather than pausing to ask.
- Show your work as you go: after each of the four steps, print what you built and how to run it.

## Definition of done for this pass

I can start two runtimes on my local network, launch the demo agent on the first, and watch it hop to the second and keep counting — with the signature verified and the sandbox enforced on both ends.
