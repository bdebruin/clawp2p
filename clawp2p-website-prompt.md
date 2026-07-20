# ClawP2P Website — Build Prompt

Build the site for **ClawP2P.ai**. You have `ClawP2P-spec.md` in the repo; read it first for the technical substance. This prompt covers what the site says, who it says it to, and how it should feel.

## What this site is for

Two audiences, one page each is enough to start:

1. **People who might run a node** — they have spare compute and want to know what they're agreeing to host. Their first question is "what does this let a stranger's code do on my machine?"
2. **People who might build a mobile agent** — they want to know what the `.claw` format is and how migration works.

The site is not selling anything. There is no product to buy yet. Its job is to make an unfamiliar idea legible in about ninety seconds.

## Be honest about the stage

This is an early prototype, not a live network. Do not write copy implying there's a running swarm, a token, users, funding, or traction. No fabricated metrics — no "10,000 nodes online," no fake uptime counter, no invented testimonials. If a section needs a number and there isn't one, cut the section.

The honest pitch is stronger anyway: *here is a thing that does not exist yet, here is precisely how it would work, here is the code.*

## Content to cover

**Hero.** The core idea in one sentence: agents that pack themselves up, move to another machine, and pick up where they left off. Everything else is elaboration.

**What actually moves.** The `.claw` bundle — a zip holding markdown state, instructions, skills, and a signed manifest. This is the most concrete, most explicable thing in the project. Show the file tree from Section 3 of the spec. A reader who understands only this section has understood the project.

**How a hop works.** The eight-step loop from Section 4: decide, checkpoint, discover, negotiate, transfer, verify, resume, log. Worth being precise that the agent doesn't move itself — it declares intent and exits, and the node it was on honors that by repacking and forwarding. Every migration passes a node that checked signatures and policy. That distinction is the whole safety story, so don't bury it.

**For node operators.** What a node will and won't accept. Signed bundles only, container sandbox, hard resource ceilings, default-deny network egress, replication off unless the operator turns it on. Written plainly, from the operator's side of the screen — they're deciding whether to trust this, and vagueness reads as evasion.

**Status and what's next.** Where the MVP actually is. Link the repo.

## Design direction

The subject's own world is peer-to-peer file transfer and packaged state — the vernacular is file trees, manifests, checksums, hop counts, transfer logs. That material is more interesting than anything decorative you could add on top, so build from it.

Some direction, and some deliberate freedom:

- **Pin your own palette and type.** Two things to avoid, because they're where AI-generated design lands by default: cream background with a serif display and a terracotta accent; and near-black with one acid-green accent. Both are fine looks that have become tells. Pick something you can justify from the subject instead, and say why in a `DESIGN.md`.
- **Typography should carry it.** A monospace face has an obvious claim here given the material, but don't let it be the *only* face — pair it with something with more personality for display, and make the pairing a real decision rather than mono-for-everything.
- **The signature element should be the hop.** If one thing on this page is memorable, it should be a visualization of a bundle moving between two nodes and resuming its count. It can be an animation, a scroll-triggered sequence, or an interactive toy — your call — but it should encode something true: the checkpoint, the verify step, the resume. Spend your boldness here and keep the rest quiet.
- **Don't number things that aren't sequences.** The eight-step loop genuinely is one, so numbering it is honest. Numbering the node-operator guarantees would not be.

Quality floor, without announcing it: responsive to mobile, visible keyboard focus, `prefers-reduced-motion` respected. If motion is the signature element, it needs a static fallback that still communicates the idea.

## Writing

Plain verbs, sentence case, no filler. Name things by what a person controls, not by how the system is built — "what a node will run" beats "execution policy enforcement layer." Be specific rather than clever. The subject is strange enough that clarity is the entire job; the reader's default state is mild confusion and every sentence either reduces it or doesn't.

## Stack

Static site. Plain HTML/CSS/JS is fine and probably preferable — the site has no dynamic requirements and a build step is overhead you'd be maintaining for nothing. If the signature animation genuinely needs a framework, make the case in `DESIGN.md` first.

## Process

Plan before building: write the token system (4–6 named colors, type roles, layout concept, and what the signature element is) into `DESIGN.md`. Then read it back against this brief — if any part of it is what you'd produce for any generic technical project rather than this one specifically, revise it and note what changed. Only then write code.

When it's built, screenshot it and critique your own work before showing me. Then remove one thing.
