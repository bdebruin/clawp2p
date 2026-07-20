# DESIGN.md — ClawP2P.ai

## The brief in one sentence
Make an unfamiliar idea legible in ninety seconds, for two kinds of people: those who have spare compute, and those who want to build a mobile agent.

## Palette
Six named colors, derived from the material itself — terminal output, transit logs, verified checksums.

| Name | Value | Use |
|---|---|---|
| `--ink` | #0D1117 | Page background (deep navy-black, not flat black) |
| `--fog` | #8B9BAE | Muted text, secondary labels |
| `--paper` | #E8EDF2 | Body text on dark |
| `--signal` | #4A9EFF | Primary accent — links, active states, the "this is live" color |
| `--verify` | #2DD4A0 | Success/verified state — used sparingly, only on the verify step |
| `--mono-bg` | #161B22 | Code block / file tree backgrounds |

**Why this palette and not the clichés:**
- Not near-black/acid-green: `--signal` is a cooler blue (think SSH terminal, not neon rave)
- Not cream/serif/terracotta: this is a dark-mode technical document, not a design studio
- The palette comes from GitHub's dark mode vernacular — which is exactly where the target audience reads code. Familiarity earns attention here.

## Typography

- **Display / headings:** "Space Grotesk" (Google Fonts) — geometric, slightly technical, has character without being aggressive. Works at large sizes. NOT a serif.
- **Body:** System font stack (`-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif`) — fast, readable, honest
- **Code / file trees / manifests:** "JetBrains Mono" (Google Fonts) — the clearest monospace at small sizes, true to the material

**Why this pairing:** Space Grotesk at display sizes gives the page a designed feel without overdesigning. JetBrains Mono for all code content is earned — this site IS about a file format. The pairing says: we know what we're building, and we know how to communicate it.

## Layout

Single scrolling page. Max-width 860px centered. Generous vertical rhythm (sections breathe). No sidebar. No nav tabs — the content has a natural order and the user should read through it.

Section order:
1. Nav (logo + GitHub link)
2. Hero
3. What actually moves (file tree)
4. How a hop works (8-step numbered sequence)
5. For node operators
6. Status

## Signature element — the hop animation

A horizontal two-panel visualization showing Node A → Node B. The agent bundle (represented as a small file icon with a count) plays through the sequence: **checkpoint** (bundle appears, count freezes), **verify** (a checkmark pulses on the receiving node), **resume** (count increments on Node B).

Implemented as a CSS animation with three keyframe phases, triggered on scroll into view. Total duration ~4 seconds, loops.

`prefers-reduced-motion` fallback: static diagram showing the same three states side by side (checkpoint | verify | resume) as labeled columns.

**Why the hop:** Everything else on this page describes; this one shows. The animation encodes the only three facts that matter — state is preserved, verification happens before execution, counting resumes. If you watch it once, you've understood the project.

## What I revised after reading back against the brief

First draft had a section titled "Features" — generic. Removed entirely. The spec says name things by what a person controls, not by how the system is built. "Features" is system language.

First draft had a subtle gradient background — removed. Flat `--ink` background is cleaner and the animation provides all the visual interest needed.
