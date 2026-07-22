"""
counter-demo — demo counter agent for ClawP2P.

Counts to 20, logging its hop number and node id on each step.
Writes incremented state to state/memory.md.
Requests migration every 5 steps by writing host:port to state/migrate_to.txt.

The migration target is read from the environment variable CLAWP2P_MIGRATE_TO.
If not set, the agent runs to completion on this node.
"""

import os
import re
from pathlib import Path

STATE = Path("/agent/state/memory.md")
HISTORY = Path("/agent/history.log")

NODE_ID = os.environ.get("CLAWP2P_NODE_ID", "unknown-node")
HOP = int(os.environ.get("CLAWP2P_HOP", "0"))
MIGRATE_TO = os.environ.get("CLAWP2P_MIGRATE_TO", "")


def read_step() -> int:
    text = STATE.read_text()
    m = re.search(r"step: (\d+)", text)
    return int(m.group(1)) if m else 0


def write_step(step: int) -> None:
    text = STATE.read_text()
    text = re.sub(r"step: \d+", f"step: {step}", text)
    text = re.sub(r"hop_count: \d+", f"hop_count: {HOP}", text)
    STATE.write_text(text)


def log(msg: str) -> None:
    print(msg, flush=True)
    with HISTORY.open("a") as f:
        f.write(msg + "\n")


step = read_step()
log(f"[hop={HOP} node={NODE_ID}] resuming at step {step}")

while step < 20:
    step += 1
    write_step(step)
    log(f"[hop={HOP} node={NODE_ID}] step={step}")

    if step % 5 == 0 and step < 20 and MIGRATE_TO:
        log(f"[hop={HOP} node={NODE_ID}] requesting migration to {MIGRATE_TO}")
        Path("/agent/state/migrate_to.txt").write_text(MIGRATE_TO)
        break

log(f"[hop={HOP} node={NODE_ID}] done at step={step}")
