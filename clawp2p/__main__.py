"""
python3 -m clawp2p — bootstrap and pack CLI for ClawP2P nodes.

Subcommands:
  init   Create CLAWP2P_DATA_DIR, generate the node keypair, write starter
         config files. Idempotent — safe to re-run.
  pack   Pack an agent directory into a signed .claw bundle.
  agent  Scaffold a new demo agent directory ready to pack.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _data_dir() -> Path:
    """Respect CLAWP2P_DATA_DIR; default to ~/.clawp2p so no root is needed."""
    return Path(os.environ.get("CLAWP2P_DATA_DIR", Path.home() / ".clawp2p"))


# --------------------------------------------------------------------------
# init
# --------------------------------------------------------------------------

def cmd_init(args) -> None:
    import sys
    # Import from parent directory (where the node lives)
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from signing import generate_keypair, save_private_key, load_private_key

    data_dir = _data_dir()
    keys_dir = data_dir / "keys"
    key_path = keys_dir / "node.pem"

    print(f"ClawP2P node init")
    print(f"Data directory: {data_dir}")
    print()

    # Create directories
    for d in (data_dir, keys_dir, data_dir / "agents", data_dir / "quarantine"):
        d.mkdir(parents=True, exist_ok=True)
    print(f"  ✓ directories created")

    # Keypair — never overwrite silently
    if key_path.is_file():
        kp = load_private_key(key_path)
        print(f"  ✓ keypair already exists (not overwritten)")
    else:
        kp = generate_keypair()
        save_private_key(kp, key_path)
        print(f"  ✓ node keypair generated → {key_path}")

    print()
    print(f"  Node public key:")
    print(f"  {kp.public_id}")
    print()

    # trusted_keys.txt — owner keys whose agents this node will run
    tk_path = data_dir / "trusted_keys.txt"
    if not tk_path.is_file():
        tk_path.write_text(
            "# Owner public keys — one ed25519:<hex> per line.\n"
            "# This node will only run agents signed by keys listed here.\n"
            "# Blank lines and lines starting with # are ignored.\n"
            "#\n"
            "# To trust your own agents, add your owner key here.\n"
            "# Your owner key is the key you pass to `python3 -m clawp2p pack`.\n"
        )
        print(f"  ✓ {tk_path} created (empty — add owner keys to accept agents)")
    else:
        print(f"  ✓ {tk_path} already exists (not overwritten)")

    # trusted_peers.txt — node keys whose hop repacks this node accepts
    tp_path = data_dir / "trusted_peers.txt"
    if not tp_path.is_file():
        tp_path.write_text(
            "# Peer node public keys — one ed25519:<hex> per line.\n"
            "# This node will only accept forwarded bundles (hop > 0) from\n"
            "# nodes listed here. Leave empty to only accept bundles directly\n"
            "# from owners (no relay).\n"
        )
        print(f"  ✓ {tp_path} created (empty — relay from other nodes disabled)")
    else:
        print(f"  ✓ {tp_path} already exists (not overwritten)")

    # node_config.json
    cfg_path = data_dir / "node_config.json"
    if not cfg_path.is_file():
        cfg = {
            "policy": {
                "max_memory_mb": 1024,
                "max_cpu_cores": 1.0,
                "max_disk_mb": 512,
                "max_runtime_seconds": 300,
                "allow_replication": False,
                "allowed_egress": [],
                "max_hops": 50
            },
            "allowed_peers": []
        }
        cfg_path.write_text(json.dumps(cfg, indent=2))
        print(f"  ✓ {cfg_path} created (outbound migration disabled — add peers to enable)")
    else:
        print(f"  ✓ {cfg_path} already exists (not overwritten)")

    print()
    print("Next steps:")
    print(f"  1. To run your own agents, add your owner public key to:")
    print(f"     {tk_path}")
    print(f"  2. Start the node:")
    print(f"     CLAWP2P_DATA_DIR={data_dir} python3 node.py")
    print(f"  3. Check it's running:")
    print(f"     curl http://localhost:7777/status")
    print()
    print("To scaffold and run a demo agent:")
    print("  python3 -m clawp2p agent --name counter-demo --out ./my-agent")
    print("  python3 -m clawp2p pack --agent ./my-agent --key <your-owner-key.pem> --out counter.claw")
    print("  curl -X POST http://localhost:7777/bundle --data-binary @counter.claw -H 'Content-Type: application/octet-stream'")


# --------------------------------------------------------------------------
# pack
# --------------------------------------------------------------------------

def cmd_pack(args) -> None:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from bundle import pack
    from signing import load_private_key

    agent_dir = Path(args.agent)
    key_path = Path(args.key)
    out_path = Path(args.out)

    if not agent_dir.is_dir():
        print(f"Error: agent directory not found: {agent_dir}", file=sys.stderr)
        sys.exit(1)
    if not key_path.is_file():
        print(f"Error: key file not found: {key_path}", file=sys.stderr)
        sys.exit(1)

    kp = load_private_key(key_path)
    result = pack(agent_dir, out_path, kp)
    size = result.stat().st_size
    print(f"Packed: {result} ({size:,} bytes)")
    print(f"Signer: {kp.public_id}")


# --------------------------------------------------------------------------
# agent scaffold
# --------------------------------------------------------------------------

def cmd_agent(args) -> None:
    out = Path(args.out)
    name = args.name

    if out.exists():
        print(f"Error: {out} already exists — pick a different --out path", file=sys.stderr)
        sys.exit(1)

    (out / "state").mkdir(parents=True)
    (out / "instructions").mkdir()
    (out / "code").mkdir()

    (out / "state" / "memory.md").write_text(
        "# Memory\n\nhop_count: 0\nstep: 0\n"
    )
    (out / "state" / "context.md").write_text(
        f"# Context\n\nAgent: {name}\nCreated by: clawp2p init\n"
    )
    (out / "instructions" / "system.md").write_text(
        f"# {name}\n\nCount to 20. Log your hop number and node id. Migrate every 5 steps.\n"
    )
    (out / "history.log").write_text("")

    # The demo agent entrypoint
    (out / "code" / "main.py").write_text(
        _DEMO_AGENT_CODE.format(name=name)
    )

    # Manifest placeholder — owner_pubkey must be filled in by pack
    # We write a minimal placeholder so the directory is valid-looking
    (out / "manifest.json").write_text(json.dumps({
        "schema_version": "1.0",
        "agent": {
            "id": f"did:claw:{_short_id()}",
            "name": name,
            "version": "0.1.0",
            "created_at": _now(),
            "owner_pubkey": "REPLACE_WITH_YOUR_PUBLIC_KEY"
        },
        "runtime": {
            "entrypoint": "code/main.py",
            "interpreter": "python3.11",
            "image": "clawp2p/agent-base:0.1"
        },
        "resources": {
            "memory_mb": 128,
            "cpu_cores": 0.25,
            "disk_mb": 64,
            "max_runtime_seconds": 60
        },
        "permissions": {
            "network_egress": [],
            "filesystem_write": ["state/", "history.log"],
            "may_replicate": False,
            "max_replicas": 0
        },
        "migration": {
            "hop_count": 0,
            "max_hops": 50,
            "origin_node": None,
            "previous_node": None,
            "requested_next": None
        },
        "integrity": {}
    }, indent=2))

    print(f"Agent scaffolded: {out}/")
    print()
    print("Before packing, edit manifest.json and set agent.owner_pubkey to your")
    print("owner public key (the key you will sign with). Then:")
    print()
    print(f"  python3 -m clawp2p pack --agent {out} --key <your-key.pem> --out {name}.claw")


def _short_id() -> str:
    import uuid
    return uuid.uuid4().hex[:16]

def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


_DEMO_AGENT_CODE = '''\
"""
{name} — demo counter agent for ClawP2P.

Counts to 20, logging its hop number and node id on each step.
Writes incremented state to state/memory.md.
Requests migration every 5 steps by writing host:port to state/migrate_to.txt.

The migration target is read from the environment variable CLAWP2P_MIGRATE_TO.
If not set, the agent just runs to completion on this node.
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
    m = re.search(r"step: (\\d+)", text)
    return int(m.group(1)) if m else 0

def write_step(step: int) -> None:
    text = STATE.read_text()
    text = re.sub(r"step: \\d+", f"step: {{step}}", text)
    text = re.sub(r"hop_count: \\d+", f"hop_count: {{HOP}}", text)
    STATE.write_text(text)

def log(msg: str) -> None:
    print(msg, flush=True)
    with HISTORY.open("a") as f:
        f.write(msg + "\\n")

step = read_step()
log(f"[hop={HOP} node={NODE_ID}] resuming at step {{step}}")

while step < 20:
    step += 1
    write_step(step)
    log(f"[hop={HOP} node={NODE_ID}] step={{step}}")

    if step % 5 == 0 and step < 20 and MIGRATE_TO:
        log(f"[hop={HOP} node={NODE_ID}] requesting migration to {{MIGRATE_TO}}")
        Path("/agent/state/migrate_to.txt").write_text(MIGRATE_TO)
        break

log(f"[hop={HOP} node={NODE_ID}] done at step={{step}}")
'''


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="python3 -m clawp2p",
        description="ClawP2P node bootstrap and bundle CLI",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # init
    sub.add_parser("init", help="Set up CLAWP2P_DATA_DIR, generate keypair, write config files")

    # pack
    p_pack = sub.add_parser("pack", help="Pack an agent directory into a signed .claw bundle")
    p_pack.add_argument("--agent", required=True, help="Path to the agent directory")
    p_pack.add_argument("--key", required=True, help="Path to your owner .pem key file")
    p_pack.add_argument("--out", required=True, help="Output path for the .claw file")

    # agent scaffold
    p_agent = sub.add_parser("agent", help="Scaffold a new demo agent directory")
    p_agent.add_argument("--name", default="counter-demo", help="Agent name")
    p_agent.add_argument("--out", required=True, help="Output directory path")

    args = parser.parse_args()
    {"init": cmd_init, "pack": cmd_pack, "agent": cmd_agent}[args.cmd](args)


if __name__ == "__main__":
    main()
