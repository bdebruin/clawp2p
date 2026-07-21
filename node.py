"""
node.py — The ClawP2P node daemon.

Receives .claw bundles, verifies them via bundle.unpack(), runs them in
sandbox.py, and repacks them on exit. Exposes an HTTP API so other nodes
and agents can interact with this machine.

Verification order (must not change):
  1. bundle.unpack() — signature, hash, manifest schema, node policy
  2. sandbox.run()   — execution inside Docker
  3. bundle.pack()   — repack with updated state and incremented hop_count

Nothing in this file bypasses or re-implements that sequence. If you find
yourself checking signatures or computing hashes here, move it to bundle.py.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, jsonify, request

import bundle as B
import sandbox as S
from bundle import BundleError, NodePolicy, QuarantinedBundle, pack, record_hop, append_history
from sandbox import RunResult, SandboxError, run as sandbox_run
from signing import TrustedKeys, generate_keypair, save_private_key, load_private_key, MANIFEST_NAME

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# Node configuration
# --------------------------------------------------------------------------

DATA_DIR = Path(os.environ.get("CLAWP2P_DATA_DIR", "/var/lib/clawp2p"))
KEYS_DIR = DATA_DIR / "keys"
AGENTS_DIR = DATA_DIR / "agents"
QUARANTINE_DIR = DATA_DIR / "quarantine"
TRUSTED_KEYS_FILE = DATA_DIR / "trusted_keys.txt"      # owner keys: whose agents we run
TRUSTED_PEERS_FILE = DATA_DIR / "trusted_peers.txt"    # node keys: whose repacks we accept
NODE_CONFIG_FILE = DATA_DIR / "node_config.json"

NODE_PORT = int(os.environ.get("CLAWP2P_PORT", "7777"))
NODE_ID = os.environ.get("CLAWP2P_NODE_ID", f"node-{uuid.uuid4().hex[:8]}")
NODE_HOST = os.environ.get("CLAWP2P_HOST", "0.0.0.0")

_started_at = datetime.now(timezone.utc)


def _load_or_create_policy() -> NodePolicy:
    if NODE_CONFIG_FILE.is_file():
        cfg = json.loads(NODE_CONFIG_FILE.read_text())
        policy_cfg = cfg.get("policy", {})
        return NodePolicy(
            max_memory_mb=policy_cfg.get("max_memory_mb", 1024),
            max_cpu_cores=policy_cfg.get("max_cpu_cores", 1.0),
            max_disk_mb=policy_cfg.get("max_disk_mb", 512),
            max_runtime_seconds=policy_cfg.get("max_runtime_seconds", 600),
            allow_replication=policy_cfg.get("allow_replication", False),
            allowed_egress=set(policy_cfg.get("allowed_egress", [])),
            max_hops=policy_cfg.get("max_hops", B.DEFAULT_MAX_HOPS),
        )
    return NodePolicy()


def _load_or_create_trusted_keys() -> TrustedKeys:
    if TRUSTED_KEYS_FILE.is_file():
        return TrustedKeys.from_file(TRUSTED_KEYS_FILE)
    logger.warning("no trusted_keys.txt found at %s — node will reject all bundles", TRUSTED_KEYS_FILE)
    return TrustedKeys()


def _load_trusted_peers() -> TrustedKeys:
    """Node keys whose hop signatures we accept. Empty is a valid stance:
    the node then only accepts bundles packed by their owners directly."""
    if TRUSTED_PEERS_FILE.is_file():
        return TrustedKeys.from_file(TRUSTED_PEERS_FILE)
    return TrustedKeys()


def _load_allowed_peers() -> set[str]:
    """host:port addresses this node will SEND bundles to.

    The migration target comes out of agent-controlled state, so it is
    untrusted input; an empty set (the default) means outbound migration is
    off entirely. This is the gate that stops a hostile agent from directing
    its bundle — and its own state — at an arbitrary internal address.
    """
    if NODE_CONFIG_FILE.is_file():
        cfg = json.loads(NODE_CONFIG_FILE.read_text())
        return set(cfg.get("allowed_peers", []))
    return set()


def _load_or_create_keypair():
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    key_path = KEYS_DIR / "node.pem"
    if key_path.is_file():
        return load_private_key(key_path)
    kp = generate_keypair()
    save_private_key(kp, key_path)
    logger.info("generated new node keypair — public id: %s", kp.public_id)
    return kp


# --------------------------------------------------------------------------
# In-memory run registry
# --------------------------------------------------------------------------

@dataclass
class AgentRun:
    run_id: str
    agent_id: str
    agent_name: str
    hop: int
    started_at: str
    status: str  # running | completed | failed | migrating
    result: RunResult | None = None
    error: str | None = None
    migrated_to: str | None = None


_runs: dict[str, AgentRun] = {}
_runs_lock = threading.Lock()


def _register_run(agent_id: str, agent_name: str, hop: int) -> AgentRun:
    run = AgentRun(
        run_id=uuid.uuid4().hex,
        agent_id=agent_id,
        agent_name=agent_name,
        hop=hop,
        started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        status="running",
    )
    with _runs_lock:
        _runs[run.run_id] = run
    return run


def _update_run(run_id: str, **kwargs) -> None:
    with _runs_lock:
        if run_id in _runs:
            for k, v in kwargs.items():
                setattr(_runs[run_id], k, v)


# --------------------------------------------------------------------------
# Flask app
# --------------------------------------------------------------------------

app = Flask(__name__)

# Lazy-initialized globals (set in main() so tests can override)
_policy: NodePolicy | None = None
_trusted_keys: TrustedKeys | None = None
_trusted_peers: TrustedKeys | None = None
_allowed_peers: set[str] | None = None
_node_keypair = None


def _get_policy() -> NodePolicy:
    global _policy
    if _policy is None:
        _policy = _load_or_create_policy()
    return _policy


def _get_trusted_keys() -> TrustedKeys:
    global _trusted_keys
    if _trusted_keys is None:
        _trusted_keys = _load_or_create_trusted_keys()
    return _trusted_keys


def _get_trusted_peers() -> TrustedKeys:
    global _trusted_peers
    if _trusted_peers is None:
        _trusted_peers = _load_trusted_peers()
    return _trusted_peers


def _get_allowed_peers() -> set[str]:
    global _allowed_peers
    if _allowed_peers is None:
        _allowed_peers = _load_allowed_peers()
    return _allowed_peers


def _get_keypair():
    global _node_keypair
    if _node_keypair is None:
        _node_keypair = _load_or_create_keypair()
    return _node_keypair


# --------------------------------------------------------------------------
# API: introspection
# --------------------------------------------------------------------------

@app.get("/status")
def status():
    """What this node looks like from outside."""
    policy = _get_policy()
    uptime_s = (datetime.now(timezone.utc) - _started_at).total_seconds()
    with _runs_lock:
        running = sum(1 for r in _runs.values() if r.status == "running")

    return jsonify({
        "node_id": NODE_ID,
        "version": "0.1.0",
        "uptime_seconds": int(uptime_s),
        "agents_running": running,
        "capacity": {
            "max_memory_mb": policy.max_memory_mb,
            "max_cpu_cores": policy.max_cpu_cores,
            "max_disk_mb": policy.max_disk_mb,
            "max_runtime_seconds": policy.max_runtime_seconds,
        },
        "public_key": _get_keypair().public_id,
    })


@app.get("/policy")
def policy():
    """The full node policy. Agents use this to decide whether to hop here."""
    p = _get_policy()
    return jsonify({
        "max_memory_mb": p.max_memory_mb,
        "max_cpu_cores": p.max_cpu_cores,
        "max_disk_mb": p.max_disk_mb,
        "max_runtime_seconds": p.max_runtime_seconds,
        "allow_replication": p.allow_replication,
        "allowed_egress": sorted(p.allowed_egress),
        "max_hops": p.max_hops,
    })


@app.get("/agents")
def agents():
    """All agents this node has run or is currently running, most recent first."""
    with _runs_lock:
        runs = list(_runs.values())
    runs.sort(key=lambda r: r.started_at, reverse=True)

    def _serialize(r: AgentRun) -> dict:
        d = {
            "run_id": r.run_id,
            "agent_id": r.agent_id,
            "agent_name": r.agent_name,
            "hop": r.hop,
            "started_at": r.started_at,
            "status": r.status,
            "migrated_to": r.migrated_to,
        }
        if r.result:
            d["exit_code"] = r.result.exit_code
            d["runtime_seconds"] = r.result.runtime_seconds
        if r.error:
            d["error"] = r.error
        return d

    return jsonify({"agents": [_serialize(r) for r in runs]})


@app.get("/agents/<run_id>")
def agent_detail(run_id: str):
    with _runs_lock:
        run = _runs.get(run_id)
    if run is None:
        return jsonify({"error": "not found"}), 404

    d = {
        "run_id": run.run_id,
        "agent_id": run.agent_id,
        "agent_name": run.agent_name,
        "hop": run.hop,
        "started_at": run.started_at,
        "status": run.status,
        "migrated_to": run.migrated_to,
        "error": run.error,
    }
    if run.result:
        d["exit_code"] = run.result.exit_code
        d["runtime_seconds"] = run.result.runtime_seconds
        d["stdout"] = run.result.stdout[-4096:] if run.result.stdout else None
    return jsonify(d)


# --------------------------------------------------------------------------
# API: receive and run a bundle
# --------------------------------------------------------------------------

@app.post("/bundle")
def receive_bundle():
    """Receive a .claw bundle, verify it, run it, return the result.

    The bundle is sent as raw bytes (application/octet-stream).
    On success: 200 with run metadata.
    On verification failure: 400 with reason (bundle quarantined, not deleted).
    On sandbox failure: 500.
    """
    if request.content_type != "application/octet-stream":
        return jsonify({"error": "content-type must be application/octet-stream"}), 415

    data = request.get_data()
    if not data:
        return jsonify({"error": "empty body"}), 400

    # Write to a temp file; unpack() validates the zip before extracting
    with tempfile.NamedTemporaryFile(suffix=".claw", delete=False) as tmp:
        tmp.write(data)
        claw_path = Path(tmp.name)

    agent_dir = None
    try:
        agent_dir = AGENTS_DIR / uuid.uuid4().hex
        manifest = B.unpack(
            claw_path,
            agent_dir,
            _get_trusted_keys(),
            trusted_peers=_get_trusted_peers(),
            policy=_get_policy(),
            quarantine_dir=QUARANTINE_DIR,
        )
    except QuarantinedBundle as exc:
        claw_path.unlink(missing_ok=True)
        logger.warning("bundle quarantined: %s (path=%s)", exc.reason, exc.quarantine_path)
        return jsonify({
            "error": "bundle rejected",
            "reason": exc.reason,
            "quarantine_path": str(exc.quarantine_path) if exc.quarantine_path else None,
        }), 400
    except BundleError as exc:
        claw_path.unlink(missing_ok=True)
        return jsonify({"error": str(exc)}), 400
    finally:
        claw_path.unlink(missing_ok=True)

    # Verification passed. Run asynchronously so the HTTP connection doesn't
    # hold open for the agent's full runtime.
    run_rec = _register_run(
        agent_id=manifest["agent"]["id"],
        agent_name=manifest["agent"]["name"],
        hop=manifest["migration"]["hop_count"],
    )
    threading.Thread(
        target=_execute_agent,
        args=(run_rec.run_id, agent_dir, manifest),
        daemon=True,
    ).start()

    return jsonify({
        "run_id": run_rec.run_id,
        "agent_id": manifest["agent"]["id"],
        "agent_name": manifest["agent"]["name"],
        "hop": manifest["migration"]["hop_count"],
        "status": "accepted",
        "poll_url": f"/agents/{run_rec.run_id}",
    }), 202


def _execute_agent(run_id: str, agent_dir: Path, manifest: dict) -> None:
    """Run the agent, handle migration, and clean up. Runs in a thread."""
    from transport import send_bundle

    try:
        result = sandbox_run(agent_dir, manifest, node_id=NODE_ID)
    except SandboxError as exc:
        logger.error("sandbox error for run %s: %s", run_id, exc)
        _update_run(run_id, status="failed", error=str(exc))
        shutil.rmtree(agent_dir, ignore_errors=True)
        return

    _update_run(run_id, result=result)

    if result.wants_to_migrate and result.succeeded:
        target = result.requested_migration

        # The target came out of agent-written state: untrusted input. The
        # agent proposes, this node disposes. An unlisted target is a policy
        # refusal, not an error — the agent ran fine, it just doesn't get to
        # aim this node's outbound traffic wherever it likes.
        if target not in _get_allowed_peers():
            logger.warning(
                "refusing migration for run %s: %r is not in allowed_peers", run_id, target
            )
            _update_run(
                run_id,
                status="completed",
                error=f"migration refused: {target} is not in this node's allowed_peers",
            )
            shutil.rmtree(agent_dir, ignore_errors=True)
            return

        _update_run(run_id, status="migrating", migrated_to=target)
        try:
            advanced = record_hop(manifest, from_node=f"{NODE_ID}:{NODE_PORT}", to_node=target)
            # Write updated manifest so pack() picks it up
            (agent_dir / MANIFEST_NAME).write_text(json.dumps(advanced, indent=2, sort_keys=True))
            claw_path = agent_dir.parent / f"{run_id}.claw"
            pack(agent_dir, claw_path, _get_keypair(), manifest=advanced)
            send_bundle(claw_path, target)
            claw_path.unlink(missing_ok=True)
            logger.info("agent %s hopped to %s", manifest["agent"]["id"], target)
        except Exception as exc:  # noqa: BLE001
            logger.error("migration failed for run %s: %s", run_id, exc)
            _update_run(run_id, status="failed", error=f"migration failed: {exc}")
        finally:
            shutil.rmtree(agent_dir, ignore_errors=True)
    else:
        status = "completed" if result.succeeded else "failed"
        _update_run(run_id, status=status)
        shutil.rmtree(agent_dir, ignore_errors=True)


# --------------------------------------------------------------------------
# Entrypoint
# --------------------------------------------------------------------------

def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=__import__("sys").stderr,
    )

    for d in (DATA_DIR, KEYS_DIR, AGENTS_DIR, QUARANTINE_DIR):
        d.mkdir(parents=True, exist_ok=True)

    # Eagerly initialize so startup errors surface before the first request
    _get_keypair()
    _get_trusted_keys()
    _get_trusted_peers()
    _get_policy()

    logger.info("ClawP2P node %s starting on %s:%d", NODE_ID, NODE_HOST, NODE_PORT)
    logger.info(
        "trusted owners: %d, trusted peers: %d, outbound targets: %d",
        len(_get_trusted_keys()), len(_get_trusted_peers()), len(_get_allowed_peers()),
    )

    app.run(host=NODE_HOST, port=NODE_PORT, threaded=True)


if __name__ == "__main__":
    main()
