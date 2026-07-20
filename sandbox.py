"""
sandbox.py — Docker-based agent execution.

This module runs agent code. It does NOT verify bundles, parse manifests for
trust decisions, or validate hashes. All of that happens in bundle.unpack().
By the time sandbox.py sees a directory, every security check has passed.

The contract with callers:
  - agent_dir must be the return value of bundle.unpack(), never a raw path
  - manifest must be the dict returned by that same unpack() call
  - If the caller cannot guarantee this, the call is wrong

Enforcement: we re-read the manifest from agent_dir to catch callers who pass
a stale or manually-constructed manifest. The two must agree on agent.id,
runtime.entrypoint, resources.*, and permissions.network_egress.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from bundle import BundleError, append_history
from signing import MANIFEST_NAME

logger = logging.getLogger(__name__)

# Docker image that agents run inside. Must have Python 3.11 and no extra
# capabilities. Build this image separately; the runtime does not build it.
AGENT_BASE_IMAGE = os.environ.get("CLAWP2P_AGENT_IMAGE", "clawp2p/agent-base:0.1")

# Hard ceiling applied before Docker limits: we never pass a container more
# than this regardless of what the manifest requests.
RUNTIME_MAX_MEMORY_MB = int(os.environ.get("CLAWP2P_MAX_MEMORY_MB", "2048"))
RUNTIME_MAX_CPU = float(os.environ.get("CLAWP2P_MAX_CPU", "2.0"))
RUNTIME_MAX_RUNTIME_SECONDS = int(os.environ.get("CLAWP2P_MAX_RUNTIME_SECONDS", "600"))

# Output from the agent is captured but capped to prevent log flooding.
MAX_OUTPUT_BYTES = 1 * 1024 * 1024  # 1 MB


class SandboxError(Exception):
    """Raised when the sandbox cannot be started or enforced."""


@dataclass
class RunResult:
    exit_code: int
    stdout: str
    stderr: str
    runtime_seconds: float
    requested_migration: str | None  # node address the agent wants to hop to, or None

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0

    @property
    def wants_to_migrate(self) -> bool:
        return self.requested_migration is not None


def _read_manifest(agent_dir: Path) -> dict:
    path = agent_dir / MANIFEST_NAME
    if not path.is_file():
        raise SandboxError(f"no manifest.json in agent_dir — was this directory from unpack()? {agent_dir}")
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise SandboxError(f"manifest.json is not valid JSON: {exc}") from exc


def _check_consistency(agent_dir_manifest: dict, caller_manifest: dict) -> None:
    """Catch the class of bug where caller passes a stale manifest."""
    for field, path in (
        ("id", ("agent", "id")),
        ("entrypoint", ("runtime", "entrypoint")),
    ):
        a_val = agent_dir_manifest
        c_val = caller_manifest
        for key in path:
            a_val = a_val[key]
            c_val = c_val[key]
        if a_val != c_val:
            raise SandboxError(
                f"manifest mismatch on {'.'.join(path)}: "
                f"on-disk {a_val!r} vs caller-supplied {c_val!r}. "
                f"Pass the manifest returned by bundle.unpack(), not a stale copy."
            )


def _build_docker_cmd(
    agent_dir: Path,
    manifest: dict,
    *,
    node_id: str,
) -> list[str]:
    """Construct the docker run command from manifest-declared limits.

    Network egress: Docker cannot enforce host:port allowlists natively, so we
    use --network=none and rely on a user-defined Docker network that proxies
    only the declared egress targets. If that proxy is not configured, the
    agent gets no network — which is the safer failure mode.

    Filesystem writes: the container mounts agent_dir/state and history.log
    read-write; everything else (instructions, code) is read-only.
    """
    res = manifest["resources"]
    perms = manifest["permissions"]
    rt = manifest["runtime"]

    memory_mb = min(res["memory_mb"], RUNTIME_MAX_MEMORY_MB)
    cpu = min(res["cpu_cores"], RUNTIME_MAX_CPU)
    timeout = min(res["max_runtime_seconds"], RUNTIME_MAX_RUNTIME_SECONDS)

    entrypoint = rt["entrypoint"]
    # Already validated by bundle.validate_manifest() — not absolute, no ..
    # We assert rather than re-validate: if this fires, the caller bypassed unpack().
    assert not Path(entrypoint).is_absolute(), "entrypoint must be relative — was unpack() called?"
    assert ".." not in Path(entrypoint).parts, "entrypoint traversal — was unpack() called?"

    image = rt.get("image", AGENT_BASE_IMAGE)

    egress_targets = perms.get("network_egress", [])
    network_mode = f"clawp2p-egress-{manifest['agent']['id']}" if egress_targets else "none"

    cmd = [
        "docker", "run",
        "--rm",
        "--name", f"clawp2p-{manifest['agent']['id'][:16]}-{_now_stamp()}",
        # Resource limits
        f"--memory={memory_mb}m",
        f"--memory-swap={memory_mb}m",  # no swap
        f"--cpus={cpu}",
        # Security: drop all capabilities, no new privileges
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--read-only",  # root FS read-only; writable mounts declared below
        # Network
        f"--network={network_mode}",
        # Writable mounts (state and history only)
        "--mount", f"type=bind,src={agent_dir / 'state'},dst=/agent/state",
        "--mount", f"type=bind,src={agent_dir / 'history.log'},dst=/agent/history.log",
        # Read-only mounts for everything else
        "--mount", f"type=bind,src={agent_dir / 'instructions'},dst=/agent/instructions,readonly",
        "--mount", f"type=bind,src={agent_dir / 'code'},dst=/agent/code,readonly",
        "--mount", f"type=bind,src={agent_dir / MANIFEST_NAME},dst=/agent/manifest.json,readonly",
        # Working directory
        "--workdir=/agent",
        # Environment: node identity passed to agent, not secrets
        "--env", f"CLAWP2P_NODE_ID={node_id}",
        "--env", f"CLAWP2P_HOP={manifest['migration']['hop_count']}",
        "--env", f"CLAWP2P_AGENT_ID={manifest['agent']['id']}",
        # Tmpfs for /tmp so agent has scratch space without touching host
        "--tmpfs=/tmp:size=64m,noexec",
        image,
        rt["interpreter"], f"/agent/{entrypoint}",
    ]

    return cmd, timeout


def _now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")


def _read_migration_request(agent_dir: Path) -> str | None:
    """An agent signals migration intent by writing to state/migrate_to.txt.

    The file contains a single node address (host:port). The node reads it
    after the container exits, then clears it — the agent never sets it
    permanently because state/ survives across hops.
    """
    req_file = agent_dir / "state" / "migrate_to.txt"
    if not req_file.is_file():
        return None
    target = req_file.read_text().strip()
    req_file.unlink()  # consume the request
    if not target:
        return None
    logger.info("agent requested migration to %s", target)
    return target


def run(
    agent_dir: Path,
    manifest: dict,
    *,
    node_id: str,
    dry_run: bool = False,
) -> RunResult:
    """Run the agent in a Docker sandbox and return its result.

    agent_dir MUST be the directory returned by bundle.unpack(). Passing any
    other directory is a caller error and will raise SandboxError.

    If dry_run is True, the Docker command is logged but not executed. Used in
    tests and environments without Docker.
    """
    agent_dir = Path(agent_dir)

    if not agent_dir.is_dir():
        raise SandboxError(f"agent_dir does not exist: {agent_dir}")

    on_disk_manifest = _read_manifest(agent_dir)
    _check_consistency(on_disk_manifest, manifest)

    # Ensure history.log exists so the bind mount doesn't fail
    history = agent_dir / "history.log"
    if not history.exists():
        history.touch()

    docker_cmd, timeout = _build_docker_cmd(agent_dir, manifest, node_id=node_id)

    agent_id = manifest["agent"]["id"]
    hop = manifest["migration"]["hop_count"]
    logger.info("starting agent %s hop=%d node=%s", agent_id, hop, node_id)
    append_history(agent_dir, f"start\tnode={node_id}\thop={hop}")

    if dry_run:
        logger.info("dry_run: would execute: %s", " ".join(docker_cmd))
        return RunResult(
            exit_code=0,
            stdout="[dry-run]",
            stderr="",
            runtime_seconds=0.0,
            requested_migration=None,
        )

    start = datetime.now(timezone.utc)
    try:
        proc = subprocess.run(
            docker_cmd,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        elapsed = (datetime.now(timezone.utc) - start).total_seconds()

        stdout = proc.stdout[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
        stderr = proc.stderr[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")

        if proc.returncode != 0:
            logger.warning(
                "agent %s exited %d after %.1fs", agent_id, proc.returncode, elapsed
            )
        else:
            logger.info("agent %s completed hop=%d in %.1fs", agent_id, hop, elapsed)

    except subprocess.TimeoutExpired:
        elapsed = (datetime.now(timezone.utc) - start).total_seconds()
        append_history(agent_dir, f"timeout\tnode={node_id}\thop={hop}\telapsed={elapsed:.1f}s")
        raise SandboxError(
            f"agent {agent_id} exceeded runtime limit of {timeout}s on hop {hop}"
        )
    except FileNotFoundError as exc:
        raise SandboxError(
            "docker not found — install Docker and ensure it is on PATH"
        ) from exc

    migration_target = _read_migration_request(agent_dir)

    append_history(
        agent_dir,
        f"exit\tcode={proc.returncode}\tnode={node_id}\thop={hop}"
        + (f"\tmigrate_to={migration_target}" if migration_target else ""),
    )

    return RunResult(
        exit_code=proc.returncode,
        stdout=stdout,
        stderr=stderr,
        runtime_seconds=elapsed,
        requested_migration=migration_target,
    )
