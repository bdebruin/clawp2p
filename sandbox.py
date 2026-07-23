"""
sandbox.py — Docker-based agent execution.

This module runs agent code. It does NOT verify bundles, parse manifests for
trust decisions, or validate hashes. All of that happens in bundle.unpack().
By the time sandbox.py sees a directory, every security check has passed.

The contract with callers:
  - agent_dir must be the return value of bundle.unpack(), never a raw path
  - manifest must be the dict returned by that same unpack() call
  - If the caller cannot guarantee this, the call is wrong

Enforcement: we re-read the manifest from agent_dir and require it to agree
with the caller's copy on agent.id, runtime.entrypoint, resources.*, and
permissions.network_egress. The docker command is then built from the ON-DISK
manifest — the one that hash-verification actually covered — so a stale or
doctored caller copy can never widen the limits.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from bundle import append_history
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

# A fork bomb is not prevented by --cap-drop; it needs an explicit pid ceiling.
RUNTIME_MAX_PIDS = int(os.environ.get("CLAWP2P_MAX_PIDS", "128"))

# UID:GID the agent process runs as inside the container. The agent-base image
# must contain this user, and bind-mounted state/ must be writable by it.
CONTAINER_USER = os.environ.get("CLAWP2P_CONTAINER_USER", "1000:1000")

# Seconds of grace beyond the manifest runtime limit before we force-kill the
# container. Covers docker startup overhead so a well-behaved agent that used
# its full budget is not killed mid-shutdown.
TIMEOUT_GRACE_SECONDS = 10

# Output from the agent is captured but capped to prevent log flooding.
MAX_OUTPUT_BYTES = 1 * 1024 * 1024  # 1 MB

# A migration target must be a bare host:port. Anything else — URLs, paths,
# whitespace tricks — is discarded. The agent wrote this file, so it is
# untrusted input even though the bundle it arrived in was verified.
_MIGRATION_TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*:\d{1,5}$")

# Docker container/network names must match [a-zA-Z0-9][a-zA-Z0-9_.-]*.
# Agent ids are DIDs ("did:claw:8f3a...") whose colons docker rejects.
_DOCKER_NAME_BAD = re.compile(r"[^a-zA-Z0-9_.-]")


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


def docker_safe_name(raw: str) -> str:
    """Reduce an agent id to something docker accepts as a name component."""
    cleaned = _DOCKER_NAME_BAD.sub("-", raw).strip("-_.")
    return cleaned or "agent"


def _read_manifest(agent_dir: Path) -> dict:
    path = agent_dir / MANIFEST_NAME
    if not path.is_file():
        raise SandboxError(f"no manifest.json in agent_dir — was this directory from unpack()? {agent_dir}")
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise SandboxError(f"manifest.json is not valid JSON: {exc}") from exc


def _check_consistency(agent_dir_manifest: dict, caller_manifest: dict) -> None:
    """Catch the class of bug where caller passes a stale manifest.

    resources and network_egress are compared as whole blocks: they feed
    directly into container limits, so a silent divergence there is exactly
    the bug this check exists to catch.
    """
    for path in (
        ("agent", "id"),
        ("runtime", "entrypoint"),
        ("resources",),
        ("permissions", "network_egress"),
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
    migrate_to: str = "",
) -> tuple[list[str], str, int]:
    """Construct the docker run command from manifest-declared limits.

    Returns (cmd, container_name, timeout_seconds). The container name is
    returned so the caller can `docker kill` it if the runtime limit trips —
    killing the docker CLI process alone does NOT stop the container.

    Network egress: Docker cannot enforce host:port allowlists natively, so we
    use --network=none and rely on a user-defined Docker network that proxies
    only the declared egress targets. If that network does not exist, docker
    refuses to start the container at all — fail closed, nothing runs.

    Filesystem writes: the container mounts agent_dir/state and history.log
    read-write; everything else (instructions, code, manifest) is read-only.
    """
    res = manifest["resources"]
    perms = manifest["permissions"]
    rt = manifest["runtime"]

    memory_mb = min(res["memory_mb"], RUNTIME_MAX_MEMORY_MB)
    cpu = min(res["cpu_cores"], RUNTIME_MAX_CPU)
    timeout = min(res["max_runtime_seconds"], RUNTIME_MAX_RUNTIME_SECONDS)

    entrypoint = rt["entrypoint"]
    # Already validated by bundle.validate_manifest(). Re-checked here as a
    # hard raise (not assert — asserts vanish under python -O) because a
    # traversing entrypoint at this point means the caller bypassed unpack().
    ep = Path(entrypoint)
    if ep.is_absolute() or ".." in ep.parts:
        raise SandboxError(f"unsafe entrypoint {entrypoint!r} — was unpack() called?")

    image = rt.get("image", AGENT_BASE_IMAGE)

    safe_id = docker_safe_name(manifest["agent"]["id"])
    container_name = f"clawp2p-{safe_id[:24]}-{uuid.uuid4().hex[:8]}"

    egress_targets = perms.get("network_egress", [])
    network_mode = f"clawp2p-egress-{safe_id}" if egress_targets else "none"

    cmd = [
        "docker", "run",
        "--rm",
        "--name", container_name,
        # Resource limits
        f"--memory={memory_mb}m",
        f"--memory-swap={memory_mb}m",  # no swap
        f"--cpus={cpu}",
        f"--pids-limit={RUNTIME_MAX_PIDS}",
        # Security: non-root, drop all capabilities, no new privileges
        f"--user={CONTAINER_USER}",
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
        # Migration target: the node's first allowed_peer, if any.
        # The agent reads this to decide where to request migration.
        # Only nodes in allowed_peers can be targeted — the node enforces
        # this gate in _execute_agent() before forwarding the bundle.
        "--env", f"CLAWP2P_MIGRATE_TO={migrate_to}",
        # Tmpfs for /tmp so agent has scratch space without touching host
        "--tmpfs=/tmp:size=64m,noexec",
        image,
        rt["interpreter"], f"/agent/{entrypoint}",
    ]

    return cmd, container_name, timeout


def _kill_container(container_name: str) -> None:
    """Force-stop a container. Errors are logged, not raised: the container
    may already have exited between the timeout firing and the kill."""
    try:
        subprocess.run(
            ["docker", "kill", container_name],
            capture_output=True,
            timeout=30,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("docker kill %s failed: %r", container_name, exc)


def _read_capped(path: Path) -> str:
    """Read at most MAX_OUTPUT_BYTES from a capture file."""
    with path.open("rb") as handle:
        return handle.read(MAX_OUTPUT_BYTES).decode("utf-8", errors="replace")


def _read_migration_request(agent_dir: Path) -> str | None:
    """An agent signals migration intent by writing to state/migrate_to.txt.

    The file contains a single node address (host:port). The node reads it
    after the container exits, then clears it — the agent never sets it
    permanently because state/ survives across hops.

    The content is agent-controlled and therefore untrusted: anything that is
    not a bare host:port is dropped here, and the node must still check the
    target against its own peer policy before sending anything to it.
    """
    req_file = agent_dir / "state" / "migrate_to.txt"
    if not req_file.is_file():
        return None
    target = req_file.read_text().strip()
    req_file.unlink()  # consume the request
    if not target:
        return None
    if not _MIGRATION_TARGET_RE.match(target):
        logger.warning("discarding malformed migration target %r", target[:128])
        return None
    logger.info("agent requested migration to %s", target)
    return target


def run(
    agent_dir: Path,
    manifest: dict,
    *,
    node_id: str,
    migrate_to: str = "",
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

    # Ensure every mount source exists: --mount type=bind errors out on a
    # missing source rather than creating it. A bundle may legitimately lack
    # state/ (fresh agent) or instructions/ — empty is fine, absent is not.
    for sub in ("state", "instructions", "code"):
        (agent_dir / sub).mkdir(exist_ok=True)
    history = agent_dir / "history.log"
    if not history.exists():
        history.touch()

    # Limits come from the on-disk manifest — the copy hash verification
    # covered — not the caller's. _check_consistency makes divergence loud,
    # this makes it irrelevant.
    docker_cmd, container_name, timeout = _build_docker_cmd(
        agent_dir, on_disk_manifest, node_id=node_id, migrate_to=migrate_to
    )

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

    # Output goes to files, not pipes: capture_output buffers in this
    # process's memory with no ceiling, so a stdout-flooding agent could OOM
    # the node before the cap was applied. Files put the flood on disk and
    # the cap is applied at read time.
    with tempfile.TemporaryDirectory(prefix="clawp2p-io-") as io_dir:
        out_path = Path(io_dir) / "stdout"
        err_path = Path(io_dir) / "stderr"

        try:
            with out_path.open("wb") as out_f, err_path.open("wb") as err_f:
                proc = subprocess.run(
                    docker_cmd,
                    stdout=out_f,
                    stderr=err_f,
                    timeout=timeout + TIMEOUT_GRACE_SECONDS,
                    check=False,
                )
            elapsed = (datetime.now(timezone.utc) - start).total_seconds()
            stdout = _read_capped(out_path)
            stderr = _read_capped(err_path)

            if proc.returncode != 0:
                logger.warning(
                    "agent %s exited %d after %.1fs", agent_id, proc.returncode, elapsed
                )
            else:
                logger.info("agent %s completed hop=%d in %.1fs", agent_id, hop, elapsed)

        except subprocess.TimeoutExpired:
            # The timeout killed the docker CLI process — NOT the container,
            # which is still running and must be stopped explicitly.
            _kill_container(container_name)
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
