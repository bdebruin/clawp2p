"""Tests for sandbox.py.

Two tiers:

  1. Command-construction tests — run everywhere, no Docker needed. These
     exist because the bugs they pin down (wrong mount directory, illegal
     docker names, limits taken from the wrong manifest) were all invisible
     to dry_run testing: dry_run never hands the command to docker, so docker
     never got the chance to reject it.

  2. Smoke tests — require a Docker daemon and are skipped without one. They
     pack a real bundle, unpack it, and run it in a real container. This is
     the only tier that proves the sandbox sandbox-es.

The smoke tests use python:3.11-slim (override with CLAWP2P_TEST_IMAGE) so
they do not depend on the clawp2p/agent-base image existing yet.
"""

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest

import bundle as B
import sandbox as X
import signing as S

# --------------------------------------------------------------------------
# Docker availability
# --------------------------------------------------------------------------


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        proc = subprocess.run(
            ["docker", "info"], capture_output=True, timeout=20, check=False
        )
        return proc.returncode == 0
    except Exception:  # noqa: BLE001
        return False


DOCKER = _docker_available()
needs_docker = pytest.mark.skipif(not DOCKER, reason="docker daemon not available")

TEST_IMAGE = os.environ.get("CLAWP2P_TEST_IMAGE", "python:3.11-slim")

# Docker's own rule for container and network names.
DOCKER_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")


# --------------------------------------------------------------------------
# Fixtures (mirror test_bundle.py's agent)
# --------------------------------------------------------------------------


@pytest.fixture
def keypair():
    return S.generate_keypair()


@pytest.fixture
def trusted(keypair):
    return S.TrustedKeys([keypair.public_id])


def _make_agent(root: Path, keypair, *, main_py: str) -> Path:
    (root / "state").mkdir(parents=True)
    (root / "instructions").mkdir()
    (root / "code").mkdir()
    (root / "state" / "memory.md").write_text("# Memory\n\ncount: 0\n")
    (root / "instructions" / "system.md").write_text("Count and report.\n")
    (root / "code" / "main.py").write_text(main_py)
    (root / "history.log").write_text("")

    manifest = B.new_manifest(
        agent_id="did:claw:8f3a9c2e1b7d4a60",
        name="counter-demo",
        owner_pubkey=keypair.public_id,
        origin_node="node-a.local:7777",
    )
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return root


@pytest.fixture
def agent_dir(tmp_path, keypair):
    return _make_agent(tmp_path / "counter-agent", keypair, main_py="print('counting')\n")


@pytest.fixture
def unpacked(agent_dir, tmp_path, keypair, trusted):
    """A verified agent directory + manifest, exactly as node.py would have."""
    claw = B.pack(agent_dir, tmp_path / "agent.claw", keypair)
    dest = tmp_path / "unpacked"
    manifest = B.unpack(claw, dest, trusted, policy=B.NodePolicy())
    return dest, manifest


# --------------------------------------------------------------------------
# Tier 1: command construction (no Docker required)
# --------------------------------------------------------------------------


def test_docker_cmd_mounts_the_entrypoint_dir(unpacked):
    """Every mount source must exist and the entrypoint must live inside a
    mounted directory — otherwise docker refuses to start (missing bind
    source) or starts a container in which the agent's code is unreachable."""
    dest, manifest = unpacked
    cmd, _, _ = X._build_docker_cmd(dest, manifest, node_id="node-test")
    joined = " ".join(cmd)

    assert f"src={dest / 'code'}" in joined
    assert "dst=/agent/code" in joined
    assert "/agent/code/main.py" in joined

    # every bind-mount source must exist on disk by the time run() executes
    for arg in cmd:
        if arg.startswith("type=bind,src="):
            src = arg.split("src=", 1)[1].split(",", 1)[0]
            assert Path(src).exists(), f"missing mount source: {src}"


def test_docker_names_are_legal(unpacked):
    """Regression: agent ids are DIDs with colons, which docker rejects in
    both container names and network names."""
    dest, manifest = unpacked
    cmd, container_name, _ = X._build_docker_cmd(dest, manifest, node_id="node-test")

    assert DOCKER_NAME_RE.match(container_name), container_name

    network_args = [a for a in cmd if a.startswith("--network=")]
    assert len(network_args) == 1
    network = network_args[0].split("=", 1)[1]
    assert network == "none" or DOCKER_NAME_RE.match(network), network


def test_docker_names_unique_per_run(unpacked):
    dest, manifest = unpacked
    _, name_a, _ = X._build_docker_cmd(dest, manifest, node_id="n")
    _, name_b, _ = X._build_docker_cmd(dest, manifest, node_id="n")
    assert name_a != name_b


def test_docker_cmd_has_hardening_flags(unpacked):
    dest, manifest = unpacked
    cmd, _, _ = X._build_docker_cmd(dest, manifest, node_id="node-test")
    joined = " ".join(cmd)

    for flag in (
        "--cap-drop=ALL",
        "--read-only",
        "--security-opt=no-new-privileges:true",
        "--pids-limit=",
        "--user=",
        "--memory-swap=",
        "noexec",
    ):
        assert flag in joined, f"missing hardening flag {flag}"


def test_limits_come_from_on_disk_manifest(unpacked):
    """A caller-supplied manifest with inflated resources must not widen the
    container limits — and must be rejected as inconsistent."""
    dest, manifest = unpacked
    doctored = json.loads(json.dumps(manifest))
    doctored["resources"]["memory_mb"] = 999999

    with pytest.raises(X.SandboxError, match="manifest mismatch"):
        X.run(dest, doctored, node_id="node-test", dry_run=True)


def test_stale_entrypoint_is_rejected(unpacked):
    dest, manifest = unpacked
    stale = json.loads(json.dumps(manifest))
    stale["runtime"]["entrypoint"] = "code/other.py"

    with pytest.raises(X.SandboxError, match="manifest mismatch"):
        X.run(dest, stale, node_id="node-test", dry_run=True)


def test_dry_run_succeeds_on_verified_bundle(unpacked):
    dest, manifest = unpacked
    result = X.run(dest, manifest, node_id="node-test", dry_run=True)
    assert result.succeeded
    assert result.stdout == "[dry-run]"


def test_dry_run_creates_missing_mount_sources(tmp_path, keypair, trusted):
    """A fresh agent without state/ must still be mountable: --mount errors
    on a missing source instead of creating it."""
    root = tmp_path / "bare-agent"
    root.mkdir()
    (root / "code").mkdir()
    (root / "code" / "main.py").write_text("print('hi')\n")
    manifest = B.new_manifest(
        agent_id="did:claw:bare", name="bare", owner_pubkey=keypair.public_id
    )
    (root / "manifest.json").write_text(json.dumps(manifest))

    claw = B.pack(root, tmp_path / "bare.claw", keypair)
    dest = tmp_path / "out"
    unpacked_manifest = B.unpack(claw, dest, trusted, policy=B.NodePolicy())

    X.run(dest, unpacked_manifest, node_id="n", dry_run=True)
    for sub in ("state", "instructions", "code"):
        assert (dest / sub).is_dir()


# --------------------------------------------------------------------------
# Migration request parsing (agent-controlled input)
# --------------------------------------------------------------------------


def _write_migration(dest: Path, content: str) -> None:
    (dest / "state").mkdir(exist_ok=True)
    (dest / "state" / "migrate_to.txt").write_text(content)


def test_valid_migration_target_is_returned(tmp_path):
    _write_migration(tmp_path, "node-b.local:7777\n")
    assert X._read_migration_request(tmp_path) == "node-b.local:7777"
    assert not (tmp_path / "state" / "migrate_to.txt").exists()  # consumed


@pytest.mark.parametrize(
    "bad",
    [
        "http://evil.example/steal",
        "node-b:7777/../..",
        "node-b",                      # no port
        ":7777",                       # no host
        "node b:7777",                 # whitespace
        "node-b:7777; rm -rf /",       # injection attempt
        "-node:7777",                  # leading dash
    ],
)
def test_malformed_migration_targets_are_discarded(tmp_path, bad):
    _write_migration(tmp_path, bad)
    assert X._read_migration_request(tmp_path) is None
    assert not (tmp_path / "state" / "migrate_to.txt").exists()  # still consumed


def test_docker_safe_name_strips_did_colons():
    assert X.docker_safe_name("did:claw:8f3a9c2e") == "did-claw-8f3a9c2e"
    assert DOCKER_NAME_RE.match(X.docker_safe_name("::::"))


# --------------------------------------------------------------------------
# Tier 2: real Docker smoke tests
# --------------------------------------------------------------------------


def _run_real(tmp_path, keypair, trusted, main_py: str, *, max_runtime: int = 60):
    root = _make_agent(tmp_path / "agent", keypair, main_py=main_py)
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["resources"]["max_runtime_seconds"] = max_runtime
    (root / "manifest.json").write_text(json.dumps(manifest))

    claw = B.pack(root, tmp_path / "agent.claw", keypair, manifest=manifest)
    dest = tmp_path / "verified"
    verified = B.unpack(claw, dest, trusted, policy=B.NodePolicy())

    # Test image is stock python:3.11-slim, which has no uid 1000 user with a
    # home dir — run as root inside the container for the smoke test only.
    saved_user = X.CONTAINER_USER
    X.CONTAINER_USER = "0:0"
    try:
        verified_manifest = json.loads(json.dumps(verified))
        verified_manifest["runtime"]["image"] = TEST_IMAGE
        (dest / "manifest.json").write_text(
            json.dumps(verified_manifest, indent=2, sort_keys=True)
        )
        return X.run(dest, verified_manifest, node_id="smoke-node"), dest
    finally:
        X.CONTAINER_USER = saved_user


@needs_docker
def test_smoke_agent_runs_and_prints(tmp_path, keypair, trusted):
    """The end-to-end path: pack → unpack → actually execute in a container."""
    result, _ = _run_real(
        tmp_path, keypair, trusted,
        "import os\n"
        "print('hello from', os.environ['CLAWP2P_NODE_ID'])\n",
    )
    assert result.succeeded, result.stderr
    assert "hello from smoke-node" in result.stdout


@needs_docker
def test_smoke_agent_state_write_persists(tmp_path, keypair, trusted):
    result, dest = _run_real(
        tmp_path, keypair, trusted,
        "open('/agent/state/memory.md', 'w').write('# Memory\\n\\ncount: 1\\n')\n",
    )
    assert result.succeeded, result.stderr
    assert "count: 1" in (dest / "state" / "memory.md").read_text()


@needs_docker
def test_smoke_readonly_mounts_are_enforced(tmp_path, keypair, trusted):
    result, dest = _run_real(
        tmp_path, keypair, trusted,
        "try:\n"
        "    open('/agent/code/main.py', 'w')\n"
        "    print('WROTE')\n"
        "except OSError:\n"
        "    print('DENIED')\n",
    )
    assert result.succeeded, result.stderr
    assert "DENIED" in result.stdout
    assert "print" in (dest / "code" / "main.py").read_text()  # unmodified


@needs_docker
def test_smoke_timeout_actually_kills_the_container(tmp_path, keypair, trusted):
    """Regression for the worst bug: subprocess timeout killed the docker CLI
    but left the container running forever."""
    with pytest.raises(X.SandboxError, match="exceeded runtime limit"):
        _run_real(
            tmp_path, keypair, trusted,
            "import time\ntime.sleep(3600)\n",
            max_runtime=5,
        )

    # Give docker a moment, then assert no clawp2p container survived.
    time.sleep(2)
    proc = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        capture_output=True, text=True, timeout=20, check=False,
    )
    survivors = [n for n in proc.stdout.splitlines() if n.startswith("clawp2p-")]
    assert not survivors, f"containers left running after timeout: {survivors}"


@needs_docker
def test_smoke_migration_request_round_trip(tmp_path, keypair, trusted):
    result, _ = _run_real(
        tmp_path, keypair, trusted,
        "open('/agent/state/migrate_to.txt', 'w').write('node-b.local:7777')\n",
    )
    assert result.succeeded, result.stderr
    assert result.requested_migration == "node-b.local:7777"
    assert result.wants_to_migrate
