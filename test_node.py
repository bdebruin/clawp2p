"""Tests for node.py's migration path — the loop that had never run.

These simulate a full A→B hop without Docker or HTTP: the sandbox is
monkeypatched to "run" the agent (returning a migration request), and
transport.send_bundle is captured so the produced .claw can be verified
exactly the way a receiving node would verify it.

Covers the two fixes on this path:
  1. Node repack works without the owner's key (split core/hop signatures)
  2. The outbound peer allowlist refuses agent-chosen targets not on it
"""

import json
import os
import tempfile
from pathlib import Path

import pytest

# node.py reads CLAWP2P_DATA_DIR at import time — pin it before importing.
_DATA_DIR = tempfile.mkdtemp(prefix="clawp2p-node-test-")
os.environ["CLAWP2P_DATA_DIR"] = _DATA_DIR

import bundle as B  # noqa: E402
import node as N    # noqa: E402
import sandbox as X  # noqa: E402
import signing as S  # noqa: E402


@pytest.fixture
def owner():
    return S.generate_keypair()


@pytest.fixture
def agent_dir(tmp_path, owner):
    root = tmp_path / "agent"
    (root / "state").mkdir(parents=True)
    (root / "instructions").mkdir()
    (root / "code").mkdir()
    (root / "state" / "memory.md").write_text("# Memory\n\ncount: 0\n")
    (root / "instructions" / "system.md").write_text("Count.\n")
    (root / "code" / "main.py").write_text("print('counting')\n")
    (root / "history.log").write_text("")
    manifest = B.new_manifest(
        agent_id="did:claw:8f3a9c2e1b7d4a60",
        name="counter-demo",
        owner_pubkey=owner.public_id,
    )
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return root


@pytest.fixture
def node_env(tmp_path, owner, monkeypatch):
    """Configure node.py's lazy globals directly, as main() would."""
    node_key = S.generate_keypair()
    monkeypatch.setattr(N, "_policy", B.NodePolicy())
    monkeypatch.setattr(N, "_trusted_keys", S.TrustedKeys([owner.public_id]))
    monkeypatch.setattr(N, "_trusted_peers", S.TrustedKeys())
    monkeypatch.setattr(N, "_allowed_peers", set())
    monkeypatch.setattr(N, "_node_keypair", node_key)
    return node_key


def _fake_result(migration_target):
    return X.RunResult(
        exit_code=0,
        stdout="counting\n",
        stderr="",
        runtime_seconds=0.1,
        requested_migration=migration_target,
    )


def _receive(agent_dir, tmp_path, owner):
    """Owner packs; node verifies — the receive half of node.receive_bundle."""
    claw = B.pack(agent_dir, tmp_path / "in.claw", owner)
    dest = tmp_path / "verified"
    manifest = B.unpack(claw, dest, N._get_trusted_keys(), policy=N._get_policy())
    return dest, manifest


def test_migration_refused_when_target_not_allowlisted(
    agent_dir, tmp_path, owner, node_env, monkeypatch
):
    dest, manifest = _receive(agent_dir, tmp_path, owner)
    sent = []
    monkeypatch.setattr(N, "sandbox_run", lambda *a, **k: _fake_result("evil-host:7777"))
    import transport
    monkeypatch.setattr(transport, "send_bundle", lambda *a, **k: sent.append(a))

    run = N._register_run("did:claw:8f3a9c2e1b7d4a60", "counter-demo", 0)
    N._execute_agent(run.run_id, dest, manifest)

    record = N._runs[run.run_id]
    assert record.status == "completed"
    assert "migration refused" in record.error
    assert record.migrated_to is None
    assert sent == []  # nothing left this node
    assert not dest.exists()  # cleaned up


def test_migration_sends_and_receiver_verifies(
    agent_dir, tmp_path, owner, node_env, monkeypatch
):
    """The full hop: run → repack with NODE key → send → node B verifies."""
    dest, manifest = _receive(agent_dir, tmp_path, owner)

    # agent mutated its state during the "run"
    (dest / "state" / "memory.md").write_text("# Memory\n\ncount: 5\n")

    monkeypatch.setattr(N, "_allowed_peers", {"node-b.local:7777"})
    monkeypatch.setattr(N, "sandbox_run", lambda *a, **k: _fake_result("node-b.local:7777"))

    captured = {}

    def _capture_send(claw_path, target):
        captured["bytes"] = Path(claw_path).read_bytes()
        captured["target"] = target
        return {"run_id": "remote", "status": "accepted"}

    import transport
    monkeypatch.setattr(transport, "send_bundle", _capture_send)

    run = N._register_run("did:claw:8f3a9c2e1b7d4a60", "counter-demo", 0)
    N._execute_agent(run.run_id, dest, manifest)

    record = N._runs[run.run_id]
    assert record.status == "migrating", record.error
    assert record.migrated_to == "node-b.local:7777"
    assert captured["target"] == "node-b.local:7777"

    # Node B: trusts the owner, and trusts node A as a peer.
    hop1 = tmp_path / "hop1.claw"
    hop1.write_bytes(captured["bytes"])
    final = B.unpack(
        hop1,
        tmp_path / "node-b-verified",
        S.TrustedKeys([owner.public_id]),
        trusted_peers=S.TrustedKeys([node_env.public_id]),
        policy=B.NodePolicy(),
    )
    assert final["migration"]["hop_count"] == 1
    assert final["integrity"]["hop_pubkey"] == node_env.public_id
    assert final["agent"]["owner_pubkey"] == owner.public_id
    assert "count: 5" in (tmp_path / "node-b-verified" / "state" / "memory.md").read_text()

    # Node C: trusts the owner but NOT node A → the forwarded bundle is refused.
    with pytest.raises(B.QuarantinedBundle, match="trusted peer"):
        B.unpack(
            hop1,
            tmp_path / "node-c-verified",
            S.TrustedKeys([owner.public_id]),
            policy=B.NodePolicy(),
        )


# --------------------------------------------------------------------------
# GET /reachability tests
# --------------------------------------------------------------------------

def test_reachability_local_node_accepts(node_env, agent_dir, owner):
    """Local node with matching policy reports reachable."""
    manifest = json.loads((agent_dir / "manifest.json").read_text())

    import urllib.parse
    with N.app.test_client() as client:
        resp = client.get(
            "/reachability?manifest=" + urllib.parse.quote(json.dumps(manifest))
        )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["reachable"] == 1
    assert data["rejecting"] == 0
    local = next(d for d in data["detail"] if d["address"].startswith("localhost:"))
    assert local["state"] == "reachable"
    assert local["dialable"] is True


def test_reachability_rejecting_egress(node_env, agent_dir, owner):
    """Manifest declaring disallowed egress target is reported as rejecting."""
    import urllib.parse
    manifest = json.loads((agent_dir / "manifest.json").read_text())
    manifest["permissions"]["network_egress"] = ["api.example.com:443"]

    with N.app.test_client() as client:
        resp = client.get(
            "/reachability?manifest=" + urllib.parse.quote(json.dumps(manifest))
        )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["reachable"] == 0
    local = next(d for d in data["detail"] if d["address"].startswith("localhost:"))
    assert local["state"] == "rejecting"
    assert any("allowlist" in r for r in local["reasons"])


def test_reachability_undialable_peer(node_env, agent_dir, owner, monkeypatch):
    """A peer that accepts the policy but is unreachable is policy_ok_undialable."""
    import urllib.parse
    from transport import TransportError

    manifest = json.loads((agent_dir / "manifest.json").read_text())
    # Add a fake peer that passes policy check but is unreachable
    monkeypatch.setattr(N, "_allowed_peers", {"192.0.2.1:7777"})  # TEST-NET, always unreachable

    def fake_fetch_status(addr):
        raise TransportError("connection refused")

    def fake_fetch_policy(addr):
        raise TransportError("connection refused")

    monkeypatch.setattr("node.fetch_status" if hasattr(N, "fetch_status") else "transport.fetch_status",
                        fake_fetch_status, raising=False)

    import transport as T
    monkeypatch.setattr(T, "fetch_status", fake_fetch_status)
    monkeypatch.setattr(T, "fetch_policy", fake_fetch_policy)

    with N.app.test_client() as client:
        resp = client.get(
            "/reachability?manifest=" + urllib.parse.quote(json.dumps(manifest))
        )
    assert resp.status_code == 200
    data = resp.get_json()
    peer = next((d for d in data["detail"] if d["address"] == "192.0.2.1:7777"), None)
    assert peer is not None
    assert peer["state"] in ("policy_ok_undialable", "unknown")
    # Local node should still be reachable
    assert data["reachable"] >= 1
