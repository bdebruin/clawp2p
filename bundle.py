"""
The .claw bundle format: pack, unpack, and manifest validation.

A .claw file is a zip containing manifest.json, state/, instructions/,
skills/, and history.log. See ClawP2P-spec.md section 3.

The ordering in unpack() is the security-critical part of this module. A
bundle is extracted to a quarantine directory, validated, and hash-verified
BEFORE anything is moved to a path the runtime will execute from. Reversing
those steps -- extracting to the live directory and then checking -- would
mean untrusted files touch an executable path even when verification fails.

Nothing here executes agent code. That is sandbox.py's job, and it should
only ever be handed a directory that came out of a successful unpack().
"""

from __future__ import annotations

import json
import shutil
import tempfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from signing import (
    MANIFEST_NAME,
    Keypair,
    SigningError,
    TrustedKeys,
    compute_bundle_hash,
    compute_state_hash,
    sign_hash,
    verify_hash,
)

SCHEMA_VERSION = "1.0"
DEFAULT_MAX_HOPS = 50
MAX_BUNDLE_BYTES = 256 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024  # zip bomb ceiling


class BundleError(Exception):
    """Raised for any malformed, unsafe, or policy-violating bundle."""


class QuarantinedBundle(BundleError):
    """Verification failed. The bundle is kept for inspection, not deleted.

    Carries the quarantine path so the node can log it and notify the sender.
    """

    def __init__(self, reason: str, quarantine_path: Path | None = None):
        super().__init__(reason)
        self.reason = reason
        self.quarantine_path = quarantine_path


# --------------------------------------------------------------------------
# Node policy
# --------------------------------------------------------------------------


@dataclass
class NodePolicy:
    """What this node is willing to run. Defaults are deliberately restrictive.

    resources are ceilings, not grants: a bundle asking for more is rejected
    outright rather than silently clamped, so the agent never resumes under
    quieter limits than it checkpointed with and then fails confusingly.
    """

    max_memory_mb: int = 1024
    max_cpu_cores: float = 1.0
    max_disk_mb: int = 512
    max_runtime_seconds: int = 600
    allow_replication: bool = False
    allowed_egress: set[str] = field(default_factory=set)
    max_hops: int = DEFAULT_MAX_HOPS

    def check(self, manifest: dict) -> None:
        res = manifest["resources"]
        perms = manifest["permissions"]

        for key, ceiling, label in (
            ("memory_mb", self.max_memory_mb, "memory"),
            ("cpu_cores", self.max_cpu_cores, "CPU"),
            ("disk_mb", self.max_disk_mb, "disk"),
            ("max_runtime_seconds", self.max_runtime_seconds, "runtime"),
        ):
            if res[key] > ceiling:
                raise BundleError(
                    f"agent requests {label} {res[key]}, node ceiling is {ceiling}"
                )

        if perms["may_replicate"] and not self.allow_replication:
            raise BundleError("agent requests replication; node policy forbids it")

        for target in perms["network_egress"]:
            if target not in self.allowed_egress:
                raise BundleError(f"egress target not on node allowlist: {target}")

        hop = manifest["migration"]["hop_count"]
        if hop > min(manifest["migration"]["max_hops"], self.max_hops):
            raise BundleError(f"hop_count {hop} exceeds max_hops")


# --------------------------------------------------------------------------
# Manifest
# --------------------------------------------------------------------------

_REQUIRED = {
    "agent": ["id", "name", "version", "created_at", "owner_pubkey"],
    "runtime": ["entrypoint", "interpreter", "image"],
    "resources": ["memory_mb", "cpu_cores", "disk_mb", "max_runtime_seconds"],
    "permissions": ["network_egress", "filesystem_write", "may_replicate", "max_replicas"],
    "migration": ["hop_count", "max_hops", "origin_node", "previous_node", "requested_next"],
}


def new_manifest(
    *,
    agent_id: str,
    name: str,
    owner_pubkey: str,
    entrypoint: str = "skills/main.py",
    version: str = "0.1.0",
    interpreter: str = "python3.11",
    image: str = "clawp2p/agent-base:0.1",
    memory_mb: int = 512,
    cpu_cores: float = 0.5,
    disk_mb: int = 256,
    max_runtime_seconds: int = 300,
    network_egress: list[str] | None = None,
    origin_node: str | None = None,
) -> dict:
    """Build a manifest for a freshly created agent, before its first hop."""
    return {
        "schema_version": SCHEMA_VERSION,
        "agent": {
            "id": agent_id,
            "name": name,
            "version": version,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "owner_pubkey": owner_pubkey,
        },
        "runtime": {"entrypoint": entrypoint, "interpreter": interpreter, "image": image},
        "resources": {
            "memory_mb": memory_mb,
            "cpu_cores": cpu_cores,
            "disk_mb": disk_mb,
            "max_runtime_seconds": max_runtime_seconds,
        },
        "permissions": {
            "network_egress": list(network_egress or []),
            "filesystem_write": ["state/", "history.log"],
            "may_replicate": False,
            "max_replicas": 0,
        },
        "migration": {
            "hop_count": 0,
            "max_hops": DEFAULT_MAX_HOPS,
            "origin_node": origin_node,
            "previous_node": None,
            "requested_next": None,
        },
        "integrity": {},
    }


def validate_manifest(manifest: dict) -> None:
    """Structural and semantic validation. Does not check signatures."""
    if not isinstance(manifest, dict):
        raise BundleError("manifest is not a JSON object")

    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise BundleError(
            f"unsupported schema_version {manifest.get('schema_version')!r}, "
            f"this runtime speaks {SCHEMA_VERSION}"
        )

    for block, keys in _REQUIRED.items():
        if block not in manifest:
            raise BundleError(f"manifest missing required block: {block}")
        if not isinstance(manifest[block], dict):
            raise BundleError(f"manifest block {block} is not an object")
        for key in keys:
            if key not in manifest[block]:
                raise BundleError(f"manifest missing required field: {block}.{key}")

    _validate_entrypoint(manifest["runtime"]["entrypoint"])

    res = manifest["resources"]
    for key in ("memory_mb", "cpu_cores", "disk_mb", "max_runtime_seconds"):
        value = res[key]
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value <= 0:
            raise BundleError(f"resources.{key} must be a positive number, got {value!r}")

    perms = manifest["permissions"]
    if not isinstance(perms["network_egress"], list):
        raise BundleError("permissions.network_egress must be a list")
    for target in perms["network_egress"]:
        if not isinstance(target, str) or "*" in target:
            raise BundleError(f"invalid egress target {target!r}: wildcards are not permitted")
        if ":" not in target:
            raise BundleError(f"egress target must be host:port, got {target!r}")

    if not isinstance(perms["may_replicate"], bool):
        raise BundleError("permissions.may_replicate must be a boolean")
    if perms["may_replicate"] and perms["max_replicas"] < 1:
        raise BundleError("may_replicate is true but max_replicas is not a positive integer")
    if not perms["may_replicate"] and perms["max_replicas"] != 0:
        raise BundleError("max_replicas must be 0 when may_replicate is false")

    mig = manifest["migration"]
    for key in ("hop_count", "max_hops"):
        if not isinstance(mig[key], int) or isinstance(mig[key], bool) or mig[key] < 0:
            raise BundleError(f"migration.{key} must be a non-negative integer")
    if mig["hop_count"] > mig["max_hops"]:
        raise BundleError(f"hop_count {mig['hop_count']} exceeds max_hops {mig['max_hops']}")


def _validate_entrypoint(entrypoint: str) -> None:
    if not isinstance(entrypoint, str) or not entrypoint:
        raise BundleError("runtime.entrypoint must be a non-empty string")
    path = Path(entrypoint)
    if path.is_absolute() or entrypoint.startswith("/") or entrypoint.startswith("\\"):
        raise BundleError(f"entrypoint must be relative to the bundle root: {entrypoint!r}")
    if ".." in path.parts:
        raise BundleError(f"entrypoint may not traverse upward: {entrypoint!r}")


def check_identity_continuity(previous: dict, current: dict) -> None:
    """agent.id is immutable across hops; owner_pubkey may not change either.

    Called by a node that has seen this agent before. A bundle whose id
    changed mid-journey is a different agent wearing the old one's history.
    """
    if previous["agent"]["id"] != current["agent"]["id"]:
        raise BundleError("agent.id changed between hops")
    if previous["agent"]["owner_pubkey"] != current["agent"]["owner_pubkey"]:
        raise BundleError("agent.owner_pubkey changed between hops")
    if current["migration"]["hop_count"] <= previous["migration"]["hop_count"]:
        raise BundleError("hop_count did not advance")


# --------------------------------------------------------------------------
# Pack
# --------------------------------------------------------------------------


def pack(agent_dir: Path, out_path: Path, keypair: Keypair, *, manifest: dict | None = None) -> Path:
    """Seal an agent directory into a signed .claw file.

    The manifest is written last, after hashing, because the hash covers the
    manifest minus its integrity block -- so integrity is filled in from the
    hash it is about to be stored alongside.
    """
    agent_dir = Path(agent_dir)
    if not agent_dir.is_dir():
        raise BundleError(f"agent directory not found: {agent_dir}")

    if manifest is None:
        manifest_path = agent_dir / MANIFEST_NAME
        if not manifest_path.exists():
            raise BundleError(f"no manifest.json in {agent_dir} and none supplied")
        manifest = json.loads(manifest_path.read_text())

    validate_manifest(manifest)

    entrypoint = agent_dir / manifest["runtime"]["entrypoint"]
    if not entrypoint.is_file():
        raise BundleError(f"entrypoint does not exist in bundle: {manifest['runtime']['entrypoint']}")

    if manifest["agent"]["owner_pubkey"] != keypair.public_id:
        raise BundleError("manifest.agent.owner_pubkey does not match the signing key")

    # Scan before hashing: signing.py also rejects symlinks, but reaching it
    # first would surface a SigningError for what is really a malformed bundle.
    for path in agent_dir.rglob("*"):
        if path.is_symlink():
            raise BundleError(f"symlink in agent directory: {path.relative_to(agent_dir)}")

    manifest = json.loads(json.dumps(manifest))  # defensive copy
    manifest["integrity"] = {}

    state_hash = compute_state_hash(agent_dir)
    bundle_hash = compute_bundle_hash(agent_dir, manifest)
    manifest["integrity"] = {
        "state_hash": state_hash,
        "bundle_hash": bundle_hash,
        "signature": sign_hash(keypair, bundle_hash),
        "signed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(agent_dir.rglob("*")):
            if path.is_symlink():
                raise BundleError(f"symlink in agent directory: {path.relative_to(agent_dir)}")
            if not path.is_file():
                continue
            rel = path.relative_to(agent_dir).as_posix()
            if rel == MANIFEST_NAME:
                continue
            archive.write(path, rel)
        archive.writestr(MANIFEST_NAME, json.dumps(manifest, indent=2, sort_keys=True))

    return out_path


# --------------------------------------------------------------------------
# Unpack
# --------------------------------------------------------------------------


def _safe_members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    """Reject path traversal, absolute paths, symlinks, and zip bombs.

    Runs over the central directory before a single byte is written to disk.
    """
    members = []
    total = 0

    for info in archive.infolist():
        name = info.filename

        if name.endswith("/"):
            continue
        if name.startswith("/") or name.startswith("\\"):
            raise BundleError(f"absolute path in archive: {name!r}")
        if ".." in Path(name).parts:
            raise BundleError(f"path traversal in archive: {name!r}")
        if ":" in name or "\\" in name:
            raise BundleError(f"illegal characters in archive path: {name!r}")

        mode = info.external_attr >> 16
        if mode & 0o170000 == 0o120000:
            raise BundleError(f"symlink in archive: {name!r}")

        total += info.file_size
        if total > MAX_UNCOMPRESSED_BYTES:
            raise BundleError("archive exceeds uncompressed size ceiling")

        members.append(info)

    if not members:
        raise BundleError("archive is empty")
    return members


def unpack(
    claw_path: Path,
    dest_dir: Path,
    trusted_keys: TrustedKeys,
    *,
    policy: NodePolicy | None = None,
    quarantine_dir: Path | None = None,
) -> dict:
    """Verify a .claw file and, only if it passes, unpack it to dest_dir.

    Returns the validated manifest. Raises QuarantinedBundle on any failure,
    with the extracted content preserved for inspection rather than deleted.
    """
    claw_path = Path(claw_path)
    dest_dir = Path(dest_dir)

    if not claw_path.is_file():
        raise BundleError(f"no such bundle: {claw_path}")
    if claw_path.stat().st_size > MAX_BUNDLE_BYTES:
        raise BundleError(f"bundle exceeds {MAX_BUNDLE_BYTES} bytes")

    staging = Path(tempfile.mkdtemp(prefix="clawp2p-verify-"))

    def quarantine(reason: str) -> QuarantinedBundle:
        if quarantine_dir is None:
            shutil.rmtree(staging, ignore_errors=True)
            return QuarantinedBundle(reason, None)
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        held = quarantine_dir / f"{claw_path.stem}-{stamp}"
        shutil.move(str(staging), str(held))
        (held / "REJECTED.txt").write_text(f"{reason}\nsource: {claw_path}\n")
        return QuarantinedBundle(reason, held)

    try:
        try:
            with zipfile.ZipFile(claw_path) as archive:
                members = _safe_members(archive)
                for info in members:
                    archive.extract(info, staging)
        except zipfile.BadZipFile as exc:
            raise BundleError(f"not a readable zip archive: {exc}") from exc

        manifest_path = staging / MANIFEST_NAME
        if not manifest_path.is_file():
            raise BundleError("bundle has no manifest.json")

        try:
            manifest = json.loads(manifest_path.read_text())
        except json.JSONDecodeError as exc:
            raise BundleError(f"manifest.json is not valid JSON: {exc}") from exc

        validate_manifest(manifest)

        integrity = manifest.get("integrity") or {}
        for key in ("state_hash", "bundle_hash", "signature", "signed_at"):
            if key not in integrity:
                raise BundleError(f"manifest missing integrity.{key}")

        owner = manifest["agent"]["owner_pubkey"]
        trusted_keys.require(owner)

        stripped = json.loads(json.dumps(manifest))
        stripped["integrity"] = {}

        recomputed = compute_bundle_hash(staging, stripped)
        if recomputed != integrity["bundle_hash"]:
            raise BundleError(
                "bundle_hash mismatch: content was modified after signing "
                f"(manifest says {integrity['bundle_hash']}, computed {recomputed})"
            )

        recomputed_state = compute_state_hash(staging)
        if recomputed_state != integrity["state_hash"]:
            raise BundleError("state_hash mismatch: agent state was modified after signing")

        verify_hash(owner, integrity["bundle_hash"], integrity["signature"])

        if policy is not None:
            policy.check(manifest)

        entrypoint = staging / manifest["runtime"]["entrypoint"]
        if not entrypoint.is_file():
            raise BundleError(f"entrypoint missing: {manifest['runtime']['entrypoint']}")

    except (BundleError, SigningError) as exc:
        raise quarantine(str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - anything unexpected is still a rejection
        raise quarantine(f"unexpected error during verification: {exc!r}") from exc

    # Verification passed. Only now does content reach an executable path.
    if dest_dir.exists():
        shutil.rmtree(dest_dir)
    dest_dir.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(staging), str(dest_dir))

    return manifest


# --------------------------------------------------------------------------
# Hop bookkeeping
# --------------------------------------------------------------------------


def record_hop(manifest: dict, *, from_node: str, to_node: str) -> dict:
    """Advance migration state. Called by the SENDING node, never by the agent.

    The agent's requested_next is cleared here: it was advisory, the sending
    node has now made the decision, and leaving it set would let the next hop
    inherit an intent that was already acted on.
    """
    manifest = json.loads(json.dumps(manifest))
    mig = manifest["migration"]

    mig["hop_count"] += 1
    mig["previous_node"] = from_node
    mig["requested_next"] = None
    if mig["origin_node"] is None:
        mig["origin_node"] = from_node

    if mig["hop_count"] > mig["max_hops"]:
        raise BundleError(f"hop_count would exceed max_hops ({mig['max_hops']})")

    return manifest


def append_history(bundle_dir: Path, line: str) -> None:
    entry = f"{datetime.now(timezone.utc).isoformat(timespec='seconds')}\t{line}\n"
    with (Path(bundle_dir) / "history.log").open("a") as handle:
        handle.write(entry)
