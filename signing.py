"""
Ed25519 signing and canonical hashing for ClawP2P bundles.

Every other module depends on the hashing rules defined here, so they are
spelled out explicitly rather than left to whatever os.walk happens to return:

  state_hash   sha256 over the state/ subtree only. Lets a node see that an
               agent's memory changed across a hop without rehashing code
               and instructions it already has.

  bundle_hash  sha256 over every file in the bundle EXCEPT manifest.json,
               combined with the manifest's own bytes minus its "integrity"
               block. The integrity block is excluded because it is where the
               hash and signature live -- including it would be circular.

  signature    Ed25519 over bundle_hash. Signing the hash rather than the
               tree means verification cost does not scale with bundle size.

Canonicalization rules (must not drift, or signatures break across versions):
  - paths are POSIX-style, relative to the bundle root, sorted bytewise
  - each entry contributes: path + NUL + len(content) + NUL + content
  - directories contribute nothing; empty dirs are not represented
  - JSON is serialized with sorted keys, no whitespace, UTF-8
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

MANIFEST_NAME = "manifest.json"
KEY_PREFIX = "ed25519:"
HASH_PREFIX = "sha256:"


class SigningError(Exception):
    """Raised for any signing or verification failure."""


# --------------------------------------------------------------------------
# Keys
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Keypair:
    private: Ed25519PrivateKey
    public: Ed25519PublicKey

    @property
    def public_id(self) -> str:
        """The 'ed25519:<base64>' string that goes in manifest.agent.owner_pubkey."""
        return encode_public_key(self.public)


def generate_keypair() -> Keypair:
    private = Ed25519PrivateKey.generate()
    return Keypair(private=private, public=private.public_key())


def encode_public_key(public: Ed25519PublicKey) -> str:
    raw = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return KEY_PREFIX + raw.hex()


def decode_public_key(encoded: str) -> Ed25519PublicKey:
    if not encoded.startswith(KEY_PREFIX):
        raise SigningError(f"public key must start with {KEY_PREFIX!r}: {encoded!r}")
    try:
        raw = bytes.fromhex(encoded[len(KEY_PREFIX):])
    except ValueError as exc:
        raise SigningError(f"public key is not valid hex: {exc}") from exc
    if len(raw) != 32:
        raise SigningError(f"Ed25519 public key must be 32 bytes, got {len(raw)}")
    return Ed25519PublicKey.from_public_bytes(raw)


def save_private_key(keypair: Keypair, path: Path, password: bytes | None = None) -> None:
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    pem = keypair.private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    path.write_bytes(pem)
    path.chmod(0o600)


def load_private_key(path: Path, password: bytes | None = None) -> Keypair:
    private = serialization.load_pem_private_key(path.read_bytes(), password=password)
    if not isinstance(private, Ed25519PrivateKey):
        raise SigningError("key file does not contain an Ed25519 private key")
    return Keypair(private=private, public=private.public_key())


# --------------------------------------------------------------------------
# Canonical hashing
# --------------------------------------------------------------------------


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _hash_tree(root: Path, *, exclude: set[str] = frozenset()) -> str:
    """Hash every regular file under root, excluding the named relative paths.

    Symlinks are a hard error rather than being followed or skipped: a bundle
    containing one is malformed, and silently ignoring it would let a sender
    hide content from the hash that the receiver's filesystem might resolve.
    """
    if not root.is_dir():
        raise SigningError(f"not a directory: {root}")

    digest = hashlib.sha256()
    entries = []

    for path in root.rglob("*"):
        if path.is_symlink():
            raise SigningError(f"symlink in bundle: {path.relative_to(root)}")
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel in exclude:
            continue
        entries.append((rel, path))

    for rel, path in sorted(entries, key=lambda pair: pair[0].encode("utf-8")):
        content = path.read_bytes()
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(content)).encode("ascii"))
        digest.update(b"\0")
        digest.update(content)

    return HASH_PREFIX + digest.hexdigest()


def compute_state_hash(bundle_root: Path) -> str:
    """Hash of the state/ subtree. Empty state hashes deterministically."""
    state_dir = bundle_root / "state"
    if not state_dir.exists():
        return HASH_PREFIX + hashlib.sha256(b"").hexdigest()
    return _hash_tree(state_dir)


def compute_bundle_hash(bundle_root: Path, manifest: dict) -> str:
    """Hash covering all bundle content plus the manifest minus its integrity block.

    The manifest passed in is used rather than the one on disk so that pack()
    can compute the hash before writing the final manifest, and verify() can
    recompute it from what it actually parsed.
    """
    tree = _hash_tree(bundle_root, exclude={MANIFEST_NAME})
    stripped = {key: value for key, value in manifest.items() if key != "integrity"}

    digest = hashlib.sha256()
    digest.update(tree.encode("ascii"))
    digest.update(b"\0")
    digest.update(canonical_json(stripped))
    return HASH_PREFIX + digest.hexdigest()


# --------------------------------------------------------------------------
# Sign / verify
# --------------------------------------------------------------------------


def sign_hash(keypair: Keypair, bundle_hash: str) -> str:
    signature = keypair.private.sign(bundle_hash.encode("ascii"))
    return KEY_PREFIX + signature.hex()


def verify_hash(public_key: str | Ed25519PublicKey, bundle_hash: str, signature: str) -> None:
    """Raise SigningError if the signature does not cover this hash."""
    key = decode_public_key(public_key) if isinstance(public_key, str) else public_key

    if not signature.startswith(KEY_PREFIX):
        raise SigningError(f"signature must start with {KEY_PREFIX!r}")
    try:
        raw = bytes.fromhex(signature[len(KEY_PREFIX):])
    except ValueError as exc:
        raise SigningError(f"signature is not valid hex: {exc}") from exc

    try:
        key.verify(raw, bundle_hash.encode("ascii"))
    except InvalidSignature as exc:
        raise SigningError("signature does not match bundle hash") from exc


class TrustedKeys:
    """A node's set of accepted signing keys.

    Deliberately explicit: there is no 'trust on first use' and no wildcard.
    A node operator adds keys they have decided to accept, and everything else
    is rejected. This is the outermost gate before any agent code is unpacked.
    """

    def __init__(self, keys: list[str] | None = None):
        self._keys: set[str] = set()
        for key in keys or []:
            self.add(key)

    def add(self, encoded: str) -> None:
        decode_public_key(encoded)  # validate before storing
        self._keys.add(encoded)

    def __contains__(self, encoded: str) -> bool:
        return encoded in self._keys

    def __len__(self) -> int:
        return len(self._keys)

    def require(self, encoded: str) -> None:
        if encoded not in self._keys:
            raise SigningError(f"signing key is not in this node's trusted set: {encoded}")

    @classmethod
    def from_file(cls, path: Path) -> "TrustedKeys":
        """One 'ed25519:<hex>' per line. Blank lines and # comments ignored."""
        keys = []
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                keys.append(line)
        return cls(keys)
