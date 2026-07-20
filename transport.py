"""
transport.py — Bundle transfer between ClawP2P nodes.

This module moves .claw files between nodes. It does NOT verify bundles —
that is always the receiving node's responsibility via bundle.unpack().
A node that trusts transport.py to pre-verify before calling unpack() has
a security hole: the transport path is untrusted by definition.

The receiving node calls bundle.unpack() on everything it receives,
regardless of whether it came from transport.send_bundle() or the HTTP API
directly. Transport is just delivery.

MVP: direct HTTP (no DHT, no relay). Two nodes exchange addresses out of band.
Next: libp2p DHT discovery replaces the hardcoded address.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

# Retry config for transient failures (network blip, node restart)
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 2.0   # seconds; doubles each retry
CONNECT_TIMEOUT = 10       # seconds to establish TCP
READ_TIMEOUT = 120         # seconds to wait for the node to accept + respond

# Upper bound on bundle size we'll attempt to send. The receiving node has
# its own ceiling in bundle.MAX_BUNDLE_BYTES; this is a client-side guard.
MAX_SEND_BYTES = 256 * 1024 * 1024


class TransportError(Exception):
    """Raised when a bundle cannot be delivered after all retries."""


def _node_url(address: str) -> str:
    """Normalize a node address to an HTTP URL.

    Accepts:
      host:port          → http://host:port
      http://host:port   → unchanged
      https://host:port  → unchanged
    """
    if address.startswith(("http://", "https://")):
        return address.rstrip("/")
    return f"http://{address}"


def send_bundle(claw_path: Path, target_address: str) -> dict:
    """Send a .claw bundle to a remote node and return the run metadata.

    target_address is host:port or a full URL. The target node is expected
    to return a 202 with run metadata on success.

    Raises TransportError if the bundle cannot be delivered after MAX_RETRIES.
    Does not quarantine on the sending side — the receiving node quarantines.
    """
    claw_path = Path(claw_path)
    if not claw_path.is_file():
        raise TransportError(f"bundle file does not exist: {claw_path}")

    size = claw_path.stat().st_size
    if size > MAX_SEND_BYTES:
        raise TransportError(
            f"bundle is {size} bytes, exceeds send ceiling of {MAX_SEND_BYTES}"
        )

    url = f"{_node_url(target_address)}/bundle"
    last_exc: Exception | None = None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            logger.info(
                "sending bundle %s to %s (attempt %d/%d, %d bytes)",
                claw_path.name, target_address, attempt, MAX_RETRIES, size,
            )
            with claw_path.open("rb") as fh:
                resp = requests.post(
                    url,
                    data=fh,
                    headers={"Content-Type": "application/octet-stream"},
                    timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                )

            if resp.status_code == 202:
                result = resp.json()
                logger.info(
                    "bundle accepted by %s: run_id=%s agent=%s hop=%d",
                    target_address,
                    result.get("run_id"),
                    result.get("agent_name"),
                    result.get("hop", -1),
                )
                return result

            if resp.status_code == 400:
                # Verification failure at the receiving node — don't retry,
                # the bundle won't pass on subsequent attempts either.
                try:
                    detail = resp.json()
                except Exception:
                    detail = {"raw": resp.text[:512]}
                reason = detail.get("reason") or detail.get("error") or resp.text[:256]
                raise TransportError(
                    f"node {target_address} rejected bundle: {reason}"
                )

            # 5xx or unexpected — worth retrying
            logger.warning(
                "node %s returned %d (attempt %d/%d): %s",
                target_address, resp.status_code, attempt, MAX_RETRIES, resp.text[:256],
            )
            last_exc = TransportError(
                f"node returned {resp.status_code}: {resp.text[:256]}"
            )

        except requests.exceptions.ConnectionError as exc:
            logger.warning(
                "connection failed to %s (attempt %d/%d): %s",
                target_address, attempt, MAX_RETRIES, exc,
            )
            last_exc = TransportError(f"connection failed: {exc}")

        except requests.exceptions.Timeout as exc:
            logger.warning(
                "timeout sending to %s (attempt %d/%d): %s",
                target_address, attempt, MAX_RETRIES, exc,
            )
            last_exc = TransportError(f"timeout: {exc}")

        if attempt < MAX_RETRIES:
            wait = RETRY_BACKOFF_BASE ** attempt
            logger.info("retrying in %.1fs", wait)
            time.sleep(wait)

    raise TransportError(
        f"failed to deliver bundle to {target_address} after {MAX_RETRIES} attempts: {last_exc}"
    )


def fetch_policy(node_address: str) -> dict:
    """Fetch the policy from a remote node.

    An agent or a sending node calls this before deciding whether to hop there.
    Returns the policy dict on success. Raises TransportError on failure.

    Not used for security decisions — the receiving node enforces its own
    policy on the incoming bundle regardless of what we fetched here.
    """
    url = f"{_node_url(node_address)}/policy"
    try:
        resp = requests.get(url, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as exc:
        raise TransportError(f"could not fetch policy from {node_address}: {exc}") from exc


def fetch_status(node_address: str) -> dict:
    """Fetch the status of a remote node.

    Returns the status dict on success. Raises TransportError on failure.
    """
    url = f"{_node_url(node_address)}/status"
    try:
        resp = requests.get(url, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as exc:
        raise TransportError(f"could not fetch status from {node_address}: {exc}") from exc


def probe_node(node_address: str) -> bool:
    """Return True if the node is reachable and responsive, False otherwise.

    Used by agents and the discovery layer to filter candidate nodes before
    committing to a hop.
    """
    try:
        fetch_status(node_address)
        return True
    except TransportError:
        return False
