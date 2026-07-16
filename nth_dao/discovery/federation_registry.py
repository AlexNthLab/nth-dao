"""Durable registry for federation peers learned from the network.

Operator-configured seeds and automatically learned peers have different
trust semantics. A seed is explicit local configuration. A learned peer is
only a previously verified hint and must be DNS-checked, IP-pinned, and have
its signed identity card verified again before every polling cycle.

This module only owns bounded persistence. It deliberately does not perform
network I/O or turn a self-signed identity into governance trust.
"""

from __future__ import annotations

import logging
import hmac
import ipaddress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List
from urllib.parse import urlsplit, urlunsplit

from nth_dao.execution_receipt import now_ms
from nth_dao.did_key import decode_ed25519_did_key_hex, is_did_key
from nth_dao.util.io import InterProcessLock, atomic_write_json, safe_load_json


logger = logging.getLogger(__name__)

LEARNED_PEERS_VERSION = 1
DEFAULT_LEARNED_PEER_TTL_MS = 24 * 60 * 60 * 1000
DEFAULT_MAX_LEARNED_PEERS = 128
DEFAULT_MAX_PEERS_PER_NETWORK = 4
DEFAULT_MIN_REFRESH_WRITE_MS = 60_000
_MAX_TEXT = 1024


class LearnedPeerCapacityError(ValueError):
    """Raised when an unknown identity cannot displace active incumbents."""


def learned_peer_network_group(peer_url: str, resolved_ip: str = "") -> str:
    """Return a bounded admission group for Sybil-resistant peer storage."""
    normalized = normalize_learned_peer_url(peer_url)
    if resolved_ip:
        address = ipaddress.ip_address(resolved_ip)
        prefix = 24 if address.version == 4 else 64
        network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
        return f"net:{network.with_prefixlen}"
    host = (urlsplit(normalized).hostname or "").lower()
    return f"host:{host}"


def normalize_learned_peer_url(value: str) -> str:
    """Normalize an automatically learned public HTTPS peer URL."""
    raw = str(value or "").strip()
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise ValueError("learned peer URL is invalid") from exc
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("learned peer URL must be an absolute HTTPS URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("learned peer URL contains forbidden URL components")
    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("learned peer hostname is invalid") from exc
    if host == "localhost" or host.endswith(".local"):
        raise ValueError("learned peer URL must not target a local hostname")
    netloc = host
    if ":" in host and not host.startswith("["):
        netloc = f"[{host}]"
    if port is not None:
        netloc = f"{netloc}:{port}"
    path = parsed.path.rstrip("/")
    return urlunsplit(("https", netloc, path, "", "")).rstrip("/")


@dataclass(frozen=True)
class LearnedPeerRecord:
    peer_url: str
    did: str
    pubkey_hex: str
    identity_url: str
    first_seen_ms: int
    last_verified_ms: int
    expires_at_ms: int
    network_group: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Any) -> "LearnedPeerRecord":
        if not isinstance(value, dict):
            raise ValueError("learned peer record must be an object")
        peer_url = normalize_learned_peer_url(value.get("peer_url", ""))
        did = value.get("did", "")
        pubkey_hex = value.get("pubkey_hex", "")
        identity_url = value.get("identity_url", "")
        if not isinstance(did, str) or len(did) > _MAX_TEXT or not is_did_key(did):
            raise ValueError("learned peer DID is invalid")
        if (
            not isinstance(pubkey_hex, str)
            or len(pubkey_hex) != 64
            or any(ch not in "0123456789abcdefABCDEF" for ch in pubkey_hex)
        ):
            raise ValueError("learned peer public key is invalid")
        if not hmac.compare_digest(
            decode_ed25519_did_key_hex(did), pubkey_hex.lower(),
        ):
            raise ValueError("learned peer DID does not match public key")
        expected_identity_url = (
            f"{peer_url}/.well-known/nth-dao/identity.json"
        )
        if (
            not isinstance(identity_url, str)
            or len(identity_url) > _MAX_TEXT
            or identity_url != expected_identity_url
        ):
            raise ValueError("learned peer identity URL is not bound to peer URL")

        def as_non_negative_int(name: str) -> int:
            raw = value.get(name)
            if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
                raise ValueError(f"learned peer {name} is invalid")
            return raw

        first_seen_ms = as_non_negative_int("first_seen_ms")
        last_verified_ms = as_non_negative_int("last_verified_ms")
        expires_at_ms = as_non_negative_int("expires_at_ms")
        if first_seen_ms > last_verified_ms or last_verified_ms >= expires_at_ms:
            raise ValueError("learned peer timestamps are inconsistent")
        network_group = value.get("network_group", "")
        if not network_group:
            network_group = learned_peer_network_group(peer_url)
        if (
            not isinstance(network_group, str)
            or not network_group
            or len(network_group) > 128
        ):
            raise ValueError("learned peer network group is invalid")
        return cls(
            peer_url=peer_url,
            did=did,
            pubkey_hex=pubkey_hex.lower(),
            identity_url=identity_url,
            first_seen_ms=first_seen_ms,
            last_verified_ms=last_verified_ms,
            expires_at_ms=expires_at_ms,
            network_group=network_group,
        )


class LearnedPeerStore:
    """Process-safe, bounded TTL store for verified gossip peers."""

    def __init__(
        self,
        workspace: Path,
        *,
        ttl_ms: int = DEFAULT_LEARNED_PEER_TTL_MS,
        max_peers: int = DEFAULT_MAX_LEARNED_PEERS,
        max_peers_per_network: Any = None,
        min_refresh_write_ms: int = DEFAULT_MIN_REFRESH_WRITE_MS,
        clock: Callable[[], int] = now_ms,
    ) -> None:
        if ttl_ms < 60_000:
            raise ValueError("learned peer TTL must be at least 60 seconds")
        if max_peers < 1 or max_peers > 4096:
            raise ValueError("max learned peers must be between 1 and 4096")
        network_limit = (
            min(DEFAULT_MAX_PEERS_PER_NETWORK, max_peers)
            if max_peers_per_network is None
            else max_peers_per_network
        )
        if (
            type(network_limit) is not int
            or network_limit < 1
            or network_limit > max_peers
        ):
            raise ValueError("per-network peer limit must be between 1 and max peers")
        if (
            isinstance(min_refresh_write_ms, bool)
            or not isinstance(min_refresh_write_ms, int)
            or min_refresh_write_ms < 0
            or min_refresh_write_ms > ttl_ms
        ):
            raise ValueError(
                "minimum learned-peer refresh write interval must be between "
                "zero and the peer TTL"
            )
        self.path = Path(workspace) / "federation" / "learned_peers.json"
        self.ttl_ms = int(ttl_ms)
        self.max_peers = int(max_peers)
        self.max_peers_per_network = int(network_limit)
        self.min_refresh_write_ms = int(min_refresh_write_ms)
        self._clock = clock

    def _load_unlocked(self) -> Dict[str, LearnedPeerRecord]:
        raw = safe_load_json(self.path, fallback={}, log_warn=True)
        if not raw:
            return {}
        if not isinstance(raw, dict) or raw.get("version") != LEARNED_PEERS_VERSION:
            logger.warning("unsupported learned peer registry at %s", self.path)
            return {}
        values = raw.get("peers")
        if not isinstance(values, list):
            logger.warning("malformed learned peer registry at %s", self.path)
            return {}
        out: Dict[str, LearnedPeerRecord] = {}
        for item in values[: self.max_peers * 2]:
            try:
                record = LearnedPeerRecord.from_dict(item)
            except ValueError as exc:
                logger.warning("ignoring malformed learned peer record: %s", exc)
                continue
            existing = out.get(record.peer_url)
            if existing is None or record.last_verified_ms > existing.last_verified_ms:
                out[record.peer_url] = record
        return out

    def _write_unlocked(self, records: Dict[str, LearnedPeerRecord]) -> None:
        ordered = sorted(
            records.values(),
            key=lambda item: (item.last_verified_ms, item.peer_url),
            reverse=True,
        )[: self.max_peers]
        atomic_write_json(
            self.path,
            {
                "version": LEARNED_PEERS_VERSION,
                "peers": [item.to_dict() for item in ordered],
            },
        )

    def active(self, *, now_ms_override: int = 0) -> List[LearnedPeerRecord]:
        current = int(now_ms_override or self._clock())
        records = self._load_unlocked().values()
        return sorted(
            (item for item in records if item.expires_at_ms > current),
            key=lambda item: (item.last_verified_ms, item.peer_url),
            reverse=True,
        )[: self.max_peers]

    def upsert_verified(
        self,
        peer_url: str,
        identity_metadata: Dict[str, Any],
        *,
        now_ms_override: int = 0,
        resolved_ip: str = "",
    ) -> LearnedPeerRecord:
        """Persist metadata only after the caller verified the identity card."""
        normalized = normalize_learned_peer_url(peer_url)
        if not isinstance(identity_metadata, dict):
            raise ValueError("verified identity metadata is required")
        metadata_peer = normalize_learned_peer_url(
            str(identity_metadata.get("peer_url") or "")
        )
        if normalized != metadata_peer:
            raise ValueError("verified identity metadata is bound to another peer")
        did = identity_metadata.get("did", "")
        pubkey_hex = identity_metadata.get("pubkey_hex", "")
        identity_url = identity_metadata.get("identity_url", "")
        current = int(now_ms_override or self._clock())
        candidate = LearnedPeerRecord.from_dict(
            {
                "peer_url": normalized,
                "did": did,
                "pubkey_hex": pubkey_hex,
                "identity_url": identity_url,
                "first_seen_ms": current,
                "last_verified_ms": current,
                "expires_at_ms": current + self.ttl_ms,
                "network_group": learned_peer_network_group(
                    normalized, resolved_ip,
                ),
            }
        )
        with InterProcessLock(self.path, timeout=5.0):
            records = self._load_unlocked()
            # Expired records do not own capacity. Active records are grouped
            # by network so a full registry can admit a new network without
            # letting one densely represented network crowd out diversity.
            records = {
                url: item
                for url, item in records.items()
                if item.expires_at_ms > current
            }
            existing = records.get(normalized)
            same_identity = [
                item for item in records.values() if item.did == candidate.did
            ]
            same_network = [
                item for item in records.values()
                if item.network_group == candidate.network_group
                and item.did != candidate.did
            ]
            if (
                existing is not None
                and existing.did == candidate.did
                and hmac.compare_digest(
                    existing.pubkey_hex, candidate.pubkey_hex,
                )
                and current <= (
                    existing.last_verified_ms + self.min_refresh_write_ms
                )
            ):
                return existing
            if existing is None and len(same_network) >= self.max_peers_per_network:
                raise LearnedPeerCapacityError(
                    "learned peer per-network capacity is full"
                )
            if (
                existing is None
                and not same_identity
                and len(records) >= self.max_peers
            ):
                network_counts: Dict[str, int] = {}
                for item in records.values():
                    network_counts[item.network_group] = (
                        network_counts.get(item.network_group, 0) + 1
                    )
                eviction_pool = list(records.values())
                if candidate.network_group in network_counts:
                    eviction_pool = [
                        item for item in eviction_pool
                        if item.network_group == candidate.network_group
                    ]
                victim = min(
                    eviction_pool,
                    key=lambda item: (
                        -network_counts[item.network_group],
                        item.last_verified_ms,
                        item.first_seen_ms,
                        item.peer_url,
                    ),
                )
                records.pop(victim.peer_url, None)
            if existing is not None and existing.did == candidate.did:
                identity_history = same_identity or [existing]
            elif same_identity:
                identity_history = same_identity
            else:
                identity_history = []
            first_seen = (
                min(item.first_seen_ms for item in identity_history)
                if identity_history
                else current
            )
            verified_at = max(
                [current] + [item.last_verified_ms for item in identity_history]
            )
            # One DID represents one node identity. A newly verified endpoint
            # supersedes older endpoints for the same DID.
            records = {
                url: item
                for url, item in records.items()
                if item.did != candidate.did or url == normalized
            }
            record = LearnedPeerRecord(
                peer_url=candidate.peer_url,
                did=candidate.did,
                pubkey_hex=candidate.pubkey_hex,
                identity_url=candidate.identity_url,
                first_seen_ms=first_seen,
                last_verified_ms=verified_at,
                expires_at_ms=verified_at + self.ttl_ms,
                network_group=candidate.network_group,
            )
            records[normalized] = record
            self._write_unlocked(records)
        return record

    def prune(self, *, now_ms_override: int = 0) -> int:
        current = int(now_ms_override or self._clock())
        with InterProcessLock(self.path, timeout=5.0):
            records = self._load_unlocked()
            active = {
                url: item
                for url, item in records.items()
                if item.expires_at_ms > current
            }
            removed = len(records) - len(active)
            if removed:
                self._write_unlocked(active)
        return removed
