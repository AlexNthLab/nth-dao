"""Trust-Kernel network endpoint value objects for built-in plugins."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from nth_dao.did_key import is_did_key
from nth_dao.federation_transport import validate_configured_peer_ip


def _public_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("verified peer resolved_ip must be an IP address") from exc
    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        raise ValueError("verified peer resolved_ip must be globally routable")
    return str(address)


def _configured_ip(value: str) -> str:
    try:
        return validate_configured_peer_ip(value)
    except ValueError as exc:
        raise ValueError("configured peer resolved_ip is not allowed") from exc


def normalize_peer_url(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("verified peer URL must be text")
    parts = urlsplit(value.strip())
    if (
        parts.scheme not in {"http", "https"}
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or parts.path not in {"", "/"}
    ):
        raise ValueError("verified peer URL must be an HTTP(S) origin")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("verified peer URL port is invalid") from exc
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    netloc = f"{host}:{port}" if port is not None else host
    return urlunsplit((parts.scheme.lower(), netloc, "", "", ""))


@dataclass(frozen=True)
class VerifiedPeerEndpoint:
    """A short-lived DID and DNS/IP binding produced by the Trust Kernel."""

    url: str
    did: str
    resolved_ip: str
    verified_at_ms: int
    expires_at_ms: int
    network_scope: str = "public"

    def __post_init__(self) -> None:
        object.__setattr__(self, "url", normalize_peer_url(self.url))
        if not isinstance(self.did, str) or not is_did_key(self.did):
            raise ValueError("verified peer did must be an Ed25519 did:key")
        if self.network_scope not in {"public", "configured"}:
            raise ValueError("verified peer network_scope is invalid")
        if self.network_scope == "public" and urlsplit(self.url).scheme != "https":
            raise ValueError("public verified peer URL must use HTTPS")
        validate_ip = _public_ip if self.network_scope == "public" else _configured_ip
        object.__setattr__(self, "resolved_ip", validate_ip(self.resolved_ip))
        if type(self.verified_at_ms) is not int or type(self.expires_at_ms) is not int:
            raise TypeError("verified peer timestamps must be integers")
        if self.verified_at_ms < 0 or not self.verified_at_ms < self.expires_at_ms:
            raise ValueError("verified peer validity window is invalid")
        if self.expires_at_ms - self.verified_at_ms > 3_600_000:
            raise ValueError("verified peer validity cannot exceed one hour")

    def require_current(self, now_ms: int) -> None:
        if type(now_ms) is not int or now_ms < 0:
            raise ValueError("current time must be a non-negative integer")
        if now_ms < self.verified_at_ms - 30_000:
            raise ValueError("verified peer binding is not active yet")
        if now_ms >= self.expires_at_ms:
            raise ValueError("verified peer binding has expired")


__all__ = ["VerifiedPeerEndpoint", "normalize_peer_url"]
