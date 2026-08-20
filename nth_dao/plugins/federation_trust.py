"""Reviewed trust kernel for signed NTH DAO federation identity cards.

This module is deliberately small enough to bind into a built-in plugin's
artifact digest.  Discovery hints and HTTP responses remain untrusted until
this kernel has bound a signed DID card to both the advertised origin and a
short-lived, globally routable IP address.
"""

from __future__ import annotations

import hmac
import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlsplit, urlunsplit

from nth_dao.federation_transport import (
    get_configured_peer_bytes_pinned,
    get_https_bytes_pinned,
    resolve_configured_peer_ip,
    resolve_safe_public_https_ip,
)
from nth_dao.plugins.network import VerifiedPeerEndpoint, normalize_peer_url


FEDERATION_TRUST_API_VERSION = "1.0.0"
FEDERATION_IDENTITY_CARD_KIND = "nth-dao-identity-card-v1"
FEDERATION_PROTOCOL = "nth-dao-federation-v1"
MAX_FEDERATION_IDENTITY_CARD_BYTES = 64 * 1024
MAX_FEDERATION_IDENTITY_TEXT = 256
_BINDING_TTL_MS = 300_000


@dataclass(frozen=True)
class VerifiedFederationIdentity:
    """A fresh endpoint binding plus metadata safe for learned-peer storage."""

    endpoint: VerifiedPeerEndpoint
    pubkey_hex: str
    identity_url: str
    card_kind: str
    federation_protocol: str

    def learned_metadata(self) -> Dict[str, Any]:
        return {
            "peer_url": self.endpoint.url,
            "did": self.endpoint.did,
            "pubkey_hex": self.pubkey_hex,
            "identity_url": self.identity_url,
            "card_kind": self.card_kind,
            "federation_protocol": self.federation_protocol,
        }


def normalize_federation_peer_url(value: str) -> str:
    """Normalize one HTTP(S) base URL used by the identity-card protocol."""

    if not isinstance(value, str):
        raise TypeError("peer_url must be text")
    raw = value.strip()
    if not raw:
        raise ValueError("peer_url is required")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("peer_url is not a valid URL") from exc
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("peer_url must start with http:// or https://")
    if not parsed.hostname:
        raise ValueError("peer_url must include a host")
    if parsed.username or parsed.password:
        raise ValueError("peer_url must not include credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("peer_url must not include query or fragment")
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    netloc = f"{host}:{port}" if port is not None else host
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme.lower(), netloc, path, "", "")).rstrip("/")


class _RejectFederationRedirect(urllib.request.HTTPRedirectHandler):
    """Identity verification never follows an origin-changing redirect."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def open_federation_identity_card(
    url: str,
    timeout_seconds: float,
    resolved_ip: str = "",
    *,
    public_https_only: bool = False,
) -> bytes:
    """Fetch one bounded card, optionally pinned to a prevalidated IP."""

    if resolved_ip:
        fetch = (
            get_https_bytes_pinned
            if public_https_only
            else get_configured_peer_bytes_pinned
        )
        return fetch(
            url,
            resolved_ip,
            timeout_s=timeout_seconds,
            max_bytes=MAX_FEDERATION_IDENTITY_CARD_BYTES,
        )
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json"},
        method="GET",
    )
    opener = urllib.request.build_opener(_RejectFederationRedirect())
    with opener.open(request, timeout=timeout_seconds) as response:  # noqa: S310
        body = response.read(MAX_FEDERATION_IDENTITY_CARD_BYTES + 1)
    if len(body) > MAX_FEDERATION_IDENTITY_CARD_BYTES:
        raise ValueError("identity card exceeds 64 KiB limit")
    return body


def verify_federation_identity_card(
    peer_url: str,
    card: Any,
    *,
    expected_challenge: str | None = None,
) -> tuple[Optional[Dict[str, Any]], str]:
    """Verify card signature, DID/key consistency, origin, and challenge.

    Success proves key control and card self-consistency.  It is not a
    governance endorsement and does not establish that the peer is honest.
    """

    try:
        normalized_peer = normalize_federation_peer_url(peer_url)
    except (TypeError, ValueError) as exc:
        return None, str(exc)
    if not isinstance(card, dict):
        return None, "identity card must be a JSON object"
    if card.get("kind") != FEDERATION_IDENTITY_CARD_KIND:
        return None, "unsupported identity card kind"

    pubkey_hex = card.get("pubkey_hex")
    did = card.get("did")
    signature_hex = card.get("sig")
    if (
        not isinstance(pubkey_hex, str)
        or re.fullmatch(r"[0-9a-fA-F]{64}", pubkey_hex) is None
    ):
        return None, "identity card pubkey_hex is not an Ed25519 key"
    if not isinstance(did, str) or len(did) > MAX_FEDERATION_IDENTITY_TEXT:
        return None, "identity card did is missing or too long"
    if (
        not isinstance(signature_hex, str)
        or re.fullmatch(r"[0-9a-fA-F]{128}", signature_hex) is None
    ):
        return None, "identity card signature is malformed"

    try:
        from nacl.exceptions import BadSignatureError
        from nacl.signing import VerifyKey

        from nth_dao.did_key import decode_ed25519_did_key_hex, is_did_key
        from nth_dao.identity import canonical_json
    except ImportError:
        return None, "identity card signature verification is unavailable"

    try:
        if not is_did_key(did):
            return None, "identity card did is not a did:key Ed25519 identifier"
        did_pubkey_hex = decode_ed25519_did_key_hex(did)
        if not hmac.compare_digest(did_pubkey_hex.lower(), pubkey_hex.lower()):
            return None, "identity card did does not match pubkey_hex"
        unsigned = dict(card)
        unsigned.pop("sig", None)
        VerifyKey(bytes.fromhex(pubkey_hex)).verify(
            canonical_json(unsigned),
            bytes.fromhex(signature_hex),
        )
    except (BadSignatureError, TypeError, ValueError) as exc:
        return None, f"identity card signature verification failed: {exc}"

    federation = card.get("federation")
    if not isinstance(federation, dict):
        return None, "identity card has no federation directory"
    if federation.get("protocol") != FEDERATION_PROTOCOL:
        return None, "unsupported federation protocol"
    if federation.get("enabled") is not True:
        return None, "peer federation is not enabled"
    try:
        claimed_peer = normalize_federation_peer_url(
            str(federation.get("peer_url") or "")
        )
    except (TypeError, ValueError):
        return None, "identity card federation.peer_url is invalid"
    if claimed_peer != normalized_peer:
        return None, "identity card federation.peer_url does not match discovery"
    if "base_url" in card:
        try:
            card_base = normalize_federation_peer_url(str(card["base_url"]))
        except (TypeError, ValueError):
            return None, "identity card base_url is invalid"
        if card_base != normalized_peer:
            return None, "identity card base_url does not match discovery"

    challenge_present = "challenge" in card
    challenge = card.get("challenge", "")
    if expected_challenge is None:
        if challenge_present:
            return None, "identity card returned an unsolicited challenge"
    elif (
        not isinstance(expected_challenge, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_challenge) is None
    ):
        return None, "expected identity challenge is invalid"
    elif (
        not isinstance(challenge, str)
        or re.fullmatch(r"[0-9a-f]{64}", challenge) is None
        or not hmac.compare_digest(challenge, expected_challenge)
    ):
        return None, "identity card challenge did not match"

    return {
        "peer_url": normalized_peer,
        "identity_url": f"{normalized_peer}/.well-known/nth-dao/identity.json",
        "did": did,
        "pubkey_hex": pubkey_hex.lower(),
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "card_kind": FEDERATION_IDENTITY_CARD_KIND,
        "federation_protocol": FEDERATION_PROTOCOL,
    }, ""


def fetch_and_verify_federation_identity(
    peer_url: str,
    *,
    timeout_seconds: float,
    expected_did: str = "",
    resolved_ip: str = "",
    public_https_only: bool = False,
) -> tuple[Optional[Dict[str, Any]], str]:
    """Fetch and verify the identity card for one peer origin."""

    try:
        normalized_peer = normalize_federation_peer_url(peer_url)
        card_url = f"{normalized_peer}/.well-known/nth-dao/identity.json"
        raw = open_federation_identity_card(
            card_url,
            timeout_seconds,
            resolved_ip,
            public_https_only=public_https_only,
        )
        def reject_duplicates(pairs):
            document = {}
            for key, value in pairs:
                if key in document:
                    raise ValueError(f"identity card repeats field {key!r}")
                document[key] = value
            return document

        card = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
        )
    except (
        OSError,
        urllib.error.URLError,
        TimeoutError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as exc:
        return None, f"identity card fetch failed: {type(exc).__name__}: {exc}"
    metadata, error = verify_federation_identity_card(normalized_peer, card)
    if metadata is not None and expected_did and not hmac.compare_digest(
        str(metadata.get("did") or ""),
        str(expected_did).strip(),
    ):
        return None, "identity card did does not match discovery record"
    return metadata, error


class FederationTrustKernel:
    """Versioned production verifier used by the built-in discovery plugin."""

    api_version = FEDERATION_TRUST_API_VERSION

    def verify_seed_identity(
        self,
        peer_url: str,
        *,
        timeout_seconds: float = 5.0,
        public_https_only: bool = True,
    ) -> Optional[VerifiedFederationIdentity]:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 0.25 <= float(timeout_seconds) <= 10.0
        ):
            raise ValueError("federation identity timeout must be between 0.25 and 10")
        deadline = time.monotonic() + float(timeout_seconds)
        normalized = normalize_peer_url(peer_url)
        resolver = (
            resolve_safe_public_https_ip
            if public_https_only
            else resolve_configured_peer_ip
        )
        resolved_ip = resolver(
            normalized,
            timeout_s=min(1.0, float(timeout_seconds)),
        )
        if resolved_ip is None:
            return None
        remaining = deadline - time.monotonic()
        if remaining < 0.05:
            return None
        metadata, _error = fetch_and_verify_federation_identity(
            normalized,
            timeout_seconds=remaining,
            resolved_ip=resolved_ip,
            public_https_only=public_https_only,
        )
        if metadata is None:
            return None
        now = int(datetime.now(timezone.utc).timestamp() * 1000)
        endpoint = VerifiedPeerEndpoint(
            url=normalized,
            did=str(metadata["did"]),
            resolved_ip=resolved_ip,
            verified_at_ms=now,
            expires_at_ms=now + _BINDING_TTL_MS,
            network_scope="public" if public_https_only else "configured",
        )
        return VerifiedFederationIdentity(
            endpoint=endpoint,
            pubkey_hex=str(metadata["pubkey_hex"]),
            identity_url=str(metadata["identity_url"]),
            card_kind=str(metadata["card_kind"]),
            federation_protocol=str(metadata["federation_protocol"]),
        )

    def verify_seed(self, peer_url: str) -> Optional[VerifiedPeerEndpoint]:
        verified = self.verify_seed_identity(peer_url)
        return verified.endpoint if verified is not None else None

    def verify_public_hint_identity(
        self,
        peer_url: str,
        *,
        timeout_seconds: float = 5.0,
    ) -> Optional[VerifiedFederationIdentity]:
        """Verify an untrusted registry/gossip hint as public HTTPS only."""

        return self.verify_seed_identity(
            peer_url,
            timeout_seconds=timeout_seconds,
            public_https_only=True,
        )

    def verify_configured_seed(
        self,
        peer_url: str,
    ) -> Optional[VerifiedPeerEndpoint]:
        """Verify an operator-selected HTTP(S) or private-LAN seed."""

        verified = self.verify_seed_identity(
            peer_url,
            public_https_only=False,
        )
        return verified.endpoint if verified is not None else None

    def verify_gossip(self, peer_url: str, resolved_ip: str) -> Optional[str]:
        normalized = normalize_peer_url(peer_url)
        metadata, _error = fetch_and_verify_federation_identity(
            normalized,
            timeout_seconds=5.0,
            resolved_ip=resolved_ip,
            public_https_only=True,
        )
        if metadata is None:
            return None
        now = int(datetime.now(timezone.utc).timestamp() * 1000)
        endpoint = VerifiedPeerEndpoint(
            url=normalized,
            did=str(metadata["did"]),
            resolved_ip=resolved_ip,
            verified_at_ms=now,
            expires_at_ms=now + _BINDING_TTL_MS,
        )
        return endpoint.did


__all__ = [
    "FEDERATION_IDENTITY_CARD_KIND",
    "FEDERATION_PROTOCOL",
    "FEDERATION_TRUST_API_VERSION",
    "FederationTrustKernel",
    "MAX_FEDERATION_IDENTITY_CARD_BYTES",
    "MAX_FEDERATION_IDENTITY_TEXT",
    "VerifiedFederationIdentity",
    "fetch_and_verify_federation_identity",
    "normalize_federation_peer_url",
    "open_federation_identity_card",
    "verify_federation_identity_card",
]
