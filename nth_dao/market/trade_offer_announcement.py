"""Verified discovery bridge for signed Trade Offer v2 documents.

The announcement is a short-lived discovery hint. It never replaces the
content-addressed Offer and does not prove availability, settlement, or price.
Consumers must fetch the exact Offer bytes and verify this binding again.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from nth_dao.canonical_json import canonical_json
from nth_dao.execution_receipt import now_ms
from nth_dao.identity import AgentIdentity
from nth_dao.market.announcement import (
    NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1,
    TaskAnnouncement,
    sign_announcement,
    verify_announcement,
)
from nth_dao.trade_rules.offer import (
    TradeOffer,
    offer_digest,
    verify_offer_successor,
)

_TIMESTAMP = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$"
)
_RESERVED_AVAILABILITY_FIELDS = frozenset({"offer_id", "revision", "state"})
MAX_TRADE_OFFER_ANNOUNCEMENT_TTL_MS = 24 * 60 * 60 * 1_000
TRADE_OFFER_HEAD_PROOF_KIND_V1 = "nth-trade-offer-head-proof-v1"
MAX_TRADE_OFFER_HEAD_PROOF_REVISIONS = 64
MAX_TRADE_OFFER_HEAD_PROOF_BYTES = 512 * 1024
MAX_TRADE_OFFER_HEAD_PROOF_CLOCK_SKEW_MS = 5 * 60 * 1_000


def trade_offer_uri(digest: str) -> str:
    """Return the only v1 federation route for an exact Trade Offer."""
    if (
        not isinstance(digest, str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
    ):
        raise ValueError("Trade Offer digest must be lowercase sha256")
    return f"/api/v2/trade/federation/offers/{digest}"


def trade_offer_head_proof_uri(digest: str) -> str:
    """Return the derived v1 route for an Offer's signed head proof bundle."""

    return f"{trade_offer_uri(digest)}/head-proof"


def _timestamp_ms(
    value: str,
    *,
    label: str,
    round_up: bool = False,
) -> int:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a UTC RFC3339 timestamp")
    match = _TIMESTAMP.fullmatch(value)
    if match is None:
        raise ValueError(f"{label} must be a UTC RFC3339 timestamp")
    try:
        base = datetime.strptime(
            match.group(1), "%Y-%m-%dT%H:%M:%S"
        ).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError(f"{label} is not a real timestamp") from exc
    fraction_ns = int((match.group(2) or "").ljust(9, "0") or "0")
    milliseconds, remainder_ns = divmod(fraction_ns, 1_000_000)
    return (
        int(base.timestamp()) * 1_000
        + milliseconds
        + (1 if round_up and remainder_ns else 0)
    )


def _verified_offer(value: TradeOffer | dict[str, Any]) -> TradeOffer:
    return (
        TradeOffer.from_json(value.canonical_bytes)
        if isinstance(value, TradeOffer)
        else TradeOffer.from_dict(value)
    )


def create_trade_offer_announcement(
    publisher: AgentIdentity,
    offer: TradeOffer | dict[str, Any],
    *,
    capability_set: Iterable[str] = (),
    availability_summary: dict[str, Any] | None = None,
    announcement_id: str = "",
    published_at_ms: int | None = None,
    not_after_ms: int | None = None,
) -> TaskAnnouncement:
    """Sign a bounded, short-lived discovery summary for one exact Offer."""
    verified = _verified_offer(offer)
    document = verified.to_dict()
    if publisher.as_did() != document["publisher_did"]:
        raise ValueError("announcement signer does not match Offer publisher")
    if document["state"] != "active":
        raise ValueError("only an active Trade Offer can be announced")
    if document["not_after"] is None:
        raise ValueError("federated Trade Offer announcement requires expiry")
    offer_published_ms = _timestamp_ms(
        document["published_at"],
        label="Offer published_at",
        round_up=True,
    )
    offer_expiry_ms = _timestamp_ms(
        document["not_after"], label="Offer not_after"
    )
    announced_ms = (
        int(datetime.now(timezone.utc).timestamp() * 1_000)
        if published_at_ms is None
        else published_at_ms
    )
    if (
        isinstance(announced_ms, bool)
        or not isinstance(announced_ms, int)
    ):
        raise ValueError("announcement publication must be an integer timestamp")
    if announced_ms < offer_published_ms:
        raise ValueError("announcement must not predate the Trade Offer")
    default_expiry_ms = min(
        offer_expiry_ms,
        announced_ms + MAX_TRADE_OFFER_ANNOUNCEMENT_TTL_MS,
    )
    expires_ms = default_expiry_ms if not_after_ms is None else not_after_ms
    if (
        isinstance(expires_ms, bool)
        or not isinstance(expires_ms, int)
    ):
        raise ValueError("announcement expiry must be an integer timestamp")
    if expires_ms <= announced_ms or expires_ms > offer_expiry_ms:
        raise ValueError(
            "announcement expiry must follow publication and not outlive the Offer"
        )
    if expires_ms - announced_ms > MAX_TRADE_OFFER_ANNOUNCEMENT_TTL_MS:
        raise ValueError("Trade Offer announcement lifetime exceeds 24 hours")
    availability = dict(availability_summary or {})
    if _RESERVED_AVAILABILITY_FIELDS & set(availability):
        raise ValueError("availability summary overrides reserved Offer fields")
    availability.update(
        {
            "offer_id": document["offer_id"],
            "revision": document["revision"],
            "state": document["state"],
        }
    )
    digest = offer_digest(verified)
    announcement = sign_announcement(
        publisher=publisher,
        title=document["title"],
        description=document["summary"],
        capability_set=list(capability_set),
        context="trade",
        reward_minor=0,
        reward_asset="exchange",
        announcement_id=announcement_id,
        published_at_ms=announced_ms,
        not_after=expires_ms,
        kind=NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1,
        listing_type="exchange",
        offer_digest=digest,
        offer_uri=trade_offer_uri(digest),
        price_minor=0,
        price_asset="",
        availability_summary=availability,
    )
    ok, reason = verify_trade_offer_announcement_binding(
        verified, announcement
    )
    if not ok:
        raise ValueError(f"Trade Offer announcement rejected: {reason}")
    return announcement


def verify_trade_offer_announcement_binding(
    offer: TradeOffer | dict[str, Any],
    announcement: TaskAnnouncement,
) -> tuple[bool, str]:
    """Bind a signed discovery hint back to the exact signed Trade Offer."""
    try:
        verified = _verified_offer(offer)
        document = verified.to_dict()
        digest = offer_digest(verified)
    except (TypeError, ValueError) as exc:
        return False, f"Trade Offer verification failed: {exc}"
    ok, reason = verify_announcement(announcement)
    if not ok:
        return False, f"announcement verification failed: {reason}"
    if announcement.kind != NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1:
        return False, "announcement is not a Trade Offer discovery hint"
    expected = {
        "publisher_did": document["publisher_did"],
        "authority_did": document["publisher_did"],
        "title": document["title"],
        "description": document["summary"],
        "context": "trade",
        "listing_type": "exchange",
        "offer_digest": digest,
        "offer_uri": trade_offer_uri(digest),
        "price_minor": 0,
        "price_asset": "",
        "reward_minor": 0,
        "reward_asset": "exchange",
    }
    for field, value in expected.items():
        if getattr(announcement, field) != value:
            return False, f"Trade Offer announcement binding mismatch: {field}"
    if document["state"] != "active" or document["not_after"] is None:
        return False, "announced Trade Offer is not active and expiring"
    offer_published_ms = _timestamp_ms(
        document["published_at"],
        label="Offer published_at",
        round_up=True,
    )
    offer_expiry_ms = _timestamp_ms(
        document["not_after"], label="Offer not_after"
    )
    if announcement.published_at_ms < offer_published_ms:
        return False, "announcement predates the Trade Offer"
    if (
        announcement.not_after <= announcement.published_at_ms
        or announcement.not_after > offer_expiry_ms
    ):
        return False, "announcement expiry is outside the Trade Offer lifetime"
    if (
        announcement.not_after - announcement.published_at_ms
        > MAX_TRADE_OFFER_ANNOUNCEMENT_TTL_MS
    ):
        return False, "Trade Offer announcement lifetime exceeds 24 hours"
    availability = announcement.availability_summary
    if not isinstance(availability, dict):
        return False, "availability summary is not an object"
    for field in _RESERVED_AVAILABILITY_FIELDS:
        if availability.get(field) != document[field]:
            return False, f"availability summary does not bind {field}"
    return True, "ok"


@dataclass(frozen=True, init=False)
class VerifiedTradeOfferHeadProof:
    """Immutable, bounded proof of one publisher-claimed Offer head.

    The wrapper is not separately signed. Authority comes from the short-lived
    signed announcement and every signed Offer revision. The proof establishes
    an unbroken disclosed chain to the announced digest; it cannot prove that
    the publisher has not withheld a later revision.
    """

    _canonical: bytes

    @classmethod
    def from_dict(
        cls,
        value: dict[str, Any],
        *,
        now_ms_override: int = 0,
    ) -> "VerifiedTradeOfferHeadProof":
        if not isinstance(value, dict) or set(value) != {
            "kind",
            "announcement",
            "offers",
        }:
            raise ValueError("Trade Offer head proof has an invalid shape")
        if value["kind"] != TRADE_OFFER_HEAD_PROOF_KIND_V1:
            raise ValueError("Trade Offer head proof kind is unsupported")
        offers_value = value["offers"]
        if (
            not isinstance(offers_value, list)
            or not 1 <= len(offers_value) <= MAX_TRADE_OFFER_HEAD_PROOF_REVISIONS
        ):
            raise ValueError(
                "Trade Offer head proof revision count is outside 1..64"
            )
        try:
            raw_encoded = canonical_json(value)
        except (TypeError, ValueError, OverflowError, RecursionError) as exc:
            raise ValueError(
                "Trade Offer head proof is not canonical JSON"
            ) from exc
        if len(raw_encoded) > MAX_TRADE_OFFER_HEAD_PROOF_BYTES:
            raise ValueError("Trade Offer head proof exceeds the byte limit")
        if (
            isinstance(now_ms_override, bool)
            or not isinstance(now_ms_override, int)
            or now_ms_override < 0
        ):
            raise ValueError("now_ms_override must be a non-negative integer")
        try:
            announcement = TaskAnnouncement.from_dict(value["announcement"])
            offers = tuple(TradeOffer.from_dict(item) for item in offers_value)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Trade Offer head proof contains an invalid signed record: {exc}"
            ) from exc
        for expected_revision, offer in enumerate(offers, start=1):
            if offer.to_dict()["revision"] != expected_revision:
                raise ValueError(
                    "Trade Offer head proof must start at revision 1 and be contiguous"
                )
        for previous, successor in zip(offers, offers[1:]):
            ok, reason = verify_offer_successor(previous, successor)
            if not ok:
                raise ValueError(
                    f"Trade Offer head proof has an invalid revision edge: {reason}"
                )
        ok, reason = verify_trade_offer_announcement_binding(
            offers[-1],
            announcement,
        )
        if not ok:
            raise ValueError(
                f"Trade Offer head proof announcement mismatch: {reason}"
            )
        moment = now_ms_override or now_ms()
        if announcement.is_expired(moment):
            raise ValueError("Trade Offer head proof announcement is expired")
        if (
            announcement.published_at_ms <= 0
            or announcement.published_at_ms
            > moment + MAX_TRADE_OFFER_HEAD_PROOF_CLOCK_SKEW_MS
        ):
            raise ValueError(
                "Trade Offer head proof announcement time is not currently valid"
            )
        normalized = {
            "kind": TRADE_OFFER_HEAD_PROOF_KIND_V1,
            "announcement": announcement.to_dict(),
            "offers": [offer.to_dict() for offer in offers],
        }
        try:
            encoded = canonical_json(normalized)
        except (TypeError, ValueError, OverflowError, RecursionError) as exc:
            raise ValueError("Trade Offer head proof is not canonical JSON") from exc
        if len(encoded) > MAX_TRADE_OFFER_HEAD_PROOF_BYTES:
            raise ValueError("Trade Offer head proof exceeds the byte limit")
        instance = object.__new__(cls)
        object.__setattr__(instance, "_canonical", encoded)
        return instance

    @property
    def announcement(self) -> TaskAnnouncement:
        return TaskAnnouncement.from_dict(self.to_dict()["announcement"])

    @property
    def offers(self) -> tuple[TradeOffer, ...]:
        return tuple(
            TradeOffer.from_dict(item) for item in self.to_dict()["offers"]
        )

    @property
    def head(self) -> TradeOffer:
        return self.offers[-1]

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self._canonical.decode("utf-8"))


def build_trade_offer_head_proof(
    announcement: TaskAnnouncement,
    offers: Iterable[TradeOffer | dict[str, Any]],
    *,
    now_ms_override: int = 0,
) -> dict[str, Any]:
    """Build and immediately reverify one wire-format head proof bundle."""

    wire = {
        "kind": TRADE_OFFER_HEAD_PROOF_KIND_V1,
        "announcement": announcement.to_dict(),
        "offers": [_verified_offer(offer).to_dict() for offer in offers],
    }
    return VerifiedTradeOfferHeadProof.from_dict(
        wire,
        now_ms_override=now_ms_override,
    ).to_dict()


__all__ = [
    "MAX_TRADE_OFFER_HEAD_PROOF_BYTES",
    "MAX_TRADE_OFFER_HEAD_PROOF_CLOCK_SKEW_MS",
    "MAX_TRADE_OFFER_HEAD_PROOF_REVISIONS",
    "MAX_TRADE_OFFER_ANNOUNCEMENT_TTL_MS",
    "TRADE_OFFER_HEAD_PROOF_KIND_V1",
    "VerifiedTradeOfferHeadProof",
    "build_trade_offer_head_proof",
    "create_trade_offer_announcement",
    "trade_offer_head_proof_uri",
    "trade_offer_uri",
    "verify_trade_offer_announcement_binding",
]
