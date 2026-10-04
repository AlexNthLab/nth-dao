"""Read-only resolution of the claimant-side authority-accepted claim chain."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from nth_dao.market.claim_ack import AuthorityClaimAckStore
from nth_dao.market.claim_intent import IntentTracker
from nth_dao.market.announcement import (
    TaskAnnouncement,
    announcement_federation_key,
    verify_announcement,
)
from nth_dao.market.claim import _claim_timeline


class ClaimEvidenceUnavailable(ValueError):
    """The local claim is not ready for completion evidence binding."""


def resolve_confirmed_claim_evidence(
    workspace: Path,
    nonce: str,
) -> dict[str, Any]:
    """Return one confirmed claim's verified announcement, receipt, and source ACK.

    This proves source acceptance of the claim, not mission execution or
    delivery. Legacy hash-only intents have no retained claim evidence and
    cannot be promoted to a verification-grade completion chain.
    """

    ws = Path(workspace)
    tracker = IntentTracker(ws / "federation" / "claim_intents")
    record = tracker.record(nonce)
    if record is None:
        record = tracker.archived_record(nonce)
    if record is None or record.get("state") != "confirmed":
        raise ClaimEvidenceUnavailable("claim is not locally confirmed")
    if not record.get("receipt_retained"):
        raise ClaimEvidenceUnavailable("claim receipt was not retained")
    source_did = record.get("source_did", "")
    federation_key = record.get("federation_key", "")
    if not source_did or not federation_key:
        raise ClaimEvidenceUnavailable("claim has no pinned source authority")
    raw_announcement = record.get("announcement")
    if not isinstance(raw_announcement, dict):
        raise ClaimEvidenceUnavailable("claim has no retained signed announcement")
    try:
        announcement = TaskAnnouncement.from_dict(raw_announcement)
        valid, _ = verify_announcement(announcement)
        if (
            not valid
            or announcement.announcement_id != record["intent"]["announcement_id"]
            or source_did != (announcement.authority_did or announcement.publisher_did)
            or federation_key != announcement_federation_key(announcement)
        ):
            raise ValueError("source differs from signed announcement")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ClaimEvidenceUnavailable(
            "signed announcement binding is invalid"
        ) from exc
    receipt = tracker.load_receipt_by_hash(record.get("receipt_hash", ""))
    if receipt is None or receipt.get("receipt_id") != record.get("receipt_id"):
        raise ClaimEvidenceUnavailable("retained claim receipt is unavailable")
    intent = record["intent"]
    if (
        receipt.get("signer_did") != intent["claimant_did"]
        or receipt.get("goal_id") != f"market:claim:{intent['announcement_id']}"
    ):
        raise ClaimEvidenceUnavailable("claim receipt does not bind the intent")
    timeline = receipt.get("timeline")
    token = receipt.get("authorizing_cap_token")
    if (
        not isinstance(timeline, list)
        or len(timeline) != 1
        or not isinstance(timeline[0], dict)
        or type(timeline[0].get("timestamp")) is not int
        or not isinstance(token, dict)
        or token.get("token_id") != intent["cap_token_id"]
        or timeline
        != [
            item.to_dict()
            for item in _claim_timeline(
                announcement,
                intent["claimant_did"],
                intent["cap_token_id"],
                timeline[0]["timestamp"],
            )
        ]
    ):
        raise ClaimEvidenceUnavailable("signed claim event differs from announcement")
    ack = AuthorityClaimAckStore(ws).find_for_receipt(
        receipt,
        expected_authority_did=source_did,
        expected_federation_key=federation_key,
        expected_claimant_did=intent["claimant_did"],
    )
    if ack is None:
        raise ClaimEvidenceUnavailable("source authority acknowledgement is missing")
    return {
        "announcement": raw_announcement,
        "intent": intent,
        "claim_receipt": receipt,
        "authority_ack": ack,
        "source_did": source_did,
        "federation_key": federation_key,
    }


__all__ = ["ClaimEvidenceUnavailable", "resolve_confirmed_claim_evidence"]
