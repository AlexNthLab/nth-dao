"""Offline verification of a source-signed completion receipt statement.

The signature authenticates the source's statement, not Spine inclusion,
local disk retention, completion quality, acceptance, or settlement.
"""

from __future__ import annotations

import hashlib
from typing import Any

from nth_dao.canonical_json import canonical_json
from nth_dao.market.announcement import TaskAnnouncement
from nth_dao.market.completion_flow import verify_portable_completion_proof
from nth_dao.market.mission_completion import receipt_digest
from nth_dao.market.source_identity import (
    MAX_PORTABLE_SOURCE_ROTATION_CHAIN_BYTES,
    verify_portable_source_rotation_chain,
)
from nth_dao.spine.event import SpineEvent, verify_event

RECEIVED_EVENT = "market.claim.completion.received"
MAX_SOURCE_RECEIPT_EVENT_BYTES = 16 * 1024
MAX_SOURCE_RECEIPT_RESPONSE_BYTES = (
    MAX_PORTABLE_SOURCE_ROTATION_CHAIN_BYTES + 2 * MAX_SOURCE_RECEIPT_EVENT_BYTES
)


def extract_source_completion_receipt(value: Any) -> tuple[dict, list]:
    """Extract signed evidence, checking any unsigned REST wrapper for consistency."""
    if not isinstance(value, dict):
        raise ValueError("source receipt response must be an object")
    try:
        size = len(canonical_json(value))
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ValueError("source receipt response is not canonical JSON") from exc
    if size > MAX_SOURCE_RECEIPT_RESPONSE_BYTES:
        raise ValueError("source receipt response exceeds size limit")
    if "source_receipt_event" not in value:
        if size > MAX_SOURCE_RECEIPT_EVENT_BYTES:
            raise ValueError("source receipt event exceeds size limit")
        return value, []
    event = value["source_receipt_event"]
    chain = value.get("source_rotation_chain")
    if not isinstance(event, dict) or not isinstance(chain, list):
        raise ValueError("source response lacks a receipt event or rotation chain")
    if len(canonical_json(event)) > MAX_SOURCE_RECEIPT_EVENT_BYTES:
        raise ValueError("source receipt event exceeds size limit")
    payload = event.get("payload")
    if not isinstance(payload, dict) or value.get("audit_event_id") != event.get("content_hash"):
        raise ValueError("source response audit event ID differs from its event")
    if not payload.keys() <= value.keys() or canonical_json({
        field: value[field] for field in payload
    }) != canonical_json(payload):
        raise ValueError("source response fields differ from the signed event")
    return event, chain


def _payload_for_verified_proof(proof: dict[str, Any], raw: bytes) -> dict[str, Any]:
    """Construct the receipt payload only after the caller verifies the proof."""
    head = proof["completion_chain"][-1]
    record = head["completion_record"]
    source_claim_id = proof["source_claim_id"]
    head_digest = receipt_digest(head)
    return {
        "completion_key": f"{source_claim_id}:{head_digest}",
        "source_claim_id": source_claim_id,
        "completion_head_digest": head_digest,
        "proof_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "claimant_did": proof["intent"]["claimant_did"],
        "source_did": TaskAnnouncement.from_dict(
            proof["announcement"],
        ).effective_authority_did(),
        "mission_id": record["mission_id"],
        "outcome": record["outcome"],
        "revision": record.get("revision", 0),
        "nonce_authenticated": False,
        "accepted": False,
        "settled": False,
    }


def _same_payload_bytes(actual: dict[str, Any], expected: dict[str, Any]) -> bool:
    return canonical_json(actual) == canonical_json(expected)


def verify_source_completion_receipt(
    proof: Any,
    receipt_event: Any,
    *,
    expected_source_did: str,
    expected_federation_key: str,
    rotation_chain: Any = None,
) -> tuple[bool, str]:
    """Bind a signed source statement to a complete proof and external pins.

    A rotated signer needs a continuous dual-signed path from the pinned DID.
    This single-event check does not prove the event was appended to Spine.
    """
    try:
        event = SpineEvent.from_dict(receipt_event)
    except (AttributeError, TypeError, ValueError, OverflowError, RecursionError):
        return False, "source receipt event schema is invalid"
    valid, reason = verify_event(event)
    if not valid:
        return False, f"source receipt event is invalid: {reason}"
    if event.type != RECEIVED_EVENT:
        return False, "source receipt event type is invalid"
    chain = [] if rotation_chain is None else rotation_chain
    if not verify_portable_source_rotation_chain(
        chain, expected_source_did, event.author_did,
    ):
        return False, "source receipt signer differs from the pinned source"
    valid, reason = verify_portable_completion_proof(
        proof,
        expected_source_did=expected_source_did,
        expected_federation_key=expected_federation_key,
    )
    if not valid:
        return False, f"portable completion proof is invalid: {reason}"
    try:
        payload = _payload_for_verified_proof(proof, canonical_json(proof))
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return False, "portable completion proof payload is invalid"
    if not _same_payload_bytes(event.payload, payload):
        return False, "source receipt does not bind this completion proof"
    return True, "ok"


__all__ = [
    "extract_source_completion_receipt",
    "MAX_SOURCE_RECEIPT_EVENT_BYTES",
    "MAX_SOURCE_RECEIPT_RESPONSE_BYTES",
    "RECEIVED_EVENT",
    "verify_source_completion_receipt",
]
