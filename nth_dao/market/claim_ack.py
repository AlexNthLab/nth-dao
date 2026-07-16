"""Authority-signed acknowledgement of a cross-DAO claim CAS result."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import is_did_key
from nth_dao.identity import AgentIdentity
from nth_dao.market.announcement import (
    TaskAnnouncement,
    announcement_federation_key,
)
from nth_dao.util.io import InterProcessLock, atomic_write_json, safe_load_json

AUTHORITY_CLAIM_ACK_KIND = "nth-authority-claim-ack-v1"
_ACK_KEYS = {
    "kind",
    "ack_id",
    "federation_key",
    "announcement_id",
    "claimant_did",
    "claim_receipt_id",
    "claim_receipt_hash",
    "claim_record_hash",
    "authority_did",
    "outcome",
    "accepted_at_ms",
    "authority_sig",
}


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _ack_identity_body(ack: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: value for key, value in ack.items()
        if key not in {"ack_id", "authority_sig"}
    }


def _ack_signing_body(ack: Dict[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in ack.items() if key != "authority_sig"}


def sign_authority_claim_ack(
    *,
    authority: AgentIdentity,
    announcement: TaskAnnouncement,
    claim_record: Dict[str, Any],
) -> Dict[str, Any]:
    """Sign the authority's durable acceptance of one claimant receipt."""
    if not authority.can_sign:
        raise ValueError("claim authority identity cannot sign")
    authority_did = authority.as_did()
    if announcement.effective_authority_did() != authority_did:
        raise ValueError("signer is not the announcement claim authority")
    if not isinstance(claim_record, dict):
        raise ValueError("claim_record must be an object")
    receipt = claim_record.get("receipt")
    claimant_did = claim_record.get("claimant_did")
    receipt_id = claim_record.get("receipt_id")
    claimed_at_ms = claim_record.get("claimed_at_ms")
    if not isinstance(receipt, dict) or not receipt:
        raise ValueError("claim record is missing its signed receipt")
    if not isinstance(claimant_did, str) or not is_did_key(claimant_did):
        raise ValueError("claim record has an invalid claimant DID")
    if not isinstance(receipt_id, str) or not receipt_id:
        raise ValueError("claim record is missing receipt_id")
    if type(claimed_at_ms) is not int or claimed_at_ms <= 0:
        raise ValueError("claim record has an invalid claimed_at_ms")

    ack: Dict[str, Any] = {
        "kind": AUTHORITY_CLAIM_ACK_KIND,
        "federation_key": announcement_federation_key(announcement),
        "announcement_id": announcement.announcement_id,
        "claimant_did": claimant_did,
        "claim_receipt_id": receipt_id,
        "claim_receipt_hash": _sha256_json(receipt),
        "claim_record_hash": _sha256_json(claim_record),
        "authority_did": authority_did,
        "outcome": "claimed",
        "accepted_at_ms": claimed_at_ms,
    }
    ack["ack_id"] = _sha256_json(_ack_identity_body(ack))
    ack["authority_sig"] = b64u_encode(
        authority.sign(canonical_json(_ack_signing_body(ack)))
    )
    return ack


def verify_authority_claim_ack(
    ack: Dict[str, Any],
    *,
    expected_authority_did: str = "",
    expected_federation_key: str = "",
    expected_claimant_did: str = "",
    expected_claim_receipt: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, str]:
    """Verify strict schema, content bindings, identifier and signature."""
    if not isinstance(ack, dict) or set(ack) != _ACK_KEYS:
        return False, "claim ack schema is invalid"
    if ack.get("kind") != AUTHORITY_CLAIM_ACK_KIND:
        return False, "claim ack kind is invalid"
    bounded_strings = (
        "ack_id", "federation_key", "announcement_id", "claimant_did",
        "claim_receipt_id", "claim_receipt_hash", "claim_record_hash",
        "authority_did", "outcome", "authority_sig",
    )
    if any(
        not isinstance(ack.get(field), str)
        or not ack[field]
        or len(ack[field].encode("utf-8")) > 1024
        for field in bounded_strings
    ):
        return False, "claim ack contains an invalid string field"
    if ack.get("outcome") != "claimed":
        return False, "claim ack outcome is invalid"
    if type(ack.get("accepted_at_ms")) is not int or ack["accepted_at_ms"] <= 0:
        return False, "claim ack accepted_at_ms is invalid"
    if not is_did_key(ack["authority_did"]) or not is_did_key(ack["claimant_did"]):
        return False, "claim ack DID is invalid"
    if expected_authority_did and ack["authority_did"] != expected_authority_did:
        return False, "claim ack authority does not match the source"
    if expected_federation_key and ack["federation_key"] != expected_federation_key:
        return False, "claim ack does not bind the requested announcement"
    if expected_claimant_did and ack["claimant_did"] != expected_claimant_did:
        return False, "claim ack does not bind the requesting agent"
    if expected_claim_receipt is not None:
        if not isinstance(expected_claim_receipt, dict):
            return False, "expected claimant receipt is invalid"
        if ack["claim_receipt_id"] != str(
            expected_claim_receipt.get("receipt_id") or ""
        ):
            return False, "claim ack receipt id does not match the claimant receipt"
        if ack["claim_receipt_hash"] != _sha256_json(expected_claim_receipt):
            return False, "claim ack receipt hash does not match the claimant receipt"
    if ack["ack_id"] != _sha256_json(_ack_identity_body(ack)):
        return False, "claim ack identifier is invalid"
    try:
        verifier = AgentIdentity.from_did(ack["authority_did"])
        signature = b64u_decode(ack["authority_sig"])
    except (TypeError, ValueError, UnicodeError) as exc:
        return False, f"claim ack encoding is invalid: {exc}"
    if len(signature) != 64:
        return False, "claim ack signature length is invalid"
    if not verifier.verify(canonical_json(_ack_signing_body(ack)), signature):
        return False, "claim ack signature is invalid"
    return True, "ok"


class AuthorityClaimAckStore:
    """Immutable local store of source-authority claim acknowledgements."""

    def __init__(self, workspace: Path) -> None:
        self.root = Path(workspace) / "federation" / "claim_acks"

    def save(self, ack: Dict[str, Any]) -> Path:
        ok, reason = verify_authority_claim_ack(ack)
        if not ok:
            raise ValueError(reason)
        ack_id = str(ack["ack_id"])
        if len(ack_id) != 64 or any(ch not in "0123456789abcdef" for ch in ack_id):
            raise ValueError("claim ack id is not a SHA-256 hex digest")
        path = self.root / f"{ack_id}.json"
        with InterProcessLock(path):
            existing = safe_load_json(path, fallback=None)
            if existing is not None:
                if existing != ack:
                    raise ValueError("claim ack id collision")
                return path
            atomic_write_json(path, ack, ensure_ascii=True, indent=2)
        return path

    def load(self, ack_id: str) -> Optional[Dict[str, Any]]:
        if (
            not isinstance(ack_id, str)
            or len(ack_id) != 64
            or any(ch not in "0123456789abcdef" for ch in ack_id)
        ):
            return None
        value = safe_load_json(self.root / f"{ack_id}.json", fallback=None)
        return value if isinstance(value, dict) else None
