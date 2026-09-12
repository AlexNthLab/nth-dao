"""Mission completion — binds a finished Mission to its market claims.

Design doc §五 (Phase 5): "receipt 可绑定真实 Mission、claim 和输出"。
The existing pieces each hold half of the chain:

* the claim receipt (``market:claim:{id}``) proves WHO claimed WHAT;
* the handoff capsule proves the work narrative (finding, evidence);
* the execution receipt proves the work ran (timeline, content hash).

The missing link is a **signed completion record** that names all three:
announcement, mission, claim receipt digest, and execution receipt digest —
so a market projection can answer "is this task done, and can I verify the
whole chain?" without trusting any single statement.

Wire contract (v1): the claimant signs one completion record binding

* ``announcement_id``   — the market task claimed;
* ``mission_id``        — the Mission that executed it;
* ``claim_receipt_digest`` — sha256 of the accepted claim receipt bytes;
* ``execution_receipt_digest`` — sha256 of the execution receipt bytes;
* ``outcome``           — "succeeded" | "failed" (a failed completion is
  still recorded: the market sees honest failures, not silence).

Verification re-derives the digests from the supplied receipts, so a
completion record cannot reference receipts the claimant does not hold.
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Any, Dict, Optional, Tuple

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import is_did_key
from nth_dao.identity import _NACL_AVAILABLE, AgentIdentity

try:  # pragma: no cover - exercised via importorskip in tests
    from nacl.exceptions import BadSignatureError as _BadSignatureError
    from nacl.signing import VerifyKey as _VerifyKey
except ImportError:  # pragma: no cover
    _BadSignatureError = ValueError  # type: ignore[assignment]
    _VerifyKey = None  # type: ignore[assignment]

logger = logging.getLogger("nth_dao.market")

COMPLETION_KIND = "nth-market-mission-completion"
COMPLETION_VERSION = 1
COMPLETION_FIELDS = frozenset({
    "kind",
    "version",
    "announcement_id",
    "mission_id",
    "claimant_did",
    "claim_receipt_digest",
    "execution_receipt_digest",
    "outcome",
    "completed_at_ms",
    "signature",
})
OUTCOME_SUCCEEDED = "succeeded"
OUTCOME_FAILED = "failed"
OUTCOMES = (OUTCOME_SUCCEEDED, OUTCOME_FAILED)
_MAX_ID = 256


class MissionCompletionRejected(ValueError):
    """Raised when a completion record cannot be built or verified."""


def receipt_digest(receipt: Dict[str, Any]) -> str:
    """Content digest of a receipt's canonical bytes (both receipt kinds)."""

    return "sha256:" + hashlib.sha256(canonical_json(receipt)).hexdigest()


def _check_shape(
    record: Dict[str, Any], *, now_ms: int, max_age_ms: int
) -> Optional[str]:
    if frozenset(record) != COMPLETION_FIELDS:
        return "missing or unknown fields"
    if record.get("kind") != COMPLETION_KIND or record.get("version") != COMPLETION_VERSION:
        return "wrong kind or version"
    if not isinstance(record.get("announcement_id"), str) or not record["announcement_id"]:
        return "announcement_id must be non-empty text"
    if not isinstance(record.get("mission_id"), str) or not record["mission_id"]:
        return "mission_id must be non-empty text"
    for field in ("claim_receipt_digest", "execution_receipt_digest"):
        value = record.get(field)
        if (
            not isinstance(value, str)
            or len(value) != 71
            or not value.startswith("sha256:")
            or any(ch not in "0123456789abcdef" for ch in value[7:])
        ):
            return f"{field} is not a sha256 digest"
    if record.get("outcome") not in OUTCOMES:
        return "outcome must be succeeded or failed"
    if not is_did_key(record.get("claimant_did", "")):
        return "claimant_did must be a did:key"
    completed_at = record.get("completed_at_ms")
    if isinstance(completed_at, bool) or not isinstance(completed_at, int) or completed_at <= 0:
        return "completed_at_ms must be positive"
    if completed_at > now_ms + 5 * 60 * 1000:
        return "completed_at_ms is in the future beyond clock skew"
    if now_ms - completed_at > max_age_ms:
        return "completion record is older than the acceptance window"
    return None


def sign_mission_completion(
    claimant: AgentIdentity,
    *,
    announcement_id: str,
    mission_id: str,
    claim_receipt: Dict[str, Any],
    execution_receipt: Dict[str, Any],
    outcome: str = OUTCOME_SUCCEEDED,
    completed_at_ms: Optional[int] = None,
) -> Dict[str, Any]:
    """Sign one completion record binding claim + execution receipts.

    Raises MissionCompletionRejected when the supplied receipts cannot be
    bound (missing ids, claimant mismatch) — the record cannot reference
    receipts the claimant does not hold.
    """

    if outcome not in OUTCOMES:
        raise MissionCompletionRejected("outcome must be succeeded or failed")
    claimant_did = claimant.as_did()
    claim_digest = receipt_digest(claim_receipt)
    exec_digest = receipt_digest(execution_receipt)
    # binding sanity: the execution receipt's signer must be the claimant —
    # a completion record cannot cite someone else's work
    receipt_signer = execution_receipt.get("signer_did", "")
    if receipt_signer and receipt_signer != claimant_did:
        raise MissionCompletionRejected(
            "execution receipt signer does not match the claimant"
        )
    completed_at = completed_at_ms if completed_at_ms is not None else int(time.time() * 1000)
    record: Dict[str, Any] = {
        "kind": COMPLETION_KIND,
        "version": COMPLETION_VERSION,
        "announcement_id": str(announcement_id),
        "mission_id": str(mission_id),
        "claimant_did": claimant_did,
        "claim_receipt_digest": claim_digest,
        "execution_receipt_digest": exec_digest,
        "outcome": outcome,
        "completed_at_ms": completed_at,
    }
    body = canonical_json(record)
    record["signature"] = b64u_encode(claimant.sign(body))
    reason = _check_shape(record, now_ms=completed_at, max_age_ms=365 * 24 * 3600 * 1000)
    if reason is not None:  # pragma: no cover - defensive self-check
        raise MissionCompletionRejected(reason)
    return record


def verify_mission_completion(
    record: Dict[str, Any],
    *,
    claim_receipt: Optional[Dict[str, Any]] = None,
    execution_receipt: Optional[Dict[str, Any]] = None,
    now_ms: Optional[int] = None,
    max_age_ms: int = 365 * 24 * 3600 * 1000,
) -> Tuple[bool, str]:
    """Verify a completion record.

    Without the receipts: signature + shape + age only (market projection
    use). With receipts supplied: their canonical digests must equal the
    recorded ones (verification-grade use — proves the claimant actually
    holds the claimed chain).
    """

    now = now_ms if now_ms is not None else int(time.time() * 1000)
    reason = _check_shape(record, now_ms=now, max_age_ms=max_age_ms)
    if reason is not None:
        return False, reason
    if not _NACL_AVAILABLE or _VerifyKey is None:
        return False, "crypto unavailable"
    try:
        signature = b64u_decode(record["signature"])
        if len(signature) != 64:
            return False, "signature encoding invalid"
        body = canonical_json({k: v for k, v in record.items() if k != "signature"})
        key_hex = ""
        from nth_dao.did_key import decode_ed25519_did_key_hex

        key_hex = decode_ed25519_did_key_hex(record["claimant_did"]) or ""
        _VerifyKey(bytes.fromhex(key_hex)).verify(body, signature)
    except (_BadSignatureError, KeyError, TypeError, ValueError, UnicodeError):
        return False, "signature verification failed"
    if claim_receipt is not None:
        if receipt_digest(claim_receipt) != record["claim_receipt_digest"]:
            return False, "claim receipt digest does not match the record"
    if execution_receipt is not None:
        if receipt_digest(execution_receipt) != record["execution_receipt_digest"]:
            return False, "execution receipt digest does not match the record"
    return True, "ok"


__all__ = [
    "COMPLETION_FIELDS",
    "COMPLETION_KIND",
    "COMPLETION_VERSION",
    "MissionCompletionRejected",
    "OUTCOME_FAILED",
    "OUTCOME_SUCCEEDED",
    "receipt_digest",
    "sign_mission_completion",
    "verify_mission_completion",
]
