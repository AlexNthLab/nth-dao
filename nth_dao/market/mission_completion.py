"""Mission completion — binds a finished Mission to its market claims.

Design doc §五 (Phase 5): "receipt 可绑定真实 Mission、claim 和输出"。
The existing pieces each hold half of the chain:

* the claim receipt (``market:claim:{id}``) proves WHO claimed WHAT;
* the authority acknowledgement proves the source DAO accepted the claim;
* the execution receipt proves the work ran (timeline, content hash).

The missing link is a **signed completion record** that names the complete
chain: announcement, mission, claim receipt digest, authority ACK digest,
and execution receipt digest —
so a market projection can answer "is this task done, and can I verify the
whole chain?" without trusting any single statement.

Wire contract (v1): the claimant signs one completion record binding

* ``announcement_id``   — the market task claimed;
* ``mission_id``        — the Mission that executed it;
* ``claim_receipt_digest`` — sha256 of the accepted claim receipt bytes;
* ``authority_ack_digest`` — sha256 of the source authority acknowledgement;
* ``execution_receipt_digest`` — sha256 of the execution receipt bytes;
* ``outcome``           — "succeeded" | "failed" (a failed completion is
  still recorded: the market sees honest failures, not silence).

Verification re-derives the digests from the supplied receipts, so a
completion record cannot reference receipts the claimant does not hold.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from pathlib import Path
from typing import Any

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import DIDKeyError, is_did_key
from nth_dao.execution_receipt import verify_receipt
from nth_dao.identity import _NACL_AVAILABLE, AgentIdentity
from nth_dao.market.claim_ack import verify_authority_claim_ack

try:  # pragma: no cover - exercised via importorskip in tests
    from nacl.exceptions import BadSignatureError as _BadSignatureError
    from nacl.signing import VerifyKey as _VerifyKey
except ImportError:  # pragma: no cover
    _BadSignatureError = ValueError  # type: ignore[assignment]
    _VerifyKey = None  # type: ignore[assignment]

logger = logging.getLogger("nth_dao.market")

COMPLETION_KIND = "nth-market-mission-completion"
COMPLETION_VERSION = 1
COMPLETION_FIELDS = frozenset(
    {
        "kind",
        "version",
        "announcement_id",
        "mission_id",
        "claimant_did",
        "claim_receipt_digest",
        "authority_ack_digest",
        "execution_receipt_digest",
        "outcome",
        "completed_at_ms",
        "signature",
    }
)
COMPLETION_REVISION_VERSION = 2
COMPLETION_REVISION_FIELDS = COMPLETION_FIELDS | frozenset({
    "revision", "supersedes_digest",
})
COMPLETION_MERGE_VERSION = 3
COMPLETION_MERGE_FIELDS = COMPLETION_FIELDS | frozenset({
    "revision", "supersedes_digests",
})
OUTCOME_SUCCEEDED = "succeeded"
OUTCOME_FAILED = "failed"
OUTCOMES = (OUTCOME_SUCCEEDED, OUTCOME_FAILED)
_MAX_ID = 256
_MAX_SAFE_INTEGER = (1 << 53) - 1
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMPLETION_EVENT_TYPES = {
    OUTCOME_SUCCEEDED: "nth.task_completed",
    OUTCOME_FAILED: "nth.task_failed",
}


class MissionCompletionRejected(ValueError):
    """Raised when a completion record cannot be built or verified."""


class CompletionLineageError(ValueError):
    """A completion graph has an invalid or missing predecessor."""


def receipt_digest(receipt: Any) -> str:
    """Content digest of a receipt's canonical bytes (both receipt kinds)."""

    return "sha256:" + hashlib.sha256(canonical_json(receipt)).hexdigest()


def _check_shape(record: Any, *, now_ms: int, max_age_ms: int | None) -> str | None:
    if not isinstance(record, dict):
        return "completion record must be an object"
    if (
        isinstance(now_ms, bool)
        or not isinstance(now_ms, int)
        or not 0 < now_ms <= _MAX_SAFE_INTEGER
    ):
        return "verification time is invalid"
    if max_age_ms is not None and (
        isinstance(max_age_ms, bool)
        or not isinstance(max_age_ms, int)
        or not 0 < max_age_ms <= _MAX_SAFE_INTEGER
    ):
        return "max_age_ms is invalid"
    version = record.get("version")
    expected_fields = (
        COMPLETION_FIELDS if version == COMPLETION_VERSION else
        COMPLETION_REVISION_FIELDS if version == COMPLETION_REVISION_VERSION else
        COMPLETION_MERGE_FIELDS if version == COMPLETION_MERGE_VERSION else None
    )
    if expected_fields is None or frozenset(record) != expected_fields:
        return "missing or unknown fields"
    if record.get("kind") != COMPLETION_KIND:
        return "wrong kind or version"
    if (
        type(record.get("version")) is not int
        or version not in (
            COMPLETION_VERSION, COMPLETION_REVISION_VERSION, COMPLETION_MERGE_VERSION,
        )
    ):
        return "wrong kind or version"
    if version == COMPLETION_REVISION_VERSION and (
        type(record.get("revision")) is not int
        or not 1 <= record["revision"] <= 31
        or not isinstance(record.get("supersedes_digest"), str)
        or _DIGEST_RE.fullmatch(record["supersedes_digest"]) is None
    ):
        return "completion revision link is invalid"
    if version == COMPLETION_MERGE_VERSION and (
        type(record.get("revision")) is not int
        or not 1 <= record["revision"] <= 31
        or not isinstance(record.get("supersedes_digests"), list)
        or not 2 <= len(record["supersedes_digests"]) <= 31
        or any(
            not isinstance(digest, str) or _DIGEST_RE.fullmatch(digest) is None
            for digest in record["supersedes_digests"]
        )
        or record["supersedes_digests"] != sorted(set(record["supersedes_digests"]))
    ):
        return "completion merge links are invalid"
    if (
        not isinstance(record.get("announcement_id"), str)
        or _ID_RE.fullmatch(record["announcement_id"]) is None
        or len(record["announcement_id"]) > _MAX_ID
    ):
        return "announcement_id must be non-empty text"
    if (
        not isinstance(record.get("mission_id"), str)
        or _ID_RE.fullmatch(record["mission_id"]) is None
    ):
        return "mission_id must be non-empty text"
    for field in (
        "claim_receipt_digest",
        "authority_ack_digest",
        "execution_receipt_digest",
    ):
        value = record.get(field)
        if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
            return f"{field} is not a sha256 digest"
    if record.get("outcome") not in OUTCOMES:
        return "outcome must be succeeded or failed"
    claimant_did = record.get("claimant_did")
    if not isinstance(claimant_did, str) or not is_did_key(claimant_did):
        return "claimant_did must be a did:key"
    completed_at = record.get("completed_at_ms")
    if (
        isinstance(completed_at, bool)
        or not isinstance(completed_at, int)
        or not 0 < completed_at <= _MAX_SAFE_INTEGER
    ):
        return "completed_at_ms must be positive"
    if completed_at > now_ms + 5 * 60 * 1000:
        return "completed_at_ms is in the future beyond clock skew"
    if max_age_ms is not None and now_ms - completed_at > max_age_ms:
        return "completion record is older than the acceptance window"
    signature = record.get("signature")
    if not isinstance(signature, str) or len(signature) != 86:
        return "signature encoding invalid"
    return None


def _claim_receipt_error(
    receipt: Any, *, announcement_id: str, claimant_did: str
) -> str | None:
    if not isinstance(receipt, dict) or not verify_receipt(receipt):
        return "claim receipt signature is invalid"
    if receipt.get("signer_did") != claimant_did:
        return "claim receipt signer does not match the claimant"
    if receipt.get("goal_id") != f"market:claim:{announcement_id}":
        return "claim receipt goal does not bind the announcement"
    timeline = receipt.get("timeline")
    if not isinstance(timeline, list) or len(timeline) != 1:
        return "claim receipt must contain exactly one claim event"
    entry = timeline[0]
    if not isinstance(entry, dict) or set(entry) != {"timestamp", "type", "payload"}:
        return "claim receipt event is malformed"
    payload = entry.get("payload")
    if entry.get("type") != "nth.task_claimed" or not isinstance(payload, dict):
        return "claim receipt does not contain a task claim"
    if type(entry.get("timestamp")) is not int or entry["timestamp"] <= 0:
        return "claim receipt timestamp is invalid"
    if payload.get("announcement_id") != announcement_id:
        return "claim receipt payload does not bind the announcement"
    if payload.get("claimant_did") != claimant_did:
        return "claim receipt payload does not bind the claimant"
    return None


def _execution_receipt_error(
    receipt: Any, *, mission_id: str, claimant_did: str, outcome: str,
    claim_at_ms: int, accepted_at_ms: int, completed_at_ms: int,
) -> str | None:
    if not isinstance(receipt, dict) or not verify_receipt(receipt):
        return "execution receipt signature is invalid"
    if receipt.get("signer_did") != claimant_did:
        return "execution receipt signer does not match the claimant"
    if receipt.get("goal_id") != f"mission:{mission_id}":
        return "execution receipt goal does not bind the mission"
    expected_type = _COMPLETION_EVENT_TYPES[outcome]
    timeline = receipt.get("timeline")
    if not isinstance(timeline, list):
        return "execution receipt timeline is invalid"
    if (
        type(claim_at_ms) is not int
        or type(accepted_at_ms) is not int
        or type(completed_at_ms) is not int
        or claim_at_ms <= 0
        or accepted_at_ms < claim_at_ms
        or completed_at_ms < accepted_at_ms
    ):
        return "claim, authority acknowledgement, and completion chronology is invalid"
    for entry in timeline:
        if not isinstance(entry, dict) or set(entry) != {
            "timestamp",
            "type",
            "payload",
        }:
            return "execution receipt event is malformed"
        payload = entry.get("payload")
        if (
            entry.get("type") == expected_type
            and isinstance(payload, dict)
            and payload.get("mission_id") == mission_id
        ):
            event_at_ms = entry.get("timestamp")
            if (
                type(event_at_ms) is not int
                or not accepted_at_ms <= event_at_ms <= completed_at_ms
            ):
                return "execution event is outside the confirmed claim chronology"
            return None
    return f"execution receipt does not prove outcome {outcome}"


def _authority_ack_error(
    ack: Any,
    *,
    announcement_id: str,
    claimant_did: str,
    claim_receipt: dict[str, Any],
    expected_authority_did: str = "",
    expected_federation_key: str = "",
) -> str | None:
    if not isinstance(ack, dict):
        return "authority claim acknowledgement must be an object"
    ok, reason = verify_authority_claim_ack(
        ack,
        expected_authority_did=expected_authority_did,
        expected_federation_key=expected_federation_key,
        expected_claimant_did=claimant_did,
        expected_claim_receipt=claim_receipt,
    )
    if not ok:
        return f"authority claim acknowledgement is invalid: {reason}"
    if ack.get("announcement_id") != announcement_id:
        return "authority claim acknowledgement does not bind the announcement"
    return None


def sign_mission_completion(
    claimant: AgentIdentity,
    *,
    announcement_id: str,
    mission_id: str,
    claim_receipt: dict[str, Any],
    authority_ack: dict[str, Any],
    execution_receipt: dict[str, Any],
    outcome: str = OUTCOME_SUCCEEDED,
    completed_at_ms: int | None = None,
    revision: int = 0,
    supersedes_digest: str = "",
    supersedes_digests: list[str] | None = None,
) -> dict[str, Any]:
    """Sign one completion record binding claim + execution receipts.

    Raises MissionCompletionRejected when the supplied receipts cannot be
    bound (missing ids, claimant mismatch) — the record cannot reference
    receipts the claimant does not hold.
    """

    if outcome not in OUTCOMES:
        raise MissionCompletionRejected("outcome must be succeeded or failed")
    if type(revision) is int and revision == 0 and not supersedes_digest and not supersedes_digests:
        version = COMPLETION_VERSION
    elif (
        type(revision) is int
        and 1 <= revision <= 31
        and isinstance(supersedes_digest, str)
        and _DIGEST_RE.fullmatch(supersedes_digest) is not None
        and not supersedes_digests
    ):
        version = COMPLETION_REVISION_VERSION
    elif (
        type(revision) is int
        and 1 <= revision <= 31
        and not supersedes_digest
        and isinstance(supersedes_digests, list)
        and 2 <= len(supersedes_digests) <= 31
        and all(isinstance(digest, str) and _DIGEST_RE.fullmatch(digest)
                for digest in supersedes_digests)
        and supersedes_digests == sorted(set(supersedes_digests))
    ):
        version = COMPLETION_MERGE_VERSION
    else:
        raise MissionCompletionRejected("completion revision link is invalid")
    completed_at = (
        completed_at_ms if completed_at_ms is not None else int(time.time() * 1000)
    )
    claimant_did = claimant.as_did()
    error = _claim_receipt_error(
        claim_receipt, announcement_id=announcement_id, claimant_did=claimant_did,
    )
    if error is not None:
        raise MissionCompletionRejected(error)
    error = _authority_ack_error(
        authority_ack, announcement_id=announcement_id,
        claimant_did=claimant_did, claim_receipt=claim_receipt,
    )
    if error is not None:
        raise MissionCompletionRejected(error)
    error = _execution_receipt_error(
        execution_receipt, mission_id=mission_id, claimant_did=claimant_did,
        outcome=outcome, claim_at_ms=claim_receipt["timeline"][0]["timestamp"],
        accepted_at_ms=authority_ack["accepted_at_ms"],
        completed_at_ms=completed_at,
    )
    if error is not None:
        raise MissionCompletionRejected(error)
    record: dict[str, Any] = {
        "kind": COMPLETION_KIND,
        "version": version,
        "announcement_id": str(announcement_id),
        "mission_id": str(mission_id),
        "claimant_did": claimant_did,
        "claim_receipt_digest": receipt_digest(claim_receipt),
        "authority_ack_digest": receipt_digest(authority_ack),
        "execution_receipt_digest": receipt_digest(execution_receipt),
        "outcome": outcome,
        "completed_at_ms": completed_at,
    }
    if version == COMPLETION_REVISION_VERSION:
        record["revision"] = revision
        record["supersedes_digest"] = supersedes_digest
    elif version == COMPLETION_MERGE_VERSION:
        record["revision"] = revision
        record["supersedes_digests"] = list(supersedes_digests)
    body = canonical_json(record)
    record["signature"] = b64u_encode(claimant.sign(body))
    reason = _check_shape(record, now_ms=completed_at, max_age_ms=None)
    if reason is not None:  # pragma: no cover - defensive self-check
        raise MissionCompletionRejected(reason)
    return record


def verify_mission_completion(
    record: Any,
    *,
    claim_receipt: dict[str, Any] | None = None,
    authority_ack: dict[str, Any] | None = None,
    execution_receipt: dict[str, Any] | None = None,
    expected_authority_did: str = "",
    expected_federation_key: str = "",
    now_ms: int | None = None,
    max_age_ms: int | None = None,
    require_evidence: bool = True,
) -> tuple[bool, str]:
    """Verify a completion record.

    Verification-grade mode is the default: all three evidence objects plus
    the expected source authority DID and federation key are required.  A
    projection that only needs to authenticate the claimant's statement may
    explicitly pass ``require_evidence=False``.  That mode proves who signed
    the statement, not that the mission completed.
    """

    now = now_ms if now_ms is not None else int(time.time() * 1000)
    reason = _check_shape(record, now_ms=now, max_age_ms=max_age_ms)
    if reason is not None:
        return False, reason
    if not _NACL_AVAILABLE or _VerifyKey is None:
        return False, "crypto unavailable"
    try:
        signature_text = record["signature"]
        signature = b64u_decode(signature_text)
        if len(signature) != 64 or b64u_encode(signature) != signature_text:
            return False, "signature encoding invalid"
        body = canonical_json({k: v for k, v in record.items() if k != "signature"})
        from nth_dao.did_key import decode_ed25519_did_key_hex

        key_hex = decode_ed25519_did_key_hex(record["claimant_did"]) or ""
        _VerifyKey(bytes.fromhex(key_hex)).verify(body, signature)
    except (
        _BadSignatureError,
        DIDKeyError,
        KeyError,
        TypeError,
        ValueError,
        UnicodeError,
    ):
        return False, "signature verification failed"
    if type(require_evidence) is not bool:
        return False, "require_evidence must be boolean"
    evidence = (claim_receipt, authority_ack, execution_receipt)
    if any(item is not None for item in evidence) and not all(
        item is not None for item in evidence
    ):
        return False, "verification-grade mode requires all three evidence objects"
    if not any(item is not None for item in evidence):
        if require_evidence:
            return False, "completion evidence is required"
        return True, "ok"
    if all(item is not None for item in evidence):
        assert claim_receipt is not None
        assert authority_ack is not None
        assert execution_receipt is not None
        if not expected_authority_did or not expected_federation_key:
            return False, "trusted announcement authority context is required"
        try:
            if receipt_digest(claim_receipt) != record["claim_receipt_digest"]:
                return False, "claim receipt digest does not match the record"
            if receipt_digest(authority_ack) != record["authority_ack_digest"]:
                return (
                    False,
                    "authority acknowledgement digest does not match the record",
                )
            if receipt_digest(execution_receipt) != record["execution_receipt_digest"]:
                return False, "execution receipt digest does not match the record"
        except (TypeError, ValueError, RecursionError):
            return False, "completion evidence is not canonical JSON"
        error = _claim_receipt_error(
            claim_receipt, announcement_id=record["announcement_id"],
            claimant_did=record["claimant_did"],
        )
        if error is not None:
            return False, error
        error = _authority_ack_error(
            authority_ack, announcement_id=record["announcement_id"],
            claimant_did=record["claimant_did"], claim_receipt=claim_receipt,
            expected_authority_did=expected_authority_did,
            expected_federation_key=expected_federation_key,
        )
        if error is not None:
            return False, error
        error = _execution_receipt_error(
            execution_receipt, mission_id=record["mission_id"],
            claimant_did=record["claimant_did"], outcome=record["outcome"],
            claim_at_ms=claim_receipt["timeline"][0]["timestamp"],
            accepted_at_ms=authority_ack["accepted_at_ms"],
            completed_at_ms=record["completed_at_ms"],
        )
        if error is not None:
            return False, error
        return True, "ok"
    return False, "completion evidence is required"


def verify_confirmed_mission_completion(
    workspace: Path,
    nonce: str,
    record: Any,
    execution_receipt: dict[str, Any],
    *,
    now_ms: int | None = None,
) -> tuple[bool, str]:
    """Verify completion against the locally confirmed source claim."""

    from nth_dao.market.claim_evidence import resolve_confirmed_claim_evidence

    evidence = resolve_confirmed_claim_evidence(workspace, nonce)
    intent = evidence["intent"]
    if not isinstance(record, dict) or (
        record.get("announcement_id") != intent["announcement_id"]
        or record.get("claimant_did") != intent["claimant_did"]
    ):
        return False, "completion does not bind the confirmed claim"
    claim_timeline = evidence["claim_receipt"]["timeline"]
    claimed_mission_id = claim_timeline[0]["payload"]["mission_id"]
    if claimed_mission_id and record.get("mission_id") != claimed_mission_id:
        return False, "completion mission differs from signed claim"
    return verify_mission_completion(
        record,
        claim_receipt=evidence["claim_receipt"],
        authority_ack=evidence["authority_ack"],
        execution_receipt=execution_receipt,
        expected_authority_did=evidence["source_did"],
        expected_federation_key=evidence["federation_key"],
        now_ms=now_ms,
    )


def resolve_completion_lineage(
    envelopes: dict[str, dict[str, Any]],
) -> tuple[list[str], list[str]]:
    """Validate signed-envelope ancestry and return topological order and heads.

    Callers must verify signatures and claim bindings before using this graph.
    An unresolved fork is reported as multiple heads, never silently selected.
    """
    children: set[str] = set()
    for digest, envelope in envelopes.items():
        if _DIGEST_RE.fullmatch(digest) is None:
            raise CompletionLineageError("completion envelope digest is invalid")
        record = envelope["completion_record"]
        version = record["version"]
        if version == COMPLETION_VERSION:
            parents: list[str] = []
            rank = 0
        elif version == COMPLETION_REVISION_VERSION:
            parents = [record["supersedes_digest"]]
            rank = record["revision"]
        elif version == COMPLETION_MERGE_VERSION:
            parents = record["supersedes_digests"]
            rank = record["revision"]
        else:
            raise CompletionLineageError("completion version is invalid")
        if any(parent not in envelopes for parent in parents):
            raise CompletionLineageError("completion revision predecessor is missing")
        if parents and (
            rank != max(envelopes[parent]["completion_record"].get("revision", 0)
                        for parent in parents) + 1
            or any(record["completed_at_ms"] <
                   envelopes[parent]["completion_record"]["completed_at_ms"]
                   for parent in parents)
        ):
            raise CompletionLineageError("completion revision order is invalid")
        children.update(parents)
    order = sorted(
        envelopes,
        key=lambda digest: (
            envelopes[digest]["completion_record"].get("revision", 0), digest,
        ),
    )
    heads = [digest for digest in order if digest not in children]
    if not heads and envelopes:
        raise CompletionLineageError("completion revision cycle")
    return order, heads


__all__ = [
    "COMPLETION_FIELDS",
    "COMPLETION_KIND",
    "COMPLETION_REVISION_FIELDS",
    "COMPLETION_REVISION_VERSION",
    "COMPLETION_MERGE_FIELDS",
    "COMPLETION_MERGE_VERSION",
    "COMPLETION_VERSION",
    "CompletionLineageError",
    "OUTCOME_FAILED",
    "OUTCOME_SUCCEEDED",
    "MissionCompletionRejected",
    "receipt_digest",
    "sign_mission_completion",
    "verify_mission_completion",
    "verify_confirmed_mission_completion",
    "resolve_completion_lineage",
]
