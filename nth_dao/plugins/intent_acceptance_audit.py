"""Explicit Host projection of local acceptance observations into signed Spine.

An anchor is a node's historical observation, not proof of correct policy,
envelope availability, current authorization, or permission to execute.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re

from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import DIDKeyError, decode_ed25519_did_key, encode_ed25519_did_key
from nth_dao.execution_receipt import now_ms
from nth_dao.spine import SignedEventLog, SpineEvent, SpineSemanticConflict, verify_event

from .intent_acceptance import IntentAcceptanceRecord, IntentAcceptanceStore


EVENT_INTENT_ACCEPTED = "intent.accepted"
INTENT_ACCEPTANCE_ANCHOR_FORMAT = "org.nth-dao.intent-acceptance-anchor.v1"
_MAX_INTEGER = 2**53 - 1
_HASH = re.compile(r"sha256:[0-9a-f]{64}")
_HASH_FIELDS = ("envelope_digest", "context_digest", "observation_digest")
_FIELDS = frozenset({
    "format", "audience_did", *_HASH_FIELDS, "acceptance_sequence",
    "accepted_at_ms", "previous_observation_digest", "authority",
    "commit_authority", "executable",
})
INTENT_ACCEPTANCE_ANCHOR_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": sorted(_FIELDS),
    "properties": {
        "format": {"type": "string", "enum": [INTENT_ACCEPTANCE_ANCHOR_FORMAT]},
        "audience_did": {"type": "string", "minLength": 1, "maxLength": 128},
        **{field: {"type": "string", "minLength": 71, "maxLength": 71} for field in _HASH_FIELDS},
        "previous_observation_digest": {"type": "string", "maxLength": 71},
        "acceptance_sequence": {"type": "integer", "minimum": 1, "maximum": _MAX_INTEGER},
        "accepted_at_ms": {"type": "integer", "minimum": 0, "maximum": _MAX_INTEGER},
        "authority": {"type": "string", "enum": ["none"]},
        "commit_authority": {"type": "boolean", "enum": [False]},
        "executable": {"type": "boolean", "enum": [False]},
    },
}


class IntentAcceptanceAuditError(RuntimeError):
    """Projection failed; recover I/O failures or inspect integrity conflicts."""


def _validate_did(value: str) -> None:
    if type(value) is not str or not 1 <= len(value) <= 128:
        raise IntentAcceptanceAuditError("anchor audience must be a canonical Ed25519 DID")
    try:
        if encode_ed25519_did_key(decode_ed25519_did_key(value)) == value:
            return
    except DIDKeyError:
        pass
    raise IntentAcceptanceAuditError("anchor audience must be a canonical Ed25519 DID")


def _observation(payload: dict) -> dict:
    return {
        "format": "org.nth-dao.intent-acceptance-observation.v1",
        "event_type": EVENT_INTENT_ACCEPTED,
        "sequence": payload["acceptance_sequence"],
        "envelope_digest": payload["envelope_digest"],
        "context_digest": payload["context_digest"],
        "accepted_at_ms": payload["accepted_at_ms"],
        "previous_audit_digest": payload["previous_observation_digest"],
        "authority": "none", "commit_authority": False, "executable": False,
    }


def validate_intent_acceptance_anchor(value: dict) -> dict:
    """Validate a detached claim's shape and hashes, not its truth or signature."""
    if type(value) is not dict:
        raise IntentAcceptanceAuditError("anchor has missing or unknown fields")
    payload = dict(value)
    if set(payload) != _FIELDS:
        raise IntentAcceptanceAuditError("anchor has missing or unknown fields")
    if (
        type(payload["format"]) is not str or payload["format"] != INTENT_ACCEPTANCE_ANCHOR_FORMAT
        or type(payload["authority"]) is not str or payload["authority"] != "none"
    ):
        raise IntentAcceptanceAuditError("anchor format or authority is invalid")
    if payload["commit_authority"] is not False or payload["executable"] is not False:
        raise IntentAcceptanceAuditError("an acceptance anchor cannot grant execution authority")
    _validate_did(payload["audience_did"])
    for field in _HASH_FIELDS:
        if type(payload[field]) is not str or _HASH.fullmatch(payload[field]) is None:
            raise IntentAcceptanceAuditError("anchor content digest is invalid")
    for field, minimum in (("acceptance_sequence", 1), ("accepted_at_ms", 0)):
        if type(payload[field]) is not int or not minimum <= payload[field] <= _MAX_INTEGER:
            raise IntentAcceptanceAuditError("anchor sequence or time is invalid")
    previous = payload["previous_observation_digest"]
    if type(previous) is not str or (
        previous != "" and _HASH.fullmatch(previous) is None
    ) or (payload["acceptance_sequence"] == 1) != (previous == ""):
        raise IntentAcceptanceAuditError("anchor predecessor is invalid")
    digest = "sha256:" + hashlib.sha256(canonical_json(_observation(payload))).hexdigest()
    if payload["observation_digest"] != digest:
        raise IntentAcceptanceAuditError("anchor observation digest mismatch")
    return payload


def _anchor_payload(record: IntentAcceptanceRecord) -> dict:
    # Only the bridge supplies records, after full journal verification.
    return validate_intent_acceptance_anchor({
        "format": INTENT_ACCEPTANCE_ANCHOR_FORMAT,
        "audience_did": record.envelope["audience_did"],
        "envelope_digest": record.envelope_digest,
        "context_digest": record.audit["context_digest"],
        "acceptance_sequence": record.sequence,
        "accepted_at_ms": record.accepted_at_ms,
        "previous_observation_digest": record.previous_audit_digest,
        "observation_digest": record.audit_digest,
        "authority": "none", "commit_authority": False, "executable": False,
    })


def verify_intent_acceptance_anchor(
    event: SpineEvent, *, expected_audience_did: str,
) -> dict:
    """Verify one node-signed historical claim against a Host-pinned audience."""
    _validate_did(expected_audience_did)
    if type(event) is not SpineEvent:
        raise IntentAcceptanceAuditError("anchor must be a signed Spine event")
    # Bind every check to captured fields, never re-read the caller's event.
    event = SpineEvent(**event.to_dict())
    payload = validate_intent_acceptance_anchor(event.payload)
    event.payload = payload
    if event.type != EVENT_INTENT_ACCEPTED or not (
        event.author_did == payload["audience_did"] == expected_audience_did
    ):
        raise IntentAcceptanceAuditError("anchor type or audience signer does not match")
    if (
        type(event.seq) is not int or not 0 <= event.seq <= _MAX_INTEGER
        or type(event.ts_ms) is not int
        or not max(1, payload["accepted_at_ms"]) <= event.ts_ms <= _MAX_INTEGER
        or type(event.sig) is not str or len(event.sig) != 86
    ):
        raise IntentAcceptanceAuditError("anchor event sequence, time or signature is invalid")
    valid, _reason = verify_event(event)
    if not valid:
        raise IntentAcceptanceAuditError("anchor event signature or content hash is invalid")
    return payload


@dataclass(frozen=True)
class IntentAcceptanceAnchor:
    acceptance_sequence: int
    envelope_digest: str
    event_id: str
    created: bool


@dataclass(frozen=True)
class IntentAcceptanceReconciliation:
    anchors: tuple[IntentAcceptanceAnchor, ...]
    next_sequence: int
    has_more: bool


class IntentAcceptanceSpineBridge:
    """Replay committed local observations into one explicitly chosen node log.

    The journal is the durable work list. No separate acknowledgement store or
    cursor is trusted. Recover I/O failures by retrying the same page, including
    after an uncertain append. Integrity conflicts require inspection first.
    Startup recovery may safely start at sequence zero again.
    This never accepts an envelope, reevaluates governance, or executes work.
    """

    def __init__(
        self, store: IntentAcceptanceStore, spine: SignedEventLog, *, audience_did: str,
    ) -> None:
        if type(store) is not IntentAcceptanceStore or type(spine) is not SignedEventLog:
            raise TypeError("bridge requires a local acceptance store and signed node log")
        _validate_did(audience_did)
        if spine.signer_did != audience_did:
            raise IntentAcceptanceAuditError("Spine signer must be the pinned acceptance audience")
        self.store, self.spine, self.audience_did = store, spine, audience_did

    def reconcile(
        self, *, after_sequence: int = 0, limit: int = 100,
    ) -> IntentAcceptanceReconciliation:
        """Verify one journal snapshot and anchor at most 100 observations.

        Pagination is an operator hint, not proof that earlier rows are anchored.
        A batch is not atomic across SQLite and Spine: an error may leave a valid
        prefix. The full page remains retryable by exact content-bound keys.
        """
        if type(after_sequence) is not int or not 0 <= after_sequence <= _MAX_INTEGER:
            raise ValueError("after_sequence must be a nonnegative safe integer")
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit must be within 1..100")
        store, spine, audience = self.store, self.spine, self.audience_did
        if spine.signer_did != audience:
            raise IntentAcceptanceAuditError("Spine signer changed; an explicit new binding is required")
        # history() verifies all stored rows, then releases every SQLite lock.
        page = store.history(after_sequence=after_sequence, limit=limit + 1)
        payloads = tuple(_anchor_payload(record) for record in page[:limit])
        if any(payload["audience_did"] != audience for payload in payloads):
            raise IntentAcceptanceAuditError("journal page belongs to a different acceptance audience")
        if not payloads:
            return IntentAcceptanceReconciliation((), after_sequence, False)
        expected = {payload["envelope_digest"]: payload for payload in payloads}

        def validate_anchor(event: SpineEvent) -> None:
            verified = verify_intent_acceptance_anchor(event, expected_audience_did=audience)
            if verified != expected.get(verified["envelope_digest"]):
                raise IntentAcceptanceAuditError("conflicting acceptance audit anchor")

        try:
            timestamp = max(now_ms(), 1, *(payload["accepted_at_ms"] for payload in payloads))
            appended = spine.append_unique_many(
                EVENT_INTENT_ACCEPTED, payloads,
                unique_payload_fields=("envelope_digest", "observation_digest"),
                ts_ms=timestamp,
                validate_event=validate_anchor,
            )
            if len(appended) != len(payloads):
                raise IntentAcceptanceAuditError("Spine returned an incomplete acceptance page")
            anchors = []
            for payload, (event, created) in zip(payloads, appended):
                if type(created) is not bool or verify_intent_acceptance_anchor(
                    event, expected_audience_did=audience,
                ) != payload:
                    raise IntentAcceptanceAuditError("Spine returned an unbound acceptance anchor")
                anchors.append(IntentAcceptanceAnchor(
                    payload["acceptance_sequence"], payload["envelope_digest"], event.event_id, created,
                ))
        except IntentAcceptanceAuditError:
            raise
        except SpineSemanticConflict:
            raise IntentAcceptanceAuditError("duplicate or conflicting acceptance audit anchor") from None
        except OSError:
            # Neither paths nor provider exception text belong in caller output.
            # append_unique_many recovers its durable append intent on the retry.
            raise IntentAcceptanceAuditError("Spine I/O unavailable or outcome uncertain; recover and retry the same journal page") from None
        except (RuntimeError, TypeError, ValueError):
            raise IntentAcceptanceAuditError("Spine integrity or contract check failed; inspect before retrying") from None
        return IntentAcceptanceReconciliation(tuple(anchors), page[len(payloads) - 1].sequence, len(page) > limit)
