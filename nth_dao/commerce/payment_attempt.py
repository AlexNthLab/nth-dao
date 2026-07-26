"""Signed, durable work records for external payment side effects.

The per-attempt head journal detects rollback of the main attempt document and
survives the local prepared/write/committed crash windows. It is an independent
local witness, not an external transparency log: an attacker who can roll back
both the attempt and its journal can only be detected by a future EventBus or
remote witness anchor.

``orphaned`` means a provider may have committed value but returned evidence
that cannot be accepted. It is deliberately terminal for the automatic worker;
an operator or dedicated reconciliation flow must resolve it without blind pay
retries.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import decode_ed25519_did_key_hex, is_did_key
from nth_dao.identity import _NACL_AVAILABLE
from nth_dao.util.io import InterProcessLock, atomic_write_json
from nth_dao.commerce.payment_witness import (
    FilePaymentAttemptHeadWitness,
    PaymentAttemptHeadWitness,
    PaymentWitnessRejected,
)
from nth_dao.commerce.settlement import (
    ADAPTER_X402_TESTNET,
    REJECT_AMOUNT_INVALID,
    REJECT_AMOUNT_MISMATCH,
    REJECT_CURRENCY_MISMATCH,
    REJECT_CURRENCY_UNSUPPORTED,
    REJECT_IDEMPOTENCY_KEY_MISMATCH,
    REJECT_INTENT_INVALID,
    REJECT_NETWORK_MISSING,
    REJECT_NETWORK_NOT_TESTNET,
    REJECT_PAYEE_MISMATCH,
    REJECT_PAYER_MISMATCH,
    REJECT_PROOF_MISSING,
    REJECT_RECEIPT_NOT_FOUND,
    REJECT_TRADE_MISMATCH,
    REJECT_TX_REF_MISSING,
    REJECT_UNKNOWN_ADAPTER,
    REJECT_WRONG_SETTLER,
    SettlementFailed,
    SettlementIntent,
    X402SettlementAdapter,
    settlement_idempotency_key,
    verify_settlement,
)

try:
    from nacl.exceptions import BadSignatureError as _BadSignatureError
    from nacl.signing import VerifyKey as _VerifyKey
except ImportError:  # pragma: no cover
    _BadSignatureError = ValueError  # type: ignore[assignment,misc]
    _VerifyKey = None  # type: ignore[assignment]

PathLike = Union[str, Path]

PAYMENT_ATTEMPT_KIND = "nth-payment-attempt-event-v1"
EVENT_CREATED = "payment_attempt_created"
EVENT_CLAIMED = "payment_attempt_claimed"
EVENT_RETRY_SCHEDULED = "payment_attempt_retry_scheduled"
EVENT_SETTLED = "payment_attempt_settled"
EVENT_BLOCKED = "payment_attempt_blocked"
EVENT_ORPHANED = "payment_attempt_orphaned"
EVENT_ORPHAN_RECONCILED = "payment_attempt_orphan_reconciled"

STATE_PENDING = "pending"
STATE_INFLIGHT = "inflight"
STATE_SETTLED = "settled"
STATE_BLOCKED = "blocked"
STATE_ORPHANED = "orphaned"

_ATTEMPT_ID = re.compile(r"^nth-settlement:v1:sha256:[0-9a-f]{64}$")
_LEASE_ID = re.compile(r"^[0-9a-f]{32}$")
_EVENT_FIELDS = frozenset({
    "attempt_id",
    "seq",
    "type",
    "actor_did",
    "prev_state",
    "new_state",
    "payload",
    "prev_event_hash",
    "created_at_ms",
    "kind",
    "signature",
})
_LEGACY_EVENT_FIELDS = _EVENT_FIELDS - {"prev_event_hash"}
_CREATE_FIELDS = frozenset({"schema_version", "adapter_id", "intent"})
_INTENT_FIELDS = frozenset({
    "trade_id",
    "amount_minor",
    "currency",
    "payee_did",
    "payer_did",
    "memo",
})
_MAX_EVENT_BYTES = 192 * 1024
_MAX_CHAIN_BYTES = 768 * 1024
_MAX_FILE_BYTES = 1024 * 1024
_MAX_JSON_DEPTH = 32
_MAX_JSON_NODES = 65_536
_EVENT_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_ERROR_CODE = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")
_ANCHOR_PHASES = frozenset({"prepared", "committed"})
_ANCHOR_FIELDS = frozenset({
    "operation_id",
    "phase",
    "attempt_id",
    "seq",
    "head_hash",
    "actor_did",
    "created_at_ms",
    "signature",
})
_MAX_ANCHOR_FILE_BYTES = 512 * 1024
logger = logging.getLogger(__name__)
_PERMANENT_SETTLEMENT_FAILURES = frozenset({
    "rail-declined",
    REJECT_AMOUNT_INVALID,
    REJECT_AMOUNT_MISMATCH,
    REJECT_CURRENCY_MISMATCH,
    REJECT_CURRENCY_UNSUPPORTED,
    REJECT_IDEMPOTENCY_KEY_MISMATCH,
    REJECT_INTENT_INVALID,
    REJECT_NETWORK_MISSING,
    REJECT_NETWORK_NOT_TESTNET,
    REJECT_PAYEE_MISMATCH,
    REJECT_PAYER_MISMATCH,
    REJECT_PROOF_MISSING,
    REJECT_TRADE_MISMATCH,
    REJECT_TX_REF_MISSING,
    REJECT_UNKNOWN_ADAPTER,
    REJECT_WRONG_SETTLER,
})


def _preflight_attempt_json(value: Any) -> bool:
    """Bound an in-memory JSON tree before canonical encoding."""
    stack = [(value, 0)]
    seen_containers: set[int] = set()
    nodes = 0
    string_characters = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_JSON_NODES:
            return False
        if item is None or type(item) in {bool, int}:
            if type(item) is int and item.bit_length() > _MAX_CHAIN_BYTES * 4:
                return False
            continue
        if type(item) is str:
            string_characters += len(item)
            if string_characters > _MAX_CHAIN_BYTES:
                return False
            continue
        if type(item) not in {dict, list}:
            return False
        container_id = id(item)
        if container_id in seen_containers:
            return False
        seen_containers.add(container_id)
        if depth >= _MAX_JSON_DEPTH and item:
            return False
        if len(item) > _MAX_JSON_NODES:
            return False
        if type(item) is dict:
            for key, child in item.items():
                if type(key) is not str:
                    return False
                string_characters += len(key)
                if string_characters > _MAX_CHAIN_BYTES:
                    return False
                stack.append((child, depth + 1))
        else:
            stack.extend((child, depth + 1) for child in item)
    return True


class PaymentAttemptRejected(ValueError):
    pass


class PaymentAttemptConflict(RuntimeError):
    pass


@dataclass
class PaymentAttemptHeadAnchor:
    operation_id: str
    phase: str
    attempt_id: str
    seq: int
    head_hash: str
    actor_did: str
    created_at_ms: int
    signature: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def signing_body(self) -> Dict[str, Any]:
        return {key: value for key, value in self.to_dict().items() if key != "signature"}


def _sign_anchor(actor: Any, anchor: PaymentAttemptHeadAnchor) -> None:
    if actor.as_did() != anchor.actor_did:
        raise PaymentAttemptRejected("payment attempt anchor actor mismatch")
    anchor.signature = b64u_encode(actor.sign(canonical_json(anchor.signing_body())))


def _verify_anchor(anchor: PaymentAttemptHeadAnchor) -> Tuple[bool, str]:
    if (
        not _LEASE_ID.fullmatch(anchor.operation_id)
        or anchor.phase not in _ANCHOR_PHASES
        or not _ATTEMPT_ID.fullmatch(anchor.attempt_id)
        or isinstance(anchor.seq, bool)
        or not isinstance(anchor.seq, int)
        or anchor.seq < 0
        or not _EVENT_HASH.fullmatch(anchor.head_hash)
        or not is_did_key(anchor.actor_did)
        or isinstance(anchor.created_at_ms, bool)
        or not isinstance(anchor.created_at_ms, int)
        or anchor.created_at_ms <= 0
    ):
        return False, "payment attempt anchor metadata is invalid"
    if not _NACL_AVAILABLE or _VerifyKey is None:
        return False, "crypto unavailable"
    try:
        signature = b64u_decode(anchor.signature)
        if len(signature) != 64 or b64u_encode(signature) != anchor.signature:
            return False, "payment attempt anchor signature invalid"
        key_hex = decode_ed25519_did_key_hex(anchor.actor_did) or ""
        _VerifyKey(bytes.fromhex(key_hex)).verify(
            canonical_json(anchor.signing_body()), signature
        )
    except (_BadSignatureError, TypeError, ValueError, UnicodeError):
        return False, "payment attempt anchor signature invalid"
    return True, "ok"


@dataclass
class PaymentAttemptEvent:
    attempt_id: str
    seq: int
    type: str
    actor_did: str
    prev_state: str
    new_state: str
    payload: Dict[str, Any] = field(default_factory=dict)
    prev_event_hash: str = ""
    created_at_ms: int = 0
    kind: str = PAYMENT_ATTEMPT_KIND
    signature: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def signing_body(self) -> Dict[str, Any]:
        return {key: value for key, value in self.to_dict().items() if key != "signature"}

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "PaymentAttemptEvent":
        return cls(**{key: value[key] for key in _EVENT_FIELDS})


def payment_attempt_event_hash(value: PaymentAttemptEvent | Dict[str, Any]) -> str:
    document = value.to_dict() if isinstance(value, PaymentAttemptEvent) else value
    return "sha256:" + hashlib.sha256(canonical_json(document)).hexdigest()


@dataclass(frozen=True)
class PaymentAttemptView:
    attempt_id: str
    actor_did: str
    adapter_id: str
    intent: Dict[str, Any]
    state: str
    lease_id: str = ""
    lease_expires_at_ms: int = 0
    next_attempt_at_ms: int = 0
    attempts: int = 0
    last_error: str = ""
    settlement: Dict[str, Any] = field(default_factory=dict)
    provider_reference: str = ""
    evidence_digest: str = ""


def _intent_dict(intent: SettlementIntent) -> Dict[str, Any]:
    intent.validate()
    return {
        "trade_id": intent.trade_id,
        "amount_minor": intent.amount_minor,
        "currency": intent.currency,
        "payee_did": intent.payee_did,
        "payer_did": intent.payer_did,
        "memo": intent.memo,
    }


def _intent_from_dict(value: Any) -> SettlementIntent:
    if not isinstance(value, dict) or set(value) != _INTENT_FIELDS:
        raise PaymentAttemptRejected("payment intent has missing or unknown fields")
    try:
        intent = SettlementIntent(**value)
        intent.validate()
    except (SettlementFailed, TypeError, ValueError) as exc:
        raise PaymentAttemptRejected(f"payment intent is invalid: {exc}") from exc
    return intent


def _sign_event(actor: Any, event: PaymentAttemptEvent) -> PaymentAttemptEvent:
    if actor.as_did() != event.actor_did:
        raise PaymentAttemptRejected("payment attempt signer does not match actor")
    event.signature = b64u_encode(actor.sign(canonical_json(event.signing_body())))
    return event


def _verify_signature(event: PaymentAttemptEvent) -> Tuple[bool, str]:
    if not _NACL_AVAILABLE or _VerifyKey is None:
        return False, "crypto unavailable"
    if not is_did_key(event.actor_did):
        return False, "invalid payment attempt actor DID"
    if not isinstance(event.signature, str) or not (1 <= len(event.signature) <= 128):
        return False, "payment attempt signature invalid"
    try:
        signature = b64u_decode(event.signature)
        if len(signature) != 64 or b64u_encode(signature) != event.signature:
            return False, "payment attempt signature invalid"
        key_hex = decode_ed25519_did_key_hex(event.actor_did) or ""
        _VerifyKey(bytes.fromhex(key_hex)).verify(
            canonical_json(event.signing_body()), signature
        )
    except (_BadSignatureError, TypeError, ValueError, UnicodeError):
        return False, "payment attempt signature invalid"
    return True, "ok"


def _verify_legacy_signature(raw: Dict[str, Any]) -> Tuple[bool, str]:
    actor_did = raw.get("actor_did")
    signature_text = raw.get("signature")
    if not _NACL_AVAILABLE or _VerifyKey is None:
        return False, "crypto unavailable"
    if not isinstance(actor_did, str) or not is_did_key(actor_did):
        return False, "invalid legacy payment attempt actor DID"
    if (
        not isinstance(signature_text, str)
        or not 1 <= len(signature_text) <= 128
    ):
        return False, "legacy payment attempt signature invalid"
    try:
        signature = b64u_decode(signature_text)
        if len(signature) != 64 or b64u_encode(signature) != signature_text:
            return False, "legacy payment attempt signature invalid"
        body = {key: value for key, value in raw.items() if key != "signature"}
        key_hex = decode_ed25519_did_key_hex(actor_did) or ""
        _VerifyKey(bytes.fromhex(key_hex)).verify(canonical_json(body), signature)
    except (
        _BadSignatureError,
        TypeError,
        ValueError,
        UnicodeError,
        OverflowError,
        RecursionError,
    ):
        return False, "legacy payment attempt signature invalid"
    return True, "ok"


def _legacy_payload(event_type: str, payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise PaymentAttemptRejected("legacy payment attempt payload is invalid")
    migrated = dict(payload)
    if event_type in {EVENT_RETRY_SCHEDULED, EVENT_BLOCKED}:
        error = migrated.pop("error", migrated.get("error_code", ""))
        migrated["error_code"] = (
            error
            if isinstance(error, str) and _ERROR_CODE.fullmatch(error)
            else (
                "legacy-retry-error"
                if event_type == EVENT_RETRY_SCHEDULED
                else "legacy-block-error"
            )
        )
    return migrated


def _project_verified(events: List[Dict[str, Any]]) -> PaymentAttemptView:
    created = PaymentAttemptEvent.from_dict(events[0])
    adapter_id = created.payload["adapter_id"]
    intent = dict(created.payload["intent"])
    state = STATE_PENDING
    lease_id = ""
    lease_expires_at_ms = 0
    next_attempt_at_ms = 0
    attempts = 0
    last_error = ""
    settlement: Dict[str, Any] = {}
    provider_reference = ""
    evidence_digest = ""
    for raw in events[1:]:
        event = PaymentAttemptEvent.from_dict(raw)
        state = event.new_state
        if event.type == EVENT_CLAIMED:
            lease_id = event.payload["lease_id"]
            lease_expires_at_ms = event.payload["lease_expires_at_ms"]
            next_attempt_at_ms = 0
            attempts += 1
        elif event.type == EVENT_RETRY_SCHEDULED:
            lease_id = ""
            lease_expires_at_ms = 0
            next_attempt_at_ms = event.payload["next_attempt_at_ms"]
            last_error = event.payload["error_code"]
        elif event.type == EVENT_SETTLED:
            lease_id = ""
            lease_expires_at_ms = 0
            settlement = dict(event.payload["settlement"])
            last_error = ""
        elif event.type == EVENT_BLOCKED:
            lease_id = ""
            lease_expires_at_ms = 0
            last_error = event.payload["error_code"]
        elif event.type == EVENT_ORPHANED:
            lease_id = ""
            lease_expires_at_ms = 0
            last_error = event.payload["error_code"]
            provider_reference = event.payload["provider_reference"]
            evidence_digest = event.payload["evidence_digest"]
        elif event.type == EVENT_ORPHAN_RECONCILED:
            settlement = dict(event.payload["settlement"])
            last_error = ""
            provider_reference = ""
            evidence_digest = ""
    return PaymentAttemptView(
        attempt_id=created.attempt_id,
        actor_did=created.actor_did,
        adapter_id=adapter_id,
        intent=intent,
        state=state,
        lease_id=lease_id,
        lease_expires_at_ms=lease_expires_at_ms,
        next_attempt_at_ms=next_attempt_at_ms,
        attempts=attempts,
        last_error=last_error,
        settlement=settlement,
        provider_reference=provider_reference,
        evidence_digest=evidence_digest,
    )


def verify_payment_attempt(events: List[Dict[str, Any]]) -> Tuple[bool, str]:
    if type(events) is not list or not events:
        return False, "payment attempt is empty"
    if not _preflight_attempt_json(events):
        return False, "payment attempt exceeds JSON resource limits"
    try:
        if len(canonical_json({"events": events})) > _MAX_CHAIN_BYTES:
            return False, "payment attempt chain is too large"
    except (TypeError, ValueError, OverflowError, RecursionError):
        return False, "payment attempt chain is not canonical JSON"

    state = ""
    actor_did = ""
    attempt_id = ""
    intent: Optional[SettlementIntent] = None
    lease_id = ""
    lease_expires_at_ms = 0
    next_attempt_at_ms = 0
    orphan_evidence_digest = ""
    last_created_at_ms = 0
    for index, raw in enumerate(events):
        if not isinstance(raw, dict) or set(raw) != _EVENT_FIELDS:
            return False, "payment attempt event has missing or unknown fields"
        try:
            if len(canonical_json(raw)) > _MAX_EVENT_BYTES:
                return False, "payment attempt event is too large"
            event = PaymentAttemptEvent.from_dict(raw)
        except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
            return False, "payment attempt event is malformed"
        if (
            not _ATTEMPT_ID.fullmatch(event.attempt_id)
            or event.seq != index
            or event.kind != PAYMENT_ATTEMPT_KIND
            or event.prev_event_hash
            != ("" if index == 0 else payment_attempt_event_hash(events[index - 1]))
            or not isinstance(event.payload, dict)
            or isinstance(event.created_at_ms, bool)
            or not isinstance(event.created_at_ms, int)
            or event.created_at_ms <= 0
            or event.created_at_ms < last_created_at_ms
        ):
            return False, "payment attempt event metadata is invalid"
        ok, reason = _verify_signature(event)
        if not ok:
            return False, reason
        if index == 0:
            if (
                event.type != EVENT_CREATED
                or event.prev_state != ""
                or event.new_state != STATE_PENDING
                or set(event.payload) != _CREATE_FIELDS
                or event.payload.get("schema_version") != 1
                or event.payload.get("adapter_id") != ADAPTER_X402_TESTNET
            ):
                return False, "payment attempt creation event is invalid"
            try:
                intent = _intent_from_dict(event.payload.get("intent"))
            except PaymentAttemptRejected as exc:
                return False, str(exc)
            if (
                not intent.payer_did
                or intent.payer_did != event.actor_did
                or settlement_idempotency_key(intent) != event.attempt_id
            ):
                return False, "payment attempt creation binding is invalid"
            actor_did = event.actor_did
            attempt_id = event.attempt_id
        else:
            if event.actor_did != actor_did or event.attempt_id != attempt_id:
                return False, "payment attempt actor or id changed"
            if event.prev_state != state:
                return False, "payment attempt previous state is invalid"
            if event.type == EVENT_CLAIMED:
                if state not in {STATE_PENDING, STATE_INFLIGHT}:
                    return False, "payment attempt claim transition is invalid"
                if state == STATE_PENDING and event.created_at_ms < next_attempt_at_ms:
                    return False, "payment attempt was claimed before retry became due"
                if state == STATE_INFLIGHT and event.created_at_ms < lease_expires_at_ms:
                    return False, "payment attempt lease was stolen before expiry"
                if set(event.payload) != {"lease_id", "lease_expires_at_ms"}:
                    return False, "payment attempt claim payload is invalid"
                new_lease = event.payload.get("lease_id")
                expiry = event.payload.get("lease_expires_at_ms")
                if (
                    not isinstance(new_lease, str)
                    or not _LEASE_ID.fullmatch(new_lease)
                    or isinstance(expiry, bool)
                    or not isinstance(expiry, int)
                    or not event.created_at_ms + 1_000 <= expiry <= event.created_at_ms + 300_000
                    or event.new_state != STATE_INFLIGHT
                ):
                    return False, "payment attempt lease is invalid"
                lease_id = new_lease
                lease_expires_at_ms = expiry
                next_attempt_at_ms = 0
            elif event.type == EVENT_RETRY_SCHEDULED:
                if state != STATE_INFLIGHT or event.new_state != STATE_PENDING:
                    return False, "payment retry transition is invalid"
                if set(event.payload) != {
                    "lease_id",
                    "error_code",
                    "next_attempt_at_ms",
                }:
                    return False, "payment retry payload is invalid"
                retry_at = event.payload.get("next_attempt_at_ms")
                error_code = event.payload.get("error_code")
                if (
                    event.payload.get("lease_id") != lease_id
                    or not isinstance(error_code, str)
                    or not _ERROR_CODE.fullmatch(error_code)
                    or isinstance(retry_at, bool)
                    or not isinstance(retry_at, int)
                    or retry_at < event.created_at_ms
                ):
                    return False, "payment retry binding is invalid"
                lease_id = ""
                lease_expires_at_ms = 0
                next_attempt_at_ms = retry_at
            elif event.type == EVENT_SETTLED:
                if state != STATE_INFLIGHT or event.new_state != STATE_SETTLED:
                    return False, "payment settlement transition is invalid"
                if set(event.payload) != {"lease_id", "settlement"}:
                    return False, "payment settlement payload is invalid"
                settlement = event.payload.get("settlement")
                if event.payload.get("lease_id") != lease_id or not isinstance(settlement, dict):
                    return False, "payment settlement lease is invalid"
                assert intent is not None
                ok, reason = verify_settlement(
                    settlement,
                    expected_amount_minor=intent.amount_minor,
                    expected_currency=intent.currency,
                    expected_payee_did=intent.payee_did,
                    expected_payer_did=intent.payer_did,
                )
                proof = settlement.get("proof") if isinstance(settlement, dict) else None
                if not ok:
                    return False, f"payment settlement is invalid: {reason}"
                if not isinstance(proof, dict) or proof.get("idempotency_key") != attempt_id:
                    return False, "payment settlement idempotency binding is invalid"
                lease_id = ""
                lease_expires_at_ms = 0
            elif event.type == EVENT_BLOCKED:
                if state != STATE_INFLIGHT or event.new_state != STATE_BLOCKED:
                    return False, "payment block transition is invalid"
                if set(event.payload) != {"lease_id", "error_code"}:
                    return False, "payment block payload is invalid"
                error_code = event.payload.get("error_code")
                if (
                    event.payload.get("lease_id") != lease_id
                    or not isinstance(error_code, str)
                    or not _ERROR_CODE.fullmatch(error_code)
                ):
                    return False, "payment block binding is invalid"
                lease_id = ""
                lease_expires_at_ms = 0
            elif event.type == EVENT_ORPHANED:
                if state != STATE_INFLIGHT or event.new_state != STATE_ORPHANED:
                    return False, "payment orphan transition is invalid"
                if set(event.payload) != {
                    "lease_id",
                    "error_code",
                    "provider_reference",
                    "evidence_digest",
                }:
                    return False, "payment orphan payload is invalid"
                error_code = event.payload.get("error_code")
                provider_reference = event.payload.get("provider_reference")
                evidence_digest = event.payload.get("evidence_digest")
                if (
                    event.payload.get("lease_id") != lease_id
                    or not isinstance(error_code, str)
                    or not _ERROR_CODE.fullmatch(error_code)
                    or not isinstance(provider_reference, str)
                    or len(provider_reference) > 256
                    or not isinstance(evidence_digest, str)
                    or not _EVENT_HASH.fullmatch(evidence_digest)
                ):
                    return False, "payment orphan binding is invalid"
                lease_id = ""
                lease_expires_at_ms = 0
                orphan_evidence_digest = evidence_digest
            elif event.type == EVENT_ORPHAN_RECONCILED:
                if state != STATE_ORPHANED or event.new_state != STATE_SETTLED:
                    return False, "payment orphan reconciliation transition is invalid"
                if set(event.payload) != {
                    "settlement",
                    "orphan_evidence_digest",
                }:
                    return False, "payment orphan reconciliation payload is invalid"
                settlement = event.payload.get("settlement")
                if (
                    event.payload.get("orphan_evidence_digest")
                    != orphan_evidence_digest
                    or not isinstance(settlement, dict)
                ):
                    return False, "payment orphan reconciliation binding is invalid"
                assert intent is not None
                ok, reason = verify_settlement(
                    settlement,
                    expected_amount_minor=intent.amount_minor,
                    expected_currency=intent.currency,
                    expected_payee_did=intent.payee_did,
                    expected_payer_did=intent.payer_did,
                )
                proof = settlement.get("proof")
                if not ok:
                    return False, f"reconciled payment settlement is invalid: {reason}"
                if not isinstance(proof, dict) or proof.get("idempotency_key") != attempt_id:
                    return False, "reconciled settlement idempotency binding is invalid"
                orphan_evidence_digest = ""
            else:
                return False, "unknown payment attempt event type"
        state = event.new_state
        last_created_at_ms = event.created_at_ms
    return True, "ok"


_LOCKS: Dict[str, threading.RLock] = {}
_LOCK_GUARD = threading.Lock()


def _thread_lock(path: Path) -> threading.RLock:
    with _LOCK_GUARD:
        return _LOCKS.setdefault(str(path), threading.RLock())


class _FileLimitExceeded(ValueError):
    pass


def _read_bounded(path: Path, limit: int) -> bytes:
    with path.open("rb") as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise _FileLimitExceeded
    return raw


class PaymentAttemptStore:
    def __init__(
        self,
        root: PathLike,
        *,
        witness: Optional[PaymentAttemptHeadWitness] = None,
    ) -> None:
        workspace_root = Path(root)
        if isinstance(witness, FilePaymentAttemptHeadWitness):
            try:
                witness.root.resolve().relative_to(workspace_root.resolve())
            except ValueError:
                pass
            else:
                raise ValueError(
                    "file payment witness must be outside the workspace"
                )
        self.root = workspace_root / "commerce" / "payment_attempts"
        self.anchor_root = workspace_root / "commerce" / "payment_attempt_heads"
        self.witness = witness
        self.root.mkdir(parents=True, exist_ok=True)
        self.anchor_root.mkdir(parents=True, exist_ok=True)

    def _path(self, attempt_id: str) -> Path:
        if not isinstance(attempt_id, str) or not _ATTEMPT_ID.fullmatch(attempt_id):
            raise PaymentAttemptRejected("invalid payment attempt id")
        return self.root / f"{attempt_id.rsplit(':', 1)[-1]}.json"

    def _anchor_path(self, attempt_id: str) -> Path:
        self._path(attempt_id)
        return self.anchor_root / f"{attempt_id.rsplit(':', 1)[-1]}.jsonl"

    def _append_anchor(self, anchor: PaymentAttemptHeadAnchor) -> None:
        path = self._anchor_path(anchor.attempt_id)
        line = canonical_json(anchor.to_dict()) + b"\n"
        try:
            raw = _read_bounded(path, _MAX_ANCHOR_FILE_BYTES)
        except FileNotFoundError:
            raw = b""
        except _FileLimitExceeded as exc:
            raise PaymentAttemptRejected(
                "payment attempt head journal exceeds size limit"
            ) from exc
        except OSError as exc:
            raise PaymentAttemptRejected(
                "payment attempt head journal cannot be inspected"
            ) from exc
        if raw and not raw.endswith(b"\n"):
            try:
                tail = raw.rsplit(b"\n", 1)[-1]
                value = json.loads(tail.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeError) as exc:
                raise PaymentAttemptRejected(
                    "payment attempt head journal has a torn tail"
                ) from exc
            if not isinstance(value, dict) or set(value) != _ANCHOR_FIELDS:
                raise PaymentAttemptRejected(
                    "payment attempt head journal has an invalid tail"
                )
        separator = b"\n" if raw and not raw.endswith(b"\n") else b""
        if len(raw) + len(separator) + len(line) > _MAX_ANCHOR_FILE_BYTES:
            raise PaymentAttemptRejected(
                "payment attempt head journal exceeds size limit"
            )
        try:
            with path.open("ab") as handle:
                if separator:
                    handle.write(separator)
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise PaymentAttemptRejected(
                "payment attempt head journal cannot be persisted"
            ) from exc

    def _read_anchors(
        self,
        attempt_id: str,
        *,
        actor_did: str,
    ) -> List[PaymentAttemptHeadAnchor]:
        path = self._anchor_path(attempt_id)
        try:
            raw = _read_bounded(path, _MAX_ANCHOR_FILE_BYTES)
        except FileNotFoundError:
            return []
        except _FileLimitExceeded as exc:
            raise PaymentAttemptRejected(
                "payment attempt head journal exceeds size limit"
            ) from exc
        except PaymentAttemptRejected:
            raise
        except OSError as exc:
            raise PaymentAttemptRejected(
                "payment attempt head journal is unreadable"
            ) from exc

        # A complete JSON object without the final newline is accepted. A
        # genuinely torn object fails closed instead of disappearing from the
        # rollback witness.
        lines = raw.split(b"\n")
        if lines and lines[-1] == b"":
            lines.pop()
        anchors: List[PaymentAttemptHeadAnchor] = []
        for line in lines:
            if not line:
                raise PaymentAttemptRejected(
                    "payment attempt head journal contains an empty record"
                )
            try:
                value = json.loads(line.decode("utf-8"))
                if not isinstance(value, dict) or set(value) != _ANCHOR_FIELDS:
                    raise PaymentAttemptRejected(
                        "payment attempt head anchor has invalid shape"
                    )
                anchors.append(PaymentAttemptHeadAnchor(**value))
            except PaymentAttemptRejected:
                raise
            except (json.JSONDecodeError, TypeError, UnicodeError) as exc:
                raise PaymentAttemptRejected(
                    "payment attempt head anchor is malformed"
                ) from exc
        return self._validate_anchor_sequence(
            anchors,
            attempt_id=attempt_id,
            actor_did=actor_did,
            source="local",
        )

    @staticmethod
    def _validate_anchor_sequence(
        anchors: List[PaymentAttemptHeadAnchor],
        *,
        attempt_id: str,
        actor_did: str,
        source: str,
    ) -> List[PaymentAttemptHeadAnchor]:
        phases_by_operation: Dict[str, set[str]] = {}
        prepared_by_operation: Dict[str, PaymentAttemptHeadAnchor] = {}
        last_created_at_ms = 0
        for anchor in anchors:
            ok, reason = _verify_anchor(anchor)
            if not ok:
                raise PaymentAttemptRejected(f"{source} witness: {reason}")
            if (
                anchor.attempt_id != attempt_id
                or anchor.actor_did != actor_did
                or anchor.created_at_ms < last_created_at_ms
            ):
                raise PaymentAttemptRejected(
                    "payment attempt head anchor binding is invalid"
                )
            phases = phases_by_operation.setdefault(anchor.operation_id, set())
            if anchor.phase in phases:
                raise PaymentAttemptRejected(
                    "payment attempt head anchor phase is duplicated"
                )
            phases.add(anchor.phase)
            if anchor.phase == "prepared":
                prepared_by_operation[anchor.operation_id] = anchor
            else:
                prepared = prepared_by_operation.get(anchor.operation_id)
                if (
                    prepared is None
                    or prepared.attempt_id != anchor.attempt_id
                    or prepared.seq != anchor.seq
                    or prepared.head_hash != anchor.head_hash
                    or prepared.actor_did != anchor.actor_did
                ):
                    raise PaymentAttemptRejected(
                        "payment attempt committed anchor has no matching prepare"
                    )
            last_created_at_ms = anchor.created_at_ms
        return anchors

    def _read_witness_anchors(
        self,
        attempt_id: str,
        *,
        actor_did: str,
    ) -> List[PaymentAttemptHeadAnchor]:
        if self.witness is None:
            return []
        try:
            records = self.witness.read(attempt_id)
        except PaymentWitnessRejected as exc:
            raise PaymentAttemptRejected(str(exc)) from exc
        except (OSError, RuntimeError) as exc:
            raise PaymentAttemptRejected(
                "external payment witness is unavailable"
            ) from exc
        if not isinstance(records, list):
            raise PaymentAttemptRejected(
                "external payment witness returned an invalid response"
            )
        anchors: List[PaymentAttemptHeadAnchor] = []
        for value in records:
            if not isinstance(value, dict) or set(value) != _ANCHOR_FIELDS:
                raise PaymentAttemptRejected(
                    "external payment witness anchor has invalid shape"
                )
            try:
                anchors.append(PaymentAttemptHeadAnchor(**value))
            except TypeError as exc:
                raise PaymentAttemptRejected(
                    "external payment witness anchor is malformed"
                ) from exc
        return self._validate_anchor_sequence(
            anchors,
            attempt_id=attempt_id,
            actor_did=actor_did,
            source="external",
        )

    @staticmethod
    def _accepted_anchor_heads(
        anchors: List[PaymentAttemptHeadAnchor],
    ) -> set[Tuple[int, str]]:
        latest_committed_index = -1
        for index, anchor in enumerate(anchors):
            if anchor.phase == "committed":
                latest_committed_index = index
        return {
            (anchor.seq, anchor.head_hash)
            for index, anchor in enumerate(anchors)
            if (
                index == latest_committed_index
                or (
                    index > latest_committed_index
                    and anchor.phase == "prepared"
                )
            )
        }

    def _validate_anchor(
        self,
        attempt_id: str,
        events: List[Dict[str, Any]],
        head_hash: str,
    ) -> None:
        actor_did = events[0].get("actor_did") if events else ""
        if not isinstance(actor_did, str) or not actor_did:
            raise PaymentAttemptRejected(
                "stored payment attempt actor is invalid"
            )
        anchors = self._read_anchors(attempt_id, actor_did=actor_did)
        if not anchors:
            raise PaymentAttemptRejected(
                "stored payment attempt has no signed head journal"
            )

        accepted = self._accepted_anchor_heads(anchors)
        current = (len(events) - 1, head_hash)
        if current not in accepted:
            raise PaymentAttemptRejected(
                "stored payment attempt was rolled back or lacks a durable prepare"
            )
        if self.witness is not None:
            witnessed = self._read_witness_anchors(
                attempt_id,
                actor_did=actor_did,
            )
            if not witnessed:
                raise PaymentAttemptRejected(
                    "stored payment attempt has no external witness"
                )
            if current not in self._accepted_anchor_heads(witnessed):
                raise PaymentAttemptRejected(
                    "stored payment attempt conflicts with its external witness"
                )

    def _load(self, path: Path) -> Optional[List[Dict[str, Any]]]:
        try:
            raw = _read_bounded(path, _MAX_FILE_BYTES)
            value = json.loads(raw.decode("utf-8"))
        except FileNotFoundError:
            return None
        except _FileLimitExceeded as exc:
            raise PaymentAttemptRejected(
                "stored payment attempt exceeds size limit"
            ) from exc
        except PaymentAttemptRejected:
            raise
        except (json.JSONDecodeError, OSError, UnicodeError) as exc:
            raise PaymentAttemptRejected(f"stored payment attempt is unreadable: {path}") from exc
        expected_id = f"nth-settlement:v1:sha256:{path.stem}"
        if (
            not isinstance(value, dict)
            or set(value) != {"attempt_id", "events", "head_hash"}
            or value.get("attempt_id") != expected_id
            or not isinstance(value.get("events"), list)
            or not value["events"]
            or not isinstance(value.get("head_hash"), str)
            or not _EVENT_HASH.fullmatch(value["head_hash"])
            or value["head_hash"] != payment_attempt_event_hash(value["events"][-1])
        ):
            raise PaymentAttemptRejected("stored payment attempt has invalid shape")
        self._validate_anchor(expected_id, value["events"], value["head_hash"])
        return value["events"]

    @staticmethod
    def _document(attempt_id: str, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not events:
            raise PaymentAttemptRejected("cannot persist an empty payment attempt")
        return {
            "attempt_id": attempt_id,
            "events": events,
            "head_hash": payment_attempt_event_hash(events[-1]),
        }

    def _persist(
        self,
        path: Path,
        attempt_id: str,
        events: List[Dict[str, Any]],
        *,
        actor: Any,
        created_at_ms: int,
    ) -> None:
        document = self._document(attempt_id, events)
        anchor_values = {
            "operation_id": uuid.uuid4().hex,
            "attempt_id": attempt_id,
            "seq": len(events) - 1,
            "head_hash": document["head_hash"],
            "actor_did": actor.as_did(),
            "created_at_ms": created_at_ms,
        }
        prepared = PaymentAttemptHeadAnchor(phase="prepared", **anchor_values)
        _sign_anchor(actor, prepared)
        self._append_anchor(prepared)
        self._append_witness(prepared)
        atomic_write_json(path, document)
        committed = PaymentAttemptHeadAnchor(phase="committed", **anchor_values)
        _sign_anchor(actor, committed)
        self._append_anchor(committed)
        self._append_witness(committed)

    def _append_witness(self, anchor: PaymentAttemptHeadAnchor) -> None:
        if self.witness is None:
            return
        try:
            self.witness.append(anchor.attempt_id, anchor.to_dict())
        except PaymentWitnessRejected as exc:
            raise PaymentAttemptRejected(str(exc)) from exc
        except (OSError, RuntimeError) as exc:
            raise PaymentAttemptRejected(
                "external payment witness is unavailable"
            ) from exc

    def migrate_legacy(
        self,
        attempt_id: str,
        *,
        actor: Any,
    ) -> PaymentAttemptView:
        """Upgrade the pre-hash-chain payment-attempt format.

        Only the unambiguous legacy shape is accepted. A current-format
        document without its head journal is not migration input because
        blessing it would turn journal deletion into a rollback bypass.
        """
        path = self._path(attempt_id)
        if not getattr(actor, "can_sign", False):
            raise PaymentAttemptRejected(
                "legacy payment attempt migration requires a signing identity"
            )
        with _thread_lock(path), InterProcessLock(path):
            try:
                raw = _read_bounded(path, _MAX_FILE_BYTES)
                document = json.loads(raw.decode("utf-8"))
            except FileNotFoundError as exc:
                raise PaymentAttemptRejected("payment attempt not found") from exc
            except _FileLimitExceeded as exc:
                raise PaymentAttemptRejected(
                    "stored payment attempt exceeds size limit"
                ) from exc
            except PaymentAttemptRejected:
                raise
            except (json.JSONDecodeError, OSError, UnicodeError) as exc:
                raise PaymentAttemptRejected(
                    "legacy payment attempt is unreadable"
                ) from exc

            if (
                isinstance(document, dict)
                and set(document) == {"attempt_id", "events", "head_hash"}
            ):
                events = self._load(path)
                if events is None:
                    raise PaymentAttemptRejected("payment attempt not found")
                ok, reason = verify_payment_attempt(events)
                if not ok:
                    raise PaymentAttemptRejected(
                        f"stored payment attempt is invalid: {reason}"
                    )
                return _project_verified(events)

            if (
                not isinstance(document, dict)
                or set(document) != {"attempt_id", "events"}
                or document.get("attempt_id") != attempt_id
                or not isinstance(document.get("events"), list)
                or not document["events"]
            ):
                raise PaymentAttemptRejected(
                    "payment attempt is not an accepted legacy format"
                )

            actor_did = actor.as_did()
            migrated_events: List[Dict[str, Any]] = []
            for index, raw in enumerate(document["events"]):
                if not isinstance(raw, dict) or set(raw) != _LEGACY_EVENT_FIELDS:
                    raise PaymentAttemptRejected(
                        "legacy payment attempt event has invalid fields"
                    )
                try:
                    if len(canonical_json(raw)) > _MAX_EVENT_BYTES:
                        raise PaymentAttemptRejected(
                            "legacy payment attempt event is too large"
                        )
                except (
                    TypeError,
                    ValueError,
                    OverflowError,
                    RecursionError,
                ) as exc:
                    raise PaymentAttemptRejected(
                        "legacy payment attempt event is not canonical JSON"
                    ) from exc
                ok, reason = _verify_legacy_signature(raw)
                if not ok:
                    raise PaymentAttemptRejected(reason)
                if (
                    raw.get("attempt_id") != attempt_id
                    or raw.get("actor_did") != actor_did
                    or raw.get("seq") != index
                ):
                    raise PaymentAttemptRejected(
                        "legacy payment attempt actor, id, or sequence is invalid"
                    )
                event = PaymentAttemptEvent(
                    attempt_id=attempt_id,
                    seq=index,
                    type=raw["type"],
                    actor_did=actor_did,
                    prev_state=raw["prev_state"],
                    new_state=raw["new_state"],
                    payload=_legacy_payload(raw["type"], raw["payload"]),
                    prev_event_hash=(
                        ""
                        if index == 0
                        else payment_attempt_event_hash(migrated_events[-1])
                    ),
                    created_at_ms=raw["created_at_ms"],
                    kind=raw["kind"],
                )
                _sign_event(actor, event)
                migrated_events.append(event.to_dict())

            ok, reason = verify_payment_attempt(migrated_events)
            if not ok:
                raise PaymentAttemptRejected(
                    f"legacy payment attempt is semantically invalid: {reason}"
                )

            head_hash = payment_attempt_event_hash(migrated_events[-1])
            anchors = self._read_anchors(attempt_id, actor_did=actor_did)
            if anchors and any(
                anchor.phase != "prepared"
                or anchor.seq != len(migrated_events) - 1
                or anchor.head_hash != head_hash
                for anchor in anchors
            ):
                raise PaymentAttemptRejected(
                    "legacy payment attempt has conflicting head anchors"
                )
            self._persist(
                path,
                attempt_id,
                migrated_events,
                actor=actor,
                created_at_ms=migrated_events[-1]["created_at_ms"],
            )
            return _project_verified(migrated_events)

    def get_events(self, attempt_id: str) -> Optional[List[Dict[str, Any]]]:
        return self._load(self._path(attempt_id))

    def get(self, attempt_id: str) -> Optional[PaymentAttemptView]:
        events = self.get_events(attempt_id)
        if events is None:
            return None
        ok, reason = verify_payment_attempt(events)
        if not ok:
            raise PaymentAttemptRejected(f"stored payment attempt is invalid: {reason}")
        return _project_verified(events)

    def create(
        self,
        *,
        actor: Any,
        intent: SettlementIntent,
        adapter_id: str = ADAPTER_X402_TESTNET,
        now_ms_override: int = 0,
    ) -> PaymentAttemptView:
        if adapter_id != ADAPTER_X402_TESTNET:
            raise PaymentAttemptRejected("only external x402 attempts are persisted")
        intent_payload = _intent_dict(intent)
        if not intent.payer_did or actor.as_did() != intent.payer_did:
            raise PaymentAttemptRejected("payment attempt actor must be the payer DID")
        attempt_id = settlement_idempotency_key(intent)
        path = self._path(attempt_id)
        created_at_ms = now_ms_override or time.time_ns() // 1_000_000
        if isinstance(created_at_ms, bool) or not isinstance(created_at_ms, int) or created_at_ms <= 0:
            raise PaymentAttemptRejected("invalid payment attempt timestamp")
        payload = {
            "schema_version": 1,
            "adapter_id": adapter_id,
            "intent": intent_payload,
        }
        with _thread_lock(path), InterProcessLock(path):
            existing = self._load(path)
            if existing is not None:
                ok, reason = verify_payment_attempt(existing)
                if not ok:
                    raise PaymentAttemptConflict(f"stored payment attempt is invalid: {reason}")
                view = _project_verified(existing)
                if view.actor_did != actor.as_did() or view.intent != intent_payload:
                    raise PaymentAttemptConflict("payment attempt id contains different intent")
                return view
            event = PaymentAttemptEvent(
                attempt_id=attempt_id,
                seq=0,
                type=EVENT_CREATED,
                actor_did=actor.as_did(),
                prev_state="",
                new_state=STATE_PENDING,
                payload=payload,
                prev_event_hash="",
                created_at_ms=created_at_ms,
            )
            _sign_event(actor, event)
            events = [event.to_dict()]
            self._persist(
                path,
                attempt_id,
                events,
                actor=actor,
                created_at_ms=created_at_ms,
            )
            return _project_verified(events)

    def _append(
        self,
        attempt_id: str,
        *,
        actor: Any,
        event_type: str,
        new_state: str,
        payload: Dict[str, Any],
        now_ms_override: int = 0,
    ) -> PaymentAttemptView:
        path = self._path(attempt_id)
        created_at_ms = now_ms_override or time.time_ns() // 1_000_000
        with _thread_lock(path), InterProcessLock(path):
            events = self._load(path)
            if not events:
                raise PaymentAttemptRejected("payment attempt not found")
            ok, reason = verify_payment_attempt(events)
            if not ok:
                raise PaymentAttemptConflict(f"stored payment attempt is invalid: {reason}")
            current = _project_verified(events)
            if actor.as_did() != current.actor_did:
                raise PaymentAttemptRejected("payment attempt actor mismatch")
            event = PaymentAttemptEvent(
                attempt_id=attempt_id,
                seq=len(events),
                type=event_type,
                actor_did=current.actor_did,
                prev_state=current.state,
                new_state=new_state,
                payload=payload,
                prev_event_hash=payment_attempt_event_hash(events[-1]),
                created_at_ms=created_at_ms,
            )
            _sign_event(actor, event)
            candidate = [*events, event.to_dict()]
            ok, reason = verify_payment_attempt(candidate)
            if not ok:
                raise PaymentAttemptRejected(reason)
            self._persist(
                path,
                attempt_id,
                candidate,
                actor=actor,
                created_at_ms=created_at_ms,
            )
            return _project_verified(candidate)

    def claim(
        self,
        attempt_id: str,
        *,
        actor: Any,
        lease_ms: int = 30_000,
        now_ms_override: int = 0,
    ) -> Optional[PaymentAttemptView]:
        if isinstance(lease_ms, bool) or not isinstance(lease_ms, int) or not 1_000 <= lease_ms <= 300_000:
            raise PaymentAttemptRejected("lease_ms must be between 1000 and 300000")
        path = self._path(attempt_id)
        current_ms = now_ms_override or time.time_ns() // 1_000_000
        with _thread_lock(path), InterProcessLock(path):
            events = self._load(path)
            if not events:
                return None
            ok, reason = verify_payment_attempt(events)
            if not ok:
                raise PaymentAttemptConflict(f"stored payment attempt is invalid: {reason}")
            current = _project_verified(events)
            if actor.as_did() != current.actor_did:
                raise PaymentAttemptRejected("payment attempt actor mismatch")
            if current.state in {STATE_SETTLED, STATE_BLOCKED, STATE_ORPHANED}:
                return None
            if current.state == STATE_PENDING and current.next_attempt_at_ms > current_ms:
                return None
            if current.state == STATE_INFLIGHT and current.lease_expires_at_ms > current_ms:
                return None
            event = PaymentAttemptEvent(
                attempt_id=attempt_id,
                seq=len(events),
                type=EVENT_CLAIMED,
                actor_did=current.actor_did,
                prev_state=current.state,
                new_state=STATE_INFLIGHT,
                payload={
                    "lease_id": uuid.uuid4().hex,
                    "lease_expires_at_ms": current_ms + lease_ms,
                },
                prev_event_hash=payment_attempt_event_hash(events[-1]),
                created_at_ms=current_ms,
            )
            _sign_event(actor, event)
            candidate = [*events, event.to_dict()]
            ok, reason = verify_payment_attempt(candidate)
            if not ok:
                raise PaymentAttemptRejected(reason)
            self._persist(
                path,
                attempt_id,
                candidate,
                actor=actor,
                created_at_ms=current_ms,
            )
            return _project_verified(candidate)

    def schedule_retry(
        self,
        attempt_id: str,
        *,
        actor: Any,
        lease_id: str,
        error_code: str,
        retry_after_ms: int,
        now_ms_override: int = 0,
    ) -> PaymentAttemptView:
        if isinstance(retry_after_ms, bool) or not isinstance(retry_after_ms, int) or retry_after_ms < 0:
            raise PaymentAttemptRejected("retry_after_ms must be non-negative")
        current_ms = now_ms_override or time.time_ns() // 1_000_000
        return self._append(
            attempt_id,
            actor=actor,
            event_type=EVENT_RETRY_SCHEDULED,
            new_state=STATE_PENDING,
            payload={
                "lease_id": lease_id,
                "error_code": error_code,
                "next_attempt_at_ms": current_ms + retry_after_ms,
            },
            now_ms_override=current_ms,
        )

    def record_settled(
        self,
        attempt_id: str,
        *,
        actor: Any,
        lease_id: str,
        settlement: Dict[str, Any],
        now_ms_override: int = 0,
    ) -> PaymentAttemptView:
        return self._append(
            attempt_id,
            actor=actor,
            event_type=EVENT_SETTLED,
            new_state=STATE_SETTLED,
            payload={"lease_id": lease_id, "settlement": dict(settlement)},
            now_ms_override=now_ms_override,
        )

    def block(
        self,
        attempt_id: str,
        *,
        actor: Any,
        lease_id: str,
        error_code: str,
        now_ms_override: int = 0,
    ) -> PaymentAttemptView:
        return self._append(
            attempt_id,
            actor=actor,
            event_type=EVENT_BLOCKED,
            new_state=STATE_BLOCKED,
            payload={"lease_id": lease_id, "error_code": error_code},
            now_ms_override=now_ms_override,
        )

    def record_orphaned(
        self,
        attempt_id: str,
        *,
        actor: Any,
        lease_id: str,
        error_code: str,
        provider_reference: str,
        evidence_digest: str,
        now_ms_override: int = 0,
    ) -> PaymentAttemptView:
        return self._append(
            attempt_id,
            actor=actor,
            event_type=EVENT_ORPHANED,
            new_state=STATE_ORPHANED,
            payload={
                "lease_id": lease_id,
                "error_code": error_code,
                "provider_reference": provider_reference,
                "evidence_digest": evidence_digest,
            },
            now_ms_override=now_ms_override,
        )

    def record_reconciled(
        self,
        attempt_id: str,
        *,
        actor: Any,
        settlement: Dict[str, Any],
        orphan_evidence_digest: str,
        now_ms_override: int = 0,
    ) -> PaymentAttemptView:
        return self._append(
            attempt_id,
            actor=actor,
            event_type=EVENT_ORPHAN_RECONCILED,
            new_state=STATE_SETTLED,
            payload={
                "settlement": dict(settlement),
                "orphan_evidence_digest": orphan_evidence_digest,
            },
            now_ms_override=now_ms_override,
        )

    def pending(self, *, limit: int = 100) -> List[PaymentAttemptView]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise PaymentAttemptRejected("limit must be between 1 and 1000")
        rows: List[PaymentAttemptView] = []
        for path in sorted(self.root.glob("*.json")):
            try:
                attempt_id = f"nth-settlement:v1:sha256:{path.stem}"
                view = self.get(attempt_id)
            except (PaymentAttemptRejected, PaymentAttemptConflict) as exc:
                logger.warning("skipping invalid payment attempt record %s: %s", path, exc)
                continue
            if view is not None and view.state in {STATE_PENDING, STATE_INFLIGHT}:
                rows.append(view)
                if len(rows) >= limit:
                    break
        return rows

@dataclass(frozen=True)
class PaymentExecutorConfig:
    lease_ms: int = 30_000
    retry_after_ms: int = 5_000
    retry_max_ms: int = 300_000
    retry_jitter_percent: int = 20
    max_attempts: int = 10

    def __post_init__(self) -> None:
        if (
            isinstance(self.lease_ms, bool)
            or not isinstance(self.lease_ms, int)
            or not 1_000 <= self.lease_ms <= 300_000
        ):
            raise ValueError("lease_ms must be between 1000 and 300000")
        if (
            isinstance(self.retry_after_ms, bool)
            or not isinstance(self.retry_after_ms, int)
            or not 0 <= self.retry_after_ms <= 86_400_000
        ):
            raise ValueError("retry_after_ms must be between 0 and 86400000")
        if (
            isinstance(self.retry_max_ms, bool)
            or not isinstance(self.retry_max_ms, int)
            or not self.retry_after_ms <= self.retry_max_ms <= 86_400_000
        ):
            raise ValueError(
                "retry_max_ms must be between retry_after_ms and 86400000"
            )
        if (
            isinstance(self.retry_jitter_percent, bool)
            or not isinstance(self.retry_jitter_percent, int)
            or not 0 <= self.retry_jitter_percent <= 50
        ):
            raise ValueError("retry_jitter_percent must be between 0 and 50")
        if (
            isinstance(self.max_attempts, bool)
            or not isinstance(self.max_attempts, int)
            or not 1 <= self.max_attempts <= 100
        ):
            raise ValueError("max_attempts must be between 1 and 100")


class PaymentAttemptExecutor:
    """Claim and reconcile instant external payments without blind retries."""

    def __init__(
        self,
        attempts: PaymentAttemptStore,
        trade_store: Any,
        *,
        actor: Any,
        adapter: X402SettlementAdapter,
        config: Optional[PaymentExecutorConfig] = None,
    ) -> None:
        if type(adapter) is not X402SettlementAdapter:
            raise ValueError(
                "payment executor requires an exact X402SettlementAdapter"
            )
        self.attempts = attempts
        self.trade_store = trade_store
        self.actor = actor
        self.adapter = adapter
        self.config = config or PaymentExecutorConfig()

    @staticmethod
    def _error_code(exc: BaseException) -> str:
        from nth_dao.commerce.trade import TradeConflict

        reason = getattr(exc, "reason", "")
        if isinstance(reason, str) and _ERROR_CODE.fullmatch(reason):
            return reason
        if isinstance(exc, TradeConflict):
            return "trade-conflict"
        if isinstance(exc, TimeoutError):
            return "provider-timeout"
        if isinstance(exc, ConnectionError):
            return "provider-connection-error"
        if isinstance(exc, OSError):
            return "io-error"
        if isinstance(exc, RuntimeError):
            return "runtime-error"
        return "internal-error"

    @classmethod
    def _orphan_metadata(cls, exc: SettlementFailed) -> Tuple[str, str, str]:
        error_code = cls._error_code(exc)
        reference = exc.provider_reference
        if (
            not isinstance(reference, str)
            or len(reference) > 256
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in reference)
        ):
            reference = ""
        digest = exc.evidence_digest
        if not isinstance(digest, str) or not _EVENT_HASH.fullmatch(digest):
            digest = "sha256:" + hashlib.sha256(canonical_json({
                "error_code": error_code,
                "provider_reference": reference,
            })).hexdigest()
        return error_code, reference, digest

    def _retry_or_block(
        self,
        claimed: PaymentAttemptView,
        exc: BaseException,
        *,
        permanent: bool,
        now_ms_override: int,
    ) -> PaymentAttemptView:
        error_code = self._error_code(exc)
        if permanent or claimed.attempts >= self.config.max_attempts:
            return self.attempts.block(
                claimed.attempt_id,
                actor=self.actor,
                lease_id=claimed.lease_id,
                error_code=error_code,
                now_ms_override=now_ms_override,
            )
        return self.attempts.schedule_retry(
            claimed.attempt_id,
            actor=self.actor,
            lease_id=claimed.lease_id,
            error_code=error_code,
            retry_after_ms=self._retry_delay_ms(claimed),
            now_ms_override=now_ms_override,
        )

    def _retry_delay_ms(self, claimed: PaymentAttemptView) -> int:
        exponent = min(max(claimed.attempts - 1, 0), 30)
        base = min(
            self.config.retry_max_ms,
            self.config.retry_after_ms * (1 << exponent),
        )
        jitter = base * self.config.retry_jitter_percent // 100
        if jitter == 0:
            return base
        digest = hashlib.sha256(canonical_json({
            "attempt_id": claimed.attempt_id,
            "attempts": claimed.attempts,
            "kind": "nth/payment-retry-jitter@1",
        })).digest()
        offset = int.from_bytes(digest[:8], "big") % (2 * jitter + 1) - jitter
        return min(self.config.retry_max_ms, max(0, base + offset))

    def _execute_claimed(
        self,
        claimed: PaymentAttemptView,
        *,
        now_ms_override: int,
    ) -> PaymentAttemptView:
        intent = _intent_from_dict(claimed.intent)
        try:
            from nth_dao.commerce.settlement import settle_trade
            from nth_dao.commerce.trade import TradeConflict, TradeRejected

            trade_event = settle_trade(
                self.trade_store,
                intent.trade_id,
                settler=self.actor,
                adapter=self.adapter,
                intent=intent,
                now_ms_override=now_ms_override,
            )
        except SettlementFailed as exc:
            if exc.payment_may_have_committed:
                error_code, provider_reference, evidence_digest = (
                    self._orphan_metadata(exc)
                )
                return self.attempts.record_orphaned(
                    claimed.attempt_id,
                    actor=self.actor,
                    lease_id=claimed.lease_id,
                    error_code=error_code,
                    provider_reference=provider_reference,
                    evidence_digest=evidence_digest,
                    now_ms_override=now_ms_override,
                )
            return self._retry_or_block(
                claimed,
                exc,
                permanent=exc.reason in _PERMANENT_SETTLEMENT_FAILURES,
                now_ms_override=now_ms_override,
            )
        except (TradeConflict, TradeRejected) as exc:
            return self._retry_or_block(
                claimed,
                exc,
                permanent=False,
                now_ms_override=now_ms_override,
            )
        except (ConnectionError, OSError, RuntimeError, TimeoutError) as exc:
            return self._retry_or_block(
                claimed,
                exc,
                permanent=False,
                now_ms_override=now_ms_override,
            )

        payload = getattr(trade_event, "payload", None)
        settlement = payload.get("settlement") if isinstance(payload, dict) else None
        if not isinstance(settlement, dict):
            raise PaymentAttemptRejected(
                "settle_trade returned an event without a settlement payload"
            )
        return self.attempts.record_settled(
            claimed.attempt_id,
            actor=self.actor,
            lease_id=claimed.lease_id,
            settlement=settlement,
            now_ms_override=now_ms_override,
        )

    def run_once(
        self,
        attempt_id: str,
        *,
        now_ms_override: int = 0,
    ) -> Optional[PaymentAttemptView]:
        claimed = self.attempts.claim(
            attempt_id,
            actor=self.actor,
            lease_ms=self.config.lease_ms,
            now_ms_override=now_ms_override,
        )
        if claimed is None:
            return None
        return self._execute_claimed(
            claimed,
            now_ms_override=now_ms_override,
        )

    def run_pending(
        self,
        *,
        limit: int = 25,
        now_ms_override: int = 0,
    ) -> List[PaymentAttemptView]:
        results: List[PaymentAttemptView] = []
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise PaymentAttemptRejected("limit must be between 1 and 1000")
        for path in sorted(self.attempts.root.glob("*.json")):
            result = self.run_once(
                f"nth-settlement:v1:sha256:{path.stem}",
                now_ms_override=now_ms_override,
            )
            if result is not None:
                results.append(result)
                if len(results) >= limit:
                    break
        return results


class _LookupOnlyX402Adapter:
    """Settlement adapter that can observe provider state but cannot pay."""

    adapter_id = ADAPTER_X402_TESTNET

    def __init__(self, adapter: X402SettlementAdapter) -> None:
        self._adapter = adapter

    def settle(self, intent: SettlementIntent) -> Any:
        result = self._adapter.lookup_settlement(intent)
        if result is None:
            raise SettlementFailed(
                REJECT_RECEIPT_NOT_FOUND,
                "the payment rail has no receipt for this idempotency key",
            )
        return result


class PaymentAttemptReconciler:
    """Resolve an orphaned attempt by verifying an existing rail receipt.

    This workflow never calls ``PaymentRail.pay``. It serializes reconciliation
    separately from the attempt store lock so the signed recovery event can be
    appended without relying on re-entrant operating-system file locks.
    """

    def __init__(
        self,
        attempts: PaymentAttemptStore,
        trade_store: Any,
        *,
        actor: Any,
        adapter: X402SettlementAdapter,
    ) -> None:
        if type(adapter) is not X402SettlementAdapter:
            raise ValueError(
                "payment reconciliation requires an exact X402SettlementAdapter"
            )
        self.attempts = attempts
        self.trade_store = trade_store
        self.actor = actor
        self.adapter = adapter

    def reconcile_once(
        self,
        attempt_id: str,
        *,
        now_ms_override: int = 0,
    ) -> PaymentAttemptView:
        path = Path(str(self.attempts._path(attempt_id)) + ".reconcile")
        with _thread_lock(path), InterProcessLock(path):
            current = self.attempts.get(attempt_id)
            if current is None:
                raise PaymentAttemptRejected("payment attempt not found")
            if self.actor.as_did() != current.actor_did:
                raise PaymentAttemptRejected("payment attempt actor mismatch")
            if current.state == STATE_SETTLED:
                return current
            if current.state != STATE_ORPHANED:
                raise PaymentAttemptRejected(
                    "only orphaned payment attempts can be reconciled"
                )

            intent = _intent_from_dict(current.intent)
            from nth_dao.commerce.settlement import settle_trade

            trade_event = settle_trade(
                self.trade_store,
                intent.trade_id,
                settler=self.actor,
                adapter=_LookupOnlyX402Adapter(self.adapter),
                intent=intent,
                now_ms_override=now_ms_override,
            )
            payload = getattr(trade_event, "payload", None)
            settlement = (
                payload.get("settlement") if isinstance(payload, dict) else None
            )
            if not isinstance(settlement, dict):
                raise PaymentAttemptRejected(
                    "settle_trade returned an event without a settlement payload"
                )
            return self.attempts.record_reconciled(
                attempt_id,
                actor=self.actor,
                settlement=settlement,
                orphan_evidence_digest=current.evidence_digest,
                now_ms_override=now_ms_override,
            )
