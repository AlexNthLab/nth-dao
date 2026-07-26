"""Durable, signed commerce replication envelopes."""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlsplit

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import decode_ed25519_did_key_hex, is_did_key
from nth_dao.identity import _NACL_AVAILABLE
from nth_dao.util.io import InterProcessLock, atomic_write_json, safe_load_json

try:
    from nacl.exceptions import BadSignatureError as _BadSignatureError
    from nacl.signing import VerifyKey as _VerifyKey
except ImportError:  # pragma: no cover
    _BadSignatureError = ValueError  # type: ignore[assignment,misc]
    _VerifyKey = None  # type: ignore[assignment]

PathLike = Union[str, Path]
ENVELOPE_KIND = "nth-commerce-sync-v1"
ACK_KIND = "nth-commerce-ack-v1"
_MAX_PAYLOAD_BYTES = 512 * 1024
_MAX_OUTBOX_RECORD_BYTES = 768 * 1024
logger = logging.getLogger(__name__)

OUTBOX_ERROR_DELIVERY_FAILED = "delivery-failed"
OUTBOX_ERROR_DELIVERY_REJECTED = "delivery-permanently-rejected"
OUTBOX_ERROR_DISPATCH_CONTRACT = "dispatcher-contract-error"
OUTBOX_ERROR_RECORD_MISSING = "outbox-record-missing"
OUTBOX_ERROR_LEASE_SUPERSEDED = "delivery-lease-superseded"
OUTBOX_ERROR_RUNTIME = "delivery-runtime-error"
OUTBOX_ERROR_PERSISTENCE = "delivery-persistence-error"
OUTBOX_ERROR_TARGET_REJECTED = "target-policy-rejected"
OUTBOX_ERROR_PEER_RESPONSE = "peer-response-invalid"
OUTBOX_ERROR_PEER_HTTP_RETRYABLE = "peer-http-retryable"
OUTBOX_ERROR_PEER_HTTP_REJECTED = "peer-http-rejected"
OUTBOX_ERROR_PEER_NETWORK = "peer-network-error"
OUTBOX_ERROR_CODES = frozenset({
    OUTBOX_ERROR_DELIVERY_FAILED,
    OUTBOX_ERROR_DELIVERY_REJECTED,
    OUTBOX_ERROR_DISPATCH_CONTRACT,
    OUTBOX_ERROR_RECORD_MISSING,
    OUTBOX_ERROR_LEASE_SUPERSEDED,
    OUTBOX_ERROR_RUNTIME,
    OUTBOX_ERROR_PERSISTENCE,
    OUTBOX_ERROR_TARGET_REJECTED,
    OUTBOX_ERROR_PEER_RESPONSE,
    OUTBOX_ERROR_PEER_HTTP_RETRYABLE,
    OUTBOX_ERROR_PEER_HTTP_REJECTED,
    OUTBOX_ERROR_PEER_NETWORK,
})


class CommerceEnvelopeRejected(ValueError):
    pass


def _normalize_target_url(value: Any) -> str:
    """Validate a public HTTP(S) route without persisting credentials."""
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > 2048
        or any(
            character.isspace()
            or ord(character) < 0x20
            or ord(character) == 0x7F
            for character in value
        )
    ):
        raise CommerceEnvelopeRejected("invalid target URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise CommerceEnvelopeRejected("invalid target URL") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or "@" in parsed.netloc
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65_535)
    ):
        raise CommerceEnvelopeRejected("invalid target URL")
    return value.rstrip("/")


def normalize_outbox_error(error: Any, *, retryable: bool) -> str:
    """Return a stable public code; never persist exception/provider text."""
    if isinstance(error, str):
        candidate = error.strip()
        if candidate in OUTBOX_ERROR_CODES:
            return candidate
    return (
        OUTBOX_ERROR_DELIVERY_FAILED
        if retryable
        else OUTBOX_ERROR_DELIVERY_REJECTED
    )


@dataclass
class CommerceEnvelope:
    message_id: str
    source_did: str
    target_did: str
    payload: Dict[str, Any]
    created_at_ms: int
    kind: str = ENVELOPE_KIND
    signature: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def signing_body(self) -> Dict[str, Any]:
        return {key: value for key, value in self.to_dict().items() if key != "signature"}

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "CommerceEnvelope":
        if not isinstance(value, dict) or set(value) != set(cls.__dataclass_fields__):  # type: ignore[attr-defined]
            raise CommerceEnvelopeRejected("envelope has missing or unknown fields")
        return cls(**value)


def _message_id(source_did: str, target_did: str, payload: Dict[str, Any]) -> str:
    body = {"source_did": source_did, "target_did": target_did, "payload": payload}
    return "sha256:" + hashlib.sha256(canonical_json(body)).hexdigest()


def sign_envelope(
    identity: Any,
    *,
    target_did: str,
    payload: Dict[str, Any],
    created_at_ms: int,
) -> CommerceEnvelope:
    source_did = identity.as_did()
    envelope = CommerceEnvelope(
        message_id=_message_id(source_did, target_did, payload),
        source_did=source_did,
        target_did=target_did,
        payload=payload,
        created_at_ms=created_at_ms,
    )
    ok, reason = _validate_envelope(envelope, require_signature=False)
    if not ok:
        raise CommerceEnvelopeRejected(reason)
    envelope.signature = b64u_encode(identity.sign(canonical_json(envelope.signing_body())))
    return envelope


def _validate_envelope(
    envelope: CommerceEnvelope,
    *,
    require_signature: bool = True,
) -> tuple[bool, str]:
    if envelope.kind != ENVELOPE_KIND:
        return False, "wrong envelope kind"
    if not is_did_key(envelope.source_did) or not is_did_key(envelope.target_did):
        return False, "invalid envelope DID"
    if not isinstance(envelope.payload, dict):
        return False, "payload must be an object"
    if isinstance(envelope.created_at_ms, bool) or not isinstance(envelope.created_at_ms, int) or envelope.created_at_ms <= 0:
        return False, "invalid envelope timestamp"
    try:
        if len(canonical_json(envelope.payload)) > _MAX_PAYLOAD_BYTES:
            return False, "envelope payload too large"
        expected_id = _message_id(
            envelope.source_did, envelope.target_did, envelope.payload,
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        return False, f"payload is not canonical JSON: {exc}"
    if envelope.message_id != expected_id:
        return False, "message id does not match envelope content"
    if not require_signature:
        return True, "ok"
    if not _NACL_AVAILABLE or _VerifyKey is None:
        return False, "crypto unavailable"
    try:
        signature = b64u_decode(envelope.signature)
        if len(signature) != 64 or b64u_encode(signature) != envelope.signature:
            return False, "envelope signature invalid"
        key_hex = decode_ed25519_did_key_hex(envelope.source_did) or ""
        _VerifyKey(bytes.fromhex(key_hex)).verify(
            canonical_json(envelope.signing_body()), signature,
        )
    except (_BadSignatureError, TypeError, ValueError, UnicodeError):
        return False, "envelope signature invalid"
    return True, "ok"


def verify_envelope(envelope: CommerceEnvelope) -> tuple[bool, str]:
    return _validate_envelope(envelope)


def _is_digest(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:"):
        return False
    try:
        bytes.fromhex(value[7:])
    except ValueError:
        return False
    return True


def trade_chain_head(events: List[Dict[str, Any]]) -> str:
    if not isinstance(events, list) or not events or not isinstance(events[-1], dict):
        raise CommerceEnvelopeRejected("trade chain has no signed head")
    return "sha256:" + hashlib.sha256(canonical_json(events[-1])).hexdigest()


@dataclass
class CommerceAck:
    message_id: str
    order_id: str
    received_chain_head: str
    receiver_did: str
    received_at_ms: int
    kind: str = ACK_KIND
    signature: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def signing_body(self) -> Dict[str, Any]:
        return {key: value for key, value in self.to_dict().items() if key != "signature"}

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "CommerceAck":
        if not isinstance(value, dict) or set(value) != set(cls.__dataclass_fields__):  # type: ignore[attr-defined]
            raise CommerceEnvelopeRejected("ack has missing or unknown fields")
        return cls(**value)


def _validate_ack(ack: CommerceAck, *, require_signature: bool = True) -> tuple[bool, str]:
    if ack.kind != ACK_KIND:
        return False, "wrong ack kind"
    if not _is_digest(ack.message_id) or not _is_digest(ack.received_chain_head):
        return False, "invalid ack digest"
    if not isinstance(ack.order_id, str) or not (1 <= len(ack.order_id) <= 160):
        return False, "invalid ack order id"
    if not is_did_key(ack.receiver_did):
        return False, "invalid ack receiver DID"
    if isinstance(ack.received_at_ms, bool) or not isinstance(ack.received_at_ms, int) or ack.received_at_ms <= 0:
        return False, "invalid ack timestamp"
    if not require_signature:
        return True, "ok"
    if not _NACL_AVAILABLE or _VerifyKey is None:
        return False, "crypto unavailable"
    try:
        signature = b64u_decode(ack.signature)
        if len(signature) != 64 or b64u_encode(signature) != ack.signature:
            return False, "ack signature invalid"
        key_hex = decode_ed25519_did_key_hex(ack.receiver_did) or ""
        _VerifyKey(bytes.fromhex(key_hex)).verify(
            canonical_json(ack.signing_body()), signature,
        )
    except (_BadSignatureError, TypeError, ValueError, UnicodeError):
        return False, "ack signature invalid"
    return True, "ok"


def sign_ack(
    identity: Any,
    *,
    message_id: str,
    order_id: str,
    received_chain_head: str,
    received_at_ms: int,
) -> CommerceAck:
    ack = CommerceAck(
        message_id=message_id,
        order_id=order_id,
        received_chain_head=received_chain_head,
        receiver_did=identity.as_did(),
        received_at_ms=received_at_ms,
    )
    ok, reason = _validate_ack(ack, require_signature=False)
    if not ok:
        raise CommerceEnvelopeRejected(reason)
    ack.signature = b64u_encode(identity.sign(canonical_json(ack.signing_body())))
    return ack


def verify_ack(ack: CommerceAck) -> tuple[bool, str]:
    return _validate_ack(ack)


@dataclass
class InboxRecord:
    source_did: str
    target_did: str
    ack: Dict[str, Any]


class CommerceInbox:
    """Durable replay receipts for accepted commerce envelopes."""

    def __init__(self, root: PathLike) -> None:
        self.root = Path(root) / "commerce" / "inbox"
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, message_id: str) -> Path:
        if not _is_digest(message_id):
            raise CommerceEnvelopeRejected("invalid message id")
        return self.root / f"{message_id[7:]}.json"

    def get_ack(
        self,
        envelope: CommerceEnvelope,
        *,
        order_id: str,
        chain_head: str,
    ) -> Optional[CommerceAck]:
        value = safe_load_json(self._path(envelope.message_id), fallback=None)
        if value is None:
            return None
        if not isinstance(value, dict):
            raise CommerceEnvelopeRejected("stored inbox receipt is invalid")
        try:
            record = InboxRecord(**value)
            ack = CommerceAck.from_dict(record.ack)
        except (TypeError, CommerceEnvelopeRejected) as exc:
            raise CommerceEnvelopeRejected("stored inbox receipt is invalid") from exc
        ok, reason = verify_ack(ack)
        if not ok:
            raise CommerceEnvelopeRejected(f"stored inbox ack is invalid: {reason}")
        if (
            record.source_did != envelope.source_did
            or record.target_did != envelope.target_did
            or ack.message_id != envelope.message_id
            or ack.order_id != order_id
            or ack.received_chain_head != chain_head
            or ack.receiver_did != envelope.target_did
        ):
            raise CommerceEnvelopeRejected("stored inbox receipt binding mismatch")
        return ack

    def acknowledge(
        self,
        envelope: CommerceEnvelope,
        *,
        order_id: str,
        chain_head: str,
        identity: Any,
        received_at_ms: int,
    ) -> tuple[CommerceAck, bool]:
        path = self._path(envelope.message_id)
        with InterProcessLock(path):
            existing = self.get_ack(
                envelope, order_id=order_id, chain_head=chain_head,
            )
            if existing is not None:
                return existing, False
            if identity.as_did() != envelope.target_did:
                raise CommerceEnvelopeRejected("inbox signer is not envelope target")
            ack = sign_ack(
                identity,
                message_id=envelope.message_id,
                order_id=order_id,
                received_chain_head=chain_head,
                received_at_ms=received_at_ms,
            )
            atomic_write_json(path, asdict(InboxRecord(
                source_did=envelope.source_did,
                target_did=envelope.target_did,
                ack=ack.to_dict(),
            )))
            return ack, True


@dataclass
class OutboxRecord:
    envelope: Dict[str, Any]
    target_url: str
    status: str = "pending"
    attempts: int = 0
    last_error: str = ""
    acknowledged_at_ms: int = 0
    blocked_at_ms: int = 0
    last_attempt_at_ms: int = 0
    next_attempt_at_ms: int = 0
    lease_id: str = ""
    lease_expires_at_ms: int = 0
    route_history: List[Dict[str, Any]] | None = None


class CommerceOutbox:
    def __init__(self, root: PathLike) -> None:
        self.root = Path(root) / "commerce" / "outbox"
        self.archive_root = Path(root) / "commerce" / "outbox_archive"
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, message_id: str) -> Path:
        if not isinstance(message_id, str) or not message_id.startswith("sha256:") or len(message_id) != 71:
            raise CommerceEnvelopeRejected("invalid message id")
        try:
            bytes.fromhex(message_id[7:])
        except ValueError as exc:
            raise CommerceEnvelopeRejected("invalid message id") from exc
        return self.root / f"{message_id[7:]}.json"

    def _archive_path(self, message_id: str) -> Path:
        self._path(message_id)
        return self.archive_root / f"{message_id[7:]}.json"

    @staticmethod
    def _load_record(path: Path) -> Optional[Dict[str, Any]]:
        try:
            with path.open("rb") as handle:
                raw = handle.read(_MAX_OUTBOX_RECORD_BYTES + 1)
        except FileNotFoundError:
            return None
        if len(raw) > _MAX_OUTBOX_RECORD_BYTES:
            raise CommerceEnvelopeRejected(f"outbox record at {path} is too large")
        try:
            value = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise CommerceEnvelopeRejected(f"corrupt outbox JSON at {path}") from exc
        if not isinstance(value, dict):
            raise CommerceEnvelopeRejected(f"outbox record at {path} is not an object")
        return value

    @staticmethod
    def _decode_record(value: Dict[str, Any], path: Path) -> OutboxRecord:
        try:
            record = OutboxRecord(**value)
        except TypeError as exc:
            raise CommerceEnvelopeRejected(f"outbox record at {path} has invalid fields") from exc
        if record.status not in {"pending", "inflight", "blocked", "acknowledged"}:
            raise CommerceEnvelopeRejected(f"outbox record at {path} has invalid status")
        if not isinstance(record.envelope, dict):
            raise CommerceEnvelopeRejected(f"outbox record at {path} has invalid envelope")
        try:
            normalized_target = _normalize_target_url(record.target_url)
        except CommerceEnvelopeRejected as exc:
            raise CommerceEnvelopeRejected(
                f"outbox record at {path} has invalid target URL",
            ) from exc
        if normalized_target != record.target_url:
            raise CommerceEnvelopeRejected(
                f"outbox record at {path} has noncanonical target URL",
            )
        if isinstance(record.attempts, bool) or not isinstance(record.attempts, int) or record.attempts < 0:
            raise CommerceEnvelopeRejected(f"outbox record at {path} has invalid attempts")
        if not isinstance(record.last_error, str) or not isinstance(record.lease_id, str):
            raise CommerceEnvelopeRejected(f"outbox record at {path} has invalid text fields")
        if record.status == "acknowledged":
            record.last_error = ""
        elif record.last_error:
            record.last_error = normalize_outbox_error(
                record.last_error,
                retryable=record.status != "blocked",
            )
        for field_name in (
            "acknowledged_at_ms", "blocked_at_ms", "last_attempt_at_ms",
            "next_attempt_at_ms", "lease_expires_at_ms",
        ):
            field_value = getattr(record, field_name)
            if isinstance(field_value, bool) or not isinstance(field_value, int) or field_value < 0:
                raise CommerceEnvelopeRejected(
                    f"outbox record at {path} has invalid {field_name}",
                )
        if record.route_history is not None:
            if (
                not isinstance(record.route_history, list)
                or len(record.route_history) > 20
                or not all(isinstance(item, dict) for item in record.route_history)
            ):
                raise CommerceEnvelopeRejected(f"outbox record at {path} has invalid route history")
            for item in record.route_history:
                if set(item) != {
                    "target_did",
                    "previous_url",
                    "new_url",
                    "changed_at_ms",
                }:
                    raise CommerceEnvelopeRejected(
                        f"outbox record at {path} has invalid route history",
                    )
                try:
                    previous_url = _normalize_target_url(item.get("previous_url"))
                    new_url = _normalize_target_url(item.get("new_url"))
                except CommerceEnvelopeRejected as exc:
                    raise CommerceEnvelopeRejected(
                        f"outbox record at {path} has invalid route history",
                    ) from exc
                if (
                    previous_url != item.get("previous_url")
                    or new_url != item.get("new_url")
                    or not is_did_key(item.get("target_did"))
                    or isinstance(item.get("changed_at_ms"), bool)
                    or not isinstance(item.get("changed_at_ms"), int)
                    or item.get("changed_at_ms") <= 0
                ):
                    raise CommerceEnvelopeRejected(
                        f"outbox record at {path} has invalid route history",
                    )
        if record.status == "inflight" and (
            not record.lease_id or record.lease_expires_at_ms <= 0
        ):
            raise CommerceEnvelopeRejected(f"outbox record at {path} has invalid lease")
        if record.status == "acknowledged" and record.acknowledged_at_ms <= 0:
            raise CommerceEnvelopeRejected(f"outbox record at {path} has invalid acknowledgement")
        if record.status == "blocked" and record.blocked_at_ms <= 0:
            raise CommerceEnvelopeRejected(f"outbox record at {path} has invalid blocked timestamp")
        return record

    def enqueue(
        self,
        envelope: CommerceEnvelope,
        *,
        target_url: str,
        allow_retarget: bool = False,
        now_ms_override: int = 0,
    ) -> OutboxRecord:
        ok, reason = verify_envelope(envelope)
        if not ok:
            raise CommerceEnvelopeRejected(reason)
        normalized_target = _normalize_target_url(target_url)
        if not isinstance(allow_retarget, bool):
            raise CommerceEnvelopeRejected("allow_retarget must be a boolean")
        if isinstance(now_ms_override, bool) or not isinstance(now_ms_override, int) or now_ms_override < 0:
            raise CommerceEnvelopeRejected("now_ms_override must be a non-negative integer")
        path = self._path(envelope.message_id)
        with InterProcessLock(path):
            current = self._load_record(path)
            if current is None:
                current = self._load_record(self._archive_path(envelope.message_id))
            wanted = OutboxRecord(
                envelope=envelope.to_dict(),
                target_url=normalized_target,
            )
            if current is not None:
                if not isinstance(current, dict):
                    raise CommerceEnvelopeRejected("stored outbox record is invalid")
                try:
                    existing_envelope = CommerceEnvelope.from_dict(current.get("envelope"))
                except (CommerceEnvelopeRejected, TypeError):
                    raise CommerceEnvelopeRejected("stored outbox envelope is invalid")
                ok, reason = verify_envelope(existing_envelope)
                if not ok:
                    raise CommerceEnvelopeRejected(f"stored outbox envelope is invalid: {reason}")
                # message_id intentionally excludes delivery time. A later
                # retry of the same source/target/payload keeps the first
                # signed occurrence instead of manufacturing duplicate work.
                if (
                    existing_envelope.message_id != envelope.message_id
                    or existing_envelope.source_did != envelope.source_did
                    or existing_envelope.target_did != envelope.target_did
                    or existing_envelope.payload != envelope.payload
                ):
                    raise CommerceEnvelopeRejected("outbox message id collision")
                existing = self._decode_record(current, path)
                if existing.status == "acknowledged":
                    if existing.target_url != wanted.target_url:
                        raise CommerceEnvelopeRejected(
                            "acknowledged outbox work cannot be retargeted",
                        )
                    return existing
                if existing.target_url == wanted.target_url:
                    return existing
                if not allow_retarget:
                    raise CommerceEnvelopeRejected("outbox target URL changed without retarget authorization")
                if existing.status not in {"pending", "blocked"}:
                    raise CommerceEnvelopeRejected("only pending or blocked outbox work can be retargeted")
                changed_at_ms = now_ms_override or time.time_ns() // 1_000_000
                history = list(existing.route_history or [])
                history.append({
                    "target_did": existing_envelope.target_did,
                    "previous_url": existing.target_url,
                    "new_url": wanted.target_url,
                    "changed_at_ms": changed_at_ms,
                })
                existing.target_url = wanted.target_url
                existing.route_history = history[-20:]
                existing.status = "pending"
                existing.blocked_at_ms = 0
                existing.next_attempt_at_ms = 0
                existing.last_error = ""
                atomic_write_json(path, asdict(existing))
                return existing
            atomic_write_json(path, asdict(wanted))
            return wanted

    def get(self, message_id: str) -> Optional[OutboxRecord]:
        path = self._path(message_id)
        with InterProcessLock(path):
            value = self._load_record(path)
            loaded_path = path
            if value is None:
                loaded_path = self._archive_path(message_id)
                value = self._load_record(loaded_path)
            if not isinstance(value, dict):
                return None
            record = self._decode_record(value, loaded_path)
            if value.get("last_error") != record.last_error:
                atomic_write_json(loaded_path, asdict(record))
            return record

    def claim(
        self,
        message_id: str,
        *,
        lease_ms: int = 30_000,
        now_ms_override: int = 0,
        force: bool = False,
    ) -> Optional[OutboxRecord]:
        if isinstance(lease_ms, bool) or not isinstance(lease_ms, int) or not (1_000 <= lease_ms <= 300_000):
            raise CommerceEnvelopeRejected("lease_ms must be between 1000 and 300000")
        if isinstance(now_ms_override, bool) or not isinstance(now_ms_override, int) or now_ms_override < 0:
            raise CommerceEnvelopeRejected("now_ms_override must be a non-negative integer")
        if not isinstance(force, bool):
            raise CommerceEnvelopeRejected("force must be a boolean")
        current_ms = now_ms_override or time.time_ns() // 1_000_000
        path = self._path(message_id)
        with InterProcessLock(path):
            value = self._load_record(path)
            if not isinstance(value, dict):
                return None
            try:
                record = self._decode_record(value, path)
            except CommerceEnvelopeRejected as exc:
                raise CommerceEnvelopeRejected("stored outbox record is invalid") from exc
            if record.status == "acknowledged":
                return None
            if record.status == "blocked" and not force:
                return None
            if record.status == "inflight" and record.lease_expires_at_ms > current_ms:
                return None
            if record.status not in {"pending", "inflight", "blocked"}:
                raise CommerceEnvelopeRejected("stored outbox status is invalid")
            if (
                record.status == "pending"
                and record.next_attempt_at_ms > current_ms
                and not force
            ):
                return None
            record.status = "inflight"
            record.blocked_at_ms = 0
            record.lease_id = uuid.uuid4().hex
            record.lease_expires_at_ms = current_ms + lease_ms
            atomic_write_json(path, asdict(record))
            return record

    def claim_pending(
        self,
        *,
        limit: int = 100,
        lease_ms: int = 30_000,
        now_ms_override: int = 0,
        force: bool = False,
    ) -> List[OutboxRecord]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not (1 <= limit <= 1000):
            raise CommerceEnvelopeRejected("limit must be between 1 and 1000")
        if isinstance(lease_ms, bool) or not isinstance(lease_ms, int) or not (1_000 <= lease_ms <= 300_000):
            raise CommerceEnvelopeRejected("lease_ms must be between 1000 and 300000")
        if isinstance(now_ms_override, bool) or not isinstance(now_ms_override, int) or now_ms_override < 0:
            raise CommerceEnvelopeRejected("now_ms_override must be a non-negative integer")
        if not isinstance(force, bool):
            raise CommerceEnvelopeRejected("force must be a boolean")
        claimed: List[OutboxRecord] = []
        for path in sorted(self.root.glob("*.json")):
            try:
                record = self.claim(
                    f"sha256:{path.stem}",
                    lease_ms=lease_ms,
                    now_ms_override=now_ms_override,
                    force=force,
                )
            except (CommerceEnvelopeRejected, TypeError, ValueError) as exc:
                logger.warning("skipping invalid commerce outbox record %s: %s", path, exc)
                continue
            if record is not None:
                claimed.append(record)
                if len(claimed) >= limit:
                    break
        return claimed

    def pending(self, *, limit: int = 100) -> List[OutboxRecord]:
        return self._list_statuses({"pending", "inflight"}, limit=limit)

    def blocked(self, *, limit: int = 100) -> List[OutboxRecord]:
        return self._list_statuses({"blocked"}, limit=limit)

    def _list_statuses(
        self,
        statuses: set[str],
        *,
        limit: int,
    ) -> List[OutboxRecord]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not (1 <= limit <= 1000):
            raise CommerceEnvelopeRejected("limit must be between 1 and 1000")
        rows: List[OutboxRecord] = []
        for path in sorted(self.root.glob("*.json")):
            try:
                value = self._load_record(path)
            except CommerceEnvelopeRejected as exc:
                logger.warning("skipping invalid commerce outbox record %s: %s", path, exc)
                continue
            try:
                record = self._decode_record(value, path) if isinstance(value, dict) else None
            except CommerceEnvelopeRejected:
                record = None
            if record is not None and record.status in statuses:
                rows.append(record)
                if len(rows) >= limit:
                    break
        return rows

    def record_attempt(
        self,
        message_id: str,
        *,
        acknowledged_at_ms: int = 0,
        error: str = "",
        lease_id: str = "",
        retry_after_ms: int = 0,
        now_ms_override: int = 0,
        retryable: bool = True,
    ) -> OutboxRecord:
        if (
            isinstance(acknowledged_at_ms, bool)
            or not isinstance(acknowledged_at_ms, int)
            or acknowledged_at_ms < 0
        ):
            raise CommerceEnvelopeRejected(
                "acknowledged_at_ms must be a non-negative integer",
            )
        if (
            isinstance(retry_after_ms, bool)
            or not isinstance(retry_after_ms, int)
            or not (0 <= retry_after_ms <= 86_400_000)
        ):
            raise CommerceEnvelopeRejected(
                "retry_after_ms must be between 0 and 86400000",
            )
        if isinstance(now_ms_override, bool) or not isinstance(now_ms_override, int) or now_ms_override < 0:
            raise CommerceEnvelopeRejected("now_ms_override must be a non-negative integer")
        if not isinstance(retryable, bool):
            raise CommerceEnvelopeRejected("retryable must be a boolean")
        attempted_at_ms = now_ms_override or time.time_ns() // 1_000_000
        path = self._path(message_id)
        with InterProcessLock(path):
            value = self._load_record(path)
            if not isinstance(value, dict):
                raise CommerceEnvelopeRejected("outbox message not found")
            record = self._decode_record(value, path)
            if record.status == "acknowledged":
                return record
            if record.status == "inflight" and (
                not lease_id or lease_id != record.lease_id
            ):
                raise CommerceEnvelopeRejected("outbox lease does not match active delivery")
            record.attempts += 1
            record.last_attempt_at_ms = attempted_at_ms
            if acknowledged_at_ms:
                record.status = "acknowledged"
                record.acknowledged_at_ms = acknowledged_at_ms
                record.blocked_at_ms = 0
                record.last_error = ""
                record.next_attempt_at_ms = 0
            elif not retryable:
                record.status = "blocked"
                record.blocked_at_ms = attempted_at_ms
                record.last_error = normalize_outbox_error(
                    error,
                    retryable=False,
                )
                record.next_attempt_at_ms = 0
            else:
                record.status = "pending"
                record.blocked_at_ms = 0
                record.last_error = normalize_outbox_error(
                    error,
                    retryable=True,
                )
                record.next_attempt_at_ms = attempted_at_ms + retry_after_ms
            record.lease_id = ""
            record.lease_expires_at_ms = 0
            atomic_write_json(path, asdict(record))
            return record

    def archive_acknowledged(
        self,
        *,
        before_ms: int,
        limit: int = 100,
    ) -> List[str]:
        """Atomically move old ACK records to the retained audit archive."""
        if isinstance(before_ms, bool) or not isinstance(before_ms, int) or before_ms <= 0:
            raise CommerceEnvelopeRejected("before_ms must be a positive integer")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1_000:
            raise CommerceEnvelopeRejected("limit must be between 1 and 1000")
        archived: List[str] = []
        for path in sorted(self.root.glob("*.json")):
            message_id = f"sha256:{path.stem}"
            with InterProcessLock(path):
                try:
                    value = self._load_record(path)
                except CommerceEnvelopeRejected as exc:
                    logger.warning("skipping invalid commerce outbox archive candidate %s: %s", path, exc)
                    continue
                try:
                    record = self._decode_record(value, path) if isinstance(value, dict) else None
                except CommerceEnvelopeRejected:
                    record = None
                if (
                    record is None
                    or record.status != "acknowledged"
                    or record.acknowledged_at_ms <= 0
                    or record.acknowledged_at_ms >= before_ms
                ):
                    continue
                self.archive_root.mkdir(parents=True, exist_ok=True)
                destination = self.archive_root / path.name
                if destination.exists():
                    raise CommerceEnvelopeRejected(
                        f"archive already contains {message_id}",
                    )
                path.replace(destination)
                archived.append(message_id)
            if len(archived) >= limit:
                break
        return archived
