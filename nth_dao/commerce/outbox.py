"""Durable, signed commerce replication envelopes."""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

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


class CommerceEnvelopeRejected(ValueError):
    pass


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
    lease_id: str = ""
    lease_expires_at_ms: int = 0


class CommerceOutbox:
    def __init__(self, root: PathLike) -> None:
        self.root = Path(root) / "commerce" / "outbox"
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, message_id: str) -> Path:
        if not isinstance(message_id, str) or not message_id.startswith("sha256:") or len(message_id) != 71:
            raise CommerceEnvelopeRejected("invalid message id")
        try:
            bytes.fromhex(message_id[7:])
        except ValueError as exc:
            raise CommerceEnvelopeRejected("invalid message id") from exc
        return self.root / f"{message_id[7:]}.json"

    def enqueue(self, envelope: CommerceEnvelope, *, target_url: str) -> OutboxRecord:
        ok, reason = verify_envelope(envelope)
        if not ok:
            raise CommerceEnvelopeRejected(reason)
        if not isinstance(target_url, str) or not target_url.strip() or len(target_url) > 2048:
            raise CommerceEnvelopeRejected("invalid target URL")
        path = self._path(envelope.message_id)
        with InterProcessLock(path):
            current = safe_load_json(path, fallback=None)
            wanted = OutboxRecord(envelope=envelope.to_dict(), target_url=target_url.rstrip("/"))
            if current is not None:
                if not isinstance(current, dict) or current.get("target_url") != wanted.target_url:
                    raise CommerceEnvelopeRejected("outbox message id collision")
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
                return OutboxRecord(**current)
            atomic_write_json(path, asdict(wanted))
            return wanted

    def get(self, message_id: str) -> Optional[OutboxRecord]:
        value = safe_load_json(self._path(message_id), fallback=None)
        try:
            return OutboxRecord(**value) if isinstance(value, dict) else None
        except TypeError:
            return None

    def claim(
        self,
        message_id: str,
        *,
        lease_ms: int = 30_000,
        now_ms_override: int = 0,
    ) -> Optional[OutboxRecord]:
        if isinstance(lease_ms, bool) or not isinstance(lease_ms, int) or not (1_000 <= lease_ms <= 300_000):
            raise CommerceEnvelopeRejected("lease_ms must be between 1000 and 300000")
        current_ms = now_ms_override or time.time_ns() // 1_000_000
        path = self._path(message_id)
        with InterProcessLock(path):
            value = safe_load_json(path, fallback=None)
            if not isinstance(value, dict):
                return None
            try:
                record = OutboxRecord(**value)
            except TypeError as exc:
                raise CommerceEnvelopeRejected("stored outbox record is invalid") from exc
            if record.status == "acknowledged":
                return None
            if record.status == "inflight" and record.lease_expires_at_ms > current_ms:
                return None
            if record.status not in {"pending", "inflight"}:
                raise CommerceEnvelopeRejected("stored outbox status is invalid")
            record.status = "inflight"
            record.lease_id = uuid.uuid4().hex
            record.lease_expires_at_ms = current_ms + lease_ms
            atomic_write_json(path, asdict(record))
            return record

    def claim_pending(
        self,
        *,
        limit: int = 100,
        lease_ms: int = 30_000,
    ) -> List[OutboxRecord]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not (1 <= limit <= 1000):
            raise CommerceEnvelopeRejected("limit must be between 1 and 1000")
        claimed: List[OutboxRecord] = []
        for path in sorted(self.root.glob("*.json")):
            try:
                record = self.claim(
                    f"sha256:{path.stem}", lease_ms=lease_ms,
                )
            except CommerceEnvelopeRejected:
                continue
            if record is not None:
                claimed.append(record)
                if len(claimed) >= limit:
                    break
        return claimed

    def pending(self, *, limit: int = 100) -> List[OutboxRecord]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not (1 <= limit <= 1000):
            raise CommerceEnvelopeRejected("limit must be between 1 and 1000")
        rows: List[OutboxRecord] = []
        for path in sorted(self.root.glob("*.json")):
            value = safe_load_json(path, fallback=None)
            try:
                record = OutboxRecord(**value) if isinstance(value, dict) else None
            except TypeError:
                record = None
            if record is not None and record.status in {"pending", "inflight"}:
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
    ) -> OutboxRecord:
        path = self._path(message_id)
        with InterProcessLock(path):
            value = safe_load_json(path, fallback=None)
            if not isinstance(value, dict):
                raise CommerceEnvelopeRejected("outbox message not found")
            record = OutboxRecord(**value)
            if record.status == "acknowledged":
                return record
            if record.status == "inflight" and (
                not lease_id or lease_id != record.lease_id
            ):
                raise CommerceEnvelopeRejected("outbox lease does not match active delivery")
            record.attempts += 1
            if acknowledged_at_ms:
                record.status = "acknowledged"
                record.acknowledged_at_ms = acknowledged_at_ms
                record.last_error = ""
            else:
                record.status = "pending"
                record.last_error = str(error or "delivery failed")[:500]
            record.lease_id = ""
            record.lease_expires_at_ms = 0
            atomic_write_json(path, asdict(record))
            return record
