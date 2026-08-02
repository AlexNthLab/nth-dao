"""Durable maker-side dispatch and receiver acknowledgement retention."""

from __future__ import annotations

import json
import math
import os
import re
import stat
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.spine import SignedEventLog, SpineEvent
from nth_dao.trade_rules.canonical import MAX_SAFE_INTEGER
from nth_dao.trade_rules.order_transport import (
    DEFAULT_ORDER_DELIVERY_CLOCK_SKEW_SECONDS,
    TradeOrderDelivery,
    TradeOrderIntakeReceipt,
    trade_order_delivery_digest,
    trade_order_intake_receipt_digest,
    verify_trade_order_delivery,
    verify_trade_order_intake_receipt,
)
from nth_dao.trade_rules.agreement_order import trade_order_digest
from nth_dao.util.io import InterProcessLock
from nth_dao.util.jsonl_safe import LOCK_TIMEOUT_PATIENT

DISPATCH_KIND = "nth.dao.trade.order-dispatch-work"
ACKNOWLEDGEMENT_KIND = "nth.dao.trade.order-intake-acknowledgement"
DISPATCH_PROTOCOL_VERSION = "1"
PENDING_RECORD_VERSION = "2"
EVENT_TRADE_ORDER_INTAKE_ACKNOWLEDGED = (
    "trade.order.intake-acknowledged"
)
DEFAULT_MAX_PENDING_DISPATCHES = 4_096
DEFAULT_MAX_ACKNOWLEDGEMENTS = 65_536
DEFAULT_MAX_DISPATCH_BYTES = 2 * 1024 * 1024 * 1024
MAX_DISPATCH_RECORD_BYTES = 768 * 1024
MAX_SUPERSEDED_DELIVERIES = 256
_OBSERVATION_CLOCK_SKEW_MS = int(
    DEFAULT_ORDER_DELIVERY_CLOCK_SKEW_SECONDS * 1_000
)

_DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
_EVENT_ID = re.compile(r"^[0-9a-f]{64}$")
_RECORD_FILE = re.compile(r"^[0-9a-f]{64}\.json$")
_TEMP_FILE = re.compile(r"^[0-9a-f]{64}\.json\..+\.tmp$")


class TradeOrderDispatchError(RuntimeError):
    """Dispatch persistence or acknowledgement projection is invalid."""


class TradeOrderDispatchBusy(TradeOrderDispatchError):
    """Another process owns the dispatch store lock."""


class TradeOrderDispatchCapacity(TradeOrderDispatchError):
    """A bounded dispatch directory reached its configured capacity."""


def _now_ms(value: int | None = None) -> int:
    result = time.time_ns() // 1_000_000 if value is None else value
    if (
        isinstance(result, bool)
        or not isinstance(result, int)
        or not 0 < result <= MAX_SAFE_INTEGER
    ):
        raise ValueError("now_ms must be a safe positive integer")
    return result


def _signed_timestamp_ms(value: str) -> int:
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise TradeOrderDispatchError("signed timestamp is invalid") from exc
    return int(moment.timestamp() * 1_000)


def _normalize_target_url(value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 2_048:
        raise TradeOrderDispatchError("target_url is invalid")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise TradeOrderDispatchError("target_url contains control characters")
    try:
        parsed = urlsplit(value.strip())
        port = parsed.port
    except ValueError as exc:
        raise TradeOrderDispatchError("target_url is invalid") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise TradeOrderDispatchError("target_url must be an HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise TradeOrderDispatchError(
            "target_url must not include credentials, query, or fragment"
        )
    host = parsed.hostname.lower().rstrip(".")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host + (f":{port}" if port is not None else "")
    return urlunsplit(
        (parsed.scheme.lower(), netloc, parsed.path.rstrip("/"), "", "")
    ).rstrip("/")


def _decode_canonical_json(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise TradeOrderDispatchError(f"{label} is invalid JSON") from exc
    if not isinstance(value, dict) or raw != canonical_json(value):
        raise TradeOrderDispatchError(f"{label} is not canonical JSON")
    return value


@dataclass(frozen=True)
class TradeOrderDispatchRecord:
    order_digest: str
    target_url: str
    delivery: TradeOrderDelivery
    attempts: int
    last_error: str
    created_at_ms: int
    updated_at_ms: int
    generation: int = 1
    superseded_delivery_digests: tuple[str, ...] = ()


@dataclass(frozen=True)
class TradeOrderAcknowledgement:
    order_digest: str
    target_url: str
    delivery: TradeOrderDelivery
    receipt: TradeOrderIntakeReceipt
    remote_event_id: str
    observed_at_ms: int

    @property
    def delivery_digest(self) -> str:
        return trade_order_delivery_digest(self.delivery)

    @property
    def receipt_digest(self) -> str:
        return trade_order_intake_receipt_digest(self.receipt)


@dataclass(frozen=True)
class TradeOrderDispatchReconciliation:
    scanned: int
    anchored: int
    completed: int
    failed: int
    next_cursor: str
    has_more: bool


@dataclass(frozen=True)
class TradeOrderDispatchResidue:
    area: str
    filename: str
    size_bytes: int
    modified_at_ns: int


class TradeOrderDispatchStore:
    """Bounded pending work plus durable receiver acknowledgements."""

    def __init__(
        self,
        root: str | Path,
        *,
        max_pending: int = DEFAULT_MAX_PENDING_DISPATCHES,
        max_acknowledgements: int = DEFAULT_MAX_ACKNOWLEDGEMENTS,
        max_bytes: int = DEFAULT_MAX_DISPATCH_BYTES,
        lock_timeout: float = LOCK_TIMEOUT_PATIENT,
    ) -> None:
        for label, value in (
            ("max_pending", max_pending),
            ("max_acknowledgements", max_acknowledgements),
            ("max_bytes", max_bytes),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 1
            ):
                raise ValueError(f"{label} must be a positive integer")
        if (
            isinstance(lock_timeout, bool)
            or not isinstance(lock_timeout, (int, float))
            or not math.isfinite(lock_timeout)
            or lock_timeout <= 0
        ):
            raise ValueError("lock_timeout must be finite and positive")
        self.workspace_root = Path(root)
        self.root = self.workspace_root / "trade" / "order_dispatch_v1"
        self.pending_root = self.root / "pending"
        self.ack_root = self.root / "acknowledgements"
        self.lock_path = self.root / ".locks" / "store"
        self.max_pending = max_pending
        self.max_acknowledgements = max_acknowledgements
        self.max_bytes = max_bytes
        self.lock_timeout = float(lock_timeout)

    @staticmethod
    def _is_linklike(path: Path) -> bool:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if is_junction and is_junction():
            return True
        if os.name == "nt":
            try:
                metadata = os.lstat(path)
            except FileNotFoundError:
                return False
            return bool(
                getattr(metadata, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            )
        return False

    def _assert_path(self, path: Path) -> None:
        try:
            relative = path.relative_to(self.workspace_root)
        except ValueError as exc:
            raise TradeOrderDispatchError(
                "dispatch path escapes workspace root"
            ) from exc
        current = self.workspace_root
        for part in ("", *relative.parts):
            if part:
                current = current / part
            if self._is_linklike(current):
                raise TradeOrderDispatchError(
                    "dispatch store must not contain links or junctions"
                )

    def _acquire(self):
        self._assert_path(self.lock_path.parent)
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        self._assert_path(self.lock_path.parent)
        return InterProcessLock(self.lock_path, timeout=self.lock_timeout)

    @staticmethod
    def _suffix(digest: str) -> str:
        match = _DIGEST.fullmatch(digest) if isinstance(digest, str) else None
        if match is None:
            raise TradeOrderDispatchError("order_digest is invalid")
        return match.group(1)

    def _path(self, directory: Path, digest: str) -> Path:
        return directory / f"{self._suffix(digest)}.json"

    def _atomic_write(self, path: Path, value: dict[str, Any]) -> None:
        payload = canonical_json(value)
        if len(payload) > MAX_DISPATCH_RECORD_BYTES:
            raise TradeOrderDispatchCapacity("dispatch record is too large")
        descriptor: int | None = None
        temporary: str | None = None
        try:
            self._assert_path(path.parent)
            path.parent.mkdir(parents=True, exist_ok=True)
            self._assert_path(path.parent)
            descriptor, temporary = tempfile.mkstemp(
                prefix=path.name + ".",
                suffix=".tmp",
                dir=str(path.parent),
            )
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = None
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            temporary = None
            if os.name != "nt":
                directory = os.open(
                    path.parent,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                )
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        except OSError as exc:
            raise TradeOrderDispatchError(
                "unable to persist dispatch state"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    def _files_and_usage(self, directory: Path) -> tuple[list[Path], int, int]:
        if not directory.exists():
            return [], 0, 0
        files: list[Path] = []
        records = 0
        total = 0
        for path in directory.iterdir():
            self._assert_path(path)
            if self._is_linklike(path) or path.is_dir():
                raise TradeOrderDispatchError(
                    "dispatch directory contains an invalid entry"
                )
            if _RECORD_FILE.fullmatch(path.name):
                files.append(path)
                records += 1
            elif _TEMP_FILE.fullmatch(path.name):
                records += 1
            else:
                raise TradeOrderDispatchError(
                    "dispatch directory contains an unknown file"
                )
            total += path.stat().st_size
        return sorted(files), records, total

    def _residue_locked(self) -> tuple[TradeOrderDispatchResidue, ...]:
        output: list[TradeOrderDispatchResidue] = []
        for area, directory in (
            ("pending", self.pending_root),
            ("acknowledgements", self.ack_root),
        ):
            self._files_and_usage(directory)
            if not directory.exists():
                continue
            for path in directory.iterdir():
                if _TEMP_FILE.fullmatch(path.name) is None:
                    continue
                metadata = path.stat()
                output.append(TradeOrderDispatchResidue(
                    area=area,
                    filename=path.name,
                    size_bytes=metadata.st_size,
                    modified_at_ns=metadata.st_mtime_ns,
                ))
        return tuple(sorted(output, key=lambda item: (item.area, item.filename)))

    def inspect_crash_residue(self) -> tuple[TradeOrderDispatchResidue, ...]:
        """Return recognized temp files without mutating dispatch state."""

        try:
            with self._acquire():
                return self._residue_locked()
        except TimeoutError as exc:
            raise TradeOrderDispatchBusy("dispatch store is busy") from exc

    def prune_crash_residue(
        self,
        *,
        expected: tuple[TradeOrderDispatchResidue, ...],
    ) -> int:
        """Delete only an unchanged operator-inspected residue snapshot."""

        if not isinstance(expected, tuple) or any(
            not isinstance(item, TradeOrderDispatchResidue)
            for item in expected
        ):
            raise TypeError("expected must be a residue tuple from inspect")
        try:
            with self._acquire():
                current = self._residue_locked()
                if current != expected:
                    raise TradeOrderDispatchError(
                        "dispatch crash residue changed since inspection"
                    )
                touched: set[Path] = set()
                for item in current:
                    directory = (
                        self.pending_root
                        if item.area == "pending"
                        else self.ack_root
                    )
                    path = directory / item.filename
                    self._assert_path(path)
                    path.unlink()
                    touched.add(directory)
                if os.name != "nt":
                    for directory_path in touched:
                        descriptor = os.open(
                            directory_path,
                            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                        )
                        try:
                            os.fsync(descriptor)
                        finally:
                            os.close(descriptor)
                return len(current)
        except TimeoutError as exc:
            raise TradeOrderDispatchBusy("dispatch store is busy") from exc
        except OSError as exc:
            raise TradeOrderDispatchError(
                "unable to prune dispatch crash residue"
            ) from exc

    @staticmethod
    def _read_bounded(path: Path, *, label: str) -> bytes:
        try:
            with path.open("rb") as stream:
                raw = stream.read(MAX_DISPATCH_RECORD_BYTES + 1)
        except OSError as exc:
            raise TradeOrderDispatchError(f"unable to read {label}") from exc
        if len(raw) > MAX_DISPATCH_RECORD_BYTES:
            raise TradeOrderDispatchError(f"{label} is too large")
        return raw

    def _read_pending(self, path: Path) -> TradeOrderDispatchRecord:
        raw = self._read_bounded(path, label="pending dispatch")
        value = _decode_canonical_json(raw, label="pending dispatch")
        legacy_fields = {
            "kind", "protocol_version", "order_digest", "target_url",
            "delivery_b64u", "attempts", "last_error", "created_at_ms",
            "updated_at_ms",
        }
        current_fields = legacy_fields | {
            "generation",
            "superseded_delivery_digests",
        }
        version = value.get("protocol_version")
        expected = (
            legacy_fields
            if version == DISPATCH_PROTOCOL_VERSION
            else current_fields
        )
        if set(value) != expected or value["kind"] != DISPATCH_KIND:
            raise TradeOrderDispatchError("pending dispatch fields are invalid")
        if version not in {DISPATCH_PROTOCOL_VERSION, PENDING_RECORD_VERSION}:
            raise TradeOrderDispatchError("pending dispatch version is invalid")
        digest = value["order_digest"]
        if path != self._path(self.pending_root, digest):
            raise TradeOrderDispatchError("pending dispatch filename mismatch")
        try:
            delivery = TradeOrderDelivery.from_json(
                b64u_decode(value["delivery_b64u"])
            )
        except (TypeError, ValueError) as exc:
            raise TradeOrderDispatchError("pending Delivery is invalid") from exc
        if b64u_encode(delivery.canonical_bytes) != value["delivery_b64u"]:
            raise TradeOrderDispatchError("pending Delivery is not canonical")
        if trade_order_digest(delivery.order) != digest:
            raise TradeOrderDispatchError("pending Order digest mismatch")
        attempts = value["attempts"]
        if (
            isinstance(attempts, bool)
            or not isinstance(attempts, int)
            or not 0 <= attempts <= MAX_SAFE_INTEGER
        ):
            raise TradeOrderDispatchError("pending attempts are invalid")
        last_error = value["last_error"]
        if not isinstance(last_error, str) or len(last_error) > 500:
            raise TradeOrderDispatchError("pending last_error is invalid")
        created = value["created_at_ms"]
        updated = value["updated_at_ms"]
        if any(
            isinstance(item, bool)
            or not isinstance(item, int)
            or not 0 < item <= MAX_SAFE_INTEGER
            for item in (created, updated)
        ) or updated < created:
            raise TradeOrderDispatchError("pending timestamps are invalid")
        generation = value.get("generation", 1)
        superseded_raw = value.get("superseded_delivery_digests", [])
        if (
            isinstance(generation, bool)
            or not isinstance(generation, int)
            or not 1 <= generation <= MAX_SAFE_INTEGER
            or not isinstance(superseded_raw, list)
            or len(superseded_raw) > MAX_SUPERSEDED_DELIVERIES
            or any(
                not isinstance(item, str) or _DIGEST.fullmatch(item) is None
                for item in superseded_raw
            )
            or len(set(superseded_raw)) != len(superseded_raw)
            or generation != len(superseded_raw) + 1
            or trade_order_delivery_digest(delivery) in superseded_raw
        ):
            raise TradeOrderDispatchError(
                "pending delivery generation history is invalid"
            )
        return TradeOrderDispatchRecord(
            order_digest=digest,
            target_url=_normalize_target_url(value["target_url"]),
            delivery=delivery,
            attempts=attempts,
            last_error=last_error,
            created_at_ms=created,
            updated_at_ms=updated,
            generation=generation,
            superseded_delivery_digests=tuple(superseded_raw),
        )

    def _pending_dict(self, record: TradeOrderDispatchRecord) -> dict[str, Any]:
        return {
            "kind": DISPATCH_KIND,
            "protocol_version": PENDING_RECORD_VERSION,
            "order_digest": record.order_digest,
            "target_url": record.target_url,
            "delivery_b64u": b64u_encode(record.delivery.canonical_bytes),
            "attempts": record.attempts,
            "last_error": record.last_error,
            "created_at_ms": record.created_at_ms,
            "updated_at_ms": record.updated_at_ms,
            "generation": record.generation,
            "superseded_delivery_digests": list(
                record.superseded_delivery_digests
            ),
        }

    def _read_ack(self, path: Path) -> TradeOrderAcknowledgement:
        raw = self._read_bounded(path, label="acknowledgement")
        value = _decode_canonical_json(raw, label="acknowledgement")
        expected = {
            "kind", "protocol_version", "order_digest", "target_url",
            "delivery_b64u", "receipt_b64u", "remote_event_id",
            "observed_at_ms",
        }
        if set(value) != expected or value["kind"] != ACKNOWLEDGEMENT_KIND:
            raise TradeOrderDispatchError("acknowledgement fields are invalid")
        if value["protocol_version"] != DISPATCH_PROTOCOL_VERSION:
            raise TradeOrderDispatchError("acknowledgement version is invalid")
        digest = value["order_digest"]
        if path != self._path(self.ack_root, digest):
            raise TradeOrderDispatchError("acknowledgement filename mismatch")
        try:
            delivery = TradeOrderDelivery.from_json(
                b64u_decode(value["delivery_b64u"])
            )
            receipt = TradeOrderIntakeReceipt.from_json(
                b64u_decode(value["receipt_b64u"])
            )
        except (TypeError, ValueError) as exc:
            raise TradeOrderDispatchError(
                "acknowledgement signed bytes are invalid"
            ) from exc
        if trade_order_digest(delivery.order) != digest:
            raise TradeOrderDispatchError("acknowledgement Order mismatch")
        remote_event_id = value["remote_event_id"]
        ok, reason = verify_trade_order_intake_receipt(
            receipt,
            delivery=delivery,
            receiver_did=delivery.to_dict()["recipient_did"],
            audit_event_id=remote_event_id,
        )
        if not ok:
            raise TradeOrderDispatchError(reason)
        observed = value["observed_at_ms"]
        if (
            isinstance(observed, bool)
            or not isinstance(observed, int)
            or not 0 < observed <= MAX_SAFE_INTEGER
        ):
            raise TradeOrderDispatchError("observed_at_ms is invalid")
        if observed + _OBSERVATION_CLOCK_SKEW_MS < _signed_timestamp_ms(
            receipt.to_dict()["received_at"]
        ):
            raise TradeOrderDispatchError(
                "acknowledgement observation predates signed receipt"
            )
        return TradeOrderAcknowledgement(
            order_digest=digest,
            target_url=_normalize_target_url(value["target_url"]),
            delivery=delivery,
            receipt=receipt,
            remote_event_id=remote_event_id,
            observed_at_ms=observed,
        )

    def prepare(
        self,
        delivery: TradeOrderDelivery,
        *,
        target_url: str,
        now_ms: int | None = None,
    ) -> TradeOrderDispatchRecord:
        verified = TradeOrderDelivery.from_json(delivery.canonical_bytes)
        digest = trade_order_digest(verified.order)
        target = _normalize_target_url(target_url)
        moment = _now_ms(now_ms)
        path = self._path(self.pending_root, digest)
        try:
            with self._acquire():
                _pending_files, pending_count, pending_bytes = (
                    self._files_and_usage(self.pending_root)
                )
                _ack_files, ack_count, ack_bytes = self._files_and_usage(
                    self.ack_root
                )
                ack_path = self._path(self.ack_root, digest)
                if ack_path.exists():
                    acknowledged = self._read_ack(ack_path)
                    return TradeOrderDispatchRecord(
                        order_digest=digest,
                        target_url=acknowledged.target_url,
                        delivery=acknowledged.delivery,
                        attempts=0,
                        last_error="",
                        created_at_ms=acknowledged.observed_at_ms,
                        updated_at_ms=acknowledged.observed_at_ms,
                    )
                existing = self._read_pending(path) if path.exists() else None
                if existing is not None:
                    if existing.target_url != target:
                        raise TradeOrderDispatchError(
                            "pending dispatch target cannot change"
                        )
                    if existing.delivery.canonical_bytes == verified.canonical_bytes:
                        return existing
                    at = datetime.fromtimestamp(
                        moment / 1_000,
                        tz=timezone.utc,
                    )
                    still_valid, reason = verify_trade_order_delivery(
                        existing.delivery,
                        recipient_did=existing.delivery.to_dict()[
                            "recipient_did"
                        ],
                        at=at,
                    )
                    if still_valid:
                        return existing
                    if reason != "Order delivery has expired":
                        raise TradeOrderDispatchError(
                            f"pending dispatch cannot be renewed: {reason}"
                        )
                    replacement_valid, replacement_reason = (
                        verify_trade_order_delivery(
                            verified,
                            recipient_did=verified.to_dict()["recipient_did"],
                            at=at,
                        )
                    )
                    if not replacement_valid:
                        raise TradeOrderDispatchError(
                            "replacement Delivery is invalid: "
                            f"{replacement_reason}"
                        )
                    if (
                        len(existing.superseded_delivery_digests)
                        >= MAX_SUPERSEDED_DELIVERIES
                    ):
                        raise TradeOrderDispatchCapacity(
                            "max superseded Delivery generations exceeded"
                        )
                    renewed = TradeOrderDispatchRecord(
                        order_digest=digest,
                        target_url=target,
                        delivery=verified,
                        attempts=existing.attempts,
                        last_error="",
                        created_at_ms=existing.created_at_ms,
                        updated_at_ms=max(moment, existing.updated_at_ms),
                        generation=existing.generation + 1,
                        superseded_delivery_digests=(
                            *existing.superseded_delivery_digests,
                            trade_order_delivery_digest(existing.delivery),
                        ),
                    )
                    self._atomic_write(path, self._pending_dict(renewed))
                    return self._read_pending(path)
                record = TradeOrderDispatchRecord(
                    order_digest=digest,
                    target_url=target,
                    delivery=verified,
                    attempts=existing.attempts if existing else 0,
                    last_error="",
                    created_at_ms=existing.created_at_ms if existing else moment,
                    updated_at_ms=max(moment, existing.updated_at_ms)
                    if existing else moment,
                )
                payload_size = len(canonical_json(self._pending_dict(record)))
                old_size = path.stat().st_size if path.exists() else 0
                if not existing and pending_count + 1 > self.max_pending:
                    raise TradeOrderDispatchCapacity("max_pending exceeded")
                if ack_count > self.max_acknowledgements:
                    raise TradeOrderDispatchCapacity(
                        "max_acknowledgements exceeded"
                    )
                if pending_bytes + ack_bytes - old_size + payload_size > self.max_bytes:
                    raise TradeOrderDispatchCapacity("max_bytes exceeded")
                self._atomic_write(path, self._pending_dict(record))
                return record
        except TimeoutError as exc:
            raise TradeOrderDispatchBusy("dispatch store is busy") from exc

    def note_failure(
        self,
        digest: str,
        *,
        error: str,
        now_ms: int | None = None,
    ) -> TradeOrderDispatchRecord:
        moment = _now_ms(now_ms)
        path = self._path(self.pending_root, digest)
        try:
            with self._acquire():
                record = self._read_pending(path)
                if record.attempts >= MAX_SAFE_INTEGER:
                    raise TradeOrderDispatchCapacity(
                        "pending dispatch attempt counter is exhausted"
                    )
                updated = TradeOrderDispatchRecord(
                    **{
                        **record.__dict__,
                        "attempts": record.attempts + 1,
                        "last_error": str(error).replace("\r", " ").replace(
                            "\n", " "
                        )[:500],
                        "updated_at_ms": max(moment, record.updated_at_ms),
                    }
                )
                self._atomic_write(path, self._pending_dict(updated))
                return updated
        except FileNotFoundError as exc:
            raise TradeOrderDispatchError("pending dispatch is missing") from exc
        except TimeoutError as exc:
            raise TradeOrderDispatchBusy("dispatch store is busy") from exc

    def put_acknowledgement(
        self,
        delivery: TradeOrderDelivery,
        receipt: TradeOrderIntakeReceipt,
        *,
        target_url: str,
        remote_event_id: str,
        observed_at_ms: int | None = None,
    ) -> TradeOrderAcknowledgement:
        verified_delivery = TradeOrderDelivery.from_json(delivery.canonical_bytes)
        verified_receipt = TradeOrderIntakeReceipt.from_json(receipt.canonical_bytes)
        digest = trade_order_digest(verified_delivery.order)
        if not isinstance(remote_event_id, str) or not _EVENT_ID.fullmatch(
            remote_event_id
        ):
            raise TradeOrderDispatchError("remote_event_id is invalid")
        ok, reason = verify_trade_order_intake_receipt(
            verified_receipt,
            delivery=verified_delivery,
            receiver_did=verified_delivery.to_dict()["recipient_did"],
            audit_event_id=remote_event_id,
        )
        if not ok:
            raise TradeOrderDispatchError(reason)
        acknowledgement = TradeOrderAcknowledgement(
            order_digest=digest,
            target_url=_normalize_target_url(target_url),
            delivery=verified_delivery,
            receipt=verified_receipt,
            remote_event_id=remote_event_id,
            observed_at_ms=_now_ms(observed_at_ms),
        )
        if (
            acknowledgement.observed_at_ms + _OBSERVATION_CLOCK_SKEW_MS
            < _signed_timestamp_ms(verified_receipt.to_dict()["received_at"])
        ):
            raise TradeOrderDispatchError(
                "acknowledgement observation predates signed receipt"
            )
        value = {
            "kind": ACKNOWLEDGEMENT_KIND,
            "protocol_version": DISPATCH_PROTOCOL_VERSION,
            "order_digest": digest,
            "target_url": acknowledgement.target_url,
            "delivery_b64u": b64u_encode(verified_delivery.canonical_bytes),
            "receipt_b64u": b64u_encode(verified_receipt.canonical_bytes),
            "remote_event_id": remote_event_id,
            "observed_at_ms": acknowledgement.observed_at_ms,
        }
        path = self._path(self.ack_root, digest)
        try:
            with self._acquire():
                existing = self._read_ack(path) if path.exists() else None
                if existing is not None:
                    if (
                        existing.target_url != acknowledgement.target_url
                        or existing.delivery.canonical_bytes
                        != acknowledgement.delivery.canonical_bytes
                        or existing.receipt.canonical_bytes
                        != acknowledgement.receipt.canonical_bytes
                        or existing.remote_event_id
                        != acknowledgement.remote_event_id
                    ):
                        raise TradeOrderDispatchError(
                            "acknowledgement conflicts with retained bytes"
                        )
                    return existing
                pending_path = self._path(self.pending_root, digest)
                if not pending_path.exists():
                    raise TradeOrderDispatchError(
                        "acknowledgement has no pending dispatch"
                    )
                pending = self._read_pending(pending_path)
                if (
                    pending.target_url != acknowledgement.target_url
                    or pending.delivery.canonical_bytes
                    != acknowledgement.delivery.canonical_bytes
                ):
                    raise TradeOrderDispatchError(
                        "acknowledgement does not match pending dispatch"
                    )
                _pending, _pending_count, pending_bytes = self._files_and_usage(
                    self.pending_root
                )
                _acks, ack_count, ack_bytes = self._files_and_usage(self.ack_root)
                if ack_count + 1 > self.max_acknowledgements:
                    raise TradeOrderDispatchCapacity(
                        "max_acknowledgements exceeded"
                    )
                if pending_bytes + ack_bytes + len(canonical_json(value)) > self.max_bytes:
                    raise TradeOrderDispatchCapacity("max_bytes exceeded")
                self._atomic_write(path, value)
                return self._read_ack(path)
        except TimeoutError as exc:
            raise TradeOrderDispatchBusy("dispatch store is busy") from exc

    def get_pending(self, digest: str) -> TradeOrderDispatchRecord | None:
        path = self._path(self.pending_root, digest)
        try:
            with self._acquire():
                self._files_and_usage(self.pending_root)
                return self._read_pending(path) if path.exists() else None
        except TimeoutError as exc:
            raise TradeOrderDispatchBusy("dispatch store is busy") from exc

    def get_acknowledgement(
        self, digest: str
    ) -> TradeOrderAcknowledgement | None:
        path = self._path(self.ack_root, digest)
        try:
            with self._acquire():
                self._files_and_usage(self.ack_root)
                return self._read_ack(path) if path.exists() else None
        except TimeoutError as exc:
            raise TradeOrderDispatchBusy("dispatch store is busy") from exc

    def get_state(
        self,
        digest: str,
    ) -> tuple[
        TradeOrderDispatchRecord | None,
        TradeOrderAcknowledgement | None,
    ]:
        """Return pending and acknowledged state from one lock snapshot."""

        return self.get_states((digest,))[digest]

    def get_states(
        self,
        digests: tuple[str, ...],
    ) -> dict[
        str,
        tuple[
            TradeOrderDispatchRecord | None,
            TradeOrderAcknowledgement | None,
        ],
    ]:
        """Return a bounded batch after one directory validation scan."""

        if not isinstance(digests, tuple) or len(digests) > 1_000:
            raise ValueError("digests must be a tuple with at most 1000 items")
        if len(set(digests)) != len(digests):
            raise ValueError("digests must not contain duplicates")
        paths = {
            digest: (
                self._path(self.pending_root, digest),
                self._path(self.ack_root, digest),
            )
            for digest in digests
        }
        try:
            with self._acquire():
                self._files_and_usage(self.pending_root)
                self._files_and_usage(self.ack_root)
                return {
                    digest: (
                        self._read_pending(pending_path)
                        if pending_path.exists()
                        else None,
                        self._read_ack(acknowledgement_path)
                        if acknowledgement_path.exists()
                        else None,
                    )
                    for digest, (
                        pending_path,
                        acknowledgement_path,
                    ) in paths.items()
                }
        except TimeoutError as exc:
            raise TradeOrderDispatchBusy("dispatch store is busy") from exc

    def list_acknowledgements(
        self,
        *,
        limit: int = 1_000,
        after: str | None = None,
    ) -> tuple[tuple[TradeOrderAcknowledgement, ...], str]:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        after_suffix = self._suffix(after) if after is not None else None
        try:
            with self._acquire():
                files, _count, _bytes = self._files_and_usage(self.ack_root)
                if after_suffix is not None:
                    files = [path for path in files if path.stem > after_suffix]
                selected = files[: limit + 1]
                page = selected[:limit]
                next_cursor = (
                    f"sha256:{page[-1].stem}"
                    if len(selected) > limit and page
                    else ""
                )
                return (
                    tuple(self._read_ack(path) for path in page),
                    next_cursor,
                )
        except TimeoutError as exc:
            raise TradeOrderDispatchBusy("dispatch store is busy") from exc

    def complete_pending(self, digest: str) -> bool:
        path = self._path(self.pending_root, digest)
        try:
            with self._acquire():
                acknowledgement_path = self._path(self.ack_root, digest)
                if not acknowledgement_path.exists():
                    raise TradeOrderDispatchError(
                        "dispatch cannot complete without a durable acknowledgement"
                    )
                acknowledgement = self._read_ack(acknowledgement_path)
                if not path.exists():
                    return False
                pending = self._read_pending(path)
                if (
                    pending.target_url != acknowledgement.target_url
                    or pending.delivery.canonical_bytes
                    != acknowledgement.delivery.canonical_bytes
                ):
                    raise TradeOrderDispatchError(
                        "pending dispatch conflicts with acknowledgement"
                    )
                path.unlink()
                if os.name != "nt":
                    directory = os.open(
                        path.parent,
                        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                    )
                    try:
                        os.fsync(directory)
                    finally:
                        os.close(directory)
                return True
        except TimeoutError as exc:
            raise TradeOrderDispatchBusy("dispatch store is busy") from exc
        except OSError as exc:
            raise TradeOrderDispatchError(
                "unable to complete pending dispatch"
            ) from exc


def acknowledgement_audit_payload(
    acknowledgement: TradeOrderAcknowledgement,
) -> dict[str, Any]:
    receipt_document = acknowledgement.receipt.to_dict()
    return {
        "protocol_version": DISPATCH_PROTOCOL_VERSION,
        "order_digest": acknowledgement.order_digest,
        "delivery_digest": acknowledgement.delivery_digest,
        "receipt_digest": acknowledgement.receipt_digest,
        "receiver_did": receipt_document["receiver_did"],
        "remote_event_id": acknowledgement.remote_event_id,
        "received_at": receipt_document["received_at"],
    }


class TradeOrderDispatchCoordinator:
    """Persist acknowledgements, anchor them locally, and retire pending work."""

    def __init__(
        self,
        store: TradeOrderDispatchStore,
        spine: SignedEventLog,
    ) -> None:
        self.store = store
        self.spine = spine

    def prepare(
        self,
        delivery: TradeOrderDelivery,
        *,
        target_url: str,
        now_ms: int | None = None,
    ) -> TradeOrderDispatchRecord:
        return self.store.prepare(
            delivery,
            target_url=target_url,
            now_ms=now_ms,
        )

    def failed(
        self,
        digest: str,
        *,
        error: str,
        now_ms: int | None = None,
    ) -> TradeOrderDispatchRecord:
        return self.store.note_failure(
            digest,
            error=error,
            now_ms=now_ms,
        )

    def _anchor(
        self,
        acknowledgement: TradeOrderAcknowledgement,
    ) -> tuple[SpineEvent, bool]:
        return self.spine.append_unique(
            EVENT_TRADE_ORDER_INTAKE_ACKNOWLEDGED,
            acknowledgement_audit_payload(acknowledgement),
            unique_payload_fields=("order_digest",),
            ts_ms=acknowledgement.observed_at_ms,
        )

    def acknowledge(
        self,
        delivery: TradeOrderDelivery,
        receipt: TradeOrderIntakeReceipt,
        *,
        target_url: str,
        remote_event_id: str,
        observed_at_ms: int | None = None,
    ) -> TradeOrderAcknowledgement:
        acknowledgement = self.store.put_acknowledgement(
            delivery,
            receipt,
            target_url=target_url,
            remote_event_id=remote_event_id,
            observed_at_ms=observed_at_ms,
        )
        self._anchor(acknowledgement)
        self.store.complete_pending(acknowledgement.order_digest)
        return acknowledgement

    def recover_acknowledgement(
        self, digest: str
    ) -> TradeOrderAcknowledgement | None:
        """Finish Spine/outbox work for one already durable receipt."""

        acknowledgement = self.store.get_acknowledgement(digest)
        if acknowledgement is None:
            return None
        self._anchor(acknowledgement)
        self.store.complete_pending(digest)
        return acknowledgement

    def reconcile(
        self,
        *,
        limit: int = 1_000,
        after: str | None = None,
    ) -> TradeOrderDispatchReconciliation:
        acknowledgements, next_cursor = self.store.list_acknowledgements(
            limit=limit,
            after=after,
        )
        anchored = 0
        completed = 0
        failed = 0
        for acknowledgement in acknowledgements:
            try:
                _event, created = self._anchor(acknowledgement)
                anchored += int(created)
                completed += int(
                    self.store.complete_pending(acknowledgement.order_digest)
                )
            except (OSError, RuntimeError, TypeError, ValueError):
                failed += 1
        return TradeOrderDispatchReconciliation(
            scanned=len(acknowledgements),
            anchored=anchored,
            completed=completed,
            failed=failed,
            next_cursor=next_cursor,
            has_more=bool(next_cursor),
        )


__all__ = [
    "ACKNOWLEDGEMENT_KIND",
    "DISPATCH_KIND",
    "DISPATCH_PROTOCOL_VERSION",
    "EVENT_TRADE_ORDER_INTAKE_ACKNOWLEDGED",
    "TradeOrderAcknowledgement",
    "TradeOrderDispatchBusy",
    "TradeOrderDispatchCapacity",
    "TradeOrderDispatchCoordinator",
    "TradeOrderDispatchError",
    "TradeOrderDispatchRecord",
    "TradeOrderDispatchReconciliation",
    "TradeOrderDispatchResidue",
    "TradeOrderDispatchStore",
    "acknowledgement_audit_payload",
]
