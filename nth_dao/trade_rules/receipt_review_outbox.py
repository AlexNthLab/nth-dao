"""Durable write-ahead records for Trade Receipt Review projection."""

from __future__ import annotations

import json
import math
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.trade_rules.agreement_order import TradeOrder
from nth_dao.trade_rules.execution_adapter import TradeExecutionAdapterPolicy
from nth_dao.trade_rules.execution_receipt import TradeExecutionReceipt
from nth_dao.trade_rules.negotiation import RuleResolutionPolicy
from nth_dao.trade_rules.receipt_review import (
    RECEIPT_REVIEW_ID_PREFIX,
    TradeReceiptReview,
    receipt_review_digest,
)
from nth_dao.util.io import InterProcessLock

RECEIPT_REVIEW_OUTBOX_KIND = "nth.dao.trade.receipt-review-audit-work"
RECEIPT_REVIEW_OUTBOX_PROTOCOL_VERSION = "3"
DEFAULT_MAX_RECEIPT_REVIEW_OUTBOX_RECORDS = 10_000
DEFAULT_MAX_RECEIPT_REVIEW_OUTBOX_BYTES = 2 * 1024 * 1024 * 1024
MAX_RECEIPT_REVIEW_OUTBOX_RECORD_BYTES = 4 * 1024 * 1024

_STATUSES = frozenset({"prepared", "reviewed", "conflicted", "anchored"})
_EVENT_TYPES = frozenset(
    {
        "",
        "trade.receipt.reviewed",
        "trade.receipt.review.conflicted",
    }
)
_ERROR_CODES = frozenset(
    {
        "",
        "receipt-review-store-failed",
        "spine-anchor-failed",
    }
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REVIEW_ID = re.compile(
    rf"^{re.escape(RECEIPT_REVIEW_ID_PREFIX)}[0-9a-f]{{64}}$"
)
_EVENT_ID = re.compile(r"^[0-9a-f]{64}$")
_RECORD_FILE = re.compile(r"^([0-9a-f]{64})\.json$")
_TEMPORARY_FILE = re.compile(
    r"^[0-9a-f]{64}\.json\.[A-Za-z0-9_-]{1,64}\.tmp$"
)
_V1_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "review_id",
        "review_digest",
        "review_b64u",
        "receipt_b64u",
        "order_b64u",
        "status",
        "event_type",
        "event_id",
        "created_at_ms",
        "updated_at_ms",
        "attempts",
        "last_error",
    }
)
_V2_FIELDS = _V1_FIELDS | frozenset(
    {
        "verifier_policy_b64u",
        "adapter_policy_b64u",
    }
)
_V3_FIELDS = _V2_FIELDS | frozenset({"first_observed_at_ms"})


class TradeReceiptReviewOutboxError(RuntimeError):
    """Receipt Review outbox state is invalid or unavailable."""


class TradeReceiptReviewOutboxCapacity(TradeReceiptReviewOutboxError):
    """The configured outbox capacity would be exceeded."""


class TradeReceiptReviewOutboxBusy(TradeReceiptReviewOutboxError):
    """Another process owns Receipt Review reconciliation."""


def _safe_int(value: Any, *, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > 9_007_199_254_740_991
    ):
        raise TradeReceiptReviewOutboxError(f"{label} is invalid")
    return value


def _strict_json(raw: bytes) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in items:
            if key in output:
                raise TradeReceiptReviewOutboxError(
                    f"duplicate Receipt Review outbox field {key!r}"
                )
            output[key] = value
        return output

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except TradeReceiptReviewOutboxError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TradeReceiptReviewOutboxError(
            "Receipt Review outbox record is not valid UTF-8 JSON"
        ) from exc
    if not isinstance(value, dict):
        raise TradeReceiptReviewOutboxError(
            "Receipt Review outbox record must be an object"
        )
    return value


@dataclass(frozen=True)
class TradeReceiptReviewOutboxRecord:
    kind: str
    protocol_version: str
    review_id: str
    review_digest: str
    review_b64u: str
    receipt_b64u: str
    order_b64u: str
    verifier_policy_b64u: str
    adapter_policy_b64u: str
    status: str
    event_type: str
    event_id: str
    created_at_ms: int
    updated_at_ms: int
    first_observed_at_ms: int
    attempts: int
    last_error: str

    @classmethod
    def from_dict(
        cls,
        value: dict[str, Any],
    ) -> "TradeReceiptReviewOutboxRecord":
        if not isinstance(value, dict):
            raise TradeReceiptReviewOutboxError(
                "Receipt Review outbox record has missing or unknown fields"
            )
        fields = set(value)
        if fields == _V1_FIELDS and value.get("protocol_version") == "1":
            value = {
                **value,
                "verifier_policy_b64u": "",
                "adapter_policy_b64u": "",
                "first_observed_at_ms": 0,
            }
            fields = _V3_FIELDS
        elif fields == _V2_FIELDS and value.get("protocol_version") == "2":
            value = {
                **value,
                "first_observed_at_ms": value.get("created_at_ms"),
            }
            fields = _V3_FIELDS
        elif (
            fields != _V3_FIELDS
            or value.get("protocol_version")
            != RECEIPT_REVIEW_OUTBOX_PROTOCOL_VERSION
        ):
            raise TradeReceiptReviewOutboxError(
                "Receipt Review outbox record has missing or unknown fields"
            )
        for field in fields - {
            "created_at_ms",
            "updated_at_ms",
            "first_observed_at_ms",
            "attempts",
        }:
            if not isinstance(value[field], str):
                raise TradeReceiptReviewOutboxError(
                    f"Receipt Review outbox {field} is invalid"
                )
        record = cls(**value)
        if record.kind != RECEIPT_REVIEW_OUTBOX_KIND:
            raise TradeReceiptReviewOutboxError("outbox kind is invalid")
        if record.protocol_version not in {
            "1",
            "2",
            RECEIPT_REVIEW_OUTBOX_PROTOCOL_VERSION,
        }:
            raise TradeReceiptReviewOutboxError(
                "outbox protocol version is unsupported"
            )
        if _REVIEW_ID.fullmatch(record.review_id) is None:
            raise TradeReceiptReviewOutboxError("outbox review_id is invalid")
        if _DIGEST.fullmatch(record.review_digest) is None:
            raise TradeReceiptReviewOutboxError(
                "outbox review_digest is invalid"
            )
        if not record.review_b64u or not record.receipt_b64u or not record.order_b64u:
            raise TradeReceiptReviewOutboxError(
                "outbox artifact encoding is missing"
            )
        policy_encodings = (
            record.verifier_policy_b64u,
            record.adapter_policy_b64u,
        )
        if record.protocol_version == "1" and any(policy_encodings):
            raise TradeReceiptReviewOutboxError(
                "v1 outbox record contains policy snapshots"
            )
        if record.protocol_version in {"2", "3"} and not all(
            policy_encodings
        ):
            raise TradeReceiptReviewOutboxError(
                "v2/v3 outbox record is missing policy snapshots"
            )
        if record.status not in _STATUSES:
            raise TradeReceiptReviewOutboxError("outbox status is invalid")
        if record.event_type not in _EVENT_TYPES:
            raise TradeReceiptReviewOutboxError("outbox event_type is invalid")
        if record.event_id and _EVENT_ID.fullmatch(record.event_id) is None:
            raise TradeReceiptReviewOutboxError("outbox event_id is invalid")
        for field in (
            "created_at_ms",
            "updated_at_ms",
            "first_observed_at_ms",
            "attempts",
        ):
            _safe_int(getattr(record, field), label=field)
        if record.protocol_version == "1" and record.first_observed_at_ms != 0:
            raise TradeReceiptReviewOutboxError(
                "v1 outbox record contains an observation time"
            )
        if record.updated_at_ms < record.created_at_ms:
            raise TradeReceiptReviewOutboxError(
                "outbox time moved backwards"
            )
        if record.last_error not in _ERROR_CODES:
            raise TradeReceiptReviewOutboxError(
                "outbox last_error is invalid"
            )
        if record.status == "prepared" and (
            record.event_type or record.event_id
        ):
            raise TradeReceiptReviewOutboxError(
                "prepared outbox record contains event state"
            )
        if record.status in {"reviewed", "conflicted"} and (
            not record.event_type or record.event_id
        ):
            raise TradeReceiptReviewOutboxError(
                "unanchored outbox event state is inconsistent"
            )
        expected_event_type = {
            "reviewed": "trade.receipt.reviewed",
            "conflicted": "trade.receipt.review.conflicted",
        }.get(record.status)
        if (
            expected_event_type is not None
            and record.event_type != expected_event_type
        ):
            raise TradeReceiptReviewOutboxError(
                "outbox status does not match event_type"
            )
        if record.status == "anchored" and (
            not record.event_type or not record.event_id
        ):
            raise TradeReceiptReviewOutboxError(
                "anchored outbox record has no event binding"
            )
        if record.status == "anchored" and record.last_error:
            raise TradeReceiptReviewOutboxError(
                "anchored outbox record must clear last_error"
            )
        return record

    def to_dict(self) -> dict[str, Any]:
        document = {
            field: getattr(self, field)
            for field in (
                "kind",
                "protocol_version",
                "review_id",
                "review_digest",
                "review_b64u",
                "receipt_b64u",
                "order_b64u",
                "status",
                "event_type",
                "event_id",
                "created_at_ms",
                "updated_at_ms",
                "attempts",
                "last_error",
            )
        }
        if self.protocol_version in {"2", "3"}:
            document.update(
                {
                    "verifier_policy_b64u": self.verifier_policy_b64u,
                    "adapter_policy_b64u": self.adapter_policy_b64u,
                }
            )
        if self.protocol_version == "3":
            document["first_observed_at_ms"] = self.first_observed_at_ms
        return document

    @staticmethod
    def _decode(value: str, *, label: str) -> bytes:
        try:
            raw = b64u_decode(value)
        except (TypeError, ValueError) as exc:
            raise TradeReceiptReviewOutboxError(
                f"outbox {label} encoding is invalid"
            ) from exc
        if b64u_encode(raw) != value:
            raise TradeReceiptReviewOutboxError(
                f"outbox {label} encoding is not canonical"
            )
        return raw

    @property
    def artifacts(
        self,
    ) -> tuple[TradeReceiptReview, TradeExecutionReceipt, TradeOrder]:
        try:
            order = TradeOrder.from_json(
                self._decode(self.order_b64u, label="Order")
            )
            receipt = TradeExecutionReceipt.from_json(
                self._decode(self.receipt_b64u, label="Receipt"),
                order=order,
            )
            review = TradeReceiptReview.from_json(
                self._decode(self.review_b64u, label="Review"),
                receipt=receipt,
                order=order,
            )
        except (TypeError, ValueError) as exc:
            raise TradeReceiptReviewOutboxError(
                "outbox contains invalid signed artifacts"
            ) from exc
        if review.review_id != self.review_id:
            raise TradeReceiptReviewOutboxError(
                "outbox review_id binding mismatch"
            )
        if (
            receipt_review_digest(
                review,
                receipt=receipt,
                order=order,
            )
            != self.review_digest
        ):
            raise TradeReceiptReviewOutboxError(
                "outbox review digest binding mismatch"
            )
        return review, receipt, order

    @property
    def policy_snapshots(
        self,
    ) -> tuple[RuleResolutionPolicy, TradeExecutionAdapterPolicy] | None:
        if self.protocol_version == "1":
            return None
        try:
            verifier_document = _strict_json(
                self._decode(
                    self.verifier_policy_b64u,
                    label="Verifier Policy",
                )
            )
            adapter_document = _strict_json(
                self._decode(
                    self.adapter_policy_b64u,
                    label="Adapter Policy",
                )
            )
            verifier_policy = RuleResolutionPolicy.from_dict(
                verifier_document
            )
            adapter_policy = TradeExecutionAdapterPolicy.from_dict(
                adapter_document
            )
        except (
            TradeReceiptReviewOutboxError,
            TypeError,
            ValueError,
        ) as exc:
            raise TradeReceiptReviewOutboxError(
                "outbox contains invalid policy snapshots"
            ) from exc
        review, _receipt, order = self.artifacts
        review_document = review.to_dict()
        if verifier_policy.digest != review_document["verifier_policy_digest"]:
            raise TradeReceiptReviewOutboxError(
                "outbox Verifier Policy digest binding mismatch"
            )
        if adapter_policy.digest != review_document["adapter_policy_digest"]:
            raise TradeReceiptReviewOutboxError(
                "outbox Adapter Policy digest binding mismatch"
            )
        order_document = order.to_dict()
        policy_document = (
            order_document["snapshot"]["proposal"]["taker_policy"]
            if review_document["reviewer_role"] == "taker"
            else order_document["snapshot"]["acceptance"]["maker_policy"]
        )
        order_policy = RuleResolutionPolicy.from_dict(policy_document)
        if verifier_policy.canonical_bytes != order_policy.canonical_bytes:
            raise TradeReceiptReviewOutboxError(
                "outbox Verifier Policy is outside the reviewer Order snapshot"
            )
        return verifier_policy, adapter_policy


@dataclass(frozen=True)
class _TradeReceiptReviewOutboxUsage:
    record_paths: tuple[Path, ...]
    records: tuple[TradeReceiptReviewOutboxRecord, ...]
    record_bytes: int
    temporary_count: int
    temporary_bytes: int

    @property
    def total_count(self) -> int:
        return len(self.record_paths) + self.temporary_count

    @property
    def total_bytes(self) -> int:
        return self.record_bytes + self.temporary_bytes


class TradeReceiptReviewOutbox:
    """Bounded records durably prepared before Review CAS publication."""

    def __init__(
        self,
        root: str | Path,
        *,
        max_records: int = DEFAULT_MAX_RECEIPT_REVIEW_OUTBOX_RECORDS,
        max_bytes: int = DEFAULT_MAX_RECEIPT_REVIEW_OUTBOX_BYTES,
        lock_timeout: float = 30.0,
    ) -> None:
        if (
            isinstance(max_records, bool)
            or not isinstance(max_records, int)
            or max_records <= 0
        ):
            raise ValueError("max_records must be a positive integer")
        if (
            isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or max_bytes <= 0
        ):
            raise ValueError("max_bytes must be a positive integer")
        if (
            isinstance(lock_timeout, bool)
            or not isinstance(lock_timeout, (int, float))
            or not math.isfinite(lock_timeout)
            or lock_timeout <= 0
        ):
            raise ValueError("lock_timeout must be a finite positive number")
        self.workspace_root = Path(root)
        self.root = (
            self.workspace_root / "trade" / "receipt_review_outbox_v1"
        )
        self.lock_path = self.root / ".locks" / "reconcile"
        self.max_records = max_records
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
            raise TradeReceiptReviewOutboxError(
                "Receipt Review outbox path escapes workspace"
            ) from exc
        current = self.workspace_root
        for part in ("", *relative.parts):
            current = current if not part else current / part
            if self._is_linklike(current):
                raise TradeReceiptReviewOutboxError(
                    "Receipt Review outbox must not contain links"
                )

    def _path(self, review_digest: str) -> Path:
        if (
            not isinstance(review_digest, str)
            or _DIGEST.fullmatch(review_digest) is None
        ):
            raise TradeReceiptReviewOutboxError(
                "review_digest is invalid"
            )
        return self.root / (
            review_digest.removeprefix("sha256:") + ".json"
        )

    def acquire_reconcile(self) -> InterProcessLock:
        self._assert_path(self.lock_path.parent)
        try:
            self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise TradeReceiptReviewOutboxError(
                f"unable to create outbox lock directory: {exc}"
            ) from exc
        self._assert_path(self.lock_path.parent)
        self._assert_path(Path(f"{self.lock_path}.lock"))
        return InterProcessLock(self.lock_path, timeout=self.lock_timeout)

    def _read(self, path: Path) -> TradeReceiptReviewOutboxRecord:
        self._assert_path(path)
        try:
            size = path.stat().st_size
            if size > MAX_RECEIPT_REVIEW_OUTBOX_RECORD_BYTES:
                raise TradeReceiptReviewOutboxCapacity(
                    "outbox record exceeds byte limit"
                )
            raw = path.read_bytes()
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise TradeReceiptReviewOutboxError(
                f"unable to read outbox record: {exc}"
            ) from exc
        if len(raw) != size:
            raise TradeReceiptReviewOutboxError(
                "outbox record changed while being read"
            )
        record = TradeReceiptReviewOutboxRecord.from_dict(_strict_json(raw))
        if record.protocol_version in {"2", "3"}:
            _ = record.policy_snapshots
        else:
            _ = record.artifacts
        if raw != canonical_json(record.to_dict()):
            raise TradeReceiptReviewOutboxError(
                "outbox record is not canonical JSON"
            )
        expected = self._path(record.review_digest)
        if path.name != expected.name:
            raise TradeReceiptReviewOutboxError(
                "outbox record does not match its filename"
            )
        return record

    def _write(
        self,
        path: Path,
        record: TradeReceiptReviewOutboxRecord,
    ) -> None:
        payload = canonical_json(record.to_dict())
        if len(payload) > MAX_RECEIPT_REVIEW_OUTBOX_RECORD_BYTES:
            raise TradeReceiptReviewOutboxCapacity(
                "outbox record exceeds byte limit"
            )
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
                directory = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        except OSError as exc:
            raise TradeReceiptReviewOutboxError(
                f"unable to persist outbox record: {exc}"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    def _inventory_locked(self) -> _TradeReceiptReviewOutboxUsage:
        if not self.root.exists():
            return _TradeReceiptReviewOutboxUsage((), (), 0, 0, 0)
        record_paths: list[Path] = []
        record_bytes = 0
        temporary_count = 0
        temporary_bytes = 0
        for path in sorted(self.root.rglob("*")):
            relative = path.relative_to(self.root)
            if self._is_linklike(path):
                raise TradeReceiptReviewOutboxError(
                    "Receipt Review outbox must not contain links"
                )
            if relative.parts and relative.parts[0] == ".locks":
                continue
            if path.is_dir():
                raise TradeReceiptReviewOutboxError(
                    "outbox contains an unexpected directory"
                )
            size = path.stat().st_size
            if _TEMPORARY_FILE.fullmatch(path.name):
                if size > MAX_RECEIPT_REVIEW_OUTBOX_RECORD_BYTES:
                    raise TradeReceiptReviewOutboxCapacity(
                        "outbox temporary file exceeds byte limit"
                    )
                temporary_count += 1
                temporary_bytes += size
                continue
            if _RECORD_FILE.fullmatch(path.name) is None:
                raise TradeReceiptReviewOutboxError(
                    "outbox contains an unknown file"
                )
            if size > MAX_RECEIPT_REVIEW_OUTBOX_RECORD_BYTES:
                raise TradeReceiptReviewOutboxCapacity(
                    "outbox record exceeds byte limit"
                )
            record_paths.append(path)
            record_bytes += size
        usage = _TradeReceiptReviewOutboxUsage(
            tuple(record_paths),
            (),
            record_bytes,
            temporary_count,
            temporary_bytes,
        )
        if usage.total_count > self.max_records:
            raise TradeReceiptReviewOutboxCapacity(
                "existing outbox exceeds max_records"
            )
        if usage.total_bytes > self.max_bytes:
            raise TradeReceiptReviewOutboxCapacity(
                "existing outbox exceeds max_bytes"
            )
        return usage

    def _records_locked(self) -> _TradeReceiptReviewOutboxUsage:
        inventory = self._inventory_locked()
        records = tuple(self._read(path) for path in inventory.record_paths)
        return _TradeReceiptReviewOutboxUsage(
            inventory.record_paths,
            records,
            sum(len(canonical_json(record.to_dict())) for record in records),
            inventory.temporary_count,
            inventory.temporary_bytes,
        )

    def _get_locked(
        self,
        review_digest: str,
    ) -> TradeReceiptReviewOutboxRecord | None:
        path = self._path(review_digest)
        return self._read(path) if path.exists() else None

    def _prepare(
        self,
        review: TradeReceiptReview,
        *,
        receipt: TradeExecutionReceipt,
        order: TradeOrder,
        now_ms: int,
        verifier_policy: RuleResolutionPolicy | None = None,
        adapter_policy: TradeExecutionAdapterPolicy | None = None,
        allow_legacy_without_policy_snapshots: bool = False,
    ) -> tuple[TradeReceiptReviewOutboxRecord, bool]:
        if not isinstance(allow_legacy_without_policy_snapshots, bool):
            raise TypeError(
                "allow_legacy_without_policy_snapshots must be boolean"
            )
        if (verifier_policy is None) != (adapter_policy is None):
            raise TradeReceiptReviewOutboxError(
                "both Receipt Review policy snapshots are required together"
            )
        if (
            verifier_policy is None
            and not allow_legacy_without_policy_snapshots
        ):
            raise TradeReceiptReviewOutboxError(
                "Receipt Review policy snapshots are required for v2 records"
            )
        if (
            verifier_policy is not None
            and allow_legacy_without_policy_snapshots
        ):
            raise TradeReceiptReviewOutboxError(
                "legacy Receipt Review records must omit policy snapshots"
            )
        moment = _safe_int(now_ms, label="now_ms")
        verified_order = TradeOrder.from_json(order.canonical_bytes)
        verified_receipt = TradeExecutionReceipt.from_json(
            receipt.canonical_bytes,
            order=verified_order,
        )
        verified_review = TradeReceiptReview.from_json(
            review.canonical_bytes,
            receipt=verified_receipt,
            order=verified_order,
        )
        digest = receipt_review_digest(
            verified_review,
            receipt=verified_receipt,
            order=verified_order,
        )
        verified_verifier_policy = (
            RuleResolutionPolicy.from_dict(
                json.loads(verifier_policy.canonical_bytes)
            )
            if verifier_policy is not None
            else None
        )
        verified_adapter_policy = (
            TradeExecutionAdapterPolicy.from_dict(
                json.loads(adapter_policy.canonical_bytes)
            )
            if adapter_policy is not None
            else None
        )
        version = (
            RECEIPT_REVIEW_OUTBOX_PROTOCOL_VERSION
            if verified_verifier_policy is not None
            else "1"
        )
        wanted = TradeReceiptReviewOutboxRecord(
            kind=RECEIPT_REVIEW_OUTBOX_KIND,
            protocol_version=version,
            review_id=verified_review.review_id,
            review_digest=digest,
            review_b64u=b64u_encode(verified_review.canonical_bytes),
            receipt_b64u=b64u_encode(verified_receipt.canonical_bytes),
            order_b64u=b64u_encode(verified_order.canonical_bytes),
            verifier_policy_b64u=(
                b64u_encode(verified_verifier_policy.canonical_bytes)
                if verified_verifier_policy is not None
                else ""
            ),
            adapter_policy_b64u=(
                b64u_encode(verified_adapter_policy.canonical_bytes)
                if verified_adapter_policy is not None
                else ""
            ),
            status="prepared",
            event_type="",
            event_id="",
            created_at_ms=moment,
            updated_at_ms=moment,
            first_observed_at_ms=moment if version != "1" else 0,
            attempts=0,
            last_error="",
        )
        if version == RECEIPT_REVIEW_OUTBOX_PROTOCOL_VERSION:
            _ = wanted.policy_snapshots
        try:
            with self.acquire_reconcile():
                usage = self._inventory_locked()
                existing = self._get_locked(digest)
                if existing is not None:
                    existing_review, existing_receipt, existing_order = (
                        existing.artifacts
                    )
                    if (
                        existing_review.canonical_bytes
                        != verified_review.canonical_bytes
                        or existing_receipt.canonical_bytes
                        != verified_receipt.canonical_bytes
                        or existing_order.canonical_bytes
                        != verified_order.canonical_bytes
                    ):
                        raise TradeReceiptReviewOutboxError(
                            "outbox digest has different signed artifacts"
                        )
                    if verified_verifier_policy is not None:
                        if existing.protocol_version == "1":
                            upgraded = TradeReceiptReviewOutboxRecord.from_dict(
                                {
                                    **existing.to_dict(),
                                    "protocol_version": (
                                        RECEIPT_REVIEW_OUTBOX_PROTOCOL_VERSION
                                    ),
                                    "verifier_policy_b64u": (
                                        wanted.verifier_policy_b64u
                                    ),
                                    "adapter_policy_b64u": (
                                        wanted.adapter_policy_b64u
                                    ),
                                    "first_observed_at_ms": moment,
                                    "updated_at_ms": max(
                                        existing.updated_at_ms,
                                        moment,
                                    ),
                                }
                            )
                            _ = upgraded.policy_snapshots
                            upgraded_size = len(
                                canonical_json(upgraded.to_dict())
                            )
                            existing_size = len(
                                canonical_json(existing.to_dict())
                            )
                            if (
                                usage.total_bytes
                                - existing_size
                                + upgraded_size
                                > self.max_bytes
                            ):
                                raise TradeReceiptReviewOutboxCapacity(
                                    "max_bytes exceeded"
                                )
                            self._write(self._path(digest), upgraded)
                            return upgraded, False
                        existing_policies = existing.policy_snapshots
                        if existing_policies is None or any(
                            left.canonical_bytes != right.canonical_bytes
                            for left, right in zip(
                                existing_policies,
                                (
                                    verified_verifier_policy,
                                    verified_adapter_policy,
                                ),
                                strict=True,
                            )
                        ):
                            raise TradeReceiptReviewOutboxError(
                                "outbox digest has different policy snapshots"
                            )
                        if existing.protocol_version == "2":
                            upgraded = TradeReceiptReviewOutboxRecord.from_dict(
                                {
                                    **existing.to_dict(),
                                    "protocol_version": (
                                        RECEIPT_REVIEW_OUTBOX_PROTOCOL_VERSION
                                    ),
                                    "first_observed_at_ms": (
                                        existing.first_observed_at_ms
                                    ),
                                }
                            )
                            upgraded_size = len(
                                canonical_json(upgraded.to_dict())
                            )
                            existing_size = len(
                                canonical_json(existing.to_dict())
                            )
                            if (
                                usage.total_bytes
                                - existing_size
                                + upgraded_size
                                > self.max_bytes
                            ):
                                raise TradeReceiptReviewOutboxCapacity(
                                    "max_bytes exceeded"
                                )
                            self._write(self._path(digest), upgraded)
                            return upgraded, False
                    return existing, False
                payload_size = len(canonical_json(wanted.to_dict()))
                if usage.total_count + 1 > self.max_records:
                    raise TradeReceiptReviewOutboxCapacity(
                        "max_records exceeded"
                    )
                if usage.total_bytes + payload_size > self.max_bytes:
                    raise TradeReceiptReviewOutboxCapacity(
                        "max_bytes exceeded"
                    )
                self._write(self._path(digest), wanted)
                return wanted, True
        except TimeoutError as exc:
            raise TradeReceiptReviewOutboxBusy(
                "Receipt Review reconciliation is busy"
            ) from exc

    def prepare(
        self,
        review: TradeReceiptReview,
        *,
        receipt: TradeExecutionReceipt,
        order: TradeOrder,
        now_ms: int,
        verifier_policy: RuleResolutionPolicy,
        adapter_policy: TradeExecutionAdapterPolicy,
    ) -> tuple[TradeReceiptReviewOutboxRecord, bool]:
        """Create or upgrade a v2 record with both policy snapshots."""

        return self._prepare(
            review,
            receipt=receipt,
            order=order,
            now_ms=now_ms,
            verifier_policy=verifier_policy,
            adapter_policy=adapter_policy,
        )

    def prepare_legacy(
        self,
        review: TradeReceiptReview,
        *,
        receipt: TradeExecutionReceipt,
        order: TradeOrder,
        now_ms: int,
    ) -> tuple[TradeReceiptReviewOutboxRecord, bool]:
        """Create an explicit v1 record only for migration and recovery."""

        return self._prepare(
            review,
            receipt=receipt,
            order=order,
            now_ms=now_ms,
            allow_legacy_without_policy_snapshots=True,
        )

    def get_policy_snapshots(
        self,
        review_digest: str,
    ) -> tuple[RuleResolutionPolicy, TradeExecutionAdapterPolicy] | None:
        try:
            with self.acquire_reconcile():
                record = self._get_locked(review_digest)
                return None if record is None else record.policy_snapshots
        except TimeoutError as exc:
            raise TradeReceiptReviewOutboxBusy(
                "Receipt Review reconciliation is busy"
            ) from exc

    def observed_at_ms(self, review_digest: str) -> int:
        """Return the durable first v2 observation time for one Review."""

        try:
            with self.acquire_reconcile():
                record = self._get_locked(review_digest)
                if record is None:
                    raise TradeReceiptReviewOutboxError(
                        "Receipt Review outbox record is missing"
                    )
                if record.protocol_version == "1":
                    raise TradeReceiptReviewOutboxError(
                        "legacy Receipt Review has no observation time"
                    )
                return record.first_observed_at_ms
        except TimeoutError as exc:
            raise TradeReceiptReviewOutboxBusy(
                "Receipt Review reconciliation is busy"
            ) from exc

    def _transition_locked(
        self,
        review_digest: str,
        *,
        expected: frozenset[str],
        status: str,
        now_ms: int,
        event_type: str,
        event_id: str = "",
        last_error: str = "",
        increment_attempts: bool = False,
    ) -> TradeReceiptReviewOutboxRecord:
        current = self._get_locked(review_digest)
        if current is None or current.status not in expected:
            raise TradeReceiptReviewOutboxError(
                "outbox compare-and-set status mismatch"
            )
        updated = TradeReceiptReviewOutboxRecord.from_dict(
            {
                **current.to_dict(),
                "status": status,
                "event_type": event_type,
                "event_id": event_id,
                "updated_at_ms": max(
                    _safe_int(now_ms, label="now_ms"),
                    current.updated_at_ms,
                ),
                "attempts": current.attempts
                + (1 if increment_attempts else 0),
                "last_error": last_error,
            }
        )
        self._write(self._path(review_digest), updated)
        return updated

    def pending(
        self,
        *,
        limit: int = 100,
        after_digest: str | None = None,
    ) -> tuple[tuple[TradeReceiptReviewOutboxRecord, ...], bool]:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError("limit must be a positive integer")
        if after_digest is not None:
            self._path(after_digest)
        try:
            with self.acquire_reconcile():
                records = sorted(
                    self._records_locked().records,
                    key=lambda record: record.review_digest,
                )
                eligible = [
                    record
                    for record in records
                    if (
                        after_digest is None
                        or record.review_digest > after_digest
                    )
                ]
                return tuple(eligible[:limit]), len(eligible) > limit
        except TimeoutError as exc:
            raise TradeReceiptReviewOutboxBusy(
                "Receipt Review reconciliation is busy"
            ) from exc


__all__ = [
    "DEFAULT_MAX_RECEIPT_REVIEW_OUTBOX_BYTES",
    "DEFAULT_MAX_RECEIPT_REVIEW_OUTBOX_RECORDS",
    "MAX_RECEIPT_REVIEW_OUTBOX_RECORD_BYTES",
    "RECEIPT_REVIEW_OUTBOX_KIND",
    "RECEIPT_REVIEW_OUTBOX_PROTOCOL_VERSION",
    "TradeReceiptReviewOutbox",
    "TradeReceiptReviewOutboxBusy",
    "TradeReceiptReviewOutboxCapacity",
    "TradeReceiptReviewOutboxError",
    "TradeReceiptReviewOutboxRecord",
]
