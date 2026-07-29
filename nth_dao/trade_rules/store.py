"""Append-only local storage and lifecycle projection for Trade Offer v2."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from nth_dao.trade_rules.canonical import MAX_TRADE_JSON_BYTES
from nth_dao.canonical_json import canonical_json
from nth_dao.trade_rules.offer import (
    OfferRejected,
    TradeOffer,
    evaluate_offer,
    offer_digest,
    verify_offer_successor,
)
from nth_dao.util.io import InterProcessLock
from nth_dao.util.jsonl_safe import LOCK_TIMEOUT_PATIENT

DEFAULT_MAX_RECORDS = 100_000
DEFAULT_MAX_STORE_BYTES = 64 * 1024 * 1024
MAX_STORED_LINE_BYTES = (MAX_TRADE_JSON_BYTES * 2) + 1
OFFER_LOG_ENTRY_KIND = "org.nthdao.trade.offer-log-entry"
OFFER_LOG_VERSION = "1.0"
OFFER_LOG_CHECKPOINT_KIND = "org.nthdao.trade.offer-log-checkpoint"
_ENTRY_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "seq",
        "previous_entry_hash",
        "offer_digest",
        "offer",
        "received_at_ms",
        "source_kind",
        "source_id",
        "entry_hash",
    }
)
_ENTRY_BODY_FIELDS = _ENTRY_FIELDS - {"entry_hash"}
_CHECKPOINT_FIELDS = frozenset(
    {"kind", "protocol_version", "seq", "entry_hash"}
)
_DIGEST_PREFIX = "sha256:"
_GENESIS_HASH = "sha256:" + ("0" * 64)
_SOURCE_KIND = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
_MAX_RECEIVED_AT_MS = (1 << 63) - 1


class OfferStoreError(RuntimeError):
    """Raised when the offer log cannot provide a trustworthy projection."""


class OfferStoreCapacityError(OfferStoreError):
    """Raised when a bounded offer log has reached its configured capacity."""


class OfferStoreCorruptionError(OfferStoreError):
    """Raised when any stored line cannot be verified exactly."""


class OfferStoreValidationError(OfferStoreError):
    """Raised when a submitted offer is not a verified protocol document."""


class OfferStoreBusyError(OfferStoreError):
    """Raised when another process holds the offer-store transaction lock."""


class OfferStoreCryptoUnavailableError(OfferStoreError):
    """Raised when signed offers cannot be verified in this runtime."""


@dataclass(frozen=True)
class OfferRecord:
    seq: int
    digest: str
    offer: TradeOffer
    entry_hash: str
    received_at_ms: int
    source_kind: str
    source_id: str


@dataclass(frozen=True)
class OfferPollResult:
    records: tuple[OfferRecord, ...]
    cursor: int


@dataclass(frozen=True)
class OfferChainView:
    publisher_did: str
    offer_id: str
    status: str
    all_digests: tuple[str, ...]
    root_digests: tuple[str, ...]
    canonical_digests: tuple[str, ...]
    canonical_head_digest: str | None
    fork_digests: tuple[str, ...]
    orphan_digests: tuple[str, ...]
    invalid_digests: tuple[str, ...]

    @property
    def is_canonical(self) -> bool:
        return self.status == "canonical"


@dataclass(frozen=True)
class OfferPublishResult:
    seq: int
    digest: str
    appended: bool
    classification: str
    chain: OfferChainView
    entry_hash: str
    received_at_ms: int
    source_kind: str
    source_id: str


class OfferStore:
    """Persist verified offers without collapsing revisions or forks.

    The JSONL log is the sole source of truth. Every signature-valid offer is
    retained exactly once by content digest. Lifecycle state is a deterministic
    projection over the signed revision graph, never a last-write-wins update.
    """

    def __init__(
        self,
        root: str | Path,
        *,
        max_records: int = DEFAULT_MAX_RECORDS,
        max_bytes: int = DEFAULT_MAX_STORE_BYTES,
        lock_timeout: float = LOCK_TIMEOUT_PATIENT,
    ) -> None:
        if isinstance(max_records, bool) or not isinstance(max_records, int):
            raise TypeError("max_records must be an integer")
        if max_records < 1:
            raise ValueError("max_records must be positive")
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
            raise TypeError("max_bytes must be an integer")
        if max_bytes < MAX_STORED_LINE_BYTES:
            raise ValueError(
                f"max_bytes must be at least {MAX_STORED_LINE_BYTES}"
            )
        if (
            isinstance(lock_timeout, bool)
            or not isinstance(lock_timeout, (int, float))
            or not math.isfinite(lock_timeout)
            or lock_timeout <= 0
        ):
            raise ValueError("lock_timeout must be a finite positive number")
        self.root = Path(root) / "trade" / "offers"
        self.log_path = self.root / "offers.jsonl"
        self.checkpoint_path = self.root / "head.json"
        self.lock_path = self.root / ".locks" / self.log_path.name
        self.max_records = max_records
        self.max_bytes = max_bytes
        self.lock_timeout = float(lock_timeout)
        self._cache_fingerprint: tuple[Any, ...] | None = None
        self._cache_records: tuple[OfferRecord, ...] = ()
        self._cache_views_head: str | None = None
        self._cache_views: tuple[OfferChainView, ...] = ()
        self._cache_by_digest_head: str | None = None
        self._cache_by_digest: dict[str, OfferRecord] = {}

    @staticmethod
    def _verified_offer(value: TradeOffer | dict[str, Any]) -> TradeOffer:
        try:
            if isinstance(value, TradeOffer):
                return TradeOffer.from_json(value.canonical_bytes)
            if isinstance(value, dict):
                return TradeOffer.from_dict(value)
        except OfferRejected as exc:
            if str(exc) == "crypto unavailable":
                raise OfferStoreCryptoUnavailableError(
                    "trade signature verification requires PyNaCl"
                ) from exc
            raise OfferStoreValidationError(f"offer rejected: {exc}") from exc
        except (TypeError, ValueError) as exc:
            raise OfferStoreValidationError(f"offer rejected: {exc}") from exc
        raise TypeError("offer must be a TradeOffer or object")

    def _read_line(self, stream: Any) -> tuple[bytes, bool]:
        raw = stream.readline(MAX_STORED_LINE_BYTES + 1)
        if not raw:
            return b"", False
        oversized = len(raw) > MAX_STORED_LINE_BYTES
        if oversized and not raw.endswith(b"\n"):
            while True:
                remainder = stream.readline(MAX_STORED_LINE_BYTES + 1)
                if not remainder or remainder.endswith(b"\n"):
                    break
        return raw, oversized

    def _storage_fingerprint(self) -> tuple[Any, ...]:
        values: list[Any] = []
        for path in (self.log_path, self.checkpoint_path):
            try:
                stat = path.stat()
                values.extend(
                    (
                        True,
                        stat.st_size,
                        stat.st_mtime_ns,
                        stat.st_ctime_ns,
                        stat.st_ino,
                    )
                )
            except FileNotFoundError:
                values.extend((False, 0, 0, 0, 0))
            except OSError as exc:
                raise OfferStoreError(
                    f"unable to stat trade storage: {exc}"
                ) from exc
        return tuple(values)

    def _remember_records(self, records: list[OfferRecord]) -> None:
        self._cache_records = tuple(records)
        self._cache_fingerprint = self._storage_fingerprint()
        head = records[-1].entry_hash if records else _GENESIS_HASH
        if self._cache_views_head != head:
            self._cache_views_head = None
            self._cache_views = ()
        if self._cache_by_digest_head != head:
            self._cache_by_digest_head = None
            self._cache_by_digest = {}

    @staticmethod
    def _is_digest(value: Any) -> bool:
        return (
            isinstance(value, str)
            and len(value) == 71
            and value.startswith(_DIGEST_PREFIX)
            and all(character in "0123456789abcdef" for character in value[7:])
        )

    @staticmethod
    def _is_source_id(value: Any) -> bool:
        if not isinstance(value, str):
            return False
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError:
            return False
        return (
            len(encoded) <= 1_024
            and not any(ord(character) < 0x20 for character in value)
        )

    @staticmethod
    def _strict_json(raw: bytes, *, label: str) -> dict[str, Any]:
        def object_pairs(pairs):
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(f"{label} contains duplicate key {key!r}")
                result[key] = value
            return result

        def reject_float(_value):
            raise ValueError(f"{label} contains a non-integer number")

        def reject_constant(_value):
            raise ValueError(f"{label} contains a non-finite number")

        try:
            value = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=object_pairs,
                parse_float=reject_float,
                parse_constant=reject_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise OfferStoreCorruptionError(f"{label} is not strict JSON") from exc
        if not isinstance(value, dict):
            raise OfferStoreCorruptionError(f"{label} must be an object")
        return value

    @staticmethod
    def _entry_hash(body: dict[str, Any]) -> str:
        return _DIGEST_PREFIX + hashlib.sha256(canonical_json(body)).hexdigest()

    @classmethod
    def _entry_document(
        cls,
        *,
        seq: int,
        previous_entry_hash: str,
        offer: TradeOffer,
        received_at_ms: int,
        source_kind: str,
        source_id: str,
    ) -> dict[str, Any]:
        body = {
            "kind": OFFER_LOG_ENTRY_KIND,
            "protocol_version": OFFER_LOG_VERSION,
            "seq": seq,
            "previous_entry_hash": previous_entry_hash,
            "offer_digest": offer_digest(offer),
            "offer": offer.to_dict(),
            "received_at_ms": received_at_ms,
            "source_kind": source_kind,
            "source_id": source_id,
        }
        return {**body, "entry_hash": cls._entry_hash(body)}

    @classmethod
    def _parse_entry(
        cls,
        raw: bytes,
        *,
        expected_seq: int,
        expected_previous_hash: str,
    ) -> OfferRecord:
        document = cls._strict_json(raw, label=f"offer log line {expected_seq}")
        if set(document) != _ENTRY_FIELDS:
            raise OfferStoreCorruptionError(
                f"offer log line {expected_seq} has invalid envelope fields"
            )
        if (
            document["kind"] != OFFER_LOG_ENTRY_KIND
            or document["protocol_version"] != OFFER_LOG_VERSION
            or type(document["seq"]) is not int
            or document["seq"] != expected_seq
        ):
            raise OfferStoreCorruptionError(
                f"offer log line {expected_seq} has invalid sequence metadata"
            )
        if document["previous_entry_hash"] != expected_previous_hash:
            raise OfferStoreCorruptionError(
                f"offer log line {expected_seq} breaks the entry hash chain"
            )
        if not cls._is_digest(document["offer_digest"]):
            raise OfferStoreCorruptionError(
                f"offer log line {expected_seq} has invalid offer_digest"
            )
        if not cls._is_digest(document["entry_hash"]):
            raise OfferStoreCorruptionError(
                f"offer log line {expected_seq} has invalid entry_hash"
            )
        if (
            type(document["received_at_ms"]) is not int
            or document["received_at_ms"] < 0
            or document["received_at_ms"] > _MAX_RECEIVED_AT_MS
            or not isinstance(document["source_kind"], str)
            or _SOURCE_KIND.fullmatch(document["source_kind"]) is None
            or not cls._is_source_id(document["source_id"])
        ):
            raise OfferStoreCorruptionError(
                f"offer log line {expected_seq} has invalid provenance"
            )
        body = {
            key: document[key]
            for key in _ENTRY_BODY_FIELDS
        }
        if cls._entry_hash(body) != document["entry_hash"]:
            raise OfferStoreCorruptionError(
                f"offer log line {expected_seq} entry_hash mismatch"
            )
        try:
            offer = TradeOffer.from_dict(document["offer"])
        except OfferRejected as exc:
            if str(exc) == "crypto unavailable":
                raise OfferStoreCryptoUnavailableError(
                    "trade signature verification requires PyNaCl"
                ) from exc
            raise OfferStoreCorruptionError(
                f"offer log line {expected_seq} contains an invalid offer: {exc}"
            ) from exc
        except (TypeError, ValueError) as exc:
            raise OfferStoreCorruptionError(
                f"offer log line {expected_seq} contains an invalid offer"
            ) from exc
        digest = offer_digest(offer)
        if digest != document["offer_digest"]:
            raise OfferStoreCorruptionError(
                f"offer log line {expected_seq} offer_digest mismatch"
            )
        return OfferRecord(
            seq=expected_seq,
            digest=digest,
            offer=offer,
            entry_hash=document["entry_hash"],
            received_at_ms=document["received_at_ms"],
            source_kind=document["source_kind"],
            source_id=document["source_id"],
        )

    def _scan_locked(self) -> tuple[list[OfferRecord], int]:
        fingerprint = self._storage_fingerprint()
        if (
            self._cache_fingerprint == fingerprint
            and self._cache_records
        ):
            records = list(self._cache_records)
            return records, records[-1].seq
        if not self.log_path.exists():
            self._verify_checkpoint_locked([])
            self._cache_records = ()
            self._cache_fingerprint = self._storage_fingerprint()
            return [], -1
        try:
            if self.log_path.stat().st_size > self.max_bytes:
                raise OfferStoreCapacityError(
                    "offer log exceeds configured max_bytes"
                )
        except OSError as exc:
            raise OfferStoreError(f"unable to stat offer log: {exc}") from exc
        records: list[OfferRecord] = []
        seen_digests: set[str] = set()
        seq = -1
        previous_entry_hash = _GENESIS_HASH
        try:
            with self.log_path.open("rb") as stream:
                while True:
                    raw, oversized = self._read_line(stream)
                    if not raw:
                        break
                    seq += 1
                    if seq >= self.max_records:
                        raise OfferStoreCapacityError(
                            "offer log exceeds configured max_records"
                        )
                    if oversized:
                        raise OfferStoreCorruptionError(
                            f"offer log line {seq} exceeds the size limit"
                        )
                    payload = raw.rstrip(b"\r\n")
                    if not payload:
                        raise OfferStoreCorruptionError(
                            f"offer log line {seq} is empty"
                        )
                    record = self._parse_entry(
                        payload,
                        expected_seq=seq,
                        expected_previous_hash=previous_entry_hash,
                    )
                    if record.digest in seen_digests:
                        raise OfferStoreCorruptionError(
                            f"offer log line {seq} duplicates digest {record.digest}"
                        )
                    seen_digests.add(record.digest)
                    records.append(record)
                    previous_entry_hash = record.entry_hash
        except OSError as exc:
            raise OfferStoreError(f"unable to read offer log: {exc}") from exc
        self._verify_checkpoint_locked(records)
        self._remember_records(records)
        return records, seq

    def _checkpoint_document(
        self, *, seq: int, entry_hash: str
    ) -> dict[str, Any]:
        return {
            "kind": OFFER_LOG_CHECKPOINT_KIND,
            "protocol_version": OFFER_LOG_VERSION,
            "seq": seq,
            "entry_hash": entry_hash,
        }

    def _load_checkpoint_locked(self) -> dict[str, Any] | None:
        if not self.checkpoint_path.exists():
            return None
        try:
            raw = self.checkpoint_path.read_bytes()
        except OSError as exc:
            raise OfferStoreError(
                f"unable to read offer checkpoint: {exc}"
            ) from exc
        checkpoint = self._strict_json(raw, label="offer log checkpoint")
        if set(checkpoint) != _CHECKPOINT_FIELDS:
            raise OfferStoreCorruptionError(
                "offer log checkpoint has invalid fields"
            )
        if (
            checkpoint["kind"] != OFFER_LOG_CHECKPOINT_KIND
            or checkpoint["protocol_version"] != OFFER_LOG_VERSION
            or type(checkpoint["seq"]) is not int
            or checkpoint["seq"] < -1
            or not self._is_digest(checkpoint["entry_hash"])
        ):
            raise OfferStoreCorruptionError(
                "offer log checkpoint has invalid metadata"
            )
        if checkpoint["seq"] == -1 and checkpoint["entry_hash"] != _GENESIS_HASH:
            raise OfferStoreCorruptionError(
                "offer log genesis checkpoint is invalid"
            )
        return checkpoint

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        if os.name == "nt":
            return
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _write_checkpoint_locked(self, *, seq: int, entry_hash: str) -> None:
        document = self._checkpoint_document(seq=seq, entry_hash=entry_hash)
        payload = canonical_json(document) + b"\n"
        descriptor: int | None = None
        temporary: str | None = None
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            descriptor, temporary = tempfile.mkstemp(
                prefix=self.checkpoint_path.name + ".",
                suffix=".tmp",
                dir=str(self.root),
            )
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = None
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.checkpoint_path)
            temporary = None
            self._fsync_directory(self.root)
        except OSError as exc:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
            raise OfferStoreError(
                f"offer checkpoint durability could not be confirmed: {exc}"
            ) from exc

    def _verify_checkpoint_locked(
        self, records: list[OfferRecord]
    ) -> None:
        checkpoint = self._load_checkpoint_locked()
        if not records:
            if checkpoint is None:
                return
            if checkpoint["seq"] == -1 and checkpoint["entry_hash"] == _GENESIS_HASH:
                return
            raise OfferStoreCorruptionError(
                "offer log is missing records committed by its checkpoint"
            )
        if checkpoint is None:
            raise OfferStoreCorruptionError(
                "offer log checkpoint is missing"
            )
        checkpoint_seq = checkpoint["seq"]
        if checkpoint_seq >= len(records):
            raise OfferStoreCorruptionError(
                "offer log was truncated behind its checkpoint"
            )
        if checkpoint_seq >= 0:
            anchored = records[checkpoint_seq]
            if anchored.entry_hash != checkpoint["entry_hash"]:
                raise OfferStoreCorruptionError(
                    "offer log checkpoint does not match its anchored entry"
                )
        elif checkpoint["entry_hash"] != _GENESIS_HASH:
            raise OfferStoreCorruptionError(
                "offer log genesis checkpoint is invalid"
            )
        latest = records[-1]
        if checkpoint_seq < latest.seq:
            # A crash may occur after the append fsync and before the atomic
            # checkpoint replace. A fully valid hash-chain tail is safe to
            # roll forward; malformed or missing tails fail above.
            self._write_checkpoint_locked(
                seq=latest.seq, entry_hash=latest.entry_hash
            )

    def _read_records(self) -> tuple[list[OfferRecord], int]:
        if not self.log_path.exists() and not self.checkpoint_path.exists():
            return [], -1
        try:
            with InterProcessLock(self.lock_path, timeout=self.lock_timeout):
                return self._scan_locked()
        except TimeoutError as exc:
            raise OfferStoreBusyError("trade offer store is busy") from exc
        except OSError as exc:
            raise OfferStoreError(
                f"unable to lock the offer store: {exc}"
            ) from exc

    @staticmethod
    def _deduplicate(
        records: Iterable[OfferRecord],
    ) -> dict[str, OfferRecord]:
        by_digest: dict[str, OfferRecord] = {}
        for record in records:
            by_digest.setdefault(record.digest, record)
        return by_digest

    @classmethod
    def _project(
        cls,
        records: Iterable[OfferRecord],
        publisher_did: str,
        offer_id: str,
    ) -> OfferChainView:
        by_digest = cls._deduplicate(
            record
            for record in records
            if record.offer.publisher_did == publisher_did
            and record.offer.offer_id == offer_id
        )
        ordered_records = sorted(by_digest.values(), key=lambda item: item.seq)
        all_digests = tuple(record.digest for record in ordered_records)
        if not ordered_records:
            return OfferChainView(
                publisher_did=publisher_did,
                offer_id=offer_id,
                status="empty",
                all_digests=(),
                root_digests=(),
                canonical_digests=(),
                canonical_head_digest=None,
                fork_digests=(),
                orphan_digests=(),
                invalid_digests=(),
            )

        roots: list[str] = []
        children: dict[str, list[str]] = {}
        orphans: set[str] = set()
        invalid: set[str] = set()

        for record in ordered_records:
            document = record.offer.to_dict()
            if document["revision"] == 1:
                roots.append(record.digest)
                continue
            previous_digest = document["previous_offer_digest"]
            previous = by_digest.get(previous_digest)
            if previous is None:
                orphans.add(record.digest)
                continue
            ok, _ = verify_offer_successor(previous.offer, record.offer)
            if not ok:
                invalid.add(record.digest)
                continue
            children.setdefault(previous_digest, []).append(record.digest)

        forks: set[str] = set()
        if len(roots) > 1:
            forks.update(roots)
        for child_digests in children.values():
            if len(child_digests) > 1:
                forks.update(child_digests)
        fork_pending = list(forks)
        while fork_pending:
            digest = fork_pending.pop()
            for descendant in children.get(digest, ()):
                if descendant not in forks:
                    forks.add(descendant)
                    fork_pending.append(descendant)

        reachable: set[str] = set()
        pending = list(roots)
        while pending:
            digest = pending.pop()
            if digest in reachable:
                continue
            reachable.add(digest)
            pending.extend(children.get(digest, ()))

        for digest in by_digest:
            if digest not in reachable and digest not in invalid:
                orphans.add(digest)

        canonical_digests: tuple[str, ...] = ()
        canonical_head_digest: str | None = None
        if forks:
            status = "forked"
        elif invalid:
            status = "invalid"
        elif orphans or len(roots) != 1:
            status = "incomplete"
        else:
            chain: list[str] = []
            current = roots[0]
            while True:
                chain.append(current)
                next_digests = children.get(current, ())
                if not next_digests:
                    break
                current = next_digests[0]
            if len(chain) != len(by_digest):
                status = "incomplete"
            else:
                status = "canonical"
                canonical_digests = tuple(chain)
                canonical_head_digest = chain[-1]

        return OfferChainView(
            publisher_did=publisher_did,
            offer_id=offer_id,
            status=status,
            all_digests=all_digests,
            root_digests=tuple(roots),
            canonical_digests=canonical_digests,
            canonical_head_digest=canonical_head_digest,
            fork_digests=tuple(
                digest for digest in all_digests if digest in forks
            ),
            orphan_digests=tuple(
                digest for digest in all_digests if digest in orphans
            ),
            invalid_digests=tuple(
                digest for digest in all_digests if digest in invalid
            ),
        )

    def _append_locked(self, document: dict[str, Any]) -> None:
        payload = canonical_json(document)
        if len(payload) > MAX_STORED_LINE_BYTES or b"\n" in payload:
            raise OfferStoreError("canonical offer entry exceeds the storage limit")
        file_existed = self.log_path.exists()
        try:
            current_size = self.log_path.stat().st_size if file_existed else 0
            if current_size + len(payload) + 1 > self.max_bytes:
                raise OfferStoreCapacityError(
                    "offer log has reached configured max_bytes"
                )
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("ab") as stream:
                stream.write(payload + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            if not file_existed:
                self._fsync_directory(self.root)
        except OSError as exc:
            raise OfferStoreError(
                f"offer append durability could not be confirmed: {exc}"
            ) from exc

    def publish(
        self,
        value: TradeOffer | dict[str, Any],
        *,
        source_kind: str = "local-library",
        source_id: str = "",
        received_at_ms: int | None = None,
    ) -> OfferPublishResult:
        if (
            not isinstance(source_kind, str)
            or _SOURCE_KIND.fullmatch(source_kind) is None
        ):
            raise OfferStoreValidationError("source_kind is invalid")
        if (
            not self._is_source_id(source_id)
        ):
            raise OfferStoreValidationError("source_id is invalid")
        if received_at_ms is None:
            received_at_ms = time.time_ns() // 1_000_000
        if (
            isinstance(received_at_ms, bool)
            or not isinstance(received_at_ms, int)
            or received_at_ms < 0
            or received_at_ms > _MAX_RECEIVED_AT_MS
        ):
            raise OfferStoreValidationError("received_at_ms is invalid")
        offer = self._verified_offer(value)
        digest = offer_digest(offer)
        try:
            with InterProcessLock(self.lock_path, timeout=self.lock_timeout):
                records, last_seq = self._scan_locked()
                existing = self._deduplicate(records)
                if digest in existing:
                    chain = self._project(
                        records, offer.publisher_did, offer.offer_id
                    )
                    return OfferPublishResult(
                        seq=existing[digest].seq,
                        digest=digest,
                        appended=False,
                        classification="duplicate",
                        chain=chain,
                        entry_hash=existing[digest].entry_hash,
                        received_at_ms=existing[digest].received_at_ms,
                        source_kind=existing[digest].source_kind,
                        source_id=existing[digest].source_id,
                    )
                if last_seq + 1 >= self.max_records:
                    raise OfferStoreCapacityError(
                        "offer log has reached configured max_records"
                    )
                if last_seq == -1 and not self.checkpoint_path.exists():
                    self._write_checkpoint_locked(
                        seq=-1, entry_hash=_GENESIS_HASH
                    )
                previous_entry_hash = (
                    records[-1].entry_hash if records else _GENESIS_HASH
                )
                entry = self._entry_document(
                    seq=last_seq + 1,
                    previous_entry_hash=previous_entry_hash,
                    offer=offer,
                    received_at_ms=received_at_ms,
                    source_kind=source_kind,
                    source_id=source_id,
                )
                self._append_locked(entry)
                appended = OfferRecord(
                    seq=last_seq + 1,
                    digest=digest,
                    offer=offer,
                    entry_hash=entry["entry_hash"],
                    received_at_ms=received_at_ms,
                    source_kind=source_kind,
                    source_id=source_id,
                )
                records.append(appended)
                self._write_checkpoint_locked(
                    seq=appended.seq, entry_hash=appended.entry_hash
                )
                self._remember_records(records)
                chain = self._project(records, offer.publisher_did, offer.offer_id)
                return OfferPublishResult(
                    seq=appended.seq,
                    digest=digest,
                    appended=True,
                    classification=chain.status,
                    chain=chain,
                    entry_hash=appended.entry_hash,
                    received_at_ms=appended.received_at_ms,
                    source_kind=appended.source_kind,
                    source_id=appended.source_id,
                )
        except TimeoutError as exc:
            raise OfferStoreBusyError("trade offer store is busy") from exc
        except OSError as exc:
            raise OfferStoreError(
                f"offer store I/O failed: {exc}"
            ) from exc

    def verify_import_anchors(
        self,
        anchors: Iterable[dict[str, Any]],
    ) -> tuple[bool, str]:
        """Check signed Spine import anchors against exact local log entries."""

        records, _ = self._read_records()
        by_seq = {record.seq: record for record in records}
        required = {
            "seq",
            "entry_hash",
            "offer_digest",
            "publisher_did",
            "offer_id",
            "source_kind",
            "source_id",
        }
        for anchor in anchors:
            if not isinstance(anchor, dict) or not required.issubset(anchor):
                return False, "signed Spine contains a malformed offer anchor"
            seq = anchor["seq"]
            entry_hash = anchor["entry_hash"]
            digest = anchor["offer_digest"]
            if (
                isinstance(seq, bool)
                or not isinstance(seq, int)
                or seq < 0
                or not self._is_digest(entry_hash)
                or not self._is_digest(digest)
            ):
                return False, "signed Spine contains a malformed offer anchor"
            record = by_seq.get(seq)
            if record is None:
                return False, f"signed Spine anchors missing offer log seq {seq}"
            if record.entry_hash != entry_hash or record.digest != digest:
                return False, f"signed Spine anchor mismatch at offer log seq {seq}"
            if (
                record.offer.publisher_did != anchor["publisher_did"]
                or record.offer.offer_id != anchor["offer_id"]
                or record.source_kind != anchor["source_kind"]
                or record.source_id != anchor["source_id"]
            ):
                return False, (
                    f"signed Spine metadata mismatch at offer log seq {seq}"
                )
        return True, "ok"

    def get(self, digest: str) -> TradeOffer | None:
        if not (
            isinstance(digest, str)
            and len(digest) == 71
            and digest.startswith("sha256:")
            and all(character in "0123456789abcdef" for character in digest[7:])
        ):
            raise ValueError("digest must be a lowercase sha256 digest")
        records, _ = self._read_records()
        head = records[-1].entry_hash if records else _GENESIS_HASH
        if self._cache_by_digest_head != head:
            self._cache_by_digest = self._deduplicate(records)
            self._cache_by_digest_head = head
        record = self._cache_by_digest.get(digest)
        return record.offer if record is not None else None

    def chain(self, publisher_did: str, offer_id: str) -> OfferChainView:
        records, _ = self._read_records()
        return self._project(records, publisher_did, offer_id)

    def list_chains(self) -> tuple[OfferChainView, ...]:
        records, _ = self._read_records()
        head = records[-1].entry_hash if records else _GENESIS_HASH
        if self._cache_views_head == head:
            return self._cache_views
        grouped: dict[tuple[str, str], list[OfferRecord]] = {}
        for record in records:
            key = (record.offer.publisher_did, record.offer.offer_id)
            grouped.setdefault(key, []).append(record)
        views = tuple(
            self._project(grouped[key], key[0], key[1])
            for key in sorted(grouped)
        )
        self._cache_views = views
        self._cache_views_head = head
        return views

    def canonical_head(
        self,
        publisher_did: str,
        offer_id: str,
        *,
        active_only: bool = False,
        at: datetime | None = None,
    ) -> TradeOffer | None:
        _, head = self.canonical_snapshot(publisher_did, offer_id)
        if head is None:
            return None
        if active_only and not evaluate_offer(head, at=at)[0]:
            return None
        return head

    def canonical_snapshot(
        self,
        publisher_did: str,
        offer_id: str,
    ) -> tuple[OfferChainView, TradeOffer | None]:
        """Return one self-consistent lifecycle projection and selected head."""

        records, _ = self._read_records()
        view = self._project(records, publisher_did, offer_id)
        if view.canonical_head_digest is None:
            return view, None
        head = self._deduplicate(records)[view.canonical_head_digest].offer
        return view, head

    def poll(self, since_seq: int = -1, *, limit: int = 500) -> OfferPollResult:
        if isinstance(since_seq, bool) or not isinstance(since_seq, int):
            raise TypeError("since_seq must be an integer")
        if since_seq < -1:
            raise ValueError("since_seq must be at least -1")
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit must be an integer")
        if not 1 <= limit <= 1_000:
            raise ValueError("limit must be in the range 1..1000")
        records, last_seq = self._read_records()
        selected: list[OfferRecord] = []
        cursor = since_seq
        exhausted = True
        for record in records:
            if record.seq <= since_seq:
                continue
            if len(selected) >= limit:
                exhausted = False
                break
            selected.append(record)
            cursor = record.seq
        if exhausted:
            cursor = max(cursor, last_seq)
        return OfferPollResult(records=tuple(selected), cursor=cursor)

    def latest_seq(self) -> int:
        _, last_seq = self._read_records()
        return last_seq


__all__ = [
    "DEFAULT_MAX_RECORDS",
    "DEFAULT_MAX_STORE_BYTES",
    "MAX_STORED_LINE_BYTES",
    "OfferChainView",
    "OfferPollResult",
    "OfferPublishResult",
    "OfferRecord",
    "OfferStore",
    "OfferStoreBusyError",
    "OfferStoreCapacityError",
    "OfferStoreCorruptionError",
    "OfferStoreCryptoUnavailableError",
    "OfferStoreError",
    "OfferStoreValidationError",
]
