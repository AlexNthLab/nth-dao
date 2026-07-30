"""Conflict-retaining CAS storage for signed Trade Receipt Reviews."""

from __future__ import annotations

import math
import hashlib
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

from nth_dao.trade_rules.agreement_order import TradeOrder
from nth_dao.trade_rules.canonical import (
    MAX_TRADE_JSON_BYTES,
    parse_trade_json,
    trade_canonical_json,
)
from nth_dao.trade_rules.execution_receipt import TradeExecutionReceipt
from nth_dao.trade_rules.receipt_review import (
    RECEIPT_REVIEW_ID_PREFIX,
    TradeReceiptReview,
    receipt_review_digest,
)
from nth_dao.util.io import InterProcessLock

DEFAULT_MAX_RECEIPT_REVIEWS = 10_000
DEFAULT_MAX_RECEIPT_REVIEW_STORE_BYTES = 128 * 1024 * 1024

_REVIEW_ID = re.compile(
    rf"^{re.escape(RECEIPT_REVIEW_ID_PREFIX)}([0-9a-f]{{64}})$"
)
_PRIMARY_FILE = re.compile(r"^([0-9a-f]{64})\.json$")
_CONFLICT_FILE = re.compile(r"^([0-9a-f]{64})\.conflict\.json$")
_MARKER_FILE = re.compile(r"^([0-9a-f]{64})\.conflicted$")
_MARKER_FIELDS = frozenset({"candidate_digest", "review_id"})


class TradeReceiptReviewStoreError(RuntimeError):
    """Base error for Receipt Review persistence."""


class TradeReceiptReviewConflict(TradeReceiptReviewStoreError):
    """One review identity has contradictory signed candidates."""


class TradeReceiptReviewStoreBusy(TradeReceiptReviewStoreError):
    """The Receipt Review store lock could not be acquired."""


class TradeReceiptReviewStoreCapacity(TradeReceiptReviewStoreError):
    """A configured Receipt Review store capacity would be exceeded."""


@dataclass(frozen=True)
class TradeReceiptReviewConflictStatus:
    review_id: str
    has_conflict: bool
    primary_review_digest: str | None
    marker_candidate_digest: str | None
    retained_review_digests: tuple[str, ...]
    retention_complete: bool


class TradeReceiptReviewStore:
    """Persist immutable reviews without resolving equivocation."""

    def __init__(
        self,
        root: str | Path,
        *,
        max_reviews: int = DEFAULT_MAX_RECEIPT_REVIEWS,
        max_bytes: int = DEFAULT_MAX_RECEIPT_REVIEW_STORE_BYTES,
        lock_timeout: float = 10.0,
    ) -> None:
        if (
            isinstance(max_reviews, bool)
            or not isinstance(max_reviews, int)
            or max_reviews <= 0
        ):
            raise ValueError("max_reviews must be a positive integer")
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
        self.root = self.workspace_root / "trade" / "receipt_reviews_v1"
        self.lock_path = self.root / ".locks" / "reviews"
        self.max_reviews = max_reviews
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
            raise TradeReceiptReviewStoreError(
                "Receipt Review store path escapes workspace root"
            ) from exc
        candidates = [self.workspace_root]
        current = self.workspace_root
        for part in relative.parts:
            current = current / part
            candidates.append(current)
        for candidate in candidates:
            if self._is_linklike(candidate):
                raise TradeReceiptReviewStoreError(
                    "Receipt Review store must not contain links or junctions"
                )

    def _path(self, review_id: str) -> Path:
        match = (
            _REVIEW_ID.fullmatch(review_id)
            if isinstance(review_id, str)
            else None
        )
        if match is None:
            raise TradeReceiptReviewStoreError("review_id is invalid")
        return self.root / f"{match.group(1)}.json"

    def _marker_path(self, review_id: str) -> Path:
        return self._path(review_id).with_suffix(".conflicted")

    def _conflict_path(self, review: TradeReceiptReview) -> Path:
        digest = receipt_review_digest(review)
        return self.root / (
            f"{self._conflict_storage_key(review.review_id, digest)}"
            ".conflict.json"
        )

    @staticmethod
    def _conflict_storage_key(
        review_id: str,
        candidate_digest: str,
    ) -> str:
        if (
            not isinstance(review_id, str)
            or _REVIEW_ID.fullmatch(review_id) is None
        ):
            raise TradeReceiptReviewStoreError("review_id is invalid")
        if (
            not isinstance(candidate_digest, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", candidate_digest) is None
        ):
            raise TradeReceiptReviewStoreError(
                "candidate Receipt Review digest is invalid"
            )
        binding = f"{review_id}\0{candidate_digest}".encode("ascii")
        return hashlib.sha256(binding).hexdigest()

    def _conflict_paths(self, review_id: str) -> tuple[Path, ...]:
        self._path(review_id)
        matches: list[Path] = []
        for path in sorted(self.root.glob("*.conflict.json")):
            payload = self._read(path)
            try:
                document = parse_trade_json(payload)
                if trade_canonical_json(document) != payload:
                    raise TradeReceiptReviewStoreError(
                        "stored Receipt Review is not canonical"
                    )
                stored_review_id = document.get("review_id")
                candidate_digest = "sha256:" + hashlib.sha256(
                    payload
                ).hexdigest()
                expected_name = (
                    self._conflict_storage_key(
                        stored_review_id,
                        candidate_digest,
                    )
                    + ".conflict.json"
                )
            except (TypeError, ValueError, UnicodeError) as exc:
                if isinstance(exc, TradeReceiptReviewStoreError):
                    raise
                raise TradeReceiptReviewStoreError(
                    "stored Receipt Review conflict header is invalid"
                ) from exc
            if path.name != expected_name:
                raise TradeReceiptReviewStoreError(
                    "stored Receipt Review does not match its conflict filename"
                )
            if stored_review_id == review_id:
                matches.append(path)
        return tuple(matches)

    def _acquire(self) -> InterProcessLock:
        directory = self.lock_path.parent
        self._assert_path(directory)
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise TradeReceiptReviewStoreError(
                f"unable to create Receipt Review lock directory: {exc}"
            ) from exc
        self._assert_path(directory)
        self._assert_path(Path(str(self.lock_path) + ".lock"))
        return InterProcessLock(self.lock_path, timeout=self.lock_timeout)

    def _read(self, path: Path) -> bytes:
        self._assert_path(path)
        try:
            size = path.stat().st_size
            if size > MAX_TRADE_JSON_BYTES:
                raise TradeReceiptReviewStoreError(
                    "stored Receipt Review exceeds byte limit"
                )
            payload = path.read_bytes()
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise TradeReceiptReviewStoreError(
                f"unable to read stored Receipt Review: {exc}"
            ) from exc
        if len(payload) != size:
            raise TradeReceiptReviewStoreError(
                "stored Receipt Review changed while being read"
            )
        return payload

    def _atomic_write(self, path: Path, payload: bytes) -> None:
        descriptor: int | None = None
        temporary: str | None = None
        try:
            self._assert_path(path.parent)
            path.parent.mkdir(parents=True, exist_ok=True)
            self._assert_path(path.parent)
            self._assert_path(path)
            descriptor, temporary = tempfile.mkstemp(
                prefix=".write-",
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
            raise TradeReceiptReviewStoreError(
                f"unable to persist Receipt Review: {exc}"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    def _verified(
        self,
        review: TradeReceiptReview | dict,
        *,
        receipt: TradeExecutionReceipt | dict,
        order: TradeOrder | dict,
    ) -> TradeReceiptReview:
        return TradeReceiptReview.from_json(
            (
                review.canonical_bytes
                if isinstance(review, TradeReceiptReview)
                else trade_canonical_json(review)
            ),
            receipt=receipt,
            order=order,
        )

    def _read_review(
        self,
        path: Path,
        *,
        receipt: TradeExecutionReceipt | dict,
        order: TradeOrder | dict,
    ) -> TradeReceiptReview:
        review = TradeReceiptReview.from_json(
            self._read(path),
            receipt=receipt,
            order=order,
        )
        primary_match = _PRIMARY_FILE.fullmatch(path.name)
        conflict_match = _CONFLICT_FILE.fullmatch(path.name)
        if primary_match is not None:
            expected = RECEIPT_REVIEW_ID_PREFIX + primary_match.group(1)
            if review.review_id != expected:
                raise TradeReceiptReviewStoreError(
                    "stored Receipt Review does not match its primary filename"
                )
        elif conflict_match is not None:
            expected_key = self._conflict_storage_key(
                review.review_id,
                receipt_review_digest(review),
            )
            if conflict_match.group(1) != expected_key:
                raise TradeReceiptReviewStoreError(
                    "stored Receipt Review does not match its conflict filename"
                )
        else:
            raise TradeReceiptReviewStoreError(
                "stored Receipt Review filename is invalid"
            )
        return review

    def _marker(
        self,
        review_id: str,
    ) -> tuple[str, str] | None:
        path = self._marker_path(review_id)
        try:
            document = parse_trade_json(self._read(path))
        except FileNotFoundError:
            return None
        if (
            not isinstance(document, dict)
            or set(document) != _MARKER_FIELDS
            or document["review_id"] != review_id
            or not isinstance(document["candidate_digest"], str)
            or re.fullmatch(
                r"sha256:[0-9a-f]{64}",
                document["candidate_digest"],
            )
            is None
        ):
            raise TradeReceiptReviewStoreError(
                "Receipt Review conflict marker is corrupt"
            )
        return review_id, document["candidate_digest"]

    def _usage(self) -> tuple[int, int]:
        if not self.root.exists():
            return 0, 0
        self._assert_path(self.root)
        count = 0
        total = 0
        try:
            entries = tuple(self.root.iterdir())
        except OSError as exc:
            raise TradeReceiptReviewStoreError(
                f"unable to scan Receipt Review store: {exc}"
            ) from exc
        for path in entries:
            if path.name == ".locks":
                continue
            self._assert_path(path)
            if not path.is_file():
                raise TradeReceiptReviewStoreError(
                    "Receipt Review store contains an unexpected entry"
                )
            if not (
                _PRIMARY_FILE.fullmatch(path.name)
                or _CONFLICT_FILE.fullmatch(path.name)
                or _MARKER_FILE.fullmatch(path.name)
            ):
                raise TradeReceiptReviewStoreError(
                    "Receipt Review store contains crash residue or unknown files"
                )
            try:
                total += path.stat().st_size
            except OSError as exc:
                raise TradeReceiptReviewStoreError(
                    f"unable to inspect Receipt Review store: {exc}"
                ) from exc
            count += 1
        return count, total

    def _check_capacity(self, added_bytes: int) -> None:
        count, total = self._usage()
        if count + 1 > self.max_reviews:
            raise TradeReceiptReviewStoreCapacity(
                "max_reviews capacity would be exceeded"
            )
        if total + added_bytes > self.max_bytes:
            raise TradeReceiptReviewStoreCapacity(
                "Receipt Review byte capacity would be exceeded"
            )

    def put(
        self,
        review: TradeReceiptReview | dict,
        *,
        receipt: TradeExecutionReceipt | dict,
        order: TradeOrder | dict,
    ) -> TradeReceiptReview:
        stored, _created = self.put_with_status(
            review,
            receipt=receipt,
            order=order,
        )
        return stored

    def put_with_status(
        self,
        review: TradeReceiptReview | dict,
        *,
        receipt: TradeExecutionReceipt | dict,
        order: TradeOrder | dict,
    ) -> tuple[TradeReceiptReview, bool]:
        """Return the stored Review and an atomic CAS-created flag."""

        verified = self._verified(
            review,
            receipt=receipt,
            order=order,
        )
        primary = self._path(verified.review_id)
        try:
            with self._acquire():
                marker_state = self._marker(verified.review_id)
                if marker_state is not None:
                    conflict = self._conflict_path(verified)
                    if not conflict.exists():
                        self._check_capacity(len(verified.canonical_bytes))
                        self._atomic_write(
                            conflict,
                            verified.canonical_bytes,
                        )
                    raise TradeReceiptReviewConflict(
                        "review has contradictory signed candidates"
                    )
                try:
                    current = self._read_review(
                        primary,
                        receipt=receipt,
                        order=order,
                    )
                except FileNotFoundError:
                    self._check_capacity(len(verified.canonical_bytes))
                    self._atomic_write(primary, verified.canonical_bytes)
                    return verified, True
                if current.canonical_bytes == verified.canonical_bytes:
                    return current, False
                candidate_digest = receipt_review_digest(verified)
                marker = trade_canonical_json(
                    {
                        "candidate_digest": candidate_digest,
                        "review_id": verified.review_id,
                    }
                )
                self._atomic_write(
                    self._marker_path(verified.review_id),
                    marker,
                )
                conflict = self._conflict_path(verified)
                if not conflict.exists():
                    self._check_capacity(len(verified.canonical_bytes))
                    self._atomic_write(conflict, verified.canonical_bytes)
                raise TradeReceiptReviewConflict(
                    "review has contradictory signed candidates"
                )
        except TimeoutError as exc:
            raise TradeReceiptReviewStoreBusy(
                "Receipt Review store lock timed out"
            ) from exc

    def get(
        self,
        review_id: str,
        *,
        receipt: TradeExecutionReceipt | dict,
        order: TradeOrder | dict,
    ) -> TradeReceiptReview | None:
        try:
            with self._acquire():
                self._usage()
                if self._marker(review_id) is not None:
                    raise TradeReceiptReviewConflict(
                        "review has contradictory signed candidates"
                    )
                try:
                    return self._read_review(
                        self._path(review_id),
                        receipt=receipt,
                        order=order,
                    )
                except FileNotFoundError:
                    return None
        except TimeoutError as exc:
            raise TradeReceiptReviewStoreBusy(
                "Receipt Review store lock timed out"
            ) from exc

    def list_conflicts(
        self,
        review_id: str,
        *,
        receipt: TradeExecutionReceipt | dict,
        order: TradeOrder | dict,
    ) -> tuple[TradeReceiptReview, ...]:
        self._path(review_id)
        try:
            with self._acquire():
                self._usage()
                reviews: list[TradeReceiptReview] = []
                for path in self._conflict_paths(review_id):
                    candidate = self._read_review(
                        path,
                        receipt=receipt,
                        order=order,
                    )
                    reviews.append(candidate)
                return tuple(reviews)
        except TimeoutError as exc:
            raise TradeReceiptReviewStoreBusy(
                "Receipt Review store lock timed out"
            ) from exc

    def conflict_status(
        self,
        review_id: str,
        *,
        receipt: TradeExecutionReceipt | dict,
        order: TradeOrder | dict,
    ) -> TradeReceiptReviewConflictStatus:
        try:
            with self._acquire():
                self._usage()
                marker = self._marker(review_id)
                retained: list[str] = []
                primary_digest: str | None = None
                primary = self._path(review_id)
                try:
                    primary_digest = receipt_review_digest(
                        self._read_review(
                            primary,
                            receipt=receipt,
                            order=order,
                        )
                    )
                    retained.append(primary_digest)
                except FileNotFoundError:
                    pass
                for path in self._conflict_paths(review_id):
                    candidate = self._read_review(
                        path,
                        receipt=receipt,
                        order=order,
                    )
                    retained.append(receipt_review_digest(candidate))
                marker_digest = marker[1] if marker else None
                return TradeReceiptReviewConflictStatus(
                    review_id=review_id,
                    has_conflict=marker is not None,
                    primary_review_digest=primary_digest,
                    marker_candidate_digest=marker_digest,
                    retained_review_digests=tuple(sorted(set(retained))),
                    retention_complete=(
                        marker is None
                        or (
                            primary_digest is not None
                            and marker_digest != primary_digest
                            and primary_digest in retained
                            and marker_digest in retained
                        )
                    ),
                )
        except TimeoutError as exc:
            raise TradeReceiptReviewStoreBusy(
                "Receipt Review store lock timed out"
            ) from exc


__all__ = [
    "DEFAULT_MAX_RECEIPT_REVIEWS",
    "DEFAULT_MAX_RECEIPT_REVIEW_STORE_BYTES",
    "TradeReceiptReviewConflict",
    "TradeReceiptReviewConflictStatus",
    "TradeReceiptReviewStore",
    "TradeReceiptReviewStoreBusy",
    "TradeReceiptReviewStoreCapacity",
    "TradeReceiptReviewStoreError",
]
