"""Durable replay and idempotency state for Dispute Statement fetches."""

from __future__ import annotations

import hashlib
import math
import os
import re
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nth_dao.did_key import is_did_key
from nth_dao.spine import SignedEventLog, SpineEvent
from nth_dao.trade_rules.agreement_order import TradeOrder
from nth_dao.trade_rules.canonical import parse_trade_json, trade_canonical_json
from nth_dao.trade_rules.dispute_statement_fetch_audit import (
    verify_trade_dispute_statement_fetch_audit_event,
)
from nth_dao.trade_rules.dispute_statement_retrieval import (
    MAX_DISPUTE_STATEMENT_FETCH_SECONDS,
    TradeDisputeStatementFetchRequest,
    TradeDisputeStatementFetchResponse,
)
from nth_dao.trade_rules.execution_receipt import TradeExecutionReceipt
from nth_dao.trade_rules.receipt_review import TradeReceiptReview
from nth_dao.trade_rules.transport_common import (
    MAX_TRANSPORT_TIMESTAMP_NS,
    bounded_seconds,
    timestamp_ns,
)

DEFAULT_MAX_DISPUTE_STATEMENT_FETCH_RECORDS = 20_000
DEFAULT_MAX_DISPUTE_STATEMENT_FETCH_JOURNAL_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_DISPUTE_STATEMENT_FETCH_RECORDS_PER_REQUESTER = 500
DEFAULT_MAX_DISPUTE_STATEMENT_FETCH_PENDING_PER_REQUESTER = 50
MAX_DISPUTE_STATEMENT_FETCH_JOURNAL_RECORD_BYTES = 512 * 1024
MAX_DISPUTE_STATEMENT_FETCH_PURGE_LIMIT = 1_000
MAX_DISPUTE_STATEMENT_FETCH_LEASE_SECONDS = 3_600.0

_SCHEMA_VERSION = 1
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVENT_ID = re.compile(r"^[0-9a-f]{64}$")
_NONCE = re.compile(r"^(?:[0-9a-f]{2}){16,64}$")
_OWNER_TOKEN = re.compile(r"^[0-9a-f]{64}$")


class TradeDisputeStatementFetchJournalError(RuntimeError):
    """The durable fetch journal is unavailable or inconsistent."""


class TradeDisputeStatementFetchJournalBusy(
    TradeDisputeStatementFetchJournalError
):
    """Another process holds the SQLite writer lock."""


class TradeDisputeStatementFetchJournalCapacity(
    TradeDisputeStatementFetchJournalError
):
    """A configured record or byte limit would be exceeded."""


class TradeDisputeStatementFetchReplayConflict(
    TradeDisputeStatementFetchJournalError
):
    """A consumed nonce or request ID was rebound to different content."""


@dataclass(frozen=True)
class TradeDisputeStatementFetchJournalRecord:
    requester_did: str
    nonce: str
    request_id: str
    request_digest: str
    request_bytes: bytes
    response_digest: str | None
    response_bytes: bytes | None
    audit_event_id: str | None
    processing_owner: str | None
    lease_until_ns: int | None
    next_retry_at_ns: int
    attempt_count: int
    observed_at_ns: int
    updated_at_ns: int
    not_after_ns: int

    @property
    def total_bytes(self) -> int:
        return len(self.request_bytes) + len(self.response_bytes or b"")

    @property
    def completed(self) -> bool:
        return self.response_bytes is not None

    def resolve(
        self,
        *,
        review: TradeReceiptReview | dict[str, Any],
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
    ) -> tuple[
        TradeDisputeStatementFetchRequest,
        TradeDisputeStatementFetchResponse | None,
    ]:
        """Reverify every retained signature and exact response binding."""

        try:
            request = TradeDisputeStatementFetchRequest.from_json(
                self.request_bytes,
                review=review,
                receipt=receipt,
                order=order,
            )
            response = (
                TradeDisputeStatementFetchResponse.from_json(
                    self.response_bytes,
                    request=request,
                    review=review,
                    receipt=receipt,
                    order=order,
                )
                if self.response_bytes is not None
                else None
            )
        except (TypeError, ValueError) as exc:
            raise TradeDisputeStatementFetchJournalError(
                "retained fetch protocol material failed verification"
            ) from exc
        return request, response


class TradeDisputeStatementFetchJournal:
    """Bounded SQLite state for atomic nonce consumption and exact replay."""

    def __init__(
        self,
        workspace: str | Path,
        *,
        max_records: int = DEFAULT_MAX_DISPUTE_STATEMENT_FETCH_RECORDS,
        max_bytes: int = DEFAULT_MAX_DISPUTE_STATEMENT_FETCH_JOURNAL_BYTES,
        max_records_per_requester: int = (
            DEFAULT_MAX_DISPUTE_STATEMENT_FETCH_RECORDS_PER_REQUESTER
        ),
        max_pending_per_requester: int = (
            DEFAULT_MAX_DISPUTE_STATEMENT_FETCH_PENDING_PER_REQUESTER
        ),
        timeout_seconds: float = 30.0,
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
            isinstance(max_records_per_requester, bool)
            or not isinstance(max_records_per_requester, int)
            or max_records_per_requester <= 0
        ):
            raise ValueError("max_records_per_requester must be a positive integer")
        if (
            isinstance(max_pending_per_requester, bool)
            or not isinstance(max_pending_per_requester, int)
            or max_pending_per_requester <= 0
        ):
            raise ValueError("max_pending_per_requester must be a positive integer")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be a finite positive number")
        self.workspace_root = Path(workspace).resolve()
        self.root = self.workspace_root / "trade"
        self.path = self.root / "dispute_statement_fetch_journal_v1.sqlite3"
        self.max_records = max_records
        self.max_bytes = max_bytes
        self.max_records_per_requester = max_records_per_requester
        self.max_pending_per_requester = max_pending_per_requester
        self.timeout_seconds = float(timeout_seconds)
        self._initialize()

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
            raise TradeDisputeStatementFetchJournalError(
                "fetch journal path escapes workspace"
            ) from exc
        current = self.workspace_root
        for part in ("", *relative.parts):
            current = current if not part else current / part
            if self._is_linklike(current):
                raise TradeDisputeStatementFetchJournalError(
                    "fetch journal path must not contain links"
                )

    def _connect(self) -> sqlite3.Connection:
        self._assert_path(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._assert_path(self.root)
        for path in (
            self.path,
            Path(str(self.path) + "-wal"),
            Path(str(self.path) + "-shm"),
            Path(str(self.path) + "-journal"),
        ):
            self._assert_path(path)
        try:
            connection = sqlite3.connect(
                self.path,
                timeout=self.timeout_seconds,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA foreign_keys = ON")
            return connection
        except sqlite3.Error as exc:
            raise TradeDisputeStatementFetchJournalError(
                "unable to open fetch journal"
            ) from exc

    @staticmethod
    def _raise_database_error(exc: sqlite3.Error) -> None:
        if isinstance(exc, sqlite3.OperationalError) and (
            "locked" in str(exc).lower() or "busy" in str(exc).lower()
        ):
            raise TradeDisputeStatementFetchJournalBusy(
                "fetch journal is busy"
            ) from exc
        raise TradeDisputeStatementFetchJournalError(
            "fetch journal operation failed"
        ) from exc

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in {0, _SCHEMA_VERSION}:
                raise TradeDisputeStatementFetchJournalError(
                    "fetch journal schema is unsupported"
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS fetch_replay (
                    requester_did TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    request_id TEXT NOT NULL UNIQUE,
                    request_digest TEXT NOT NULL,
                    request_bytes BLOB NOT NULL,
                    response_digest TEXT,
                    response_bytes BLOB,
                    audit_event_id TEXT,
                    processing_owner TEXT,
                    lease_until_ns INTEGER,
                    next_retry_at_ns INTEGER NOT NULL,
                    attempt_count INTEGER NOT NULL,
                    observed_at_ns INTEGER NOT NULL,
                    updated_at_ns INTEGER NOT NULL,
                    not_after_ns INTEGER NOT NULL,
                    total_bytes INTEGER NOT NULL,
                    PRIMARY KEY (requester_did, nonce),
                    CHECK (
                        (response_digest IS NULL AND response_bytes IS NULL)
                        OR
                        (response_digest IS NOT NULL AND response_bytes IS NOT NULL)
                    ),
                    CHECK (
                        (processing_owner IS NULL AND lease_until_ns IS NULL)
                        OR
                        (processing_owner IS NOT NULL AND lease_until_ns IS NOT NULL)
                    ),
                    CHECK (response_bytes IS NULL OR processing_owner IS NULL),
                    CHECK (response_bytes IS NOT NULL OR audit_event_id IS NULL),
                    CHECK (attempt_count >= 0)
                ) WITHOUT ROWID
                """
            )
            if version == 0:
                connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            columns = tuple(
                (
                    row["name"],
                    row["type"],
                    row["notnull"],
                    row["pk"],
                )
                for row in connection.execute(
                    "PRAGMA table_info(fetch_replay)"
                ).fetchall()
            )
            expected = (
                ("requester_did", "TEXT", 1, 1),
                ("nonce", "TEXT", 1, 2),
                ("request_id", "TEXT", 1, 0),
                ("request_digest", "TEXT", 1, 0),
                ("request_bytes", "BLOB", 1, 0),
                ("response_digest", "TEXT", 0, 0),
                ("response_bytes", "BLOB", 0, 0),
                ("audit_event_id", "TEXT", 0, 0),
                ("processing_owner", "TEXT", 0, 0),
                ("lease_until_ns", "INTEGER", 0, 0),
                ("next_retry_at_ns", "INTEGER", 1, 0),
                ("attempt_count", "INTEGER", 1, 0),
                ("observed_at_ns", "INTEGER", 1, 0),
                ("updated_at_ns", "INTEGER", 1, 0),
                ("not_after_ns", "INTEGER", 1, 0),
                ("total_bytes", "INTEGER", 1, 0),
            )
            if columns != expected:
                raise TradeDisputeStatementFetchJournalError(
                    "fetch journal schema is incompatible"
                )
            self._verify_schema_constraints(connection)
            integrity = connection.execute("PRAGMA quick_check").fetchone()[0]
            if integrity != "ok":
                raise TradeDisputeStatementFetchJournalError(
                    "fetch journal integrity check failed"
                )
        except TradeDisputeStatementFetchJournalError:
            raise
        except sqlite3.Error as exc:
            self._raise_database_error(exc)
        finally:
            connection.close()

    @staticmethod
    def _verify_schema_constraints(connection: sqlite3.Connection) -> None:
        indexes: set[tuple[int, str, int, tuple[str, ...]]] = set()
        for index in connection.execute("PRAGMA index_list(fetch_replay)"):
            index_name = index["name"]
            quoted_index_name = '"' + index_name.replace('"', '""') + '"'
            index_columns = tuple(
                row["name"]
                for row in connection.execute(
                    f"PRAGMA index_info({quoted_index_name})"
                ).fetchall()
            )
            indexes.add(
                (
                    index["unique"],
                    index["origin"],
                    index["partial"],
                    index_columns,
                )
            )
        required_indexes = {
            (1, "pk", 0, ("requester_did", "nonce")),
            (1, "u", 0, ("request_id",)),
        }
        table_rows = connection.execute(
            "PRAGMA table_list('fetch_replay')"
        ).fetchall()
        if (
            not required_indexes.issubset(indexes)
            or len(table_rows) != 1
            or table_rows[0]["type"] != "table"
            or table_rows[0]["wr"] != 1
        ):
            raise TradeDisputeStatementFetchJournalError(
                "fetch journal schema constraints are incompatible"
            )

        insert_sql = (
            "INSERT INTO fetch_replay (requester_did, nonce, request_id, "
            "request_digest, request_bytes, response_digest, response_bytes, "
            "audit_event_id, processing_owner, lease_until_ns, "
            "next_retry_at_ns, attempt_count, observed_at_ns, updated_at_ns, "
            "not_after_ns, total_bytes) VALUES "
            "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        probe_prefix = "nth-schema-probe-" + os.urandom(16).hex()

        def values(
            suffix: str,
            *,
            response_digest: str | None = None,
            response_bytes: bytes | None = None,
            audit_event_id: str | None = None,
            processing_owner: str | None = None,
            lease_until_ns: int | None = None,
            attempt_count: int = 0,
        ) -> tuple[Any, ...]:
            request_bytes = b"{}"
            return (
                f"did:key:z{probe_prefix}{suffix}",
                (suffix.encode("utf-8").hex() + "00" * 16)[:32],
                f"{probe_prefix}-request-{suffix}",
                f"{probe_prefix}-digest-{suffix}",
                request_bytes,
                response_digest,
                response_bytes,
                audit_event_id,
                processing_owner,
                lease_until_ns,
                1,
                attempt_count,
                1,
                1,
                2,
                len(request_bytes) + len(response_bytes or b""),
            )

        def must_reject(label: str, row_values: tuple[Any, ...]) -> None:
            try:
                connection.execute(insert_sql, row_values)
            except sqlite3.IntegrityError:
                return
            raise TradeDisputeStatementFetchJournalError(
                f"fetch journal schema does not enforce {label}"
            )

        connection.execute("SAVEPOINT fetch_schema_probe")
        try:
            valid = values("valid")
            connection.execute(insert_sql, valid)
            duplicate = list(values("duplicate"))
            duplicate[2] = valid[2]
            must_reject("request_id uniqueness", tuple(duplicate))
            must_reject(
                "response field pairing",
                values("response-pair", response_digest="x"),
            )
            must_reject(
                "lease field pairing",
                values("lease-pair", processing_owner="a" * 64),
            )
            must_reject(
                "completed lease exclusion",
                values(
                    "completed-owner",
                    response_digest="x",
                    response_bytes=b"x",
                    processing_owner="a" * 64,
                    lease_until_ns=2,
                ),
            )
            must_reject(
                "audit completion binding",
                values("audit-without-response", audit_event_id="a" * 64),
            )
            must_reject(
                "non-negative attempt count",
                values("negative-attempt", attempt_count=-1),
            )
        finally:
            connection.execute("ROLLBACK TO fetch_schema_probe")
            connection.execute("RELEASE fetch_schema_probe")

    @staticmethod
    def _timestamp_ns(value: Any, *, label: str) -> int:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 1 <= value <= MAX_TRANSPORT_TIMESTAMP_NS
        ):
            raise TradeDisputeStatementFetchJournalError(f"{label} is invalid")
        return value

    @staticmethod
    def _digest(value: Any, *, label: str) -> str:
        if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
            raise TradeDisputeStatementFetchJournalError(f"{label} is invalid")
        return value

    @staticmethod
    def _owner_token(value: Any, *, label: str = "owner_token") -> str:
        if not isinstance(value, str) or _OWNER_TOKEN.fullmatch(value) is None:
            raise TradeDisputeStatementFetchJournalError(f"{label} is invalid")
        return value

    @staticmethod
    def _event_id(value: Any, *, label: str = "audit_event_id") -> str:
        if not isinstance(value, str) or _EVENT_ID.fullmatch(value) is None:
            raise TradeDisputeStatementFetchJournalError(f"{label} is invalid")
        return value

    @classmethod
    def _record(cls, row: sqlite3.Row) -> TradeDisputeStatementFetchJournalRecord:
        requester_did = row["requester_did"]
        nonce = row["nonce"]
        if not isinstance(requester_did, str) or not is_did_key(requester_did):
            raise TradeDisputeStatementFetchJournalError(
                "retained requester_did is invalid"
            )
        if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
            raise TradeDisputeStatementFetchJournalError(
                "retained nonce is invalid"
            )
        request_bytes = row["request_bytes"]
        response_bytes = row["response_bytes"]
        if not isinstance(request_bytes, (bytes, bytearray, memoryview)):
            raise TradeDisputeStatementFetchJournalError(
                "retained request bytes are invalid"
            )
        if response_bytes is not None and not isinstance(
            response_bytes, (bytes, bytearray, memoryview)
        ):
            raise TradeDisputeStatementFetchJournalError(
                "retained response bytes are invalid"
            )
        request_value = bytes(request_bytes)
        response_value = bytes(response_bytes) if response_bytes is not None else None
        try:
            request_document = parse_trade_json(request_value)
            if trade_canonical_json(request_document) != request_value:
                raise ValueError("request is not canonical")
            response_document = (
                parse_trade_json(response_value)
                if response_value is not None
                else None
            )
            if (
                response_document is not None
                and trade_canonical_json(response_document) != response_value
            ):
                raise ValueError("response is not canonical")
        except (TypeError, ValueError) as exc:
            raise TradeDisputeStatementFetchJournalError(
                "retained fetch bytes are invalid"
            ) from exc
        request_digest = cls._digest(
            row["request_digest"], label="retained request_digest"
        )
        if request_digest != "sha256:" + hashlib.sha256(request_value).hexdigest():
            raise TradeDisputeStatementFetchJournalError(
                "retained request digest is inconsistent"
            )
        response_digest = row["response_digest"]
        audit_event_id = row["audit_event_id"]
        if audit_event_id is not None:
            audit_event_id = cls._event_id(
                audit_event_id,
                label="retained audit_event_id",
            )
        processing_owner = row["processing_owner"]
        lease_until_ns = row["lease_until_ns"]
        if processing_owner is None:
            if lease_until_ns is not None:
                raise TradeDisputeStatementFetchJournalError(
                    "retained fetch lease fields are inconsistent"
                )
            normalized_owner = None
            normalized_lease = None
        else:
            normalized_owner = cls._owner_token(
                processing_owner,
                label="retained processing_owner",
            )
            normalized_lease = cls._timestamp_ns(
                lease_until_ns,
                label="retained lease_until_ns",
            )
        if response_value is None:
            if response_digest is not None:
                raise TradeDisputeStatementFetchJournalError(
                    "retained response fields are inconsistent"
                )
            normalized_response_digest = None
        else:
            normalized_response_digest = cls._digest(
                response_digest, label="retained response_digest"
            )
            if normalized_response_digest != (
                "sha256:" + hashlib.sha256(response_value).hexdigest()
            ):
                raise TradeDisputeStatementFetchJournalError(
                    "retained response digest is inconsistent"
                )
        request_id = row["request_id"]
        if (
            not isinstance(request_id, str)
            or request_document.get("request_id") != request_id
            or request_document.get("requester_did") != requester_did
            or request_document.get("nonce") != nonce
        ):
            raise TradeDisputeStatementFetchJournalError(
                "retained request index binding is inconsistent"
            )
        if response_document is not None and (
            response_document.get("request_id") != request_id
            or response_document.get("request_digest") != request_digest
            or response_document.get("requester_did") != requester_did
        ):
            raise TradeDisputeStatementFetchJournalError(
                "retained response binding is inconsistent"
            )
        record = TradeDisputeStatementFetchJournalRecord(
            requester_did=requester_did,
            nonce=nonce,
            request_id=request_id,
            request_digest=request_digest,
            request_bytes=request_value,
            response_digest=normalized_response_digest,
            response_bytes=response_value,
            audit_event_id=audit_event_id,
            processing_owner=normalized_owner,
            lease_until_ns=normalized_lease,
            next_retry_at_ns=cls._timestamp_ns(
                row["next_retry_at_ns"], label="retained next_retry_at_ns"
            ),
            attempt_count=row["attempt_count"],
            observed_at_ns=cls._timestamp_ns(
                row["observed_at_ns"], label="retained observed_at_ns"
            ),
            updated_at_ns=cls._timestamp_ns(
                row["updated_at_ns"], label="retained updated_at_ns"
            ),
            not_after_ns=cls._timestamp_ns(
                row["not_after_ns"], label="retained not_after_ns"
            ),
        )
        expected_not_after_ns = timestamp_ns(
            request_document.get("not_after"),
            label="retained request.not_after",
            error_type=TradeDisputeStatementFetchJournalError,
        )
        if record.not_after_ns != expected_not_after_ns:
            raise TradeDisputeStatementFetchJournalError(
                "retained request expiry binding is inconsistent"
            )
        if record.updated_at_ns < record.observed_at_ns:
            raise TradeDisputeStatementFetchJournalError(
                "retained fetch chronology is inconsistent"
            )
        if (
            isinstance(record.attempt_count, bool)
            or not isinstance(record.attempt_count, int)
            or record.attempt_count < 0
            or (record.processing_owner is not None and record.attempt_count == 0)
            or (record.response_bytes is not None and record.processing_owner is not None)
            or (record.audit_event_id is not None and record.response_bytes is None)
        ):
            raise TradeDisputeStatementFetchJournalError(
                "retained fetch processing state is inconsistent"
            )
        total_bytes = row["total_bytes"]
        if (
            isinstance(total_bytes, bool)
            or not isinstance(total_bytes, int)
            or total_bytes != record.total_bytes
            or total_bytes > MAX_DISPUTE_STATEMENT_FETCH_JOURNAL_RECORD_BYTES
        ):
            raise TradeDisputeStatementFetchJournalError(
                "retained fetch byte accounting is inconsistent"
            )
        return record

    def reserve(
        self,
        request: TradeDisputeStatementFetchRequest,
        *,
        observed_at_ns: int,
    ) -> tuple[TradeDisputeStatementFetchJournalRecord, bool]:
        """Atomically consume a nonce before any Statement lookup or signing."""

        if not isinstance(request, TradeDisputeStatementFetchRequest):
            raise TypeError("request must be a TradeDisputeStatementFetchRequest")
        observed = self._timestamp_ns(observed_at_ns, label="observed_at_ns")
        document = request.to_dict()
        request_bytes = request.canonical_bytes
        request_digest = "sha256:" + hashlib.sha256(request_bytes).hexdigest()
        not_after_ns = timestamp_ns(
            document["not_after"],
            label="request.not_after",
            error_type=TradeDisputeStatementFetchJournalError,
        )
        if len(request_bytes) > MAX_DISPUTE_STATEMENT_FETCH_JOURNAL_RECORD_BYTES:
            raise TradeDisputeStatementFetchJournalCapacity(
                "fetch journal record exceeds byte limit"
            )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing_row = connection.execute(
                "SELECT * FROM fetch_replay WHERE requester_did = ? AND nonce = ?",
                (document["requester_did"], document["nonce"]),
            ).fetchone()
            if existing_row is not None:
                existing = self._record(existing_row)
                if existing.request_bytes != request_bytes:
                    raise TradeDisputeStatementFetchReplayConflict(
                        "fetch nonce was rebound to a different request"
                    )
                connection.execute("COMMIT")
                return existing, False
            request_id_row = connection.execute(
                "SELECT * FROM fetch_replay WHERE request_id = ?",
                (document["request_id"],),
            ).fetchone()
            if request_id_row is not None:
                raise TradeDisputeStatementFetchReplayConflict(
                    "fetch request_id was rebound to a different nonce"
                )
            usage = connection.execute(
                "SELECT COUNT(*) AS records, "
                "COALESCE(SUM(total_bytes), 0) AS bytes FROM fetch_replay"
            ).fetchone()
            if usage["records"] + 1 > self.max_records:
                raise TradeDisputeStatementFetchJournalCapacity(
                    "max fetch journal records exceeded"
                )
            if usage["bytes"] + len(request_bytes) > self.max_bytes:
                raise TradeDisputeStatementFetchJournalCapacity(
                    "max fetch journal bytes exceeded"
                )
            requester_usage = connection.execute(
                "SELECT COUNT(*) AS records, "
                "COALESCE(SUM(CASE WHEN response_bytes IS NULL THEN 1 ELSE 0 END), 0) "
                "AS pending FROM fetch_replay WHERE requester_did = ?",
                (document["requester_did"],),
            ).fetchone()
            if requester_usage["records"] + 1 > self.max_records_per_requester:
                raise TradeDisputeStatementFetchJournalCapacity(
                    "max fetch journal records for requester exceeded"
                )
            if requester_usage["pending"] + 1 > self.max_pending_per_requester:
                raise TradeDisputeStatementFetchJournalCapacity(
                    "max pending fetch records for requester exceeded"
                )
            connection.execute(
                "INSERT INTO fetch_replay (requester_did, nonce, request_id, "
                "request_digest, request_bytes, response_digest, response_bytes, "
                "audit_event_id, processing_owner, lease_until_ns, "
                "next_retry_at_ns, attempt_count, "
                "observed_at_ns, updated_at_ns, not_after_ns, total_bytes) "
                "VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, ?, 0, ?, ?, ?, ?)",
                (
                    document["requester_did"],
                    document["nonce"],
                    document["request_id"],
                    request_digest,
                    request_bytes,
                    observed,
                    observed,
                    observed,
                    not_after_ns,
                    len(request_bytes),
                ),
            )
            row = connection.execute(
                "SELECT * FROM fetch_replay WHERE requester_did = ? AND nonce = ?",
                (document["requester_did"], document["nonce"]),
            ).fetchone()
            connection.execute("COMMIT")
            return self._record(row), True
        except TradeDisputeStatementFetchJournalError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            self._raise_database_error(exc)
        finally:
            connection.close()

    def mark_audited(
        self,
        request: TradeDisputeStatementFetchRequest,
        response: TradeDisputeStatementFetchResponse,
        *,
        audit_event: SpineEvent,
        spine: SignedEventLog,
        review: TradeReceiptReview | dict[str, Any],
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
        updated_at_ns: int,
    ) -> TradeDisputeStatementFetchJournalRecord:
        """Bind one completed response to its exact signed Spine event."""

        if not isinstance(request, TradeDisputeStatementFetchRequest):
            raise TypeError("request must be a TradeDisputeStatementFetchRequest")
        if not isinstance(response, TradeDisputeStatementFetchResponse):
            raise TypeError("response must be a TradeDisputeStatementFetchResponse")
        if not isinstance(audit_event, SpineEvent):
            raise TypeError("audit_event must be a SpineEvent")
        if not isinstance(spine, SignedEventLog):
            raise TypeError("spine must be a SignedEventLog")
        ok, reason = verify_trade_dispute_statement_fetch_audit_event(
            audit_event,
            request,
            response,
            review=review,
            receipt=receipt,
            order=order,
        )
        if not ok:
            raise TradeDisputeStatementFetchJournalError(reason)
        try:
            persisted_event = spine.reconcile_append(audit_event.event_id)
        except (OSError, RuntimeError, ValueError) as exc:
            raise TradeDisputeStatementFetchJournalError(
                "unable to verify persisted fetch audit event"
            ) from exc
        if persisted_event != audit_event:
            raise TradeDisputeStatementFetchJournalError(
                "fetch audit event is not persisted in the supplied Spine"
            )
        event_id = self._event_id(audit_event.event_id)
        updated = self._timestamp_ns(updated_at_ns, label="updated_at_ns")
        request_document = request.to_dict()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM fetch_replay WHERE requester_did = ? AND nonce = ?",
                (request_document["requester_did"], request_document["nonce"]),
            ).fetchone()
            if row is None:
                raise TradeDisputeStatementFetchReplayConflict(
                    "fetch request was not reserved"
                )
            existing = self._record(row)
            if (
                existing.request_bytes != request.canonical_bytes
                or existing.response_bytes != response.canonical_bytes
            ):
                raise TradeDisputeStatementFetchReplayConflict(
                    "fetch audit does not bind the completed exchange"
                )
            if existing.audit_event_id is not None:
                if existing.audit_event_id != event_id:
                    raise TradeDisputeStatementFetchReplayConflict(
                        "fetch response already has a different audit event"
                    )
                connection.execute("COMMIT")
                return existing
            connection.execute(
                "UPDATE fetch_replay SET audit_event_id = ?, updated_at_ns = ? "
                "WHERE requester_did = ? AND nonce = ?",
                (
                    event_id,
                    max(updated, existing.updated_at_ns),
                    existing.requester_did,
                    existing.nonce,
                ),
            )
            audited_row = connection.execute(
                "SELECT * FROM fetch_replay WHERE requester_did = ? AND nonce = ?",
                (existing.requester_did, existing.nonce),
            ).fetchone()
            connection.execute("COMMIT")
            return self._record(audited_row)
        except TradeDisputeStatementFetchJournalError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            self._raise_database_error(exc)
        finally:
            connection.close()

    def claim_processing(
        self,
        request: TradeDisputeStatementFetchRequest,
        *,
        owner_token: str,
        at_ns: int,
        lease_seconds: float,
    ) -> tuple[TradeDisputeStatementFetchJournalRecord, bool]:
        """Acquire the only active processing lease for one reserved request."""

        if not isinstance(request, TradeDisputeStatementFetchRequest):
            raise TypeError("request must be a TradeDisputeStatementFetchRequest")
        owner = self._owner_token(owner_token)
        observed = self._timestamp_ns(at_ns, label="at_ns")
        lease = bounded_seconds(
            lease_seconds,
            label="lease_seconds",
            error_type=TradeDisputeStatementFetchJournalError,
            maximum=MAX_DISPUTE_STATEMENT_FETCH_LEASE_SECONDS,
        )
        if lease <= 0:
            raise ValueError("lease_seconds must be greater than zero")
        lease_until = observed + int(lease * 1_000_000_000)
        self._timestamp_ns(lease_until, label="lease_until_ns")
        document = request.to_dict()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM fetch_replay WHERE requester_did = ? AND nonce = ?",
                (document["requester_did"], document["nonce"]),
            ).fetchone()
            if row is None:
                raise TradeDisputeStatementFetchReplayConflict(
                    "fetch request was not reserved"
                )
            existing = self._record(row)
            if existing.request_bytes != request.canonical_bytes:
                raise TradeDisputeStatementFetchReplayConflict(
                    "reserved fetch request has conflicting content"
                )
            if existing.completed:
                connection.execute("COMMIT")
                return existing, False
            if (
                existing.processing_owner is not None
                and existing.lease_until_ns is not None
                and existing.lease_until_ns > observed
            ):
                connection.execute("COMMIT")
                return existing, existing.processing_owner == owner
            if existing.next_retry_at_ns > observed:
                connection.execute("COMMIT")
                return existing, False
            connection.execute(
                "UPDATE fetch_replay SET processing_owner = ?, lease_until_ns = ?, "
                "attempt_count = attempt_count + 1, updated_at_ns = ? "
                "WHERE requester_did = ? AND nonce = ?",
                (
                    owner,
                    lease_until,
                    max(observed, existing.updated_at_ns),
                    existing.requester_did,
                    existing.nonce,
                ),
            )
            claimed_row = connection.execute(
                "SELECT * FROM fetch_replay WHERE requester_did = ? AND nonce = ?",
                (existing.requester_did, existing.nonce),
            ).fetchone()
            connection.execute("COMMIT")
            return self._record(claimed_row), True
        except TradeDisputeStatementFetchJournalError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            self._raise_database_error(exc)
        finally:
            connection.close()

    def release_processing(
        self,
        request: TradeDisputeStatementFetchRequest,
        *,
        owner_token: str,
        at_ns: int,
        retry_after_seconds: float,
    ) -> TradeDisputeStatementFetchJournalRecord:
        """Release a failed processing lease and persist a bounded retry floor."""

        if not isinstance(request, TradeDisputeStatementFetchRequest):
            raise TypeError("request must be a TradeDisputeStatementFetchRequest")
        owner = self._owner_token(owner_token)
        observed = self._timestamp_ns(at_ns, label="at_ns")
        retry_after = bounded_seconds(
            retry_after_seconds,
            label="retry_after_seconds",
            error_type=TradeDisputeStatementFetchJournalError,
            maximum=MAX_DISPUTE_STATEMENT_FETCH_SECONDS,
        )
        next_retry = observed + int(retry_after * 1_000_000_000)
        self._timestamp_ns(next_retry, label="next_retry_at_ns")
        document = request.to_dict()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM fetch_replay WHERE requester_did = ? AND nonce = ?",
                (document["requester_did"], document["nonce"]),
            ).fetchone()
            if row is None:
                raise TradeDisputeStatementFetchReplayConflict(
                    "fetch request was not reserved"
                )
            existing = self._record(row)
            if existing.request_bytes != request.canonical_bytes:
                raise TradeDisputeStatementFetchReplayConflict(
                    "reserved fetch request has conflicting content"
                )
            if existing.completed:
                connection.execute("COMMIT")
                return existing
            if existing.processing_owner != owner:
                raise TradeDisputeStatementFetchReplayConflict(
                    "fetch processing lease ownership changed"
                )
            connection.execute(
                "UPDATE fetch_replay SET processing_owner = NULL, "
                "lease_until_ns = NULL, next_retry_at_ns = ?, updated_at_ns = ? "
                "WHERE requester_did = ? AND nonce = ?",
                (
                    next_retry,
                    max(observed, existing.updated_at_ns),
                    existing.requester_did,
                    existing.nonce,
                ),
            )
            released_row = connection.execute(
                "SELECT * FROM fetch_replay WHERE requester_did = ? AND nonce = ?",
                (existing.requester_did, existing.nonce),
            ).fetchone()
            connection.execute("COMMIT")
            return self._record(released_row)
        except TradeDisputeStatementFetchJournalError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            self._raise_database_error(exc)
        finally:
            connection.close()

    def complete(
        self,
        request: TradeDisputeStatementFetchRequest,
        response: TradeDisputeStatementFetchResponse,
        *,
        owner_token: str,
        updated_at_ns: int,
    ) -> tuple[TradeDisputeStatementFetchJournalRecord, bool]:
        """Persist one exact signed Response or replay the retained bytes."""

        if not isinstance(request, TradeDisputeStatementFetchRequest):
            raise TypeError("request must be a TradeDisputeStatementFetchRequest")
        if not isinstance(response, TradeDisputeStatementFetchResponse):
            raise TypeError("response must be a TradeDisputeStatementFetchResponse")
        owner = self._owner_token(owner_token)
        updated = self._timestamp_ns(updated_at_ns, label="updated_at_ns")
        request_document = request.to_dict()
        response_document = response.to_dict()
        request_digest = "sha256:" + hashlib.sha256(
            request.canonical_bytes
        ).hexdigest()
        if (
            response_document["request_id"] != request_document["request_id"]
            or response_document["request_digest"] != request_digest
            or response_document["requester_did"]
            != request_document["requester_did"]
        ):
            raise TradeDisputeStatementFetchReplayConflict(
                "fetch response does not bind the reserved request"
            )
        response_bytes = response.canonical_bytes
        response_digest = "sha256:" + hashlib.sha256(response_bytes).hexdigest()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM fetch_replay WHERE requester_did = ? AND nonce = ?",
                (request_document["requester_did"], request_document["nonce"]),
            ).fetchone()
            if row is None:
                raise TradeDisputeStatementFetchReplayConflict(
                    "fetch request was not reserved"
                )
            existing = self._record(row)
            if existing.request_bytes != request.canonical_bytes:
                raise TradeDisputeStatementFetchReplayConflict(
                    "reserved fetch request has conflicting content"
                )
            if existing.response_bytes is not None:
                if existing.response_bytes != response_bytes:
                    raise TradeDisputeStatementFetchReplayConflict(
                        "fetch request already has a different signed response"
                    )
                connection.execute("COMMIT")
                return existing, False
            if existing.processing_owner != owner:
                raise TradeDisputeStatementFetchReplayConflict(
                    "fetch completion does not own the processing lease"
                )
            if updated < existing.observed_at_ns:
                raise TradeDisputeStatementFetchJournalError(
                    "updated_at_ns predates request observation"
                )
            total_bytes = len(existing.request_bytes) + len(response_bytes)
            if total_bytes > MAX_DISPUTE_STATEMENT_FETCH_JOURNAL_RECORD_BYTES:
                raise TradeDisputeStatementFetchJournalCapacity(
                    "fetch journal record exceeds byte limit"
                )
            usage = connection.execute(
                "SELECT COALESCE(SUM(total_bytes), 0) AS bytes FROM fetch_replay"
            ).fetchone()
            if usage["bytes"] - existing.total_bytes + total_bytes > self.max_bytes:
                raise TradeDisputeStatementFetchJournalCapacity(
                    "max fetch journal bytes exceeded"
                )
            connection.execute(
                "UPDATE fetch_replay SET response_digest = ?, response_bytes = ?, "
                "processing_owner = NULL, lease_until_ns = NULL, "
                "next_retry_at_ns = ?, updated_at_ns = ?, total_bytes = ? "
                "WHERE requester_did = ? AND nonce = ?",
                (
                    response_digest,
                    response_bytes,
                    updated,
                    updated,
                    total_bytes,
                    existing.requester_did,
                    existing.nonce,
                ),
            )
            completed_row = connection.execute(
                "SELECT * FROM fetch_replay WHERE requester_did = ? AND nonce = ?",
                (existing.requester_did, existing.nonce),
            ).fetchone()
            connection.execute("COMMIT")
            return self._record(completed_row), True
        except TradeDisputeStatementFetchJournalError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            self._raise_database_error(exc)
        finally:
            connection.close()

    def get(
        self,
        requester_did: str,
        nonce: str,
    ) -> TradeDisputeStatementFetchJournalRecord | None:
        if not isinstance(requester_did, str) or not is_did_key(requester_did):
            raise ValueError("requester_did must be an Ed25519 did:key")
        if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
            raise ValueError("nonce is invalid")
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM fetch_replay WHERE requester_did = ? AND nonce = ?",
                (requester_did, nonce),
            ).fetchone()
        except sqlite3.Error as exc:
            self._raise_database_error(exc)
        finally:
            connection.close()
        return self._record(row) if row is not None else None

    def purge_ineligible_replays(
        self,
        *,
        at_ns: int,
        clock_skew_seconds: float,
        limit: int = 100,
    ) -> tuple[str, ...]:
        """Delete only requests that a compliant verifier can no longer accept."""

        observed = self._timestamp_ns(at_ns, label="at_ns")
        skew = bounded_seconds(
            clock_skew_seconds,
            label="clock_skew_seconds",
            error_type=TradeDisputeStatementFetchJournalError,
            maximum=MAX_DISPUTE_STATEMENT_FETCH_SECONDS,
        )
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_DISPUTE_STATEMENT_FETCH_PURGE_LIMIT
        ):
            raise ValueError(
                f"limit must be between 1 and {MAX_DISPUTE_STATEMENT_FETCH_PURGE_LIMIT}"
            )
        cutoff_ns = observed - int(skew * 1_000_000_000)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT * FROM fetch_replay "
                "WHERE not_after_ns < ? "
                "AND (response_bytes IS NULL OR audit_event_id IS NOT NULL) "
                "AND (processing_owner IS NULL OR lease_until_ns <= ?) "
                "ORDER BY not_after_ns, request_id LIMIT ?",
                (cutoff_ns, observed, limit),
            ).fetchall()
            records = tuple(self._record(row) for row in rows)
            for record in records:
                connection.execute(
                    "DELETE FROM fetch_replay WHERE requester_did = ? AND nonce = ?",
                    (record.requester_did, record.nonce),
                )
            connection.execute("COMMIT")
            return tuple(record.request_id for record in records)
        except TradeDisputeStatementFetchJournalError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            self._raise_database_error(exc)
        finally:
            connection.close()


__all__ = [
    "DEFAULT_MAX_DISPUTE_STATEMENT_FETCH_JOURNAL_BYTES",
    "DEFAULT_MAX_DISPUTE_STATEMENT_FETCH_PENDING_PER_REQUESTER",
    "DEFAULT_MAX_DISPUTE_STATEMENT_FETCH_RECORDS",
    "DEFAULT_MAX_DISPUTE_STATEMENT_FETCH_RECORDS_PER_REQUESTER",
    "MAX_DISPUTE_STATEMENT_FETCH_JOURNAL_RECORD_BYTES",
    "MAX_DISPUTE_STATEMENT_FETCH_LEASE_SECONDS",
    "MAX_DISPUTE_STATEMENT_FETCH_PURGE_LIMIT",
    "TradeDisputeStatementFetchJournal",
    "TradeDisputeStatementFetchJournalBusy",
    "TradeDisputeStatementFetchJournalCapacity",
    "TradeDisputeStatementFetchJournalError",
    "TradeDisputeStatementFetchJournalRecord",
    "TradeDisputeStatementFetchReplayConflict",
]
