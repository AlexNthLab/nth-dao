"""Destination- and Package-verified intake of federated dispute claims."""

from __future__ import annotations

import copy
import hashlib
import math
import os
import re
import sqlite3
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from nth_dao.did_key import is_did_key
from nth_dao.trade_rules.agreement_order import TradeOrder
from nth_dao.trade_rules.canonical import (
    TradeCanonicalJSONError,
    parse_trade_json,
    trade_canonical_json,
)
from nth_dao.trade_rules.dispute_statement_audit import (
    MAX_TRADE_DISPUTE_AUDIT_OBSERVED_AT_MS,
    TradeDisputeStatementAuditCoordinator,
    TradeDisputeStatementAuditResult,
)
from nth_dao.trade_rules.dispute_statement_transport import (
    DEFAULT_DISPUTE_STATEMENT_DELIVERY_CLOCK_SKEW_SECONDS,
    DEFAULT_MAX_DISPUTE_STATEMENT_DELIVERY_TTL_SECONDS,
    MAX_DISPUTE_STATEMENT_TRANSPORT_SECONDS,
    MAX_DISPUTE_STATEMENT_ACKNOWLEDGEMENT_BYTES,
    TradeDisputeStatementAcknowledgement,
    TradeDisputeStatementDelivery,
    TradeDisputeStatementDeliveryRejected,
    create_trade_dispute_statement_acknowledgement,
    trade_dispute_statement_acknowledgement_digest,
    trade_dispute_statement_delivery_digest,
    verify_trade_dispute_statement_delivery,
)
from nth_dao.trade_rules.execution_receipt import TradeExecutionReceipt
from nth_dao.trade_rules.negotiation import RulePackageResolver
from nth_dao.trade_rules.receipt_review import TradeReceiptReview
from nth_dao.trade_rules.signing import (
    TradeProofError,
    encode_ed25519_signature,
    signed_document_input,
    verification_method_for_did,
    verify_ed25519_did_signature,
)
from nth_dao.trade_rules.transport_common import bounded_seconds

DEFAULT_MAX_DISPUTE_STATEMENT_INTAKE_RECORDS = 5_000
DEFAULT_MAX_DISPUTE_STATEMENT_INTAKE_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_DISPUTE_STATEMENT_ARCHIVE_RECORDS = 50_000
DEFAULT_MAX_DISPUTE_STATEMENT_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
DEFAULT_DISPUTE_STATEMENT_ARCHIVE_RETENTION_SECONDS = 30 * 24 * 60 * 60
MAX_DISPUTE_STATEMENT_ARCHIVE_RETENTION_SECONDS = 10 * 366 * 24 * 60 * 60
MAX_DISPUTE_STATEMENT_MAINTENANCE_BATCH = 10_000
_MAX_INTAKE_ARTIFACT_BYTES = 2 * 1024 * 1024
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVENT_ID = re.compile(r"^[0-9a-f]{64}$")
_STATUSES = frozenset({"observed", "anchored", "acknowledged"})
DISPUTE_STATEMENT_OBSERVATION_KIND = "nth.dao.trade.dispute-statement-observation"
DISPUTE_STATEMENT_OBSERVATION_PROTOCOL_VERSION = "1"
DISPUTE_STATEMENT_OBSERVATION_PROOF_PURPOSE = "tradeDisputeStatementObservation"
DISPUTE_STATEMENT_OBSERVATION_PROOF_TYPE = "Ed25519Signature2020"
DISPUTE_STATEMENT_OBSERVATION_SIGNING_DOMAIN = (
    b"nth-dao/trade-dispute-statement-observation/v1"
)
MAX_DISPUTE_STATEMENT_OBSERVATION_BYTES = 2 * 1024
_OBSERVATION_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "delivery_id",
        "delivery_digest",
        "receiver_did",
        "received_at",
        "proof",
    }
)
_OBSERVATION_PROOF_FIELDS = frozenset(
    {
        "type",
        "created",
        "verification_method",
        "proof_purpose",
        "proof_value",
    }
)


class TradeDisputeStatementIntakeJournalError(RuntimeError):
    """The durable federation intake journal is invalid or unavailable."""


class TradeDisputeStatementIntakeJournalCapacity(
    TradeDisputeStatementIntakeJournalError
):
    """The configured intake journal capacity would be exceeded."""


class TradeDisputeStatementObservationRejected(ValueError):
    """A receiver-signed first-observation attestation is invalid."""


@dataclass(frozen=True, init=False)
class TradeDisputeStatementObservation:
    """Receiver-signed evidence of one exact Delivery observation time."""

    _canonical_bytes: bytes

    @classmethod
    def _create(cls, canonical: bytes) -> "TradeDisputeStatementObservation":
        value = object.__new__(cls)
        object.__setattr__(value, "_canonical_bytes", bytes(canonical))
        return value

    @classmethod
    def from_dict(
        cls,
        document: dict[str, Any],
        *,
        delivery_digest: str,
        delivery_bytes: bytes,
    ) -> "TradeDisputeStatementObservation":
        try:
            canonical = trade_canonical_json(copy.deepcopy(document))
            if len(canonical) > MAX_DISPUTE_STATEMENT_OBSERVATION_BYTES:
                raise TradeDisputeStatementObservationRejected(
                    "observation exceeds byte limit"
                )
            snapshot = parse_trade_json(canonical)
            if set(snapshot) != _OBSERVATION_FIELDS:
                raise TradeDisputeStatementObservationRejected(
                    "observation has missing or unknown fields"
                )
            if (
                snapshot["kind"] != DISPUTE_STATEMENT_OBSERVATION_KIND
                or snapshot["protocol_version"]
                != DISPUTE_STATEMENT_OBSERVATION_PROTOCOL_VERSION
            ):
                raise TradeDisputeStatementObservationRejected(
                    "observation protocol is invalid"
                )
            if (
                not isinstance(delivery_digest, str)
                or _DIGEST.fullmatch(delivery_digest) is None
                or snapshot["delivery_digest"] != delivery_digest
                or delivery_digest
                != "sha256:" + hashlib.sha256(delivery_bytes).hexdigest()
            ):
                raise TradeDisputeStatementObservationRejected(
                    "observation delivery_digest is invalid"
                )
            delivery_document = parse_trade_json(delivery_bytes)
            if snapshot["delivery_id"] != delivery_document.get("delivery_id"):
                raise TradeDisputeStatementObservationRejected(
                    "observation delivery_id does not match Delivery"
                )
            receiver_did = snapshot["receiver_did"]
            if (
                not isinstance(receiver_did, str)
                or not is_did_key(receiver_did)
                or receiver_did != delivery_document.get("recipient_did")
            ):
                raise TradeDisputeStatementObservationRejected(
                    "observation receiver_did does not match Delivery"
                )
            _parse_received_at(snapshot["received_at"])
            proof = snapshot["proof"]
            if not isinstance(proof, dict) or set(proof) != _OBSERVATION_PROOF_FIELDS:
                raise TradeDisputeStatementObservationRejected(
                    "observation proof has missing or unknown fields"
                )
            if (
                proof["type"] != DISPUTE_STATEMENT_OBSERVATION_PROOF_TYPE
                or proof["created"] != snapshot["received_at"]
                or proof["verification_method"]
                != verification_method_for_did(receiver_did)
                or proof["proof_purpose"]
                != DISPUTE_STATEMENT_OBSERVATION_PROOF_PURPOSE
            ):
                raise TradeDisputeStatementObservationRejected(
                    "observation proof binding is invalid"
                )
            signing_input = signed_document_input(
                DISPUTE_STATEMENT_OBSERVATION_SIGNING_DOMAIN,
                snapshot,
            )
            valid, _reason = verify_ed25519_did_signature(
                publisher_did=receiver_did,
                proof_value=proof["proof_value"],
                signing_input=signing_input,
            )
            if not valid:
                raise TradeDisputeStatementObservationRejected(
                    "observation signature is invalid"
                )
        except TradeDisputeStatementObservationRejected:
            raise
        except (
            TradeCanonicalJSONError,
            TradeDisputeStatementIntakeJournalError,
            TradeProofError,
            TypeError,
            ValueError,
            UnicodeError,
        ) as exc:
            raise TradeDisputeStatementObservationRejected(str(exc)) from exc
        return cls._create(canonical)

    @classmethod
    def from_json(
        cls,
        raw: bytes | str,
        *,
        delivery_digest: str,
        delivery_bytes: bytes,
    ) -> "TradeDisputeStatementObservation":
        try:
            return cls.from_dict(
                parse_trade_json(raw),
                delivery_digest=delivery_digest,
                delivery_bytes=delivery_bytes,
            )
        except TradeCanonicalJSONError as exc:
            raise TradeDisputeStatementObservationRejected(str(exc)) from exc

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical_bytes)


def create_trade_dispute_statement_observation(
    identity: Any,
    *,
    delivery: TradeDisputeStatementDelivery,
    delivery_digest: str,
    received_at: str,
) -> TradeDisputeStatementObservation:
    """Sign the receiver's first durable observation of an exact Delivery."""

    if not isinstance(delivery, TradeDisputeStatementDelivery):
        raise TypeError("delivery must be a TradeDisputeStatementDelivery")
    delivery_bytes = delivery.canonical_bytes
    expected_digest = "sha256:" + hashlib.sha256(delivery_bytes).hexdigest()
    if delivery_digest != expected_digest:
        raise TradeDisputeStatementObservationRejected(
            "observation delivery_digest does not match Delivery"
        )
    receiver_did = identity.as_did()
    delivery_document = delivery.to_dict()
    if receiver_did != delivery_document["recipient_did"]:
        raise TradeDisputeStatementObservationRejected(
            "observation signer is not Delivery recipient"
        )
    _parse_received_at(received_at)
    document = {
        "kind": DISPUTE_STATEMENT_OBSERVATION_KIND,
        "protocol_version": DISPUTE_STATEMENT_OBSERVATION_PROTOCOL_VERSION,
        "delivery_id": delivery_document["delivery_id"],
        "delivery_digest": delivery_digest,
        "receiver_did": receiver_did,
        "received_at": received_at,
        "proof": {
            "type": DISPUTE_STATEMENT_OBSERVATION_PROOF_TYPE,
            "created": received_at,
            "verification_method": verification_method_for_did(receiver_did),
            "proof_purpose": DISPUTE_STATEMENT_OBSERVATION_PROOF_PURPOSE,
            "proof_value": "A" * 86,
        },
    }
    document["proof"]["proof_value"] = encode_ed25519_signature(
        identity.sign(
            signed_document_input(
                DISPUTE_STATEMENT_OBSERVATION_SIGNING_DOMAIN,
                document,
            )
        )
    )
    return TradeDisputeStatementObservation.from_dict(
        document,
        delivery_digest=delivery_digest,
        delivery_bytes=delivery_bytes,
    )


@dataclass(frozen=True)
class TradeDisputeStatementIntakeJournalRecord:
    delivery_digest: str
    delivery_bytes: bytes
    observed_at_ms: int
    received_at: str
    status: str
    audit_event_id: str
    observation_bytes: bytes
    acknowledgement_bytes: bytes | None


@dataclass(frozen=True)
class TradeDisputeStatementIntakeMaintenanceResult:
    """Rows safely purged and archived during one bounded maintenance cycle."""

    purged_digests: tuple[str, ...]
    archived_digests: tuple[str, ...]


class TradeDisputeStatementIntakeJournal:
    """Bounded SQLite state for restart-safe exact Delivery replay."""

    def __init__(
        self,
        workspace: str | Path,
        *,
        max_records: int = DEFAULT_MAX_DISPUTE_STATEMENT_INTAKE_RECORDS,
        max_bytes: int = DEFAULT_MAX_DISPUTE_STATEMENT_INTAKE_BYTES,
        max_archive_records: int = (
            DEFAULT_MAX_DISPUTE_STATEMENT_ARCHIVE_RECORDS
        ),
        max_archive_bytes: int = DEFAULT_MAX_DISPUTE_STATEMENT_ARCHIVE_BYTES,
        timeout_seconds: float = 30.0,
    ) -> None:
        for value, label in (
            (max_records, "max_records"),
            (max_bytes, "max_bytes"),
            (max_archive_records, "max_archive_records"),
            (max_archive_bytes, "max_archive_bytes"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{label} must be a positive integer")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be a finite positive number")
        self.workspace_root = Path(workspace).resolve()
        self.path = (
            self.workspace_root / "trade" / "dispute_statement_intake_v1.sqlite3"
        )
        self.max_records = max_records
        self.max_bytes = max_bytes
        self.max_archive_records = max_archive_records
        self.max_archive_bytes = max_archive_bytes
        self.timeout_seconds = float(timeout_seconds)
        self._assert_path(self.path.parent)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._assert_path(self.path.parent)
        self._assert_path(self.path)
        for suffix in ("-wal", "-shm", "-journal"):
            self._assert_path(Path(str(self.path) + suffix))
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
            raise TradeDisputeStatementIntakeJournalError(
                "dispute intake journal path escapes workspace"
            ) from exc
        current = self.workspace_root
        for candidate in (
            current,
            *(
                current.joinpath(*relative.parts[:index])
                for index in range(1, len(relative.parts) + 1)
            ),
        ):
            if self._is_linklike(candidate):
                raise TradeDisputeStatementIntakeJournalError(
                    "dispute intake journal must not contain links"
                )

    def _connect(self) -> sqlite3.Connection:
        self._assert_path(self.path.parent)
        self._assert_path(self.path)
        for suffix in ("-wal", "-shm", "-journal"):
            self._assert_path(Path(str(self.path) + suffix))
        connection = sqlite3.connect(
            self.path,
            timeout=self.timeout_seconds,
            isolation_level=None,
        )
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
        except BaseException:
            connection.close()
            raise
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        try:
            with self._connection() as connection:
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                if version not in {0, 1, 2, 3}:
                    raise TradeDisputeStatementIntakeJournalError(
                        "dispute intake journal schema version is unsupported"
                    )
                connection.execute("BEGIN IMMEDIATE")
                if version == 1:
                    legacy_columns = {
                        row[1]
                        for row in connection.execute(
                            "PRAGMA table_info(dispute_statement_intake)"
                        )
                    }
                    expected_legacy = {
                        "delivery_digest",
                        "delivery_bytes",
                        "observed_at_ms",
                        "received_at",
                        "status",
                        "audit_event_id",
                        "acknowledgement_bytes",
                    }
                    if legacy_columns != expected_legacy:
                        raise TradeDisputeStatementIntakeJournalError(
                            "legacy dispute intake journal schema is invalid"
                        )
                    count = connection.execute(
                        "SELECT COUNT(*) FROM dispute_statement_intake"
                    ).fetchone()[0]
                    if count:
                        raise TradeDisputeStatementIntakeJournalError(
                            "legacy dispute intake journal contains unsigned "
                            "observations and cannot be trusted"
                        )
                    connection.execute("DROP TABLE dispute_statement_intake")
                if version in {0, 1}:
                    connection.execute(
                        """
                        CREATE TABLE dispute_statement_intake (
                            delivery_digest TEXT PRIMARY KEY,
                            delivery_bytes BLOB NOT NULL,
                            observed_at_ms INTEGER NOT NULL,
                            received_at TEXT NOT NULL,
                            status TEXT NOT NULL,
                            audit_event_id TEXT NOT NULL,
                            observation_bytes BLOB NOT NULL,
                            acknowledgement_bytes BLOB
                        ) WITHOUT ROWID
                        """
                    )
                if version in {0, 1, 2}:
                    connection.execute(
                        """
                        CREATE TABLE dispute_statement_intake_archive (
                            delivery_digest TEXT PRIMARY KEY,
                            delivery_bytes BLOB NOT NULL,
                            observed_at_ms INTEGER NOT NULL,
                            received_at TEXT NOT NULL,
                            status TEXT NOT NULL,
                            audit_event_id TEXT NOT NULL,
                            observation_bytes BLOB NOT NULL,
                            acknowledgement_bytes BLOB NOT NULL,
                            archived_at_ms INTEGER NOT NULL,
                            retention_seconds INTEGER NOT NULL,
                            purge_after_ms INTEGER NOT NULL
                        ) WITHOUT ROWID
                        """
                    )
                    connection.execute("PRAGMA user_version = 3")
                columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(dispute_statement_intake)"
                    )
                }
                if columns != {
                    "delivery_digest",
                    "delivery_bytes",
                    "observed_at_ms",
                    "received_at",
                    "status",
                    "audit_event_id",
                    "observation_bytes",
                    "acknowledgement_bytes",
                }:
                    raise TradeDisputeStatementIntakeJournalError(
                        "dispute intake journal schema is invalid"
                    )
                archive_columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(dispute_statement_intake_archive)"
                    )
                }
                if archive_columns != {
                    "delivery_digest",
                    "delivery_bytes",
                    "observed_at_ms",
                    "received_at",
                    "status",
                    "audit_event_id",
                    "observation_bytes",
                    "acknowledgement_bytes",
                    "archived_at_ms",
                    "retention_seconds",
                    "purge_after_ms",
                }:
                    raise TradeDisputeStatementIntakeJournalError(
                        "dispute intake archive schema is invalid"
                    )
                active_count, active_bytes = connection.execute(
                    "SELECT COUNT(*), COALESCE(SUM("
                    "LENGTH(delivery_bytes) + LENGTH(observation_bytes) + CASE "
                    "WHEN acknowledgement_bytes IS NULL THEN ? "
                    "ELSE LENGTH(acknowledgement_bytes) END), 0) "
                    "FROM dispute_statement_intake",
                    (MAX_DISPUTE_STATEMENT_ACKNOWLEDGEMENT_BYTES,),
                ).fetchone()
                archive_count, archive_bytes = connection.execute(
                    "SELECT COUNT(*), COALESCE(SUM("
                    "LENGTH(delivery_bytes) + LENGTH(observation_bytes) + "
                    "LENGTH(acknowledgement_bytes)), 0) "
                    "FROM dispute_statement_intake_archive"
                ).fetchone()
                if active_count > self.max_records:
                    raise TradeDisputeStatementIntakeJournalCapacity(
                        "existing intake journal exceeds max_records"
                    )
                if active_bytes > self.max_bytes:
                    raise TradeDisputeStatementIntakeJournalCapacity(
                        "existing intake journal exceeds max_bytes"
                    )
                if archive_count > self.max_archive_records:
                    raise TradeDisputeStatementIntakeJournalCapacity(
                        "existing intake archive exceeds max_archive_records"
                    )
                if archive_bytes > self.max_archive_bytes:
                    raise TradeDisputeStatementIntakeJournalCapacity(
                        "existing intake archive exceeds max_archive_bytes"
                    )
                connection.commit()
        except TradeDisputeStatementIntakeJournalError:
            raise
        except sqlite3.Error as exc:
            raise TradeDisputeStatementIntakeJournalError(
                f"unable to initialize dispute intake journal: {exc}"
            ) from exc

    @staticmethod
    def _digest(value: Any) -> str:
        if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
            raise TradeDisputeStatementIntakeJournalError("delivery_digest is invalid")
        return value

    @staticmethod
    def _delivery_document(delivery_bytes: bytes) -> dict[str, Any]:
        try:
            document = parse_trade_json(delivery_bytes)
            if (
                not isinstance(document, dict)
                or trade_canonical_json(document) != delivery_bytes
            ):
                raise TradeDisputeStatementIntakeJournalError(
                    "dispute intake journal Delivery is not canonical"
                )
        except TradeCanonicalJSONError as exc:
            raise TradeDisputeStatementIntakeJournalError(
                "dispute intake journal Delivery is invalid"
            ) from exc
        return document

    @classmethod
    def _assert_acknowledgement_binding(
        cls,
        acknowledgement: TradeDisputeStatementAcknowledgement,
        record: TradeDisputeStatementIntakeJournalRecord,
    ) -> None:
        delivery = cls._delivery_document(record.delivery_bytes)
        document = acknowledgement.to_dict()
        try:
            expected = {
                "delivery_id": delivery["delivery_id"],
                "delivery_digest": record.delivery_digest,
                "order_digest": delivery["order_digest"],
                "receipt_digest": delivery["receipt_digest"],
                "review_digest": delivery["review_digest"],
                "statement_digest": delivery["statement_digest"],
                "sender_did": delivery["sender_did"],
                "receiver_did": delivery["recipient_did"],
                "received_at": record.received_at,
                "audit_event_id": record.audit_event_id,
            }
        except KeyError as exc:
            raise TradeDisputeStatementIntakeJournalError(
                "dispute intake journal Delivery binding is invalid"
            ) from exc
        for field, value in expected.items():
            if document[field] != value:
                raise TradeDisputeStatementIntakeJournalError(
                    f"acknowledgement {field} does not bind journal Delivery"
                )

    @staticmethod
    def _record(row: sqlite3.Row) -> TradeDisputeStatementIntakeJournalRecord:
        delivery_digest = row["delivery_digest"]
        delivery_bytes = row["delivery_bytes"]
        observed_at_ms = row["observed_at_ms"]
        received_at = row["received_at"]
        status = row["status"]
        audit_event_id = row["audit_event_id"]
        observation_bytes = row["observation_bytes"]
        acknowledgement_bytes = row["acknowledgement_bytes"]
        if (
            not isinstance(delivery_digest, str)
            or _DIGEST.fullmatch(delivery_digest) is None
            or not isinstance(delivery_bytes, bytes)
            or not 1 <= len(delivery_bytes) <= _MAX_INTAKE_ARTIFACT_BYTES
            or isinstance(observed_at_ms, bool)
            or not isinstance(observed_at_ms, int)
            or not 1 <= observed_at_ms <= MAX_TRADE_DISPUTE_AUDIT_OBSERVED_AT_MS
            or not isinstance(received_at, str)
            or status not in _STATUSES
            or not isinstance(audit_event_id, str)
            or not isinstance(observation_bytes, bytes)
            or not 1
            <= len(observation_bytes)
            <= MAX_DISPUTE_STATEMENT_OBSERVATION_BYTES
            or (status == "observed" and audit_event_id != "")
            or (status != "observed" and _EVENT_ID.fullmatch(audit_event_id) is None)
            or (
                acknowledgement_bytes is not None
                and (
                    not isinstance(acknowledgement_bytes, bytes)
                    or not 1
                    <= len(acknowledgement_bytes)
                    <= MAX_DISPUTE_STATEMENT_ACKNOWLEDGEMENT_BYTES
                )
            )
            or (status == "acknowledged" and acknowledgement_bytes is None)
            or (status != "acknowledged" and acknowledgement_bytes is not None)
        ):
            raise TradeDisputeStatementIntakeJournalError(
                "dispute intake journal row is invalid"
            )
        expected_delivery_digest = (
            "sha256:" + hashlib.sha256(delivery_bytes).hexdigest()
        )
        if delivery_digest != expected_delivery_digest:
            raise TradeDisputeStatementIntakeJournalError(
                "dispute intake journal Delivery digest is inconsistent"
            )
        TradeDisputeStatementIntakeJournal._delivery_document(delivery_bytes)
        received_moment = _parse_received_at(received_at)
        if _timestamp_ms(received_moment) != observed_at_ms:
            raise TradeDisputeStatementIntakeJournalError(
                "dispute intake journal observation time is inconsistent"
            )
        record = TradeDisputeStatementIntakeJournalRecord(
            delivery_digest=delivery_digest,
            delivery_bytes=delivery_bytes,
            observed_at_ms=observed_at_ms,
            received_at=received_at,
            status=status,
            audit_event_id=audit_event_id,
            observation_bytes=observation_bytes,
            acknowledgement_bytes=acknowledgement_bytes,
        )
        try:
            observation = TradeDisputeStatementObservation.from_json(
                observation_bytes,
                delivery_digest=delivery_digest,
                delivery_bytes=delivery_bytes,
            )
        except ValueError as exc:
            raise TradeDisputeStatementIntakeJournalError(
                "dispute intake journal Observation is invalid"
            ) from exc
        if observation.canonical_bytes != observation_bytes:
            raise TradeDisputeStatementIntakeJournalError(
                "dispute intake journal Observation is not canonical"
            )
        if observation.to_dict()["received_at"] != received_at:
            raise TradeDisputeStatementIntakeJournalError(
                "dispute intake journal Observation time is inconsistent"
            )
        if acknowledgement_bytes is not None:
            try:
                acknowledgement = TradeDisputeStatementAcknowledgement.from_json(
                    acknowledgement_bytes
                )
            except ValueError as exc:
                raise TradeDisputeStatementIntakeJournalError(
                    "dispute intake journal Acknowledgement is invalid"
                ) from exc
            if acknowledgement.canonical_bytes != acknowledgement_bytes:
                raise TradeDisputeStatementIntakeJournalError(
                    "dispute intake journal Acknowledgement is not canonical"
                )
            TradeDisputeStatementIntakeJournal._assert_acknowledgement_binding(
                acknowledgement,
                record,
            )
        return record

    @staticmethod
    def _retention_seconds(value: Any) -> int:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= MAX_DISPUTE_STATEMENT_ARCHIVE_RETENTION_SECONDS
        ):
            raise TradeDisputeStatementIntakeJournalError(
                "archive retention_seconds is invalid"
            )
        return value

    @staticmethod
    def _purge_after_ms(
        record: TradeDisputeStatementIntakeJournalRecord,
        retention_seconds: int,
        archived_at_ms: int,
    ) -> int:
        delivery = TradeDisputeStatementIntakeJournal._delivery_document(
            record.delivery_bytes
        )
        try:
            expiry_ms = _timestamp_ms(_parse_received_at(delivery["not_after"]))
        except KeyError as exc:
            raise TradeDisputeStatementIntakeJournalError(
                "archived Delivery has no not_after"
            ) from exc
        latest_actionable_ms = max(
            record.observed_at_ms,
            expiry_ms + int(MAX_DISPUTE_STATEMENT_TRANSPORT_SECONDS * 1_000),
            archived_at_ms,
        )
        return latest_actionable_ms + retention_seconds * 1_000

    @staticmethod
    def _archive_record(
        row: sqlite3.Row,
    ) -> TradeDisputeStatementIntakeJournalRecord:
        record = TradeDisputeStatementIntakeJournal._record(row)
        archived_at_ms = row["archived_at_ms"]
        retention_seconds = (
            TradeDisputeStatementIntakeJournal._retention_seconds(
                row["retention_seconds"]
            )
        )
        purge_after_ms = row["purge_after_ms"]
        if (
            record.status != "acknowledged"
            or isinstance(archived_at_ms, bool)
            or not isinstance(archived_at_ms, int)
            or not record.observed_at_ms
            <= archived_at_ms
            <= MAX_TRADE_DISPUTE_AUDIT_OBSERVED_AT_MS
            or isinstance(purge_after_ms, bool)
            or not isinstance(purge_after_ms, int)
            or purge_after_ms
            != TradeDisputeStatementIntakeJournal._purge_after_ms(
                record,
                retention_seconds,
                archived_at_ms,
            )
        ):
            raise TradeDisputeStatementIntakeJournalError(
                "dispute intake archive row is invalid"
            )
        return record

    def get(
        self,
        delivery_digest: str,
    ) -> TradeDisputeStatementIntakeJournalRecord | None:
        digest = self._digest(delivery_digest)
        try:
            with self._connection() as connection:
                connection.execute("BEGIN")
                active_row = connection.execute(
                    "SELECT * FROM dispute_statement_intake WHERE delivery_digest = ?",
                    (digest,),
                ).fetchone()
                archive_row = connection.execute(
                    "SELECT * FROM dispute_statement_intake_archive "
                    "WHERE delivery_digest = ?",
                    (digest,),
                ).fetchone()
                connection.commit()
        except sqlite3.Error as exc:
            raise TradeDisputeStatementIntakeJournalError(
                f"unable to read dispute intake journal: {exc}"
            ) from exc
        if active_row is not None and archive_row is not None:
            raise TradeDisputeStatementIntakeJournalError(
                "delivery_digest exists in active and archive journals"
            )
        if active_row is not None:
            return self._record(active_row)
        if archive_row is None:
            return None
        return self._archive_record(archive_row)

    def observe(
        self,
        delivery_digest: str,
        delivery: TradeDisputeStatementDelivery,
        *,
        observed_at_ms: int,
        received_at: str,
        observation: TradeDisputeStatementObservation,
    ) -> tuple[TradeDisputeStatementIntakeJournalRecord, bool]:
        digest = self._digest(delivery_digest)
        if not isinstance(delivery, TradeDisputeStatementDelivery):
            raise TypeError("delivery must be a TradeDisputeStatementDelivery")
        if not isinstance(observation, TradeDisputeStatementObservation):
            raise TypeError(
                "observation must be a TradeDisputeStatementObservation"
            )
        delivery_bytes = delivery.canonical_bytes
        if not 1 <= len(delivery_bytes) <= _MAX_INTAKE_ARTIFACT_BYTES:
            raise TradeDisputeStatementIntakeJournalError(
                "delivery exceeds intake artifact byte limit"
            )
        if (
            isinstance(observed_at_ms, bool)
            or not isinstance(observed_at_ms, int)
            or not 1 <= observed_at_ms <= MAX_TRADE_DISPUTE_AUDIT_OBSERVED_AT_MS
        ):
            raise TradeDisputeStatementIntakeJournalError("observed_at_ms is invalid")
        expected_digest = "sha256:" + hashlib.sha256(delivery_bytes).hexdigest()
        if digest != expected_digest:
            raise TradeDisputeStatementIntakeJournalError(
                "delivery_digest does not match delivery_bytes"
            )
        received_moment = _parse_received_at(received_at)
        if _timestamp_ms(received_moment) != observed_at_ms:
            raise TradeDisputeStatementIntakeJournalError(
                "observed_at_ms does not match received_at"
            )
        verified_observation = TradeDisputeStatementObservation.from_json(
            observation.canonical_bytes,
            delivery_digest=digest,
            delivery_bytes=delivery_bytes,
        )
        if verified_observation.to_dict()["received_at"] != received_at:
            raise TradeDisputeStatementIntakeJournalError(
                "observation received_at does not match journal observation"
            )
        observation_bytes = verified_observation.canonical_bytes
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    "SELECT * FROM dispute_statement_intake WHERE delivery_digest = ?",
                    (digest,),
                ).fetchone()
                archived = connection.execute(
                    "SELECT * FROM dispute_statement_intake_archive "
                    "WHERE delivery_digest = ?",
                    (digest,),
                ).fetchone()
                if existing is not None and archived is not None:
                    raise TradeDisputeStatementIntakeJournalError(
                        "delivery_digest exists in active and archive journals"
                    )
                if existing is not None:
                    record = self._record(existing)
                    if record.delivery_bytes != delivery_bytes:
                        raise TradeDisputeStatementIntakeJournalError(
                            "delivery digest collision or journal corruption"
                        )
                    connection.commit()
                    return record, False
                if archived is not None:
                    record = self._archive_record(archived)
                    if record.delivery_bytes != delivery_bytes:
                        raise TradeDisputeStatementIntakeJournalError(
                            "delivery digest collision or archive corruption"
                        )
                    connection.commit()
                    return record, False
                count, total = connection.execute(
                    "SELECT COUNT(*), COALESCE(SUM("
                    "LENGTH(delivery_bytes) + LENGTH(observation_bytes) + CASE "
                    "WHEN acknowledgement_bytes IS NULL THEN ? "
                    "ELSE LENGTH(acknowledgement_bytes) END), 0) "
                    "FROM dispute_statement_intake",
                    (MAX_DISPUTE_STATEMENT_ACKNOWLEDGEMENT_BYTES,),
                ).fetchone()
                if count + 1 > self.max_records:
                    raise TradeDisputeStatementIntakeJournalCapacity(
                        "max_records exceeded"
                    )
                if (
                    total
                    + len(delivery_bytes)
                    + len(observation_bytes)
                    + MAX_DISPUTE_STATEMENT_ACKNOWLEDGEMENT_BYTES
                    > self.max_bytes
                ):
                    raise TradeDisputeStatementIntakeJournalCapacity(
                        "max_bytes exceeded"
                    )
                connection.execute(
                    "INSERT INTO dispute_statement_intake ("
                    "delivery_digest, delivery_bytes, observed_at_ms, "
                    "received_at, status, audit_event_id, "
                    "observation_bytes, acknowledgement_bytes) VALUES "
                    "(?, ?, ?, ?, 'observed', '', ?, NULL)",
                    (
                        digest,
                        delivery_bytes,
                        observed_at_ms,
                        received_at,
                        observation_bytes,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM dispute_statement_intake WHERE delivery_digest = ?",
                    (digest,),
                ).fetchone()
                connection.commit()
        except TradeDisputeStatementIntakeJournalError:
            raise
        except sqlite3.Error as exc:
            raise TradeDisputeStatementIntakeJournalError(
                f"unable to persist dispute intake observation: {exc}"
            ) from exc
        if row is None:
            raise TradeDisputeStatementIntakeJournalError(
                "persisted dispute intake observation disappeared"
            )
        return self._record(row), True

    def mark_anchored(
        self,
        delivery_digest: str,
        *,
        audit_event_id: str,
    ) -> TradeDisputeStatementIntakeJournalRecord:
        digest = self._digest(delivery_digest)
        if (
            not isinstance(audit_event_id, str)
            or _EVENT_ID.fullmatch(audit_event_id) is None
        ):
            raise TradeDisputeStatementIntakeJournalError("audit_event_id is invalid")
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM dispute_statement_intake WHERE delivery_digest = ?",
                    (digest,),
                ).fetchone()
                archived = connection.execute(
                    "SELECT * FROM dispute_statement_intake_archive "
                    "WHERE delivery_digest = ?",
                    (digest,),
                ).fetchone()
                if row is not None and archived is not None:
                    raise TradeDisputeStatementIntakeJournalError(
                        "delivery_digest exists in active and archive journals"
                    )
                if row is None:
                    if archived is None:
                        raise TradeDisputeStatementIntakeJournalError(
                            "dispute intake observation is missing"
                        )
                    record = self._archive_record(archived)
                    if record.audit_event_id != audit_event_id:
                        raise TradeDisputeStatementIntakeJournalError(
                            "dispute intake audit event conflicts"
                        )
                    connection.commit()
                    return record
                record = self._record(row)
                if record.status != "observed":
                    if record.audit_event_id != audit_event_id:
                        raise TradeDisputeStatementIntakeJournalError(
                            "dispute intake audit event conflicts"
                        )
                    connection.commit()
                    return record
                connection.execute(
                    "UPDATE dispute_statement_intake SET "
                    "status = 'anchored', audit_event_id = ? "
                    "WHERE delivery_digest = ? AND status = 'observed'",
                    (audit_event_id, digest),
                )
                updated = connection.execute(
                    "SELECT * FROM dispute_statement_intake WHERE delivery_digest = ?",
                    (digest,),
                ).fetchone()
                connection.commit()
        except TradeDisputeStatementIntakeJournalError:
            raise
        except sqlite3.Error as exc:
            raise TradeDisputeStatementIntakeJournalError(
                f"unable to persist dispute intake anchor: {exc}"
            ) from exc
        if updated is None:
            raise TradeDisputeStatementIntakeJournalError(
                "persisted dispute intake anchor disappeared"
            )
        return self._record(updated)

    def mark_acknowledged(
        self,
        delivery_digest: str,
        *,
        audit_event_id: str,
        acknowledgement: TradeDisputeStatementAcknowledgement,
    ) -> TradeDisputeStatementIntakeJournalRecord:
        digest = self._digest(delivery_digest)
        if (
            not isinstance(audit_event_id, str)
            or _EVENT_ID.fullmatch(audit_event_id) is None
        ):
            raise TradeDisputeStatementIntakeJournalError("audit_event_id is invalid")
        if not isinstance(
            acknowledgement,
            TradeDisputeStatementAcknowledgement,
        ):
            raise TypeError(
                "acknowledgement must be a TradeDisputeStatementAcknowledgement"
            )
        acknowledgement_bytes = acknowledgement.canonical_bytes
        if (
            not 1
            <= len(acknowledgement_bytes)
            <= MAX_DISPUTE_STATEMENT_ACKNOWLEDGEMENT_BYTES
        ):
            raise TradeDisputeStatementIntakeJournalError(
                "acknowledgement exceeds intake artifact byte limit"
            )
        acknowledgement_document = acknowledgement.to_dict()
        if acknowledgement_document["delivery_digest"] != digest:
            raise TradeDisputeStatementIntakeJournalError(
                "acknowledgement does not bind delivery_digest"
            )
        if acknowledgement_document["audit_event_id"] != audit_event_id:
            raise TradeDisputeStatementIntakeJournalError(
                "acknowledgement does not bind audit_event_id"
            )
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM dispute_statement_intake WHERE delivery_digest = ?",
                    (digest,),
                ).fetchone()
                archived = connection.execute(
                    "SELECT * FROM dispute_statement_intake_archive "
                    "WHERE delivery_digest = ?",
                    (digest,),
                ).fetchone()
                if row is not None and archived is not None:
                    raise TradeDisputeStatementIntakeJournalError(
                        "delivery_digest exists in active and archive journals"
                    )
                if row is None:
                    if archived is None:
                        raise TradeDisputeStatementIntakeJournalError(
                            "dispute intake observation is missing"
                        )
                    record = self._archive_record(archived)
                    if (
                        record.audit_event_id != audit_event_id
                        or record.acknowledgement_bytes != acknowledgement_bytes
                    ):
                        raise TradeDisputeStatementIntakeJournalError(
                            "dispute intake archived acknowledgement conflicts"
                        )
                    connection.commit()
                    return record
                record = self._record(row)
                if record.audit_event_id != audit_event_id:
                    raise TradeDisputeStatementIntakeJournalError(
                        "dispute intake audit event conflicts"
                    )
                self._assert_acknowledgement_binding(acknowledgement, record)
                if record.status == "acknowledged":
                    if record.acknowledgement_bytes != acknowledgement_bytes:
                        raise TradeDisputeStatementIntakeJournalError(
                            "dispute intake acknowledgement conflicts"
                        )
                    connection.commit()
                    return record
                if record.status != "anchored":
                    raise TradeDisputeStatementIntakeJournalError(
                        "dispute intake must be anchored before acknowledgement"
                    )
                current_total = connection.execute(
                    "SELECT COALESCE(SUM("
                    "LENGTH(delivery_bytes) + LENGTH(observation_bytes) + CASE "
                    "WHEN acknowledgement_bytes IS NULL THEN ? "
                    "ELSE LENGTH(acknowledgement_bytes) END), 0) "
                    "FROM dispute_statement_intake",
                    (MAX_DISPUTE_STATEMENT_ACKNOWLEDGEMENT_BYTES,),
                ).fetchone()[0]
                projected_total = (
                    current_total
                    - MAX_DISPUTE_STATEMENT_ACKNOWLEDGEMENT_BYTES
                    + len(acknowledgement_bytes)
                )
                if projected_total > self.max_bytes:
                    raise TradeDisputeStatementIntakeJournalCapacity(
                        "max_bytes exceeded"
                    )
                connection.execute(
                    "UPDATE dispute_statement_intake SET "
                    "status = 'acknowledged', acknowledgement_bytes = ? "
                    "WHERE delivery_digest = ? AND status = 'anchored'",
                    (acknowledgement_bytes, digest),
                )
                updated = connection.execute(
                    "SELECT * FROM dispute_statement_intake WHERE delivery_digest = ?",
                    (digest,),
                ).fetchone()
                connection.commit()
        except TradeDisputeStatementIntakeJournalError:
            raise
        except sqlite3.Error as exc:
            raise TradeDisputeStatementIntakeJournalError(
                f"unable to persist dispute intake acknowledgement: {exc}"
            ) from exc
        if updated is None:
            raise TradeDisputeStatementIntakeJournalError(
                "persisted dispute intake acknowledgement disappeared"
            )
        return self._record(updated)

    @staticmethod
    def _maintenance_limit(value: Any) -> int:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 1 <= value <= MAX_DISPUTE_STATEMENT_MAINTENANCE_BATCH
        ):
            raise TradeDisputeStatementIntakeJournalError(
                "maintenance limit is invalid"
            )
        return value

    @staticmethod
    def _maintenance_at_ms(value: datetime | None) -> int:
        try:
            result = _timestamp_ms(_utc_now(value))
        except ValueError as exc:
            raise TradeDisputeStatementIntakeJournalError(
                "maintenance at must be timezone-aware"
            ) from exc
        if not 1 <= result <= MAX_TRADE_DISPUTE_AUDIT_OBSERVED_AT_MS:
            raise TradeDisputeStatementIntakeJournalError(
                "maintenance at is outside the supported range"
            )
        return result

    def archive_acknowledged(
        self,
        *,
        at: datetime | None = None,
        retention_seconds: int = (
            DEFAULT_DISPUTE_STATEMENT_ARCHIVE_RETENTION_SECONDS
        ),
        limit: int = 1_000,
    ) -> tuple[str, ...]:
        """Move verified acknowledged rows out of the bounded hot journal."""

        archived_at_ms = self._maintenance_at_ms(at)
        retention = self._retention_seconds(retention_seconds)
        batch_limit = self._maintenance_limit(limit)
        archived_digests: list[str] = []
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                rows = connection.execute(
                    "SELECT * FROM dispute_statement_intake "
                    "WHERE status = 'acknowledged' AND observed_at_ms <= ? "
                    "ORDER BY observed_at_ms, delivery_digest LIMIT ?",
                    (archived_at_ms, batch_limit),
                ).fetchall()
                prepared: list[
                    tuple[TradeDisputeStatementIntakeJournalRecord, int]
                ] = []
                for row in rows:
                    record = self._record(row)
                    if record.acknowledgement_bytes is None:
                        raise TradeDisputeStatementIntakeJournalError(
                            "acknowledged intake record lost its acknowledgement"
                        )
                    if connection.execute(
                        "SELECT 1 FROM dispute_statement_intake_archive "
                        "WHERE delivery_digest = ?",
                        (record.delivery_digest,),
                    ).fetchone() is not None:
                        raise TradeDisputeStatementIntakeJournalError(
                            "delivery_digest exists in active and archive journals"
                        )
                    purge_after_ms = self._purge_after_ms(
                        record,
                        retention,
                        archived_at_ms,
                    )
                    prepared.append((record, purge_after_ms))
                archive_count, archive_bytes = connection.execute(
                    "SELECT COUNT(*), COALESCE(SUM("
                    "LENGTH(delivery_bytes) + LENGTH(observation_bytes) + "
                    "LENGTH(acknowledgement_bytes)), 0) "
                    "FROM dispute_statement_intake_archive"
                ).fetchone()
                batch_bytes = sum(
                    len(record.delivery_bytes)
                    + len(record.observation_bytes)
                    + len(record.acknowledgement_bytes or b"")
                    for record, _purge_after_ms in prepared
                )
                if archive_count + len(prepared) > self.max_archive_records:
                    raise TradeDisputeStatementIntakeJournalCapacity(
                        "max_archive_records exceeded"
                    )
                if archive_bytes + batch_bytes > self.max_archive_bytes:
                    raise TradeDisputeStatementIntakeJournalCapacity(
                        "max_archive_bytes exceeded"
                    )
                for record, purge_after_ms in prepared:
                    connection.execute(
                        "INSERT INTO dispute_statement_intake_archive ("
                        "delivery_digest, delivery_bytes, observed_at_ms, "
                        "received_at, status, audit_event_id, observation_bytes, "
                        "acknowledgement_bytes, archived_at_ms, retention_seconds, "
                        "purge_after_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            record.delivery_digest,
                            record.delivery_bytes,
                            record.observed_at_ms,
                            record.received_at,
                            record.status,
                            record.audit_event_id,
                            record.observation_bytes,
                            record.acknowledgement_bytes,
                            archived_at_ms,
                            retention,
                            purge_after_ms,
                        ),
                    )
                    deleted = connection.execute(
                        "DELETE FROM dispute_statement_intake "
                        "WHERE delivery_digest = ? AND status = 'acknowledged'",
                        (record.delivery_digest,),
                    ).rowcount
                    if deleted != 1:
                        raise TradeDisputeStatementIntakeJournalError(
                            "acknowledged intake record changed during archive"
                        )
                    archived_digests.append(record.delivery_digest)
                connection.commit()
        except TradeDisputeStatementIntakeJournalError:
            raise
        except sqlite3.Error as exc:
            raise TradeDisputeStatementIntakeJournalError(
                f"unable to archive dispute intake journal: {exc}"
            ) from exc
        return tuple(archived_digests)

    def purge_archive(
        self,
        *,
        at: datetime | None = None,
        limit: int = 1_000,
    ) -> tuple[str, ...]:
        """Delete expired archive rows after their verified retention horizon."""

        purge_at_ms = self._maintenance_at_ms(at)
        batch_limit = self._maintenance_limit(limit)
        purged_digests: list[str] = []
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                rows = connection.execute(
                    "SELECT * FROM dispute_statement_intake_archive "
                    "WHERE purge_after_ms <= ? "
                    "ORDER BY purge_after_ms, delivery_digest LIMIT ?",
                    (purge_at_ms, batch_limit),
                ).fetchall()
                for row in rows:
                    record = self._archive_record(row)
                    if row["purge_after_ms"] > purge_at_ms:
                        raise TradeDisputeStatementIntakeJournalError(
                            "archive row is not eligible for purge"
                        )
                    deleted = connection.execute(
                        "DELETE FROM dispute_statement_intake_archive "
                        "WHERE delivery_digest = ? AND purge_after_ms = ?",
                        (record.delivery_digest, row["purge_after_ms"]),
                    ).rowcount
                    if deleted != 1:
                        raise TradeDisputeStatementIntakeJournalError(
                            "archive row changed during purge"
                        )
                    purged_digests.append(record.delivery_digest)
                connection.commit()
        except TradeDisputeStatementIntakeJournalError:
            raise
        except sqlite3.Error as exc:
            raise TradeDisputeStatementIntakeJournalError(
                f"unable to purge dispute intake archive: {exc}"
            ) from exc
        return tuple(purged_digests)

    def maintain(
        self,
        *,
        at: datetime | None = None,
        retention_seconds: int = (
            DEFAULT_DISPUTE_STATEMENT_ARCHIVE_RETENTION_SECONDS
        ),
        archive_limit: int = 1_000,
        purge_limit: int = 1_000,
    ) -> TradeDisputeStatementIntakeMaintenanceResult:
        """Purge eligible history, then archive acknowledged hot rows."""

        moment = _utc_now(at)
        purged = self.purge_archive(at=moment, limit=purge_limit)
        archived = self.archive_acknowledged(
            at=moment,
            retention_seconds=retention_seconds,
            limit=archive_limit,
        )
        return TradeDisputeStatementIntakeMaintenanceResult(
            purged_digests=purged,
            archived_digests=archived,
        )


def _utc_now(value: datetime | None) -> datetime:
    moment = value or datetime.now(timezone.utc)
    if (
        not isinstance(moment, datetime)
        or moment.tzinfo is None
        or moment.utcoffset() is None
    ):
        raise TradeDisputeStatementDeliveryRejected("at must be timezone-aware")
    return moment.astimezone(timezone.utc)


def _timestamp_ms(value: datetime) -> int:
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = value - epoch
    microseconds = (
        delta.days * 86_400 + delta.seconds
    ) * 1_000_000 + delta.microseconds
    return (microseconds + 999) // 1_000


def _format_received_at(value: datetime) -> str:
    timespec = "microseconds" if value.microsecond else "seconds"
    return value.isoformat(timespec=timespec).replace("+00:00", "Z")


def _parse_received_at(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise TradeDisputeStatementIntakeJournalError("received_at is invalid")
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TradeDisputeStatementIntakeJournalError("received_at is invalid") from exc
    if moment.tzinfo != timezone.utc or _format_received_at(moment) != value:
        raise TradeDisputeStatementIntakeJournalError("received_at is invalid")
    return moment


@dataclass(frozen=True)
class TradeDisputeStatementIntakeResult:
    """Verified retention plus a receiver claim, never an adjudication."""

    delivery: TradeDisputeStatementDelivery
    delivery_digest: str
    audit: TradeDisputeStatementAuditResult
    acknowledgement: TradeDisputeStatementAcknowledgement
    acknowledgement_digest: str


class TradeDisputeStatementIntakeCoordinator:
    """Resolve and retain one destination-bound remote signed claim."""

    def __init__(
        self,
        audit_coordinator: TradeDisputeStatementAuditCoordinator,
        *,
        receiver_identity: Any,
        package_resolver: RulePackageResolver,
        journal: TradeDisputeStatementIntakeJournal | None = None,
        max_ttl_seconds: float = (DEFAULT_MAX_DISPUTE_STATEMENT_DELIVERY_TTL_SECONDS),
        clock_skew_seconds: float = (
            DEFAULT_DISPUTE_STATEMENT_DELIVERY_CLOCK_SKEW_SECONDS
        ),
        archive_retention_seconds: int = (
            DEFAULT_DISPUTE_STATEMENT_ARCHIVE_RETENTION_SECONDS
        ),
        maintenance_limit: int = 1_000,
    ) -> None:
        if not isinstance(
            audit_coordinator,
            TradeDisputeStatementAuditCoordinator,
        ):
            raise TypeError(
                "audit_coordinator must be a TradeDisputeStatementAuditCoordinator"
            )
        receiver_did = receiver_identity.as_did()
        if not isinstance(receiver_did, str) or not is_did_key(receiver_did):
            raise ValueError("receiver_identity must expose an Ed25519 did:key")
        if not callable(getattr(receiver_identity, "sign", None)):
            raise ValueError("receiver_identity must support signing")
        if audit_coordinator.spine.signer_did != receiver_did:
            raise ValueError(
                "Spine signer must match dispute intake receiver identity"
            )
        if not callable(getattr(package_resolver, "load", None)):
            raise TypeError("package_resolver must provide load(digest)")
        if journal is None:
            journal = TradeDisputeStatementIntakeJournal(
                audit_coordinator.store.workspace_root
            )
        if not isinstance(journal, TradeDisputeStatementIntakeJournal):
            raise TypeError("journal must be a TradeDisputeStatementIntakeJournal")
        if journal.workspace_root != audit_coordinator.store.workspace_root:
            raise ValueError("journal and Statement Store must share a workspace")
        self.audit_coordinator = audit_coordinator
        self.receiver_identity = receiver_identity
        self.receiver_did = receiver_did
        self.package_resolver = package_resolver
        self.journal = journal
        self.max_ttl_seconds = bounded_seconds(
            max_ttl_seconds,
            label="max_ttl_seconds",
            error_type=TradeDisputeStatementDeliveryRejected,
            maximum=MAX_DISPUTE_STATEMENT_TRANSPORT_SECONDS,
        )
        self.clock_skew_seconds = bounded_seconds(
            clock_skew_seconds,
            label="clock_skew_seconds",
            error_type=TradeDisputeStatementDeliveryRejected,
            maximum=MAX_DISPUTE_STATEMENT_TRANSPORT_SECONDS,
        )
        self.archive_retention_seconds = journal._retention_seconds(
            archive_retention_seconds
        )
        self.maintenance_limit = journal._maintenance_limit(maintenance_limit)

    def receive(
        self,
        delivery: TradeDisputeStatementDelivery | dict[str, Any],
        *,
        review: TradeReceiptReview | dict[str, Any],
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
        at: datetime | None = None,
    ) -> TradeDisputeStatementIntakeResult:
        """Verify, resolve, retain, anchor, then acknowledge one claim."""

        verified_delivery = (
            TradeDisputeStatementDelivery.from_json(
                delivery.canonical_bytes,
                review=review,
                receipt=receipt,
                order=order,
            )
            if isinstance(delivery, TradeDisputeStatementDelivery)
            else TradeDisputeStatementDelivery.from_dict(
                delivery,
                review=review,
                receipt=receipt,
                order=order,
            )
        )
        moment = _utc_now(at)
        received_at = _format_received_at(moment)
        delivery_digest = trade_dispute_statement_delivery_digest(
            verified_delivery,
            review=review,
            receipt=receipt,
            order=order,
        )
        existing = self.journal.get(delivery_digest)
        if existing is None:
            valid, reason = verify_trade_dispute_statement_delivery(
                verified_delivery,
                review=review,
                receipt=receipt,
                order=order,
                recipient_did=self.receiver_did,
                at=moment,
                max_ttl_seconds=self.max_ttl_seconds,
                clock_skew_seconds=self.clock_skew_seconds,
            )
            if not valid:
                raise TradeDisputeStatementDeliveryRejected(reason)
            self.journal.maintain(
                at=moment,
                retention_seconds=self.archive_retention_seconds,
                archive_limit=self.maintenance_limit,
                purge_limit=self.maintenance_limit,
            )
            observation = create_trade_dispute_statement_observation(
                self.receiver_identity,
                delivery=verified_delivery,
                delivery_digest=delivery_digest,
                received_at=received_at,
            )
            journal_record, _created = self.journal.observe(
                delivery_digest,
                verified_delivery,
                observed_at_ms=_timestamp_ms(moment),
                received_at=received_at,
                observation=observation,
            )
        else:
            journal_record = existing
        if journal_record.delivery_bytes != verified_delivery.canonical_bytes:
            raise TradeDisputeStatementIntakeJournalError(
                "delivery digest collision or journal corruption"
            )
        observed = _parse_received_at(journal_record.received_at)
        valid, reason = verify_trade_dispute_statement_delivery(
            verified_delivery,
            review=review,
            receipt=receipt,
            order=order,
            recipient_did=self.receiver_did,
            at=observed,
            max_ttl_seconds=self.max_ttl_seconds,
            clock_skew_seconds=self.clock_skew_seconds,
        )
        if not valid:
            raise TradeDisputeStatementIntakeJournalError(
                "persisted delivery observation is invalid: " + reason
            )
        statement = verified_delivery.statement.resolve(
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=self.package_resolver,
        )
        audit = self.audit_coordinator.record(
            statement,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=self.package_resolver,
            observed_at_ms=journal_record.observed_at_ms,
            clock_skew_seconds=self.clock_skew_seconds,
        )
        journal_record = self.journal.mark_anchored(
            delivery_digest,
            audit_event_id=audit.event.event_id,
        )
        acknowledgement = create_trade_dispute_statement_acknowledgement(
            self.receiver_identity,
            delivery=verified_delivery,
            review=review,
            receipt=receipt,
            order=order,
            received_at=journal_record.received_at,
            audit_event_id=audit.event.event_id,
            max_ttl_seconds=self.max_ttl_seconds,
            clock_skew_seconds=self.clock_skew_seconds,
        )
        journal_record = self.journal.mark_acknowledged(
            delivery_digest,
            audit_event_id=audit.event.event_id,
            acknowledgement=acknowledgement,
        )
        if journal_record.acknowledgement_bytes is None:
            raise TradeDisputeStatementIntakeJournalError(
                "acknowledged intake record lost its acknowledgement"
            )
        acknowledgement = TradeDisputeStatementAcknowledgement.from_json(
            journal_record.acknowledgement_bytes
        )
        return TradeDisputeStatementIntakeResult(
            delivery=verified_delivery,
            delivery_digest=delivery_digest,
            audit=audit,
            acknowledgement=acknowledgement,
            acknowledgement_digest=(
                trade_dispute_statement_acknowledgement_digest(acknowledgement)
            ),
        )


__all__ = [
    "DEFAULT_DISPUTE_STATEMENT_ARCHIVE_RETENTION_SECONDS",
    "DEFAULT_MAX_DISPUTE_STATEMENT_ARCHIVE_BYTES",
    "DEFAULT_MAX_DISPUTE_STATEMENT_ARCHIVE_RECORDS",
    "DEFAULT_MAX_DISPUTE_STATEMENT_INTAKE_BYTES",
    "DEFAULT_MAX_DISPUTE_STATEMENT_INTAKE_RECORDS",
    "DISPUTE_STATEMENT_OBSERVATION_KIND",
    "MAX_DISPUTE_STATEMENT_OBSERVATION_BYTES",
    "MAX_DISPUTE_STATEMENT_ARCHIVE_RETENTION_SECONDS",
    "MAX_DISPUTE_STATEMENT_MAINTENANCE_BATCH",
    "TradeDisputeStatementIntakeCoordinator",
    "TradeDisputeStatementIntakeJournal",
    "TradeDisputeStatementIntakeJournalCapacity",
    "TradeDisputeStatementIntakeJournalError",
    "TradeDisputeStatementIntakeMaintenanceResult",
    "TradeDisputeStatementIntakeJournalRecord",
    "TradeDisputeStatementIntakeResult",
    "TradeDisputeStatementObservation",
    "TradeDisputeStatementObservationRejected",
    "create_trade_dispute_statement_observation",
]
