"""Append-only local storage and coordination for Intent acceptance policy."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
import time
from typing import Iterator

from nth_dao.canonical_json import canonical_json
from nth_dao.util.io import InterProcessLock
from nth_dao.util.path_security import path_is_linklike

from .intent_policy import (
    INTENT_POLICY_MAX_DOCUMENT_BYTES,
    IntentAcceptancePolicySnapshot,
    IntentPolicyError,
    _did,
    _digest,
    _identifier,
    verify_intent_policy_successor,
)


_APPLICATION_ID = 0x4E544850
_MAX_SAFE_INTEGER = 2**53 - 1
_MAX_RECORDS = 4096
_MAX_BYTES = 64 * 1024 * 1024
_HASH = re.compile(r"sha256:[0-9a-f]{64}")
_TABLE_SQL_V1 = """
    CREATE TABLE policies (
        sequence INTEGER PRIMARY KEY,
        digest TEXT NOT NULL UNIQUE,
        audience_did TEXT NOT NULL,
        scope_id TEXT NOT NULL,
        revision INTEGER NOT NULL,
        previous_digest TEXT NOT NULL,
        policy_json TEXT NOT NULL,
        stored_at_ms INTEGER NOT NULL,
        UNIQUE (audience_did, scope_id, revision)
    )
"""
_TABLE_SQL = """
    CREATE TABLE policies (
        sequence INTEGER PRIMARY KEY,
        digest TEXT NOT NULL UNIQUE,
        audience_did TEXT NOT NULL,
        scope_id TEXT NOT NULL,
        revision INTEGER NOT NULL,
        previous_digest TEXT NOT NULL,
        policy_json TEXT NOT NULL,
        stored_at_ms INTEGER NOT NULL,
        cumulative_bytes INTEGER NOT NULL,
        previous_audit_digest TEXT NOT NULL,
        audit_digest TEXT NOT NULL,
        UNIQUE (audience_did, scope_id, revision)
    )
"""
_TRIGGER_SQL = {
    f"no_{operation.lower()}": f"""
        CREATE TRIGGER no_{operation.lower()} BEFORE {operation} ON policies
        BEGIN SELECT RAISE(ABORT, 'intent policy store is append-only'); END
    """
    for operation in ("UPDATE", "DELETE")
}
_COLUMNS = (
    "sequence", "digest", "audience_did", "scope_id", "revision",
    "previous_digest", "policy_json", "stored_at_ms",
    "cumulative_bytes", "previous_audit_digest", "audit_digest",
)
_V1_COLUMNS = _COLUMNS[:8]
_UNIQUE_COLUMNS = (
    ("digest",),
    ("audience_did", "scope_id", "revision"),
)
_INVALID_RECORD_SQL = f"""
    typeof(sequence) != 'integer' OR sequence < 1 OR sequence > {_MAX_SAFE_INTEGER}
    OR typeof(revision) != 'integer' OR revision < 1 OR revision > {_MAX_SAFE_INTEGER}
    OR typeof(stored_at_ms) != 'integer' OR stored_at_ms < 0 OR stored_at_ms > {_MAX_SAFE_INTEGER}
    OR typeof(cumulative_bytes) != 'integer' OR cumulative_bytes < 1 OR cumulative_bytes > {_MAX_SAFE_INTEGER}
    OR typeof(digest) != 'text' OR LENGTH(CAST(digest AS BLOB)) > 71
    OR typeof(audience_did) != 'text' OR LENGTH(CAST(audience_did AS BLOB)) > 128
    OR typeof(scope_id) != 'text' OR LENGTH(CAST(scope_id AS BLOB)) > 256
    OR typeof(previous_digest) != 'text' OR LENGTH(CAST(previous_digest AS BLOB)) > 71
    OR typeof(policy_json) != 'text' OR LENGTH(CAST(policy_json AS BLOB)) > {INTENT_POLICY_MAX_DOCUMENT_BYTES}
    OR typeof(previous_audit_digest) != 'text' OR LENGTH(CAST(previous_audit_digest AS BLOB)) > 71
    OR typeof(audit_digest) != 'text' OR LENGTH(CAST(audit_digest AS BLOB)) > 71
"""


class IntentPolicyStoreError(RuntimeError):
    """The local policy store is malformed or unavailable."""


class IntentPolicyStoreBusy(IntentPolicyStoreError):
    """Another process is changing policy or accepting under its head."""


class IntentPolicyStoreConflict(IntentPolicyStoreError):
    """A policy does not extend the current audience/scope head."""


class IntentPolicyStoreCapacity(IntentPolicyStoreError):
    """The configured policy-store capacity has been reached."""


@dataclass(frozen=True)
class IntentPolicyRecord:
    sequence: int
    digest: str
    audience_did: str
    scope_id: str
    revision: int
    previous_digest: str
    policy_json: str
    stored_at_ms: int
    cumulative_bytes: int
    previous_audit_digest: str
    audit_digest: str

    @property
    def policy(self) -> IntentAcceptancePolicySnapshot:
        return IntentAcceptancePolicySnapshot.from_json(self.policy_json)

    @property
    def audit(self) -> dict:
        return {
            "format": "org.nth-dao.intent-policy-observation.v1",
            "event_type": "intent.policy.published",
            "sequence": self.sequence,
            "policy_digest": self.digest,
            "audience_did": self.audience_did,
            "scope_id": self.scope_id,
            "revision": self.revision,
            "stored_at_ms": self.stored_at_ms,
            "cumulative_bytes": self.cumulative_bytes,
            "previous_audit_digest": self.previous_audit_digest,
            "authority": "none",
            "commit_authority": False,
            "executable": False,
        }


def _audit_digest(record: IntentPolicyRecord) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(record.audit)).hexdigest()


@dataclass(frozen=True)
class IntentPolicyPublishResult:
    record: IntentPolicyRecord
    created: bool


class IntentPolicyStore:
    """Content-addressed policy history with one derived head per scope."""

    def __init__(
        self,
        workspace: Path,
        *,
        timeout: float = 5.0,
        max_records: int = 1024,
        max_bytes: int = 16 * 1024 * 1024,
        clock=None,
    ) -> None:
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or not 0 < timeout <= 30
        ):
            raise ValueError("timeout must be finite and within (0, 30]")
        if type(max_records) is not int or not 1 <= max_records <= _MAX_RECORDS:
            raise ValueError("max_records is outside the supported range")
        if type(max_bytes) is not int or not 1 <= max_bytes <= _MAX_BYTES:
            raise ValueError("max_bytes is outside the supported range")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be a trusted callable")
        self.workspace = Path(workspace).absolute()
        self.path = self.workspace / ".nth" / "intent_policy_v1" / "policy.sqlite3"
        self._coordination_target = self.path.parent / "current-policy"
        self.timeout = float(timeout)
        self.max_records = max_records
        self.max_bytes = max_bytes
        self._clock = clock if clock is not None else lambda: time.time_ns() // 1_000_000
        try:
            self._assert_path()
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError:
            raise IntentPolicyStoreError("policy storage is unavailable") from None
        with self._transaction(write=True, initialize=True) as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                application = connection.execute("PRAGMA application_id").fetchone()[0]
                if application != 0 or connection.execute(
                    "SELECT 1 FROM sqlite_master LIMIT 1"
                ).fetchone():
                    raise IntentPolicyStoreError("unrecognized nonempty policy database")
                connection.execute(_TABLE_SQL)
                for statement in _TRIGGER_SQL.values():
                    connection.execute(statement)
                connection.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
                connection.execute("PRAGMA user_version = 2")
            elif version == 1:
                self._migrate_v1(connection)
            self._check_schema(connection)
        self.verify_history()

    def _assert_path(self) -> None:
        candidates = (*self.path.parents, self.path, Path(str(self._coordination_target) + ".lock"))
        if any(path_is_linklike(candidate) for candidate in candidates):
            raise IntentPolicyStoreError("policy storage must not contain links")
        for suffix in ("-wal", "-shm", "-journal"):
            if path_is_linklike(Path(str(self.path) + suffix)):
                raise IntentPolicyStoreError("policy sidecars must not contain links")

    @staticmethod
    def _check_schema(connection: sqlite3.Connection, *, version: int = 2) -> None:
        if (
            connection.execute("PRAGMA user_version").fetchone()[0] != version
            or connection.execute("PRAGMA application_id").fetchone()[0] != _APPLICATION_ID
        ):
            raise IntentPolicyStoreError("unsupported policy database format")
        table_sql = _TABLE_SQL if version == 2 else _TABLE_SQL_V1
        expected = {("table", "policies", "policies"): " ".join(table_sql.split())}
        expected.update({
            ("trigger", name, "policies"): " ".join(statement.split())
            for name, statement in _TRIGGER_SQL.items()
        })
        expected.update({
            ("index", f"sqlite_autoindex_policies_{index}", "policies"): None
            for index in range(1, 3)
        })
        rows = connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master"
        ).fetchall()
        actual = {
            (row["type"], row["name"], row["tbl_name"]): (
                " ".join(row["sql"].split()) if row["sql"] is not None else None
            )
            for row in rows
        }
        if len(rows) != len(expected) or actual != expected:
            raise IntentPolicyStoreError("policy schema integrity check failed")
        for index, names in enumerate(_UNIQUE_COLUMNS, 1):
            columns = connection.execute(
                f"PRAGMA index_xinfo('sqlite_autoindex_policies_{index}')"
            ).fetchall()
            keys = [
                (row["name"], row["desc"], row["coll"])
                for row in columns
                if row["key"]
            ]
            if keys != [(name, 0, "BINARY") for name in names]:
                raise IntentPolicyStoreError("policy index schema integrity check failed")

    @classmethod
    def _migrate_v1(cls, connection: sqlite3.Connection) -> None:
        """Upgrade the unpublished v1 local schema without losing policy bytes."""

        cls._check_schema(connection, version=1)
        count, size, invalid = connection.execute(f"""
            SELECT COUNT(*), COALESCE(SUM(LENGTH(CAST(policy_json AS BLOB))), 0),
                COALESCE(MAX(CASE WHEN
                    typeof(sequence) != 'integer' OR sequence < 1 OR sequence > {_MAX_SAFE_INTEGER}
                    OR typeof(revision) != 'integer' OR revision < 1 OR revision > {_MAX_SAFE_INTEGER}
                    OR typeof(stored_at_ms) != 'integer' OR stored_at_ms < 0 OR stored_at_ms > {_MAX_SAFE_INTEGER}
                    OR typeof(digest) != 'text' OR LENGTH(CAST(digest AS BLOB)) > 71
                    OR typeof(audience_did) != 'text' OR LENGTH(CAST(audience_did AS BLOB)) > 128
                    OR typeof(scope_id) != 'text' OR LENGTH(CAST(scope_id AS BLOB)) > 256
                    OR typeof(previous_digest) != 'text' OR LENGTH(CAST(previous_digest AS BLOB)) > 71
                    OR typeof(policy_json) != 'text' OR LENGTH(CAST(policy_json AS BLOB)) > {INTENT_POLICY_MAX_DOCUMENT_BYTES}
                THEN 1 ELSE 0 END), 0)
            FROM policies NOT INDEXED
        """).fetchone()
        if invalid or count > _MAX_RECORDS or size > _MAX_BYTES:
            raise IntentPolicyStoreError("legacy policy store exceeds safe migration limits")
        rows = tuple(connection.execute(
            f"SELECT {', '.join(_V1_COLUMNS)} FROM policies ORDER BY sequence"
        ))
        records = cls._verify_v1_rows(rows)
        for name in _TRIGGER_SQL:
            connection.execute(f'DROP TRIGGER "{name}"')
        connection.execute("ALTER TABLE policies RENAME TO policies_v1")
        connection.execute(_TABLE_SQL)
        previous_audit_digest = ""
        cumulative_bytes = 0
        for legacy in records:
            cumulative_bytes += len(legacy["policy_json"].encode())
            record = IntentPolicyRecord(
                **legacy,
                cumulative_bytes=cumulative_bytes,
                previous_audit_digest=previous_audit_digest,
                audit_digest="",
            )
            record = IntentPolicyRecord(
                **(record.__dict__ | {"audit_digest": _audit_digest(record)})
            )
            connection.execute(
                f"INSERT INTO policies ({', '.join(_COLUMNS)}) VALUES ({', '.join('?' for _ in _COLUMNS)})",
                tuple(getattr(record, field) for field in _COLUMNS),
            )
            previous_audit_digest = record.audit_digest
        connection.execute("DROP TABLE policies_v1")
        for statement in _TRIGGER_SQL.values():
            connection.execute(statement)
        connection.execute("PRAGMA user_version = 2")

    @contextmanager
    def _transaction(
        self, *, write: bool = False, initialize: bool = False,
    ) -> Iterator[sqlite3.Connection]:
        connection = None
        try:
            self._assert_path()
            target = str(self.path) if initialize else self.path.as_uri() + "?mode=rw"
            connection = sqlite3.connect(
                target,
                uri=not initialize,
                timeout=self.timeout,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            if not initialize:
                self._check_schema(connection)
            yield connection
            connection.commit()
        except IntentPolicyStoreError:
            raise
        except (OSError, sqlite3.Error) as exc:
            if isinstance(exc, sqlite3.Error):
                code = getattr(exc, "sqlite_errorcode", 0) & 0xFF
                if code in {
                    getattr(sqlite3, "SQLITE_BUSY", 5),
                    getattr(sqlite3, "SQLITE_LOCKED", 6),
                }:
                    raise IntentPolicyStoreBusy("policy store is busy") from None
            raise IntentPolicyStoreError("policy database operation failed") from None
        finally:
            if connection is not None:
                connection.close()

    @contextmanager
    def coordination_lock(self) -> Iterator[None]:
        """Serialize policy-head changes with governed acceptance commits."""

        lock = InterProcessLock(self._coordination_target, timeout=self.timeout)
        try:
            self._assert_path()
            lock.acquire()
        except TimeoutError:
            raise IntentPolicyStoreBusy("current policy is busy") from None
        except OSError:
            raise IntentPolicyStoreError("policy coordination lock is unavailable") from None
        try:
            self._assert_path()
            yield
        finally:
            lock.release()

    def _read_usage(self, connection: sqlite3.Connection) -> tuple[int, int]:
        row = connection.execute(
            "SELECT sequence, cumulative_bytes FROM policies ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return 0, 0
        if (
            type(row["sequence"]) is not int
            or type(row["cumulative_bytes"]) is not int
            or not 1 <= row["sequence"] <= _MAX_SAFE_INTEGER
            or not 1 <= row["cumulative_bytes"] <= _MAX_SAFE_INTEGER
        ):
            raise IntentPolicyStoreError("policy usage tail is invalid")
        if row["sequence"] > self.max_records or row["cumulative_bytes"] > self.max_bytes:
            raise IntentPolicyStoreCapacity("policy store exceeds configured capacity")
        return row["sequence"], row["cumulative_bytes"]

    def _read_rows(self, connection: sqlite3.Connection) -> tuple[sqlite3.Row, ...]:
        expected_count, expected_size = self._read_usage(connection)
        count, size, invalid = connection.execute(f"""
            SELECT COUNT(*), COALESCE(SUM(LENGTH(CAST(policy_json AS BLOB))), 0),
                COALESCE(MAX(CASE WHEN
                    typeof(sequence) != 'integer' OR sequence < 1 OR sequence > {_MAX_SAFE_INTEGER}
                    OR typeof(revision) != 'integer' OR revision < 1 OR revision > {_MAX_SAFE_INTEGER}
                    OR typeof(stored_at_ms) != 'integer' OR stored_at_ms < 0 OR stored_at_ms > {_MAX_SAFE_INTEGER}
                    OR typeof(cumulative_bytes) != 'integer' OR cumulative_bytes < 1 OR cumulative_bytes > {_MAX_SAFE_INTEGER}
                    OR typeof(digest) != 'text' OR LENGTH(CAST(digest AS BLOB)) > 71
                    OR typeof(audience_did) != 'text' OR LENGTH(CAST(audience_did AS BLOB)) > 128
                    OR typeof(scope_id) != 'text' OR LENGTH(CAST(scope_id AS BLOB)) > 256
                    OR typeof(previous_digest) != 'text' OR LENGTH(CAST(previous_digest AS BLOB)) > 71
                    OR typeof(policy_json) != 'text' OR LENGTH(CAST(policy_json AS BLOB)) > {INTENT_POLICY_MAX_DOCUMENT_BYTES}
                    OR typeof(previous_audit_digest) != 'text' OR LENGTH(CAST(previous_audit_digest AS BLOB)) > 71
                    OR typeof(audit_digest) != 'text' OR LENGTH(CAST(audit_digest AS BLOB)) > 71
                THEN 1 ELSE 0 END), 0)
            FROM policies NOT INDEXED
        """).fetchone()
        if invalid:
            raise IntentPolicyStoreError("policy field type or byte-limit integrity check failed")
        if count != expected_count or size != expected_size:
            raise IntentPolicyStoreError("policy cumulative usage integrity check failed")
        return tuple(connection.execute(
            f"SELECT {', '.join(_COLUMNS)} FROM policies ORDER BY sequence"
        ))

    @classmethod
    def _select_record(
        cls,
        connection: sqlite3.Connection,
        *,
        where: str = "",
        parameters: tuple = (),
        order: str = "",
    ) -> IntentPolicyRecord | None:
        suffix = f" {where} {order} LIMIT 1"
        check = connection.execute(
            f"SELECT CASE WHEN {_INVALID_RECORD_SQL} THEN 1 ELSE 0 END "
            f"FROM policies{suffix}",
            parameters,
        ).fetchone()
        if check is None:
            return None
        if check[0]:
            raise IntentPolicyStoreError("policy record exceeds safe read limits")
        return cls._record_from_row(connection.execute(
            f"SELECT {', '.join(_COLUMNS)} FROM policies{suffix}",
            parameters,
        ).fetchone())

    @staticmethod
    def _record_from_row(row: sqlite3.Row | None) -> IntentPolicyRecord | None:
        if row is None:
            return None
        try:
            record = IntentPolicyRecord(**{field: row[field] for field in _COLUMNS})
            if any(type(getattr(record, field)) is not int for field in (
                "sequence", "revision", "stored_at_ms", "cumulative_bytes",
            )) or any(type(getattr(record, field)) is not str for field in (
                "digest", "audience_did", "scope_id", "previous_digest", "policy_json",
                "previous_audit_digest", "audit_digest",
            )):
                raise ValueError("invalid policy record type")
            if (
                record.sequence < 1
                or record.revision < 1
                or record.stored_at_ms < 0
                or record.cumulative_bytes < len(record.policy_json.encode())
                or _HASH.fullmatch(record.digest) is None
                or (record.previous_audit_digest and _HASH.fullmatch(record.previous_audit_digest) is None)
                or _HASH.fullmatch(record.audit_digest) is None
                or record.audit_digest != _audit_digest(record)
            ):
                raise ValueError("invalid policy record")
            policy = record.policy
            document = policy.to_dict()
            if (
                policy.digest != record.digest
                or policy.canonical_bytes.decode() != record.policy_json
                or document["audience_did"] != record.audience_did
                or document["scope_id"] != record.scope_id
                or document["policy_revision"] != record.revision
                or document["previous_policy_digest"] != record.previous_digest
            ):
                raise ValueError("policy record binding mismatch")
            return record
        except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError, IntentPolicyError):
            raise IntentPolicyStoreError("policy record integrity check failed") from None

    @staticmethod
    def _verify_v1_rows(rows: tuple[sqlite3.Row, ...]) -> tuple[dict, ...]:
        records: list[dict] = []
        heads: dict[tuple[str, str], IntentAcceptancePolicySnapshot] = {}
        previous_time = 0
        try:
            for row in rows:
                record = {field: row[field] for field in _V1_COLUMNS}
                if any(type(record[field]) is not int for field in (
                    "sequence", "revision", "stored_at_ms",
                )) or any(type(record[field]) is not str for field in (
                    "digest", "audience_did", "scope_id", "previous_digest", "policy_json",
                )):
                    raise ValueError("invalid legacy policy field type")
                if (
                    record["sequence"] != len(records) + 1
                    or record["stored_at_ms"] < previous_time
                    or _HASH.fullmatch(record["digest"]) is None
                ):
                    raise ValueError("legacy policy sequence, clock, or digest mismatch")
                policy = IntentAcceptancePolicySnapshot.from_json(record["policy_json"])
                document = policy.to_dict()
                if policy.digest != record["digest"]:
                    raise ValueError("legacy policy content binding mismatch")
                if (
                    document["audience_did"] != record["audience_did"]
                    or document["scope_id"] != record["scope_id"]
                    or document["policy_revision"] != record["revision"]
                    or document["previous_policy_digest"] != record["previous_digest"]
                ):
                    raise ValueError("legacy policy index binding mismatch")
                key = (record["audience_did"], record["scope_id"])
                previous = heads.get(key)
                if previous is None:
                    if record["revision"] != 1 or record["previous_digest"] != "":
                        raise ValueError("legacy policy chain has no genesis")
                else:
                    verify_intent_policy_successor(previous, policy)
                heads[key] = policy
                previous_time = record["stored_at_ms"]
                records.append(record)
        except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError, IntentPolicyError):
            raise IntentPolicyStoreError("legacy policy history integrity check failed") from None
        return tuple(records)

    @staticmethod
    def _verify_rows(rows: tuple[sqlite3.Row, ...]) -> tuple[IntentPolicyRecord, ...]:
        records: list[IntentPolicyRecord] = []
        heads: dict[tuple[str, str], IntentAcceptancePolicySnapshot] = {}
        previous_time = 0
        previous_audit_digest = ""
        cumulative_bytes = 0
        try:
            for row in rows:
                record = IntentPolicyRecord(**{field: row[field] for field in _COLUMNS})
                if record.sequence != len(records) + 1 or record.stored_at_ms < previous_time:
                    raise ValueError("policy sequence or clock mismatch")
                cumulative_bytes += len(record.policy_json.encode())
                if (
                    _HASH.fullmatch(record.digest) is None
                    or record.cumulative_bytes != cumulative_bytes
                    or record.previous_audit_digest != previous_audit_digest
                    or record.audit_digest != _audit_digest(record)
                ):
                    raise ValueError("invalid policy digest")
                policy = record.policy
                document = policy.to_dict()
                if policy.digest != record.digest or policy.canonical_bytes.decode() != record.policy_json:
                    raise ValueError("policy content binding mismatch")
                if (
                    document["audience_did"] != record.audience_did
                    or document["scope_id"] != record.scope_id
                    or document["policy_revision"] != record.revision
                    or document["previous_policy_digest"] != record.previous_digest
                ):
                    raise ValueError("policy index binding mismatch")
                key = (record.audience_did, record.scope_id)
                previous = heads.get(key)
                if previous is None:
                    if record.revision != 1 or record.previous_digest != "":
                        raise ValueError("policy chain has no genesis")
                else:
                    verify_intent_policy_successor(previous, policy)
                heads[key] = policy
                previous_time = record.stored_at_ms
                previous_audit_digest = record.audit_digest
                records.append(record)
        except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError, IntentPolicyError):
            raise IntentPolicyStoreError("policy history integrity check failed") from None
        return tuple(records)

    def history(self) -> tuple[IntentPolicyRecord, ...]:
        with self._transaction() as connection:
            rows = self._read_rows(connection)
        return self._verify_rows(rows)

    def verify_history(self, *, expected_tail_digest: str | None = None) -> tuple[int, str]:
        if expected_tail_digest is not None and (
            type(expected_tail_digest) is not str
            or (expected_tail_digest != "" and _HASH.fullmatch(expected_tail_digest) is None)
        ):
            raise ValueError("expected_tail_digest must be a content hash or empty genesis marker")
        records = self.history()
        tail = records[-1].audit_digest if records else ""
        if expected_tail_digest is not None and tail != expected_tail_digest:
            raise IntentPolicyStoreError("policy history does not match the retained tail")
        return (len(records), tail)

    def _require_tail_unlocked(self, expected_tail_digest: str) -> None:
        if type(expected_tail_digest) is not str or (
            expected_tail_digest != "" and _HASH.fullmatch(expected_tail_digest) is None
        ):
            raise ValueError("expected_tail_digest must be a content hash or empty genesis marker")
        with self._transaction() as connection:
            self._read_usage(connection)
            tail = self._select_record(connection, order="ORDER BY sequence DESC")
        actual = tail.audit_digest if tail is not None else ""
        if actual != expected_tail_digest:
            raise IntentPolicyStoreError("policy history does not match the retained tail")

    def current(self, audience_did: str, scope_id: str) -> IntentAcceptancePolicySnapshot | None:
        """Return the latest contiguous chain head, even after it expires."""

        _did(audience_did, "policy audience_did")
        _identifier(scope_id, "policy scope_id")
        with self.coordination_lock():
            return self._current_unlocked(audience_did, scope_id)

    def effective_at(
        self, audience_did: str, scope_id: str, *, now_ms: int,
    ) -> IntentAcceptancePolicySnapshot | None:
        """Return the latest head only while it is effective at ``now_ms``."""

        if type(now_ms) is not int or not 0 <= now_ms <= _MAX_SAFE_INTEGER:
            raise ValueError("now_ms must be a nonnegative safe integer")
        _did(audience_did, "policy audience_did")
        _identifier(scope_id, "policy scope_id")
        with self.coordination_lock():
            policy = self._current_unlocked(audience_did, scope_id)
        return policy if policy is not None and policy.is_valid_at(now_ms) else None

    def _current_unlocked(
        self, audience_did: str, scope_id: str,
    ) -> IntentAcceptancePolicySnapshot | None:
        with self._transaction() as connection:
            self._read_usage(connection)
            record = self._select_record(
                connection,
                where="WHERE audience_did=? AND scope_id=?",
                parameters=(audience_did, scope_id),
                order="ORDER BY revision DESC",
            )
        return record.policy if record is not None else None

    def get(self, digest: str) -> IntentAcceptancePolicySnapshot | None:
        _digest(digest, "policy digest")
        with self._transaction() as connection:
            self._read_usage(connection)
            record = self._select_record(
                connection, where="WHERE digest=?", parameters=(digest,)
            )
        return record.policy if record is not None else None

    def publish(self, policy: IntentAcceptancePolicySnapshot) -> IntentPolicyPublishResult:
        if type(policy) is not IntentAcceptancePolicySnapshot:
            raise TypeError("policy must be an IntentAcceptancePolicySnapshot")
        with self.coordination_lock():
            return self._publish_unlocked(policy)

    def _publish_unlocked(
        self, policy: IntentAcceptancePolicySnapshot,
    ) -> IntentPolicyPublishResult:
        document = policy.to_dict()
        with self._transaction(write=True) as connection:
            count, usage = self._read_usage(connection)
            existing = self._select_record(
                connection, where="WHERE digest=?", parameters=(policy.digest,)
            )
            if existing is not None:
                return IntentPolicyPublishResult(existing, created=False)
            current_record = self._select_record(
                connection,
                where="WHERE audience_did=? AND scope_id=?",
                parameters=(document["audience_did"], document["scope_id"]),
                order="ORDER BY revision DESC",
            )
            current = current_record.policy if current_record is not None else None
            tail = self._select_record(connection, order="ORDER BY sequence DESC")
            if (tail is None) != (count == 0) or (tail is not None and tail.sequence != count):
                raise IntentPolicyStoreError("policy sequence tail is inconsistent")
            try:
                if current is None:
                    if document["policy_revision"] != 1 or document["previous_policy_digest"] != "":
                        raise IntentPolicyStoreConflict("policy scope must start at revision 1")
                else:
                    verify_intent_policy_successor(current, policy)
            except IntentPolicyError as exc:
                raise IntentPolicyStoreConflict(str(exc)) from None
            encoded = policy.canonical_bytes
            if count >= self.max_records or usage + len(encoded) > self.max_bytes:
                raise IntentPolicyStoreCapacity("policy store capacity reached")
            stored_at_ms = self._read_clock()
            if not policy.is_valid_at(stored_at_ms):
                raise IntentPolicyStoreConflict(
                    "policy must be currently valid when published; scheduled publication is unsupported"
                )
            if tail is not None and stored_at_ms < tail.stored_at_ms:
                raise IntentPolicyStoreConflict("Host clock moved backwards")
            record = IntentPolicyRecord(
                sequence=count + 1,
                digest=policy.digest,
                audience_did=document["audience_did"],
                scope_id=document["scope_id"],
                revision=document["policy_revision"],
                previous_digest=document["previous_policy_digest"],
                policy_json=encoded.decode(),
                stored_at_ms=stored_at_ms,
                cumulative_bytes=usage + len(encoded),
                previous_audit_digest=tail.audit_digest if tail is not None else "",
                audit_digest="",
            )
            record = IntentPolicyRecord(
                **(record.__dict__ | {"audit_digest": _audit_digest(record)})
            )
            try:
                connection.execute(
                    f"INSERT INTO policies VALUES ({', '.join('?' for _ in _COLUMNS)})",
                    tuple(getattr(record, field) for field in _COLUMNS),
                )
            except sqlite3.IntegrityError:
                raise IntentPolicyStoreConflict("policy head changed concurrently") from None
            return IntentPolicyPublishResult(record, created=True)

    def _read_clock(self) -> int:
        now = self._clock()
        if type(now) is not int or not 0 <= now <= _MAX_SAFE_INTEGER:
            raise IntentPolicyStoreError("Host clock must return a nonnegative safe integer")
        return now


__all__ = [
    "IntentPolicyPublishResult",
    "IntentPolicyRecord",
    "IntentPolicyStore",
    "IntentPolicyStoreBusy",
    "IntentPolicyStoreCapacity",
    "IntentPolicyStoreConflict",
    "IntentPolicyStoreError",
]
