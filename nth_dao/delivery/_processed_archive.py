"""Immutable completed intake evidence; disk-indexed, never loaded wholesale.

The active inbox journal remains the recovery queue. This optional local store
keeps replay tombstones and exact completed bytes after active-cache eviction.
Callers hold the inbox process lock across archive writes and transitions.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from contextlib import closing, contextmanager
from hashlib import sha256
from pathlib import Path
from urllib.parse import quote

from nth_dao.canonical_json import canonical_json
from nth_dao.util.io import atomic_write_bytes, open_independent_file
from nth_dao.util.path_security import check_independent_file

MAX_RECORD_BYTES = 2_200_000


class ProcessedArchiveCorrupt(RuntimeError):
    """An immutable archive binding no longer matches its durable evidence."""


class ProcessedArchive:
    def __init__(self, directory: Path) -> None:
        self.directory = directory / "processed_archive"
        self.catalog_path = self.directory / "catalog.sqlite3"

    @staticmethod
    def _nonce_key(sender: str, nonce: str) -> str:
        return sha256(canonical_json({"sender_did": sender, "nonce": nonce})).hexdigest()

    def _message_path(self, message_id: str) -> Path:
        if not isinstance(message_id, str) or not message_id.startswith("sha256:"):
            raise ValueError("invalid archived message address")
        digest = message_id[7:]
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("invalid archived message address")
        return self.directory / "messages" / digest[:2] / f"{digest}.json"

    def _nonce_path(self, sender: str, nonce: str) -> Path:
        digest = self._nonce_key(sender, nonce)
        return self.directory / "nonces" / digest[:2] / f"{digest}.json"

    def _check_catalog_paths(self) -> None:
        check_independent_file(self.catalog_path)
        for suffix in ("-journal", "-wal", "-shm"):
            check_independent_file(Path(str(self.catalog_path) + suffix), missing_ok=True)

    @contextmanager
    def _database(self):
        try:
            self._check_catalog_paths()
            with open_independent_file(self.catalog_path, "rb") as pinned:
                metadata = os.fstat(pinned.fileno())
                uri = "file:" + quote(str(self.catalog_path), safe="/\\:") + "?mode=rw"
                with closing(sqlite3.connect(uri, uri=True, timeout=10)) as database:
                    database.execute("PRAGMA trusted_schema=OFF")
                    database.execute("PRAGMA synchronous=FULL")
                    if database.execute("PRAGMA user_version").fetchone() != (1,):
                        raise ProcessedArchiveCorrupt("completed archive catalog version differs")
                    current = check_independent_file(self.catalog_path)
                    if (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino):
                        raise ProcessedArchiveCorrupt("completed archive catalog changed during open")
                    yield database
                    self._check_catalog_paths()
                    current = check_independent_file(self.catalog_path)
                    if (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino):
                        raise ProcessedArchiveCorrupt("completed archive catalog changed during use")
        except (FileNotFoundError, ValueError, sqlite3.DatabaseError) as exc:
            raise ProcessedArchiveCorrupt("completed archive catalog is missing, unsafe or corrupt") from exc

    def require_catalog(self) -> None:
        with self._database() as database:
            database.execute("SELECT message_id, nonce_key, record_sha256 FROM entries LIMIT 0")

    def initialize_catalog(self) -> None:
        """Upgrade verified legacy pairs once, without deleting legacy evidence.

        The caller holds the inbox process lock. Publish the new database before
        upgrading the journal marker; a crash before publication can retry.
        """
        try:
            if check_independent_file(self.catalog_path, missing_ok=True) is not None:
                self.require_catalog()
                return
            self.directory.mkdir(parents=True, exist_ok=True)
            check_independent_file(self.catalog_path, missing_ok=True)
            fd, name = tempfile.mkstemp(prefix=".catalog-", suffix=".tmp", dir=self.directory)
            temporary = Path(name)
            with os.fdopen(fd, "rb") as handle:
                owned = os.fstat(handle.fileno())
                current = check_independent_file(temporary)
                if (current.st_dev, current.st_ino) != (owned.st_dev, owned.st_ino):
                    raise ProcessedArchiveCorrupt("completed archive temporary catalog changed")
                for suffix in ("-journal", "-wal", "-shm"):
                    check_independent_file(Path(str(temporary) + suffix), missing_ok=True)
                uri = "file:" + quote(str(temporary), safe="/\\:") + "?mode=rw"
                with closing(sqlite3.connect(uri, uri=True)) as database, database:
                    current = check_independent_file(temporary)
                    if (current.st_dev, current.st_ino) != (owned.st_dev, owned.st_ino):
                        raise ProcessedArchiveCorrupt("completed archive temporary catalog changed during open")
                    database.execute("PRAGMA trusted_schema=OFF")
                    database.execute("PRAGMA journal_mode=DELETE")
                    database.execute("PRAGMA synchronous=FULL")
                    database.execute("CREATE TABLE entries (message_id TEXT PRIMARY KEY, nonce_key TEXT UNIQUE NOT NULL, "
                                     "record_sha256 TEXT NOT NULL)")
                    database.execute("PRAGMA user_version=1")
                    for path in self.directory.glob("messages/*/*.json"):
                        message_id = "sha256:" + path.stem
                        raw, record = self._message_evidence(message_id)
                        if raw is None or path != self._message_path(message_id):
                            raise ProcessedArchiveCorrupt("legacy archive message location differs")
                        database.execute("INSERT INTO entries VALUES (?, ?, ?)",
                                         (message_id, self._nonce_key(record["sender_did"], record["nonce"]),
                                          sha256(raw).hexdigest()))
                    for path in self.directory.glob("nonces/*/*.json"):
                        raw = self._read(path)
                        if raw is None:
                            raise ProcessedArchiveCorrupt("legacy archive nonce pointer is missing")
                        pointer = self._decode(raw)
                        if set(pointer) != {"message_id", "record_sha256"}:
                            raise ProcessedArchiveCorrupt("invalid legacy archive nonce pointer")
                        row = database.execute("SELECT nonce_key, record_sha256 FROM entries WHERE message_id=?",
                                               (pointer["message_id"],)).fetchone()
                        if row != (path.stem, pointer["record_sha256"]) or path.parent.name != path.stem[:2]:
                            raise ProcessedArchiveCorrupt("legacy archive nonce pointer lacks matching evidence")
            metadata = check_independent_file(temporary)
            if (metadata.st_dev, metadata.st_ino) != (owned.st_dev, owned.st_ino):
                raise ProcessedArchiveCorrupt("completed archive catalog changed before publication")
            with open_independent_file(temporary, "r+b") as handle:
                os.fsync(handle.fileno())
            if check_independent_file(self.catalog_path, missing_ok=True) is not None:
                raise ProcessedArchiveCorrupt("completed archive catalog already exists")
            os.replace(temporary, self.catalog_path)
            if os.name != "nt":
                parent_fd = os.open(self.directory, os.O_RDONLY)
                try:
                    os.fsync(parent_fd)
                finally:
                    os.close(parent_fd)
        except (ValueError, sqlite3.DatabaseError) as exc:
            raise ProcessedArchiveCorrupt("cannot initialize completed archive catalog") from exc
        self.require_catalog()

    def _catalog_row(self, column: str, value: str) -> tuple | None:
        query = {"message_id": "SELECT message_id, nonce_key, record_sha256 FROM entries WHERE message_id=?",
                 "nonce_key": "SELECT message_id, nonce_key, record_sha256 FROM entries WHERE nonce_key=?"}[column]
        with self._database() as database:
            return database.execute(query, (value,)).fetchone()

    def _catalog_retain(self, record: dict, raw: bytes) -> None:
        row = (record["message_id"], self._nonce_key(record["sender_did"], record["nonce"]), sha256(raw).hexdigest())
        with self._database() as database, database:
            existing = database.execute("SELECT message_id, nonce_key, record_sha256 FROM entries "
                                        "WHERE message_id=? OR nonce_key=?", row[:2]).fetchall()
            if existing:
                if existing != [row]:
                    raise ProcessedArchiveCorrupt("completed archive catalog binding differs")
                return
            database.execute("INSERT INTO entries VALUES (?, ?, ?)", row)

    def _read(self, path: Path) -> bytes | None:
        try:
            with open_independent_file(path, "rb") as handle:
                raw = handle.read(MAX_RECORD_BYTES + 1)
        except FileNotFoundError:
            return None
        except ValueError as exc:
            raise ProcessedArchiveCorrupt("completed archive path is unsafe") from exc
        if len(raw) > MAX_RECORD_BYTES:
            raise ProcessedArchiveCorrupt("completed archive record exceeds the byte limit")
        return raw

    @staticmethod
    def _decode(raw: bytes) -> dict:
        try:
            value = json.loads(raw)
            if not isinstance(value, dict) or canonical_json(value) != raw:
                raise ValueError("not a canonical object")
            return value
        except (TypeError, ValueError, RecursionError) as exc:
            raise ProcessedArchiveCorrupt("invalid completed archive record") from exc

    def _retain(self, path: Path, raw: bytes) -> None:
        if len(raw) > MAX_RECORD_BYTES:
            raise ProcessedArchiveCorrupt("completed archive record exceeds the byte limit")
        existing = self._read(path)
        if existing is not None:
            if existing != raw:
                raise ProcessedArchiveCorrupt("completed archive binding differs")
            return
        try:
            atomic_write_bytes(path, raw, reject_links=True)
        except ValueError as exc:
            raise ProcessedArchiveCorrupt("completed archive path is unsafe") from exc

    def store(self, record: dict) -> None:
        raw = canonical_json(record)
        message_id = record["message_id"]
        # Write the evidence before its lookup pointer. A crash between writes
        # leaves pending work intact; exact retry repairs the missing pointer.
        self._retain(self._message_path(message_id), raw)
        self._retain(self._nonce_path(record["sender_did"], record["nonce"]), canonical_json({
            "message_id": message_id, "record_sha256": sha256(raw).hexdigest(),
        }))
        self._catalog_retain(record, raw)

    def _message_evidence(self, message_id: str) -> tuple[bytes | None, dict | None]:
        raw = self._read(self._message_path(message_id))
        if raw is None:
            return None, None
        record = self._decode(raw)
        if (
            set(record) != {"message_id", "sender_did", "nonce", "at_ms", "envelope_sha256", "envelope_json"}
            or record["message_id"] != message_id
            or not isinstance(record["sender_did"], str) or not isinstance(record["nonce"], str)
            or type(record["at_ms"]) is not int or record["at_ms"] < 0
            or not (record["envelope_json"] is None or isinstance(record["envelope_json"], str))
            or not (record["envelope_sha256"] is None or isinstance(record["envelope_sha256"], str))
        ):
            raise ProcessedArchiveCorrupt("completed archive fields differ")
        pointer = self._read(self._nonce_path(record["sender_did"], record["nonce"]))
        if pointer != canonical_json({"message_id": message_id, "record_sha256": sha256(raw).hexdigest()}):
            raise ProcessedArchiveCorrupt("completed archive nonce pointer differs")
        return raw, record

    def message(self, message_id: str) -> dict | None:
        row = self._catalog_row("message_id", message_id)
        raw, record = self._message_evidence(message_id)
        if row is None and raw is None:
            return None
        if record is None or row != (message_id, self._nonce_key(record["sender_did"], record["nonce"]),
                                     sha256(raw).hexdigest()):
            raise ProcessedArchiveCorrupt("completed archive catalog lacks matching evidence")
        return record

    def nonce_message(self, sender: str, nonce: str) -> str | None:
        row = self._catalog_row("nonce_key", self._nonce_key(sender, nonce))
        raw = self._read(self._nonce_path(sender, nonce))
        if raw is None:
            if row is not None:
                raise ProcessedArchiveCorrupt("completed archive nonce pointer is missing")
            return None
        pointer = self._decode(raw)
        if set(pointer) != {"message_id", "record_sha256"}:
            raise ProcessedArchiveCorrupt("invalid completed archive nonce pointer")
        if row != (pointer["message_id"], self._nonce_key(sender, nonce), pointer["record_sha256"]):
            raise ProcessedArchiveCorrupt("completed archive nonce pointer differs from catalog")
        try:
            record = self.message(pointer["message_id"])
        except ValueError as exc:
            raise ProcessedArchiveCorrupt("invalid archived nonce address") from exc
        if record is None or (record["sender_did"], record["nonce"]) != (sender, nonce):
            raise ProcessedArchiveCorrupt("completed archive nonce lacks matching evidence")
        return record["message_id"]
