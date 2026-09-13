"""Signed file-bundle transport, the cheapest true-offline baseline.

One ``send`` writes ONE self-contained bundle file into the exchange
directory::

    {"protocol":   "nth-delivery-file-bundle",
     "version":    1,
     "sender_did": "did:key:...",
     "created_at_ms": 1750000000000,
     "envelopes":  ["<canonical envelope json>", ...],
     "envelopes_sha256": "sha256:<digest over the concatenated lines>",
     "signature":  "<b64url Ed25519 by sender_did>"}

``poll`` scans the exchange directory, verifies the bundle signature and
every envelope digest, and leases parsed envelopes. ``poll_into`` is the
durable production path: it persists each envelope in DeliveryInbox before
committing the import journal. A crash in between safely redelivers after the
lease expires, and the inbox turns that into an idempotent duplicate.

Threat model notes (design doc §10): a hostile courier can drop, duplicate,
reorder, or corrupt bundles — duplication is handled by the import journal,
corruption by digest/signature checks, dropping is inherent to store-and-
carry and surfaced as non-delivery, not as an error.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Union

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.envelope import (
    MAX_ENVELOPE_BYTES,
    MAX_SAFE_INTEGER,
    TransportEnvelope,
    TransportEnvelopeRejected,
    validate_envelope,
)
from nth_dao.delivery.inbox import DeliveryInbox, InboxDecision
from nth_dao.delivery.transports.base import (
    PRIVACY_LOCAL,
    SendResult,
    Transport,
    TransportCapabilities,
)
from nth_dao.did_key import (
    DIDKeyError,
    decode_ed25519_did_key,
    decode_ed25519_did_key_hex,
    is_did_key,
)
from nth_dao.identity import _NACL_AVAILABLE, AgentIdentity
from nth_dao.util.io import InterProcessLock

try:
    from nacl.exceptions import BadSignatureError as _BadSignatureError
    from nacl.signing import VerifyKey as _VerifyKey
except ImportError:  # pragma: no cover
    _BadSignatureError = ValueError  # type: ignore[assignment,misc]
    _VerifyKey = None  # type: ignore[assignment]

logger = logging.getLogger("nth_dao.delivery")

BUNDLE_PROTOCOL = "nth-delivery-file-bundle"
BUNDLE_VERSION = 1
BUNDLE_SUFFIX = ".nthbundle"
BUNDLE_MAX_BUNDLES_PER_DIR = 4_096
BUNDLE_MAX_DIRECTORY_ENTRIES = BUNDLE_MAX_BUNDLES_PER_DIR + 128
BUNDLE_MAX_ENVELOPES = 256
BUNDLE_MAX_FILE_BYTES = 64 * 1024 * 1024
_IMPORTED_JOURNAL = "imported.jsonl"
_IMPORTED_JOURNAL_CAP = 1024 * 1024
_IMPORTED_EVENT_MAX_BYTES = 4 * 1024
DEFAULT_IMPORT_LEASE_MS = 300_000
MAX_IMPORT_LEASE_MS = 86_400_000

_BUNDLE_FIELDS = (
    "protocol",
    "version",
    "sender_did",
    "created_at_ms",
    "envelopes",
    "envelopes_sha256",
    "signature",
)
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class FileBundleRejected(ValueError):
    """Raised when a bundle cannot be built, signed, or verified."""


def _bundle_body(bundle: dict) -> dict:
    return {key: value for key, value in bundle.items() if key != "signature"}


def _envelopes_digest(envelope_jsons: List[str]) -> str:
    hasher = hashlib.sha256()
    for envelope_json in envelope_jsons:
        hasher.update(envelope_json.encode("utf-8"))
        hasher.update(b"\n")
    return "sha256:" + hasher.hexdigest()


def _validated_clock_ms(clock: Callable[[], int]) -> int:
    value = clock()
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 < value <= MAX_SAFE_INTEGER
    ):
        raise FileBundleRejected("clock must return a positive safe integer in milliseconds")
    return value


def _lease_deadline(now_ms: int, lease_ms: int) -> int:
    if now_ms > MAX_SAFE_INTEGER - lease_ms:
        raise FileBundleRejected("import lease expiry exceeds the safe integer range")
    return now_ms + lease_ms


class FileBundleTransport(Transport):
    """Exchange-directory transport for offline, human-carried delivery."""

    def __init__(
        self,
        exchange_dir: Union[str, Path],
        identity: AgentIdentity,
        *,
        state_dir: Optional[Union[str, Path]] = None,
        clock: Optional[Callable[[], int]] = None,
        name: str = "file-bundle",
    ) -> None:
        if not _NACL_AVAILABLE or _VerifyKey is None:
            raise FileBundleRejected("crypto unavailable: PyNaCl is required")
        self._exchange_dir = Path(exchange_dir)
        self._state_dir = Path(state_dir) if state_dir else self._exchange_dir / ".state"
        self._imported_path = self._state_dir / _IMPORTED_JOURNAL
        self._identity = identity
        self._clock = clock or (lambda: int(time.time() * 1000))
        self._lock = threading.RLock()
        self._imported: set[str] = set()
        self._leases: Dict[str, int] = {}
        self._imported_stat: Optional[tuple] = None
        self.capabilities = TransportCapabilities(
            name=name,
            unicast=False,
            broadcast=True,
            realtime=False,
            privacy_level=PRIVACY_LOCAL,
            external_infrastructure=False,
            ack_mode="none",
        )
        self._exchange_dir.mkdir(parents=True, exist_ok=True)
        self._state_dir.mkdir(parents=True, exist_ok=True)
        with InterProcessLock(self._imported_path):
            self._load_imported()

    # ─────────────────────── Transport API ───────────────────────

    def send(self, envelope: TransportEnvelope) -> SendResult:
        if not isinstance(envelope, TransportEnvelope):
            return SendResult(accepted=False, error_code="invalid-envelope")
        try:
            stable_envelope = TransportEnvelope.from_dict(
                TransportEnvelope.to_dict(envelope)
            )
        except Exception:  # noqa: BLE001 - hostile mutable input fails closed
            return SendResult(accepted=False, error_code="invalid-envelope")
        ok, reason = validate_envelope(stable_envelope, require_signature=True)
        if not ok:
            return SendResult(accepted=False, error_code="invalid-envelope")
        try:
            bundle = self._build_bundle([stable_envelope])
        except FileBundleRejected as exc:
            return SendResult(accepted=False, error_code=f"bundle-error: {exc}")
        try:
            self._write_bundle(bundle)
        except OSError as exc:
            logger.warning("file bundle write failed: %s", exc)
            return SendResult(accepted=False, error_code="exchange-dir-unwritable")
        return SendResult(accepted=True)

    def poll(
        self,
        *,
        max_items: int = 64,
        lease_ms: int = DEFAULT_IMPORT_LEASE_MS,
    ) -> List[TransportEnvelope]:
        """Lease verified envelopes; callers must commit durable intake.

        Prefer :meth:`poll_into`. Direct callers must call ``commit_import``
        only after their own durable intake succeeds. An uncommitted lease is
        eligible for redelivery after ``lease_ms``.
        """

        if isinstance(max_items, bool) or not isinstance(max_items, int) or max_items < 1:
            raise ValueError("max_items must be a positive integer")
        if (
            isinstance(lease_ms, bool)
            or not isinstance(lease_ms, int)
            or not 1 <= lease_ms <= MAX_IMPORT_LEASE_MS
        ):
            raise ValueError(
                f"lease_ms must be within [1, {MAX_IMPORT_LEASE_MS}]"
            )
        now_ms = _validated_clock_ms(self._clock)
        lease_deadline_ms = _lease_deadline(now_ms, lease_ms)
        envelopes: List[TransportEnvelope] = []
        bundle_paths = self._bounded_bundle_paths()
        if bundle_paths is None:
            return []
        for bundle_path in bundle_paths:
            if len(envelopes) >= max_items:
                break
            try:
                # stat BEFORE read: a hostile courier can drop arbitrarily
                # large files; never pull one into memory unread
                if bundle_path.stat().st_size > BUNDLE_MAX_FILE_BYTES:
                    logger.warning("bundle %s exceeds the size limit; skipping", bundle_path.name)
                    continue
                with open(bundle_path, "rb") as handle:
                    raw = handle.read(BUNDLE_MAX_FILE_BYTES + 1)
                # The bounded read also catches replacement/growth between
                # the directory stat and opening the file.
                if len(raw) > BUNDLE_MAX_FILE_BYTES:
                    logger.warning("bundle %s grew past the size limit; skipping", bundle_path.name)
                    continue
            except OSError as exc:
                logger.warning("cannot read bundle %s: %s", bundle_path.name, exc)
                continue
            try:
                bundle = json.loads(raw.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                logger.warning("bundle %s is not valid JSON; skipping", bundle_path.name)
                continue
            digest = self._verify_bundle(bundle)
            if digest is None:
                continue
            for envelope_json in bundle["envelopes"]:
                if len(envelopes) >= max_items:
                    break
                try:
                    parsed = json.loads(envelope_json)
                    envelope = TransportEnvelope.from_dict(parsed)
                except (json.JSONDecodeError, TransportEnvelopeRejected, TypeError):
                    logger.warning("bundle %s holds a malformed envelope; skipping it", bundle_path.name)
                    continue
                with self._lock:
                    with InterProcessLock(self._imported_path):
                        self._refold_imported_if_changed()
                        # Legacy journals recorded the whole bundle digest;
                        # new journals record each message independently so
                        # max_items pagination cannot discard the tail.
                        if digest in self._imported:
                            break
                        if envelope.message_id in self._imported:
                            continue
                        lease_expires_at_ms = self._leases.get(envelope.message_id, 0)
                        if lease_expires_at_ms > now_ms:
                            continue
                        lease_expires_at_ms = lease_deadline_ms
                        self._append_import_event_locked(
                            {
                                "event": "leased",
                                "message_id": envelope.message_id,
                                "at_ms": now_ms,
                                "lease_expires_at_ms": lease_expires_at_ms,
                            }
                        )
                        self._leases[envelope.message_id] = lease_expires_at_ms
                        self._compact_import_journal_if_needed_locked(now_ms=now_ms)
                envelopes.append(envelope)
        return envelopes

    def _bounded_bundle_paths(self) -> Optional[List[Path]]:
        """List regular bundle files without unbounded directory materialization."""

        paths: List[Path] = []
        entry_count = 0
        try:
            with os.scandir(self._exchange_dir) as entries:
                for entry in entries:
                    entry_count += 1
                    if entry_count > BUNDLE_MAX_DIRECTORY_ENTRIES:
                        logger.warning(
                            "bundle exchange directory exceeds the %d entry limit; refusing poll",
                            BUNDLE_MAX_DIRECTORY_ENTRIES,
                        )
                        return None
                    if not entry.name.endswith(BUNDLE_SUFFIX):
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        logger.warning(
                            "bundle path %s is not a regular file; skipping",
                            entry.name,
                        )
                        continue
                    paths.append(Path(entry.path))
                    if len(paths) > BUNDLE_MAX_BUNDLES_PER_DIR:
                        logger.warning(
                            "bundle exchange directory exceeds the %d bundle limit; refusing poll",
                            BUNDLE_MAX_BUNDLES_PER_DIR,
                        )
                        return None
        except OSError as exc:
            logger.warning("cannot scan bundle exchange directory: %s", exc)
            return None
        paths.sort()
        return paths

    def commit_import(self, message_id: str) -> bool:
        """Commit one lease after downstream durable intake; idempotent."""

        if not isinstance(message_id, str) or _SHA256_RE.fullmatch(message_id) is None:
            raise ValueError("message_id must be a sha256 content address")
        now_ms = _validated_clock_ms(self._clock)
        with self._lock:
            with InterProcessLock(self._imported_path):
                self._refold_imported_if_changed()
                if message_id in self._imported:
                    return False
                if message_id not in self._leases:
                    raise FileBundleRejected("cannot commit an envelope without an import lease")
                if self._leases[message_id] <= now_ms:
                    raise FileBundleRejected("cannot commit an expired import lease")
                self._append_import_event_locked(
                    {
                        "event": "committed",
                        "message_id": message_id,
                        "at_ms": now_ms,
                    }
                )
                self._leases.pop(message_id, None)
                self._imported.add(message_id)
                self._compact_import_journal_if_needed_locked(now_ms=now_ms)
                return True

    def poll_into(
        self,
        inbox: DeliveryInbox,
        *,
        max_items: int = 64,
        lease_ms: int = DEFAULT_IMPORT_LEASE_MS,
    ) -> List[InboxDecision]:
        """Persist leased envelopes in ``inbox`` before committing imports."""

        if not isinstance(inbox, DeliveryInbox):
            raise TypeError("inbox must be a DeliveryInbox")
        decisions: List[InboxDecision] = []
        for envelope in self.poll(max_items=max_items, lease_ms=lease_ms):
            decision = inbox.accept(envelope)
            decisions.append(decision)
            if decision.accepted or decision.duplicate or not decision.retryable:
                self.commit_import(envelope.message_id)
        return decisions

    def health(self):
        from nth_dao.delivery.transports.base import TransportHealth

        return TransportHealth(reachable=self._exchange_dir.exists())

    # ─────────────────────── bundle internals ───────────────────────

    def _build_bundle(self, envelopes: List[TransportEnvelope]) -> dict:
        envelope_jsons: List[str] = []
        for envelope in envelopes:
            envelope_jsons.append(canonical_json(envelope.to_dict()).decode("utf-8"))
        if not envelope_jsons or len(envelope_jsons) > BUNDLE_MAX_ENVELOPES:
            raise FileBundleRejected("bundle must hold 1..256 envelopes")
        for envelope_json in envelope_jsons:
            if len(envelope_json.encode("utf-8")) > MAX_ENVELOPE_BYTES:
                raise FileBundleRejected("envelope exceeds the wire limit")
        now_ms = _validated_clock_ms(self._clock)
        bundle = {
            "protocol": BUNDLE_PROTOCOL,
            "version": BUNDLE_VERSION,
            "sender_did": self._identity.as_did(),
            "created_at_ms": now_ms,
            "envelopes": envelope_jsons,
            "envelopes_sha256": _envelopes_digest(envelope_jsons),
        }
        bundle["signature"] = b64u_encode(
            self._identity.sign(canonical_json(_bundle_body(bundle)))
        )
        return bundle

    def _write_bundle(self, bundle: dict) -> None:
        stamp = bundle["created_at_ms"]
        nonce = bundle["envelopes_sha256"][-12:]
        path = self._exchange_dir / f"bundle-{stamp}-{nonce}{BUNDLE_SUFFIX}"
        # unique tmp name: two processes must never share one temp file
        tmp = self._exchange_dir / (
            f".tmp-{stamp}-{nonce}-{os.getpid()}-{secrets.token_hex(4)}"
        )
        try:
            with open(tmp, "wb") as handle:
                handle.write(canonical_json(bundle))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
        except OSError:
            tmp.unlink(missing_ok=True)
            raise

    def _verify_bundle(self, bundle: object) -> Optional[str]:
        """Verify one parsed bundle; returns its digest, or None (with log)."""

        if not isinstance(bundle, dict) or frozenset(bundle) != frozenset(_BUNDLE_FIELDS):
            logger.warning("bundle has missing or unknown fields; rejecting")
            return None
        version = bundle["version"]
        if (
            isinstance(version, bool)
            or not isinstance(version, int)
            or bundle["protocol"] != BUNDLE_PROTOCOL
            or version != BUNDLE_VERSION
        ):
            logger.warning("bundle protocol/version mismatch; rejecting")
            return None
        sender_did = bundle["sender_did"]
        if not is_did_key(sender_did) or not isinstance(sender_did, str):
            logger.warning("bundle sender_did invalid; rejecting")
            return None
        try:
            decode_ed25519_did_key(sender_did)
        except (DIDKeyError, ValueError, TypeError):
            logger.warning("bundle sender_did undecodable; rejecting")
            return None
        created_at_ms = bundle["created_at_ms"]
        if (
            isinstance(created_at_ms, bool)
            or not isinstance(created_at_ms, int)
            or not 0 < created_at_ms <= MAX_SAFE_INTEGER
        ):
            logger.warning("bundle created_at_ms invalid; rejecting")
            return None
        envelopes = bundle["envelopes"]
        if not isinstance(envelopes, list) or not envelopes or len(envelopes) > BUNDLE_MAX_ENVELOPES:
            logger.warning("bundle envelope list invalid; rejecting")
            return None
        for envelope_json in envelopes:
            if (
                not isinstance(envelope_json, str)
                or len(envelope_json.encode("utf-8")) > MAX_ENVELOPE_BYTES
            ):
                logger.warning("bundle holds an oversized envelope; rejecting")
                return None
            try:
                parsed = json.loads(envelope_json)
                envelope = TransportEnvelope.from_dict(parsed)
            except (json.JSONDecodeError, TypeError, ValueError, RecursionError):
                logger.warning("bundle holds a malformed envelope; rejecting")
                return None
            if canonical_json(envelope.to_dict()).decode("utf-8") != envelope_json:
                logger.warning("bundle envelope is not canonical JSON; rejecting")
                return None
            ok, _reason = validate_envelope(envelope, require_signature=True)
            if not ok:
                logger.warning("bundle holds an invalid envelope; rejecting")
                return None
        if bundle["envelopes_sha256"] != _envelopes_digest(envelopes):
            logger.warning("bundle digest mismatch; rejecting")
            return None
        if not _NACL_AVAILABLE or _VerifyKey is None:  # pragma: no cover
            logger.warning("crypto unavailable; rejecting bundle")
            return None
        try:
            signature = b64u_decode(bundle["signature"])
            if len(signature) != 64 or b64u_encode(signature) != bundle["signature"]:
                raise FileBundleRejected("bad signature encoding")
            key_hex = decode_ed25519_did_key_hex(sender_did) or ""
            _VerifyKey(bytes.fromhex(key_hex)).verify(
                canonical_json(_bundle_body(bundle)), signature,
            )
        except (_BadSignatureError, TypeError, ValueError, UnicodeError, DIDKeyError):
            logger.warning("bundle signature verification failed; rejecting")
            return None
        return bundle["envelopes_sha256"]

    def _load_imported(self) -> None:
        if not self._imported_path.exists():
            self._imported_stat = None
            return
        with open(self._imported_path, "rb") as handle:
            stat = os.fstat(handle.fileno())
            self._imported_stat = (stat.st_mtime_ns, stat.st_size)
            while True:
                line = handle.readline(_IMPORTED_EVENT_MAX_BYTES + 1)
                if not line:
                    break
                if len(line) > _IMPORTED_EVENT_MAX_BYTES:
                    raise FileBundleRejected("import journal event exceeds the byte limit")
                if not line.endswith(b"\n"):
                    logger.warning("import journal has a torn final line; ignoring it")
                    break
                if not line.strip():
                    continue
                self._fold_import_event(line)

    def _fold_import_event(self, line: bytes) -> None:
        try:
            event = json.loads(line.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise FileBundleRejected(f"corrupt import journal: {exc}") from exc
        if not isinstance(event, dict):
            raise FileBundleRejected("import journal event must be an object")
        event_name = event.get("event")
        if event_name is None:
            valid_legacy_fields = (
                frozenset({"message_id", "at_ms"}),
                frozenset({"envelopes_sha256", "at_ms"}),
            )
            if frozenset(event) not in valid_legacy_fields:
                raise FileBundleRejected("legacy import journal fields are invalid")
        elif event_name == "leased":
            if frozenset(event) != frozenset(
                {"event", "message_id", "at_ms", "lease_expires_at_ms"}
            ):
                raise FileBundleRejected("import lease event fields are invalid")
        elif event_name == "committed":
            if frozenset(event) != frozenset({"event", "message_id", "at_ms"}):
                raise FileBundleRejected("import commit event fields are invalid")
        else:
            raise FileBundleRejected("import journal event is unsupported")

        digest = event.get("message_id", event.get("envelopes_sha256"))
        if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
            raise FileBundleRejected("import journal digest invalid")
        at_ms = event.get("at_ms")
        if (
            isinstance(at_ms, bool)
            or not isinstance(at_ms, int)
            or not 0 < at_ms <= MAX_SAFE_INTEGER
        ):
            raise FileBundleRejected("import journal timestamp is invalid")
        if event_name is None:
            # v1 journals only contained terminal import records.
            self._imported.add(digest)
            self._leases.pop(digest, None)
        elif event_name == "leased":
            lease_expires_at_ms = event.get("lease_expires_at_ms")
            if (
                isinstance(lease_expires_at_ms, bool)
                or not isinstance(lease_expires_at_ms, int)
                or not 0 < lease_expires_at_ms <= MAX_SAFE_INTEGER
                or lease_expires_at_ms <= at_ms
            ):
                raise FileBundleRejected("import lease expiry is invalid")
            if digest not in self._imported:
                self._leases[digest] = lease_expires_at_ms
        else:
            self._leases.pop(digest, None)
            self._imported.add(digest)

    def _refold_imported_if_changed(self) -> None:
        """Re-fold the import journal when another process imported into the
        shared state dir (same stat-check pattern as inbox/outbox)."""

        try:
            if not self._imported_path.exists():
                return
            stat = self._imported_path.stat()
        except OSError:
            return
        current = (stat.st_mtime_ns, stat.st_size)
        if current != self._imported_stat:
            self._imported = set()
            self._leases = {}
            self._load_imported()

    def _append_import_event_locked(self, event: dict) -> None:
        with open(self._imported_path, "ab") as handle:
            handle.write(canonical_json(event) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
            stat = os.fstat(handle.fileno())
            self._imported_stat = (stat.st_mtime_ns, stat.st_size)

    def _compact_import_journal_if_needed_locked(self, *, now_ms: int) -> None:
        if self._imported_path.stat().st_size <= _IMPORTED_JOURNAL_CAP:
            return
        tmp = self._imported_path.with_suffix(
            f".jsonl.{os.getpid()}-{secrets.token_hex(4)}.tmp"
        )
        self._leases = {
            message_id: lease_expires_at_ms
            for message_id, lease_expires_at_ms in self._leases.items()
            if message_id not in self._imported and lease_expires_at_ms > now_ms
        }
        try:
            with open(tmp, "wb") as handle:
                for message_id in sorted(self._imported):
                    handle.write(
                        canonical_json(
                            {
                                "event": "committed",
                                "message_id": message_id,
                                "at_ms": now_ms,
                            }
                        )
                        + b"\n"
                    )
                for message_id, lease_expires_at_ms in sorted(self._leases.items()):
                    if message_id in self._imported:
                        continue
                    handle.write(
                        canonical_json(
                            {
                                "event": "leased",
                                "message_id": message_id,
                                "at_ms": now_ms,
                                "lease_expires_at_ms": lease_expires_at_ms,
                            }
                        )
                        + b"\n"
                    )
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self._imported_path)
        except OSError:
            tmp.unlink(missing_ok=True)
            raise
        stat = self._imported_path.stat()
        self._imported_stat = (stat.st_mtime_ns, stat.st_size)
        logger.warning(
            "import journal exceeded %d bytes; compacted to %d committed and %d leased entries",
            _IMPORTED_JOURNAL_CAP,
            len(self._imported),
            len(self._leases),
        )


__all__ = [
    "BUNDLE_MAX_ENVELOPES",
    "BUNDLE_MAX_BUNDLES_PER_DIR",
    "BUNDLE_MAX_DIRECTORY_ENTRIES",
    "BUNDLE_PROTOCOL",
    "BUNDLE_VERSION",
    "DEFAULT_IMPORT_LEASE_MS",
    "FileBundleRejected",
    "FileBundleTransport",
]
