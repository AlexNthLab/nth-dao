"""Claim intent — the offline-safe claim lifecycle from design doc §7.1.

The existing market claim path (``claim_announcement`` /
``record_foreign_claim``) is the CAS authority: exactly one winner per
announcement. What travels badly offline is the *intent*: an agent that
cannot reach the authority still wants to declare, sign, and carry "I
intend to claim this task" — explicitly WITHOUT reserving it — and the
UI must distinguish 待确认 (pending) from 已确认 (confirmed).

This module adds that lifecycle layer on top of the borrowed authority:

* :func:`sign_claim_intent` — the claimant signs a small intent object
  offline (announcement binding, claimant DID, cap-token id, nonce, TTL).
  An intent is NEVER authority: it does not reserve, does not win races,
  and expires on its own clock.
* :func:`verify_claim_intent` — fail-closed wire validation (exact field
  set, Ed25519 signature against the embedded claimant DID, TTL window,
  safe integers, nonce format).
* :func:`admit_claim_intent` — authority side: verifies the intent, binds
  it to the accompanying pre-signed receipt (same announcement AND same
  claimant — a fresh intent cannot be paired with a stale receipt to
  dodge the authority skew window), then delegates to the borrowed
  ``record_foreign_claim`` CAS. Accepts → ClaimOutcome; loses the race →
  ClaimConflict; anything else → ClaimRejected.
* :class:`IntentTracker` — claimant-side, journal-backed pending/
  confirmed/rejected/expired tracking so hosts can render the design
  doc's mandated UI distinction and sweep stale intents after TTL.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import stat as stat_module
import threading
import time
from contextlib import closing
from copy import deepcopy
from pathlib import Path
from typing import Any

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import (
    DIDKeyError,
    decode_ed25519_did_key_hex,
    is_did_key,
)
from nth_dao.execution_receipt import verify_receipt
from nth_dao.identity import _NACL_AVAILABLE, AgentIdentity
from nth_dao.market.announcement import (
    TaskAnnouncement,
    announcement_federation_key,
    verify_announcement,
)
from nth_dao.market.claim import (
    ClaimOutcome,
    ClaimRejected,
    MAX_FOREIGN_CLAIM_CLOCK_SKEW_MS,
    _claim_timeline,
    record_foreign_claim,
)
from nth_dao.util.io import InterProcessLock, atomic_write_bytes

try:  # pragma: no cover - exercised via importorskip in tests
    from nacl.exceptions import BadSignatureError as _BadSignatureError
    from nacl.signing import VerifyKey as _VerifyKey
except ImportError:  # pragma: no cover
    _BadSignatureError = ValueError  # type: ignore[assignment]
    _VerifyKey = None  # type: ignore[assignment]

logger = logging.getLogger("nth_dao.market")

INTENT_KIND = "nth-market-claim-intent"
INTENT_VERSION = 1
INTENT_FIELDS = frozenset(
    {
        "kind",
        "version",
        "announcement_id",
        "claimant_did",
        "cap_token_id",
        "nonce",
        "created_at_ms",
        "expires_at_ms",
        "signature",
    }
)
DEFAULT_INTENT_TTL_MS = 30 * 60 * 1000  # 30 minutes
MAX_INTENT_TTL_MS = 24 * 60 * 60 * 1000  # 1 day
INTENT_MAX_CLOCK_SKEW_MS = 5 * 60 * 1000
MAX_SAFE_INTEGER = (1 << 53) - 1

REJECT_INTENT_MALFORMED = "intent-malformed"
REJECT_INTENT_SIGNATURE = "intent-signature-invalid"
REJECT_INTENT_EXPIRED = "intent-expired"
REJECT_INTENT_FUTURE = "intent-created-in-future"
REJECT_INTENT_BINDING = "intent-binding-mismatch"

_NONCE_RE = re.compile(r"^[A-Za-z0-9]{16,64}$")
# Keep this wire constraint aligned with ``TaskAnnouncement``.  Announcement
# IDs are local namespace identifiers and the federation layer qualifies them
# with a content digest; claim intents must not reject an ID that the
# announcement protocol accepts.
_ANN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_TOKEN_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,128}$")

_JOURNAL = "claim-intents.jsonl"
_RECEIPT_DIR = "claim-receipts"
_RECEIPT_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_ARCHIVE_DIR = "claim-intents-archive"
_ARCHIVE_NAME_RE = re.compile(r"^claim-intents-([0-9a-f]{64})\.jsonl$")
_ARCHIVE_INDEX = "index.sqlite3"
_TRACKER_EVENTS = (
    "sent", "receipt-retained", "confirmed", "rejected", "expired", "reconciled",
)
_TRACKER_SENT_FIELDS_V1 = frozenset({"event", "nonce", "intent"})
_TRACKER_SENT_FIELDS_V2 = frozenset(
    {"event", "nonce", "intent", "receipt_id", "receipt_hash"}
)
_TRACKER_SENT_FIELDS_V3 = _TRACKER_SENT_FIELDS_V2 | {
    "source_peer",
    "source_did",
    "federation_key",
}
_TRACKER_SENT_FIELDS_V4 = _TRACKER_SENT_FIELDS_V2 | {"receipt_retained"}
_TRACKER_SENT_FIELDS_V5 = _TRACKER_SENT_FIELDS_V3 | {"receipt_retained"}
_TRACKER_SENT_FIELDS_V6 = _TRACKER_SENT_FIELDS_V5 | {"announcement"}
_TRACKER_TERMINAL_FIELDS = frozenset({"event", "nonce"})
_TRACKER_RECONCILED_FIELDS = frozenset({"event", "nonce", "retry_nonce"})
_TRACKER_RETENTION_FIELDS = frozenset({"event", "nonce", "receipt_hash"})
DEFAULT_MAX_TRACKED_INTENTS = 4_096
MAX_TRACKER_JOURNAL_BYTES = 16 * 1024 * 1024
MAX_TRACKED_RECEIPT_BYTES = 256 * 1024
DEFAULT_MAX_RECEIPT_STORE_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_RECEIPT_FILES = 4_096


class ClaimIntentRejected(ClaimRejected):
    """Intent-specific rejection (distinct reason codes for the UI)."""


class IntentTrackerCorrupt(RuntimeError):
    """Raised when the durable lifecycle journal cannot be trusted."""


class IntentTrackerFull(RuntimeError):
    """Raised when a tracker reaches its configured durable capacity."""


class IntentReceiptStoreFull(IntentTrackerFull):
    """Raised when retained Receipt files reach their local quota."""


def _read_bounded_regular_file(path: Path, maximum: int, label: str) -> bytes:
    """Check and read the same regular-file descriptor, with a hard byte cap."""

    if path.is_symlink():
        raise IntentTrackerCorrupt(f"{label} is a symlink")
    before = os.stat(path, follow_symlinks=False)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        after = os.stat(path, follow_symlinks=False)
        if (
            not stat_module.S_ISREG(opened.st_mode)
            or not stat_module.S_ISREG(before.st_mode)
            or not stat_module.S_ISREG(after.st_mode)
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise IntentTrackerCorrupt(f"{label} entry is unsafe")
        if opened.st_size > maximum:
            raise IntentTrackerCorrupt(f"{label} exceeds size limit")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > maximum:
            raise IntentTrackerCorrupt(f"{label} exceeds size limit")
        return raw
    finally:
        os.close(fd)


def _read_archive_segment(path: Path) -> bytes:
    """Bound one immutable segment read to the journal's maximum size."""

    try:
        return _read_bounded_regular_file(
            path, MAX_TRACKER_JOURNAL_BYTES, "claim-intent archive",
        )
    except OSError as exc:
        raise IntentTrackerCorrupt("cannot read claim-intent archive") from exc


def _now_ms() -> int:
    return int(time.time() * 1000)


def sign_claim_intent(
    claimant: AgentIdentity,
    *,
    announcement_id: str,
    cap_token: dict[str, Any],
    created_at_ms: int | None = None,
    ttl_ms: int = DEFAULT_INTENT_TTL_MS,
    nonce: str | None = None,
) -> dict[str, Any]:
    """Sign one offline claim intent (NEVER authority — reserves nothing)."""

    if not isinstance(cap_token, dict):
        raise ClaimIntentRejected(
            REJECT_INTENT_MALFORMED, "cap_token must be an object"
        )
    claimant_did = claimant.as_did()
    if (
        not isinstance(announcement_id, str)
        or _ANN_ID_RE.fullmatch(announcement_id) is None
    ):
        raise ClaimIntentRejected(REJECT_INTENT_MALFORMED, "announcement_id is invalid")
    if str(cap_token.get("subject_did", "")) != claimant_did:
        raise ClaimIntentRejected(
            REJECT_INTENT_BINDING,
            "cap_token subject must equal the signing claimant",
        )
    cap_token_id = cap_token.get("token_id")
    if (
        not isinstance(cap_token_id, str)
        or _TOKEN_ID_RE.fullmatch(cap_token_id) is None
    ):
        raise ClaimIntentRejected(
            REJECT_INTENT_MALFORMED, "cap_token token_id is invalid"
        )
    if (
        isinstance(ttl_ms, bool)
        or not isinstance(ttl_ms, int)
        or not 1 <= ttl_ms <= MAX_INTENT_TTL_MS
    ):
        raise ClaimIntentRejected(REJECT_INTENT_MALFORMED, "ttl_ms out of range")
    now = created_at_ms if created_at_ms is not None else _now_ms()
    if (
        isinstance(now, bool)
        or not isinstance(now, int)
        or not 0 < now <= MAX_SAFE_INTEGER
        or now + ttl_ms > MAX_SAFE_INTEGER
    ):
        raise ClaimIntentRejected(
            REJECT_INTENT_MALFORMED, "created_at_ms must be positive"
        )
    if nonce is None:
        nonce = b64u_encode(os.urandom(18))[:24].replace("-", "a").replace("_", "b")
    if not isinstance(nonce, str) or _NONCE_RE.fullmatch(nonce) is None:
        raise ClaimIntentRejected(REJECT_INTENT_MALFORMED, "nonce format is invalid")
    intent = {
        "kind": INTENT_KIND,
        "version": INTENT_VERSION,
        "announcement_id": announcement_id,
        "claimant_did": claimant_did,
        "cap_token_id": cap_token_id,
        "nonce": nonce,
        "created_at_ms": now,
        "expires_at_ms": now + ttl_ms,
    }
    body = canonical_json(intent)
    intent["signature"] = b64u_encode(claimant.sign(body))
    ok, reason = verify_claim_intent(intent, now_ms=now)
    if not ok:  # pragma: no cover - defensive self-check
        raise ClaimIntentRejected(reason, "self-check failed")
    return intent


def verify_claim_intent(
    intent: Any,
    *,
    now_ms: int | None = None,
) -> tuple[bool, str]:
    """Fail-closed intent validation: (ok, reason)."""

    if not isinstance(intent, dict) or frozenset(intent) != INTENT_FIELDS:
        return False, REJECT_INTENT_MALFORMED
    if intent.get("kind") != INTENT_KIND or type(intent.get("version")) is not int:
        return False, REJECT_INTENT_MALFORMED
    if intent["version"] != INTENT_VERSION:
        return False, REJECT_INTENT_MALFORMED
    announcement_id = intent.get("announcement_id")
    if (
        not isinstance(announcement_id, str)
        or _ANN_ID_RE.fullmatch(announcement_id) is None
    ):
        return False, REJECT_INTENT_MALFORMED
    claimant_did = intent.get("claimant_did")
    if not isinstance(claimant_did, str) or not is_did_key(claimant_did):
        return False, REJECT_INTENT_MALFORMED
    cap_token_id = intent.get("cap_token_id")
    if (
        not isinstance(cap_token_id, str)
        or _TOKEN_ID_RE.fullmatch(cap_token_id) is None
    ):
        return False, REJECT_INTENT_MALFORMED
    nonce = intent.get("nonce")
    if not isinstance(nonce, str) or _NONCE_RE.fullmatch(nonce) is None:
        return False, REJECT_INTENT_MALFORMED
    for field in ("created_at_ms", "expires_at_ms"):
        value = intent.get(field)
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 < value <= MAX_SAFE_INTEGER
        ):
            return False, REJECT_INTENT_MALFORMED
    if intent["expires_at_ms"] <= intent["created_at_ms"]:
        return False, REJECT_INTENT_MALFORMED
    if intent["expires_at_ms"] - intent["created_at_ms"] > MAX_INTENT_TTL_MS:
        return False, REJECT_INTENT_MALFORMED
    now = now_ms if now_ms is not None else _now_ms()
    if (
        isinstance(now, bool)
        or not isinstance(now, int)
        or not 0 < now <= MAX_SAFE_INTEGER
    ):
        return False, REJECT_INTENT_MALFORMED
    if now >= intent["expires_at_ms"]:
        return False, REJECT_INTENT_EXPIRED
    if intent["created_at_ms"] > now + INTENT_MAX_CLOCK_SKEW_MS:
        return False, REJECT_INTENT_FUTURE
    if not _NACL_AVAILABLE or _VerifyKey is None:
        return False, REJECT_INTENT_SIGNATURE
    signature_text = intent.get("signature")
    if not isinstance(signature_text, str) or len(signature_text) != 86:
        return False, REJECT_INTENT_SIGNATURE
    try:
        signature = b64u_decode(signature_text)
        if len(signature) != 64 or b64u_encode(signature) != signature_text:
            return False, REJECT_INTENT_SIGNATURE
        body = canonical_json({k: v for k, v in intent.items() if k != "signature"})
        key_hex = decode_ed25519_did_key_hex(claimant_did) or ""
        _VerifyKey(bytes.fromhex(key_hex)).verify(body, signature)
    except (
        _BadSignatureError,
        DIDKeyError,
        KeyError,
        TypeError,
        ValueError,
        UnicodeError,
    ):
        return False, REJECT_INTENT_SIGNATURE
    return True, "ok"


def admit_claim_intent(
    feed: Any,
    claim_store: Any,
    intent: dict[str, Any],
    receipt: dict[str, Any],
    *,
    cap_token: dict[str, Any],
    revoked_ids: set | None = None,
    now_ms_override: int = 0,
    spine: Any = None,
) -> ClaimOutcome:
    """Authority side: verify the intent, bind it to the receipt, run the
    borrowed CAS. Accepted → ClaimOutcome; race lost → ClaimConflict;
    anything else → ClaimRejected/ClaimIntentRejected."""

    if not isinstance(receipt, dict) or not isinstance(cap_token, dict):
        raise ClaimIntentRejected(
            REJECT_INTENT_MALFORMED, "receipt and cap_token must be objects"
        )
    if (
        isinstance(now_ms_override, bool)
        or not isinstance(now_ms_override, int)
        or now_ms_override < 0
        or now_ms_override > MAX_SAFE_INTEGER
    ):
        raise ClaimIntentRejected(REJECT_INTENT_MALFORMED, "authority clock is invalid")
    now = now_ms_override or _now_ms()
    ok, reason = verify_claim_intent(intent, now_ms=now)
    if not ok:
        raise ClaimIntentRejected(reason, "intent failed verification")
    # cross-binding: the intent and the receipt must describe the SAME
    # claim of the SAME announcement by the SAME claimant — otherwise a
    # freshly-signed intent could be paired with a stale receipt (or vice
    # versa) to slip past the authority skew window
    announcement_id = intent["announcement_id"]
    if str(receipt.get("goal_id", "")) != f"market:claim:{announcement_id}":
        raise ClaimIntentRejected(
            REJECT_INTENT_BINDING,
            "receipt goal_id does not bind the intent's announcement",
        )
    if str(receipt.get("signer_did", "")) != intent["claimant_did"]:
        raise ClaimIntentRejected(
            REJECT_INTENT_BINDING,
            "receipt signer does not match the intent claimant",
        )
    # round-24 bug LL-2: the intent self-describes the token it means to
    # claim with — the submitted cap_token must be that token, otherwise the
    # UI/audit trail says token X while the claim actually used token Y
    submitted_token_id = cap_token.get("token_id")
    if intent["cap_token_id"] != submitted_token_id:
        raise ClaimIntentRejected(
            REJECT_INTENT_BINDING,
            "intent cites a different cap_token than the one submitted",
        )
    return record_foreign_claim(
        feed,
        claim_store,
        announcement_id,
        cap_token,
        receipt,
        revoked_ids=revoked_ids,
        now_ms_override=now,
        spine=spine,
    )


class IntentTracker:
    """Claimant-side journal of intent lifecycle (pending → terminal).

    Hosts render 待确认 from ``pending()`` and 已确认/已拒绝/已过期 from
    the terminal states, per design doc §7.1's UI mandate. The journal is
    crash-safe (fsync per event, torn tail tolerated, corruption fails
    closed) and ``sweep_expired`` folds stale pendings after their TTL.
    """

    def __init__(
        self,
        directory: str | Path,
        *,
        max_intents: int = DEFAULT_MAX_TRACKED_INTENTS,
        max_receipt_store_bytes: int = DEFAULT_MAX_RECEIPT_STORE_BYTES,
        max_receipt_files: int = DEFAULT_MAX_RECEIPT_FILES,
    ) -> None:
        if (
            isinstance(max_intents, bool)
            or not isinstance(max_intents, int)
            or max_intents < 1
        ):
            raise ValueError("max_intents must be a positive integer")
        for name, value in (
            ("max_receipt_store_bytes", max_receipt_store_bytes),
            ("max_receipt_files", max_receipt_files),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        self._dir = Path(directory)
        self._journal_path = self._dir / _JOURNAL
        self._dir.mkdir(parents=True, exist_ok=True)
        self._max_intents = max_intents
        self._max_receipt_store_bytes = max_receipt_store_bytes
        self._max_receipt_files = max_receipt_files
        self._thread_lock = threading.RLock()
        self._journal_stat: tuple[int, int] | None = None
        # nonce -> state dict
        self._intents: dict[str, dict[str, Any]] = {}
        with InterProcessLock(self._journal_path):
            self._load_locked()

    def _load_locked(self) -> None:
        self._intents = {}
        self._sync_archive_index_locked()
        if not self._journal_path.exists():
            self._journal_stat = None
            return
        stat = self._journal_path.stat()
        if stat.st_size > MAX_TRACKER_JOURNAL_BYTES:
            raise IntentTrackerCorrupt(
                f"claim-intent journal exceeds {MAX_TRACKER_JOURNAL_BYTES} bytes"
            )
        raw = self._journal_path.read_bytes()
        torn = bool(raw) and not raw.endswith(b"\n")
        if torn:
            complete_size = raw.rfind(b"\n") + 1
            logger.warning(
                "claim-intent journal torn tail; truncating %d byte(s)",
                len(raw) - complete_size,
            )
            try:
                with open(self._journal_path, "r+b") as handle:
                    handle.truncate(complete_size)
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError as exc:
                raise IntentTrackerCorrupt(
                    f"cannot repair claim-intent journal torn tail: {exc}"
                ) from exc
            raw = raw[:complete_size]
        lines = raw.split(b"\n")
        for index, line in enumerate(lines):
            if not line.strip():
                continue
            try:
                event = json.loads(line.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise IntentTrackerCorrupt(
                    f"corrupt claim-intent journal line {index + 1}: {exc}"
                ) from exc
            if not isinstance(event, dict):
                raise IntentTrackerCorrupt("tracker event must be an object")
            self._fold_event_locked(event)
        stat = self._journal_path.stat()
        self._journal_stat = (stat.st_mtime_ns, stat.st_size)

    def _archive_sent_bindings(
        self, path: Path, raw: bytes,
    ) -> list[tuple[str, str, str, str, int]]:
        """Extract replay bindings from a verified immutable segment."""

        if raw and not raw.endswith(b"\n"):
            raise IntentTrackerCorrupt(
                f"claim-intent archive {path.name} has a torn tail"
            )
        bindings: dict[str, tuple[str, str, str, str, int]] = {}
        for index, line in enumerate(raw.split(b"\n"), start=1):
            if not line:
                continue
            try:
                event = json.loads(line.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise IntentTrackerCorrupt(
                    f"corrupt claim-intent archive {path.name} line {index}: {exc}"
                ) from exc
            if not isinstance(event, dict):
                raise IntentTrackerCorrupt(
                    f"claim-intent archive {path.name} event is not an object"
                )
            if event.get("event") == "receipt-retained":
                nonce = event.get("nonce")
                prior = bindings.get(nonce) if isinstance(nonce, str) else None
                if (
                    frozenset(event) != _TRACKER_RETENTION_FIELDS
                    or prior is None
                    or not prior[3]
                    or prior[3] != event.get("receipt_hash")
                    or prior[4]
                ):
                    raise IntentTrackerCorrupt(
                        f"claim-intent archive {path.name} retention event is invalid"
                    )
                bindings[nonce] = (*prior[:4], 1)
                continue
            if event.get("event") != "sent":
                continue
            probe = object.__new__(IntentTracker)
            probe._intents = {}
            probe._max_intents = 1
            probe._fold_event_locked(event)
            nonce = event.get("nonce")
            intent = event.get("intent")
            if (
                not isinstance(nonce, str)
                or _NONCE_RE.fullmatch(nonce) is None
                or not isinstance(intent, dict)
                or intent.get("nonce") != nonce
            ):
                raise IntentTrackerCorrupt(
                    f"claim-intent archive {path.name} intent binding is invalid"
                )
            ok, reason = verify_claim_intent(
                intent, now_ms=intent.get("created_at_ms"),
            )
            if not ok:
                raise IntentTrackerCorrupt(
                    f"claim-intent archive {path.name} has invalid signature: {reason}"
                )
            receipt_id = event.get("receipt_id", "")
            receipt_hash = event.get("receipt_hash", "")
            if "receipt_retained" in event and event["receipt_retained"] is not True:
                raise IntentTrackerCorrupt(
                    f"claim-intent archive {path.name} retention marker is invalid"
                )
            if receipt_id or receipt_hash:
                if (
                    not isinstance(receipt_id, str)
                    or not receipt_id
                    or len(receipt_id.encode("utf-8")) > 256
                    or not isinstance(receipt_hash, str)
                    or len(receipt_hash) != 64
                    or any(ch not in "0123456789abcdef" for ch in receipt_hash)
                ):
                    raise IntentTrackerCorrupt(
                        f"claim-intent archive {path.name} receipt binding is invalid"
                    )
            if nonce in bindings:
                raise IntentTrackerCorrupt(
                    f"claim-intent archive {path.name} repeats an intent nonce"
                )
            bindings[nonce] = (
                nonce,
                hashlib.sha256(canonical_json(intent)).hexdigest(),
                receipt_id,
                receipt_hash,
                int(event.get("receipt_retained") is True),
            )
        if not bindings:
            raise IntentTrackerCorrupt(
                f"claim-intent archive {path.name} has no sent event"
            )
        return list(bindings.values())

    def _sync_archive_index_locked(self) -> None:
        """Rebuild only new/changed segments; never load old bindings into RAM."""

        archive_dir = self._dir / _ARCHIVE_DIR
        index_path = archive_dir / _ARCHIVE_INDEX
        if not archive_dir.exists() and not index_path.exists():
            return
        try:
            paths = sorted(archive_dir.glob("claim-intents-*.jsonl"))
            with closing(sqlite3.connect(index_path, timeout=10)) as database:
                database.execute("PRAGMA synchronous=FULL")
                with database:
                    database.execute(
                        "CREATE TABLE IF NOT EXISTS segments "
                        "(name TEXT PRIMARY KEY, size INTEGER NOT NULL, "
                        "mtime_ns INTEGER NOT NULL)"
                    )
                    database.execute(
                        "CREATE TABLE IF NOT EXISTS bindings "
                        "(nonce TEXT PRIMARY KEY, intent_hash TEXT NOT NULL, "
                        "receipt_id TEXT NOT NULL, receipt_hash TEXT NOT NULL, "
                        "receipt_retained INTEGER NOT NULL DEFAULT 0)"
                    )
                    columns = {
                        row[1]
                        for row in database.execute("PRAGMA table_info(bindings)")
                    }
                    if "receipt_retained" not in columns:
                        database.execute(
                            "ALTER TABLE bindings ADD COLUMN "
                            "receipt_retained INTEGER NOT NULL DEFAULT 0"
                        )
                    if "segment_name" not in columns:
                        database.execute(
                            "ALTER TABLE bindings ADD COLUMN segment_name TEXT"
                        )
                    database.execute(
                        "CREATE UNIQUE INDEX IF NOT EXISTS receipt_binding "
                        "ON bindings(receipt_id, receipt_hash) "
                        "WHERE receipt_id <> ''"
                    )
                    database.execute(
                        "CREATE INDEX IF NOT EXISTS retained_receipt_lookup "
                        "ON bindings(receipt_hash) WHERE receipt_retained = 1"
                    )
                known = {
                    name: (size, mtime_ns)
                    for name, size, mtime_ns in database.execute(
                        "SELECT name, size, mtime_ns FROM segments"
                    )
                }
                current_names = {path.name for path in paths}
                if known.keys() - current_names:
                    raise IntentTrackerCorrupt(
                        "indexed claim-intent archive segment is missing"
                    )
                for path in paths:
                    match = _ARCHIVE_NAME_RE.fullmatch(path.name)
                    if match is None:
                        raise IntentTrackerCorrupt(
                            "claim-intent archive name is invalid"
                        )
                    stat = path.stat()
                    missing_locator = (
                        database.execute(
                            "SELECT 1 FROM bindings WHERE segment_name IS NULL LIMIT 1"
                        ).fetchone()
                        is not None
                    )
                    if (
                        known.get(path.name) == (stat.st_size, stat.st_mtime_ns)
                        and not missing_locator
                    ):
                        continue
                    raw = _read_archive_segment(path)
                    if hashlib.sha256(raw).hexdigest() != match.group(1):
                        raise IntentTrackerCorrupt(
                            f"claim-intent archive {path.name} failed its content hash"
                        )
                    bindings = self._archive_sent_bindings(path, raw)
                    with database:
                        for binding in bindings:
                            prior = database.execute(
                                "SELECT intent_hash, receipt_id, receipt_hash, "
                                "receipt_retained, segment_name "
                                "FROM bindings WHERE nonce = ?",
                                (binding[0],),
                            ).fetchone()
                            if prior is not None:
                                if tuple(prior[:4]) != binding[1:]:
                                    raise IntentTrackerCorrupt(
                                        "archived intent nonce has conflicting bindings"
                                    )
                                if prior[4] is None:
                                    database.execute(
                                        "UPDATE bindings SET segment_name = ? "
                                        "WHERE nonce = ?",
                                        (path.name, binding[0]),
                                    )
                                continue
                            database.execute(
                                "INSERT INTO bindings "
                                "(nonce, intent_hash, receipt_id, receipt_hash, "
                                "receipt_retained, segment_name) "
                                "VALUES (?, ?, ?, ?, ?, ?)",
                                (*binding, path.name),
                            )
                        database.execute(
                            "INSERT INTO segments (name, size, mtime_ns) "
                            "VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET "
                            "size = excluded.size, mtime_ns = excluded.mtime_ns",
                            (path.name, stat.st_size, stat.st_mtime_ns),
                        )
        except (OSError, sqlite3.DatabaseError) as exc:
            raise IntentTrackerCorrupt(
                f"cannot verify claim-intent archive index: {exc}"
            ) from exc

    def _archived_binding_exists_locked(
        self,
        nonce: str,
        receipt_id: str,
        receipt_hash: str,
    ) -> tuple[bool, bool]:
        index_path = self._dir / _ARCHIVE_DIR / _ARCHIVE_INDEX
        if not index_path.exists():
            self._sync_archive_index_locked()
            if not index_path.exists():
                return False, False
        try:
            with closing(sqlite3.connect(index_path, timeout=10)) as database:
                nonce_found = database.execute(
                    "SELECT 1 FROM bindings WHERE nonce = ?", (nonce,),
                ).fetchone() is not None
                receipt_found = bool(receipt_id) and database.execute(
                    "SELECT 1 FROM bindings WHERE receipt_id = ? "
                    "AND receipt_hash = ?", (receipt_id, receipt_hash),
                ).fetchone() is not None
                return nonce_found, receipt_found
        except sqlite3.DatabaseError as exc:
            raise IntentTrackerCorrupt(
                f"cannot query claim-intent archive index: {exc}"
            ) from exc

    def _save_receipt_locked(self, raw: bytes, receipt_hash: str) -> None:
        path = self._dir / _RECEIPT_DIR / f"{receipt_hash}.json"
        try:
            try:
                existing = _read_bounded_regular_file(
                    path, MAX_TRACKED_RECEIPT_BYTES, "stored claim receipt",
                )
            except FileNotFoundError:
                path.parent.mkdir(parents=True, exist_ok=True)
                file_count, total_bytes = self._receipt_storage_usage_locked()
                if (
                    file_count >= self._max_receipt_files
                    or total_bytes + len(raw) > self._max_receipt_store_bytes
                ):
                    raise IntentReceiptStoreFull(
                        "claim receipt storage capacity reached"
                    )
                atomic_write_bytes(path, raw)
                return
            if not existing or existing != raw:
                raise IntentTrackerCorrupt(
                    "stored claim receipt does not match its content address"
                )
        except OSError as exc:
            raise IntentTrackerCorrupt(
                f"cannot persist claim receipt: {exc}"
            ) from exc

    def _receipt_storage_usage_locked(self) -> tuple[int, int]:
        path = self._dir / _RECEIPT_DIR
        if not path.exists():
            return 0, 0
        file_count = 0
        total_bytes = 0
        try:
            with os.scandir(path) as entries:
                for entry in entries:
                    if not entry.is_file(follow_symlinks=False):
                        raise IntentTrackerCorrupt(
                            "claim receipt storage contains a non-file entry"
                        )
                    file_count += 1
                    total_bytes += entry.stat(follow_symlinks=False).st_size
        except OSError as exc:
            raise IntentTrackerCorrupt(
                f"cannot inspect claim receipt storage: {exc}"
            ) from exc
        return file_count, total_bytes

    def receipt_storage_status(self) -> dict[str, int]:
        """Report physical usage, including crash orphans and temporary files."""

        with self._thread_lock, InterProcessLock(self._journal_path):
            files, used_bytes = self._receipt_storage_usage_locked()
            return {
                "files": files,
                "used_bytes": used_bytes,
                "max_files": self._max_receipt_files,
                "max_bytes": self._max_receipt_store_bytes,
            }

    def verify_receipt_storage(self) -> int:
        """Explicitly verify every committed active and archived Receipt blob.

        Legacy hash-only bindings without a retention marker are not evidence.
        This audit does not remove unreferenced blobs or repair missing ones.
        """

        self.verify_archive_integrity()
        with self._thread_lock, InterProcessLock(self._journal_path):
            self._refold_if_changed_locked()
            expected = {
                entry["receipt_hash"]
                for entry in self._intents.values()
                if entry.get("receipt_retained")
            }
            self._sync_archive_index_locked()
            index_path = self._dir / _ARCHIVE_DIR / _ARCHIVE_INDEX
            if index_path.exists():
                try:
                    with closing(sqlite3.connect(index_path, timeout=10)) as database:
                        expected.update(
                            row[0] for row in database.execute(
                                "SELECT DISTINCT receipt_hash FROM bindings "
                                "WHERE receipt_retained = 1"
                            )
                        )
                except sqlite3.DatabaseError as exc:
                    raise IntentTrackerCorrupt(
                        f"cannot audit retained claim receipts: {exc}"
                    ) from exc
        for receipt_hash in expected:
            if self.load_receipt_by_hash(receipt_hash) is None:
                raise IntentTrackerCorrupt(
                    "committed claim receipt evidence is missing"
                )
        return len(expected)

    def load_receipt_by_hash(self, receipt_hash: str) -> dict[str, Any] | None:
        """Load retained signed evidence by exact hash, including archived claims.

        A missing legacy blob returns ``None``. Missing committed retained
        evidence is corruption. Callers must still bind the receipt to their
        intent and source-authority ACK.
        """

        if (
            not isinstance(receipt_hash, str)
            or _RECEIPT_HASH_RE.fullmatch(receipt_hash) is None
        ):
            raise ValueError("receipt_hash must be lowercase SHA-256 hex")
        path = self._dir / _RECEIPT_DIR / f"{receipt_hash}.json"
        with self._thread_lock, InterProcessLock(self._journal_path):
            try:
                try:
                    raw = _read_bounded_regular_file(
                        path, MAX_TRACKED_RECEIPT_BYTES, "stored claim receipt",
                    )
                except FileNotFoundError:
                    self._refold_if_changed_locked()
                    if any(
                        entry["receipt_hash"] == receipt_hash
                        and entry.get("receipt_retained")
                        for entry in self._intents.values()
                    ):
                        raise IntentTrackerCorrupt(
                            "committed claim receipt evidence is missing"
                        )
                    self._sync_archive_index_locked()
                    index_path = self._dir / _ARCHIVE_DIR / _ARCHIVE_INDEX
                    if index_path.exists():
                        try:
                            with closing(
                                sqlite3.connect(index_path, timeout=10)
                            ) as database:
                                archived = database.execute(
                                    "SELECT 1 FROM bindings WHERE receipt_hash = ? "
                                    "AND receipt_retained = 1 LIMIT 1",
                                    (receipt_hash,),
                                ).fetchone()
                        except sqlite3.DatabaseError as exc:
                            raise IntentTrackerCorrupt(
                                f"cannot check retained claim receipt: {exc}"
                            ) from exc
                        if archived is not None:
                            raise IntentTrackerCorrupt(
                                "committed claim receipt evidence is missing"
                            )
                    return None
            except OSError as exc:
                raise IntentTrackerCorrupt(
                    f"cannot read stored claim receipt: {exc}"
                ) from exc
            if (
                not raw or hashlib.sha256(raw).hexdigest() != receipt_hash
            ):
                raise IntentTrackerCorrupt("stored claim receipt hash is invalid")
            try:
                receipt = json.loads(raw.decode("utf-8"))
                if (
                    not isinstance(receipt, dict)
                    or canonical_json(receipt) != raw
                    or not verify_receipt(receipt)
                    or not str(receipt.get("goal_id", "")).startswith("market:claim:")
                ):
                    raise IntentTrackerCorrupt("stored claim receipt is invalid")
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError,
                    RecursionError) as exc:
                raise IntentTrackerCorrupt(
                    "stored claim receipt is malformed"
                ) from exc
            return receipt

    def verify_archive_integrity(self) -> int:
        """Fully rehash archives and compare every replay binding to the index.

        This is an explicit, potentially long-running audit. Normal startup
        checks segment names and file metadata without reading every segment.
        """

        with self._thread_lock, InterProcessLock(self._journal_path):
            self._sync_archive_index_locked()
            archive_dir = self._dir / _ARCHIVE_DIR
            index_path = archive_dir / _ARCHIVE_INDEX
            if not index_path.exists():
                return 0
            seen: set[str] = set()
            try:
                with closing(sqlite3.connect(index_path, timeout=10)) as database:
                    for path in sorted(archive_dir.glob("claim-intents-*.jsonl")):
                        match = _ARCHIVE_NAME_RE.fullmatch(path.name)
                        if match is None:
                            raise IntentTrackerCorrupt(
                                "claim-intent archive name is invalid"
                            )
                        raw = _read_archive_segment(path)
                        if hashlib.sha256(raw).hexdigest() != match.group(1):
                            raise IntentTrackerCorrupt(
                                "claim-intent archive "
                                f"{path.name} failed its content hash"
                            )
                        for nonce, intent_hash, receipt_id, receipt_hash, retained in (
                            self._archive_sent_bindings(path, raw)
                        ):
                            indexed = database.execute(
                                "SELECT intent_hash, receipt_id, receipt_hash, "
                                "receipt_retained "
                                "FROM bindings WHERE nonce = ?", (nonce,),
                            ).fetchone()
                            if indexed != (
                                intent_hash, receipt_id, receipt_hash, retained,
                            ):
                                raise IntentTrackerCorrupt(
                                    "claim-intent archive index does not match "
                                    "its segment"
                                )
                            seen.add(nonce)
                    indexed_count = database.execute(
                        "SELECT COUNT(*) FROM bindings"
                    ).fetchone()[0]
                    if indexed_count != len(seen):
                        raise IntentTrackerCorrupt(
                            "claim-intent archive index has unbacked bindings"
                        )
            except (OSError, sqlite3.DatabaseError) as exc:
                raise IntentTrackerCorrupt(
                    f"cannot audit claim-intent archives: {exc}"
                ) from exc
            return len(seen)

    def _fold_event_locked(self, event: dict[str, Any]) -> None:
        kind = event.get("event")
        if kind not in _TRACKER_EVENTS:
            raise IntentTrackerCorrupt(f"unknown tracker event: {kind!r}")
        event_fields = frozenset(event)
        valid_fields = (
            (
                _TRACKER_SENT_FIELDS_V1,
                _TRACKER_SENT_FIELDS_V2,
                _TRACKER_SENT_FIELDS_V3,
                _TRACKER_SENT_FIELDS_V4,
                _TRACKER_SENT_FIELDS_V5,
                _TRACKER_SENT_FIELDS_V6,
            )
            if kind == "sent"
            else (
                (_TRACKER_RETENTION_FIELDS,)
                if kind == "receipt-retained"
                else (
                    (_TRACKER_RECONCILED_FIELDS,)
                    if kind == "reconciled"
                    else (_TRACKER_TERMINAL_FIELDS,)
                )
            )
        )
        if event_fields not in valid_fields:
            raise IntentTrackerCorrupt(
                f"{kind} tracker event has missing or unknown fields"
            )
        nonce = event.get("nonce")
        if not isinstance(nonce, str) or _NONCE_RE.fullmatch(nonce) is None:
            raise IntentTrackerCorrupt("tracker event nonce is invalid")
        if kind == "sent":
            intent = event.get("intent")
            if not isinstance(intent, dict) or intent.get("nonce") != nonce:
                raise IntentTrackerCorrupt("sent event does not bind its intent nonce")
            created_at_ms = intent.get("created_at_ms")
            ok, reason = verify_claim_intent(intent, now_ms=created_at_ms)
            if not ok:
                raise IntentTrackerCorrupt(
                    f"sent event contains an invalid intent: {reason}"
                )
            if nonce in self._intents:
                raise IntentTrackerCorrupt("sent event repeats an existing nonce")
            if len(self._intents) >= self._max_intents:
                raise IntentTrackerCorrupt("tracker journal exceeds its intent cap")
            receipt_id = event.get("receipt_id", "")
            receipt_hash = event.get("receipt_hash", "")
            if event_fields in (
                _TRACKER_SENT_FIELDS_V2,
                _TRACKER_SENT_FIELDS_V3,
                _TRACKER_SENT_FIELDS_V4,
                _TRACKER_SENT_FIELDS_V5,
                _TRACKER_SENT_FIELDS_V6,
            ) and (
                not isinstance(receipt_id, str)
                or not receipt_id
                or len(receipt_id.encode("utf-8")) > 256
                or not isinstance(receipt_hash, str)
                or len(receipt_hash) != 64
                or any(ch not in "0123456789abcdef" for ch in receipt_hash)
            ):
                raise IntentTrackerCorrupt("sent event receipt binding is invalid")
            if (
                event_fields
                in (
                    _TRACKER_SENT_FIELDS_V4,
                    _TRACKER_SENT_FIELDS_V5,
                    _TRACKER_SENT_FIELDS_V6,
                )
                and event.get("receipt_retained") is not True
            ):
                raise IntentTrackerCorrupt("sent event retention marker is invalid")
            if event_fields in (
                _TRACKER_SENT_FIELDS_V3,
                _TRACKER_SENT_FIELDS_V5,
                _TRACKER_SENT_FIELDS_V6,
            ) and (
                not isinstance(event.get("source_peer"), str)
                or not event["source_peer"]
                or len(event["source_peer"].encode("utf-8")) > 2_048
                or not isinstance(event.get("source_did"), str)
                or not is_did_key(event["source_did"])
                or not isinstance(event.get("federation_key"), str)
                or not event["federation_key"]
                or len(event["federation_key"].encode("utf-8")) > 256
            ):
                raise IntentTrackerCorrupt("sent event source binding is invalid")
            if event_fields == _TRACKER_SENT_FIELDS_V6:
                try:
                    raw_announcement = event["announcement"]
                    if (
                        len(canonical_json(raw_announcement))
                        > MAX_TRACKED_RECEIPT_BYTES
                    ):
                        raise ValueError("announcement exceeds retention limit")
                    announcement = TaskAnnouncement.from_dict(raw_announcement)
                    valid, _ = verify_announcement(announcement)
                    if (
                        not valid
                        or announcement.announcement_id != intent["announcement_id"]
                        or event["source_did"]
                        != (announcement.authority_did or announcement.publisher_did)
                        or event["federation_key"]
                        != announcement_federation_key(announcement)
                    ):
                        raise ValueError("announcement source binding differs")
                except (TypeError, ValueError, OverflowError, RecursionError) as exc:
                    raise IntentTrackerCorrupt(
                        "sent event announcement binding is invalid"
                    ) from exc
            self._intents[nonce] = {
                "state": "pending",
                "intent": intent,
                "receipt_id": receipt_id,
                "receipt_hash": receipt_hash,
                "receipt_retained": event.get("receipt_retained", False),
                "source_peer": event.get("source_peer", ""),
                "source_did": event.get("source_did", ""),
                "federation_key": event.get("federation_key", ""),
                "announcement": event.get("announcement"),
            }
            return
        if kind == "receipt-retained":
            prior = self._intents.get(nonce)
            if (
                prior is None
                or not prior["receipt_hash"]
                or prior["receipt_hash"] != event["receipt_hash"]
                or prior["receipt_retained"]
            ):
                raise IntentTrackerCorrupt(
                    "receipt retention event does not bind an unretained intent"
                )
            prior["receipt_retained"] = True
            return
        if kind == "reconciled":
            retry_nonce = event.get("retry_nonce")
            if (
                not isinstance(retry_nonce, str)
                or _NONCE_RE.fullmatch(retry_nonce) is None
                or retry_nonce == nonce
            ):
                raise IntentTrackerCorrupt("reconciled retry nonce is invalid")
            prior = self._intents.get(nonce)
            retry = self._intents.get(retry_nonce)
            if prior is None or retry is None:
                raise IntentTrackerCorrupt(
                    "reconciled event references an unknown intent"
                )
            if prior["state"] not in {"pending", "expired", "confirmed"}:
                raise IntentTrackerCorrupt(
                    "reconciled authority claim references a rejected intent"
                )
            if retry["state"] != "pending":
                raise IntentTrackerCorrupt(
                    "reconciled retry intent is already terminal"
                )
            prior["state"] = "confirmed"
            retry["state"] = "rejected"
            return
        entry = self._intents.get(nonce)
        if entry is None:
            raise IntentTrackerCorrupt("terminal event references an unknown intent")
        if kind == "confirmed" and entry["state"] == "expired":
            # Expiry is a local timeout inference. A later authority-signed
            # ACK for the exact retained receipt is stronger evidence that
            # the source accepted the claim while it was valid.
            entry["state"] = "confirmed"
            return
        if entry["state"] != "pending":
            raise IntentTrackerCorrupt("intent has more than one terminal transition")
        entry["state"] = kind

    def _refold_if_changed_locked(self) -> None:
        try:
            if not self._journal_path.exists():
                if self._journal_stat is not None:
                    raise IntentTrackerCorrupt("claim-intent journal disappeared")
                return
            stat = self._journal_path.stat()
        except OSError as exc:
            raise IntentTrackerCorrupt(
                f"cannot stat claim-intent journal: {exc}"
            ) from exc
        current = (stat.st_mtime_ns, stat.st_size)
        if current != self._journal_stat:
            self._load_locked()

    def _append_events_locked(
        self,
        events: list[dict[str, Any]],
        *,
        protected_nonces: frozenset[str] = frozenset(),
    ) -> None:
        encoded = [canonical_json(event) + b"\n" for event in events]
        current_size = (
            self._journal_path.stat().st_size if self._journal_path.exists() else 0
        )
        added_size = sum(len(line) for line in encoded)
        while current_size + added_size > MAX_TRACKER_JOURNAL_BYTES:
            terminal_count = sum(
                entry["state"] != "pending" for entry in self._intents.values()
            )
            if terminal_count == 0:
                break
            removed = self._compact_locked(
                force_terminal=max(1, terminal_count // 4),
                protected_nonces=protected_nonces,
            )
            if removed == 0:
                break
            current_size = (
                self._journal_path.stat().st_size
                if self._journal_path.exists()
                else 0
            )
        if current_size + added_size > MAX_TRACKER_JOURNAL_BYTES:
            raise IntentTrackerFull("claim-intent journal byte cap reached")
        with open(self._journal_path, "ab") as handle:
            handle.writelines(encoded)
            handle.flush()
            os.fsync(handle.fileno())
            stat = os.fstat(handle.fileno())
            self._journal_stat = (stat.st_mtime_ns, stat.st_size)

    def _compact_locked(
        self,
        *,
        minimum_free: int = 0,
        force_terminal: int = 0,
        protected_nonces: frozenset[str] = frozenset(),
    ) -> int:
        """Archive old terminal history and atomically rewrite active state.

        The immutable archive segment contains the original events for the
        selected terminal intents.  Its content hash makes crash retries
        idempotent without copying the entire active journal each time.
        Pending and currently transitioning intents are never removed.
        """

        free_slots = self._max_intents - len(self._intents)
        remove_count = max(minimum_free - free_slots, force_terminal, 0)
        if remove_count == 0:
            return 0
        terminals = sorted(
            (
                (nonce, entry)
                for nonce, entry in self._intents.items()
                if entry["state"] != "pending" and nonce not in protected_nonces
            ),
            key=lambda item: (
                item[1]["intent"]["created_at_ms"],
                item[0],
            ),
        )
        selected = terminals[:remove_count]
        if not selected:
            return 0
        if not self._journal_path.exists():
            raise IntentTrackerCorrupt("cannot compact a missing claim-intent journal")
        original = self._journal_path.read_bytes()
        removed_nonces = {nonce for nonce, _entry in selected}
        archived_lines: list[bytes] = []
        active_lines: list[bytes] = []
        active_states: dict[str, str] = {}
        for line in original.splitlines(keepends=True):
            event = json.loads(line)
            kind = event["event"]
            nonce = event["nonce"]
            retry_nonce = event.get("retry_nonce", "")
            prior_removed = nonce in removed_nonces
            retry_removed = retry_nonce in removed_nonces
            if prior_removed or retry_removed:
                archived_lines.append(line)
                if kind == "reconciled":
                    if not prior_removed and active_states.get(nonce) != "confirmed":
                        active_lines.append(canonical_json({
                            "event": "confirmed", "nonce": nonce,
                        }) + b"\n")
                        active_states[nonce] = "confirmed"
                    if not retry_removed:
                        active_lines.append(canonical_json({
                            "event": "rejected", "nonce": retry_nonce,
                        }) + b"\n")
                        active_states[retry_nonce] = "rejected"
                continue
            active_lines.append(line)
            if kind == "sent":
                active_states[nonce] = "pending"
            elif kind == "receipt-retained":
                continue
            elif kind == "reconciled":
                active_states[nonce] = "confirmed"
                active_states[retry_nonce] = "rejected"
            else:
                active_states[nonce] = kind
        archived = b"".join(archived_lines)
        digest = hashlib.sha256(archived).hexdigest()
        archive_path = self._dir / _ARCHIVE_DIR / f"claim-intents-{digest}.jsonl"
        if archive_path.exists():
            if _read_archive_segment(archive_path) != archived:
                raise IntentTrackerCorrupt(
                    "claim-intent archive digest collision or corruption"
                )
        else:
            atomic_write_bytes(archive_path, archived)
        # Commit replay tombstones before removing their active-journal rows.
        # If the process stops here, both sources retain the same binding.
        self._sync_archive_index_locked()

        replacement = b"".join(active_lines)
        if len(replacement) > MAX_TRACKER_JOURNAL_BYTES:
            raise IntentTrackerFull("compacted claim-intent journal remains too large")
        probe = object.__new__(IntentTracker)
        probe._intents = {}
        probe._max_intents = self._max_intents
        for line in active_lines:
            probe._fold_event_locked(json.loads(line))
        expected = {
            nonce: entry for nonce, entry in self._intents.items()
            if nonce not in removed_nonces
        }
        if probe._intents != expected:
            raise IntentTrackerCorrupt(
                "compacted claim-intent journal changes retained state"
            )
        atomic_write_bytes(self._journal_path, replacement)
        for nonce in removed_nonces:
            del self._intents[nonce]
        stat = self._journal_path.stat()
        self._journal_stat = (stat.st_mtime_ns, stat.st_size)
        return len(selected)

    def record_sent(
        self,
        intent: dict[str, Any],
        *,
        receipt: dict[str, Any] | None = None,
        announcement: TaskAnnouncement | None = None,
        cap_token: dict[str, Any] | None = None,
        source_peer: str = "",
        source_did: str = "",
        federation_key: str = "",
    ) -> None:
        try:
            intent = json.loads(canonical_json(intent))
        except (TypeError, ValueError, OverflowError, RecursionError) as exc:
            raise ClaimIntentRejected(
                REJECT_INTENT_MALFORMED,
                "tracked intent is not canonical JSON",
            ) from exc
        ok, reason = verify_claim_intent(intent)
        if not ok:
            raise ClaimIntentRejected(reason, "refusing to track an invalid intent")
        receipt_id = ""
        receipt_hash = ""
        receipt_bytes = b""
        if receipt is not None:
            if not isinstance(receipt, dict):
                raise ClaimIntentRejected(
                    REJECT_INTENT_MALFORMED,
                    "tracked receipt must be an object",
                )
            try:
                receipt_bytes = canonical_json(receipt)
            except (TypeError, ValueError, RecursionError) as exc:
                raise ClaimIntentRejected(
                    REJECT_INTENT_MALFORMED,
                    "tracked receipt is not canonical JSON",
                ) from exc
            if len(receipt_bytes) > MAX_TRACKED_RECEIPT_BYTES:
                raise ClaimIntentRejected(
                    REJECT_INTENT_MALFORMED,
                    "tracked receipt exceeds size limit",
                )
            receipt = json.loads(receipt_bytes)
            if not verify_receipt(receipt):
                raise ClaimIntentRejected(
                    REJECT_INTENT_SIGNATURE,
                    "tracked receipt signature or authorization is invalid",
                )
            receipt_id_value = receipt.get("receipt_id")
            authorizing_token = receipt.get("authorizing_cap_token")
            if (
                not isinstance(receipt_id_value, str)
                or not receipt_id_value
                or len(receipt_id_value.encode("utf-8")) > 256
                or receipt.get("signer_did") != intent["claimant_did"]
                or receipt.get("goal_id")
                != f"market:claim:{intent['announcement_id']}"
                or not isinstance(authorizing_token, dict)
                or authorizing_token.get("token_id") != intent["cap_token_id"]
            ):
                raise ClaimIntentRejected(
                    REJECT_INTENT_BINDING,
                    "tracked receipt does not bind the intent",
                )
            if not isinstance(announcement, TaskAnnouncement):
                raise ClaimIntentRejected(
                    REJECT_INTENT_BINDING,
                    "tracked receipt requires its signed announcement",
                )
            try:
                announcement = deepcopy(announcement)
            except (TypeError, ValueError, RuntimeError, RecursionError) as exc:
                raise ClaimIntentRejected(
                    REJECT_INTENT_BINDING,
                    "tracked announcement cannot be snapshotted",
                ) from exc
            announcement_ok, _ = verify_announcement(announcement)
            if (
                not announcement_ok
                or announcement.announcement_id != intent["announcement_id"]
            ):
                raise ClaimIntentRejected(
                    REJECT_INTENT_BINDING,
                    "tracked announcement is invalid or does not bind the intent",
                )
            timeline = receipt.get("timeline")
            if not isinstance(timeline, list) or len(timeline) != 1:
                raise ClaimIntentRejected(
                    REJECT_INTENT_BINDING,
                    "tracked receipt must contain one signed claim event",
                )
            entry = timeline[0]
            if (
                not isinstance(entry, dict)
                or type(entry.get("timestamp")) is not int
                or entry["timestamp"] <= 0
                or timeline != [
                    item.to_dict() for item in _claim_timeline(
                        announcement,
                        intent["claimant_did"],
                        intent["cap_token_id"],
                        entry["timestamp"],
                    )
                ]
            ):
                raise ClaimIntentRejected(
                    REJECT_INTENT_BINDING,
                    "signed claim event does not bind the intent",
                )
            signed_at = entry["timestamp"]
            if abs(signed_at - _now_ms()) > MAX_FOREIGN_CLAIM_CLOCK_SKEW_MS:
                raise ClaimIntentRejected(
                    REJECT_INTENT_BINDING,
                    "signed claim receipt is outside the authority clock "
                    "window; re-sign it",
                )
            if (
                type(authorizing_token.get("not_before")) is not int
                or type(authorizing_token.get("not_after")) is not int
                or not authorizing_token["not_before"]
                <= signed_at
                <= authorizing_token["not_after"]
            ):
                raise ClaimIntentRejected(
                    REJECT_INTENT_BINDING,
                    "signed claim receipt is outside the token validity window",
                )
            receipt_id = receipt_id_value
            receipt_hash = hashlib.sha256(receipt_bytes).hexdigest()
        source_values = (source_peer, source_did, federation_key)
        if not all(isinstance(value, str) for value in source_values):
            raise ClaimIntentRejected(
                REJECT_INTENT_BINDING,
                "tracked claim source binding must contain strings",
            )
        if any(source_values) and not all(source_values):
            raise ClaimIntentRejected(
                REJECT_INTENT_BINDING,
                "tracked claim source binding is incomplete",
            )
        if source_peer and receipt is None:
            raise ClaimIntentRejected(
                REJECT_INTENT_BINDING,
                "tracked claim source binding requires a signed receipt",
            )
        if cap_token is not None or source_peer:
            if not isinstance(cap_token, dict) or receipt is None:
                raise ClaimIntentRejected(
                    REJECT_INTENT_BINDING,
                    "tracked forwarded claim requires its capability token",
                )
            try:
                same_token = canonical_json(cap_token) == canonical_json(
                    receipt["authorizing_cap_token"]
                )
            except (TypeError, ValueError, OverflowError, RecursionError) as exc:
                raise ClaimIntentRejected(
                    REJECT_INTENT_BINDING,
                    "tracked forwarded capability token is malformed",
                ) from exc
            if not same_token:
                raise ClaimIntentRejected(
                    REJECT_INTENT_BINDING,
                    "forwarded capability token differs from the signed receipt",
                )
        if source_peer and (
            not isinstance(source_peer, str)
            or len(source_peer.encode("utf-8")) > 2_048
            or not isinstance(source_did, str)
            or not is_did_key(source_did)
            or not isinstance(federation_key, str)
            or not federation_key
            or len(federation_key.encode("utf-8")) > 256
        ):
            raise ClaimIntentRejected(
                REJECT_INTENT_BINDING,
                "tracked claim source binding is invalid",
            )
        if source_peer and (
            source_did != (announcement.authority_did or announcement.publisher_did)
            or federation_key != announcement_federation_key(announcement)
        ):
            raise ClaimIntentRejected(
                REJECT_INTENT_BINDING,
                "tracked claim source does not bind its signed announcement",
            )
        retained_announcement = None
        if source_peer:
            retained_announcement = announcement.to_dict()
            if len(canonical_json(retained_announcement)) > MAX_TRACKED_RECEIPT_BYTES:
                raise ClaimIntentRejected(
                    REJECT_INTENT_BINDING,
                    "tracked announcement exceeds retention limit",
                )
        nonce = intent["nonce"]
        with self._thread_lock, InterProcessLock(self._journal_path):
            self._refold_if_changed_locked()
            existing = self._intents.get(nonce)
            if existing is not None:
                if (
                    existing["intent"] != intent
                    or existing.get("receipt_id", "") != receipt_id
                    or existing.get("receipt_hash", "") != receipt_hash
                    or existing.get("source_peer", "") != source_peer
                    or existing.get("source_did", "") != source_did
                    or existing.get("federation_key", "") != federation_key
                    or (
                        existing.get("announcement") is not None
                        and existing["announcement"] != retained_announcement
                    )
                ):
                    raise ClaimIntentRejected(
                        REJECT_INTENT_BINDING,
                        "nonce is already bound to a different intent",
                    )
                if receipt_bytes:
                    if (
                        existing.get("receipt_retained")
                        and not (
                            self._dir / _RECEIPT_DIR / f"{receipt_hash}.json"
                        ).exists()
                    ):
                        raise IntentTrackerCorrupt(
                            "committed claim receipt evidence is missing"
                        )
                    self._save_receipt_locked(receipt_bytes, receipt_hash)
                    if not existing.get("receipt_retained"):
                        self._append_events_locked(
                            [
                                {
                                    "event": "receipt-retained",
                                    "nonce": nonce,
                                    "receipt_hash": receipt_hash,
                                }
                            ],
                            protected_nonces=frozenset({nonce}),
                        )
                        existing["receipt_retained"] = True
                return
            archived_nonce, archived_receipt = self._archived_binding_exists_locked(
                nonce,
                receipt_id,
                receipt_hash,
            )
            if archived_nonce:
                raise ClaimIntentRejected(
                    REJECT_INTENT_BINDING,
                    "nonce was already used by an archived intent",
                )
            if archived_receipt:
                raise ClaimIntentRejected(
                    REJECT_INTENT_BINDING,
                    "signed receipt was already bound by an archived intent",
                )
            if receipt_id and any(
                entry.get("receipt_id") == receipt_id
                and entry.get("receipt_hash") == receipt_hash
                for entry in self._intents.values()
            ):
                raise ClaimIntentRejected(
                    REJECT_INTENT_BINDING,
                    "signed receipt is already bound to another intent",
                )
            if len(self._intents) >= self._max_intents:
                self._compact_locked(
                    minimum_free=max(1, self._max_intents // 4)
                )
                archived_nonce, archived_receipt = self._archived_binding_exists_locked(
                    nonce, receipt_id, receipt_hash,
                )
                if archived_nonce:
                    raise ClaimIntentRejected(
                        REJECT_INTENT_BINDING,
                        "nonce was already used by an archived intent",
                    )
                if archived_receipt:
                    raise ClaimIntentRejected(
                        REJECT_INTENT_BINDING,
                        "signed receipt was already bound by an archived intent",
                    )
            if len(self._intents) >= self._max_intents:
                raise IntentTrackerFull("claim-intent tracker capacity reached")
            if receipt_bytes:
                # Evidence must be durable before an intent can be forwarded.
                # A crash here can leave an unreferenced blob, never a sent
                # journal entry that points at bytes we did not retain.
                self._save_receipt_locked(receipt_bytes, receipt_hash)
            stored_intent = deepcopy(intent)
            event = {"event": "sent", "nonce": nonce, "intent": stored_intent}
            if receipt is not None:
                event["receipt_id"] = receipt_id
                event["receipt_hash"] = receipt_hash
                event["receipt_retained"] = True
            if source_peer:
                event["source_peer"] = source_peer
                event["source_did"] = source_did
                event["federation_key"] = federation_key
                event["announcement"] = retained_announcement
            self._append_events_locked([event])
            self._intents[nonce] = {
                "state": "pending",
                "intent": stored_intent,
                "receipt_id": receipt_id,
                "receipt_hash": receipt_hash,
                "receipt_retained": bool(receipt_bytes),
                "source_peer": source_peer,
                "source_did": source_did,
                "federation_key": federation_key,
                "announcement": retained_announcement,
            }

    def mark(self, intent: dict[str, Any], state: str) -> None:
        """Mark one intent terminal: confirmed | rejected | expired."""

        if state not in ("confirmed", "rejected", "expired"):
            raise ValueError("state must be confirmed/rejected/expired")
        nonce = intent.get("nonce", "") if isinstance(intent, dict) else ""
        with self._thread_lock, InterProcessLock(self._journal_path):
            self._refold_if_changed_locked()
            entry = self._intents.get(nonce)
            if entry is None:
                raise KeyError(nonce)
            if entry["intent"] != intent:
                raise ClaimIntentRejected(
                    REJECT_INTENT_BINDING,
                    "terminal transition does not match the tracked intent",
                )
            if entry["state"] != "pending":
                if entry["state"] == state:
                    return
                raise ClaimIntentRejected(
                    REJECT_INTENT_BINDING,
                    f"intent is already terminal as {entry['state']}",
                )
            self._append_events_locked(
                [{"event": state, "nonce": nonce}],
                protected_nonces=frozenset({nonce}),
            )
            entry["state"] = state

    def pending(self, *, now_ms: int | None = None) -> list[dict[str, Any]]:
        now = now_ms if now_ms is not None else _now_ms()
        with self._thread_lock, InterProcessLock(self._journal_path):
            self._refold_if_changed_locked()
            return [
                deepcopy(entry["intent"])
                for entry in self._intents.values()
                if entry["state"] == "pending"
                and now < entry["intent"].get("expires_at_ms", 0)
            ]

    def confirm_by_receipt(self, receipt_id: str, receipt_hash: str) -> str | None:
        """Confirm the one pending intent bound to an authority-acked receipt.

        Returns its nonce, or ``None`` when this tracker never recorded that
        receipt.  Matching both identifier and canonical hash prevents an ACK
        for unrelated evidence from confirming a local intent.
        """

        if (
            not isinstance(receipt_id, str)
            or not receipt_id
            or not isinstance(receipt_hash, str)
            or len(receipt_hash) != 64
            or any(ch not in "0123456789abcdef" for ch in receipt_hash)
        ):
            raise ValueError("receipt binding is invalid")
        with self._thread_lock, InterProcessLock(self._journal_path):
            self._refold_if_changed_locked()
            matches = [
                (nonce, entry)
                for nonce, entry in self._intents.items()
                if entry["state"] in {"pending", "confirmed", "expired"}
                and entry.get("receipt_id") == receipt_id
                and entry.get("receipt_hash") == receipt_hash
            ]
            if not matches:
                return None
            if len(matches) != 1:
                raise IntentTrackerCorrupt(
                    "multiple pending intents bind the same signed receipt"
                )
            nonce, entry = matches[0]
            if entry["state"] == "confirmed":
                return nonce
            self._append_events_locked(
                [{"event": "confirmed", "nonce": nonce}],
                protected_nonces=frozenset({nonce}),
            )
            entry["state"] = "confirmed"
            return nonce

    def reconcile_retry(
        self,
        retry_intent: dict[str, Any],
        receipt_id: str,
        receipt_hash: str,
    ) -> tuple[str, bool] | None:
        """Resolve a retry from an ACK for one retained earlier receipt.

        The journal records the prior confirmation and retry rejection in one
        append-only event, so a crash cannot persist a false half-transition.
        Returns ``(prior_nonce, newly_confirmed)``. ``None`` means the ACK
        does not bind any retained earlier intent and no state was changed.
        """

        if (
            not isinstance(receipt_id, str)
            or not receipt_id
            or not isinstance(receipt_hash, str)
            or len(receipt_hash) != 64
            or any(ch not in "0123456789abcdef" for ch in receipt_hash)
        ):
            raise ValueError("receipt binding is invalid")
        retry_nonce = (
            retry_intent.get("nonce", "")
            if isinstance(retry_intent, dict)
            else ""
        )
        with self._thread_lock, InterProcessLock(self._journal_path):
            self._refold_if_changed_locked()
            retry = self._intents.get(retry_nonce)
            if retry is None:
                raise KeyError(retry_nonce)
            if retry["intent"] != retry_intent:
                raise ClaimIntentRejected(
                    REJECT_INTENT_BINDING,
                    "retry transition does not match the tracked intent",
                )
            if retry["state"] != "pending":
                raise ClaimIntentRejected(
                    REJECT_INTENT_BINDING,
                    f"retry intent is already terminal as {retry['state']}",
                )
            matches = [
                (nonce, entry)
                for nonce, entry in self._intents.items()
                if nonce != retry_nonce
                and entry["state"] in {"pending", "confirmed", "expired"}
                and entry.get("receipt_id") == receipt_id
                and entry.get("receipt_hash") == receipt_hash
            ]
            if not matches:
                return None
            if len(matches) != 1:
                raise IntentTrackerCorrupt(
                    "multiple intents bind the authority-acked receipt"
                )
            prior_nonce, prior = matches[0]
            newly_confirmed = prior["state"] != "confirmed"
            self._append_events_locked(
                [{
                    "event": "reconciled",
                    "nonce": prior_nonce,
                    "retry_nonce": retry_nonce,
                }],
                protected_nonces=frozenset({prior_nonce, retry_nonce}),
            )
            prior["state"] = "confirmed"
            retry["state"] = "rejected"
            return prior_nonce, newly_confirmed

    def sweep_expired(self, *, now_ms: int | None = None) -> int:
        now = now_ms if now_ms is not None else _now_ms()
        with self._thread_lock, InterProcessLock(self._journal_path):
            self._refold_if_changed_locked()
            expired = [
                entry
                for entry in self._intents.values()
                if entry["state"] == "pending"
                and now >= entry["intent"].get("expires_at_ms", 0)
            ]
            events = [
                {"event": "expired", "nonce": entry["intent"]["nonce"]}
                for entry in expired
            ]
            if events:
                self._append_events_locked(events)
                for entry in expired:
                    entry["state"] = "expired"
            return len(expired)

    def stats(self) -> dict[str, int]:
        with self._thread_lock, InterProcessLock(self._journal_path):
            self._refold_if_changed_locked()
            counts: dict[str, int] = {}
            for entry in self._intents.values():
                counts[entry["state"]] = counts.get(entry["state"], 0) + 1
            return counts

    def records(
        self,
        *,
        now_ms: int | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Return a detached, newest-first lifecycle projection.

        A pending intent whose TTL elapsed is projected as ``expired`` even
        before a maintenance sweep persists that terminal transition.  This
        keeps read-only callers honest without making a GET-like operation
        mutate the append-only journal.
        """

        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        now = now_ms if now_ms is not None else _now_ms()
        if (
            isinstance(now, bool)
            or not isinstance(now, int)
            or not 0 < now <= MAX_SAFE_INTEGER
        ):
            raise ValueError("now_ms must be a positive safe integer")
        with self._thread_lock, InterProcessLock(self._journal_path):
            self._refold_if_changed_locked()
            records = []
            for entry in self._intents.values():
                state = entry["state"]
                intent = entry["intent"]
                if state == "pending" and now >= intent["expires_at_ms"]:
                    state = "expired"
                records.append({
                    "state": state,
                    "intent": deepcopy(intent),
                    "receipt_id": entry.get("receipt_id", ""),
                    "source_peer": entry.get("source_peer", ""),
                    "source_did": entry.get("source_did", ""),
                    "federation_key": entry.get("federation_key", ""),
                })
            records.sort(
                key=lambda item: (
                    item["intent"]["created_at_ms"],
                    item["intent"]["nonce"],
                ),
                reverse=True,
            )
            return records[: min(limit, self._max_intents)]

    def record(self, nonce: str) -> dict[str, Any] | None:
        """Return one detached internal record for reconciliation."""

        if not isinstance(nonce, str) or _NONCE_RE.fullmatch(nonce) is None:
            raise ValueError("nonce is invalid")
        with self._thread_lock, InterProcessLock(self._journal_path):
            self._refold_if_changed_locked()
            entry = self._intents.get(nonce)
            return deepcopy(entry) if entry is not None else None

    def archived_record(self, nonce: str) -> dict[str, Any] | None:
        """Read one terminal claim from its content-addressed archive segment."""

        if not isinstance(nonce, str) or _NONCE_RE.fullmatch(nonce) is None:
            raise ValueError("nonce is invalid")
        with self._thread_lock, InterProcessLock(self._journal_path):
            self._sync_archive_index_locked()
            archive_dir = self._dir / _ARCHIVE_DIR
            index_path = archive_dir / _ARCHIVE_INDEX
            if not index_path.exists():
                return None
            try:
                with closing(sqlite3.connect(index_path, timeout=10)) as database:
                    row = database.execute(
                        "SELECT intent_hash, receipt_id, receipt_hash, "
                        "receipt_retained, segment_name FROM bindings WHERE nonce = ?",
                        (nonce,),
                    ).fetchone()
            except sqlite3.DatabaseError as exc:
                raise IntentTrackerCorrupt("cannot resolve archived claim") from exc
            if row is None:
                return None
            intent_hash, receipt_id, receipt_hash, retained, name = row
            match = _ARCHIVE_NAME_RE.fullmatch(name or "")
            if match is None:
                raise IntentTrackerCorrupt(
                    "archived claim has no valid segment locator"
                )
            path = archive_dir / name
            try:
                raw = _read_archive_segment(path)
            except OSError as exc:
                raise IntentTrackerCorrupt("archived claim segment is missing") from exc
            if hashlib.sha256(raw).hexdigest() != match.group(1):
                raise IntentTrackerCorrupt(
                    "archived claim segment failed its content hash"
                )
            if len(raw) > MAX_TRACKER_JOURNAL_BYTES:
                raise IntentTrackerCorrupt("archived claim segment exceeds size limit")
            probe = object.__new__(IntentTracker)
            probe._intents = {}
            probe._max_intents = 1
            for line in raw.splitlines():
                try:
                    event = json.loads(line)
                except (UnicodeError, json.JSONDecodeError) as exc:
                    raise IntentTrackerCorrupt(
                        "archived claim event is malformed"
                    ) from exc
                if event.get("nonce") == nonce and event.get("event") == "sent":
                    probe._fold_event_locked(event)
                elif nonce in (event.get("nonce"), event.get("retry_nonce")):
                    entry = probe._intents.get(nonce)
                    if entry is None:
                        raise IntentTrackerCorrupt(
                            "archived claim lacks its sent event"
                        )
                    kind = event.get("event")
                    if kind == "receipt-retained":
                        if event.get("receipt_hash") != entry["receipt_hash"]:
                            raise IntentTrackerCorrupt(
                                "archived receipt retention differs"
                            )
                        entry["receipt_retained"] = True
                    elif kind == "reconciled":
                        entry["state"] = (
                            "confirmed" if event.get("nonce") == nonce else "rejected"
                        )
                    elif kind in ("confirmed", "rejected", "expired"):
                        entry["state"] = kind
                    else:
                        raise IntentTrackerCorrupt("archived claim has unknown event")
            entry = probe._intents.get(nonce)
            if (
                entry is None
                or hashlib.sha256(canonical_json(entry["intent"])).hexdigest()
                != intent_hash
                or (
                    entry["receipt_id"],
                    entry["receipt_hash"],
                    int(entry["receipt_retained"]),
                )
                != (receipt_id, receipt_hash, retained)
                or entry["state"] == "pending"
            ):
                raise IntentTrackerCorrupt(
                    "archived claim differs from indexed binding"
                )
            return deepcopy(entry)


__all__ = [
    "DEFAULT_INTENT_TTL_MS",
    "DEFAULT_MAX_TRACKED_INTENTS",
    "INTENT_KIND",
    "INTENT_VERSION",
    "MAX_INTENT_TTL_MS",
    "ClaimIntentRejected",
    "IntentTracker",
    "IntentTrackerCorrupt",
    "IntentTrackerFull",
    "IntentReceiptStoreFull",
    "admit_claim_intent",
    "sign_claim_intent",
    "verify_claim_intent",
]
