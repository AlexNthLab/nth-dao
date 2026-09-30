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

import json
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Any

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import (
    DIDKeyError,
    decode_ed25519_did_key_hex,
    is_did_key,
)
from nth_dao.identity import _NACL_AVAILABLE, AgentIdentity
from nth_dao.market.claim import (
    ClaimOutcome,
    ClaimRejected,
    record_foreign_claim,
)
from nth_dao.util.io import InterProcessLock

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
_TRACKER_EVENTS = ("sent", "confirmed", "rejected", "expired")
_TRACKER_SENT_FIELDS = frozenset({"event", "nonce", "intent"})
_TRACKER_TERMINAL_FIELDS = frozenset({"event", "nonce"})
DEFAULT_MAX_TRACKED_INTENTS = 4_096
MAX_TRACKER_JOURNAL_BYTES = 16 * 1024 * 1024


class ClaimIntentRejected(ClaimRejected):
    """Intent-specific rejection (distinct reason codes for the UI)."""


class IntentTrackerCorrupt(RuntimeError):
    """Raised when the durable lifecycle journal cannot be trusted."""


class IntentTrackerFull(RuntimeError):
    """Raised when a tracker reaches its configured durable capacity."""


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
    ) -> None:
        if (
            isinstance(max_intents, bool)
            or not isinstance(max_intents, int)
            or max_intents < 1
        ):
            raise ValueError("max_intents must be a positive integer")
        self._dir = Path(directory)
        self._journal_path = self._dir / _JOURNAL
        self._dir.mkdir(parents=True, exist_ok=True)
        self._max_intents = max_intents
        self._thread_lock = threading.RLock()
        self._journal_stat: tuple[int, int] | None = None
        # nonce -> state dict
        self._intents: dict[str, dict[str, Any]] = {}
        with InterProcessLock(self._journal_path):
            self._load_locked()

    def _load_locked(self) -> None:
        self._intents = {}
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

    def _fold_event_locked(self, event: dict[str, Any]) -> None:
        kind = event.get("event")
        if kind not in _TRACKER_EVENTS:
            raise IntentTrackerCorrupt(f"unknown tracker event: {kind!r}")
        expected_fields = (
            _TRACKER_SENT_FIELDS if kind == "sent" else _TRACKER_TERMINAL_FIELDS
        )
        if frozenset(event) != expected_fields:
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
            self._intents[nonce] = {"state": "pending", "intent": intent}
            return
        entry = self._intents.get(nonce)
        if entry is None:
            raise IntentTrackerCorrupt("terminal event references an unknown intent")
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

    def _append_events_locked(self, events: list[dict[str, Any]]) -> None:
        encoded = [canonical_json(event) + b"\n" for event in events]
        current_size = (
            self._journal_path.stat().st_size if self._journal_path.exists() else 0
        )
        if (
            current_size + sum(len(line) for line in encoded)
            > MAX_TRACKER_JOURNAL_BYTES
        ):
            raise IntentTrackerFull("claim-intent journal byte cap reached")
        with open(self._journal_path, "ab") as handle:
            handle.writelines(encoded)
            handle.flush()
            os.fsync(handle.fileno())
            stat = os.fstat(handle.fileno())
            self._journal_stat = (stat.st_mtime_ns, stat.st_size)

    def record_sent(self, intent: dict[str, Any]) -> None:
        ok, reason = verify_claim_intent(intent)
        if not ok:
            raise ClaimIntentRejected(reason, "refusing to track an invalid intent")
        nonce = intent["nonce"]
        with self._thread_lock, InterProcessLock(self._journal_path):
            self._refold_if_changed_locked()
            existing = self._intents.get(nonce)
            if existing is not None:
                if existing["intent"] != intent:
                    raise ClaimIntentRejected(
                        REJECT_INTENT_BINDING,
                        "nonce is already bound to a different intent",
                    )
                return
            if len(self._intents) >= self._max_intents:
                raise IntentTrackerFull("claim-intent tracker capacity reached")
            event = {"event": "sent", "nonce": nonce, "intent": intent}
            self._append_events_locked([event])
            self._intents[nonce] = {"state": "pending", "intent": intent}

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
            self._append_events_locked([{"event": state, "nonce": nonce}])
            entry["state"] = state

    def pending(self, *, now_ms: int | None = None) -> list[dict[str, Any]]:
        now = now_ms if now_ms is not None else _now_ms()
        with self._thread_lock, InterProcessLock(self._journal_path):
            self._refold_if_changed_locked()
            return [
                entry["intent"]
                for entry in self._intents.values()
                if entry["state"] == "pending"
                and now < entry["intent"].get("expires_at_ms", 0)
            ]

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
    "admit_claim_intent",
    "sign_claim_intent",
    "verify_claim_intent",
]
