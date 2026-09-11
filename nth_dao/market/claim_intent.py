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
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

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

try:  # pragma: no cover - exercised via importorskip in tests
    from nacl.exceptions import BadSignatureError as _BadSignatureError
    from nacl.signing import VerifyKey as _VerifyKey
except ImportError:  # pragma: no cover
    _BadSignatureError = ValueError  # type: ignore[assignment]
    _VerifyKey = None  # type: ignore[assignment]

logger = logging.getLogger("nth_dao.market")

INTENT_KIND = "nth-market-claim-intent"
INTENT_VERSION = 1
INTENT_FIELDS = frozenset({
    "kind",
    "version",
    "announcement_id",
    "claimant_did",
    "cap_token_id",
    "nonce",
    "created_at_ms",
    "expires_at_ms",
    "signature",
})
DEFAULT_INTENT_TTL_MS = 30 * 60 * 1000  # 30 minutes
MAX_INTENT_TTL_MS = 24 * 60 * 60 * 1000  # 1 day
INTENT_MAX_CLOCK_SKEW_MS = 5 * 60 * 1000

REJECT_INTENT_MALFORMED = "intent-malformed"
REJECT_INTENT_SIGNATURE = "intent-signature-invalid"
REJECT_INTENT_EXPIRED = "intent-expired"
REJECT_INTENT_FUTURE = "intent-created-in-future"
REJECT_INTENT_BINDING = "intent-binding-mismatch"

_NONCE_RE = re.compile(r"^[A-Za-z0-9]{16,64}$")
_ANN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

_JOURNAL = "claim-intents.jsonl"
_TRACKER_EVENTS = ("sent", "confirmed", "rejected", "expired")


class ClaimIntentRejected(ClaimRejected):
    """Intent-specific rejection (distinct reason codes for the UI)."""


def _now_ms() -> int:
    return int(time.time() * 1000)


def sign_claim_intent(
    claimant: AgentIdentity,
    *,
    announcement_id: str,
    cap_token: Dict[str, Any],
    created_at_ms: Optional[int] = None,
    ttl_ms: int = DEFAULT_INTENT_TTL_MS,
    nonce: Optional[str] = None,
) -> Dict[str, Any]:
    """Sign one offline claim intent (NEVER authority — reserves nothing)."""

    claimant_did = claimant.as_did()
    if not isinstance(announcement_id, str) or _ANN_ID_RE.fullmatch(announcement_id) is None:
        raise ClaimIntentRejected(REJECT_INTENT_MALFORMED, "announcement_id is invalid")
    if str(cap_token.get("subject_did", "")) != claimant_did:
        raise ClaimIntentRejected(
            REJECT_INTENT_BINDING,
            "cap_token subject must equal the signing claimant",
        )
    if isinstance(ttl_ms, bool) or not isinstance(ttl_ms, int) or not 1 <= ttl_ms <= MAX_INTENT_TTL_MS:
        raise ClaimIntentRejected(REJECT_INTENT_MALFORMED, "ttl_ms out of range")
    now = created_at_ms if created_at_ms is not None else _now_ms()
    if isinstance(now, bool) or not isinstance(now, int) or now <= 0:
        raise ClaimIntentRejected(REJECT_INTENT_MALFORMED, "created_at_ms must be positive")
    if nonce is None:
        nonce = b64u_encode(os.urandom(18))[:24].replace("-", "a").replace("_", "b")
    if not isinstance(nonce, str) or _NONCE_RE.fullmatch(nonce) is None:
        raise ClaimIntentRejected(REJECT_INTENT_MALFORMED, "nonce format is invalid")
    intent = {
        "kind": INTENT_KIND,
        "version": INTENT_VERSION,
        "announcement_id": announcement_id,
        "claimant_did": claimant_did,
        "cap_token_id": str(cap_token.get("token_id", "")),
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
    now_ms: Optional[int] = None,
) -> tuple:
    """Fail-closed intent validation: (ok, reason)."""

    if not isinstance(intent, dict) or frozenset(intent) != INTENT_FIELDS:
        return False, REJECT_INTENT_MALFORMED
    if intent.get("kind") != INTENT_KIND or intent.get("version") != INTENT_VERSION:
        return False, REJECT_INTENT_MALFORMED
    if _ANN_ID_RE.fullmatch(str(intent.get("announcement_id", ""))) is None:
        return False, REJECT_INTENT_MALFORMED
    claimant_did = intent.get("claimant_did", "")
    if not is_did_key(claimant_did):
        return False, REJECT_INTENT_MALFORMED
    if not isinstance(intent.get("cap_token_id"), str) or len(intent["cap_token_id"]) > 128:
        return False, REJECT_INTENT_MALFORMED
    if _NONCE_RE.fullmatch(str(intent.get("nonce", ""))) is None:
        return False, REJECT_INTENT_MALFORMED
    for field in ("created_at_ms", "expires_at_ms"):
        value = intent.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            return False, REJECT_INTENT_MALFORMED
    if intent["expires_at_ms"] <= intent["created_at_ms"]:
        return False, REJECT_INTENT_MALFORMED
    if intent["expires_at_ms"] - intent["created_at_ms"] > MAX_INTENT_TTL_MS:
        return False, REJECT_INTENT_MALFORMED
    now = now_ms if now_ms is not None else _now_ms()
    if now >= intent["expires_at_ms"]:
        return False, REJECT_INTENT_EXPIRED
    if intent["created_at_ms"] > now + INTENT_MAX_CLOCK_SKEW_MS:
        return False, REJECT_INTENT_FUTURE
    if not _NACL_AVAILABLE or _VerifyKey is None:
        return False, REJECT_INTENT_SIGNATURE
    try:
        signature = b64u_decode(intent["signature"])
        if len(signature) != 64:
            return False, REJECT_INTENT_SIGNATURE
        body = canonical_json({k: v for k, v in intent.items() if k != "signature"})
        key_hex = decode_ed25519_did_key_hex(claimant_did) or ""
        _VerifyKey(bytes.fromhex(key_hex)).verify(body, signature)
    except (_BadSignatureError, DIDKeyError, KeyError, TypeError, ValueError, UnicodeError):
        return False, REJECT_INTENT_SIGNATURE
    return True, "ok"


def admit_claim_intent(
    feed: Any,
    claim_store: Any,
    intent: Dict[str, Any],
    receipt: Dict[str, Any],
    *,
    cap_token: Dict[str, Any],
    revoked_ids: Optional[set] = None,
    now_ms_override: int = 0,
    spine: Any = None,
) -> ClaimOutcome:
    """Authority side: verify the intent, bind it to the receipt, run the
    borrowed CAS. Accepted → ClaimOutcome; race lost → ClaimConflict;
    anything else → ClaimRejected/ClaimIntentRejected."""

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
    submitted_token_id = str(cap_token.get("token_id", ""))
    if intent["cap_token_id"] and intent["cap_token_id"] != submitted_token_id:
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
        now_ms_override=now_ms_override,
        spine=spine,
    )


class IntentTracker:
    """Claimant-side journal of intent lifecycle (pending → terminal).

    Hosts render 待确认 from ``pending()`` and 已确认/已拒绝/已过期 from
    the terminal states, per design doc §7.1's UI mandate. The journal is
    crash-safe (fsync per event, torn tail tolerated, corruption fails
    closed) and ``sweep_expired`` folds stale pendings after their TTL.
    """

    def __init__(self, directory: Union[str, Path]) -> None:
        self._dir = Path(directory)
        self._journal_path = self._dir / _JOURNAL
        self._dir.mkdir(parents=True, exist_ok=True)
        # nonce -> state dict
        self._intents: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if not self._journal_path.exists():
            return
        raw = self._journal_path.read_bytes()
        torn = bool(raw) and not raw.endswith(b"\n")
        lines = raw.split(b"\n")
        for index, line in enumerate(lines):
            if not line.strip():
                continue
            if index == len(lines) - 1 and torn:
                logger.warning("claim-intent journal torn tail; ignoring")
                break
            try:
                event = json.loads(line.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise RuntimeError(
                    f"corrupt claim-intent journal line {index + 1}: {exc}"
                ) from exc
            kind = event.get("event")
            if kind not in _TRACKER_EVENTS:
                raise RuntimeError(f"unknown tracker event: {kind!r}")
            nonce = event.get("nonce", "")
            if kind == "sent":
                self._intents[nonce] = {
                    "state": "pending",
                    "intent": event.get("intent", {}),
                }
            else:
                entry = self._intents.get(nonce)
                if entry is not None:
                    entry["state"] = kind

    def _append(self, event: Dict[str, Any]) -> None:
        # flock around the write+fsync (round-24 LL-4: same cross-process
        # discipline as the courier store; no caller of _append holds the
        # file lock, so no nested-lock deadlock is possible)
        import fcntl

        lock_path = self._dir / "claim-intents.lock"
        with open(lock_path, "a+") as lock_fh:
            fcntl.flock(lock_fh, fcntl.LOCK_EX)
            try:
                with open(self._journal_path, "ab") as handle:
                    handle.write(canonical_json(event) + b"\n")
                    handle.flush()
                    os.fsync(handle.fileno())
            finally:
                fcntl.flock(lock_fh, fcntl.LOCK_UN)

    def record_sent(self, intent: Dict[str, Any]) -> None:
        ok, reason = verify_claim_intent(intent)
        if not ok:
            raise ClaimIntentRejected(reason, "refusing to track an invalid intent")
        nonce = intent["nonce"]
        if nonce in self._intents:
            return  # idempotent re-send
        self._append({"event": "sent", "nonce": nonce, "intent": intent})
        self._intents[nonce] = {"state": "pending", "intent": intent}

    def mark(self, intent: Dict[str, Any], state: str) -> None:
        """Mark one intent terminal: confirmed | rejected | expired."""

        if state not in ("confirmed", "rejected", "expired"):
            raise ValueError("state must be confirmed/rejected/expired")
        nonce = intent.get("nonce", "") if isinstance(intent, dict) else ""
        entry = self._intents.get(nonce)
        if entry is None or entry["state"] != "pending":
            return  # idempotent
        self._append({"event": state, "nonce": nonce})
        entry["state"] = state

    def pending(self, *, now_ms: Optional[int] = None) -> List[Dict[str, Any]]:
        now = now_ms if now_ms is not None else _now_ms()
        return [
            entry["intent"]
            for entry in self._intents.values()
            if entry["state"] == "pending" and now < entry["intent"].get("expires_at_ms", 0)
        ]

    def sweep_expired(self, *, now_ms: Optional[int] = None) -> int:
        now = now_ms if now_ms is not None else _now_ms()
        swept = 0
        for entry in self._intents.values():
            if entry["state"] == "pending" and now >= entry["intent"].get("expires_at_ms", 0):
                self._append({"event": "expired", "nonce": entry["intent"]["nonce"]})
                entry["state"] = "expired"
                swept += 1
        return swept

    def stats(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for entry in self._intents.values():
            counts[entry["state"]] = counts.get(entry["state"], 0) + 1
        return counts


__all__ = [
    "DEFAULT_INTENT_TTL_MS",
    "INTENT_KIND",
    "INTENT_VERSION",
    "MAX_INTENT_TTL_MS",
    "ClaimIntentRejected",
    "IntentTracker",
    "admit_claim_intent",
    "sign_claim_intent",
    "verify_claim_intent",
]
