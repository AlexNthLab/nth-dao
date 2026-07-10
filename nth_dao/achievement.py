"""AchievementCredential reducer 鈥?fold AgentLedger events into monthly W3C VCs.

The AgentLedger is append-only and per-event granular. For sharing, sync, and
external verification we want a coarser portable summary:

    "In 2026-04, this agent (did:key:...) completed 41 steps under the
     code-review and triage templates, with a 0.93 success rate, and was
     handed off to 6 times."

That snapshot can be signed once at month-close and republished cheaply.
This module performs that fold deterministically.

W3C VC alignment (data-model 2.0, JWT/LD-agnostic JSON form):

    {
      "@context": ["https://www.w3.org/ns/credentials/v2",
                   "https://nth-dao.org/credentials/achievement/v1"],
      "type": ["VerifiableCredential", "AchievementCredential"],
      "issuer": "did:key:z...",      # the agent itself; self-issued
      "validFrom": "2026-04-01T00:00:00",
      "validUntil": "2026-04-30T23:59:59.999999",
      "credentialSubject": {
        "id": "did:key:z...",
        "period": "2026-04",
        "fingerprint": "...",
        "missions_owned": 3,
        "steps_completed": 41,
        "steps_failed": 3,
        "success_rate": 0.932,
        "handoffs_received": 6,
        "handoffs_given": 4,
        "reviews_given": 12,
        "reviews_received": 9,
        "endorsements_given": 2,
        "endorsements_received": 5,
        "templates_used": {"code-review": 20, "triage": 21},
        "categories": {"code_review": 41},
        "total_token_cost": 184320,
        "ledger_seq_start": 102, "ledger_seq_end": 158,
        "ledger_hash_start": "...", "ledger_hash_end": "..."
      },
      "proof": {                       # only present when signed
        "type": "Ed25519Signature2020",
        "created": "...",
        "verificationMethod": "did:key:z...#z...",
        "proofPurpose": "assertionMethod",
        "proofValue": "<hex>"          # over canonical_json(credential minus proof)
      }
    }

Self-issued: an agent vouches for its own activity. The on-chain ledger
hash range pins the claim to a specific run of events 鈥?anyone replaying
ledger.jsonl through this reducer must arrive at the same numbers, which
makes the credential cheaply auditable.
"""

from __future__ import annotations

import calendar
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .agent_ledger import (
    EVENT_ENDORSEMENT_GIVEN,
    EVENT_ENDORSEMENT_RECEIVED,
    EVENT_MISSION_OWNED,
    EVENT_REVIEW_GIVEN,
    EVENT_REVIEW_RECEIVED,
    EVENT_STEP_COMPLETE,
    EVENT_STEP_FAILED,
    EVENT_STEP_HANDOFF,
    AgentLedger,
    LedgerEvent,
)
from .identity import AgentIdentity, canonical_json, normalize_for_canonical_json

logger = logging.getLogger("nth_dao.achievement")


CREDENTIAL_CONTEXT = [
    "https://www.w3.org/ns/credentials/v2",
    "https://nth-dao.org/credentials/achievement/v1",
]
CREDENTIAL_TYPE = ["VerifiableCredential", "AchievementCredential"]
PROOF_TYPE = "Ed25519Signature2020"


def _period_bounds(period: str) -> Tuple[datetime, datetime]:
    """`period` like "2026-04" 鈫?(start, end inclusive) in naive local time.

    Matches `LedgerEvent.timestamp` which is `datetime.now().isoformat()`
    (naive, local) so string comparison works.
    """
    year_str, month_str = period.split("-", 1)
    year, month = int(year_str), int(month_str)
    if not (1 <= month <= 12):
        raise ValueError(f"invalid month in period {period!r}")
    last_day = calendar.monthrange(year, month)[1]
    return (
        datetime(year, month, 1, 0, 0, 0),
        datetime(year, month, last_day, 23, 59, 59, 999_999),
    )


def _bucket_period(timestamp: str) -> str:
    """Extract YYYY-MM from an ISO timestamp; "" on parse failure."""
    if not timestamp or len(timestamp) < 7:
        return ""
    return timestamp[:7]


def list_periods(ledger: AgentLedger) -> List[str]:
    """All YYYY-MM buckets that have at least one event, ascending."""
    seen: Dict[str, None] = {}
    for ev in ledger.all_events():
        p = _bucket_period(ev.timestamp)
        if p:
            seen[p] = None
    return sorted(seen.keys())


def reduce_period(ledger: AgentLedger, period: str) -> Dict[str, Any]:
    """Fold one month's events into a credentialSubject-shaped dict.

    Deterministic 鈥?same events 鈬?same dict. Empty-month returns a
    well-formed all-zeros snapshot so the caller can still issue a
    "no-activity" credential if desired (rarely useful; check the
    `event_count` field).
    """
    start, end = _period_bounds(period)
    events: List[LedgerEvent] = [
        ev for ev in ledger.all_events()
        if start.isoformat() <= ev.timestamp <= end.isoformat()
    ]
    subject: Dict[str, Any] = {
        "id": _agent_did(ledger),
        "period": period,
        "fingerprint": ledger.fingerprint,
        "event_count": len(events),
        "missions_owned": 0,
        "steps_completed": 0,
        "steps_failed": 0,
        "success_rate": 0.0,
        "handoffs_received": 0,
        "handoffs_given": 0,
        "reviews_given": 0,
        "reviews_received": 0,
        "endorsements_given": 0,
        "endorsements_received": 0,
        "templates_used": {},
        "categories": {},
        "total_token_cost": 0,
        "ledger_seq_start": events[0].seq if events else 0,
        "ledger_seq_end": events[-1].seq if events else 0,
        "ledger_hash_start": events[0].event_hash if events else "",
        "ledger_hash_end": events[-1].event_hash if events else "",
    }
    templates: Dict[str, int] = {}
    categories: Dict[str, int] = {}
    for ev in events:
        d = ev.data or {}
        if ev.type == EVENT_MISSION_OWNED:
            subject["missions_owned"] += 1
        elif ev.type == EVENT_STEP_COMPLETE:
            subject["steps_completed"] += 1
            subject["total_token_cost"] += int(d.get("token_cost", 0))
            if (tid := d.get("template_id")):
                templates[tid] = templates.get(tid, 0) + 1
            if (cat := d.get("category")):
                categories[cat] = categories.get(cat, 0) + 1
        elif ev.type == EVENT_STEP_FAILED:
            subject["steps_failed"] += 1
            if (cat := d.get("category")):
                categories[cat] = categories.get(cat, 0) + 1
        elif ev.type == EVENT_STEP_HANDOFF:
            if d.get("direction") == "received":
                subject["handoffs_received"] += 1
            elif d.get("direction") == "given":
                subject["handoffs_given"] += 1
        elif ev.type == EVENT_REVIEW_GIVEN:
            subject["reviews_given"] += 1
        elif ev.type == EVENT_REVIEW_RECEIVED:
            subject["reviews_received"] += 1
        elif ev.type == EVENT_ENDORSEMENT_GIVEN:
            subject["endorsements_given"] += 1
        elif ev.type == EVENT_ENDORSEMENT_RECEIVED:
            subject["endorsements_received"] += 1
    attempts = subject["steps_completed"] + subject["steps_failed"]
    subject["success_rate"] = (
        subject["steps_completed"] / attempts if attempts else 0.0
    )
    subject["templates_used"] = templates
    subject["categories"] = categories
    return subject


def _agent_did(ledger: AgentLedger) -> str:
    """Resolve the issuer DID for this ledger; fall back to fingerprint URN."""
    if ledger.identity and ledger.identity.pubkey_hex:
        try:
            return ledger.identity.as_did()
        except Exception:
            pass
    return f"urn:nth-dao:agent:{ledger.fingerprint}"


def build_credential(
    ledger: AgentLedger,
    period: str,
    *,
    issued_at: Optional[datetime] = None,
    verify_ledger: bool = True,
) -> Dict[str, Any]:
    """Build an *unsigned* AchievementCredential for the given month.

    Call `sign_credential(cred, identity)` afterwards for a proof block.
    """
    if verify_ledger and hasattr(ledger, "verify_chain"):
        ok, reason = ledger.verify_chain()
        if not ok:
            raise ValueError(f"ledger verification failed: {reason}")
    start, end = _period_bounds(period)
    issuer = _agent_did(ledger)
    issued = (issued_at or datetime.now(timezone.utc)).isoformat()
    return {
        "@context": list(CREDENTIAL_CONTEXT),
        "type": list(CREDENTIAL_TYPE),
        "issuer": issuer,
        "issuanceDate": issued,
        "validFrom": start.isoformat(),
        "validUntil": end.isoformat(),
        "credentialSubject": reduce_period(ledger, period),
    }


def sign_credential(
    credential: Dict[str, Any],
    identity: AgentIdentity,
    *,
    created_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Attach an Ed25519Signature2020 proof. The credential is returned
    with a new top-level "proof" key; the input dict is not mutated."""
    if not identity.can_sign:
        raise RuntimeError("identity has no signing key; cannot sign credential")
    issuer = credential.get("issuer", "")
    if not issuer:
        raise ValueError("credential issuer is required")
    subject = credential.get("credentialSubject", {})
    if not isinstance(subject, dict):
        raise ValueError("credentialSubject must be an object")
    if subject.get("id") != issuer:
        raise ValueError("credentialSubject.id must match issuer")
    if identity.pubkey_hex:
        try:
            expected_issuer = identity.as_did()
        except Exception:
            expected_issuer = ""
        if expected_issuer and expected_issuer != issuer:
            raise ValueError(
                "credential issuer does not match signing identity DID"
            )
    payload = normalize_for_canonical_json(
        {k: v for k, v in credential.items() if k != "proof"}
    )
    sig_hex = identity.sign_json(payload)
    created = (created_at or datetime.now(timezone.utc)).isoformat()
    proof = {
        "type": PROOF_TYPE,
        "created": created,
        "verificationMethod": f"{credential['issuer']}#{identity.pubkey_hex}",
        "proofPurpose": "assertionMethod",
        "proofValue": sig_hex,
    }
    return {**credential, "proof": proof}


def verify_credential(credential: Dict[str, Any]) -> Tuple[bool, str]:
    """Verify a signed credential against the embedded did:key issuer.

    Returns (ok, reason). A credential without a proof returns (False, ...).
    """
    proof = credential.get("proof")
    if not isinstance(proof, dict):
        return False, "missing proof"
    if credential.get("type") != CREDENTIAL_TYPE:
        return False, "unexpected credential type"
    sig_hex = proof.get("proofValue", "")
    if not sig_hex:
        return False, "missing proofValue"
    issuer = credential.get("issuer", "")
    if not issuer.startswith("did:key:"):
        return False, f"unsupported issuer scheme: {issuer!r}"
    if proof.get("type") != PROOF_TYPE:
        return False, "unexpected proof type"
    if proof.get("proofPurpose") != "assertionMethod":
        return False, "unexpected proof purpose"
    subject = credential.get("credentialSubject", {})
    if not isinstance(subject, dict):
        return False, "credentialSubject must be an object"
    if subject.get("id") != issuer:
        return False, "credentialSubject.id must match issuer"
    try:
        from .did_key import decode_ed25519_did_key
        from nacl.signing import VerifyKey
    except ImportError as e:
        return False, f"verification requires PyNaCl + did_key: {e}"
    payload = normalize_for_canonical_json(
        {k: v for k, v in credential.items() if k != "proof"}
    )
    try:
        pubkey_bytes = decode_ed25519_did_key(issuer)
        expected_fragment = f"{issuer}#{pubkey_bytes.hex()}"
        if proof.get("verificationMethod") != expected_fragment:
            return False, "verificationMethod does not match issuer key"
        VerifyKey(pubkey_bytes).verify(canonical_json(payload), bytes.fromhex(sig_hex))
    except Exception as e:
        return False, f"signature invalid: {e}"
    return True, "ok"


def credential_digest(credential: Dict[str, Any]) -> str:
    """Stable SHA-256 over canonical-JSON of the credential sans proof.

    Useful for caching, deduplication, and as a content-addressable key
    when publishing credentials to an external index.
    """
    payload = normalize_for_canonical_json({
        "@context": credential.get("@context"),
        "type": credential.get("type"),
        "issuer": credential.get("issuer"),
        "validFrom": credential.get("validFrom"),
        "validUntil": credential.get("validUntil"),
        "credentialSubject": credential.get("credentialSubject"),
    })
    return hashlib.sha256(canonical_json(payload)).hexdigest()


__all__ = [
    "build_credential",
    "credential_digest",
    "list_periods",
    "reduce_period",
    "sign_credential",
    "verify_credential",
    "CREDENTIAL_CONTEXT",
    "CREDENTIAL_TYPE",
]
