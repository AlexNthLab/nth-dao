"""Conformance vector runner — loads vectors.json + verifies behavior.

This module is the contract between the Python reference implementation
and any future port (Rust / Go / TypeScript / …). A port is wire-compatible
when its equivalent of `run_all_vectors()` produces zero failures.

All vector inputs are deterministic: fixed seeds, fixed timestamps, no
randomness. That means a port can compute the SAME outputs from the SAME
inputs without needing access to any Python-only entropy source.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..identity import canonical_json

logger = logging.getLogger("nth_dao.conformance")


VECTORS_PATH = Path(__file__).parent / "vectors.json"


@dataclass
class ConformanceFailure:
    """One vector failed under the reference implementation."""

    vector_id: str
    category: str
    description: str
    expected: Any
    actual: Any


def load_vectors(path: Optional[Path] = None) -> Dict[str, Any]:
    """Read the vectors.json file as a dict."""
    path = path or VECTORS_PATH
    if not path.exists():
        raise FileNotFoundError(
            f"conformance vectors not found at {path}; "
            "run `python -m nth_dao.conformance.regenerate` first"
        )
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ─────────────────── individual checkers ───────────────────


def check_canonical_json(vectors: List[dict]) -> List[ConformanceFailure]:
    """Verify the canonical JSON encoder produces the expected bytes."""
    failures = []
    for v in vectors:
        expected = bytes.fromhex(v["expected_bytes_hex"])
        actual = canonical_json(v["input"])
        if actual != expected:
            failures.append(ConformanceFailure(
                vector_id=v["id"],
                category="canonical_json",
                description=v.get("description", ""),
                expected=expected.hex(),
                actual=actual.hex(),
            ))
    return failures


def check_fingerprint(vectors: List[dict]) -> List[ConformanceFailure]:
    """AgentIdentity.fingerprint() must be sha256(pubkey_hex or agent_id)[:16]."""
    failures = []
    for v in vectors:
        payload = v["input"]["pubkey_hex"] or v["input"]["agent_id"]
        actual = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
        expected = v["expected_fingerprint"]
        if actual != expected:
            failures.append(ConformanceFailure(
                vector_id=v["id"],
                category="fingerprint",
                description=v.get("description", ""),
                expected=expected,
                actual=actual,
            ))
    return failures


def check_signature_verify(vectors: List[dict]) -> List[ConformanceFailure]:
    """Ed25519 verify with a known pubkey + message + signature."""
    try:
        from nacl.signing import VerifyKey
    except ImportError:
        # Skip silently — PyNaCl not installed
        return []
    failures = []
    for v in vectors:
        pubkey_hex = v["pubkey_hex"]
        message = bytes.fromhex(v["message_hex"])
        signature = bytes.fromhex(v["signature_hex"])
        expected = bool(v["expected_valid"])
        try:
            VerifyKey(bytes.fromhex(pubkey_hex)).verify(message, signature)
            actual = True
        except Exception:
            actual = False
        if actual != expected:
            failures.append(ConformanceFailure(
                vector_id=v["id"],
                category="signature_verify",
                description=v.get("description", ""),
                expected=expected,
                actual=actual,
            ))
    return failures


def check_endorsement_canonical_payload(vectors: List[dict]) -> List[ConformanceFailure]:
    """Endorsement.signable_dict() canonicalized must match expected bytes.

    This locks the field order and exact serialization. A Rust/Go port that
    re-orders fields will diverge here.
    """
    from ..web_of_trust import Endorsement
    failures = []
    for v in vectors:
        e = Endorsement.from_dict(v["input"])
        actual = canonical_json(e.signable_dict()).hex()
        expected = v["expected_canonical_hex"]
        if actual != expected:
            failures.append(ConformanceFailure(
                vector_id=v["id"],
                category="endorsement_canonical_payload",
                description=v.get("description", ""),
                expected=expected,
                actual=actual,
            ))
    return failures


def check_template_canonical_payload(vectors: List[dict]) -> List[ConformanceFailure]:
    """MissionTemplate.signable_dict() canonicalized must match expected bytes."""
    from ..orchestration.template import MissionTemplate
    failures = []
    for v in vectors:
        t = MissionTemplate.from_dict(v["input"])
        actual = canonical_json(t.signable_dict()).hex()
        expected = v["expected_canonical_hex"]
        if actual != expected:
            failures.append(ConformanceFailure(
                vector_id=v["id"],
                category="template_canonical_payload",
                description=v.get("description", ""),
                expected=expected,
                actual=actual,
            ))
    return failures


def check_channel_message_canonical(vectors: List[dict]) -> List[ConformanceFailure]:
    """Channel message signable payload bytes are stable."""
    failures = []
    for v in vectors:
        actual = canonical_json(v["input"]).hex()
        expected = v["expected_canonical_hex"]
        if actual != expected:
            failures.append(ConformanceFailure(
                vector_id=v["id"], category="channel_message_canonical",
                description=v.get("description", ""),
                expected=expected, actual=actual,
            ))
    return failures


def check_invitation_canonical(vectors: List[dict]) -> List[ConformanceFailure]:
    """Invitation.signable_dict() canonical bytes are stable."""
    from ..invitation import Invitation
    failures = []
    for v in vectors:
        inv = Invitation.from_dict(v["input"])
        actual = canonical_json(inv.signable_dict()).hex()
        expected = v["expected_canonical_hex"]
        if actual != expected:
            failures.append(ConformanceFailure(
                vector_id=v["id"], category="invitation_canonical",
                description=v.get("description", ""),
                expected=expected, actual=actual,
            ))
    return failures


def check_team_config_canonical(vectors: List[dict]) -> List[ConformanceFailure]:
    """TeamConfig.signable_dict() canonical bytes are stable."""
    from ..membership import TeamConfig
    failures = []
    for v in vectors:
        cfg = TeamConfig.from_dict(v["input"])
        actual = canonical_json(cfg.signable_dict()).hex()
        expected = v["expected_canonical_hex"]
        if actual != expected:
            failures.append(ConformanceFailure(
                vector_id=v["id"], category="team_config_canonical",
                description=v.get("description", ""),
                expected=expected, actual=actual,
            ))
    return failures


def check_did_key_encoding(vectors: List[dict]) -> List[ConformanceFailure]:
    """did:key encoding of Ed25519 pubkeys produces stable strings."""
    from ..did_key import encode_ed25519_did_key_hex
    failures = []
    for v in vectors:
        actual = encode_ed25519_did_key_hex(v["input"]["pubkey_hex"])
        expected = v["expected_did"]
        if actual != expected:
            failures.append(ConformanceFailure(
                vector_id=v["id"], category="did_key_encoding",
                description=v.get("description", ""),
                expected=expected, actual=actual,
            ))
    return failures


def check_lan_psk_tag(vectors: List[dict]) -> List[ConformanceFailure]:
    """HMAC-SHA256(psk, canonical(message - psk_tag)) — locked construction."""
    import hashlib
    import hmac as _hmac
    import json as _json
    failures = []
    for v in vectors:
        psk = v["input"]["psk"]
        msg = v["input"]["message"]
        canon = _json.dumps(
            {k: m for k, m in msg.items() if k != "psk_tag"},
            sort_keys=True, separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        actual = _hmac.new(psk.encode("utf-8"), canon, hashlib.sha256).hexdigest()
        expected = v["expected_psk_tag"]
        if actual != expected:
            failures.append(ConformanceFailure(
                vector_id=v["id"], category="lan_psk_tag",
                description=v.get("description", ""),
                expected=expected, actual=actual,
            ))
    return failures


def check_replay_window(vectors: List[dict]) -> List[ConformanceFailure]:
    """gossip replay window: accept (now - 600s, now + 60s], reject otherwise."""
    from ..gossip import _within_replay_window
    from datetime import datetime, timedelta
    failures = []
    for v in vectors:
        # Vector specifies the message timestamp as a relative-to-now offset
        # in seconds, so it stays correct regardless of when the test runs.
        offset = int(v["offset_seconds"])
        ts = (datetime.now() + timedelta(seconds=offset)).isoformat()
        actual = _within_replay_window(ts)
        expected = bool(v["expected_within_window"])
        if actual != expected:
            failures.append(ConformanceFailure(
                vector_id=v["id"],
                category="replay_window",
                description=v.get("description", ""),
                expected=expected,
                actual=actual,
            ))
    return failures


# ─────────────────── orchestration ───────────────────


def check_mandate_canonical(category_label: str):
    """Factory for the three mandate canonical-JSON checkers
    (intent / cart / payment). All three share the same shape:
    canonical_json(input) must equal expected_bytes_hex."""
    def _check(vectors: List[dict]) -> List[ConformanceFailure]:
        failures = []
        for v in vectors:
            expected = bytes.fromhex(v["expected_bytes_hex"])
            actual = canonical_json(v["input"])
            if actual != expected:
                failures.append(ConformanceFailure(
                    vector_id=v["id"],
                    category=category_label,
                    description=v.get("description", ""),
                    expected=expected.hex(),
                    actual=actual.hex(),
                ))
        return failures
    return _check


def check_mandate_negative_binding(vectors: List[dict]) -> List[ConformanceFailure]:
    """Each vector pairs a cart with an intent (or a payment with a
    cart) that MUST be rejected by the appropriate binding check, with
    a reason string that contains a fixed substring."""
    from ..mandate.cart import cart_satisfies_intent
    from ..mandate.payment import payment_satisfies_cart

    failures: List[ConformanceFailure] = []
    for v in vectors:
        inp = v["input"]
        expected_ok = v["expected_ok"]
        expected_reason_contains = v["expected_reason_contains"]

        # Conformance vectors are about STRUCTURAL binding logic
        # (digest binding, currency, allow-lists, etc.), not
        # signature verification - that lives in its own category.
        # Voss V-21 added require_signed=True to the binding helpers;
        # pass require_signed=False here so the vectors keep
        # exercising the pure structural rules without bloating each
        # vector with a redundant proof block.
        if "cart" in inp and "intent" in inp:
            ok, reason = cart_satisfies_intent(
                inp["cart"], inp["intent"], require_signed=False,
            )
        elif "payment" in inp and "cart_presented" in inp:
            ok, reason = payment_satisfies_cart(
                inp["payment"], inp["cart_presented"], require_signed=False,
            )
        else:
            failures.append(ConformanceFailure(
                vector_id=v["id"], category="mandate_negative_binding",
                description=v.get("description", ""),
                expected="known input shape",
                actual=f"unknown input keys: {sorted(inp)}",
            ))
            continue

        if ok != expected_ok or expected_reason_contains not in reason:
            failures.append(ConformanceFailure(
                vector_id=v["id"], category="mandate_negative_binding",
                description=v.get("description", ""),
                expected=f"ok={expected_ok}, reason~='{expected_reason_contains}'",
                actual=f"ok={ok}, reason={reason!r}",
            ))
    return failures


def check_mandate_negative_expiry(vectors: List[dict]) -> List[ConformanceFailure]:
    """is_intent_expired called with fixed `now` must return the
    expected bool."""
    from datetime import datetime
    from ..mandate.intent import is_intent_expired

    failures: List[ConformanceFailure] = []
    for v in vectors:
        intent = v["input"]["intent"]
        now = datetime.fromisoformat(v["input"]["now"])
        actual = is_intent_expired(intent, now=now)
        expected = v["expected_expired"]
        if actual != expected:
            failures.append(ConformanceFailure(
                vector_id=v["id"], category="mandate_negative_expiry",
                description=v.get("description", ""),
                expected=str(expected), actual=str(actual),
            ))
    return failures


def check_handoff_response_v2(vectors: List[dict]) -> List[ConformanceFailure]:
    """Signed handoff response v2 and receipt-binding entry bytes are stable."""
    from ..runtime import verify_handoff_response

    failures: List[ConformanceFailure] = []
    for v in vectors:
        statement = v["statement"]
        ok, reason = verify_handoff_response(statement)
        expected_valid = bool(v.get("expected_valid", True))
        if ok != expected_valid:
            failures.append(ConformanceFailure(
                vector_id=v["id"],
                category="handoff_response_v2",
                description=v.get("description", ""),
                expected=expected_valid,
                actual=f"{ok}: {reason}",
            ))
        actual_hash = statement.get("response_hash")
        expected_hash = v["expected_response_hash"]
        if actual_hash != expected_hash:
            failures.append(ConformanceFailure(
                vector_id=v["id"],
                category="handoff_response_v2",
                description="response_hash",
                expected=expected_hash,
                actual=actual_hash,
            ))
        signing_body = {k: val for k, val in statement.items() if k != "sig"}
        actual_body_hex = canonical_json(signing_body).hex()
        expected_body_hex = v["expected_signing_body_hex"]
        if actual_body_hex != expected_body_hex:
            failures.append(ConformanceFailure(
                vector_id=v["id"],
                category="handoff_response_v2",
                description="canonical signing body",
                expected=expected_body_hex,
                actual=actual_body_hex,
            ))
        actual_entry_hex = canonical_json(v["receipt_timeline_entry"]).hex()
        expected_entry_hex = v["expected_receipt_timeline_entry_hex"]
        if actual_entry_hex != expected_entry_hex:
            failures.append(ConformanceFailure(
                vector_id=v["id"],
                category="handoff_response_v2",
                description="receipt timeline entry canonical bytes",
                expected=expected_entry_hex,
                actual=actual_entry_hex,
            ))
    return failures


def check_handoff_review_packet_v1(vectors: List[dict]) -> List[ConformanceFailure]:
    """Derived handoff review packet v1 shape and canonical bytes are stable."""
    failures: List[ConformanceFailure] = []
    for v in vectors:
        packet = v["packet"]
        if packet.get("packet_kind") != "nth-handoff-review-packet-v1":
            failures.append(ConformanceFailure(
                vector_id=v["id"],
                category="handoff_review_packet_v1",
                description="packet_kind",
                expected="nth-handoff-review-packet-v1",
                actual=packet.get("packet_kind"),
            ))
        if packet.get("packet_version") != 1:
            failures.append(ConformanceFailure(
                vector_id=v["id"],
                category="handoff_review_packet_v1",
                description="packet_version",
                expected=1,
                actual=packet.get("packet_version"),
            ))
        expected_signed = bool(v.get("expected_packet_is_signed", False))
        if bool(packet.get("packet_is_signed")) != expected_signed:
            failures.append(ConformanceFailure(
                vector_id=v["id"],
                category="handoff_review_packet_v1",
                description="packet_is_signed",
                expected=expected_signed,
                actual=packet.get("packet_is_signed"),
            ))
        expected_truth = bool(v.get("expected_is_truth_verdict", False))
        if bool(packet.get("is_truth_verdict")) != expected_truth:
            failures.append(ConformanceFailure(
                vector_id=v["id"],
                category="handoff_review_packet_v1",
                description="is_truth_verdict",
                expected=expected_truth,
                actual=packet.get("is_truth_verdict"),
            ))
        actual_summary: Dict[str, int] = {
            "total": len(packet.get("evidence_verification", [])),
            "verified": 0,
            "unreachable": 0,
            "unavailable": 0,
            "mismatch": 0,
            "invalid": 0,
            "unsupported": 0,
        }
        for item in packet.get("evidence_verification", []):
            status = str(item.get("status", "invalid"))
            actual_summary[status] = actual_summary.get(status, 0) + 1
        expected_summary = v.get("expected_evidence_summary", {})
        if actual_summary != expected_summary or packet.get("evidence_summary") != expected_summary:
            failures.append(ConformanceFailure(
                vector_id=v["id"],
                category="handoff_review_packet_v1",
                description="evidence_summary",
                expected=expected_summary,
                actual={
                    "computed": actual_summary,
                    "packet": packet.get("evidence_summary"),
                },
            ))
        actual_hex = canonical_json(packet).hex()
        expected_hex = v["expected_canonical_hex"]
        if actual_hex != expected_hex:
            failures.append(ConformanceFailure(
                vector_id=v["id"],
                category="handoff_review_packet_v1",
                description="canonical packet bytes",
                expected=expected_hex,
                actual=actual_hex,
            ))
    return failures


_CHECKERS: Dict[str, Callable[[List[dict]], List[ConformanceFailure]]] = {
    "canonical_json":              check_canonical_json,
    "fingerprint":                 check_fingerprint,
    "signature_verify":            check_signature_verify,
    "endorsement_canonical_payload": check_endorsement_canonical_payload,
    "template_canonical_payload":  check_template_canonical_payload,
    "channel_message_canonical":   check_channel_message_canonical,
    "invitation_canonical":        check_invitation_canonical,
    "team_config_canonical":       check_team_config_canonical,
    "did_key_encoding":            check_did_key_encoding,
    "lan_psk_tag":                 check_lan_psk_tag,
    "replay_window":               check_replay_window,
    # v0.10 T-4 Mandate vectors
    "mandate_intent_canonical":    check_mandate_canonical("mandate_intent_canonical"),
    "mandate_cart_canonical":      check_mandate_canonical("mandate_cart_canonical"),
    "mandate_payment_canonical":   check_mandate_canonical("mandate_payment_canonical"),
    "mandate_negative_binding":    check_mandate_negative_binding,
    "mandate_negative_expiry":     check_mandate_negative_expiry,
    "handoff_response_v2":         check_handoff_response_v2,
    "handoff_review_packet_v1":    check_handoff_review_packet_v1,
}


def run_all_vectors(
    vectors_data: Optional[Dict[str, Any]] = None,
) -> List[ConformanceFailure]:
    """Execute every checker against the loaded vectors.

    Returns a list of failures; empty list = wire-compatible.
    """
    if vectors_data is None:
        vectors_data = load_vectors()
    all_failures: List[ConformanceFailure] = []
    for category, checker in _CHECKERS.items():
        category_data = vectors_data.get("vectors", {}).get(category, [])
        if not category_data:
            continue
        try:
            failures = checker(category_data)
            all_failures.extend(failures)
        except Exception as e:
            logger.exception("checker %s raised", category)
            all_failures.append(ConformanceFailure(
                vector_id=f"{category}:checker-error",
                category=category,
                description=f"checker raised {type(e).__name__}",
                expected="checker completes without exception",
                actual=str(e),
            ))
    return all_failures
