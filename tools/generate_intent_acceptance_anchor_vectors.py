"""Generate deterministic public test identities and anchors, never local keys."""

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path

from nth_dao.canonical_json import canonical_json
from nth_dao.plugins.intent_acceptance import IntentAcceptanceRecord
from nth_dao.plugins.intent_acceptance_audit import (
    EVENT_INTENT_ACCEPTED, INTENT_ACCEPTANCE_ANCHOR_SCHEMA, _anchor_payload,
)
from nth_dao.spine import GENESIS_PREV, sign_event
from tools.generate_intent_envelope_vectors import _test_identity, vector_documents


def anchor_vector_documents():
    cases = vector_documents()["intent-envelope-wire-cases-v1.json"]["positive_cases"][:2]
    audience = _test_identity("intent-envelope-audience-v1")
    positives = []
    previous_observation, previous_event = "", GENESIS_PREV
    for n, case in enumerate(cases):
        record = IntentAcceptanceRecord(
            n + 1, case["document_digest"], canonical_json(case["envelope"]).decode(),
            canonical_json(case["expected"]).decode(), case["now_ms"], previous_observation, "",
        )
        record = replace(record, audit_digest="sha256:" + hashlib.sha256(canonical_json(record.audit)).hexdigest())
        payload = _anchor_payload(record)
        event = sign_event(seq=n, prev_hash=previous_event, event_type=EVENT_INTENT_ACCEPTED,
                           payload=payload, identity=audience, ts_ms=70000 + n)
        positives.append({"id": case["id"], "event": event.to_dict(),
                          "payload_canonical_hex": canonical_json(payload).hex()})
        previous_observation, previous_event = record.audit_digest, event.content_hash

    base = positives[0]["event"]["payload"]
    negatives = []
    for label, updates in [
        ("execute", {"executable": True}), ("numeric-false", {"commit_authority": 0}),
        ("unknown-field", {"payment": "unauthorized"}), ("wrong-version", {"format": "v2"}),
        ("wrong-authority", {"authority": "owner"}), ("boolean-time", {"accepted_at_ms": True}),
        ("wrong-predecessor", {"acceptance_sequence": 2}),
        ("wrong-observation", {"observation_digest": "sha256:" + "f" * 64}),
        ("wrong-envelope", {"envelope_digest": "sha256:" + "f" * 64}),
        ("trailing-control-digest", {"context_digest": base["context_digest"] + "\n"}),
        ("audience-mismatch", {"audience_did": _test_identity("anchor-stranger-v1").as_did()}),
        ("audience-fragment", {"audience_did": audience.as_did() + "#key-1"}),
    ]:
        event = sign_event(seq=0, prev_hash=GENESIS_PREV, event_type=EVENT_INTENT_ACCEPTED,
                           payload=base | updates, identity=audience, ts_ms=70000)
        negatives.append({"id": label, "event": event.to_dict(), "signature_valid": True})
    for label, identity, event_type, timestamp in [
        ("wrong-signer", _test_identity("anchor-stranger-v1"), EVENT_INTENT_ACCEPTED, 70000),
        ("wrong-event-type", audience, "trade.accepted", 70000),
        ("predates-observation", audience, EVENT_INTENT_ACCEPTED, 999),
    ]:
        event = sign_event(seq=0, prev_hash=GENESIS_PREV, event_type=event_type,
                           payload=base, identity=identity, ts_ms=timestamp)
        negatives.append({"id": label, "event": event.to_dict(), "signature_valid": True})
    tampered = deepcopy(positives[0]["event"])
    tampered["sig"] = "A" * 86
    negatives.append({"id": "invalid-signature", "event": tampered, "signature_valid": False})
    raw_cases = []
    for field in ("accepted_at_ms", "acceptance_sequence"):
        raw = canonical_json(positives[0]["event"]).decode()
        needle = json.dumps(field) + ":" + str(base[field])
        for token in (str(base[field]) + ".0", str(base[field]) + ".00000000000000001"):
            raw_cases.append({"id": field + "-" + token, "event_json": raw.replace(needle, json.dumps(field) + ":" + token, 1)})
    return {
        "intent-acceptance-anchor-schema-v1.json": deepcopy(INTENT_ACCEPTANCE_ANCHOR_SCHEMA),
        "intent-acceptance-anchor-cases-v1.json": {
            "format": "org.nth-dao.intent-acceptance-anchor-conformance.v1",
            "test_only": True,
            "expected_audience_did": audience.as_did(),
            "expected_public_key_hex": audience.pubkey_hex,
            "positive_cases": positives, "negative_cases": negatives, "raw_negative_cases": raw_cases,
        },
    }


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1] / "nth_dao/plugins/vectors"
    for name, document in anchor_vector_documents().items():
        (root / name).write_text(json.dumps(document, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
