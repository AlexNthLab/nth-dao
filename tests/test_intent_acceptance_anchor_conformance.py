"""Deterministic anchor vectors and independent Node signature verification."""

import json
from pathlib import Path
import shutil
import subprocess

import pytest

from nth_dao.canonical_json import canonical_json
from nth_dao.plugins.intent_acceptance import IntentAcceptanceStore
from nth_dao.plugins.intent_acceptance_audit import IntentAcceptanceAuditError, IntentAcceptanceSpineBridge, verify_intent_acceptance_anchor
from nth_dao.plugins.intent_envelope import IntentAcceptanceContext
from nth_dao.spine import SignedEventLog, SpineEvent, verify_event
from tools.generate_intent_acceptance_anchor_vectors import anchor_vector_documents
from tools.generate_intent_envelope_vectors import _test_identity


ROOT = Path(__file__).parents[1] / "nth_dao/plugins/vectors"


def _vectors():
    return json.loads((ROOT / "intent-acceptance-anchor-cases-v1.json").read_text(encoding="utf-8"))


def test_anchor_vectors_are_reproducible():
    for name, document in anchor_vector_documents().items():
        assert json.loads((ROOT / name).read_text(encoding="utf-8")) == document


def test_python_anchor_vectors_and_resigned_negative_cases():
    vectors = _vectors()
    for case in vectors["positive_cases"]:
        result = verify_intent_acceptance_anchor(SpineEvent.from_dict(case["event"]), expected_audience_did=vectors["expected_audience_did"])
        assert canonical_json(result).hex() == case["payload_canonical_hex"]
    for case in vectors["negative_cases"]:
        event = SpineEvent.from_dict(case["event"])
        assert verify_event(event)[0] is case["signature_valid"], case["id"]
        with pytest.raises(IntentAcceptanceAuditError):
            verify_intent_acceptance_anchor(event, expected_audience_did=vectors["expected_audience_did"])
    for case in vectors["raw_negative_cases"]:
        with pytest.raises((IntentAcceptanceAuditError, ValueError)):
            verify_intent_acceptance_anchor(SpineEvent.from_dict(json.loads(case["event_json"])), expected_audience_did=vectors["expected_audience_did"])


def test_vectors_match_real_journal_projection(tmp_path):
    cases = json.loads((ROOT / "intent-envelope-wire-cases-v1.json").read_text(encoding="utf-8"))["positive_cases"][:2]
    clock = [0]
    store = IntentAcceptanceStore(tmp_path, clock=lambda: clock[0])
    for case in cases:
        clock[0] = case["now_ms"]
        expected = IntentAcceptanceContext(**(case["expected"] | {
            "allowed_solver_classes": tuple(case["expected"]["allowed_solver_classes"]),
        }))
        store.accept(case["envelope"], resolve_context=lambda _: expected)
    audience = _test_identity("intent-envelope-audience-v1")
    log = SignedEventLog(tmp_path / "vectors.spine.jsonl", audience)
    bridge = IntentAcceptanceSpineBridge(store, log, audience_did=audience.as_did())
    assert len(bridge.reconcile().anchors) == 2
    assert [event.payload for event in log.verified_snapshot()] == [case["event"]["payload"] for case in _vectors()["positive_cases"]]


def test_node_verifies_signed_anchor_vectors():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node required for independent conformance")
    vectors = _vectors()
    completed = subprocess.run(
        [node, str(Path(__file__).parent / "conformance/intent_acceptance_anchor.cjs")],
        input=json.dumps(vectors), text=True, encoding="utf-8", capture_output=True,
        timeout=30, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {"positive": 2, "negative": 16, "raw": 4}
