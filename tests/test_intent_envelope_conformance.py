"""Independent Ed25519/canonical/semantic wire verification in Python and Node."""

from copy import deepcopy
from dataclasses import fields, replace
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from nth_dao.canonical_json import canonical_json
from nth_dao.identity import AgentIdentity
from nth_dao.plugins.intent_envelope import (
    INTENT_ENVELOPE_SIGNING_DOMAIN,
    INTENT_ENVELOPE_SCHEMA,
    IntentAcceptanceContext,
    IntentEnvelopeError,
    intent_envelope_digest,
    intent_envelope_signing_bytes,
    verify_intent_envelope,
)
from nth_dao.plugins.intent_resolver import INTENT_DRAFT_SCHEMA
from tools.generate_intent_envelope_vectors import vector_documents


VECTOR_ROOT = Path(__file__).resolve().parents[1] / "nth_dao" / "plugins" / "vectors"


def _vectors():
    return json.loads((VECTOR_ROOT / "intent-envelope-wire-cases-v1.json").read_text(encoding="utf-8"))


def _expected(value):
    # Test-fixture JSON uses arrays; never coerce scalars into a Python policy tuple.
    if type(value) is not dict or set(value) != {field.name for field in fields(IntentAcceptanceContext)}:
        raise IntentEnvelopeError("invalid expected context fields")
    if type(value["allowed_solver_classes"]) is not list:
        raise IntentEnvelopeError("expected solver classes must be a JSON array")
    return IntentAcceptanceContext(**(value | {"allowed_solver_classes": tuple(value["allowed_solver_classes"])}))


def _negative_cases(vectors):
    first = vectors["positive_cases"][0]
    for case in vectors["negative_cases"]:
        expected = deepcopy(first["expected"]) | case["expected_updates"]
        for field in case.get("expected_omissions", []):
            expected.pop(field)
        yield {
            "id": case["id"],
            "envelope": deepcopy(first["envelope"]) | case["body_updates"] | {"signature": case["signature"]},
            "expected": expected,
            "now_ms": case["now_ms"], "signature_valid": case["signature_valid"],
        }


def test_vectors_reproducible_without_local_keys():
    pytest.importorskip("nacl.signing")
    for name, document in vector_documents().items():
        assert json.loads((VECTOR_ROOT / name).read_text(encoding="utf-8")) == document


def test_python_signed_vectors():
    pytest.importorskip("nacl.signing")
    vectors = _vectors()
    for case in vectors["positive_cases"]:
        envelope = case["envelope"]
        assert verify_intent_envelope(envelope, expected=_expected(case["expected"]), now_ms=case["now_ms"]) == envelope
        assert intent_envelope_digest(envelope) == case["document_digest"]
        body = {k: v for k, v in envelope.items() if k != "signature"}
        assert intent_envelope_signing_bytes(body).hex() == case["signing_bytes_hex"]
    for case in _negative_cases(vectors):
        envelope = case["envelope"]
        body = {k: v for k, v in envelope.items() if k != "signature"}
        verifier = AgentIdentity.from_did(envelope["signer_did"])
        # Re-signed malformed cases must fail semantics, not merely bad crypto.
        assert verifier.verify(
            INTENT_ENVELOPE_SIGNING_DOMAIN + canonical_json(body), bytes.fromhex(envelope["signature"]),
        ) is case["signature_valid"], case["id"]
        with pytest.raises(IntentEnvelopeError):
            verify_intent_envelope(envelope, expected=_expected(case["expected"]), now_ms=case["now_ms"])


def test_node_verifies_python_and_python_verifies_node():
    pytest.importorskip("nacl.signing")
    node = shutil.which("node")
    if not node:
        pytest.skip("Node required for independent conformance")
    vectors = _vectors()
    payload = {
        "vectors": vectors, "negative_cases": list(_negative_cases(vectors)),
        "schema": INTENT_ENVELOPE_SCHEMA, "draftSchema": INTENT_DRAFT_SCHEMA,
    }
    completed = subprocess.run(
        [node, str(Path(__file__).parent / "conformance" / "intent_envelope.cjs")],
        input=json.dumps(payload, ensure_ascii=False), text=True, encoding="utf-8",
        capture_output=True, timeout=30, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["positive"] == len(vectors["positive_cases"])
    assert result["negative"] == len(vectors["negative_cases"])
    assert result["raw_json"] == len(vectors["raw_json_cases"])
    expected = replace(_expected(vectors["positive_cases"][0]["expected"]), signer_did=result["envelope"]["signer_did"])
    assert verify_intent_envelope(result["envelope"], expected=expected, now_ms=1000) == result["envelope"]


def test_python_raw_json_vectors():
    pytest.importorskip("nacl.signing")
    for case in _vectors()["raw_json_cases"]:
        accepted = False
        try:
            parsed = json.loads(case["case_json"])
            verify_intent_envelope(
                parsed["envelope"], expected=_expected(parsed["expected"]), now_ms=parsed["now_ms"],
            )
            accepted = True
        except (IntentEnvelopeError, json.JSONDecodeError):
            pass
        assert accepted is case["accept"], case["id"]


@pytest.mark.parametrize("section,field", [
    ("envelope", "issued_at_ms"), ("envelope", "expires_at_ms"),
    ("envelope", "revision"), ("expected", "revision"), (None, "now_ms"),
])
def test_node_rejects_float_tokens_before_rounding(section, field):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node required for independent conformance")
    vectors = _vectors()
    case = deepcopy(vectors["positive_cases"][0])
    case["id"] = "raw-float-token"
    target = case[section] if section else case
    target[field] = float(target[field])
    completed = subprocess.run(
        [node, str(Path(__file__).parent / "conformance" / "intent_envelope.cjs")],
        input=json.dumps({
            "vectors": vectors, "negative_cases": [case],
            "schema": INTENT_ENVELOPE_SCHEMA, "draftSchema": INTENT_DRAFT_SCHEMA,
        }, ensure_ascii=False), text=True, encoding="utf-8", capture_output=True,
        timeout=30, check=False,
    )
    assert completed.returncode != 0
    assert "JSON number must use an integer token" in completed.stderr
    assert "negative accepted" not in completed.stderr


@pytest.mark.parametrize("mutation", ["token-guard", "missing-source-context"])
def test_node_raw_json_defenses_fail_closed(mutation):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node required for independent conformance")
    root = Path(__file__).parent / "conformance"
    source = (root / "intent_envelope.cjs").read_text(encoding="utf-8")
    if mutation == "token-guard":
        guard = "check(/^-?(?:0|[1-9][0-9]*)$/.test(context.source), 'JSON number must use an integer token');"
        assert source.count(guard) == 1
        source = source.replace(guard, "", 1)
        expected_error = "raw JSON result mismatch: raw-envelope-issued_at_ms-decimal"
    else:
        source = (
            "const originalParse = JSON.parse;"
            "JSON.parse = (raw, reviver) => originalParse(raw, reviver && function(k,v) {"
            "return reviver.call(this,k,v); });\n" + source
        )
        expected_error = "Conformance requires native JSON.parse source context"
    completed = subprocess.run(
        [node, "-e", source], cwd=root,
        input=json.dumps({
            "vectors": _vectors(), "negative_cases": [],
            "schema": INTENT_ENVELOPE_SCHEMA, "draftSchema": INTENT_DRAFT_SCHEMA,
        }, ensure_ascii=False), text=True, encoding="utf-8", capture_output=True,
        timeout=30, check=False,
    )
    assert completed.returncode != 0
    assert expected_error in completed.stderr


@pytest.mark.parametrize("guard,case_id", [
    ("primeOrderPoint(publicKey); ", "crypto-public-key-mixed-equation"),
    ("primeOrderPoint(signatureBytes.subarray(0, 32));", "crypto-R-zero-nonce-equation"),
    ("  validateExpectedContext(expected);", "context-duplicate-policy"),
])
def test_vectors_detect_removed_guards(guard, case_id):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node required for independent conformance")
    root = Path(__file__).parent / "conformance"
    source = (root / "intent_envelope.cjs").read_text(encoding="utf-8")
    assert source.count(guard) == 1
    vectors = _vectors()
    case = next(case for case in _negative_cases(vectors) if case["id"] == case_id)
    completed = subprocess.run(
        [node, "-e", source.replace(guard, "", 1)], cwd=root,
        input=json.dumps({
            "vectors": vectors, "negative_cases": [case],
            "schema": INTENT_ENVELOPE_SCHEMA, "draftSchema": INTENT_DRAFT_SCHEMA,
        }, ensure_ascii=False), text=True, encoding="utf-8", capture_output=True,
        timeout=30, check=False,
    )
    assert completed.returncode != 0
    assert "negative accepted: " + case_id in completed.stderr
