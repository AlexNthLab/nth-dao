"""Independent Python and Node conformance for Intent policy snapshots."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

import pytest

from nth_dao.plugins.intent_acceptance import IntentAcceptanceHead
from nth_dao.plugins.intent_policy import (
    IntentAcceptancePolicySnapshot,
    IntentPolicyError,
    verify_intent_policy_successor,
)
from tools.generate_intent_policy_vectors import build_vectors


VECTOR = (
    Path(__file__).parents[1]
    / "nth_dao/plugins/vectors/intent-policy-wire-cases-v1.json"
)


def _vectors() -> dict:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_intent_policy_vectors_are_reproducible():
    assert _vectors() == build_vectors()


def test_python_validates_policy_vectors_and_resolution():
    vectors = _vectors()
    for case in vectors["positive_cases"]:
        policy = IntentAcceptancePolicySnapshot.from_dict(case["policy"])
        assert policy.canonical_bytes.hex() == case["canonical_hex"]
        assert policy.digest == case["digest"]
        resolution = case.get("resolution")
        if resolution is not None:
            expected = resolution["expected"]
            context = policy.resolve(
                signer_did=resolution["signer_did"],
                head=IntentAcceptanceHead(**resolution["head"]),
                now_ms=resolution["now_ms"],
            )
            assert context.__dict__ | {
                "allowed_solver_classes": list(context.allowed_solver_classes),
            } == expected
    for case in vectors["negative_cases"]:
        with pytest.raises(IntentPolicyError):
            IntentAcceptancePolicySnapshot.from_dict(case["policy"])
    for case in vectors["successor_cases"]:
        previous = IntentAcceptancePolicySnapshot.from_dict(case["previous"])
        successor = IntentAcceptancePolicySnapshot.from_dict(case["successor"])
        if case["valid"]:
            verify_intent_policy_successor(previous, successor)
        else:
            with pytest.raises(IntentPolicyError):
                verify_intent_policy_successor(previous, successor)


def test_node_independently_validates_policy_vectors():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node required for independent policy conformance")
    completed = subprocess.run(
        [node, str(Path(__file__).parent / "conformance/intent_policy.cjs"), str(VECTOR)],
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    vectors = _vectors()
    assert result == {
        "positive": len(vectors["positive_cases"]),
        "negative": len(vectors["negative_cases"]),
        "successors": len(vectors["successor_cases"]),
    }
