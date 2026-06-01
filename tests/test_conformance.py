"""v0.9.4 — Run the conformance vectors against the Python reference impl.

A non-Python port that wants wire compatibility must produce zero failures
under their own equivalent of `run_all_vectors()`. The Python reference
implementation MUST pass its own vectors; otherwise the file is wrong.
"""

import pytest

from nth_dao.conformance import (
    ConformanceFailure,
    load_vectors,
    run_all_vectors,
)


def test_vectors_file_loads():
    data = load_vectors()
    assert data["format"] == "nth-dao-conformance-v1"
    assert data["schema_version"] >= 1
    assert "vectors" in data
    assert len(data["vectors"]) >= 6


def test_python_reference_passes_all_vectors():
    """The Python implementation MUST pass its own conformance vectors."""
    failures = run_all_vectors()
    if failures:
        msg_lines = ["The Python reference fails its own vectors:"]
        for f in failures:
            msg_lines.append(
                f"  [{f.category}] {f.vector_id}  expected={f.expected!r}  actual={f.actual!r}"
            )
        pytest.fail("\n".join(msg_lines))


def test_each_category_has_at_least_one_vector():
    """Every documented category MUST ship at least one vector."""
    expected_categories = {
        "canonical_json",
        "fingerprint",
        "endorsement_canonical_payload",
        "template_canonical_payload",
        "channel_message_canonical",
        "invitation_canonical",
        "team_config_canonical",
        "did_key_encoding",
        "lan_psk_tag",
        "replay_window",
    }
    data = load_vectors()
    present = set(data["vectors"].keys())
    missing = expected_categories - present
    assert not missing, f"missing categories: {missing}"


def test_canonical_json_has_unicode_vector():
    """Cross-implementation unicode handling is critical; ensure coverage."""
    data = load_vectors()
    canon = data["vectors"].get("canonical_json", [])
    has_unicode = any("王" in str(v.get("input", {})) for v in canon)
    assert has_unicode, "no canonical_json vector tests unicode handling"


def test_replay_window_covers_both_boundaries():
    """Both past (replay) and future (skew) cases must be covered."""
    data = load_vectors()
    cases = data["vectors"].get("replay_window", [])
    has_past_reject = any(
        v["offset_seconds"] < -600 and not v["expected_within_window"]
        for v in cases
    )
    has_future_reject = any(
        v["offset_seconds"] > 60 and not v["expected_within_window"]
        for v in cases
    )
    assert has_past_reject, "no vector rejects ancient (replay) message"
    assert has_future_reject, "no vector rejects too-future (skew) message"
