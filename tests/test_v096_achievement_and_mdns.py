"""Tests for v0.9.6 AchievementCredential reducer and the optional mDNS backend.

The mDNS tests are skipped automatically when `zeroconf` is not installed
(i.e. the `[lan]` extra was not pulled in), so the rest of the suite runs
green on the zero-dep core install.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from nth_dao.achievement import (
    build_credential,
    credential_digest,
    list_periods,
    reduce_period,
    sign_credential,
    verify_credential,
)
from nth_dao.agent_ledger import AgentLedger
from nth_dao.identity import AgentIdentity, crypto_available


# ─── Achievement reducer ─────────────────────────────────────────────────


@pytest.fixture
def signing_identity():
    if not crypto_available():
        pytest.skip("PyNaCl not installed — signing-credential tests skipped")
    return AgentIdentity.generate(label="alice")


@pytest.fixture
def busy_ledger(tmp_path: Path, signing_identity):
    ledger = AgentLedger(tmp_path, identity=signing_identity)
    # synthesize a handful of events; timestamps come from "now" so they all
    # land in today's month — exactly what monthly fold is for.
    ledger.record_mission_owned("m-1", template_id="code-review")
    ledger.record_step_complete(
        "m-1", "s-1", template_id="code-review", template_version="1.0.0",
        category="code_review", token_cost=4800, elapsed_seconds=120,
    )
    ledger.record_step_complete(
        "m-1", "s-2", template_id="code-review", template_version="1.0.0",
        category="code_review", token_cost=3100, elapsed_seconds=60,
    )
    ledger.record_step_failed(
        "m-1", "s-3", template_id="triage", category="triage", reason="timeout",
    )
    ledger.record_handoff_received("m-1", "s-2", from_agent="bob",
                                   template_id="code-review")
    ledger.record_review_given("code-review", "1.0.0", "m-1", 0.92)
    ledger.record_endorsement_received(endorser_pubkey="b" * 64, context="general")
    return ledger


def test_list_periods_returns_current_month(busy_ledger):
    periods = list_periods(busy_ledger)
    assert len(periods) >= 1
    current = datetime.now().strftime("%Y-%m")
    assert current in periods


def test_reduce_period_correct_counts(busy_ledger):
    current = datetime.now().strftime("%Y-%m")
    subj = reduce_period(busy_ledger, current)
    assert subj["missions_owned"] == 1
    assert subj["steps_completed"] == 2
    assert subj["steps_failed"] == 1
    assert subj["handoffs_received"] == 1
    assert subj["reviews_given"] == 1
    assert subj["endorsements_received"] == 1
    assert subj["templates_used"] == {"code-review": 2}
    assert subj["categories"] == {"code_review": 2, "triage": 1}
    # 2 completed + 1 failed → success_rate = 2/3
    assert abs(subj["success_rate"] - (2 / 3)) < 1e-9
    assert subj["total_token_cost"] == 4800 + 3100
    # Period seq pinning — the ledger ran exactly the events we recorded
    assert subj["ledger_seq_start"] == 1
    assert subj["ledger_seq_end"] == 7


def test_reduce_period_invalid_month():
    fake_ledger = type("L", (), {"all_events": lambda self: [], "fingerprint": "x"})()
    with pytest.raises(ValueError):
        reduce_period(fake_ledger, "2026-13")


def test_reduce_period_empty_month(busy_ledger):
    subj = reduce_period(busy_ledger, "2024-01")  # before any data exists
    assert subj["event_count"] == 0
    assert subj["steps_completed"] == 0
    assert subj["success_rate"] == 0.0
    assert subj["ledger_seq_start"] == 0
    assert subj["ledger_seq_end"] == 0


def test_build_credential_shape(busy_ledger):
    current = datetime.now().strftime("%Y-%m")
    cred = build_credential(busy_ledger, current)
    assert cred["type"] == ["VerifiableCredential", "AchievementCredential"]
    assert cred["@context"][0].startswith("https://www.w3.org/")
    assert cred["issuer"].startswith("did:key:")
    assert cred["credentialSubject"]["period"] == current
    assert "proof" not in cred                  # unsigned by default


def test_sign_and_verify_credential(busy_ledger, signing_identity):
    current = datetime.now().strftime("%Y-%m")
    cred = build_credential(busy_ledger, current)
    signed = sign_credential(cred, signing_identity)
    assert "proof" in signed
    assert signed["proof"]["type"] == "Ed25519Signature2020"
    ok, reason = verify_credential(signed)
    assert ok, reason


def test_verify_credential_rejects_tampered(busy_ledger, signing_identity):
    current = datetime.now().strftime("%Y-%m")
    cred = build_credential(busy_ledger, current)
    signed = sign_credential(cred, signing_identity)
    # tamper with the steps_completed count
    signed["credentialSubject"]["steps_completed"] = 9999
    ok, reason = verify_credential(signed)
    assert not ok
    assert "signature invalid" in reason


def test_verify_credential_rejects_missing_proof(busy_ledger):
    current = datetime.now().strftime("%Y-%m")
    cred = build_credential(busy_ledger, current)
    ok, reason = verify_credential(cred)
    assert not ok
    assert "missing proof" in reason


def test_credential_digest_stable(busy_ledger, signing_identity):
    current = datetime.now().strftime("%Y-%m")
    cred = build_credential(
        busy_ledger,
        current,
        issued_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    d1 = credential_digest(cred)
    # adding a proof must NOT change the digest (proof is excluded)
    signed = sign_credential(cred, signing_identity)
    d2 = credential_digest(signed)
    assert d1 == d2
    rebuilt_later = build_credential(
        busy_ledger,
        current,
        issued_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )
    assert credential_digest(rebuilt_later) == d1
    # mutating the subject DOES change the digest
    cred["credentialSubject"]["steps_completed"] += 1
    d3 = credential_digest(cred)
    assert d1 != d3


def test_verify_credential_rejects_bad_proof_semantics(busy_ledger, signing_identity):
    current = datetime.now().strftime("%Y-%m")
    signed = sign_credential(build_credential(busy_ledger, current), signing_identity)
    signed["proof"]["proofPurpose"] = "authentication"
    ok, reason = verify_credential(signed)
    assert not ok
    assert "proof purpose" in reason


def test_sign_credential_rejects_issuer_mismatch(busy_ledger):
    current = datetime.now().strftime("%Y-%m")
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    cred = build_credential(busy_ledger, current)
    cred["issuer"] = bob.as_did()
    with pytest.raises(ValueError, match="issuer"):
        sign_credential(cred, alice)


def test_sign_credential_rejects_subject_mismatch(busy_ledger, signing_identity):
    current = datetime.now().strftime("%Y-%m")
    cred = build_credential(busy_ledger, current)
    cred["credentialSubject"]["id"] = "did:key:zWrong"
    with pytest.raises(ValueError, match="credentialSubject.id"):
        sign_credential(cred, signing_identity)


def test_build_credential_rejects_corrupt_ledger(tmp_path: Path, signing_identity):
    ledger = AgentLedger(tmp_path, identity=signing_identity)
    ledger.record_step_complete("m-1", "s-1", token_cost=1)
    line = json.loads(ledger.ledger_path.read_text(encoding="utf-8").splitlines()[0])
    line["event_hash"] = "0" * 64
    ledger.ledger_path.write_text(json.dumps(line) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="ledger verification failed"):
        build_credential(ledger, datetime.now().strftime("%Y-%m"))


# ─── mDNS backend (skipped when [lan] not installed) ─────────────────────


def _can_import_zeroconf() -> bool:
    try:
        import zeroconf  # noqa: F401
    except ImportError:
        return False
    return True


_zeroconf_importable = _can_import_zeroconf()
mdns_skip = pytest.mark.skipif(
    not _zeroconf_importable,
    reason="zeroconf not installed — `pip install nth-dao[lan]` to enable",
)


@mdns_skip
def test_mdns_module_imports_when_zeroconf_present():
    # Just confirm the optional backend is reachable. Real network discovery
    # is too flaky for CI; the contract is "import works + sane API surface".
    from nth_dao.discovery import lan_mdns

    assert hasattr(lan_mdns, "MDNSDiscovery")
    assert lan_mdns.is_available() is True


@mdns_skip
def test_mdns_pack_unpack_roundtrip():
    from nth_dao.discovery.lan_mdns import _pack_props, _unpack_props

    src = {
        "agent_id": "alice",
        "label": "Alice's laptop",
        "capabilities": ["python", "web"],
        "groups": ["nth-dao-core", "privacy-wg"],
        "ws_url": "ws://1.2.3.4:9876",
        "pubkey_hex": "a" * 64,
    }
    packed = _pack_props(src)
    assert all(isinstance(k, bytes) and isinstance(v, bytes) for k, v in packed.items())
    unpacked = _unpack_props(packed)
    assert unpacked["agent_id"] == "alice"
    assert unpacked["capabilities"] == ["python", "web"]
    assert unpacked["groups"] == ["nth-dao-core", "privacy-wg"]
    assert unpacked["ws_url"] == "ws://1.2.3.4:9876"


def test_mdns_rejects_truncated_critical_fields():
    from nth_dao.discovery.lan_mdns import _pack_props

    with pytest.raises(ValueError, match="agent_id"):
        _pack_props({"agent_id": "a" * 300})


def test_mdns_truncates_display_fields_on_utf8_boundary():
    from nth_dao.discovery.lan_mdns import TXT_MAX_VALUE_BYTES, _pack_props, _unpack_props

    packed = _pack_props({"label": "测" * 100})
    assert len(packed[b"label"]) <= TXT_MAX_VALUE_BYTES
    unpacked = _unpack_props(packed)
    assert unpacked["label"]
    assert "�" not in unpacked["label"]


def test_mdns_module_clean_failure_without_zeroconf():
    # When zeroconf is missing the discovery package still imports cleanly,
    # `mdns_available()` reports False, and calling MDNSDiscovery().start()
    # raises a clear ImportError pointing at the `[lan]` extra.
    from nth_dao import discovery

    assert hasattr(discovery, "mdns_available")
    if not _zeroconf_importable:
        assert discovery.mdns_available() is False
        # MDNSDiscovery is a lazy class — instantiating without start() works,
        # but start()/discover() must raise ImportError pointing at `[lan]`.
        assert discovery.MDNSDiscovery is not None
        instance = discovery.MDNSDiscovery(agent_id="probe")
        with pytest.raises(ImportError, match=r"\[lan\]"):
            instance.start()
        with pytest.raises(ImportError, match=r"\[lan\]"):
            instance.discover(timeout=0.1)
    else:
        # zeroconf IS installed → both paths succeed silently.
        assert discovery.mdns_available() is True
