"""v0.9.5 鈥?AgentLedger + Guardian recovery + A2A translation tests."""

import json

import pytest

from nth_dao.identity import AgentIdentity, crypto_available


pytestmark = pytest.mark.skipif(
    not crypto_available(), reason="PyNaCl required for v0.9.5 tests"
)


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ AgentLedger 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€


def test_agent_ledger_appends_and_reduces(tmp_path):
    from nth_dao.agent_ledger import AgentLedger
    ident = AgentIdentity.generate(label="alice")
    al = AgentLedger(tmp_path, identity=ident)
    # No events yet
    s0 = al.compute_stats()
    assert s0["event_count"] == 0
    assert s0["success_rate"] == 0.0
    # Record some work
    al.record_step_complete("m1", "s1", template_id="code-review",
                            template_version="1.0.0",
                            category="code_review", token_cost=4000,
                            elapsed_seconds=60)
    al.record_step_complete("m2", "s1", template_id="code-review",
                            template_version="1.0.0",
                            category="code_review", token_cost=5000,
                            elapsed_seconds=120)
    al.record_step_failed("m3", "s1", template_id="data-cleanup",
                          category="data_cleanup", reason="timeout")
    s = al.compute_stats()
    assert s["event_count"] == 3
    assert s["steps_completed"] == 2
    assert s["steps_failed"] == 1
    assert s["success_rate"] == pytest.approx(2 / 3)
    assert s["templates_used"]["code-review"] == 2
    assert s["categories"]["code_review"] == 2
    assert s["categories"]["data_cleanup"] == 1
    assert s["total_token_cost"] == 9000


def test_agent_ledger_scopes_by_pubkey_fingerprint(tmp_path):
    """Same pubkey, different agent_id strings 鈫?same ledger file."""
    from nth_dao.agent_ledger import AgentLedger
    ident = AgentIdentity.generate(label="alice")
    al1 = AgentLedger(tmp_path, identity=ident)
    al1.record_step_complete("m1", "s1")
    # Re-open (simulates a new process)
    al2 = AgentLedger(tmp_path, identity=ident)
    assert al2.compute_stats()["event_count"] == 1


def test_agent_ledger_stats_cache_refreshes_on_new_event(tmp_path):
    from nth_dao.agent_ledger import AgentLedger
    ident = AgentIdentity.generate(label="alice")
    al = AgentLedger(tmp_path, identity=ident)
    al.record_step_complete("m1", "s1")
    s1 = al.stats()
    assert s1["event_count"] == 1
    al.record_step_complete("m2", "s1")
    s2 = al.stats()
    assert s2["event_count"] == 2


def test_agent_ledger_handoff_counters(tmp_path):
    from nth_dao.agent_ledger import AgentLedger
    ident = AgentIdentity.generate(label="alice")
    al = AgentLedger(tmp_path, identity=ident)
    al.record_handoff_received("m1", "s1", from_agent="bob")
    al.record_handoff_given("m1", "s2", to_agent="carol")
    al.record_handoff_given("m2", "s1", to_agent="dave")
    s = al.compute_stats()
    assert s["handoffs_received"] == 1
    assert s["handoffs_given"] == 2


def test_agent_ledger_events_are_signed_when_identity_can_sign(tmp_path):
    from nth_dao.agent_ledger import AgentLedger
    ident = AgentIdentity.generate(label="alice")
    al = AgentLedger(tmp_path, identity=ident)
    e = al.record_step_complete("m1", "s1")
    assert e.sig  # non-empty
    assert e.event_hash
    assert e.prev_hash == "0" * 64
    ok, reason = al.verify_chain()
    assert ok, reason


def test_agent_ledger_detects_tampered_event(tmp_path):
    from nth_dao.agent_ledger import AgentLedger
    ident = AgentIdentity.generate(label="alice")
    al = AgentLedger(tmp_path, identity=ident)
    al.record_step_complete("m1", "s1", token_cost=1)
    raw = al.ledger_path.read_text(encoding="utf-8")
    al.ledger_path.write_text(
        raw.replace('"token_cost": 1', '"token_cost": 999'),
        encoding="utf-8",
    )
    ok, reason = al.verify_chain()
    assert not ok
    assert "event_hash" in reason or "signature" in reason


def test_agent_ledger_stats_cache_uses_ledger_hash(tmp_path):
    from nth_dao.agent_ledger import AgentLedger
    ident = AgentIdentity.generate(label="alice")
    al = AgentLedger(tmp_path, identity=ident)
    al.record_step_complete("m1", "s1", token_cost=1)
    first = al.stats()
    raw = al.ledger_path.read_text(encoding="utf-8")
    al.ledger_path.write_text(
        raw.replace('"token_cost": 1', '"token_cost": 2'),
        encoding="utf-8",
    )
    second = al.stats()
    assert second["ledger_hash"] != first["ledger_hash"]


def test_agent_ledger_works_without_identity(tmp_path):
    """Plain agent_id fallback."""
    from nth_dao.agent_ledger import AgentLedger
    al = AgentLedger(tmp_path, agent_id="plain-alice")
    al.record_step_complete("m1", "s1")
    s = al.compute_stats()
    assert s["event_count"] == 1
    # Events are unsigned in this mode
    e = al.all_events()[0]
    assert e.sig == ""


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ Guardian recovery 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€


def test_guardian_set_round_trip_and_signature(tmp_path):
    from nth_dao.guardian import (
        GuardianSet,
        publish_guardian_set,
    )
    alice = AgentIdentity.generate(label="alice (protected)")
    g1 = AgentIdentity.generate(label="g1")
    g2 = AgentIdentity.generate(label="g2")
    g3 = AgentIdentity.generate(label="g3")
    gs = publish_guardian_set(
        alice, [g1.pubkey_hex, g2.pubkey_hex, g3.pubkey_hex], threshold=2,
    )
    assert gs.verify_signature()
    assert gs.is_well_formed()
    # Round-trip via dict
    reloaded = GuardianSet.from_dict(gs.to_dict())
    assert reloaded.verify_signature()


def test_publish_guardian_set_rejects_owner_as_guardian(tmp_path):
    from nth_dao.guardian import publish_guardian_set
    alice = AgentIdentity.generate(label="alice")
    g = AgentIdentity.generate(label="g")
    with pytest.raises(ValueError, match="own pubkey"):
        publish_guardian_set(alice, [alice.pubkey_hex, g.pubkey_hex], threshold=1)


def test_publish_guardian_set_threshold_validated(tmp_path):
    from nth_dao.guardian import publish_guardian_set
    alice = AgentIdentity.generate(label="alice")
    g1 = AgentIdentity.generate(label="g1")
    g2 = AgentIdentity.generate(label="g2")
    with pytest.raises(ValueError, match="threshold"):
        publish_guardian_set(alice, [g1.pubkey_hex, g2.pubkey_hex], threshold=3)
    with pytest.raises(ValueError, match="threshold"):
        publish_guardian_set(alice, [g1.pubkey_hex, g2.pubkey_hex], threshold=0)


def test_replacement_with_quorum_verifies(tmp_path):
    from nth_dao.guardian import (
        begin_key_replacement,
        publish_guardian_set,
        sign_replacement,
        verify_replacement,
    )
    alice = AgentIdentity.generate(label="alice")
    g1 = AgentIdentity.generate(label="g1")
    g2 = AgentIdentity.generate(label="g2")
    g3 = AgentIdentity.generate(label="g3")
    new_alice = AgentIdentity.generate(label="new alice key")

    gs = publish_guardian_set(
        alice, [g1.pubkey_hex, g2.pubkey_hex, g3.pubkey_hex], threshold=2,
    )
    proof = begin_key_replacement(gs, new_alice.pubkey_hex,
                                  reason="laptop stolen 2026-05")
    proof.signatures.append(sign_replacement(g1, proof))
    proof.signatures.append(sign_replacement(g2, proof))
    valid, reason = verify_replacement(proof, gs)
    assert valid, reason


def test_replacement_below_threshold_rejected(tmp_path):
    from nth_dao.guardian import (
        begin_key_replacement,
        publish_guardian_set,
        sign_replacement,
        verify_replacement,
    )
    alice = AgentIdentity.generate(label="alice")
    g1 = AgentIdentity.generate(label="g1")
    g2 = AgentIdentity.generate(label="g2")
    new_alice = AgentIdentity.generate(label="new alice key")
    gs = publish_guardian_set(alice, [g1.pubkey_hex, g2.pubkey_hex], threshold=2)
    proof = begin_key_replacement(gs, new_alice.pubkey_hex)
    proof.signatures.append(sign_replacement(g1, proof))
    # only 1 of 2 鈥?below threshold
    valid, reason = verify_replacement(proof, gs)
    assert not valid
    assert "signatures" in reason


def test_replacement_signature_by_non_guardian_ignored(tmp_path):
    from nth_dao.guardian import (
        begin_key_replacement,
        publish_guardian_set,
        sign_replacement,
        verify_replacement,
    )
    alice = AgentIdentity.generate(label="alice")
    g1 = AgentIdentity.generate(label="g1")
    g2 = AgentIdentity.generate(label="g2")
    mallory = AgentIdentity.generate(label="mallory (not a guardian)")
    new_alice = AgentIdentity.generate(label="new alice")
    gs = publish_guardian_set(alice, [g1.pubkey_hex, g2.pubkey_hex], threshold=2)
    proof = begin_key_replacement(gs, new_alice.pubkey_hex)
    proof.signatures.append(sign_replacement(g1, proof))
    proof.signatures.append(sign_replacement(mallory, proof))  # ignored
    valid, _ = verify_replacement(proof, gs)
    assert not valid  # only 1 valid sig from a guardian, need 2


def test_replacement_duplicate_guardian_signature_dedup(tmp_path):
    from nth_dao.guardian import (
        begin_key_replacement,
        publish_guardian_set,
        sign_replacement,
        verify_replacement,
    )
    alice = AgentIdentity.generate(label="alice")
    g1 = AgentIdentity.generate(label="g1")
    g2 = AgentIdentity.generate(label="g2")
    new_alice = AgentIdentity.generate(label="new alice")
    gs = publish_guardian_set(alice, [g1.pubkey_hex, g2.pubkey_hex], threshold=2)
    proof = begin_key_replacement(gs, new_alice.pubkey_hex)
    proof.signatures.append(sign_replacement(g1, proof))
    proof.signatures.append(sign_replacement(g1, proof))  # duplicate same guardian
    valid, _ = verify_replacement(proof, gs)
    assert not valid  # still only 1 distinct guardian


def test_replacement_tampered_proof_rejected(tmp_path):
    from nth_dao.guardian import (
        begin_key_replacement,
        publish_guardian_set,
        sign_replacement,
        verify_replacement,
    )
    alice = AgentIdentity.generate(label="alice")
    g1 = AgentIdentity.generate(label="g1")
    g2 = AgentIdentity.generate(label="g2")
    new_alice = AgentIdentity.generate(label="new alice")
    gs = publish_guardian_set(alice, [g1.pubkey_hex, g2.pubkey_hex], threshold=2)
    proof = begin_key_replacement(gs, new_alice.pubkey_hex, reason="legit reason")
    proof.signatures.append(sign_replacement(g1, proof))
    proof.signatures.append(sign_replacement(g2, proof))
    # Tamper with the new_pubkey AFTER signing
    proof.new_pubkey = "00" * 32
    valid, _ = verify_replacement(proof, gs)
    assert not valid


def test_forged_guardian_set_cannot_bind_victim_fingerprint(tmp_path):
    from nth_dao.guardian import (
        GuardianSet,
        GuardianStore,
        publish_guardian_set,
    )
    victim = AgentIdentity.generate(label="victim")
    attacker = AgentIdentity.generate(label="attacker")
    g1 = AgentIdentity.generate(label="g1")
    g2 = AgentIdentity.generate(label="g2")
    legitimate = publish_guardian_set(
        attacker, [g1.pubkey_hex, g2.pubkey_hex], threshold=2,
    )
    forged = GuardianSet.from_dict(legitimate.to_dict())
    forged.protected_fingerprint = victim.fingerprint()
    assert not forged.is_well_formed()
    assert not forged.verify_signature()
    store = GuardianStore(tmp_path)
    with pytest.raises(ValueError, match="malformed"):
        store.save_guardian_set(forged)


def test_guardian_store_rejects_replay_and_pubkey_reuse(tmp_path):
    from nth_dao.guardian import (
        GuardianStore,
        begin_key_replacement,
        publish_guardian_set,
        sign_replacement,
    )
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    g1 = AgentIdentity.generate(label="g1")
    g2 = AgentIdentity.generate(label="g2")
    new_key = AgentIdentity.generate(label="new")
    gs1 = publish_guardian_set(alice, [g1.pubkey_hex, g2.pubkey_hex], threshold=2)
    gs2 = publish_guardian_set(bob, [g1.pubkey_hex, g2.pubkey_hex], threshold=2)
    store = GuardianStore(tmp_path)
    store.save_guardian_set(gs1)
    store.save_guardian_set(gs2)
    proof1 = begin_key_replacement(gs1, new_key.pubkey_hex)
    proof1.signatures.append(sign_replacement(g1, proof1))
    proof1.signatures.append(sign_replacement(g2, proof1))
    assert store.commit_replacement(proof1)
    assert not store.commit_replacement(proof1)
    proof2 = begin_key_replacement(gs2, new_key.pubkey_hex)
    proof2.signatures.append(sign_replacement(g1, proof2))
    proof2.signatures.append(sign_replacement(g2, proof2))
    assert not store.commit_replacement(proof2)


def test_guardian_store_commit_persists_active_replacement(tmp_path):
    from nth_dao.guardian import (
        GuardianStore,
        begin_key_replacement,
        publish_guardian_set,
        sign_replacement,
    )
    alice = AgentIdentity.generate(label="alice")
    g1 = AgentIdentity.generate(label="g1")
    g2 = AgentIdentity.generate(label="g2")
    new_alice = AgentIdentity.generate(label="new alice")
    gs = publish_guardian_set(alice, [g1.pubkey_hex, g2.pubkey_hex], threshold=2)
    store = GuardianStore(tmp_path)
    store.save_guardian_set(gs)
    proof = begin_key_replacement(gs, new_alice.pubkey_hex)
    proof.signatures.append(sign_replacement(g1, proof))
    proof.signatures.append(sign_replacement(g2, proof))
    assert store.commit_replacement(proof)
    assert store.resolve_current_pubkey(alice.fingerprint()) == new_alice.pubkey_hex


def test_guardian_store_commit_below_threshold_returns_false(tmp_path):
    from nth_dao.guardian import (
        GuardianStore,
        begin_key_replacement,
        publish_guardian_set,
        sign_replacement,
    )
    alice = AgentIdentity.generate(label="alice")
    g1 = AgentIdentity.generate(label="g1")
    g2 = AgentIdentity.generate(label="g2")
    new_alice = AgentIdentity.generate(label="new alice")
    gs = publish_guardian_set(alice, [g1.pubkey_hex, g2.pubkey_hex], threshold=2)
    store = GuardianStore(tmp_path)
    store.save_guardian_set(gs)
    proof = begin_key_replacement(gs, new_alice.pubkey_hex)
    proof.signatures.append(sign_replacement(g1, proof))  # only 1
    assert not store.commit_replacement(proof)
    assert store.resolve_current_pubkey(alice.fingerprint()) is None


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ A2A translation 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€


def test_template_to_a2a_skill_includes_input_schema(tmp_path):
    from nth_dao.a2a import template_to_a2a_skill
    from nth_dao.orchestration import IOField, StepSkeleton, mint_template
    alice = AgentIdentity.generate(label="alice")
    t = mint_template(
        alice,
        template_id="code-review", version="1.0.0",
        name="Code Review", category="code_review",
        inputs={
            "diff_url": IOField(type="string", required=True,
                                description="PR diff URL"),
            "severity": IOField(type="enum", values=["low", "med", "high"],
                                description="severity hint"),
        },
        outputs={
            "score": IOField(type="float", description="quality 0-1"),
        },
    )
    skill = template_to_a2a_skill(t)
    assert skill["id"] == "code-review@1.0.0"
    assert skill["inputModes"] == ["application/json"]
    assert skill["outputModes"] == ["application/json"]
    assert skill["x-nth-dao"]["category"] == "code_review"
    assert skill["x-nth-dao"]["input_schema"]["type"] == "object"
    assert skill["x-nth-dao"]["input_schema"]["properties"]["diff_url"]["type"] == "string"
    assert "diff_url" in skill["x-nth-dao"]["input_schema"]["required"]
    assert skill["x-nth-dao"]["input_schema"]["properties"]["severity"]["enum"] == ["low", "med", "high"]
    assert skill["x-nth-dao"]["output_schema"]["properties"]["score"]["type"] == "number"


def test_agent_card_from_assembles_well_formed_card(tmp_path):
    from nth_dao.a2a import agent_card_from
    from nth_dao.orchestration import IOField, mint_template
    alice = AgentIdentity.generate(label="alice")
    t = mint_template(
        alice, template_id="t", version="1.0.0", name="t",
        inputs={"x": IOField(type="string", required=False, description="x")},
    )
    card = agent_card_from(
        agent_did=alice.as_did(),
        name="Alice's Agent",
        description="A friendly NTH DAO agent.",
        templates=[t],
        capabilities=["code_review"],
        endpoint_url="https://alice.example/a2a",
    )
    assert card["x-nth-dao"]["agent_did"].startswith("did:key:z")
    assert card["name"] == "Alice's Agent"
    assert card["url"] == "https://alice.example/a2a"
    assert card["preferredTransport"] == "JSONRPC"
    assert isinstance(card["capabilities"], dict)
    assert card["defaultInputModes"] == ["application/json"]
    assert len(card["skills"]) == 1
    assert card["skills"][0]["id"] == "t@1.0.0"


def test_a2a_task_from_mission_maps_status(tmp_path):
    from nth_dao.a2a import a2a_task_from_mission
    from nth_dao.orchestration import Mission
    m = Mission.new(title="t", goal="g", owner="alice",
                    steps=[{"id": "s", "description": "x"}])
    task = a2a_task_from_mission(m)
    assert task["id"] == m.id
    assert task["status"]["state"] == "submitted"
    # Push to completed
    m.status = "completed"
    task2 = a2a_task_from_mission(m)
    assert task2["status"]["state"] == "completed"


def test_mission_inputs_from_a2a_message_with_jsonrpc_params(tmp_path):
    from nth_dao.a2a import mission_inputs_from_a2a_message
    from nth_dao.orchestration import IOField, mint_template
    alice = AgentIdentity.generate(label="alice")
    t = mint_template(
        alice, template_id="t", version="1.0.0", name="t",
        inputs={
            "url": IOField(type="string", required=True, description="url"),
        },
    )
    msg = {
        "jsonrpc": "2.0",
        "method":  "SendMessage",
        "params":  {"task_id": "abc", "input": {"url": "https://example.com"}},
    }
    inputs = mission_inputs_from_a2a_message(msg, t)
    assert inputs == {"url": "https://example.com"}


def test_mission_inputs_from_a2a_message_missing_required_field(tmp_path):
    from nth_dao.a2a import mission_inputs_from_a2a_message
    from nth_dao.orchestration import IOField, mint_template
    alice = AgentIdentity.generate(label="alice")
    t = mint_template(
        alice, template_id="t", version="1.0.0", name="t",
        inputs={"url": IOField(type="string", required=True, description="url")},
    )
    with pytest.raises(ValueError, match="A2A inputs invalid"):
        mission_inputs_from_a2a_message({"input": {}}, t)


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ facade 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€


def test_facade_exports_v095():
    import nth_dao as nth
    assert hasattr(nth, "AgentLedger")
    assert hasattr(nth, "GuardianSet")
    assert hasattr(nth, "publish_guardian_set")
    assert hasattr(nth, "a2a_adapter")
