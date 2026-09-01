"""Host policy-gate tests for reviewed Intent acceptance."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3

import pytest

from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import encode_ed25519_did_key
from nth_dao.plugins.intent_acceptance import IntentAcceptanceHead, IntentAcceptanceStore
from nth_dao.plugins.intent_envelope import IntentAcceptanceContext, IntentEnvelopeError
from nth_dao.plugins.intent_policy import (
    IntentAcceptancePolicySnapshot,
    IntentPolicyDenied,
    IntentPolicyError,
    IntentPolicyMember,
    verify_intent_policy_successor,
)
from nth_dao.plugins.intent_policy_store import (
    IntentPolicyStore,
    IntentPolicyStoreConflict,
    IntentPolicyStoreError,
)
from nth_dao.plugins import intent_policy_store as policy_store_module
from tools.generate_intent_envelope_vectors import _test_identity


def _hash(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


@pytest.fixture
def policy_inputs():
    signer = _test_identity("intent-envelope-signer-v1")
    audience = _test_identity("intent-envelope-audience-v1")
    vectors = json.loads(
        (
            Path(__file__).parents[1]
            / "nth_dao/plugins/vectors/intent-envelope-wire-cases-v1.json"
        ).read_text(encoding="utf-8")
    )
    case = vectors["positive_cases"][0]
    return signer, audience, case


def _member(signer_did: str, **changes) -> IntentPolicyMember:
    values = {
        "signer_did": signer_did,
        "role": "member",
        "status": "active",
        "allowed_solver_classes": ("org.nth-dao.solver.review",),
        "automation_ceiling": "A1",
    }
    return IntentPolicyMember(**(values | changes))


def _policy(signer_did: str, audience_did: str, draft_digest: str, **changes):
    values = {
        "audience_did": audience_did,
        "scope_id": "workspace:conformance-intent",
        "reviewed_draft_digest": draft_digest,
        "membership_digest": _hash("membership-v1"),
        "revocation_digest": _hash("revocations-v1"),
        "policy_revision": 1,
        "previous_policy_digest": "",
        "issued_at_ms": 900,
        "expires_at_ms": 2_000,
        "allowed_acceptance_roles": ("admin", "member", "owner"),
        "members": (_member(signer_did),),
    }
    return IntentAcceptancePolicySnapshot.create(**(values | changes))


def test_policy_resolves_exact_context_and_acceptance_records_provenance(
    tmp_path, policy_inputs,
):
    _signer, audience, case = policy_inputs
    envelope = case["envelope"]
    policy = _policy(envelope["signer_did"], audience.as_did(), envelope["draft_digest"])
    head = IntentAcceptanceHead(0, "")

    context = policy.resolve(signer_did=envelope["signer_did"], head=head, now_ms=1_000)

    assert context == IntentAcceptanceContext(
        signer_did=envelope["signer_did"],
        audience_did=audience.as_did(),
        scope_id=envelope["scope_id"],
        draft_digest=envelope["draft_digest"],
        revision=1,
        previous_digest="",
        allowed_solver_classes=("org.nth-dao.solver.review",),
        automation_ceiling="A1",
        authorization_digest=policy.digest,
    )
    store = IntentAcceptanceStore(tmp_path, clock=lambda: 1_000)
    policies = IntentPolicyStore(tmp_path, clock=lambda: 1_000)
    published = policies.publish(policy)
    result = store.accept_governed(
        envelope,
        policy_store=policies,
        signer_did=envelope["signer_did"],
        expected_policy_tail_digest=published.record.audit_digest,
    )
    persisted = json.loads(result.record.context_json)
    assert persisted["authorization_digest"] == policy.digest
    assert result.record.audit["context_digest"] == _hash(result.record.context_json)


@pytest.mark.parametrize(
    ("member_changes", "roles", "message"),
    [
        ({"status": "revoked"}, ("admin", "member", "owner"), "revoked"),
        ({"role": "member"}, ("admin", "owner"), "role"),
    ],
)
def test_revoked_or_disallowed_role_fails_closed(
    policy_inputs, member_changes, roles, message,
):
    _signer, audience, case = policy_inputs
    member = _member(case["envelope"]["signer_did"], **member_changes)
    policy = _policy(
        member.signer_did,
        audience.as_did(),
        case["envelope"]["draft_digest"],
        members=(member,),
        allowed_acceptance_roles=roles,
    )
    with pytest.raises(IntentPolicyDenied, match=message):
        policy.resolve(signer_did=member.signer_did, head=IntentAcceptanceHead(0, ""), now_ms=1_000)


def test_unlisted_signer_and_expired_policy_fail_closed(policy_inputs):
    signer, audience, case = policy_inputs
    policy = _policy(signer.as_did(), audience.as_did(), case["envelope"]["draft_digest"])
    outsider = _test_identity("intent-policy-outsider")
    with pytest.raises(IntentPolicyDenied, match="not a member"):
        policy.resolve(signer_did=outsider.as_did(), head=IntentAcceptanceHead(0, ""), now_ms=1_000)
    for moment in (899, 2_000):
        with pytest.raises(IntentPolicyDenied, match="currently valid"):
            policy.resolve(signer_did=signer.as_did(), head=IntentAcceptanceHead(0, ""), now_ms=moment)


def test_exact_retry_rechecks_current_revocation(tmp_path, policy_inputs):
    signer, audience, case = policy_inputs
    envelope = case["envelope"]
    active = _policy(signer.as_did(), audience.as_did(), envelope["draft_digest"])
    store = IntentAcceptanceStore(tmp_path, clock=lambda: 1_000)
    policies = IntentPolicyStore(tmp_path, clock=lambda: 1_000)
    retained_tail = policies.publish(active).record.audit_digest

    def accept_current():
        return store.accept_governed(
            envelope,
            policy_store=policies,
            signer_did=signer.as_did(),
            expected_policy_tail_digest=retained_tail,
        )

    assert accept_current().created
    revoked = _policy(
        signer.as_did(),
        audience.as_did(),
        envelope["draft_digest"],
        members=(_member(signer.as_did(), status="revoked"),),
        revocation_digest=_hash("revocations-v2"),
        policy_revision=2,
        previous_policy_digest=active.digest,
        issued_at_ms=1_000,
        expires_at_ms=3_000,
    )
    revoked_result = policies.publish(revoked)
    retained_tail = revoked_result.record.audit_digest
    with pytest.raises(IntentPolicyDenied, match="revoked"):
        accept_current()
    assert len(store.history()) == 1
    assert store.verify_governed_history(
        policy_store=policies,
        expected_policy_tail_digest=revoked_result.record.audit_digest,
    )[0:3] == (1, store.history()[0].audit_digest, 2)


def test_policy_snapshot_is_detached_content_addressed_and_non_executable(policy_inputs):
    signer, audience, case = policy_inputs
    document = _policy(signer.as_did(), audience.as_did(), case["envelope"]["draft_digest"]).to_dict()
    parsed = IntentAcceptancePolicySnapshot.from_dict(document)
    digest = parsed.digest
    document["members"][0]["status"] = "revoked"
    assert parsed.digest == digest
    assert parsed.to_dict()["members"][0]["status"] == "active"
    assert parsed.to_dict()["commit_authority"] is False
    assert parsed.to_dict()["executable"] is False
    changed = parsed.to_dict()
    changed["membership_digest"] = _hash("membership-v2")
    assert IntentAcceptancePolicySnapshot.from_dict(changed).digest != digest


def test_policy_successor_chain_is_contiguous(policy_inputs):
    signer, audience, case = policy_inputs
    first = _policy(signer.as_did(), audience.as_did(), case["envelope"]["draft_digest"])
    second = _policy(
        signer.as_did(), audience.as_did(), case["envelope"]["draft_digest"],
        policy_revision=2,
        previous_policy_digest=first.digest,
        issued_at_ms=1_000,
        expires_at_ms=3_000,
    )
    verify_intent_policy_successor(first, second)
    wrong = IntentAcceptancePolicySnapshot.from_dict(
        second.to_dict() | {"previous_policy_digest": _hash("wrong")}
    )
    with pytest.raises(IntentPolicyError, match="predecessor"):
        verify_intent_policy_successor(first, wrong)


def test_policy_successor_cannot_reactivate_or_forget_revoked_did(policy_inputs):
    signer, audience, case = policy_inputs
    outsider = _test_identity("intent-policy-successor-outsider")
    revoked_member = _member(signer.as_did(), status="revoked")
    first = _policy(
        signer.as_did(), audience.as_did(), case["envelope"]["draft_digest"],
        members=(revoked_member,),
    )
    for members in (
        (_member(outsider.as_did()),),
        (_member(signer.as_did()),),
    ):
        with pytest.raises(IntentPolicyError, match="removes or reactivates"):
            successor = _policy(
                signer.as_did(), audience.as_did(), case["envelope"]["draft_digest"],
                members=members,
                policy_revision=2,
                previous_policy_digest=first.digest,
                issued_at_ms=1_000,
                expires_at_ms=3_000,
            )
            verify_intent_policy_successor(first, successor)


def test_policy_successor_retains_revoked_did_when_other_members_change(policy_inputs):
    signer, audience, case = policy_inputs
    outsider = _test_identity("intent-policy-successor-active")
    first = _policy(
        signer.as_did(), audience.as_did(), case["envelope"]["draft_digest"],
        members=(_member(signer.as_did(), status="revoked"),),
    )
    members = tuple(sorted(
        (_member(signer.as_did(), status="revoked"), _member(outsider.as_did())),
        key=lambda member: member.signer_did,
    ))
    second = _policy(
        signer.as_did(), audience.as_did(), case["envelope"]["draft_digest"],
        members=members,
        policy_revision=2,
        previous_policy_digest=first.digest,
        issued_at_ms=1_000,
        expires_at_ms=3_000,
    )
    verify_intent_policy_successor(first, second)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"format": "other"}, "format"),
        ({"commit_authority": True}, "authority"),
        ({"members": []}, "1..64"),
        ({"allowed_acceptance_roles": ["guest"]}, "roles"),
        ({"policy_revision": True}, "safe integer"),
        ({"previous_policy_digest": _hash("unexpected")}, "genesis"),
        ({"expires_at_ms": 900}, "validity"),
        ({"membership_digest": "unknown"}, "content hash"),
    ],
)
def test_malformed_policy_documents_are_rejected(policy_inputs, change, message):
    signer, audience, case = policy_inputs
    document = _policy(signer.as_did(), audience.as_did(), case["envelope"]["draft_digest"]).to_dict()
    with pytest.raises(IntentPolicyError, match=message):
        IntentAcceptancePolicySnapshot.from_dict(document | change)


def test_duplicate_members_and_unknown_fields_are_rejected(policy_inputs):
    signer, audience, case = policy_inputs
    document = _policy(signer.as_did(), audience.as_did(), case["envelope"]["draft_digest"]).to_dict()
    document["members"] *= 2
    with pytest.raises(IntentPolicyError, match="sorted and unique"):
        IntentAcceptancePolicySnapshot.from_dict(document)
    clean = _policy(signer.as_did(), audience.as_did(), case["envelope"]["draft_digest"]).to_dict()
    with pytest.raises(IntentPolicyError, match="unknown"):
        IntentAcceptancePolicySnapshot.from_dict(clean | {"payment_grant": True})


def test_policy_rejects_oversized_collections_before_normalization(policy_inputs):
    signer, audience, case = policy_inputs
    document = _policy(
        signer.as_did(), audience.as_did(), case["envelope"]["draft_digest"]
    ).to_dict()
    with pytest.raises(IntentPolicyError, match="1..3 acceptance roles"):
        IntentAcceptancePolicySnapshot.from_dict(
            document | {"allowed_acceptance_roles": ["member"] * 100_000}
        )
    member = document["members"][0] | {
        "allowed_solver_classes": ["org.nth-dao.solver.review"] * 100_000,
    }
    with pytest.raises(IntentPolicyError, match="must be an array"):
        IntentAcceptancePolicySnapshot.from_dict(document | {"members": [member]})


def test_policy_rejects_noncanonical_json_and_non_prime_order_did(policy_inputs):
    signer, audience, case = policy_inputs
    policy = _policy(
        signer.as_did(), audience.as_did(), case["envelope"]["draft_digest"]
    )
    assert IntentAcceptancePolicySnapshot.from_json(policy.canonical_bytes).digest == policy.digest
    with pytest.raises(IntentPolicyError, match="canonical"):
        IntentAcceptancePolicySnapshot.from_json(
            json.dumps(policy.to_dict(), indent=2).encode()
        )
    invalid_did = encode_ed25519_did_key(bytes(32))
    with pytest.raises(IntentPolicyError, match="strict Ed25519"):
        _member(invalid_did)


@pytest.mark.parametrize("roles", [None, "admin", {"admin"}])
def test_policy_constructor_rejects_ambiguous_role_containers(policy_inputs, roles):
    signer, audience, case = policy_inputs
    with pytest.raises(IntentPolicyError, match="list or tuple"):
        _policy(
            signer.as_did(), audience.as_did(), case["envelope"]["draft_digest"],
            allowed_acceptance_roles=roles,
        )


def test_legacy_context_rows_remain_readable_without_fabricated_policy_digest(
    tmp_path, policy_inputs,
):
    _signer, _audience, case = policy_inputs
    expected = case["expected"] | {
        "allowed_solver_classes": tuple(case["expected"]["allowed_solver_classes"]),
    }
    expected.pop("authorization_digest", None)
    context = IntentAcceptanceContext(**expected)
    store = IntentAcceptanceStore(tmp_path, clock=lambda: 1_000)
    result = store.accept(case["envelope"], resolve_context=lambda _head: context)
    record = result.record
    old_context = json.loads(record.context_json)
    old_context.pop("authorization_digest")
    context_json = canonical_json(old_context).decode()
    audit = record.audit | {"context_digest": _hash(context_json)}
    audit_digest = "sha256:" + hashlib.sha256(canonical_json(audit)).hexdigest()
    connection = sqlite3.connect(store.path)
    try:
        trigger = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name='no_update'"
        ).fetchone()[0]
        connection.execute("DROP TRIGGER no_update")
        connection.execute(
            "UPDATE acceptances SET context_json=?, audit_digest=? WHERE sequence=1",
            (context_json, audit_digest),
        )
        connection.execute(trigger)
        connection.commit()
    finally:
        connection.close()
    reopened = IntentAcceptanceStore(tmp_path, clock=lambda: 1_001)
    loaded = reopened.history()[0]
    assert "authorization_digest" not in json.loads(loaded.context_json)
    assert reopened.verify_history() == (1, audit_digest)


def test_invalid_authorization_digest_is_never_accepted(policy_inputs):
    _signer, _audience, case = policy_inputs
    values = case["expected"] | {
        "allowed_solver_classes": tuple(case["expected"]["allowed_solver_classes"]),
        "authorization_digest": "sha256:" + "g" * 64,
    }
    with pytest.raises(IntentEnvelopeError, match="authorization_digest"):
        IntentAcceptanceContext(**values)


def test_legacy_accept_cannot_fabricate_governed_authorization(
    tmp_path, policy_inputs,
):
    _signer, _audience, case = policy_inputs
    values = case["expected"] | {
        "allowed_solver_classes": tuple(case["expected"]["allowed_solver_classes"]),
        "authorization_digest": "sha256:" + "1" * 64,
    }
    context = IntentAcceptanceContext(**values)
    store = IntentAcceptanceStore(tmp_path, clock=lambda: 1_000)

    with pytest.raises(IntentEnvelopeError, match="accept_governed"):
        store.accept(case["envelope"], resolve_context=lambda _head: context)
    assert store.history() == ()


def test_governed_acceptance_uses_store_clock_for_policy_and_commit(
    tmp_path, policy_inputs,
):
    signer, audience, case = policy_inputs
    policy = _policy(
        signer.as_did(),
        audience.as_did(),
        case["envelope"]["draft_digest"],
        expires_at_ms=1_500,
    )
    store = IntentAcceptanceStore(tmp_path, clock=lambda: 1_600)
    policies = IntentPolicyStore(tmp_path, clock=lambda: 1_000)
    published = policies.publish(policy)

    with pytest.raises(IntentPolicyDenied, match="currently valid"):
        store.accept_governed(
            case["envelope"],
            policy_store=policies,
            signer_did=signer.as_did(),
            expected_policy_tail_digest=published.record.audit_digest,
        )
    assert store.history() == ()


def test_governed_acceptance_rechecks_policy_at_insert_boundary(
    tmp_path, policy_inputs,
):
    signer, audience, case = policy_inputs
    policy = _policy(
        signer.as_did(),
        audience.as_did(),
        case["envelope"]["draft_digest"],
        expires_at_ms=1_500,
    )
    ticks = iter((1_000, 1_500))
    store = IntentAcceptanceStore(tmp_path, clock=lambda: next(ticks))
    policies = IntentPolicyStore(tmp_path, clock=lambda: 1_000)
    published = policies.publish(policy)

    with pytest.raises(IntentEnvelopeError, match="policy expired"):
        store.accept_governed(
            case["envelope"],
            policy_store=policies,
            signer_did=signer.as_did(),
            expected_policy_tail_digest=published.record.audit_digest,
        )
    assert store.history() == ()


def test_policy_store_persists_content_and_derives_current_head(
    tmp_path, policy_inputs,
):
    signer, audience, case = policy_inputs
    first = _policy(signer.as_did(), audience.as_did(), case["envelope"]["draft_digest"])
    second = _policy(
        signer.as_did(),
        audience.as_did(),
        case["envelope"]["draft_digest"],
        policy_revision=2,
        previous_policy_digest=first.digest,
        issued_at_ms=1_000,
        expires_at_ms=3_000,
    )
    store = IntentPolicyStore(tmp_path, clock=lambda: 1_000)

    first_result = store.publish(first)
    assert first_result.created
    assert not store.publish(first).created
    second_result = store.publish(second)
    assert second_result.created
    assert store.current(audience.as_did(), case["envelope"]["scope_id"]).digest == second.digest
    assert store.get(first.digest).canonical_bytes == first.canonical_bytes

    reopened = IntentPolicyStore(tmp_path, clock=lambda: 1_001)
    assert reopened.verify_history() == (2, second_result.record.audit_digest)
    assert reopened.verify_history(
        expected_tail_digest=second_result.record.audit_digest
    ) == (2, second_result.record.audit_digest)
    assert reopened.current(audience.as_did(), case["envelope"]["scope_id"]).digest == second.digest


def test_policy_store_rejects_skipped_or_stale_successors(policy_inputs, tmp_path):
    signer, audience, case = policy_inputs
    first = _policy(signer.as_did(), audience.as_did(), case["envelope"]["draft_digest"])
    store = IntentPolicyStore(tmp_path, clock=lambda: 1_000)
    first_result = store.publish(first)

    for changes in (
        {"policy_revision": 3, "previous_policy_digest": first.digest},
        {"policy_revision": 2, "previous_policy_digest": _hash("stale")},
    ):
        candidate = _policy(
            signer.as_did(),
            audience.as_did(),
            case["envelope"]["draft_digest"],
            issued_at_ms=1_000,
            expires_at_ms=3_000,
            **changes,
        )
        with pytest.raises(IntentPolicyStoreConflict):
            store.publish(candidate)
    assert store.verify_history() == (1, first_result.record.audit_digest)


def test_policy_store_cannot_reactivate_a_revoked_did(policy_inputs, tmp_path):
    signer, audience, case = policy_inputs
    revoked = _policy(
        signer.as_did(),
        audience.as_did(),
        case["envelope"]["draft_digest"],
        members=(_member(signer.as_did(), status="revoked"),),
    )
    store = IntentPolicyStore(tmp_path, clock=lambda: 1_000)
    revoked_result = store.publish(revoked)
    reactivated = _policy(
        signer.as_did(),
        audience.as_did(),
        case["envelope"]["draft_digest"],
        policy_revision=2,
        previous_policy_digest=revoked.digest,
        issued_at_ms=1_000,
        expires_at_ms=3_000,
    )

    with pytest.raises(IntentPolicyStoreConflict, match="reactivat"):
        store.publish(reactivated)
    assert store.verify_history() == (1, revoked_result.record.audit_digest)


def test_current_policy_acceptance_is_dereferenceable_and_current(
    tmp_path, policy_inputs,
):
    signer, audience, case = policy_inputs
    policy = _policy(signer.as_did(), audience.as_did(), case["envelope"]["draft_digest"])
    policies = IntentPolicyStore(tmp_path, clock=lambda: 1_000)
    acceptances = IntentAcceptanceStore(tmp_path, clock=lambda: 1_000)
    published = policies.publish(policy)

    result = acceptances.accept_governed(
        case["envelope"],
        policy_store=policies,
        signer_did=signer.as_did(),
        expected_policy_tail_digest=published.record.audit_digest,
    )

    context = json.loads(result.record.context_json)
    assert context["authorization_digest"] == policy.digest
    assert policies.get(context["authorization_digest"]).canonical_bytes == policy.canonical_bytes
    assert acceptances.verify_governed_history(
        policy_store=policies,
        expected_policy_tail_digest=published.record.audit_digest,
    ) == (
        1,
        result.record.audit_digest,
        1,
        published.record.audit_digest,
    )


def test_governed_history_rejects_missing_policy_evidence(tmp_path, policy_inputs):
    signer, audience, case = policy_inputs
    policy = _policy(signer.as_did(), audience.as_did(), case["envelope"]["draft_digest"])
    policies = IntentPolicyStore(tmp_path, clock=lambda: 1_000)
    acceptances = IntentAcceptanceStore(tmp_path, clock=lambda: 1_000)
    published = policies.publish(policy)
    acceptances.accept_governed(
        case["envelope"],
        policy_store=policies,
        signer_did=signer.as_did(),
        expected_policy_tail_digest=published.record.audit_digest,
    )
    connection = sqlite3.connect(policies.path)
    try:
        trigger = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name='no_delete'"
        ).fetchone()[0]
        connection.execute("DROP TRIGGER no_delete")
        connection.execute("DELETE FROM policies")
        connection.execute(trigger)
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(RuntimeError, match="retained tail"):
        acceptances.verify_governed_history(
            policy_store=policies,
            expected_policy_tail_digest=published.record.audit_digest,
        )
    with pytest.raises(RuntimeError, match="missing policy"):
        acceptances.verify_governed_history(policy_store=policies)


def test_current_policy_acceptance_fails_without_persisted_head(
    tmp_path, policy_inputs,
):
    signer, _audience, case = policy_inputs
    policies = IntentPolicyStore(tmp_path, clock=lambda: 1_000)
    acceptances = IntentAcceptanceStore(tmp_path, clock=lambda: 1_000)

    with pytest.raises(RuntimeError, match="no current policy"):
        acceptances.accept_governed(
            case["envelope"],
            policy_store=policies,
            signer_did=signer.as_did(),
            expected_policy_tail_digest="",
        )
    assert acceptances.history() == ()


def test_governed_acceptance_rejects_foreign_workspace_policy_store(
    tmp_path, policy_inputs,
):
    signer, audience, case = policy_inputs
    acceptance_workspace = tmp_path / "acceptance-node"
    policy_workspace = tmp_path / "foreign-policy-node"
    acceptance_workspace.mkdir()
    policy_workspace.mkdir()
    policy = _policy(
        signer.as_did(),
        audience.as_did(),
        case["envelope"]["draft_digest"],
    )
    policies = IntentPolicyStore(policy_workspace, clock=lambda: 1_000)
    published = policies.publish(policy)
    acceptances = IntentAcceptanceStore(acceptance_workspace, clock=lambda: 1_000)

    with pytest.raises(RuntimeError, match="different workspace"):
        acceptances.accept_governed(
            case["envelope"],
            policy_store=policies,
            signer_did=signer.as_did(),
            expected_policy_tail_digest=published.record.audit_digest,
        )

    assert acceptances.history() == ()


def test_policy_store_detects_persisted_content_tampering(tmp_path, policy_inputs):
    signer, audience, case = policy_inputs
    policy = _policy(signer.as_did(), audience.as_did(), case["envelope"]["draft_digest"])
    store = IntentPolicyStore(tmp_path, clock=lambda: 1_000)
    store.publish(policy)
    tampered = policy.to_dict()
    tampered["membership_digest"] = _hash("tampered-membership")
    connection = sqlite3.connect(store.path)
    try:
        trigger = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name='no_update'"
        ).fetchone()[0]
        connection.execute("DROP TRIGGER no_update")
        connection.execute(
            "UPDATE policies SET policy_json=? WHERE sequence=1",
            (canonical_json(tampered).decode(),),
        )
        connection.execute(trigger)
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(IntentPolicyStoreError, match="integrity"):
        IntentPolicyStore(tmp_path, clock=lambda: 1_001)


def test_policy_store_tail_pin_detects_history_truncation(tmp_path, policy_inputs):
    signer, audience, case = policy_inputs
    first = _policy(signer.as_did(), audience.as_did(), case["envelope"]["draft_digest"])
    second = _policy(
        signer.as_did(), audience.as_did(), case["envelope"]["draft_digest"],
        policy_revision=2,
        previous_policy_digest=first.digest,
        issued_at_ms=1_000,
        expires_at_ms=3_000,
    )
    store = IntentPolicyStore(tmp_path, clock=lambda: 1_000)
    store.publish(first)
    tail = store.publish(second).record.audit_digest
    connection = sqlite3.connect(store.path)
    try:
        trigger = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name='no_delete'"
        ).fetchone()[0]
        connection.execute("DROP TRIGGER no_delete")
        connection.execute("DELETE FROM policies WHERE sequence=2")
        connection.execute(trigger)
        connection.commit()
    finally:
        connection.close()

    reopened = IntentPolicyStore(tmp_path, clock=lambda: 1_001)
    with pytest.raises(IntentPolicyStoreError, match="retained tail"):
        reopened.verify_history(expected_tail_digest=tail)
    acceptances = IntentAcceptanceStore(tmp_path, clock=lambda: 1_001)
    with pytest.raises(RuntimeError, match="retained tail"):
        acceptances.accept_governed(
            case["envelope"],
            policy_store=reopened,
            signer_did=signer.as_did(),
            expected_policy_tail_digest=tail,
        )
    assert acceptances.history() == ()


def test_policy_store_migrates_unpublished_v1_schema(tmp_path, policy_inputs):
    signer, audience, case = policy_inputs
    policy = _policy(signer.as_did(), audience.as_did(), case["envelope"]["draft_digest"])
    path = tmp_path / ".nth" / "intent_policy_v1" / "policy.sqlite3"
    path.parent.mkdir(parents=True)
    connection = sqlite3.connect(path)
    try:
        connection.execute(policy_store_module._TABLE_SQL_V1)
        for statement in policy_store_module._TRIGGER_SQL.values():
            connection.execute(statement)
        connection.execute(
            f"PRAGMA application_id = {policy_store_module._APPLICATION_ID}"
        )
        connection.execute("PRAGMA user_version = 1")
        document = policy.to_dict()
        connection.execute(
            "INSERT INTO policies VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                1,
                policy.digest,
                document["audience_did"],
                document["scope_id"],
                document["policy_revision"],
                document["previous_policy_digest"],
                policy.canonical_bytes.decode(),
                1_000,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    migrated = IntentPolicyStore(tmp_path, clock=lambda: 1_001)
    count, tail = migrated.verify_history()
    assert count == 1
    assert tail == migrated.history()[0].audit_digest
    assert migrated.get(policy.digest).canonical_bytes == policy.canonical_bytes
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2


@pytest.mark.parametrize("store_time", [899, 2_000])
def test_policy_store_rejects_future_or_expired_publication(
    tmp_path, policy_inputs, store_time,
):
    signer, audience, case = policy_inputs
    policy = _policy(signer.as_did(), audience.as_did(), case["envelope"]["draft_digest"])
    store = IntentPolicyStore(tmp_path, clock=lambda: store_time)

    with pytest.raises(IntentPolicyStoreConflict, match="currently valid"):
        store.publish(policy)

    assert store.history() == ()


def test_policy_hot_paths_do_not_reparse_complete_history(
    tmp_path, policy_inputs, monkeypatch,
):
    signer, audience, case = policy_inputs
    first = _policy(signer.as_did(), audience.as_did(), case["envelope"]["draft_digest"])
    second = _policy(
        signer.as_did(), audience.as_did(), case["envelope"]["draft_digest"],
        policy_revision=2,
        previous_policy_digest=first.digest,
        issued_at_ms=1_000,
        expires_at_ms=3_000,
    )
    store = IntentPolicyStore(tmp_path, clock=lambda: 1_000)
    store.publish(first)
    monkeypatch.setattr(store, "history", lambda: pytest.fail("full history hot path"))

    assert store.current(audience.as_did(), case["envelope"]["scope_id"]).digest == first.digest
    assert store.get(first.digest).digest == first.digest
    assert store.publish(second).created
    assert store.effective_at(
        audience.as_did(), case["envelope"]["scope_id"], now_ms=1_500
    ).digest == second.digest
    assert store.effective_at(
        audience.as_did(), case["envelope"]["scope_id"], now_ms=3_000
    ) is None


def test_policy_hot_path_rejects_oversized_row_before_materializing_it(
    tmp_path, policy_inputs, monkeypatch,
):
    signer, audience, case = policy_inputs
    policy = _policy(signer.as_did(), audience.as_did(), case["envelope"]["draft_digest"])
    store = IntentPolicyStore(tmp_path, clock=lambda: 1_000)
    store.publish(policy)
    connection = sqlite3.connect(store.path)
    try:
        trigger = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name='no_update'"
        ).fetchone()[0]
        connection.execute("DROP TRIGGER no_update")
        connection.execute(
            "UPDATE policies SET policy_json=CAST(zeroblob(600000) AS TEXT) WHERE sequence=1"
        )
        connection.execute(trigger)
        connection.commit()
    finally:
        connection.close()
    monkeypatch.setattr(
        IntentPolicyStore,
        "_record_from_row",
        staticmethod(lambda _row: pytest.fail("oversized row crossed into Python")),
    )

    with pytest.raises(IntentPolicyStoreError, match="safe read limits"):
        store.current(audience.as_did(), case["envelope"]["scope_id"])


def test_policy_api_is_exposed_only_as_host_sdk():
    import nth_dao.plugins as facade

    assert facade.IntentAcceptancePolicySnapshot is IntentAcceptancePolicySnapshot
    assert "IntentAcceptancePolicySnapshot" in facade.__all__
    assert facade.IntentPolicyStore is IntentPolicyStore
    assert "IntentPolicyStore" in facade.__all__
