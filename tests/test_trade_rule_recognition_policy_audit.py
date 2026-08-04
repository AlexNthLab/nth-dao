from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.spine import SignedEventLog
from nth_dao.trade_rules import (
    RulePackageStore,
    RuleRecognitionAuditCoordinator,
    RuleRecognitionStore,
    TradeRuleRecognition,
    build_rule_package,
)
from nth_dao.trade_rules.negotiation import RuleResolutionPolicy
from nth_dao.trade_rules.recognition import RuleRecognitionTrustPolicy
from nth_dao.trade_rules.recognition_conformance import VECTORS_PATH
from nth_dao.trade_rules.recognition_policy import (
    create_rule_recognition_policy,
)
from nth_dao.trade_rules.recognition_policy_audit import (
    EVENT_TRADE_RULE_RECOGNITION_POLICY_UPDATED,
    RuleRecognitionPolicyAuditCoordinator,
    RuleRecognitionPolicyAuditError,
    RuleRecognitionPolicyAuditIntegrityError,
    rule_recognition_policy_audit_payload,
    validate_rule_recognition_policy_audit_payload,
)
from nth_dao.trade_rules.recognition_policy_store import (
    RuleRecognitionPolicyStore,
)

pytestmark = pytest.mark.skipif(
    not crypto_available(),
    reason="Recognition policy requires PyNaCl",
)


def _system(tmp_path):
    vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    package = build_rule_package(
        vectors["package_manifest"],
        {
            digest: bytes.fromhex(raw)
            for digest, raw in vectors["package_resources_hex"].items()
        },
    )
    node = AgentIdentity.generate(label="node")
    spine = SignedEventLog(tmp_path / "spine.jsonl", node)
    packages = RulePackageStore(tmp_path)
    packages.install(package.manifest, package.resources)
    recognitions = RuleRecognitionAuditCoordinator(
        store=RuleRecognitionStore(tmp_path),
        spine=spine,
    )
    policies = RuleRecognitionPolicyStore(
        tmp_path,
        node_did=node.as_did(),
    )
    coordinator = RuleRecognitionPolicyAuditCoordinator(
        policy_store=policies,
        package_store=packages,
        recognition_audit=recognitions,
        spine=spine,
    )
    statement = TradeRuleRecognition.from_dict(vectors["recognized"])
    policy = create_rule_recognition_policy(
        node,
        node_did=node.as_did(),
        trust_policy=RuleRecognitionTrustPolicy(
            trusted_issuers={statement.to_dict()["issuer_did"]},
            threshold=1,
            issuer_rule_scopes={
                statement.to_dict()["issuer_did"]: ("*",)
            },
        ),
        issued_at="2026-08-01T00:00:00Z",
        now=datetime(2026, 8, 1, tzinfo=timezone.utc),
    )
    return coordinator, package, statement, policy, node


def test_record_is_store_first_audited_and_idempotent(tmp_path):
    coordinator, _package, _statement, policy, _node = _system(tmp_path)

    first = coordinator.record(
        policy,
        observed_at_ms=1_785_542_400_000,
    )
    duplicate = coordinator.record(
        policy,
        observed_at_ms=1_785_542_401_000,
    )

    assert first.store_created
    assert first.anchor_created
    assert not duplicate.store_created
    assert not duplicate.anchor_created
    assert first.event.event_id == duplicate.event.event_id
    assert coordinator.verify_anchors() == (True, "ok")


def test_reconcile_repairs_store_first_crash(tmp_path):
    coordinator, _package, _statement, policy, _node = _system(tmp_path)
    coordinator.policy_store.append(policy)

    assert coordinator.verify_anchors()[0] is False
    repaired = coordinator.reconcile(observed_at_ms=1_785_542_400_000)

    assert repaired.scanned == 1
    assert repaired.anchored == 1
    assert repaired.remaining == 0
    assert coordinator.verify_anchors() == (True, "ok")


def test_record_blocks_successor_until_predecessor_is_reconciled(tmp_path):
    coordinator, _package, _statement, policy, node = _system(tmp_path)
    coordinator.policy_store.append(policy)
    successor = create_rule_recognition_policy(
        node,
        node_did=node.as_did(),
        trust_policy=policy.trust_policy,
        issued_at="2026-08-01T00:00:01Z",
        previous=policy,
        now=datetime(2026, 8, 1, 0, 0, 1, tzinfo=timezone.utc),
    )

    with pytest.raises(
        RuleRecognitionPolicyAuditIntegrityError,
        match="reconcile before recording a successor",
    ):
        coordinator.record(
            successor,
            observed_at_ms=1_785_542_401_000,
        )
    assert coordinator.policy_store.list_all() == (policy,)

    coordinator.reconcile(observed_at_ms=1_785_542_402_000)
    recorded = coordinator.record(
        successor,
        observed_at_ms=1_785_542_403_000,
    )
    assert recorded.store_created
    assert coordinator.verify_anchors() == (True, "ok")


def test_orphan_anchor_blocks_unrelated_policy_write(tmp_path):
    coordinator, _package, _statement, policy, node = _system(tmp_path)
    coordinator.spine.append(
        EVENT_TRADE_RULE_RECOGNITION_POLICY_UPDATED,
        rule_recognition_policy_audit_payload(policy),
        ts_ms=1_785_542_400_000,
    )
    unrelated = create_rule_recognition_policy(
        node,
        node_did=node.as_did(),
        trust_policy=policy.trust_policy,
        issued_at="2026-08-01T00:00:01Z",
        previous=policy,
        now=datetime(2026, 8, 1, 0, 0, 1, tzinfo=timezone.utc),
    )

    with pytest.raises(
        RuleRecognitionPolicyAuditIntegrityError,
        match="rollback evidence",
    ):
        coordinator.record(
            unrelated,
            observed_at_ms=1_785_542_401_000,
        )
    assert coordinator.policy_store.list_all() == ()


def test_exact_orphan_policy_can_restore_local_cas(tmp_path):
    coordinator, _package, _statement, policy, _node = _system(tmp_path)
    event = coordinator.spine.append(
        EVENT_TRADE_RULE_RECOGNITION_POLICY_UPDATED,
        rule_recognition_policy_audit_payload(policy),
        ts_ms=1_785_542_400_000,
    )

    restored = coordinator.record(
        policy,
        observed_at_ms=1_785_542_401_000,
    )

    assert restored.store_created
    assert not restored.anchor_created
    assert restored.event.event_id == event.event_id
    assert coordinator.verify_anchors() == (True, "ok")


def test_evaluate_requires_both_audit_chains_and_reports_quorum(tmp_path):
    coordinator, package, statement, policy, _node = _system(tmp_path)
    coordinator.record(policy, observed_at_ms=1_785_542_400_000)
    imported = coordinator.recognition_audit.store.import_json(
        statement.canonical_bytes,
        package=package,
    )
    assert imported.accepted

    with pytest.raises(
        RuleRecognitionPolicyAuditIntegrityError,
        match="missing Recognition anchor",
    ):
        coordinator.evaluate(
            package.digest,
            at=datetime(2026, 8, 1, tzinfo=timezone.utc),
        )

    coordinator.recognition_audit.record(
        statement,
        package=package,
        observed_at_ms=1_785_542_401_000,
    )
    result = coordinator.evaluate(
        package.digest,
        at=datetime(2026, 8, 1, tzinfo=timezone.utc),
    )

    assert result.policy.digest == policy.digest
    assert result.snapshot.observed_quorum_met
    assert result.snapshot.recognized_by == (
        statement.to_dict()["issuer_did"],
    )
    assert not RuleResolutionPolicy().accepts(package)


def test_evaluate_uses_policy_effective_at_requested_time(tmp_path):
    coordinator, package, statement, policy, node = _system(tmp_path)
    coordinator.record(policy, observed_at_ms=1_785_542_400_000)
    coordinator.recognition_audit.record(
        statement,
        package=package,
        observed_at_ms=1_785_542_401_000,
    )
    unrelated_issuer = AgentIdentity.generate(label="future-issuer").as_did()
    future_policy = create_rule_recognition_policy(
        node,
        node_did=node.as_did(),
        trust_policy=RuleRecognitionTrustPolicy(
            trusted_issuers={unrelated_issuer},
            threshold=1,
            issuer_rule_scopes={unrelated_issuer: ("*",)},
        ),
        issued_at="2026-08-02T00:00:00Z",
        previous=policy,
        now=datetime(2026, 8, 2, tzinfo=timezone.utc),
    )
    coordinator.record(
        future_policy,
        observed_at_ms=1_785_628_800_000,
    )

    historical = coordinator.evaluate(
        package.digest,
        at=datetime(2026, 8, 1, 12, tzinfo=timezone.utc),
    )
    future = coordinator.evaluate(
        package.digest,
        at=datetime(2026, 8, 2, tzinfo=timezone.utc),
    )

    assert historical.policy.digest == policy.digest
    assert historical.snapshot.observed_quorum_met
    assert future.policy.digest == future_policy.digest
    assert not future.snapshot.observed_quorum_met


def test_evaluate_rejects_time_before_first_policy(tmp_path):
    coordinator, package, _statement, policy, _node = _system(tmp_path)
    coordinator.record(policy, observed_at_ms=1_785_542_400_000)

    with pytest.raises(
        RuleRecognitionPolicyAuditError,
        match="not active at the requested time",
    ):
        coordinator.evaluate(
            package.digest,
            at=datetime(2026, 7, 31, 23, 59, 59, tzinfo=timezone.utc),
        )


def test_evaluate_rejects_naive_projection_time(tmp_path):
    coordinator, package, _statement, policy, _node = _system(tmp_path)
    coordinator.record(policy, observed_at_ms=1_785_542_400_000)

    with pytest.raises(
        RuleRecognitionPolicyAuditError,
        match="timezone-aware",
    ):
        coordinator.evaluate(
            package.digest,
            at=datetime(2026, 8, 1),
        )


def test_evaluate_fails_without_policy_or_package(tmp_path):
    coordinator, package, _statement, policy, _node = _system(tmp_path)

    with pytest.raises(
        RuleRecognitionPolicyAuditError,
        match="not configured",
    ):
        coordinator.evaluate(package.digest)
    coordinator.record(policy, observed_at_ms=1_785_542_400_000)
    with pytest.raises(
        RuleRecognitionPolicyAuditError,
        match="not installed",
    ):
        coordinator.evaluate("sha256:" + ("0" * 64))


@pytest.mark.parametrize(
    "issued_at",
    [
        "2026-02-30T00:00:00Z",
        "2026-08-01T00:00:00.000000Z",
        "2026-08-01T00:00:00+00:00",
    ],
)
def test_audit_payload_rejects_noncanonical_or_impossible_time(
    tmp_path,
    issued_at,
):
    _coordinator, _package, _statement, policy, _node = _system(tmp_path)
    payload = rule_recognition_policy_audit_payload(policy)
    payload["issued_at"] = issued_at

    with pytest.raises(RuleRecognitionPolicyAuditError, match="issued_at"):
        validate_rule_recognition_policy_audit_payload(payload)


def test_audit_payload_rejects_policy_id_not_bound_to_node(tmp_path):
    _coordinator, _package, _statement, policy, _node = _system(tmp_path)
    payload = rule_recognition_policy_audit_payload(policy)
    payload["policy_id"] = (
        "nth-trade-recognition-policy-sha256:" + ("0" * 64)
    )

    with pytest.raises(
        RuleRecognitionPolicyAuditError,
        match="does not bind node_did",
    ):
        validate_rule_recognition_policy_audit_payload(payload)


def test_evaluate_rejects_policy_change_during_projection(
    tmp_path,
    monkeypatch,
):
    coordinator, package, _statement, policy, node = _system(tmp_path)
    coordinator.record(policy, observed_at_ms=1_785_542_400_000)
    successor = create_rule_recognition_policy(
        node,
        node_did=node.as_did(),
        trust_policy=policy.trust_policy,
        issued_at="2026-08-01T00:00:01Z",
        previous=policy,
        now=datetime(2026, 8, 1, 0, 0, 1, tzinfo=timezone.utc),
    )

    original_anchor_index = coordinator._anchor_index

    def _race_policy():
        coordinator.policy_store.append(successor)
        return original_anchor_index()

    monkeypatch.setattr(coordinator, "_anchor_index", _race_policy)
    with pytest.raises(
        RuleRecognitionPolicyAuditIntegrityError,
        match="changed during projection",
    ):
        coordinator.evaluate(package.digest)


def test_evaluate_rejects_recognition_change_during_projection(
    tmp_path,
    monkeypatch,
):
    coordinator, package, statement, policy, _node = _system(tmp_path)
    coordinator.record(policy, observed_at_ms=1_785_542_400_000)

    original_anchor_index = coordinator.recognition_audit._anchor_index

    def _race_recognition(events=None):
        imported = coordinator.recognition_audit.store.import_json(
            statement.canonical_bytes,
            package=package,
        )
        assert imported.accepted
        return original_anchor_index(events)

    monkeypatch.setattr(
        coordinator.recognition_audit,
        "_anchor_index",
        _race_recognition,
    )
    with pytest.raises(
        RuleRecognitionPolicyAuditIntegrityError,
        match="statements changed during projection",
    ):
        coordinator.evaluate(package.digest)
