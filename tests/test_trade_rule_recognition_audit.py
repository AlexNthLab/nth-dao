from __future__ import annotations

import copy
import json
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from datetime import datetime, timezone

import pytest

from nth_dao.identity import AgentIdentity
from nth_dao.spine import SignedEventLog
from nth_dao.trade_rules.package_store import build_rule_package
from nth_dao.trade_rules.recognition import (
    TradeRuleRecognition,
    create_rule_recognition,
)
from nth_dao.trade_rules.recognition_audit import (
    EVENT_TRADE_RULE_RECOGNITION_RECORDED,
    RuleRecognitionAuditCoordinator,
    RuleRecognitionAuditError,
    rule_recognition_audit_payload,
    validate_rule_recognition_audit_binding,
    validate_rule_recognition_audit_payload,
)
from nth_dao.trade_rules.recognition_conformance import (
    AUDIT_SCHEMA_PATH,
    VECTORS_PATH,
)
from nth_dao.trade_rules.recognition_store import RuleRecognitionStore


def _artifacts():
    vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    package = build_rule_package(
        vectors["package_manifest"],
        {
            digest: bytes.fromhex(payload)
            for digest, payload in vectors["package_resources_hex"].items()
        },
    )
    return (
        vectors,
        package,
        TradeRuleRecognition.from_dict(vectors["recognized"]),
        TradeRuleRecognition.from_dict(vectors["revoked"]),
    )


def _coordinator(tmp_path):
    return RuleRecognitionAuditCoordinator(
        store=RuleRecognitionStore(tmp_path),
        spine=SignedEventLog(
            tmp_path / "spine.jsonl",
            AgentIdentity.generate(label="recognition-auditor"),
        ),
    )


def _process_record(workspace_root: str):
    _vectors, package, statement, _revoked = _artifacts()
    root = workspace_root
    coordinator = RuleRecognitionAuditCoordinator(
        store=RuleRecognitionStore(root),
        spine=SignedEventLog(
            f"{root}/spine.jsonl",
            AgentIdentity.generate(label="process-auditor"),
        ),
    )
    result = coordinator.record(
        statement,
        package=package,
        observed_at_ms=1_785_542_400_000,
    )
    return (
        result.store_created,
        result.anchor_created,
        result.event.event_id,
    )


def test_audit_payload_binds_exact_signed_statement():
    vectors, package, statement, _revoked = _artifacts()
    payload = rule_recognition_audit_payload(statement, package=package)

    assert payload == vectors["recognized_audit_payload"]
    assert validate_rule_recognition_audit_binding(
        payload,
        statement=statement,
        package=package,
    ) == payload

    tampered = {**payload, "decision": "revoked"}
    with pytest.raises(
        RuleRecognitionAuditError,
        match="does not bind",
    ):
        validate_rule_recognition_audit_binding(
            tampered,
            statement=statement,
            package=package,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("protocol_version", "2"),
        ("recognition_digest", "sha256:BAD"),
        ("issuer_did", "did:key:invalid"),
        ("sequence", True),
        ("decision", "approved"),
        ("issued_at", "2026-08-01"),
        ("issued_at", "2026-02-30T00:00:00Z"),
    ],
)
def test_audit_payload_rejects_invalid_wire_values(field, value):
    _vectors, package, statement, _revoked = _artifacts()
    payload = rule_recognition_audit_payload(statement, package=package)
    payload[field] = value

    with pytest.raises(RuleRecognitionAuditError):
        validate_rule_recognition_audit_payload(payload)


def test_audit_payload_rejects_reversed_validity_interval():
    _vectors, package, statement, _revoked = _artifacts()
    payload = rule_recognition_audit_payload(statement, package=package)
    payload["not_after"] = payload["issued_at"]

    with pytest.raises(RuleRecognitionAuditError, match="must follow"):
        validate_rule_recognition_audit_payload(payload)


@pytest.mark.parametrize("observed_at_ms", [True, 0, -1, 2**53])
def test_record_rejects_invalid_observation_time_without_side_effects(
    tmp_path,
    observed_at_ms,
):
    _vectors, package, statement, _revoked = _artifacts()
    coordinator = _coordinator(tmp_path)

    with pytest.raises(ValueError, match="positive safe integer"):
        coordinator.record(
            statement,
            package=package,
            observed_at_ms=observed_at_ms,
        )
    assert coordinator.store.list_for_package(package) == ()
    assert coordinator.spine.verified_snapshot() == ()


def test_record_is_store_first_and_spine_idempotent(tmp_path):
    _vectors, package, statement, _revoked = _artifacts()
    coordinator = _coordinator(tmp_path)

    first = coordinator.record(
        statement,
        package=package,
        observed_at_ms=1_785_542_400_000,
    )
    second = coordinator.record(
        statement,
        package=package,
        observed_at_ms=1_785_542_401_000,
    )

    assert first.store_created
    assert first.anchor_created
    assert not second.store_created
    assert not second.anchor_created
    assert first.event.event_id == second.event.event_id
    assert len(coordinator.store.list_for_package(package)) == 1
    events = coordinator.spine.verified_snapshot()
    assert len(events) == 1
    assert events[0].type == EVENT_TRADE_RULE_RECOGNITION_RECORDED
    assert coordinator.verify_anchors(package=package) == (True, "ok")


def test_store_survives_spine_failure_and_reconcile_repairs(
    tmp_path,
    monkeypatch,
):
    _vectors, package, statement, _revoked = _artifacts()
    coordinator = _coordinator(tmp_path)
    original = coordinator.spine.append_unique

    def fail_append(*args, **kwargs):
        raise OSError("simulated Spine outage")

    monkeypatch.setattr(coordinator.spine, "append_unique", fail_append)
    with pytest.raises(
        RuleRecognitionAuditError,
        match="unable to project",
    ):
        coordinator.record(
            statement,
            package=package,
            observed_at_ms=1_785_542_400_000,
        )
    assert len(coordinator.store.list_for_package(package)) == 1
    assert coordinator.spine.verified_snapshot() == ()

    monkeypatch.setattr(coordinator.spine, "append_unique", original)
    repaired = coordinator.reconcile(
        package=package,
        observed_at_ms=1_785_542_401_000,
    )
    assert repaired.scanned == 1
    assert repaired.anchored == 1
    assert repaired.failed == 0
    assert coordinator.verify_anchors(package=package) == (True, "ok")


def test_concurrent_record_creates_one_anchor(tmp_path):
    _vectors, package, statement, _revoked = _artifacts()
    coordinator = _coordinator(tmp_path)

    def record(_index):
        return coordinator.record(
            statement,
            package=package,
            observed_at_ms=1_785_542_400_000,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(record, range(16)))

    assert sum(result.store_created for result in results) == 1
    assert sum(result.anchor_created for result in results) == 1
    assert len({result.event.event_id for result in results}) == 1
    assert len(coordinator.spine.verified_snapshot()) == 1


def test_cross_process_record_creates_one_store_fact_and_anchor(tmp_path):
    context = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(
        max_workers=4,
        mp_context=context,
    ) as pool:
        results = list(
            pool.map(
                _process_record,
                [str(tmp_path)] * 8,
            )
        )

    assert sum(item[0] for item in results) == 1
    assert sum(item[1] for item in results) == 1
    assert len({item[2] for item in results}) == 1
    _vectors, package, _statement, _revoked = _artifacts()
    coordinator = RuleRecognitionAuditCoordinator(
        store=RuleRecognitionStore(tmp_path),
        spine=SignedEventLog(
            tmp_path / "spine.jsonl",
            AgentIdentity.generate(label="verifier"),
        ),
    )
    assert coordinator.verify_anchors(package=package) == (True, "ok")
    assert len(coordinator.spine.verified_snapshot()) == 1


def test_reconcile_is_bounded_and_resumable(tmp_path):
    _vectors, package, recognized, revoked = _artifacts()
    coordinator = _coordinator(tmp_path)
    for statement in (recognized, revoked):
        result = coordinator.store.import_json(
            statement.canonical_bytes,
            package=package,
        )
        assert result.accepted

    first = coordinator.reconcile(
        package=package,
        limit=1,
        observed_at_ms=1_785_542_400_000,
    )
    assert first.scanned == 1
    assert first.anchored == 1
    assert first.has_more
    assert first.remaining == 1
    assert first.blocked_digest is None
    assert first.error_code is None

    second = coordinator.reconcile(
        package=package,
        limit=1,
        observed_at_ms=1_785_542_401_000,
    )
    assert second.scanned == 1
    assert second.anchored == 1
    assert not second.has_more
    assert second.remaining == 0
    assert second.verified_anchored == 1
    assert coordinator.verify_anchors(package=package) == (True, "ok")


def test_reconcile_discovers_facts_added_between_runs(tmp_path):
    _vectors, package, statement, _revoked = _artifacts()
    coordinator = _coordinator(tmp_path)
    assert coordinator.store.import_json(
        statement.canonical_bytes,
        package=package,
    ).accepted
    first = coordinator.reconcile(
        package=package,
        limit=1,
        observed_at_ms=1_785_542_400_000,
    )
    assert first.remaining == 0

    late = create_rule_recognition(
        AgentIdentity.generate(label="late-issuer"),
        package=package,
        decision="recognized",
        issued_at="2026-08-03T00:00:00Z",
        not_after="2026-08-21T00:00:00Z",
        now=datetime(2026, 8, 3, tzinfo=timezone.utc),
    )
    assert coordinator.store.import_json(
        late.canonical_bytes,
        package=package,
    ).accepted
    second = coordinator.reconcile(
        package=package,
        limit=1,
        observed_at_ms=1_785_542_401_000,
    )
    assert second.scanned == 1
    assert second.anchored == 1
    assert second.remaining == 0
    assert coordinator.verify_anchors(package=package) == (True, "ok")


def test_reconcile_failure_does_not_advance_past_unanchored_fact(
    tmp_path,
    monkeypatch,
):
    _vectors, package, recognized, revoked = _artifacts()
    coordinator = _coordinator(tmp_path)
    statements = sorted((recognized, revoked), key=lambda item: item.digest)
    for statement in statements:
        result = coordinator.store.import_json(
            statement.canonical_bytes,
            package=package,
        )
        assert result.accepted
    original = coordinator._anchor

    def fail_second(statement, **kwargs):
        if statement.digest == statements[1].digest:
            raise RuleRecognitionAuditError("simulated anchor failure")
        return original(statement, **kwargs)

    monkeypatch.setattr(coordinator, "_anchor", fail_second)
    blocked = coordinator.reconcile(
        package=package,
        limit=2,
        observed_at_ms=1_785_542_400_000,
    )
    assert blocked.scanned == 2
    assert blocked.anchored == 1
    assert blocked.failed == 1
    assert blocked.has_more
    assert blocked.remaining == 1
    assert blocked.blocked_digest == statements[1].digest
    assert blocked.error_code == "spine-anchor-failed"
    assert blocked.error_message == "simulated anchor failure"

    monkeypatch.setattr(coordinator, "_anchor", original)
    repaired = coordinator.reconcile(
        package=package,
        limit=2,
        observed_at_ms=1_785_542_401_000,
    )
    assert repaired.scanned == 1
    assert repaired.anchored == 1
    assert repaired.failed == 0
    assert not repaired.has_more
    assert coordinator.verify_anchors(package=package) == (True, "ok")


def test_verify_anchors_detects_missing_and_orphaned_facts(tmp_path):
    _vectors, package, statement, _revoked = _artifacts()
    coordinator = _coordinator(tmp_path)
    imported = coordinator.store.import_json(
        statement.canonical_bytes,
        package=package,
    )
    assert imported.accepted

    ok, reason = coordinator.verify_anchors(package=package)
    assert not ok
    assert reason.startswith("missing Recognition anchor")

    payload = rule_recognition_audit_payload(statement, package=package)
    coordinator.spine.append(
        EVENT_TRADE_RULE_RECOGNITION_RECORDED,
        payload,
        ts_ms=1_785_542_400_000,
    )
    coordinator.spine.append(
        EVENT_TRADE_RULE_RECOGNITION_RECORDED,
        payload,
        ts_ms=1_785_542_401_000,
    )
    ok, reason = coordinator.verify_anchors(package=package)
    assert not ok
    assert "duplicate Recognition anchors" in reason


def test_verify_anchors_detects_orphan_without_local_statement(tmp_path):
    _vectors, package, statement, _revoked = _artifacts()
    coordinator = _coordinator(tmp_path)
    coordinator.spine.append(
        EVENT_TRADE_RULE_RECOGNITION_RECORDED,
        rule_recognition_audit_payload(statement, package=package),
        ts_ms=1_785_542_400_000,
    )

    ok, reason = coordinator.verify_anchors(package=package)
    assert not ok
    assert reason.startswith(
        "Recognition anchor has no local statement"
    )
    with pytest.raises(
        RuleRecognitionAuditError,
        match="rollback evidence",
    ):
        coordinator.reconcile(
            package=package,
            observed_at_ms=1_785_542_401_000,
        )


def test_record_blocks_new_fact_while_an_orphan_anchor_exists(tmp_path):
    _vectors, package, recognized, revoked = _artifacts()
    coordinator = _coordinator(tmp_path)
    coordinator.spine.append(
        EVENT_TRADE_RULE_RECOGNITION_RECORDED,
        rule_recognition_audit_payload(recognized, package=package),
        ts_ms=1_785_542_400_000,
    )

    with pytest.raises(
        RuleRecognitionAuditError,
        match="rollback evidence",
    ):
        coordinator.record(
            revoked,
            package=package,
            observed_at_ms=1_785_542_401_000,
        )
    assert coordinator.store.list_for_package(package) == ()
    assert len(coordinator.spine.verified_snapshot()) == 1


def test_record_can_restore_the_exact_orphaned_statement(tmp_path):
    _vectors, package, statement, _revoked = _artifacts()
    coordinator = _coordinator(tmp_path)
    event = coordinator.spine.append(
        EVENT_TRADE_RULE_RECOGNITION_RECORDED,
        rule_recognition_audit_payload(statement, package=package),
        ts_ms=1_785_542_400_000,
    )

    restored = coordinator.record(
        statement,
        package=package,
        observed_at_ms=1_785_542_401_000,
    )
    assert restored.store_created
    assert not restored.anchor_created
    assert restored.event.event_id == event.event_id
    assert coordinator.verify_anchors(package=package) == (True, "ok")


def test_record_rejects_conflicting_existing_anchor(tmp_path):
    _vectors, package, statement, _revoked = _artifacts()
    coordinator = _coordinator(tmp_path)
    payload = rule_recognition_audit_payload(statement, package=package)
    forged_payload = {**payload, "decision": "deprecated"}
    coordinator.spine.append(
        EVENT_TRADE_RULE_RECOGNITION_RECORDED,
        forged_payload,
        ts_ms=1_785_542_400_000,
    )

    with pytest.raises(
        RuleRecognitionAuditError,
        match="anchor mismatch",
    ):
        coordinator.record(
            statement,
            package=package,
            observed_at_ms=1_785_542_401_000,
        )
    assert coordinator.store.list_for_package(package) == ()
    assert len(coordinator.spine.verified_snapshot()) == 1


def test_tampered_statement_is_never_persisted_or_anchored(tmp_path):
    vectors, package, _statement, _revoked = _artifacts()
    coordinator = _coordinator(tmp_path)
    tampered = vectors["recognized"]
    tampered["not_after"] = "2026-08-19T00:00:00Z"

    with pytest.raises(ValueError, match="signature invalid"):
        coordinator.record(
            tampered,
            package=package,
            observed_at_ms=1_785_542_400_000,
        )
    assert coordinator.store.list_for_package(package) == ()
    assert coordinator.spine.verified_snapshot() == ()


def test_audit_schema_accepts_vector_and_rejects_extra_field():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(AUDIT_SCHEMA_PATH.read_text(encoding="utf-8"))
    vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)

    validator.validate(vectors["recognized_audit_payload"])
    validator.validate(vectors["revoked_audit_payload"])
    for payload in vectors["invalid_audit_payloads"].values():
        with pytest.raises(RuleRecognitionAuditError):
            validate_rule_recognition_audit_payload(payload)
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(
            vectors["invalid_audit_payloads"]["invalid_issuer_did"]
        )
    invalid = copy.deepcopy(vectors["recognized_audit_payload"])
    invalid["accepted"] = True
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(invalid)
