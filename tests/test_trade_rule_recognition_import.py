from __future__ import annotations

import copy
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone

import pytest
import nth_dao.trade_rules.recognition_audit as recognition_audit_api

from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.spine import SignedEventLog
from nth_dao.trade_rules import (
    EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORTED,
    EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED,
    RuleRecognitionAuditCoordinator,
    RuleRecognitionAuditIntegrityError,
    RuleRecognitionProofImportCoordinator,
    RuleRecognitionProofImportError,
    RuleRecognitionProofStore,
    RuleRecognitionStore,
    RuleRecognitionStoreCapacity,
    append_recognition_proof_import_event,
    build_rule_package,
    build_rule_recognition_proof_pages,
    canonical_recognition_source_origin,
    create_rule_recognition,
    parse_rule_recognition_proof_bundle,
    parse_rule_recognition_proof_pages,
    recognition_proof_import_payload,
    recognition_proof_import_states,
    sign_offer_package_binding,
    validate_recognition_proof_import_payload,
)
from nth_dao.trade_rules.canonical import MAX_TRADE_JSON_BYTES
from nth_dao.trade_rules.recognition_transport_conformance import VECTORS_PATH
from nth_dao.trade_rules.recognition_import_conformance import (
    SCHEMA_PATH as IMPORT_SCHEMA_PATH,
    VECTORS_PATH as IMPORT_VECTORS_PATH,
    generate_vectors as generate_import_vectors,
)
from nth_dao.trade_rules.recognition_import_pages_conformance import (
    VECTORS_PATH as PAGE_IMPORT_VECTORS_PATH,
    generate_vectors as generate_page_import_vectors,
)

pytestmark = pytest.mark.skipif(
    not crypto_available(),
    reason="Trade Rule Recognition requires PyNaCl",
)

_NOW = datetime(2026, 8, 3, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("http://Peer.Example:80", "http://peer.example"),
        ("https://Peer.Example.:443", "https://peer.example"),
        ("http://[2001:0db8::1]:8080", "http://[2001:db8::1]:8080"),
    ],
)
def test_recognition_source_origin_canonicalization(value, expected):
    assert canonical_recognition_source_origin(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "http://.",
        "http://peer.example/foo/..",
        "http://peer.example/%2e",
        "http://peer.example\\foo",
        " http://peer.example",
        "http://peer.example\x00",
    ],
)
def test_recognition_source_origin_rejects_ambiguous_or_empty_hosts(value):
    with pytest.raises(ValueError, match="Recognition source"):
        canonical_recognition_source_origin(value)


def _artifacts():
    vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    package = build_rule_package(
        vectors["package_manifest"],
        {
            digest: bytes.fromhex(payload)
            for digest, payload in vectors["package_resources_hex"].items()
        },
    )
    proof = parse_rule_recognition_proof_bundle(
        vectors["bundle"],
        package=package,
        expected_offer_digest=vectors["offer_digest"],
        expected_offer_publisher_did=vectors["offer_publisher_did"],
        now=_NOW,
    )
    return vectors, package, proof


def _paged_artifacts(*, observed_at=None, count=300):
    observed_at = observed_at or datetime.now(timezone.utc).replace(microsecond=0)
    _vectors, package, _proof = _artifacts()
    observer = AgentIdentity.generate()
    issuer = AgentIdentity.generate()
    offer_digest = "sha256:" + ("b" * 64)
    binding = sign_offer_package_binding(
        observer,
        offer_digest=offer_digest,
        package_digest=package.digest,
        created="2026-08-01T00:00:00Z",
    )
    statements = []
    previous = None
    for _index in range(count):
        previous = create_rule_recognition(
            issuer,
            package=package,
            decision="recognized",
            issued_at="2026-08-01T00:00:00Z",
            not_after="2026-08-20T00:00:00Z",
            previous=previous,
            now=datetime(2026, 8, 1, tzinfo=timezone.utc),
        )
        statements.append(previous)
    not_after = observed_at + timedelta(minutes=5)
    wires = build_rule_recognition_proof_pages(
        package,
        statements,
        offer_package_binding=binding,
        observer_identity=observer,
        observed_at=observed_at.isoformat().replace("+00:00", "Z"),
        not_after=not_after.isoformat().replace("+00:00", "Z"),
        now=observed_at,
    )
    proof_set = parse_rule_recognition_proof_pages(
        wires,
        package=package,
        expected_offer_digest=offer_digest,
        expected_offer_publisher_did=observer.as_did(),
        now=observed_at,
    )
    return package, observer, offer_digest, proof_set, observed_at


def test_paged_proof_import_commits_complete_large_graph(tmp_path, monkeypatch):
    package, observer, offer_digest, proof_set, observed_at = _paged_artifacts()
    monkeypatch.setattr(
        "nth_dao.spine.log.now_ms",
        lambda: int(observed_at.timestamp() * 1000),
    )
    spine = SignedEventLog(tmp_path / "spine.jsonl", AgentIdentity.generate())
    audit = RuleRecognitionAuditCoordinator(
        store=RuleRecognitionStore(tmp_path),
        spine=spine,
    )
    importer = RuleRecognitionProofImportCoordinator(tmp_path, audit)

    commit = importer.import_pages_or_recover(
        order_digest="sha256:" + ("1" * 64),
        package=package,
        offer_digest=offer_digest,
        offer_publisher_did=observer.as_did(),
        source_origin="http://localhost:19090",
        fetch_proof_set=lambda: proof_set,
    )

    assert len(commit.imported) == 300
    assert len(commit.page_audits) == len(proof_set.pages)
    assert all(
        audit_item["proposal_event_id"]
        and audit_item["completion_event_id"]
        for audit_item in commit.page_audits
    )
    assert {
        statement.digest
        for statement in audit.verified_statements(package=package)
    } == {statement.digest for statement in proof_set.statements}
    states = recognition_proof_import_states(
        spine.verified_snapshot(),
        package_digest=package.digest,
    )
    assert len(states) == len(proof_set.pages)
    assert all(state.completed_event is not None for state in states)


def test_paged_proof_import_preflights_whole_store_capacity(
    tmp_path,
    monkeypatch,
):
    package, observer, offer_digest, proof_set, observed_at = _paged_artifacts()
    monkeypatch.setattr(
        "nth_dao.spine.log.now_ms",
        lambda: int(observed_at.timestamp() * 1000),
    )
    monkeypatch.setattr(
        "nth_dao.trade_rules.recognition_import_coordinator."
        "MAX_RULE_RECOGNITION_IMPORT_BATCH",
        128,
    )
    spine = SignedEventLog(tmp_path / "spine.jsonl", AgentIdentity.generate())
    store = RuleRecognitionStore(tmp_path, max_statements=200)
    audit = RuleRecognitionAuditCoordinator(store=store, spine=spine)
    importer = RuleRecognitionProofImportCoordinator(tmp_path, audit)

    with pytest.raises(
        RuleRecognitionStoreCapacity,
        match="statement count limit reached",
    ):
        importer.import_pages_or_recover(
            order_digest="sha256:" + ("6" * 64),
            package=package,
            offer_digest=offer_digest,
            offer_publisher_did=observer.as_did(),
            source_origin="http://localhost:19090",
            fetch_proof_set=lambda: proof_set,
        )

    assert store.list_for_package(package) == ()
    assert recognition_proof_import_states(spine.verified_snapshot()) == ()
    assert RuleRecognitionProofStore(tmp_path)._files() == []


def test_paged_proof_import_deduplicates_refreshed_observation_across_origin_migration(
    tmp_path,
    monkeypatch,
):
    initial_time = datetime.now(timezone.utc).replace(
        microsecond=0,
    ) - timedelta(minutes=1)
    package, observer, offer_digest, first_set, _observed_at = (
        _paged_artifacts(observed_at=initial_time)
    )
    refreshed_at = initial_time + timedelta(seconds=30)
    binding = sign_offer_package_binding(
        observer,
        offer_digest=offer_digest,
        package_digest=package.digest,
        created="2026-08-01T00:00:00Z",
    )
    refreshed_wires = build_rule_recognition_proof_pages(
        package,
        first_set.statements,
        offer_package_binding=binding,
        observer_identity=observer,
        observed_at=refreshed_at.isoformat().replace("+00:00", "Z"),
        not_after=(refreshed_at + timedelta(minutes=5)).isoformat().replace(
            "+00:00",
            "Z",
        ),
        now=refreshed_at,
    )
    refreshed_set = parse_rule_recognition_proof_pages(
        refreshed_wires,
        package=package,
        expected_offer_digest=offer_digest,
        expected_offer_publisher_did=observer.as_did(),
        now=refreshed_at,
    )
    monkeypatch.setattr(
        "nth_dao.spine.log.now_ms",
        lambda: int(initial_time.timestamp() * 1000),
    )
    spine = SignedEventLog(tmp_path / "spine.jsonl", AgentIdentity.generate())
    audit = RuleRecognitionAuditCoordinator(
        store=RuleRecognitionStore(tmp_path),
        spine=spine,
    )
    importer = RuleRecognitionProofImportCoordinator(tmp_path, audit)
    kwargs = {
        "order_digest": "sha256:" + ("2" * 64),
        "package": package,
        "offer_digest": offer_digest,
        "offer_publisher_did": observer.as_did(),
    }

    first = importer.import_pages_or_recover(
        **kwargs,
        source_origin="http://Peer.Example:80",
        fetch_proof_set=lambda: first_set,
    )
    proof_files_before = tuple(
        RuleRecognitionProofStore(tmp_path)._files()
    )
    spine_before = spine.verified_snapshot()
    second = importer.import_pages_or_recover(
        **kwargs,
        source_origin="http://peer.example",
        fetch_proof_set=lambda: refreshed_set,
    )

    assert len(first.imported) == 300
    assert second.imported == ()
    assert second.page_audits == first.page_audits
    assert tuple(RuleRecognitionProofStore(tmp_path)._files()) == (
        proof_files_before
    )
    assert spine.verified_snapshot() == spine_before


def test_paged_proof_import_recovers_after_partial_proposal_phase(
    tmp_path,
    monkeypatch,
):
    observed_at = datetime.now(timezone.utc).replace(
        microsecond=0,
    ) - timedelta(minutes=1)
    package, observer, offer_digest, proof_set, _observed_at = (
        _paged_artifacts(observed_at=observed_at)
    )
    monkeypatch.setattr(
        "nth_dao.spine.log.now_ms",
        lambda: int(observed_at.timestamp() * 1000),
    )
    spine = SignedEventLog(tmp_path / "spine.jsonl", AgentIdentity.generate())
    audit = RuleRecognitionAuditCoordinator(
        store=RuleRecognitionStore(tmp_path),
        spine=spine,
    )
    importer = RuleRecognitionProofImportCoordinator(tmp_path, audit)
    proof_store = RuleRecognitionProofStore(tmp_path)
    for page in proof_set.pages:
        proof_store.put(page)
    first_payload = recognition_proof_import_payload(
        proof_set.pages[0],
        event_type=EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED,
        order_digest="sha256:" + ("3" * 64),
        offer_digest=offer_digest,
        source_origin="http://localhost:19090",
    )
    append_recognition_proof_import_event(
        spine,
        event_type=EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED,
        payload=first_payload,
    )

    with pytest.raises(
        RuleRecognitionAuditIntegrityError,
        match="proof import is incomplete",
    ):
        audit.verified_statements(package=package)

    def unexpected_fetch():
        raise AssertionError("recovery must not fetch retained proof pages")

    commit = importer.import_pages_or_recover(
        order_digest="sha256:" + ("3" * 64),
        package=package,
        offer_digest=offer_digest,
        offer_publisher_did=observer.as_did(),
        source_origin="http://different-origin.invalid",
        fetch_proof_set=unexpected_fetch,
    )

    assert len(commit.imported) == 300
    assert len(commit.page_audits) == len(proof_set.pages)
    states = recognition_proof_import_states(
        spine.verified_snapshot(),
        package_digest=package.digest,
    )
    assert len(states) == len(proof_set.pages)
    assert all(state.completed_event is not None for state in states)
    assert {
        state.payload["source_origin"] for state in states
    } == {"http://localhost:19090"}
    assert len(audit.verified_statements(package=package)) == 300


def test_paged_proof_import_recovers_after_partial_statement_phase(
    tmp_path,
    monkeypatch,
):
    observed_at = datetime.now(timezone.utc).replace(
        microsecond=0,
    ) - timedelta(minutes=1)
    package, observer, offer_digest, proof_set, _observed_at = (
        _paged_artifacts(observed_at=observed_at)
    )
    monkeypatch.setattr(
        "nth_dao.spine.log.now_ms",
        lambda: int(observed_at.timestamp() * 1000),
    )
    monkeypatch.setattr(
        "nth_dao.trade_rules.recognition_import_coordinator."
        "MAX_RULE_RECOGNITION_IMPORT_BATCH",
        128,
    )
    spine = SignedEventLog(tmp_path / "spine.jsonl", AgentIdentity.generate())
    audit = RuleRecognitionAuditCoordinator(
        store=RuleRecognitionStore(tmp_path),
        spine=spine,
    )
    importer = RuleRecognitionProofImportCoordinator(tmp_path, audit)
    original_record_batch = audit.record_batch
    batch_calls = 0

    def fail_second_batch(statements, *, package):
        nonlocal batch_calls
        batch_calls += 1
        if batch_calls == 2:
            raise OSError("simulated crash during statement persistence")
        return original_record_batch(statements, package=package)

    monkeypatch.setattr(audit, "record_batch", fail_second_batch)
    kwargs = {
        "order_digest": "sha256:" + ("4" * 64),
        "package": package,
        "offer_digest": offer_digest,
        "offer_publisher_did": observer.as_did(),
        "source_origin": "http://localhost:19090",
    }
    with pytest.raises(
        OSError,
        match="simulated crash during statement persistence",
    ):
        importer.import_pages_or_recover(
            **kwargs,
            fetch_proof_set=lambda: proof_set,
        )
    interrupted_states = recognition_proof_import_states(
        spine.verified_snapshot(),
        package_digest=package.digest,
    )
    assert len(interrupted_states) == len(proof_set.pages)
    assert all(
        state.completed_event is None for state in interrupted_states
    )
    with pytest.raises(
        RuleRecognitionAuditIntegrityError,
        match="proof import is incomplete",
    ):
        audit.verified_statements(package=package)

    monkeypatch.setattr(audit, "record_batch", original_record_batch)

    def unexpected_fetch():
        raise AssertionError("recovery must use retained proof pages")

    recovered = importer.import_or_recover(
        **kwargs,
        fetch_proof=unexpected_fetch,
    )

    assert 0 < len(recovered.imported) < 300
    assert len(audit.verified_statements(package=package)) == 300
    final_states = recognition_proof_import_states(
        spine.verified_snapshot(),
        package_digest=package.digest,
    )
    assert all(state.completed_event is not None for state in final_states)


def test_proof_store_is_content_addressed_and_detects_replacement(tmp_path):
    _vectors, _package, proof = _artifacts()
    store = RuleRecognitionProofStore(tmp_path)
    digest, created = store.put(proof)

    assert created is True
    assert store.put(proof) == (digest, False)
    assert store.get(digest) == proof.canonical_bytes

    store._path(digest).write_bytes(b"{}")
    with pytest.raises(
        RuleRecognitionProofImportError,
        match="content-address check",
    ):
        store.get(digest)


def test_proof_store_rejects_oversized_existing_content_before_reading_it(
    tmp_path,
):
    _vectors, _package, proof = _artifacts()
    store = RuleRecognitionProofStore(tmp_path)
    digest, _created = store.put(proof)
    store._path(digest).write_bytes(b"x" * (MAX_TRADE_JSON_BYTES + 1))

    with pytest.raises(
        RuleRecognitionProofImportError,
        match="exceeds its byte limit",
    ):
        store.put(proof)


def test_proof_store_does_not_claim_success_when_fsync_fails(
    tmp_path,
    monkeypatch,
):
    _vectors, _package, proof = _artifacts()
    store = RuleRecognitionProofStore(tmp_path)
    digest = "sha256:" + hashlib.sha256(proof.canonical_bytes).hexdigest()

    def fail_fsync(_descriptor):
        raise OSError("simulated durable-write failure")

    monkeypatch.setattr(os, "fsync", fail_fsync)
    with pytest.raises(
        RuleRecognitionProofImportError,
        match="unable to persist",
    ):
        store.put(proof)
    assert not store._path(digest).exists()


def test_proof_store_repairs_only_exact_audited_bytes(tmp_path):
    _vectors, _package, proof = _artifacts()
    store = RuleRecognitionProofStore(tmp_path)
    digest, created = store.put(proof)
    assert created is True
    store._path(digest).write_bytes(b"{}")

    assert store.repair_exact(proof, expected_digest=digest) is True
    assert store.get(digest) == proof.canonical_bytes
    assert store.repair_exact(proof, expected_digest=digest) is False
    with pytest.raises(
        RuleRecognitionProofImportError,
        match="does not match the audited proof digest",
    ):
        store.repair_exact(
            proof,
            expected_digest="sha256:" + ("0" * 64),
        )


def test_proof_import_rejects_completion_that_precedes_its_proposal(tmp_path):
    vectors, _package, proof = _artifacts()
    spine = SignedEventLog(
        tmp_path / "spine.jsonl",
        AgentIdentity.generate(),
    )
    proposed = recognition_proof_import_payload(
        proof,
        event_type=EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED,
        order_digest="sha256:" + ("9" * 64),
        offer_digest=vectors["offer_digest"],
        source_origin="http://localhost:19090",
    )
    completed = dict(proposed)
    completed["action"] = "recognition-proof-imported"
    append_recognition_proof_import_event(
        spine,
        event_type=EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORTED,
        payload=completed,
    )
    append_recognition_proof_import_event(
        spine,
        event_type=EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED,
        payload=proposed,
    )

    with pytest.raises(
        RuleRecognitionProofImportError,
        match="completion precedes its proposal",
    ):
        recognition_proof_import_states(spine.verified_snapshot())


def test_pending_proof_import_blocks_verified_projection_until_completion(
    tmp_path,
    monkeypatch,
):
    vectors, package, proof = _artifacts()
    monkeypatch.setattr(
        "nth_dao.spine.log.now_ms",
        lambda: int(_NOW.timestamp() * 1000),
    )
    identity = AgentIdentity.generate()
    spine = SignedEventLog(tmp_path / "spine.jsonl", identity)
    coordinator = RuleRecognitionAuditCoordinator(
        store=RuleRecognitionStore(tmp_path),
        spine=spine,
    )
    RuleRecognitionProofStore(tmp_path).put(proof)
    proposed = recognition_proof_import_payload(
        proof,
        event_type=EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED,
        order_digest="sha256:" + ("1" * 64),
        offer_digest=vectors["offer_digest"],
        source_origin="http://localhost:19090",
    )
    append_recognition_proof_import_event(
        spine,
        event_type=EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED,
        payload=proposed,
    )

    with pytest.raises(
        RuleRecognitionAuditIntegrityError,
        match="proof import is incomplete",
    ):
        coordinator.verified_statements(package=package)

    coordinator.record_batch(list(proof.statements), package=package)
    with pytest.raises(
        RuleRecognitionAuditIntegrityError,
        match="proof import is incomplete",
    ):
        coordinator.verified_statements(package=package)

    completed = dict(proposed)
    completed["action"] = "recognition-proof-imported"
    append_recognition_proof_import_event(
        spine,
        event_type=EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORTED,
        payload=completed,
    )
    assert {
        statement.digest
        for statement in coordinator.verified_statements(package=package)
    } == {statement.digest for statement in proof.statements}
    states = recognition_proof_import_states(
        spine.verified_snapshot(),
        package_digest=package.digest,
    )
    assert len(states) == 1
    assert states[0].completed_event is not None
    proof_store = RuleRecognitionProofStore(tmp_path)
    proof_digest = states[0].payload["proof_digest"]
    proof_store._path(proof_digest).write_bytes(b"{}")
    assert {
        statement.digest
        for statement in coordinator.verified_statements(package=package)
    } == {statement.digest for statement in proof.statements}
    with pytest.raises(
        RuleRecognitionAuditIntegrityError,
        match="source evidence is invalid",
    ):
        coordinator.verify_proof_import_evidence(package=package)


def test_completed_partial_page_set_cannot_enter_verified_projection(
    tmp_path,
    monkeypatch,
):
    observed_at = datetime.now(timezone.utc).replace(
        microsecond=0,
    ) - timedelta(minutes=1)
    monkeypatch.setattr(
        "nth_dao.trade_rules.recognition_transport_pages."
        "MAX_RULE_RECOGNITION_PROOF_PAGE_STATEMENTS",
        1,
    )
    package, _observer, offer_digest, proof_set, _observed_at = (
        _paged_artifacts(observed_at=observed_at, count=2)
    )
    assert len(proof_set.pages) == 2
    monkeypatch.setattr(
        "nth_dao.spine.log.now_ms",
        lambda: int(observed_at.timestamp() * 1000),
    )
    spine = SignedEventLog(tmp_path / "spine.jsonl", AgentIdentity.generate())
    audit = RuleRecognitionAuditCoordinator(
        store=RuleRecognitionStore(tmp_path),
        spine=spine,
    )
    page = proof_set.pages[0]
    RuleRecognitionProofStore(tmp_path).put(page)
    audit.record_batch(page.statements, package=package)
    proposed = recognition_proof_import_payload(
        page,
        event_type=EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED,
        order_digest="sha256:" + ("5" * 64),
        offer_digest=offer_digest,
        source_origin="http://localhost:19090",
    )
    append_recognition_proof_import_event(
        spine,
        event_type=EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED,
        payload=proposed,
    )
    completed = dict(proposed)
    completed["action"] = "recognition-proof-imported"
    append_recognition_proof_import_event(
        spine,
        event_type=EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORTED,
        payload=completed,
    )

    with pytest.raises(
        RuleRecognitionAuditIntegrityError,
        match="page import set is incomplete",
    ):
        audit.verified_statements(package=package)


def test_completion_cannot_claim_statements_missing_from_local_cas(tmp_path):
    vectors, package, proof = _artifacts()
    spine = SignedEventLog(
        tmp_path / "spine.jsonl",
        AgentIdentity.generate(),
    )
    coordinator = RuleRecognitionAuditCoordinator(
        store=RuleRecognitionStore(tmp_path),
        spine=spine,
    )
    RuleRecognitionProofStore(tmp_path).put(proof)
    proposed = recognition_proof_import_payload(
        proof,
        event_type=EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED,
        order_digest="sha256:" + ("2" * 64),
        offer_digest=vectors["offer_digest"],
        source_origin="http://localhost:19090",
    )
    append_recognition_proof_import_event(
        spine,
        event_type=EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED,
        payload=proposed,
    )
    completed = dict(proposed)
    completed["action"] = "recognition-proof-imported"
    append_recognition_proof_import_event(
        spine,
        event_type=EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORTED,
        payload=completed,
    )

    with pytest.raises(
        RuleRecognitionAuditIntegrityError,
        match="missing local statement",
    ):
        coordinator.verified_statements(package=package)


def test_record_batch_uses_constant_store_scans_and_bounded_spine_chunks(
    tmp_path,
    monkeypatch,
):
    _vectors, package, _proof = _artifacts()
    statements = [
        create_rule_recognition(
            AgentIdentity.generate(),
            package=package,
            decision="recognized",
            issued_at="2026-08-03T00:00:00Z",
            not_after="2026-08-20T00:00:00Z",
            now=_NOW,
        )
        for _ in range(16)
    ]
    store = RuleRecognitionStore(tmp_path)
    spine = SignedEventLog(tmp_path / "spine.jsonl", AgentIdentity.generate())
    coordinator = RuleRecognitionAuditCoordinator(store=store, spine=spine)
    monkeypatch.setattr(
        recognition_audit_api,
        "MAX_SPINE_APPEND_BATCH",
        10,
    )
    store_scans = 0
    spine_scans = 0
    original_statement_files = store._statement_files
    original_verified_events = spine._verified_events_unlocked

    def counted_statement_files():
        nonlocal store_scans
        store_scans += 1
        return original_statement_files()

    def counted_verified_events():
        nonlocal spine_scans
        spine_scans += 1
        return original_verified_events()

    monkeypatch.setattr(store, "_statement_files", counted_statement_files)
    monkeypatch.setattr(
        spine,
        "_verified_events_unlocked",
        counted_verified_events,
    )

    results = coordinator.record_batch(statements, package=package)

    assert len(results) == 16
    assert all(result.store_created for result in results)
    assert all(result.anchor_created for result in results)
    assert store_scans == 3
    assert spine_scans == 3


def test_recognition_proof_import_vectors_and_schema_are_current():
    jsonschema = pytest.importorskip("jsonschema")
    stored = json.loads(IMPORT_VECTORS_PATH.read_text(encoding="utf-8"))
    assert stored == generate_import_vectors()
    schema = json.loads(IMPORT_SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)
    validator.validate(stored["proposed"])
    validator.validate(stored["completed"])

    invalid = copy.deepcopy(stored["completed"])
    invalid["proof_digest"] = "sha256:" + ("0" * 64)
    with pytest.raises(RuleRecognitionProofImportError, match="binding is invalid"):
        validate_recognition_proof_import_payload(
            stored["event_types"]["completed"],
            invalid,
        )


def test_recognition_page_import_vectors_and_schema_are_current():
    jsonschema = pytest.importorskip("jsonschema")
    stored = json.loads(PAGE_IMPORT_VECTORS_PATH.read_text(encoding="utf-8"))
    assert stored == generate_page_import_vectors()
    schema = json.loads(IMPORT_SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)
    for event_type, payloads in (
        (stored["event_types"]["proposed"], stored["proposed_pages"]),
        (stored["event_types"]["completed"], stored["completed_pages"]),
    ):
        for payload in payloads:
            validator.validate(payload)
            assert validate_recognition_proof_import_payload(
                event_type,
                payload,
            ) == payload
    assert [
        payload["page_index"] for payload in stored["proposed_pages"]
    ] == list(range(len(stored["proposed_pages"])))
    invalid = copy.deepcopy(stored["proposed_pages"][0])
    invalid.pop("page_index")
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(invalid)
    with pytest.raises(
        RuleRecognitionProofImportError,
        match="missing or unknown fields",
    ):
        validate_recognition_proof_import_payload(
            stored["event_types"]["proposed"],
            invalid,
        )
