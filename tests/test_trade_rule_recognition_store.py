import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest

from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.trade_rules.manifest import manifest_body, sign_manifest
from nth_dao.trade_rules.package_store import build_rule_package
from nth_dao.trade_rules.recognition import create_rule_recognition
from nth_dao.trade_rules.recognition_store import (
    RuleRecognitionStore,
    RuleRecognitionStoreCapacity,
    RuleRecognitionStoreCorruption,
)

pytestmark = pytest.mark.skipif(
    not crypto_available(),
    reason="Trade Rule signatures require PyNaCl",
)


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _package(rule_id="org.nthdao.community.exchange"):
    publisher = AgentIdentity.generate()
    payload = b'{"type":"object"}'
    digest = _digest(payload)
    manifest = sign_manifest(
        publisher,
        manifest_body(
            rule_id=rule_id,
            version="1.0.0",
            publisher_did=publisher.as_did(),
            summary="Recognition store test package",
            applies_to=["service"],
            families=["acceptance"],
            resources=[
                {
                    "purpose": "terms",
                    "media_type": "application/json",
                    "digest": digest,
                    "size": len(payload),
                }
            ],
            published_at="2026-08-01T00:00:00Z",
            not_after="2027-08-01T00:00:00Z",
        ),
        created="2026-08-01T00:00:00Z",
    )
    return build_rule_package(manifest, {digest: payload})


def _statement(package, issuer=None):
    identity = issuer or AgentIdentity.generate()
    return create_rule_recognition(
        identity,
        package=package,
        decision="recognized",
        issued_at="2026-08-01T00:00:00Z",
        not_after="2026-08-20T00:00:00Z",
        now=datetime(2026, 8, 1, tzinfo=timezone.utc),
    )


def test_store_import_is_durable_idempotent_and_content_addressed(tmp_path):
    package = _package()
    statement = _statement(package)
    store = RuleRecognitionStore(tmp_path)

    first = store.import_json(
        statement.canonical_bytes,
        package=package,
    )
    second = store.import_json(
        statement.canonical_bytes,
        package=package,
    )
    assert first.accepted and not first.duplicate
    assert second.accepted and second.duplicate

    restarted = RuleRecognitionStore(tmp_path)
    loaded = restarted.list_for_package(package)
    assert len(loaded) == 1
    assert loaded[0].canonical_bytes == statement.canonical_bytes
    stored_path = (
        tmp_path
        / "trade"
        / "rule_recognitions_v1"
        / "statements"
        / f"{statement.digest[7:]}.json"
    )
    assert stored_path.read_bytes() == statement.canonical_bytes


def test_invalid_input_is_quarantined_without_storing_raw_bytes(tmp_path):
    package = _package()
    statement = _statement(package)
    tampered = statement.to_dict()
    secret = "do-not-store-this-remote-content"
    tampered["proof"]["proof_value"] = secret
    raw = json.dumps(tampered).encode()
    result = RuleRecognitionStore(tmp_path).import_json(
        raw,
        package=package,
    )
    assert not result.accepted
    assert result.quarantine_persisted
    assert result.rejection_code == "signature-invalid"
    quarantine_files = list(
        (
            tmp_path
            / "trade"
            / "rule_recognitions_v1"
            / "quarantine"
        ).glob("*.json")
    )
    assert len(quarantine_files) == 1
    metadata = quarantine_files[0].read_text(encoding="utf-8")
    assert secret not in metadata
    assert result.input_digest in metadata
    assert RuleRecognitionStore(tmp_path).list_for_package(package) == ()


def test_store_retains_statements_for_multiple_packages_but_filters_reads(
    tmp_path,
):
    first_package = _package()
    second_package = _package("org.nthdao.community.delivery")
    first = _statement(first_package)
    second = _statement(second_package)
    store = RuleRecognitionStore(tmp_path)
    store.import_json(first.canonical_bytes, package=first_package)
    store.import_json(second.canonical_bytes, package=second_package)

    assert [item.digest for item in store.list_for_package(first_package)] == [
        first.digest
    ]
    assert [item.digest for item in store.list_for_package(second_package)] == [
        second.digest
    ]


def test_store_concurrent_duplicate_import_is_exactly_one_new_write(tmp_path):
    package = _package()
    statement = _statement(package)

    def publish(_):
        return RuleRecognitionStore(tmp_path).import_json(
            statement.canonical_bytes,
            package=package,
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(publish, range(16)))
    assert sum(not result.duplicate for result in results) == 1
    assert all(result.accepted for result in results)
    assert len(RuleRecognitionStore(tmp_path).list_for_package(package)) == 1


def test_store_capacity_and_corruption_fail_closed(tmp_path):
    package = _package()
    first = _statement(package)
    second = _statement(package)
    store = RuleRecognitionStore(tmp_path, max_statements=1)
    store.import_json(first.canonical_bytes, package=package)
    with pytest.raises(RuleRecognitionStoreCapacity):
        store.import_json(second.canonical_bytes, package=package)

    path = (
        tmp_path
        / "trade"
        / "rule_recognitions_v1"
        / "statements"
        / f"{first.digest[7:]}.json"
    )
    path.write_bytes(b"{}")
    with pytest.raises(RuleRecognitionStoreCorruption):
        store.list_for_package(package)


def test_store_rejects_unexpected_quarantine_entries(tmp_path):
    package = _package()
    quarantine = (
        tmp_path
        / "trade"
        / "rule_recognitions_v1"
        / "quarantine"
    )
    quarantine.mkdir(parents=True)
    (quarantine / "unexpected.txt").write_text("x", encoding="utf-8")
    tampered = _statement(package).to_dict()
    tampered["proof"]["proof_value"] = "invalid"
    with pytest.raises(
        RuleRecognitionStoreCorruption,
        match="quarantine contains an unexpected entry",
    ):
        RuleRecognitionStore(tmp_path).import_json(
            json.dumps(tampered),
            package=package,
        )
