"""Signature, freshness, and rollback tests for curated registry envelopes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import multiprocessing
from pathlib import Path
import threading

import pytest

from nth_dao.identity import AgentIdentity
from nth_dao.plugins.registry_trust import (
    CURATED_REGISTRY_FORMAT,
    CuratedRegistryTrust,
)


def _hold_registry_refresh_lease(
    workspace: str,
    entered: multiprocessing.synchronize.Event,
    release: multiprocessing.synchronize.Event,
) -> None:
    trust = CuratedRegistryTrust(Path(workspace))
    with trust.refresh_cycle():
        entered.set()
        if not release.wait(10.0):
            raise RuntimeError("parent did not release registry refresh lease")


def _signed_envelope(
    publisher: AgentIdentity,
    *,
    version: int = 1,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> dict:
    now = datetime.now(timezone.utc)
    document = {
        "format": CURATED_REGISTRY_FORMAT,
        "publisher_did": publisher.as_did(),
        "version": version,
        "issued_at": (issued_at or now - timedelta(seconds=1)).isoformat(),
        "expires_at": (expires_at or now + timedelta(hours=1)).isoformat(),
        "peers": [{"peer_url": "https://peer.example"}],
    }
    document["sig"] = publisher.sign_json(document)
    return document


def test_signed_registry_version_is_process_safe_and_monotonic(
    tmp_path: Path,
) -> None:
    publisher = AgentIdentity.generate(label="publisher")
    first = CuratedRegistryTrust(tmp_path)
    second = CuratedRegistryTrust(tmp_path)
    envelope = _signed_envelope(publisher)

    verified = first.verify(
        envelope,
        expected_publisher_did=publisher.as_did(),
    )
    first.commit(verified)

    replay = second.verify(
        envelope,
        expected_publisher_did=publisher.as_did(),
    )
    assert replay.already_accepted is True
    assert second.commit(replay) is False
    upgraded = second.verify(
        _signed_envelope(publisher, version=2),
        expected_publisher_did=publisher.as_did(),
    )
    second.commit(upgraded)


def test_same_version_with_different_signed_content_is_rejected(
    tmp_path: Path,
) -> None:
    publisher = AgentIdentity.generate(label="publisher")
    trust = CuratedRegistryTrust(tmp_path)
    first_document = _signed_envelope(publisher, version=4)
    trust.commit(
        trust.verify(
            first_document,
            expected_publisher_did=publisher.as_did(),
        )
    )
    conflicting = _signed_envelope(publisher, version=4)
    conflicting["peers"] = [{"peer_url": "https://other.example"}]
    conflicting["sig"] = publisher.sign_json(
        {key: value for key, value in conflicting.items() if key != "sig"}
    )

    with pytest.raises(ValueError, match="conflicts with accepted content"):
        trust.verify(
            conflicting,
            expected_publisher_did=publisher.as_did(),
        )


def test_legacy_state_requires_version_increment_and_migrates(
    tmp_path: Path,
) -> None:
    publisher = AgentIdentity.generate(label="legacy-publisher")
    trust = CuratedRegistryTrust(tmp_path)
    trust.path.parent.mkdir(parents=True, exist_ok=True)
    trust.path.write_text(
        json.dumps({
            "format": "nth-dao-curated-registry-state-v1",
            "publishers": {publisher.as_did(): 6},
        }),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="legacy state requires a higher version"):
        trust.verify(
            _signed_envelope(publisher, version=6),
            expected_publisher_did=publisher.as_did(),
        )
    upgraded = trust.verify(
        _signed_envelope(publisher, version=7),
        expected_publisher_did=publisher.as_did(),
    )
    assert trust.commit(upgraded) is True
    persisted = json.loads(trust.path.read_text(encoding="utf-8"))
    assert persisted["format"] == "nth-dao-curated-registry-state-v2"
    assert persisted["publishers"][publisher.as_did()]["version"] == 7


def test_registry_refresh_lease_excludes_another_process(tmp_path: Path) -> None:
    context = multiprocessing.get_context("spawn")
    entered = context.Event()
    release = context.Event()
    worker = context.Process(
        target=_hold_registry_refresh_lease,
        args=(str(tmp_path), entered, release),
    )
    worker.start()
    try:
        assert entered.wait(5.0)
        with pytest.raises(RuntimeError, match="already running"):
            with CuratedRegistryTrust(tmp_path).refresh_cycle():
                pytest.fail("a concurrent process acquired the refresh lease")
    finally:
        release.set()
        worker.join(timeout=10.0)
        if worker.is_alive():
            worker.terminate()
            worker.join(timeout=5.0)

    assert worker.exitcode == 0
    with CuratedRegistryTrust(tmp_path).refresh_cycle():
        pass


def test_registry_state_lock_is_safe_for_threads_sharing_one_instance(
    tmp_path: Path,
) -> None:
    publisher = AgentIdentity.generate(label="threaded-publisher")
    document = _signed_envelope(publisher, version=3)
    trust = CuratedRegistryTrust(tmp_path)
    verified = [
        trust.verify(document, expected_publisher_did=publisher.as_did())
        for _ in range(2)
    ]
    barrier = threading.Barrier(2)
    results: list[bool] = []
    errors: list[Exception] = []

    def commit(envelope) -> None:
        try:
            barrier.wait(timeout=2.0)
            results.append(trust.commit(envelope))
        except Exception as exc:  # noqa: BLE001 - asserted below
            errors.append(exc)

    workers = [threading.Thread(target=commit, args=(item,)) for item in verified]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=5.0)

    assert all(not worker.is_alive() for worker in workers)
    assert errors == []
    assert sorted(results) == [False, True]


def test_newer_registry_commit_blocks_an_already_verified_older_version(
    tmp_path: Path,
) -> None:
    publisher = AgentIdentity.generate(label="publisher")
    old_trust = CuratedRegistryTrust(tmp_path)
    new_trust = CuratedRegistryTrust(tmp_path)
    old = old_trust.verify(
        _signed_envelope(publisher, version=10),
        expected_publisher_did=publisher.as_did(),
    )
    new = new_trust.verify(
        _signed_envelope(publisher, version=11),
        expected_publisher_did=publisher.as_did(),
    )

    new_trust.commit(new)

    with pytest.raises(ValueError, match="concurrently superseded"):
        old_trust.commit(old)


def test_checked_in_signed_registry_envelope_conformance_vector(
    tmp_path: Path,
) -> None:
    vector_path = (
        Path(__file__).parents[1]
        / "nth_dao"
        / "plugins"
        / "vectors"
        / "curated-registry-envelope-v2.json"
    )
    vector = json.loads(vector_path.read_text(encoding="utf-8"))
    assert vector["format"] == "nth-dao-curated-registry-conformance-v1"
    assert vector["schema_version"] == 1

    verified = CuratedRegistryTrust(tmp_path).verify(
        vector["document"],
        expected_publisher_did=vector["expected_publisher_did"],
        now_ms_override=vector["verify_at_ms"],
    )

    assert verified.publisher_did == vector["expected_publisher_did"]
    assert verified.version == 7
    assert verified.peers[0]["peer_url"] == "https://peer.example"


def test_registry_rejects_tamper_wrong_publisher_and_expiry(tmp_path: Path) -> None:
    publisher = AgentIdentity.generate(label="publisher")
    attacker = AgentIdentity.generate(label="attacker")
    trust = CuratedRegistryTrust(tmp_path)
    tampered = _signed_envelope(publisher)
    tampered["peers"][0]["peer_url"] = "https://attacker.example"

    with pytest.raises(ValueError, match="signature verification failed"):
        trust.verify(
            tampered,
            expected_publisher_did=publisher.as_did(),
        )
    with pytest.raises(ValueError, match="local pin"):
        trust.verify(
            _signed_envelope(publisher),
            expected_publisher_did=attacker.as_did(),
        )
    now = datetime.now(timezone.utc)
    with pytest.raises(ValueError, match="expired"):
        trust.verify(
            _signed_envelope(
                publisher,
                issued_at=now - timedelta(hours=2),
                expires_at=now - timedelta(hours=1),
            ),
            expected_publisher_did=publisher.as_did(),
        )


def test_registry_rejects_future_and_overlong_validity_windows(tmp_path: Path) -> None:
    publisher = AgentIdentity.generate(label="publisher")
    trust = CuratedRegistryTrust(tmp_path)
    now = datetime.now(timezone.utc)

    with pytest.raises(ValueError, match="not active yet"):
        trust.verify(
            _signed_envelope(
                publisher,
                issued_at=now + timedelta(minutes=5),
                expires_at=now + timedelta(hours=1),
            ),
            expected_publisher_did=publisher.as_did(),
        )
    with pytest.raises(ValueError, match="validity window"):
        trust.verify(
            _signed_envelope(
                publisher,
                issued_at=now,
                expires_at=now + timedelta(days=2),
            ),
            expected_publisher_did=publisher.as_did(),
        )
