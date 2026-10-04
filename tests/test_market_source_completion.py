"""A source DAO checks claimant completion against its own CAS record."""

from __future__ import annotations

import time
import asyncio
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("nacl")

from nth_dao.cap_token import (
    CAP_NTH_RECEIPT_SIGN, encode_authorization_header, sign_cap_token,
)
from nth_dao.execution_receipt import TimelineEntry, sign_receipt
from nth_dao.identity import AgentIdentity
from nth_dao.market.announcement import announcement_federation_key, sign_announcement
from nth_dao.market.claim import ClaimStore, record_foreign_claim, sign_claim_receipt
from nth_dao.market.claim_ack import AuthorityClaimAckStore, sign_authority_claim_ack
from nth_dao.market.claim_intent import IntentTracker, sign_claim_intent
from nth_dao.market.completion_flow import (
    build_portable_completion_proof,
    verify_source_claim_completion,
)
from nth_dao.market.completion_store import ClaimCompletionStore
from nth_dao.market.feed import MarketFeed
from nth_dao.market.mission_completion import receipt_digest, sign_mission_completion
from nth_dao.market.source_identity import record_source_identity_rotation
from nth_dao.market.trade_offer_announcement import create_trade_offer_announcement
from nth_dao.trade_rules import OfferStore, offer_body, offer_digest, sign_offer


def _claim(
    workspace: Path, announcement, claimant: AgentIdentity,
) -> tuple[dict, dict, dict, dict]:
    feed = MarketFeed(workspace)
    feed.publish(announcement)
    token = sign_cap_token(
        issuer=claimant, subject_did=claimant.as_did(),
        capabilities=[CAP_NTH_RECEIPT_SIGN],
        scope_task_id=f"market:claim:{announcement.announcement_id}",
    )
    receipt = sign_claim_receipt(announcement, claimant, token)
    outcome = record_foreign_claim(
        feed, ClaimStore(workspace), announcement.announcement_id, token, receipt,
    )
    return token, receipt, outcome.claim_record, outcome.receipt


def _source_and_proof(
    tmp_path: Path, *, authority: AgentIdentity | None = None,
    announcement=None,
):
    source = tmp_path / "source"
    claimant_workspace = tmp_path / "claimant"
    authority = authority or AgentIdentity.generate(label="source")
    claimant = AgentIdentity.generate(label="claimant")
    if announcement is None:
        announcement = sign_announcement(
            publisher=authority, authority_did=authority.as_did(), title="work",
        )
    token, receipt, claim_record, _ = _claim(source, announcement, claimant)
    ack = sign_authority_claim_ack(
        authority=authority, announcement=announcement, claim_record=claim_record,
    )
    intent = sign_claim_intent(
        claimant, announcement_id=announcement.announcement_id, cap_token=token,
    )
    tracker = IntentTracker(claimant_workspace / "federation" / "claim_intents")
    tracker.record_sent(
        intent, receipt=receipt, announcement=announcement, cap_token=token,
        source_peer="https://source.example", source_did=authority.as_did(),
        federation_key=announcement_federation_key(announcement),
    )
    tracker.mark(intent, "confirmed")
    AuthorityClaimAckStore(claimant_workspace).save(ack)
    completed_at = int(time.time() * 1000) + 2
    execution = sign_receipt(
        [TimelineEntry(
            timestamp=completed_at - 1, type="nth.task_completed",
            payload={"mission_id": "mission-1"},
        )],
        claimant, goal_id="mission:mission-1",
    )
    completion = sign_mission_completion(
        claimant, announcement_id=announcement.announcement_id,
        mission_id="mission-1", claim_receipt=receipt, authority_ack=ack,
        execution_receipt=execution, completed_at_ms=completed_at,
    )
    ClaimCompletionStore(claimant_workspace).record(intent["nonce"], completion, execution)
    proof = build_portable_completion_proof(claimant_workspace, intent["nonce"])
    assert proof is not None
    return source, authority, claimant, announcement, proof


def test_source_verifies_proof_against_its_own_claim(tmp_path: Path) -> None:
    source, authority, _claimant, _announcement, proof = _source_and_proof(tmp_path)
    assert verify_source_claim_completion(
        source, proof, source_did=authority.as_did(),
    ) == (True, "ok")


def test_unrelated_corrupt_feed_line_does_not_hide_valid_source_proof(
    tmp_path: Path,
) -> None:
    source, authority, _claimant, _announcement, proof = _source_and_proof(tmp_path)
    feed_path = source / "market_feed" / "announcements.jsonl"
    with feed_path.open("a", encoding="utf-8") as stream:
        stream.write("{unrelated-invalid-json\n")
    assert verify_source_claim_completion(
        source, proof, source_did=authority.as_did(),
    ) == (True, "ok")


def test_historical_source_lookup_reuses_verified_locator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, authority, _claimant, announcement, proof = _source_and_proof(tmp_path)
    key = announcement_federation_key(announcement)
    assert verify_source_claim_completion(
        source, proof, source_did=authority.as_did(),
    ) == (True, "ok")

    def no_full_read(*_args, **_kwargs):
        raise AssertionError("historical lookup must not load the whole feed")

    monkeypatch.setattr(MarketFeed, "_read_all", no_full_read)
    assert MarketFeed(source).get_signed_historical_by_federation_key(key) is not None
    assert verify_source_claim_completion(
        source, proof, source_did=authority.as_did(),
    ) == (True, "ok")


def test_historical_locator_cannot_substitute_another_signed_row(tmp_path: Path) -> None:
    source, authority, _claimant, announcement, proof = _source_and_proof(tmp_path)
    key = announcement_federation_key(announcement)
    feed = MarketFeed(source)
    assert feed.get_signed_historical_by_federation_key(key) is not None
    unrelated = sign_announcement(
        publisher=authority, authority_did=authority.as_did(), title="other",
    )
    feed.publish(unrelated)
    feed_path = source / "market_feed" / "announcements.jsonl"
    lines = feed_path.read_bytes().splitlines(keepends=True)
    locator_path = source / "market_feed" / "historical_index" / f"{key[-64:]}.json"
    locator = json.loads(locator_path.read_text(encoding="utf-8"))
    locator["offset"] = len(lines[0])
    locator["line_sha256"] = hashlib.sha256(lines[1]).hexdigest()
    locator_path.write_text(json.dumps(locator), encoding="utf-8")
    assert verify_source_claim_completion(
        source, proof, source_did=authority.as_did(),
    ) == (True, "ok")


def test_historical_locator_rechecks_original_signed_row(tmp_path: Path) -> None:
    source, authority, _claimant, announcement, proof = _source_and_proof(tmp_path)
    feed = MarketFeed(source)
    assert feed.get_signed_historical_by_federation_key(
        announcement_federation_key(announcement),
    ) is not None
    path = source / "market_feed" / "announcements.jsonl"
    row = json.loads(path.read_text(encoding="utf-8"))
    row["publisher_sig"] = "invalid"
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="source feed corruption"):
        verify_source_claim_completion(source, proof, source_did=authority.as_did())


def test_source_verifies_historical_offer_claim_after_withdrawal(tmp_path: Path) -> None:
    authority = AgentIdentity.generate(label="source")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    published = now - timedelta(minutes=2)
    successor_published = now - timedelta(minutes=1)
    expiry = now + timedelta(days=2)

    def iso(moment: datetime) -> str:
        return moment.strftime("%Y-%m-%dT%H:%M:%SZ")

    offer = sign_offer(
        authority,
        offer_body(
            offer_id="org.nthdao.tests/completion-history",
            revision=1,
            state="active",
            publisher_did=authority.as_did(),
            title="Review for compute",
            summary="Exchange a review for compute.",
            provides=[{
                "leg_id": "review", "resource_type": "service:review",
                "resource_id": "urn:nth:test:review", "quantity": "1",
                "unit": "review", "descriptor_digest": "sha256:" + "a" * 64,
            }],
            requests=[{
                "leg_id": "compute", "resource_type": "service:compute",
                "resource_id": "urn:nth:test:compute", "quantity": "1",
                "unit": "task", "descriptor_digest": "sha256:" + "b" * 64,
            }],
            published_at=iso(published),
            not_after=iso(expiry),
        ),
        created=iso(published + timedelta(seconds=1)),
    )
    OfferStore(tmp_path / "source").publish(offer)
    announcement = create_trade_offer_announcement(authority, offer)
    source, _authority, _claimant, _ann, proof = _source_and_proof(
        tmp_path, authority=authority, announcement=announcement,
    )
    assert verify_source_claim_completion(
        source, proof, source_did=authority.as_did(),
    ) == (True, "ok")

    withdrawn_body = offer.to_dict()
    withdrawn_body.pop("proof")
    withdrawn_body.update({
        "revision": 2,
        "previous_offer_digest": offer_digest(offer),
        "state": "withdrawn",
        "published_at": iso(successor_published),
    })
    withdrawn = sign_offer(
        authority, withdrawn_body,
        created=iso(successor_published + timedelta(seconds=1)),
    )
    OfferStore(source).publish(withdrawn)
    assert MarketFeed(source).get_by_federation_key(
        announcement_federation_key(announcement), include_expired=True,
    ) is None
    assert verify_source_claim_completion(
        source, proof, source_did=authority.as_did(),
    ) == (True, "ok")


def test_source_rejects_unowned_or_missing_local_claim(tmp_path: Path) -> None:
    source, authority, claimant, announcement, proof = _source_and_proof(tmp_path)
    other = AgentIdentity.generate(label="other")
    assert not verify_source_claim_completion(
        source, proof, source_did=other.as_did(),
    )[0]
    empty = tmp_path / "empty"
    assert not verify_source_claim_completion(
        empty, proof, source_did=authority.as_did(),
    )[0]
    unclaimed = tmp_path / "unclaimed"
    MarketFeed(unclaimed).publish(announcement)
    assert not verify_source_claim_completion(
        unclaimed, proof, source_did=authority.as_did(),
    )[0]
    assert not (unclaimed / "market_claims").exists()
    conflicting = tmp_path / "conflicting"
    _claim(conflicting, announcement, other)
    assert not verify_source_claim_completion(
        conflicting, proof, source_did=authority.as_did(),
    )[0]
    same_claimant_new_receipt = tmp_path / "same-claimant-new-receipt"
    _claim(same_claimant_new_receipt, announcement, claimant)
    assert not verify_source_claim_completion(
        same_claimant_new_receipt, proof, source_did=authority.as_did(),
    )[0]
    assert claimant.as_did() != other.as_did()


def test_source_rejects_unpinned_and_tampered_proof(tmp_path: Path) -> None:
    source, authority, _claimant, _announcement, proof = _source_and_proof(tmp_path)
    assert not verify_source_claim_completion(source, proof, source_did="")[0]
    changed = {**proof, "source_claim_id": "0" * 64}
    assert not verify_source_claim_completion(
        source, changed, source_did=authority.as_did(),
    )[0]
    invalid_key = {
        **proof,
        "authority_ack": {**proof["authority_ack"], "federation_key": "not-a-key"},
    }
    assert not verify_source_claim_completion(
        source, invalid_key, source_did=authority.as_did(),
    )[0]


def test_source_proof_survives_dual_signed_identity_rotation(tmp_path: Path) -> None:
    source, old_identity, _claimant, _announcement, proof = _source_and_proof(tmp_path)
    new_identity = AgentIdentity.generate(label="new source")
    assert not verify_source_claim_completion(
        source, proof, source_did=new_identity.as_did(),
    )[0]
    record_source_identity_rotation(source, old_identity, new_identity)
    assert verify_source_claim_completion(
        source, proof, source_did=new_identity.as_did(),
    ) == (True, "ok")


def test_source_rotation_rejects_forged_or_unrelated_lineage(tmp_path: Path) -> None:
    source, old_identity, _claimant, _announcement, proof = _source_and_proof(tmp_path)
    current = AgentIdentity.generate(label="new source")
    unrelated = AgentIdentity.generate(label="unrelated")
    record_source_identity_rotation(source, unrelated, current)
    assert not verify_source_claim_completion(
        source, proof, source_did=current.as_did(),
    )[0]
    record_source_identity_rotation(source, old_identity, current)
    assert verify_source_claim_completion(
        source, proof, source_did=current.as_did(),
    ) == (True, "ok")
    path = source / "market_feed" / "source_identity_rotations.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    rows[-1]["previous_sig"] = "00" * 64
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="corrupt source identity history"):
        verify_source_claim_completion(source, proof, source_did=current.as_did())


def test_source_rotation_multihop_and_fork_fail_closed(tmp_path: Path) -> None:
    source, original, _claimant, _announcement, proof = _source_and_proof(tmp_path)
    middle = AgentIdentity.generate(label="middle")
    current = AgentIdentity.generate(label="current")
    fork = AgentIdentity.generate(label="fork")
    record_source_identity_rotation(source, original, middle)
    record_source_identity_rotation(source, middle, current)
    assert verify_source_claim_completion(
        source, proof, source_did=current.as_did(),
    ) == (True, "ok")
    record_source_identity_rotation(source, original, fork)
    assert not verify_source_claim_completion(
        source, proof, source_did=current.as_did(),
    )[0]


def test_source_rotation_rejects_signed_cycle(tmp_path: Path) -> None:
    source, original, _claimant, _announcement, proof = _source_and_proof(tmp_path)
    current = AgentIdentity.generate(label="current")
    record_source_identity_rotation(source, original, current)
    record_source_identity_rotation(source, current, original)
    assert not verify_source_claim_completion(
        source, proof, source_did=current.as_did(),
    )[0]


def test_source_rotation_refuses_write_that_would_brick_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.market.source_identity as source_identity

    old = AgentIdentity.generate(label="old")
    new = AgentIdentity.generate(label="new")
    monkeypatch.setattr(source_identity, "_MAX_LOG_BYTES", 1)
    with pytest.raises(ValueError, match="capacity"):
        record_source_identity_rotation(tmp_path, old, new)
    path = tmp_path / "market_feed" / "source_identity_rotations.jsonl"
    assert not path.exists() or path.stat().st_size == 0


def test_corrupt_rotation_evidence_is_unavailable_not_claimant_mismatch(
    tmp_path: Path,
) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from nth_dao.web import create_app

    source = tmp_path / "source"
    app = create_app(source, require_console_auth=False)
    old_identity = app.state.nth.node_identity
    _source, _old, _claimant, _announcement, proof = _source_and_proof(
        tmp_path, authority=old_identity,
    )
    current = AgentIdentity.generate(label="current")
    app.state.nth.node_identity = current
    path = source / "market_feed" / "source_identity_rotations.jsonl"
    path.write_text("{corrupt\n", encoding="utf-8")
    response = TestClient(app).post(
        "/api/v2/market/completion-proofs/verify-source", json={"proof": proof},
    )
    assert response.status_code == 503


def test_unreadable_rotation_history_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from nth_dao.web import create_app

    source = tmp_path / "source"
    app = create_app(source, require_console_auth=False)
    old_identity = app.state.nth.node_identity
    _source, _old, _claimant, _announcement, proof = _source_and_proof(
        tmp_path, authority=old_identity,
    )
    current = AgentIdentity.generate(label="current")
    record_source_identity_rotation(source, old_identity, current)
    app.state.nth.node_identity = current
    original_stat = Path.stat

    def fail_rotation_stat(path: Path, *args, **kwargs):
        if path.name == "source_identity_rotations.jsonl":
            raise PermissionError("rotation history denied")
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", fail_rotation_stat)
    response = TestClient(app).post(
        "/api/v2/market/completion-proofs/verify-source", json={"proof": proof},
    )
    assert response.status_code == 503


def test_source_rotation_is_respected_by_operator_rest(tmp_path: Path) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from nth_dao.web import create_app

    source = tmp_path / "source"
    app = create_app(source, require_console_auth=False)
    old_identity = app.state.nth.node_identity
    _source, _old, _claimant, _announcement, proof = _source_and_proof(
        tmp_path, authority=old_identity,
    )
    current = AgentIdentity.generate(label="current")
    route = "/api/v2/market/completion-proofs/verify-source"
    app.state.nth.node_identity = current
    client = TestClient(app)
    assert client.post(route, json={"proof": proof}).json()["verified"] is False
    record_source_identity_rotation(source, old_identity, current)
    response = client.post(route, json={"proof": proof})
    assert response.status_code == 200, response.text
    assert response.json()["verified"] is True


def test_source_proof_rest_is_operator_only_and_never_accepts_work(
    tmp_path: Path,
) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from nth_dao.web import create_app

    source = tmp_path / "source"
    app = create_app(source, require_console_auth=False)
    authority = app.state.nth.node_identity
    _source, _authority, _claimant, _announcement, proof = _source_and_proof(
        tmp_path, authority=authority,
    )
    route = "/api/v2/market/completion-proofs/verify-source"
    client = TestClient(app)
    valid = client.post(route, json={"proof": proof})
    assert valid.status_code == 200, valid.text
    assert valid.json() == {
        "verified": True, "reason": "ok",
        "verification_scope": "source_claim_binding_only",
        "source_claim_id": proof["source_claim_id"],
        "outcome": "succeeded", "mission_id": "mission-1",
        "completion_head_digest": receipt_digest(proof["completion_chain"][-1]),
        "revision": 0,
        "nonce_authenticated": False,
        "recorded": False, "accepted": False, "settled": False,
    }
    assert not (source / "federation" / "received_completions").exists()

    tampered = client.post(
        route, json={"proof": {**proof, "source_claim_id": "0" * 64}},
    )
    assert tampered.status_code == 200
    assert tampered.json()["verified"] is False
    assert "source_claim_id" not in tampered.json()
    assert client.post(route, json={"proof": proof, "extra": True}).status_code == 422
    oversized = client.post(
        route, content=b"{}", headers={"Content-Length": str(22 * 1024 * 1024)},
    )
    assert oversized.status_code == 413

    locked_app = create_app(source, require_console_auth=True)
    locked = TestClient(locked_app)
    assert locked.post(route, json={"proof": proof}).status_code in (401, 403)
    outsider = AgentIdentity.generate(label="outsider")
    outsider_token = sign_cap_token(
        issuer=outsider, subject_did=outsider.as_did(),
        capabilities=[CAP_NTH_RECEIPT_SIGN],
    )
    outsider_headers = {
        "Authorization": f"CapToken {encode_authorization_header(outsider_token)}",
    }
    assert locked.post(route, content=b"{", headers=outsider_headers).status_code == 403
    assert locked.post(
        route, content=b"{}",
        headers={**outsider_headers, "Content-Length": str(22 * 1024 * 1024)},
    ).status_code == 403
    authorized = locked.post(
        route, json={"proof": proof},
        headers={"Authorization": f"Bearer {locked_app.state.nth_console_token}"},
    )
    assert authorized.status_code == 200, authorized.text
    assert authorized.json()["verified"] is True


def test_source_proof_preparse_concurrency_is_bounded() -> None:
    from nth_dao.web import _FederationBodyLimitMiddleware

    async def exercise() -> None:
        entered = 0
        two_entered = asyncio.Event()
        release = asyncio.Event()

        async def downstream(_scope, _receive, _send) -> None:
            nonlocal entered
            entered += 1
            if entered == 2:
                two_entered.set()
            await release.wait()

        middleware = _FederationBodyLimitMiddleware(downstream)
        scope = {
            "type": "http", "method": "POST",
            "path": "/api/v2/market/completion-proofs/verify-source",
            "app": SimpleNamespace(state=SimpleNamespace(nth_require_console_auth=False)),
            "client": ("127.0.0.1", 50000), "headers": [],
        }

        async def receive() -> dict:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(_message: dict) -> None:
            return None

        first = asyncio.create_task(middleware(scope, receive, send))
        second = asyncio.create_task(middleware(scope, receive, send))
        try:
            await asyncio.wait_for(two_entered.wait(), timeout=2)
            response_messages = []

            async def record(message: dict) -> None:
                response_messages.append(message)

            await middleware(scope, receive, record)
            assert entered == 2
            assert response_messages[0]["status"] == 429
        finally:
            release.set()
            await asyncio.gather(first, second)

    asyncio.run(exercise())


def test_source_proof_streamed_body_without_length_is_bounded() -> None:
    from nth_dao.web import (
        _CLAIM_SOURCE_PROOF_MAX_BODY_BYTES, _FederationBodyLimitMiddleware,
    )

    async def exercise() -> None:
        seen_by_app = 0

        async def downstream(_scope, receive, send) -> None:
            nonlocal seen_by_app
            while True:
                message = await receive()
                seen_by_app += len(message.get("body") or b"")
                if not message.get("more_body"):
                    break
            await send({"type": "http.response.start", "status": 200, "headers": []})

        middleware = _FederationBodyLimitMiddleware(downstream)
        scope = {
            "type": "http", "method": "POST",
            "path": "/api/v2/market/completion-proofs/verify-source",
            "app": SimpleNamespace(state=SimpleNamespace(nth_require_console_auth=False)),
            "client": ("127.0.0.1", 50000), "headers": [],
        }
        sent = 0
        responses: list[dict] = []

        async def receive() -> dict:
            nonlocal sent
            sent += 1
            return {
                "type": "http.request", "body": b"x" * (1024 * 1024),
                "more_body": sent * 1024 * 1024 <= _CLAIM_SOURCE_PROOF_MAX_BODY_BYTES,
            }

        async def send(message: dict) -> None:
            responses.append(message)

        await middleware(scope, receive, send)
        assert responses[0]["status"] == 413
        assert seen_by_app <= _CLAIM_SOURCE_PROOF_MAX_BODY_BYTES
        assert sent * 1024 * 1024 > _CLAIM_SOURCE_PROOF_MAX_BODY_BYTES

    asyncio.run(exercise())


@pytest.mark.parametrize("unreadable_part", ["market_feed", "market_claims"])
def test_source_proof_reports_local_storage_failure_as_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unreadable_part: str,
) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from nth_dao.web import create_app

    source = tmp_path / "source"
    app = create_app(source, require_console_auth=False)
    authority = app.state.nth.node_identity
    _source, _authority, _claimant, _announcement, proof = _source_and_proof(
        tmp_path, authority=authority,
    )
    original_read_text = Path.read_text
    original_open = Path.open

    def fail_selected_read(path: Path, *args, **kwargs) -> str:
        if path.parent.name == "market_claims" and unreadable_part == "market_claims":
            raise PermissionError(f"test-denied: {unreadable_part}")
        return original_read_text(path, *args, **kwargs)

    def fail_selected_open(path: Path, *args, **kwargs):
        if path.name == "announcements.jsonl" and unreadable_part == "market_feed":
            raise PermissionError(f"test-denied: {unreadable_part}")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", fail_selected_read)
    monkeypatch.setattr(Path, "open", fail_selected_open)
    response = TestClient(app).post(
        "/api/v2/market/completion-proofs/verify-source", json={"proof": proof},
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "source completion verification unavailable"


@pytest.mark.parametrize("corrupt_part", ["market_feed", "market_claims"])
def test_source_proof_reports_corrupt_local_evidence_as_unavailable(
    tmp_path: Path, corrupt_part: str,
) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from nth_dao.web import create_app

    source = tmp_path / "source"
    app = create_app(source, require_console_auth=False)
    authority = app.state.nth.node_identity
    _source, _authority, _claimant, _announcement, proof = _source_and_proof(
        tmp_path, authority=authority,
    )
    if corrupt_part == "market_feed":
        target = source / "market_feed" / "announcements.jsonl"
    else:
        target = next((source / "market_claims").glob("sha256-*.json"))
    target.write_text("{invalid-json", encoding="utf-8")
    response = TestClient(app).post(
        "/api/v2/market/completion-proofs/verify-source", json={"proof": proof},
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "source completion verification unavailable"
