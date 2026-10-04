"""A source DAO checks claimant completion against its own CAS record."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("nacl")

from nth_dao.cap_token import (
    CAP_NTH_RECEIPT_SIGN,
    encode_authorization_header,
    sign_cap_token,
)
from nth_dao.execution_receipt import TimelineEntry, sign_receipt
from nth_dao.identity import AgentIdentity
from nth_dao.market.announcement import (
    NTH_ANNOUNCEMENT_KIND_V1,
    announcement_federation_key,
    sign_announcement,
)
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
from nth_dao.market.source_completion_inbox import (
    RECEIVED_EVENT,
    SourceCompletionConflict,
    SourceCompletionCorrupt,
    SourceCompletionInbox,
    SourceCompletionPending,
)
from nth_dao.market.source_identity import record_source_identity_rotation
from nth_dao.market.trade_offer_announcement import create_trade_offer_announcement
from nth_dao.spine.log import SignedEventLog
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


def _competing_root(proof: dict, claimant: AgentIdentity, *, offset: int = 4) -> dict:
    original = proof["completion_chain"][0]["completion_record"]
    completed_at = original["completed_at_ms"] + offset
    execution = sign_receipt(
        [TimelineEntry(
            timestamp=completed_at - 1, type="nth.task_failed",
            payload={"mission_id": "mission-1"},
        )], claimant, goal_id="mission:mission-1",
    )
    failed = sign_mission_completion(
        claimant, announcement_id=original["announcement_id"],
        mission_id="mission-1", claim_receipt=proof["claim_receipt"],
        authority_ack=proof["authority_ack"], execution_receipt=execution,
        outcome="failed", completed_at_ms=completed_at,
    )
    return {
        **proof, "completion_chain": [{
            "version": 1, "nonce": proof["nonce"],
            "completion_record": failed, "execution_receipt": execution,
        }],
    }


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


def test_source_rotation_rejects_duplicate_json_fields_before_export(
    tmp_path: Path,
) -> None:
    from nth_dao.market.source_identity import export_source_identity_rotation_chain

    source, old, _claimant, _announcement, proof = _source_and_proof(tmp_path)
    current = AgentIdentity.generate(label="current")
    record_source_identity_rotation(source, old, current)
    path = source / "market_feed" / "source_identity_rotations.jsonl"
    line = path.read_bytes().removesuffix(b"\n")
    path.write_bytes(b'{"previous_did":"forged",' + line[1:] + b"\n")
    with pytest.raises(ValueError, match="corrupt source identity history"):
        verify_source_claim_completion(source, proof, source_did=current.as_did())
    with pytest.raises(ValueError, match="corrupt source identity history"):
        export_source_identity_rotation_chain(source, old.as_did(), current.as_did())


def test_source_rotation_export_tolerates_identical_edge_retries(
    tmp_path: Path,
) -> None:
    from nth_dao.market.source_identity import export_source_identity_rotation_chain

    source, old, _claimant, _announcement, proof = _source_and_proof(tmp_path)
    current = AgentIdentity.generate(label="current")
    first = record_source_identity_rotation(source, old, current)
    record_source_identity_rotation(source, old, current)
    assert export_source_identity_rotation_chain(
        source, old.as_did(), current.as_did(),
    ) == [first]
    recorded = SourceCompletionInbox(
        source, source_did=current.as_did(),
        spine=SignedEventLog(source / "spine.jsonl", current),
    ).record(proof)
    assert recorded["source_rotation_chain"] == [first]


def test_source_receipt_survives_unrelated_malformed_rotation_row(
    tmp_path: Path,
) -> None:
    source, old, _claimant, _announcement, proof = _source_and_proof(tmp_path)
    current = AgentIdentity.generate(label="current")
    rotation = record_source_identity_rotation(source, old, current)
    inbox = SourceCompletionInbox(
        source, source_did=current.as_did(),
        spine=SignedEventLog(source / "spine.jsonl", current),
    )
    recorded = inbox.record(proof)
    path = source / "market_feed" / "source_identity_rotations.jsonl"
    with path.open("ab") as stream:
        stream.write(b"{invalid unrelated row}\n")
    assert verify_source_claim_completion(
        source, proof, source_did=current.as_did(),
    ) == (True, "ok")
    recovered = inbox.get(proof["source_claim_id"], recorded["completion_head_digest"][7:])
    assert recovered["audit_event_id"] == recorded["audit_event_id"]
    assert recovered["source_rotation_chain"] == [rotation]


def test_source_rotation_multihop_and_fork_fail_closed(tmp_path: Path) -> None:
    from nth_dao.market.source_identity import export_source_identity_rotation_chain

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
    with pytest.raises(ValueError, match="ambiguous"):
        export_source_identity_rotation_chain(
            source, original.as_did(), current.as_did(),
        )


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
    from nth_dao.market import source_identity

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


@pytest.mark.parametrize("route", [
    "/api/v2/market/completion-proofs/verify-source",
    "/api/v2/market/completion-proofs/record-source",
])
def test_source_proof_preparse_concurrency_is_bounded(route: str) -> None:
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
            "path": route,
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


def test_source_proof_get_has_one_slot_and_shares_post_budget() -> None:
    from nth_dao.web import _FederationBodyLimitMiddleware

    async def exercise() -> None:
        entered = 0
        first_entered = asyncio.Event()
        second_entered = asyncio.Event()
        release = asyncio.Event()

        async def downstream(_scope, _receive, _send) -> None:
            nonlocal entered
            entered += 1
            first_entered.set()
            if entered == 2:
                second_entered.set()
            await release.wait()

        middleware = _FederationBodyLimitMiddleware(downstream)
        base = {
            "type": "http",
            "app": SimpleNamespace(state=SimpleNamespace(nth_require_console_auth=False)),
            "client": ("127.0.0.1", 50000), "headers": [],
        }
        get_scope = {
            **base, "method": "GET",
            "path": "/api/v2/market/completion-proofs/source/"
            + "a" * 64 + "/" + "b" * 64,
        }
        post_scope = {
            **base, "method": "POST",
            "path": "/api/v2/market/completion-proofs/record-source",
        }
        async def receive() -> dict:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(_message: dict) -> None:
            return None

        async def status(scope: dict) -> int:
            messages: list[dict] = []
            async def capture(message: dict) -> None:
                messages.append(message)

            await middleware(scope, receive, capture)
            return messages[0]["status"]

        first = asyncio.create_task(middleware(get_scope, receive, send))
        second = None
        try:
            await asyncio.wait_for(first_entered.wait(), timeout=2)
            assert await asyncio.wait_for(status(get_scope), timeout=1) == 429
            second = asyncio.create_task(middleware(post_scope, receive, send))
            await asyncio.wait_for(second_entered.wait(), timeout=2)
            assert await asyncio.wait_for(status(post_scope), timeout=1) == 429
            assert entered == 2
        finally:
            release.set()
            await first
            if second is not None:
                await second

    asyncio.run(exercise())


@pytest.mark.parametrize("route", [
    "/api/v2/market/completion-proofs/verify-source",
    "/api/v2/market/completion-proofs/record-source",
])
def test_source_proof_streamed_body_without_length_is_bounded(route: str) -> None:
    from nth_dao.web import (
        _CLAIM_SOURCE_PROOF_MAX_BODY_BYTES,
        _FederationBodyLimitMiddleware,
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
            "path": route,
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


def test_source_inbox_records_one_signed_receipt_without_accepting_work(
    tmp_path: Path,
) -> None:
    source, authority, claimant, _announcement, proof = _source_and_proof(tmp_path)
    spine = SignedEventLog(source / "spine.jsonl", authority)
    inbox = SourceCompletionInbox(source, source_did=authority.as_did(), spine=spine)
    first = inbox.record(proof)
    second = inbox.record(proof)
    assert first["recorded"] is True and first["already_recorded"] is False
    assert second["audit_event_id"] == first["audit_event_id"]
    assert second["already_recorded"] is True
    assert first["claimant_did"] == claimant.as_did()
    assert first["source_claim_id"] == proof["source_claim_id"]
    assert first["nonce_authenticated"] is False
    assert first["accepted"] is False and first["settled"] is False
    assert spine.head_seq == 0
    event = spine.get_verified_event(first["audit_event_id"])
    assert event is not None and event.type == RECEIVED_EVENT
    assert event.author_did == authority.as_did()
    assert first["source_receipt_event"] == event.to_dict()
    assert inbox.get(
        proof["source_claim_id"], first["completion_head_digest"][7:],
    ) == {**first, "already_recorded": True}


def test_source_receipt_offline_verifier_binds_pins_proof_and_audit(
    tmp_path: Path,
) -> None:
    from nth_dao.market.source_completion_receipt import (
        verify_source_completion_receipt,
    )
    from nth_dao.spine.event import sign_event

    source, authority, claimant, announcement, proof = _source_and_proof(tmp_path)
    recorded = SourceCompletionInbox(
        source, source_did=authority.as_did(),
        spine=SignedEventLog(source / "spine.jsonl", authority),
    ).record(proof)
    event = recorded["source_receipt_event"]
    pins = {
        "expected_source_did": authority.as_did(),
        "expected_federation_key": announcement_federation_key(announcement),
    }
    assert verify_source_completion_receipt(proof, event, **pins) == (True, "ok")
    assert not verify_source_completion_receipt(proof, event, **{
        **pins, "expected_source_did": claimant.as_did(),
    })[0]
    assert not verify_source_completion_receipt(proof, event, **{
        **pins, "expected_federation_key": "untrusted",
    })[0]
    assert not verify_source_completion_receipt(proof, {}, **pins)[0]
    assert not verify_source_completion_receipt(proof, {
        **event, "payload": {**event["payload"], "accepted": True},
    }, **pins)[0]
    signed_wrong_meaning = sign_event(
        seq=event["seq"], prev_hash=event["prev_hash"],
        event_type=RECEIVED_EVENT,
        payload={**event["payload"], "accepted": True},
        identity=authority, ts_ms=event["ts_ms"],
    ).to_dict()
    assert not verify_source_completion_receipt(
        proof, signed_wrong_meaning, **pins,
    )[0]
    signed_wrong_type = sign_event(
        seq=event["seq"], prev_hash=event["prev_hash"],
        event_type=RECEIVED_EVENT,
        payload={**event["payload"], "accepted": 0},
        identity=authority, ts_ms=event["ts_ms"],
    ).to_dict()
    assert not verify_source_completion_receipt(
        proof, signed_wrong_type, **pins,
    )[0]
    signed_wrong_author = sign_event(
        seq=event["seq"], prev_hash=event["prev_hash"],
        event_type=RECEIVED_EVENT, payload=event["payload"],
        identity=AgentIdentity.generate(label="untrusted"), ts_ms=event["ts_ms"],
    ).to_dict()
    assert not verify_source_completion_receipt(
        proof, signed_wrong_author, **pins,
    )[0]
    assert not verify_source_completion_receipt(
        _competing_root(proof, claimant), event, **pins,
    )[0]


def test_source_receipt_offline_verifies_dual_signed_source_rotation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    from nth_dao.canonical_json import canonical_json
    from nth_dao.cli.claim_completion import main
    from nth_dao.market.source_completion_receipt import (
        verify_source_completion_receipt,
    )

    source, old, _claimant, announcement, proof = _source_and_proof(tmp_path)
    middle = AgentIdentity.generate(label="middle-source")
    current = AgentIdentity.generate(label="current-source")
    first = record_source_identity_rotation(source, old, middle)
    second = record_source_identity_rotation(source, middle, current)
    recorded = SourceCompletionInbox(
        source, source_did=current.as_did(),
        spine=SignedEventLog(source / "spine.jsonl", current),
    ).record(proof)
    event = recorded["source_receipt_event"]
    pins = {
        "expected_source_did": old.as_did(),
        "expected_federation_key": announcement_federation_key(announcement),
    }
    assert not verify_source_completion_receipt(proof, event, **pins)[0]
    assert recorded["source_rotation_chain"] == [first, second]
    chain = recorded["source_rotation_chain"]
    assert verify_source_completion_receipt(
        proof, event, rotation_chain=chain, **pins,
    ) == (True, "ok")
    for invalid in (
        [second], [first], list(reversed(chain)),
        [{**first, "successor_sig": "0" * 128}, second],
        [first, second, first],
    ):
        assert not verify_source_completion_receipt(
            proof, event, rotation_chain=invalid, **pins,
        )[0]
    assert not verify_source_completion_receipt(
        proof, event, rotation_chain=chain,
        expected_source_did=middle.as_did(),
        expected_federation_key=pins["expected_federation_key"],
    )[0]
    proof_file = tmp_path / "rotated-proof.json"
    response_file = tmp_path / "rotated-source-response.json"
    proof_file.write_bytes(canonical_json(proof))
    response_file.write_bytes(canonical_json(recorded))
    command = [
        "verify-receipt", "--proof-file", str(proof_file),
        "--receipt-event-file", str(response_file),
        "--source-did", old.as_did(),
        "--federation-key", pins["expected_federation_key"],
    ]
    assert main(command) == 0
    assert json.loads(capsys.readouterr().out)["receipt_verified"] is True
    response_file.write_bytes(canonical_json({
        **recorded, "source_rotation_chain": [{
            **first, "previous_sig": "0" * 128,
        }, second],
    }))
    assert main(command) == 1
    assert json.loads(capsys.readouterr().out)["receipt_verified"] is False


def test_source_receipt_cli_verifies_statement_binding_without_audit_inclusion(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    from nth_dao.canonical_json import canonical_json
    from nth_dao.cli.claim_completion import main

    source, authority, _claimant, announcement, proof = _source_and_proof(tmp_path)
    recorded = SourceCompletionInbox(
        source, source_did=authority.as_did(),
        spine=SignedEventLog(source / "spine.jsonl", authority),
    ).record(proof)
    proof_file = tmp_path / "completion-proof.json"
    event_file = tmp_path / "source-receipt-event.json"
    proof_file.write_bytes(canonical_json(proof))
    event = recorded["source_receipt_event"]
    event_file.write_bytes(canonical_json(event))
    command = [
        "verify-receipt", "--proof-file", str(proof_file),
        "--receipt-event-file", str(event_file),
        "--source-did", authority.as_did(),
        "--federation-key", announcement_federation_key(announcement),
    ]
    assert main(command) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["receipt_verified"] is True
    assert result["audit_inclusion_verified"] is False
    assert result["verification_scope"] == "source_statement_and_proof_binding"
    assert "source_statement_signature_verified" not in result
    assert result["accepted"] is False and result["settled"] is False
    event_file.write_bytes(b'{"seq":0,' + canonical_json(event)[1:])
    assert main(command) == 1
    assert "repeats a field" in capsys.readouterr().err
    event_file.write_bytes(canonical_json({
        **event, "payload": {**event["payload"], "accepted": True},
    }))
    assert main(command) == 1
    assert json.loads(capsys.readouterr().out)["receipt_verified"] is False


def test_source_receipt_offline_signature_does_not_claim_spine_inclusion(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    from nth_dao.canonical_json import canonical_json
    from nth_dao.cli.claim_completion import main
    from nth_dao.market.source_completion_receipt import _payload_for_verified_proof
    from nth_dao.spine.event import GENESIS_PREV, sign_event

    source, authority, _claimant, announcement, proof = _source_and_proof(tmp_path)
    event = sign_event(
        seq=0, prev_hash=GENESIS_PREV, event_type=RECEIVED_EVENT,
        payload=_payload_for_verified_proof(proof, canonical_json(proof)),
        identity=authority, ts_ms=int(time.time() * 1000),
    )
    assert not (source / "spine.jsonl").exists()
    proof_file = tmp_path / "proof.json"
    event_file = tmp_path / "unrecorded-event.json"
    proof_file.write_bytes(canonical_json(proof))
    event_file.write_bytes(canonical_json(event.to_dict()))
    assert main([
        "verify-receipt", "--proof-file", str(proof_file),
        "--receipt-event-file", str(event_file),
        "--source-did", authority.as_did(),
        "--federation-key", announcement_federation_key(announcement),
    ]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["receipt_verified"] is True
    assert result["audit_inclusion_verified"] is False
    assert result["source_retention_verified"] is False


def test_source_receipt_event_matches_packaged_conformance_vector(
    tmp_path: Path,
) -> None:
    vector_path = (
        Path(__file__).parents[1] / "nth_dao" / "market" / "vectors"
        / "source-completion-received-v1.json"
    )
    vector = json.loads(vector_path.read_text(encoding="utf-8"))
    source, authority, _claimant, _announcement, proof = _source_and_proof(tmp_path)
    spine = SignedEventLog(source / "spine.jsonl", authority)
    result = SourceCompletionInbox(
        source, source_did=authority.as_did(), spine=spine,
    ).record(proof)
    event = spine.get_verified_event(result["audit_event_id"])
    assert event is not None and event.type == vector["event_type"] == RECEIVED_EVENT
    assert vector["portable_receipt_field"] == "source_receipt_event"
    assert vector["portable_rotation_field"] == "source_rotation_chain"
    assert result[vector["portable_rotation_field"]] == []
    assert set(result[vector["portable_receipt_field"]]) == set(
        vector["portable_receipt_event_fields"]
    )
    assert result["source_receipt_event"] == event.to_dict()
    assert set(event.payload) == set(vector["payload"])
    assert event.payload[vector["semantic_key_field"]] == (
        event.payload["source_claim_id"] + ":" + event.payload["completion_head_digest"]
    )
    for field in ("nonce_authenticated", "accepted", "settled"):
        assert event.payload[field] is vector["payload"][field] is False
    sample = vector["payload"]
    assert sample["completion_key"] == (
        sample["source_claim_id"] + ":" + sample["completion_head_digest"]
    )


def test_source_receipt_fixed_signature_and_rotation_vector() -> None:
    from nth_dao.canonical_json import canonical_json
    from nth_dao.market.source_identity import verify_portable_source_rotation_chain
    from nth_dao.spine.event import SpineEvent, verify_event

    vector_path = (
        Path(__file__).parents[1] / "nth_dao" / "market" / "vectors"
        / "source-completion-receipt-crypto-v1.json"
    )
    vector = json.loads(vector_path.read_text(encoding="utf-8"))
    event = SpineEvent.from_dict(vector["event"])
    assert canonical_json(event.core()).decode("utf-8") == vector["event_core_canonical_json"]
    assert verify_event(event) == (True, "ok")
    chain = vector["rotation_chain"]
    body = {key: value for key, value in chain[0].items() if not key.endswith("_sig")}
    assert canonical_json(body).decode("utf-8") == vector["rotation_body_canonical_json"]
    assert verify_portable_source_rotation_chain(
        chain, vector["pinned_source_did"], event.author_did,
    )
    assert not verify_portable_source_rotation_chain(
        [], vector["pinned_source_did"], event.author_did,
    )
    assert not verify_portable_source_rotation_chain(
        [{**chain[0], "previous_sig": "0" * 128}],
        vector["pinned_source_did"], event.author_did,
    )
    tampered = SpineEvent.from_dict({
        **vector["event"], "payload": {**event.payload, "accepted": True},
    })
    assert not verify_event(tampered)[0]


def test_source_inbox_rejects_signed_audit_payload_type_confusion(
    tmp_path: Path,
) -> None:
    source, authority, _claimant, _announcement, proof = _source_and_proof(tmp_path)
    spine = SignedEventLog(source / "spine.jsonl", authority)
    inbox = SourceCompletionInbox(source, source_did=authority.as_did(), spine=spine)
    _raw, payload = inbox._verified_payload(proof)
    spine.append_unique(
        RECEIVED_EVENT, {**payload, "accepted": 0},
        unique_payload_fields=("completion_key",),
    )
    with pytest.raises(SourceCompletionConflict, match="different proof"):
        inbox.record(proof)
    assert not list(inbox.root.rglob("*.json"))


def test_source_inbox_rejects_nonce_rewrapped_signed_completion(
    tmp_path: Path,
) -> None:
    source, authority, claimant, announcement, proof = _source_and_proof(tmp_path)
    spine = SignedEventLog(source / "spine.jsonl", authority)
    inbox = SourceCompletionInbox(source, source_did=authority.as_did(), spine=spine)
    first = inbox.record(proof)
    replacement_intent = sign_claim_intent(
        claimant, announcement_id=announcement.announcement_id,
        cap_token=proof["claim_receipt"]["authorizing_cap_token"],
    )
    rebound = {
        **proof, "nonce": replacement_intent["nonce"],
        "intent": replacement_intent,
        "completion_chain": [
            {**envelope, "nonce": replacement_intent["nonce"]}
            for envelope in proof["completion_chain"]
        ],
    }
    assert verify_source_claim_completion(
        source, rebound, source_did=authority.as_did(),
    ) == (True, "ok")
    with pytest.raises(SourceCompletionConflict, match="same signed completion"):
        inbox.record(rebound)
    assert spine.head_seq == 0
    assert len(list(inbox.root.rglob("*.json"))) == 1
    assert inbox.get(proof["source_claim_id"], first["completion_head_digest"][7:])[
        "lineage_state"
    ] == "single_retained_head"


def test_source_inbox_marks_legacy_nonce_aliases_as_duplicate_signed_head(
    tmp_path: Path,
) -> None:
    source, authority, claimant, announcement, proof = _source_and_proof(tmp_path)
    spine = SignedEventLog(source / "spine.jsonl", authority)
    inbox = SourceCompletionInbox(source, source_did=authority.as_did(), spine=spine)
    first = inbox.record(proof)
    replacement_intent = sign_claim_intent(
        claimant, announcement_id=announcement.announcement_id,
        cap_token=proof["claim_receipt"]["authorizing_cap_token"],
    )
    rebound = {
        **proof, "nonce": replacement_intent["nonce"],
        "intent": replacement_intent,
        "completion_chain": [
            {**envelope, "nonce": replacement_intent["nonce"]}
            for envelope in proof["completion_chain"]
        ],
    }
    raw, payload = inbox._verified_payload(rebound)
    slot = inbox._slot(proof["source_claim_id"])
    inbox._write_immutable(slot / (payload["completion_head_digest"][7:] + ".json"), raw)
    spine.append_unique(
        RECEIVED_EVENT, payload, unique_payload_fields=("completion_key",),
    )
    legacy = inbox.get(proof["source_claim_id"], first["completion_head_digest"][7:])
    assert legacy["lineage_state"] == "duplicate_signed_head"
    assert legacy["single_retained_head_digest"] is None
    assert len(legacy["lineage_heads"]) == 2
    assert spine.head_seq == 1
    competing = inbox.record(_competing_root(proof, claimant))
    assert competing["lineage_state"] == "unresolved_fork"
    assert competing["has_duplicate_signed_head"] is True
    assert len(competing["lineage_heads"]) == 3


def test_source_inbox_allows_audited_retry_with_legacy_pending_alias(
    tmp_path: Path,
) -> None:
    source, authority, claimant, announcement, proof = _source_and_proof(tmp_path)
    spine = SignedEventLog(source / "spine.jsonl", authority)
    inbox = SourceCompletionInbox(source, source_did=authority.as_did(), spine=spine)
    first = inbox.record(proof)
    replacement_intent = sign_claim_intent(
        claimant, announcement_id=announcement.announcement_id,
        cap_token=proof["claim_receipt"]["authorizing_cap_token"],
    )
    rebound = {
        **proof, "nonce": replacement_intent["nonce"],
        "intent": replacement_intent,
        "completion_chain": [
            {**envelope, "nonce": replacement_intent["nonce"]}
            for envelope in proof["completion_chain"]
        ],
    }
    raw, payload = inbox._verified_payload(rebound)
    slot = inbox._slot(proof["source_claim_id"])
    inbox._write_immutable(slot / (payload["completion_head_digest"][7:] + ".json"), raw)
    retry = inbox.record(proof)
    assert retry["audit_event_id"] == first["audit_event_id"]
    assert retry["already_recorded"] is True
    assert retry["lineage_state"] == "pending_audit"
    reconciled = inbox.reconcile_pending(
        proof["source_claim_id"], payload["completion_head_digest"][7:],
        expected_proof_digest=payload["proof_digest"],
    )
    assert reconciled["lineage_state"] == "duplicate_signed_head"
    assert reconciled["single_retained_head_digest"] is None
    assert spine.head_seq == 1


def test_source_inbox_retry_repairs_blob_after_failed_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, authority, _claimant, _announcement, proof = _source_and_proof(tmp_path)
    spine = SignedEventLog(source / "spine.jsonl", authority)
    inbox = SourceCompletionInbox(source, source_did=authority.as_did(), spine=spine)
    original = spine.append_unique

    def fail_once(*_args, **_kwargs):
        raise OSError("audit temporarily unavailable")

    monkeypatch.setattr(spine, "append_unique", fail_once)
    with pytest.raises(OSError, match="audit temporarily unavailable"):
        inbox.record(proof)
    assert len(list((source / "federation" / "inbox").rglob("*.json"))) == 1
    head_hex = receipt_digest(proof["completion_chain"][-1])[7:]
    with pytest.raises(SourceCompletionPending, match="pending audit"):
        inbox.get(proof["source_claim_id"], head_hex)
    monkeypatch.setattr(spine, "append_unique", original)
    assert inbox.record(proof)["recorded"] is True
    assert spine.head_seq == 0


def test_source_inbox_pending_audit_is_visible_and_requires_explicit_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, authority, claimant, _announcement, proof = _source_and_proof(tmp_path)
    spine = SignedEventLog(source / "spine.jsonl", authority)
    inbox = SourceCompletionInbox(source, source_did=authority.as_did(), spine=spine)
    first = inbox.record(proof)
    competing = _competing_root(proof, claimant)
    pending_hex = receipt_digest(competing["completion_chain"][-1])[7:]
    original_append = spine.append_unique
    monkeypatch.setattr(
        spine, "append_unique",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("audit failed")),
    )
    with pytest.raises(OSError, match="audit failed"):
        inbox.record(competing)
    monkeypatch.setattr(spine, "append_unique", original_append)
    pending_path = (
        source / "federation" / "inbox" / proof["source_claim_id"]
        / f"{pending_hex}.json"
    )
    pending_digest = "sha256:" + hashlib.sha256(pending_path.read_bytes()).hexdigest()
    first_read = inbox.get(proof["source_claim_id"], first["completion_head_digest"][7:])
    assert first_read["lineage_state"] == "pending_audit"
    assert first_read["single_retained_head_digest"] is None
    assert first_read["pending_head_digests"] == [f"sha256:{pending_hex}"]
    with pytest.raises(SourceCompletionPending):
        inbox.get(proof["source_claim_id"], pending_hex)
    with pytest.raises(SourceCompletionPending):
        inbox.record(_competing_root(proof, claimant, offset=8))
    assert spine.head_seq == 0
    with pytest.raises(SourceCompletionConflict):
        inbox.reconcile_pending(
            proof["source_claim_id"], pending_hex,
            expected_proof_digest="sha256:" + "0" * 64,
        )
    repaired = inbox.reconcile_pending(
        proof["source_claim_id"], pending_hex,
        expected_proof_digest=pending_digest,
    )
    assert repaired["lineage_state"] == "unresolved_fork"
    assert repaired["recorded"] is True
    assert spine.head_seq == 1


def test_source_inbox_retry_reconciles_committed_audit_after_lost_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, authority, _claimant, _announcement, proof = _source_and_proof(tmp_path)
    spine = SignedEventLog(source / "spine.jsonl", authority)
    inbox = SourceCompletionInbox(source, source_did=authority.as_did(), spine=spine)
    original = spine.append_unique

    def append_then_fail(*args, **kwargs):
        original(*args, **kwargs)
        raise OSError("response lost after append")

    monkeypatch.setattr(spine, "append_unique", append_then_fail)
    with pytest.raises(OSError, match="response lost"):
        inbox.record(proof)
    monkeypatch.setattr(spine, "append_unique", original)
    result = inbox.record(proof)
    assert result["already_recorded"] is True
    assert spine.head_seq == 0


def test_source_inbox_reconcile_retry_after_lost_audit_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, authority, _claimant, _announcement, proof = _source_and_proof(tmp_path)
    spine = SignedEventLog(source / "spine.jsonl", authority)
    inbox = SourceCompletionInbox(source, source_did=authority.as_did(), spine=spine)
    original_append = spine.append_unique
    monkeypatch.setattr(
        spine, "append_unique",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("audit failed")),
    )
    with pytest.raises(OSError, match="audit failed"):
        inbox.record(proof)
    head_hex = receipt_digest(proof["completion_chain"][-1])[7:]
    path = inbox.root / proof["source_claim_id"] / f"{head_hex}.json"
    expected = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

    def append_then_fail(*args, **kwargs):
        original_append(*args, **kwargs)
        raise OSError("response lost after append")

    monkeypatch.setattr(spine, "append_unique", append_then_fail)
    with pytest.raises(OSError, match="response lost"):
        inbox.reconcile_pending(
            proof["source_claim_id"], head_hex, expected_proof_digest=expected,
        )
    monkeypatch.setattr(spine, "append_unique", original_append)
    result = inbox.reconcile_pending(
        proof["source_claim_id"], head_hex, expected_proof_digest=expected,
    )
    assert result["already_recorded"] is True
    assert result["lineage_state"] == "single_retained_head"
    assert spine.head_seq == 0


def test_source_inbox_publish_never_overwrites_existing_proof(tmp_path: Path) -> None:
    source, authority, _claimant, _announcement, proof = _source_and_proof(tmp_path)
    inbox = SourceCompletionInbox(
        source, source_did=authority.as_did(),
        spine=SignedEventLog(source / "spine.jsonl", authority),
    )
    result = inbox.record(proof)
    path = inbox.root / proof["source_claim_id"] / (
        result["completion_head_digest"][7:] + ".json"
    )
    original = path.read_bytes()
    with pytest.raises((FileExistsError, ValueError)):
        inbox._write_immutable(path, b"different")
    assert path.read_bytes() == original
    assert inbox.get(proof["source_claim_id"], path.stem) is not None


def test_source_inbox_publish_failure_is_not_audited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.market.source_completion_inbox as source_inbox_module

    source, authority, _claimant, _announcement, proof = _source_and_proof(tmp_path)
    spine = SignedEventLog(source / "spine.jsonl", authority)
    inbox = SourceCompletionInbox(source, source_did=authority.as_did(), spine=spine)
    publish = source_inbox_module._publish_immutable

    def fail_publish(*_args):
        raise OSError("durable rename failed")

    monkeypatch.setattr(source_inbox_module, "_publish_immutable", fail_publish)
    with pytest.raises(OSError, match="durable rename failed"):
        inbox.record(proof)
    assert not list(inbox.root.rglob("*.json"))
    assert spine.head_seq == -1
    monkeypatch.setattr(source_inbox_module, "_publish_immutable", publish)
    assert inbox.record(proof)["recorded"] is True


def test_source_inbox_directory_sync_order_stays_within_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.market.source_completion_inbox as source_inbox_module

    visited: list[Path] = []
    monkeypatch.setattr(
        source_inbox_module, "_fsync_directory", lambda path: visited.append(path),
    )
    slot = tmp_path / "federation" / "inbox" / ("a" * 64)
    source_inbox_module._sync_directory_chain(slot, tmp_path)
    assert visited == [slot, slot.parent, slot.parent.parent, tmp_path]


def test_source_inbox_directory_sync_failure_is_not_audited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.market.source_completion_inbox as source_inbox_module

    source, authority, _claimant, _announcement, proof = _source_and_proof(tmp_path)
    spine = SignedEventLog(source / "spine.jsonl", authority)
    inbox = SourceCompletionInbox(source, source_did=authority.as_did(), spine=spine)
    original = source_inbox_module._sync_directory_chain

    def fail_sync(_slot: Path, _workspace: Path) -> None:
        raise OSError("directory sync failed")

    monkeypatch.setattr(source_inbox_module, "_requires_directory_fsync", lambda: True)
    monkeypatch.setattr(source_inbox_module, "_sync_directory_chain", fail_sync)
    with pytest.raises(OSError, match="directory sync failed"):
        inbox.record(proof)
    assert spine.head_seq == -1
    assert not list(inbox.root.rglob("*.json"))
    monkeypatch.setattr(source_inbox_module, "_sync_directory_chain", original)
    monkeypatch.setattr(
        source_inbox_module, "_requires_directory_fsync", lambda: os.name != "nt",
    )
    assert inbox.record(proof)["recorded"] is True


def test_source_inbox_rejects_tampered_blob_and_stale_signer(tmp_path: Path) -> None:
    source, authority, _claimant, _announcement, proof = _source_and_proof(tmp_path)
    stranger = AgentIdentity.generate(label="stranger")
    with pytest.raises(SourceCompletionCorrupt, match="signer"):
        SourceCompletionInbox(
            source, source_did=authority.as_did(),
            spine=SignedEventLog(source / "wrong-spine.jsonl", stranger),
        )
    spine = SignedEventLog(source / "spine.jsonl", authority)
    inbox = SourceCompletionInbox(source, source_did=authority.as_did(), spine=spine)
    recorded = inbox.record(proof)
    path = (
        source / "federation" / "inbox"
        / proof["source_claim_id"] / (recorded["completion_head_digest"][7:] + ".json")
    )
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(SourceCompletionCorrupt):
        inbox.get(proof["source_claim_id"], recorded["completion_head_digest"][7:])
    with pytest.raises(SourceCompletionCorrupt):
        inbox.record(proof)


def test_source_inbox_cannot_report_missing_audited_blob(tmp_path: Path) -> None:
    source, authority, _claimant, _announcement, proof = _source_and_proof(tmp_path)
    inbox = SourceCompletionInbox(
        source, source_did=authority.as_did(),
        spine=SignedEventLog(source / "spine.jsonl", authority),
    )
    result = inbox.record(proof)
    head_hex = result["completion_head_digest"][7:]
    path = source / "federation" / "inbox" / proof["source_claim_id"] / f"{head_hex}.json"
    path.unlink()
    with pytest.raises(SourceCompletionCorrupt, match="missing"):
        inbox.get(proof["source_claim_id"], head_hex)
    assert inbox.record(proof)["already_recorded"] is True
    assert inbox.get(proof["source_claim_id"], head_hex) is not None


def test_source_inbox_unknown_lookup_does_not_create_per_id_lock(tmp_path: Path) -> None:
    source, authority, _claimant, _announcement, _proof = _source_and_proof(tmp_path)
    inbox = SourceCompletionInbox(
        source, source_did=authority.as_did(),
        spine=SignedEventLog(source / "spine.jsonl", authority),
    )
    unknown_id = "a" * 64
    assert inbox.get(unknown_id, "b" * 64) is None
    assert not (
        source / ".nth" / "locks" / "received_claim_completions"
        / f"{unknown_id}.lock"
    ).exists()


@pytest.mark.skipif(os.name != "nt", reason="Win32 extended-path regression")
def test_source_inbox_retains_full_hashes_beyond_max_path(tmp_path: Path) -> None:
    padding = max(1, 155 - len(str(tmp_path / "source")))
    long_root = tmp_path / ("x" * padding)
    source, authority, _claimant, _announcement, proof = _source_and_proof(tmp_path)
    long_root.mkdir()
    relocated = long_root / "source"
    source.rename(relocated)
    source = relocated
    inbox = SourceCompletionInbox(
        source, source_did=authority.as_did(),
        spine=SignedEventLog(source / "spine.jsonl", authority),
    )
    result = inbox.record(proof)
    assert len(str(inbox.root / proof["source_claim_id"] / (
        result["completion_head_digest"][7:] + ".json"
    ))) > 260
    assert inbox.get(
        proof["source_claim_id"], result["completion_head_digest"][7:],
    )["audit_event_id"] == result["audit_event_id"]


def test_source_inbox_concurrent_idempotent_import(tmp_path: Path) -> None:
    source, authority, _claimant, _announcement, proof = _source_and_proof(tmp_path)
    spine = SignedEventLog(source / "spine.jsonl", authority)
    inbox = SourceCompletionInbox(source, source_did=authority.as_did(), spine=spine)
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(inbox.record, [proof] * 5))
    assert len({item["audit_event_id"] for item in results}) == 1
    assert sum(not item["already_recorded"] for item in results) == 1
    assert spine.head_seq == 0


def test_source_inbox_old_signed_audit_survives_dual_signed_rotation(
    tmp_path: Path,
) -> None:
    source, old, _claimant, _announcement, proof = _source_and_proof(tmp_path)
    path = source / "spine.jsonl"
    first = SourceCompletionInbox(
        source, source_did=old.as_did(), spine=SignedEventLog(path, old),
    ).record(proof)
    current = AgentIdentity.generate(label="successor")
    record_source_identity_rotation(source, old, current)
    rotated = SourceCompletionInbox(
        source, source_did=current.as_did(), spine=SignedEventLog(path, current),
    )
    head_hex = first["completion_head_digest"][7:]
    assert rotated.get(proof["source_claim_id"], head_hex)["audit_event_id"] == first[
        "audit_event_id"
    ]
    assert rotated.record(proof)["already_recorded"] is True


def test_source_inbox_read_fails_closed_if_local_claim_changes(tmp_path: Path) -> None:
    source, authority, _claimant, _announcement, proof = _source_and_proof(tmp_path)
    inbox = SourceCompletionInbox(
        source, source_did=authority.as_did(),
        spine=SignedEventLog(source / "spine.jsonl", authority),
    )
    recorded = inbox.record(proof)
    claim_file = next((source / "market_claims").glob("sha256-*.json"))
    claim_file.write_text("{}", encoding="utf-8")
    with pytest.raises((SourceCompletionCorrupt, ValueError)):
        inbox.get(proof["source_claim_id"], recorded["completion_head_digest"][7:])


def test_source_inbox_v1_announcement_uses_effective_authority(tmp_path: Path) -> None:
    authority = AgentIdentity.generate(label="legacy-source")
    announcement = sign_announcement(
        publisher=authority, title="legacy work", kind=NTH_ANNOUNCEMENT_KIND_V1,
    )
    announcement.authority_did = ""
    source, _authority, _claimant, _ann, proof = _source_and_proof(
        tmp_path, authority=authority, announcement=announcement,
    )
    inbox = SourceCompletionInbox(
        source, source_did=authority.as_did(),
        spine=SignedEventLog(source / "spine.jsonl", authority),
    )
    assert inbox.record(proof)["source_did"] == authority.as_did()


def test_source_inbox_separate_signed_heads_share_one_source_claim(
    tmp_path: Path,
) -> None:
    source, authority, claimant, _announcement, proof = _source_and_proof(tmp_path)
    inbox_spine = SignedEventLog(source / "spine.jsonl", authority)
    inbox = SourceCompletionInbox(
        source, source_did=authority.as_did(), spine=inbox_spine,
    )
    first = inbox.record(proof)
    first_record = proof["completion_chain"][-1]["completion_record"]
    completed_at = first_record["completed_at_ms"] + 3
    execution = sign_receipt(
        [TimelineEntry(
            timestamp=completed_at - 1, type="nth.task_completed",
            payload={"mission_id": "mission-1"},
        )], claimant, goal_id="mission:mission-1",
    )
    revision = sign_mission_completion(
        claimant, announcement_id=first_record["announcement_id"],
        mission_id="mission-1", claim_receipt=proof["claim_receipt"],
        authority_ack=proof["authority_ack"], execution_receipt=execution,
        outcome="succeeded", completed_at_ms=completed_at, revision=1,
        supersedes_digest=first["completion_head_digest"],
    )
    advanced = {
        **proof,
        "completion_chain": [*proof["completion_chain"], {
            "version": 1, "nonce": proof["nonce"],
            "completion_record": revision, "execution_receipt": execution,
        }],
    }
    second = inbox.record(advanced)
    assert second["source_claim_id"] == first["source_claim_id"]
    assert second["completion_head_digest"] != first["completion_head_digest"]
    assert second["lineage_state"] == "single_retained_head"
    assert second["single_retained_head_digest"] == second["completion_head_digest"]
    assert inbox_spine.head_seq == 1
    assert inbox.get(
        proof["source_claim_id"], first["completion_head_digest"][7:],
    ) is not None


def test_source_inbox_marks_conflicting_signed_roots_as_unresolved(
    tmp_path: Path,
) -> None:
    source, authority, claimant, _announcement, proof = _source_and_proof(tmp_path)
    inbox = SourceCompletionInbox(
        source, source_did=authority.as_did(),
        spine=SignedEventLog(source / "spine.jsonl", authority),
    )
    first = inbox.record(proof)
    competing = _competing_root(proof, claimant)
    second = inbox.record(competing)
    assert second["lineage_state"] == "unresolved_fork"
    assert second["single_retained_head_digest"] is None
    assert set(second["lineage_heads"]) == {
        first["completion_head_digest"], second["completion_head_digest"],
    }
    previous = inbox.get(
        proof["source_claim_id"], first["completion_head_digest"][7:],
    )
    assert previous["lineage_state"] == "unresolved_fork"
    assert previous["single_retained_head_digest"] is None
    missing = (
        source / "federation" / "inbox" / proof["source_claim_id"]
        / (second["completion_head_digest"][7:] + ".json")
    )
    missing.unlink()
    with pytest.raises(SourceCompletionCorrupt, match="audited source proof is missing"):
        inbox.get(proof["source_claim_id"], first["completion_head_digest"][7:])


def test_source_inbox_rest_is_operator_only_and_failure_is_explicit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from nth_dao.web import create_app

    source = tmp_path / "source"
    app = create_app(source, require_console_auth=False)
    _source, authority, _claimant, _announcement, proof = _source_and_proof(
        tmp_path, authority=app.state.nth.node_identity,
    )
    client = TestClient(app)
    route = "/api/v2/market/completion-proofs/record-source"
    tampered = client.post(route, json={"proof": {**proof, "source_claim_id": "0" * 64}})
    assert tampered.status_code == 422
    assert not (source / "federation" / "inbox").exists()

    saved_spine = app.state.nth.spine
    app.state.nth.spine = None
    assert client.post(route, json={"proof": proof}).status_code == 503
    app.state.nth.spine = saved_spine
    recorded = client.post(route, json={"proof": proof})
    assert recorded.status_code == 200, recorded.text
    body = recorded.json()
    assert body["source_did"] == authority.as_did()
    assert body["recorded"] is True and body["accepted"] is False
    lookup = (
        "/api/v2/market/completion-proofs/source/"
        + proof["source_claim_id"] + "/" + body["completion_head_digest"][7:]
    )
    assert client.get(lookup).json()["audit_event_id"] == body["audit_event_id"]
    assert client.get(lookup).json()["source_receipt_event"] == body[
        "source_receipt_event"
    ]
    assert client.post(route, json={"proof": proof}).json()["already_recorded"] is True

    locked = create_app(source, require_console_auth=True)
    locked_client = TestClient(locked)
    assert locked_client.post(route, content=b"{").status_code in (401, 403)
    assert locked_client.get(lookup).status_code in (401, 403)
    authorized = locked_client.post(
        route, json={"proof": proof},
        headers={"Authorization": f"Bearer {locked.state.nth_console_token}"},
    )
    assert authorized.status_code == 200, authorized.text
    assert locked_client.post(
        route, content=b"{}", headers={
            "Content-Length": str(22 * 1024 * 1024),
            "Authorization": f"Bearer {locked.state.nth_console_token}",
        },
    ).status_code == 413


def test_source_receipt_cli_consumes_real_source_rest_response(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from nth_dao.canonical_json import canonical_json
    from nth_dao.cli.claim_completion import main
    from nth_dao.web import create_app

    source = tmp_path / "source"
    app = create_app(source, require_console_auth=False)
    _source, authority, _claimant, announcement, proof = _source_and_proof(
        tmp_path, authority=app.state.nth.node_identity,
    )
    client = TestClient(app)
    recorded = client.post(
        "/api/v2/market/completion-proofs/record-source", json={"proof": proof},
    )
    assert recorded.status_code == 200, recorded.text
    lookup = (
        "/api/v2/market/completion-proofs/source/"
        + proof["source_claim_id"] + "/"
        + recorded.json()["completion_head_digest"][7:]
    )
    response = client.get(lookup)
    assert response.status_code == 200, response.text
    proof_file = tmp_path / "proof.json"
    receipt_file = tmp_path / "source-response.json"
    proof_file.write_bytes(canonical_json(proof))
    receipt_file.write_bytes(canonical_json(response.json()))
    command = [
        "verify-receipt", "--proof-file", str(proof_file),
        "--receipt-event-file", str(receipt_file),
        "--source-did", authority.as_did(),
        "--federation-key", announcement_federation_key(announcement),
    ]
    assert main(command) == 0
    assert json.loads(capsys.readouterr().out)["receipt_verified"] is True
    receipt_file.write_bytes(canonical_json({
        **response.json(), "audit_event_id": "0" * 64,
    }))
    assert main(command) == 1
    capsys.readouterr()
    receipt_file.write_bytes(canonical_json({
        **response.json(), "outcome": "failed",
    }))
    assert main(command) == 1
    capsys.readouterr()
    receipt_file.write_bytes(canonical_json({
        **response.json(), "accepted": 0,
    }))
    assert main(command) == 1
    capsys.readouterr()
    receipt_file.write_bytes(canonical_json({
        **response.json(), "source_receipt_event": {
            **response.json()["source_receipt_event"], "sig": "bad",
        },
    }))
    assert main(command) == 1
    assert json.loads(capsys.readouterr().out)["receipt_verified"] is False


def test_source_inbox_missing_local_announcement_is_unavailable(tmp_path: Path) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from nth_dao.web import create_app

    source = tmp_path / "source"
    app = create_app(source, require_console_auth=False)
    _source, authority, _claimant, _announcement, proof = _source_and_proof(
        tmp_path, authority=app.state.nth.node_identity,
    )
    (source / "market_feed" / "announcements.jsonl").unlink()
    assert verify_source_claim_completion(
        source, proof, source_did=authority.as_did(),
    ) == (False, "source announcement is not retained locally")
    response = TestClient(app).post(
        "/api/v2/market/completion-proofs/record-source", json={"proof": proof},
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "source evidence unavailable"
    assert not (source / "federation" / "inbox").exists()


def test_source_inbox_reconcile_rest_is_explicit_and_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from nth_dao.web import create_app

    source = tmp_path / "source"
    app = create_app(source, require_console_auth=False)
    _source, _authority, claimant, _announcement, proof = _source_and_proof(
        tmp_path, authority=app.state.nth.node_identity,
    )
    client = TestClient(app)
    record_route = "/api/v2/market/completion-proofs/record-source"
    first = client.post(record_route, json={"proof": proof})
    assert first.status_code == 200
    competing = _competing_root(proof, claimant)
    spine = app.state.nth.spine
    original_append = spine.append_unique
    monkeypatch.setattr(
        spine, "append_unique",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("audit failed")),
    )
    assert client.post(record_route, json={"proof": competing}).status_code == 503
    monkeypatch.setattr(spine, "append_unique", original_append)
    pending_hex = receipt_digest(competing["completion_chain"][-1])[7:]
    route = (
        "/api/v2/market/completion-proofs/source/"
        + proof["source_claim_id"] + "/" + pending_hex
    )
    pending_path = (
        source / "federation" / "inbox" / proof["source_claim_id"]
        / f"{pending_hex}.json"
    )
    digest = "sha256:" + hashlib.sha256(pending_path.read_bytes()).hexdigest()
    assert client.get(route).status_code == 409
    assert client.get(
        route.replace(pending_hex, first.json()["completion_head_digest"][7:]),
    ).json()["lineage_state"] == "pending_audit"
    assert client.post(route + "/reconcile", params={
        "expected_proof_digest": digest,
    }, content=b"x").status_code == 413
    assert client.post(route + "/reconcile", params={
        "expected_proof_digest": "sha256:" + "0" * 64,
    }).status_code == 409
    repaired = client.post(route + "/reconcile", params={
        "expected_proof_digest": digest,
    })
    assert repaired.status_code == 200, repaired.text
    assert repaired.json()["lineage_state"] == "unresolved_fork"
    locked = TestClient(create_app(source, require_console_auth=True))
    assert locked.post(route + "/reconcile", params={
        "expected_proof_digest": digest,
    }).status_code in (401, 403)
