"""XDAO-2:跨 DAO 认领·来源 DAO 侧 HTTP 端点 /market/{id}/claim-foreign。

源端点是关键安全面 —— 外部节点匿名提交预签认领。用 TestClient 直接签收据
(模拟外部 agent)打这个端点:记录成功 / auth ON 也匿名放行 / 伪造拒 / 冲突。
(agent 的 claim-sign a2a 方法 e2e 留到 XDAO-3 编排就位一起测。)
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("nacl")

from fastapi.testclient import TestClient

from nth_dao.cap_token import CAP_NTH_RECEIPT_SIGN, sign_cap_token
from nth_dao.identity import AgentIdentity
from nth_dao.market import MarketFeed, sign_announcement
from nth_dao.market.announcement import TaskAnnouncement, announcement_federation_key
from nth_dao.market.claim import sign_claim_receipt
from nth_dao.market.claim_ack import verify_authority_claim_ack
from nth_dao.market.claim_intent import sign_claim_intent, verify_claim_intent
from nth_dao.web import _FederationBodyLimitMiddleware, create_app
from nth_dao.web.dummy_agent import _sign_foreign_claim_artifacts


def _sign_foreign(ann_dict, caps=("code_review",)):
    """模拟外部 agent:自签 cap_token + ClaimReceipt + ClaimIntent。"""
    agent = AgentIdentity.generate(label="foreign-agent")
    ann = TaskAnnouncement.from_dict(ann_dict)
    cap = sign_cap_token(
        issuer=agent, subject_did=agent.as_did(),
        capabilities=[*caps, CAP_NTH_RECEIPT_SIGN],
    )
    return (
        agent,
        cap,
        sign_claim_receipt(ann, agent, cap),
        sign_claim_intent(
            agent,
            announcement_id=ann.announcement_id,
            cap_token=cap,
        ),
    )


def test_agent_signs_cross_bound_claim_artifacts() -> None:
    publisher = AgentIdentity.generate(label="publisher")
    claimant = AgentIdentity.generate(label="claimant")
    announcement = sign_announcement(
        publisher=publisher,
        authority_did=publisher.as_did(),
        title="signed claim artifacts",
        capability_set=["code_review"],
    )

    artifacts = _sign_foreign_claim_artifacts(announcement.to_dict(), claimant)

    assert set(artifacts) == {"cap_token", "receipt", "intent"}
    intent = artifacts["intent"]
    assert verify_claim_intent(intent) == (True, "ok")
    assert intent["announcement_id"] == announcement.announcement_id
    assert intent["claimant_did"] == claimant.as_did()
    assert intent["cap_token_id"] == artifacts["cap_token"]["token_id"]
    assert artifacts["receipt"]["signer_did"] == claimant.as_did()
    assert "private_key" not in str(artifacts).lower()


def test_claim_foreign_records(tmp_path: Path) -> None:
    c = TestClient(create_app(tmp_path, require_console_auth=False))
    ann = c.post(
        "/api/v2/market/announce",
        json={"title": "t", "capability_set": ["code_review"], "reward_minor": 5},
    ).json()
    aid = ann["announcement_id"]
    agent, cap, receipt, intent = _sign_foreign(ann)

    r = c.post(
        f"/api/v2/market/{aid}/claim-foreign",
        json={"cap_token": cap, "receipt": receipt, "intent": intent},
    )
    assert r.status_code == 200, r.text
    assert r.json()["claimed"] is True
    assert r.json()["claimant_did"] == agent.as_did()
    assert r.json()["foreign"] is True
    authority_ack = r.json()["authority_ack"]
    assert r.json()["authority_ack_id"] == authority_ack["ack_id"]
    assert verify_authority_claim_ack(
        authority_ack,
        expected_authority_did=c.app.state.nth.node_identity.as_did(),
        expected_claimant_did=agent.as_did(),
        expected_claim_receipt=receipt,
    ) == (True, "ok")
    # 已认领 → 不再出现在开放广场。
    open_ids = {x["announcement_id"] for x in c.get("/api/v2/market/open").json()}
    assert aid not in open_ids


def test_claim_foreign_anonymous_when_auth_on(tmp_path: Path) -> None:
    # 关键:auth ON 时,claim-foreign 仍**匿名放行**(外部节点没本地 token)。
    app = create_app(tmp_path, require_console_auth=True)
    c = TestClient(app)
    # 直接经 feed 发布(绕过 HTTP 写鉴权),造一条公告。
    pub = AgentIdentity.generate(label="pub")
    ann = sign_announcement(
        publisher=pub,
        authority_did=app.state.nth.node_identity.as_did(),
        title="t",
        capability_set=["code_review"],
        reward_minor=5,
    )
    MarketFeed(tmp_path).publish(ann)
    _, cap, receipt, intent = _sign_foreign(ann.to_dict())
    # 不带任何 Authorization → 仍应 200(中间件对本路径豁免)。
    r = c.post(
        f"/api/v2/market/{ann.announcement_id}/claim-foreign",
        json={"cap_token": cap, "receipt": receipt, "intent": intent},
    )
    assert r.status_code == 200, r.text


def test_claim_status_is_crypto_authorized_when_console_auth_is_on(
    tmp_path: Path,
) -> None:
    app = create_app(tmp_path, require_console_auth=True)
    client = TestClient(app)
    publisher = AgentIdentity.generate(label="publisher")
    announcement = sign_announcement(
        publisher=publisher,
        authority_did=app.state.nth.node_identity.as_did(),
        title="recover a lost authority acknowledgement",
        capability_set=["code_review"],
    )
    MarketFeed(tmp_path).publish(announcement)
    _agent, cap_token, receipt, intent = _sign_foreign(
        announcement.to_dict(),
    )
    claim = client.post(
        f"/api/v2/market/{announcement.announcement_id}/claim-foreign",
        json={
            "cap_token": cap_token,
            "receipt": receipt,
            "intent": intent,
        },
    )
    assert claim.status_code == 200, claim.text

    federation_key = announcement_federation_key(announcement)
    recovered = client.post(
        "/api/v2/market/federation/claim-status",
        json={"intent": intent, "federation_key": federation_key},
    )
    assert recovered.status_code == 200, recovered.text
    assert recovered.json()["claimant_matches"] is True
    assert recovered.json()["authority_ack_id"] == claim.json()["authority_ack_id"]

    tampered = dict(intent)
    tampered["nonce"] = "A" * 24
    rejected = client.post(
        "/api/v2/market/federation/claim-status",
        json={"intent": tampered, "federation_key": federation_key},
    )
    assert rejected.status_code == 403, rejected.text
    assert "intent-signature-invalid" in rejected.text


def test_claim_foreign_rejects_valid_but_undelegated_mirror_feed(
    tmp_path: Path,
) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    publisher = AgentIdentity.generate(label="external-publisher")
    announcement = sign_announcement(
        publisher=publisher,
        title="not delegated to this node",
        capability_set=["code_review"],
    )
    MarketFeed(tmp_path).publish(announcement)
    _, cap_token, receipt, intent = _sign_foreign(announcement.to_dict())

    response = client.post(
        f"/api/v2/market/{announcement.announcement_id}/claim-foreign",
        json={"cap_token": cap_token, "receipt": receipt, "intent": intent},
    )

    assert response.status_code == 409
    assert "not the signed authority" in response.text


def test_claim_foreign_rejects_forged(tmp_path: Path) -> None:
    c = TestClient(create_app(tmp_path, require_console_auth=False))
    ann = c.post(
        "/api/v2/market/announce",
        json={"title": "t", "capability_set": ["code_review"]},
    ).json()
    _, cap, receipt, intent = _sign_foreign(ann)
    receipt["timeline"][0]["payload"]["reward_minor"] = 999_999  # 篡改签名体
    r = c.post(
        f"/api/v2/market/{ann['announcement_id']}/claim-foreign",
        json={"cap_token": cap, "receipt": receipt, "intent": intent},
    )
    assert r.status_code == 403, r.text


def test_claim_foreign_requires_intent(tmp_path: Path) -> None:
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    announcement = client.post(
        "/api/v2/market/announce",
        json={"title": "requires intent", "capability_set": ["code_review"]},
    ).json()
    _, cap_token, receipt, _intent = _sign_foreign(announcement)

    response = client.post(
        f"/api/v2/market/{announcement['announcement_id']}/claim-foreign",
        json={"cap_token": cap_token, "receipt": receipt},
    )

    assert response.status_code == 422


def test_claim_foreign_rejects_tampered_intent(tmp_path: Path) -> None:
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    announcement = client.post(
        "/api/v2/market/announce",
        json={"title": "tampered intent", "capability_set": ["code_review"]},
    ).json()
    _, cap_token, receipt, intent = _sign_foreign(announcement)
    intent["nonce"] = "A" * 24

    response = client.post(
        f"/api/v2/market/{announcement['announcement_id']}/claim-foreign",
        json={"cap_token": cap_token, "receipt": receipt, "intent": intent},
    )

    assert response.status_code == 403
    assert "intent-signature-invalid" in response.text


def test_claim_foreign_rejects_intent_cap_token_swap(tmp_path: Path) -> None:
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    announcement = client.post(
        "/api/v2/market/announce",
        json={"title": "token swap", "capability_set": ["code_review"]},
    ).json()
    claimant, first_token, receipt, intent = _sign_foreign(announcement)
    replacement = sign_cap_token(
        issuer=claimant,
        subject_did=claimant.as_did(),
        capabilities=["code_review", CAP_NTH_RECEIPT_SIGN],
    )
    assert replacement["token_id"] != first_token["token_id"]

    response = client.post(
        f"/api/v2/market/{announcement['announcement_id']}/claim-foreign",
        json={"cap_token": replacement, "receipt": receipt, "intent": intent},
    )

    assert response.status_code == 403
    assert "intent-binding-mismatch" in response.text


def test_claim_foreign_rejects_expired_intent(tmp_path: Path) -> None:
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    announcement = client.post(
        "/api/v2/market/announce",
        json={"title": "expired intent", "capability_set": ["code_review"]},
    ).json()
    claimant = AgentIdentity.generate(label="expired-claimant")
    parsed = TaskAnnouncement.from_dict(announcement)
    cap_token = sign_cap_token(
        issuer=claimant,
        subject_did=claimant.as_did(),
        capabilities=["code_review", CAP_NTH_RECEIPT_SIGN],
    )
    receipt = sign_claim_receipt(parsed, claimant, cap_token)
    intent = sign_claim_intent(
        claimant,
        announcement_id=parsed.announcement_id,
        cap_token=cap_token,
        created_at_ms=int(time.time() * 1000) - 10_000,
        ttl_ms=1,
    )

    response = client.post(
        f"/api/v2/market/{parsed.announcement_id}/claim-foreign",
        json={"cap_token": cap_token, "receipt": receipt, "intent": intent},
    )

    assert response.status_code == 403
    assert "intent-expired" in response.text


def test_claim_foreign_conflict(tmp_path: Path) -> None:
    c = TestClient(create_app(tmp_path, require_console_auth=False))
    ann = c.post(
        "/api/v2/market/announce",
        json={"title": "t", "capability_set": ["code_review"]},
    ).json()
    aid = ann["announcement_id"]
    _, capA, recA, intentA = _sign_foreign(ann)
    assert c.post(
        f"/api/v2/market/{aid}/claim-foreign",
        json={"cap_token": capA, "receipt": recA, "intent": intentA},
    ).status_code == 200
    _, capB, recB, intentB = _sign_foreign(ann)  # 不同 agent
    r = c.post(
        f"/api/v2/market/{aid}/claim-foreign",
        json={"cap_token": capB, "receipt": recB, "intent": intentB},
    )
    assert r.status_code == 409, r.text


def test_claim_foreign_exact_replay_is_idempotent(tmp_path: Path) -> None:
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    announcement = client.post(
        "/api/v2/market/announce",
        json={"title": "exact replay", "capability_set": ["code_review"]},
    ).json()
    _, cap_token, receipt, intent = _sign_foreign(announcement)
    payload = {"cap_token": cap_token, "receipt": receipt, "intent": intent}
    path = f"/api/v2/market/{announcement['announcement_id']}/claim-foreign"

    first = client.post(path, json=payload)
    replay = client.post(path, json=payload)

    assert first.status_code == replay.status_code == 200
    assert replay.json()["submitted_intent_accepted"] is True
    assert replay.json()["authority_ack"] == first.json()["authority_ack"]


def test_claim_foreign_same_did_returns_original_authority_ack(tmp_path: Path) -> None:
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    announcement_dict = client.post(
        "/api/v2/market/announce",
        json={"title": "reconcile", "capability_set": ["code_review"]},
    ).json()
    announcement = TaskAnnouncement.from_dict(announcement_dict)
    claimant = AgentIdentity.generate(label="reconnecting-claimant")

    def artifacts():
        token = sign_cap_token(
            issuer=claimant,
            subject_did=claimant.as_did(),
            capabilities=["code_review", CAP_NTH_RECEIPT_SIGN],
        )
        claim_receipt = sign_claim_receipt(announcement, claimant, token)
        claim_intent = sign_claim_intent(
            claimant,
            announcement_id=announcement.announcement_id,
            cap_token=token,
        )
        return token, claim_receipt, claim_intent

    first_token, first_receipt, first_intent = artifacts()
    path = f"/api/v2/market/{announcement.announcement_id}/claim-foreign"
    first = client.post(path, json={
        "cap_token": first_token,
        "receipt": first_receipt,
        "intent": first_intent,
    })
    second_token, second_receipt, second_intent = artifacts()
    second = client.post(path, json={
        "cap_token": second_token,
        "receipt": second_receipt,
        "intent": second_intent,
    })

    assert first.status_code == second.status_code == 200
    assert second.json()["already_claimed"] is True
    assert second.json()["submitted_intent_accepted"] is False
    assert second.json()["receipt_id"] == first_receipt["receipt_id"]
    assert verify_authority_claim_ack(
        second.json()["authority_ack"],
        expected_claimant_did=claimant.as_did(),
        expected_claim_receipt=first_receipt,
    ) == (True, "ok")


def test_claim_foreign_rejects_oversized_body_before_json_parsing(
    tmp_path: Path,
) -> None:
    client = TestClient(create_app(tmp_path, require_console_auth=True))
    body = b'{"cap_token":{"padding":"' + (b"x" * (257 * 1024)) + b'"}}'

    response = client.post(
        "/api/v2/market/missing/claim-foreign",
        content=body,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert "256 KiB" in response.text


def test_claim_status_rejects_oversized_body_before_json_parsing(
    tmp_path: Path,
) -> None:
    client = TestClient(create_app(tmp_path, require_console_auth=True))
    body = b'{"intent":{"padding":"' + (b"x" * (257 * 1024)) + b'"}}'

    response = client.post(
        "/api/v2/market/federation/claim-status",
        content=body,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert "256 KiB" in response.text


def test_claim_foreign_chunked_body_is_bounded_without_content_length() -> None:
    async def drain(_scope, receive, send):
        while True:
            message = await receive()
            if not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    chunks = [
        {"type": "http.request", "body": b"x" * (200 * 1024), "more_body": True},
        {"type": "http.request", "body": b"x" * (60 * 1024), "more_body": False},
    ]
    sent: list[dict] = []

    async def receive():
        return chunks.pop(0)

    async def send(message):
        sent.append(message)

    asyncio.run(_FederationBodyLimitMiddleware(drain)(
        {
            "type": "http", "method": "POST",
            "path": "/api/v2/market/missing/claim-foreign", "headers": [],
        },
        receive,
        send,
    ))

    assert sent[0]["status"] == 413


def test_federation_hello_body_is_bounded_before_json_parsing() -> None:
    async def drain(_scope, receive, send):
        while True:
            message = await receive()
            if not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    chunks = [{
        "type": "http.request",
        "body": b"x" * (17 * 1024),
        "more_body": False,
    }]
    sent: list[dict] = []

    async def receive():
        return chunks.pop(0)

    async def send(message):
        sent.append(message)

    asyncio.run(_FederationBodyLimitMiddleware(drain)(
        {
            "type": "http", "method": "POST",
            "path": "/api/v2/market/federation/hello", "headers": [],
        },
        receive,
        send,
    ))

    assert sent[0]["status"] == 413


def test_claim_foreign_has_per_source_and_global_rate_limit(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    app.state.market_fed_foreign_claim_limiter = SimpleNamespace(
        check=lambda _key: SimpleNamespace(
            allowed=False, retry_after_seconds=7.2,
        ),
    )
    app.state.market_fed_foreign_claim_global_limiter = SimpleNamespace(
        check=lambda _key: SimpleNamespace(
            allowed=True, retry_after_seconds=0.0,
        ),
    )

    response = TestClient(app).post(
        "/api/v2/market/missing/claim-foreign",
        json={"cap_token": {}, "receipt": {}, "intent": {}},
    )

    assert response.status_code == 429
    assert response.headers["retry-after"] == "7"


def test_claim_foreign_global_denial_short_circuits_per_source_limiter(
    tmp_path: Path,
) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    app.state.market_fed_foreign_claim_global_limiter = SimpleNamespace(
        check=lambda _key: SimpleNamespace(
            allowed=False, retry_after_seconds=9.0,
        ),
    )
    app.state.market_fed_foreign_claim_limiter = SimpleNamespace(
        check=lambda _key: (_ for _ in ()).throw(
            AssertionError("per-source limiter should not be touched"),
        ),
    )

    response = TestClient(app).post(
        "/api/v2/market/missing/claim-foreign",
        json={"cap_token": {}, "receipt": {}, "intent": {}},
    )

    assert response.status_code == 429
    assert response.headers["retry-after"] == "9"


def test_claim_foreign_rejects_unknown_request_fields(tmp_path: Path) -> None:
    response = TestClient(create_app(tmp_path, require_console_auth=False)).post(
        "/api/v2/market/missing/claim-foreign",
        json={"cap_token": {}, "receipt": {}, "intent": {}, "unexpected": True},
    )

    assert response.status_code == 422


def test_claim_intent_projection_fails_closed_on_corrupt_journal(
    tmp_path: Path,
) -> None:
    journal_dir = tmp_path / "federation" / "claim_intents"
    journal_dir.mkdir(parents=True)
    (journal_dir / "claim-intents.jsonl").write_text(
        "{corrupt}\n",
        encoding="utf-8",
    )
    client = TestClient(create_app(tmp_path, require_console_auth=False))

    response = client.get("/api/v2/market/claim-intents")

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "claim intent state is temporarily unavailable"
    )
    assert "corrupt" not in response.text


def test_claim_intent_projection_pages_older_records_without_losing_ties(
    tmp_path: Path, monkeypatch,
) -> None:
    from nth_dao.market.claim_intent import IntentTracker

    nonces = [f"claimnonce{i:016d}" for i in range(5)]
    records = [
        {
            "state": "pending" if i == 0 else "confirmed",
            "intent": {"created_at_ms": 1_700_000_000_000 + i // 2, "nonce": nonce},
        }
        for i, nonce in enumerate(nonces)
    ]
    records.reverse()
    monkeypatch.setattr(IntentTracker, "records", lambda self, **kwargs: records)
    monkeypatch.setattr(IntentTracker, "receipt_storage_status", lambda self: {
        "files": 0, "used_bytes": 0, "max_files": 10, "max_bytes": 1000,
    })
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    cursor = ""
    seen = []
    while True:
        response = client.get(
            "/api/v2/market/claim-intents",
            params={"limit": 2, "cursor": cursor},
        )
        assert response.status_code == 200
        page = response.json()
        assert page["stats"] == {"pending": 1, "confirmed": 4}
        seen.extend(item["intent"]["nonce"] for item in page["items"])
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert seen == list(reversed(nonces))
    assert client.get(
        "/api/v2/market/claim-intents", params={"cursor": "1:bad"},
    ).status_code == 422


def test_old_pending_claim_is_reachable_after_first_hundred(
    tmp_path: Path, monkeypatch,
) -> None:
    from nth_dao.market.claim_intent import IntentTracker

    records = [
        {
            "state": "pending" if i == 0 else "confirmed",
            "intent": {
                "created_at_ms": 1_700_000_000_000 + i,
                "nonce": f"claimnonce{i:016d}",
            },
        }
        for i in reversed(range(101))
    ]
    monkeypatch.setattr(IntentTracker, "records", lambda self, **kwargs: records)
    monkeypatch.setattr(IntentTracker, "receipt_storage_status", lambda self: {
        "files": 0, "used_bytes": 0, "max_files": 10, "max_bytes": 1000,
    })
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    first = client.get("/api/v2/market/claim-intents").json()
    assert len(first["items"]) == 100
    assert first["next_cursor"]
    second = client.get(
        "/api/v2/market/claim-intents", params={"cursor": first["next_cursor"]},
    ).json()
    assert len(second["items"]) == 1
    assert second["items"][0]["state"] == "pending"
    assert second["next_cursor"] is None
