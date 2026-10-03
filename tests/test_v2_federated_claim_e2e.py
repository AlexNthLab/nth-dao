"""XDAO-3 capstone:跨 DAO 认领端到端(真双节点)。

源 DAO 起一个**真 uvicorn 服务**(发布任务 + 收 /claim-foreign);编排 DAO 用
TestClient + spawn 真子进程 agent + 注入联邦缓存(来源=源 DAO 真 URL)。一键
打 /market/federated/claim → 本地 agent claim-sign → 转投源 DAO 落 CAS。

这条链把 XDAO-1/2/3 串起来验:agent 自签(真子进程)+ 跨节点 HTTP + 源 DAO 的
CAS 落盘。也补上 agent claim-sign 方法的 e2e。
"""
from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("nacl")
uvicorn = pytest.importorskip("uvicorn")

from fastapi.testclient import TestClient  # noqa: E402

from nth_dao.identity import AgentIdentity, crypto_available  # noqa: E402
from nth_dao.market import ClaimStore  # noqa: E402
from nth_dao.market.announcement import (  # noqa: E402
    TaskAnnouncement,
    announcement_federation_key,
    sign_announcement,
)
from nth_dao.market.claim_ack import sign_authority_claim_ack  # noqa: E402
from nth_dao.web import create_app  # noqa: E402
from nth_dao.web.market_federation_poll import FederationCache  # noqa: E402

pytestmark = pytest.mark.skipif(
    not crypto_available(), reason="PyNaCl needed (signing across nodes)"
)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _BgServer:
    """在后台线程跑一个真 uvicorn(给跨节点 HTTP 提供真 socket)。"""

    def __init__(self, app, port: int) -> None:
        self._server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    def start(self) -> None:
        self._thread.start()
        for _ in range(200):
            if self._server.started:
                return
            time.sleep(0.05)
        raise RuntimeError("source server did not start in time")

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=5)


def test_cross_dao_claim_full_loop(tmp_path: Path) -> None:
    # ── 源 DAO:真服务 + 发布一个任务 ──
    src_ws = tmp_path / "source"
    src_app = create_app(src_ws, require_console_auth=False)
    src_port = _free_port()
    src = _BgServer(src_app, src_port)
    src.start()
    src_url = f"http://127.0.0.1:{src_port}"
    try:
        # 经同一 app 的 TestClient 发布(与运行中的服务共享 workspace/feed)。
        ann = TestClient(src_app).post(
            "/api/v2/market/announce",
            json={"title": "cross-dao", "capability_set": ["code_review"], "reward_minor": 9},
        ).json()
        aid = ann["announcement_id"]

        # ── 编排 DAO:spawn agent + 注入联邦缓存(来源=源 DAO 真 URL)──
        orch_ws = tmp_path / "orch"
        orch_app = create_app(orch_ws, require_console_auth=False)
        orch = TestClient(orch_app)
        sp = orch.post(
            "/api/v2/agents/spawn",
            json={"kind": "mock", "label": "claimer", "capabilities": []},
        ).json()
        did, agent_id = sp["did"], sp["agent_id"]

        cache = FederationCache()
        source_ann = TaskAnnouncement.from_dict(ann)
        other = AgentIdentity.generate(label="other-dao")
        colliding_ann = sign_announcement(
            publisher=other,
            authority_did=other.as_did(),
            title="different DAO, same local id",
            announcement_id=aid,
        )
        cache.replace_all({
            "source": {
                "ann": source_ann,
                "source": src_url,
                "source_did": src_app.state.nth.node_identity.as_did(),
            },
            "other": {
                "ann": colliding_ann,
                "source": "https://other.example",
                "source_did": other.as_did(),
            },
        })
        orch_app.state.market_fed_cache = cache

        try:
            ambiguous = orch.post(
                "/api/v2/market/federated/claim",
                json={"announcement_id": aid, "agent_did": did},
            )
            assert ambiguous.status_code == 409
            assert "ambiguous" in ambiguous.text

            # ── 一键跨 DAO 认领(agent 启动时序 → not-yet-authorized 退避重试)──
            source_key = announcement_federation_key(source_ann)
            r = orch.post(
                "/api/v2/market/federated/claim",
                json={
                    "announcement_id": aid,
                    "federation_key": source_key,
                    "agent_did": did,
                },
            )
            for _ in range(20):
                if "not-yet-authorized" not in r.text:
                    break
                time.sleep(0.5)
                r = orch.post(
                    "/api/v2/market/federated/claim",
                    json={
                        "announcement_id": aid,
                        "federation_key": source_key,
                        "agent_did": did,
                    },
                )
            assert r.status_code == 200, r.text
            assert r.json()["claimed"] is True
            ack_id = r.json()["authority_ack_id"]
            assert r.json()["claim_intent_state"] == "confirmed"
            assert r.json()["claim_intent_nonce"]
            assert (orch_ws / "federation" / "claim_acks" / f"{ack_id}.json").is_file()
            # 认领方 = 编排节点的 agent(它用自己私钥签的)。
            assert r.json()["claimant_did"] == did
            # 关键:**源 DAO** 的 ClaimStore 真落了这条认领(权威在主 DAO)。
            assert ClaimStore(src_ws).is_claimed(aid)
            intent_status = orch.get("/api/v2/market/claim-intents").json()
            assert intent_status["stats"] == {"confirmed": 1}
            assert intent_status["items"][0]["state"] == "confirmed"
            assert intent_status["items"][0]["intent"]["claimant_did"] == did
            source_status = TestClient(src_app).post(
                "/api/v2/market/federation/claim-status",
                json={
                    "intent": intent_status["items"][0]["intent"],
                    "federation_key": source_key,
                },
            )
            assert source_status.status_code == 200, source_status.text
            assert source_status.json()["claimant_matches"] is True
            assert source_status.json()["authority_ack"]["authority_did"] == (
                src_app.state.nth.node_identity.as_did()
            )
            tampered_intent = dict(intent_status["items"][0]["intent"])
            tampered_intent["announcement_id"] = "tampered"
            rejected_status = TestClient(src_app).post(
                "/api/v2/market/federation/claim-status",
                json={"intent": tampered_intent, "federation_key": source_key},
            )
            assert rejected_status.status_code == 403

            lost_race = orch.post(
                "/api/v2/market/federated/claim",
                json={
                    "announcement_id": aid,
                    "federation_key": source_key,
                    "agent_did": did,
                },
            )
            assert lost_race.status_code == 200, lost_race.text
            assert lost_race.json()["already_claimed"] is True
            assert lost_race.json()["submitted_intent_accepted"] is False
            assert lost_race.json()["claim_intent_state"] == "rejected"
            assert lost_race.json()["already_confirmed_intent_nonce"] == r.json()[
                "claim_intent_nonce"
            ]
            assert "reconciled_intent_nonce" not in lost_race.json()
            terminal_status = orch.get("/api/v2/market/claim-intents").json()
            assert terminal_status["stats"] == {"confirmed": 1, "rejected": 1}
        finally:
            orch.post(f"/api/v2/agents/{agent_id}/stop")
    finally:
        src.stop()


def test_https_claim_uses_fresh_identity_and_same_pinned_ip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.web.market_federation_poll as poll
    import nth_dao.web.v2_api as v2_api

    source = AgentIdentity.generate(label="source")
    announcement = sign_announcement(
        publisher=source,
        authority_did=source.as_did(),
        title="pinned claim",
    )
    app = create_app(tmp_path / "orch", require_console_auth=False)
    client = TestClient(app)
    spawned = client.post(
        "/api/v2/agents/spawn",
        json={"kind": "mock", "label": "claimer", "capabilities": []},
    ).json()
    cache = FederationCache()
    cache.replace_all({
        "source": {
            "ann": announcement,
            "source": "https://source.example",
            "source_did": source.as_did(),
        },
    })
    app.state.market_fed_cache = cache
    cache.mark_error("temporary source outage", peer_count=1)
    stale_response = client.post(
        "/api/v2/market/federated/claim",
        json={
            "announcement_id": announcement.announcement_id,
            "federation_key": announcement_federation_key(announcement),
            "agent_did": spawned["did"],
        },
    )
    assert stale_response.status_code == 409
    assert "stale and non-actionable" in stale_response.text
    cache.replace_all({
        "source": {
            "ann": announcement,
            "source": "https://source.example",
            "source_did": source.as_did(),
        },
    })
    fresh_checks: list[tuple[str, str, str]] = []
    identity_attempts: list[str] = []
    pinned_posts: list[tuple[str, str]] = []
    include_ack = {"value": False}
    status_claimant_matches = {"value": True}
    identity_mode = {"value": "normal"}
    withheld_ack: dict[str, object] = {}
    monkeypatch.setattr(
        poll, "_resolve_safe_gossip_ip", lambda _url: "93.184.216.34",
    )

    def fresh_identity(peer_url, *, timeout_seconds, expected_did="", resolved_ip=""):
        fresh_checks.append((peer_url, expected_did, resolved_ip))
        return ({
            "peer_url": peer_url,
            "did": source.as_did(),
            "pubkey_hex": source.pubkey_hex,
        }, "")

    other_source = AgentIdentity.generate(label="wrong-source")

    def pinned_identity_card(url, timeout_seconds, resolved_ip=""):
        identity_attempts.append(resolved_ip)
        assert url == "https://source.example/.well-known/nth-dao/identity.json"
        if resolved_ip == "93.184.216.34" and identity_mode["value"] == "transport":
            raise ConnectionResetError("source address unavailable")
        identity = (
            other_source
            if resolved_ip == "93.184.216.34" and identity_mode["value"] == "mismatch"
            else source
        )
        card = {
            "kind": "nth-dao-identity-card-v1",
            "agent_id": "admin",
            "did": identity.as_did(),
            "pubkey_hex": identity.pubkey_hex,
            "capabilities": ["nth-dao-federation"],
            "issued_at": "2026-07-10T00:00:00+00:00",
            "base_url": "https://source.example",
            "federation": {
                "protocol": "nth-dao-federation-v1",
                "enabled": True,
                "peer_url": "https://source.example",
            },
        }
        card["sig"] = identity.sign_json(card)
        return json.dumps(card).encode("utf-8")

    def pinned_post(url, resolved_ip, payload, **kwargs):
        pinned_posts.append((url, resolved_ip))
        assert payload["federation_key"] == announcement_federation_key(
            announcement,
        )
        if url.endswith("/claim-status"):
            assert payload["intent"]["claimant_did"] == spawned["did"]
            if not status_claimant_matches["value"]:
                return 200, json.dumps({
                    "claimed": True,
                    "claimant_matches": False,
                }).encode("utf-8")
            return 200, json.dumps({
                "claimed": True,
                "claimant_matches": True,
                "authority_ack": withheld_ack["value"],
            }).encode("utf-8")
        assert payload["cap_token"]
        assert payload["receipt"]
        assert payload["intent"]
        assert payload["intent"]["cap_token_id"] == payload["cap_token"]["token_id"]
        assert payload["intent"]["claimant_did"] == payload["receipt"]["signer_did"]
        receipt = payload["receipt"]
        token = payload["cap_token"]
        claim_record = {
            "announcement_id": announcement.announcement_id,
            "status": "claimed",
            "claimant_did": receipt["signer_did"],
            "publisher_did": announcement.publisher_did,
            "cap_token_id": token["token_id"],
            "claimed_at_ms": receipt["timeline"][0]["timestamp"],
            "receipt_id": receipt["receipt_id"],
            "receipt": receipt,
            "foreign": True,
        }
        ack = sign_authority_claim_ack(
            authority=source,
            announcement=announcement,
            claim_record=claim_record,
        )
        if not include_ack["value"]:
            withheld_ack["value"] = ack
            return 200, json.dumps({"claimed": True}).encode("utf-8")
        return 200, json.dumps({
            "claimed": True,
            "claimant_did": receipt["signer_did"],
            "already_claimed": True,
            "submitted_intent_accepted": False,
            "authority_ack": withheld_ack["value"],
        }).encode("utf-8")

    monkeypatch.setattr(v2_api, "_fetch_and_verify_federation_identity", fresh_identity)
    monkeypatch.setattr(v2_api, "_open_federation_identity_card", pinned_identity_card)
    monkeypatch.setattr(
        v2_api,
        "_resolve_operator_trade_peer_ips",
        lambda _url: ("93.184.216.34", "93.184.216.35"),
    )
    monkeypatch.setattr(poll, "_urllib_post_json_pinned_raw", pinned_post)
    key = announcement_federation_key(announcement)
    try:
        response = client.post(
            "/api/v2/market/federated/claim",
            json={
                "announcement_id": announcement.announcement_id,
                "federation_key": key,
                "agent_did": spawned["did"],
            },
        )
        for _ in range(20):
            if "not-yet-authorized" not in response.text:
                break
            time.sleep(0.25)
            response = client.post(
                "/api/v2/market/federated/claim",
                json={
                    "announcement_id": announcement.announcement_id,
                    "federation_key": key,
                    "agent_did": spawned["did"],
                },
            )

        assert response.status_code == 502, response.text
        assert "acknowledgement is invalid" in response.text
        assert response.json()["error"]["code"] == "claim-ack-invalid"
        assert response.json()["claim_intent_state"] == "pending"
        assert response.json()["claim_intent_nonce"]
        pending_status = client.get("/api/v2/market/claim-intents").json()
        assert pending_status["stats"] == {"pending": 1}
        include_ack["value"] = True
        cache.replace_all({})
        identity_mode["value"] = "mismatch"
        identity_rejected = client.post(
            "/api/v2/market/claim-intents/"
            f"{pending_status['items'][0]['intent']['nonce']}/reconcile",
        )
        assert identity_rejected.status_code == 409
        assert identity_attempts == ["93.184.216.34"]
        assert len(pinned_posts) == 1
        identity_mode["value"] = "transport"
        status_claimant_matches["value"] = False
        unverified_negative = client.post(
            "/api/v2/market/claim-intents/"
            f"{pending_status['items'][0]['intent']['nonce']}/reconcile",
        )
        assert unverified_negative.status_code == 200
        assert unverified_negative.json()["claimant_matches"] is False
        assert unverified_negative.json()["state"] == "pending"
        assert client.get("/api/v2/market/claim-intents").json()["stats"] == {
            "pending": 1,
        }
        status_claimant_matches["value"] = True
        response = client.post(
            "/api/v2/market/claim-intents/"
            f"{pending_status['items'][0]['intent']['nonce']}/reconcile",
        )
        assert response.status_code == 200, response.text
        assert response.json()["authority_ack_id"]
        assert response.json()["state"] == "confirmed"
        final_status = client.get("/api/v2/market/claim-intents").json()
        assert final_status["stats"] == {"confirmed": 1}
        assert fresh_checks
        assert {check[:2] for check in fresh_checks} == {
            ("https://source.example", source.as_did()),
        }
        assert identity_attempts == [
            "93.184.216.34",
            "93.184.216.34",
            "93.184.216.35",
            "93.184.216.34",
            "93.184.216.35",
        ]
        assert pinned_posts == [
            (
                "https://source.example/api/v2/market/federation/claim-foreign",
                "93.184.216.34",
            ),
            (
                "https://source.example/api/v2/market/federation/claim-status",
                "93.184.216.35",
            ),
            (
                "https://source.example/api/v2/market/federation/claim-status",
                "93.184.216.35",
            ),
        ]

        from nth_dao.market.claim_intent import IntentTracker

        def reject_post(*_args, **_kwargs):
            return 409, json.dumps({"detail": "listing closed"}).encode("utf-8")

        def fail_terminal_write(self, intent, state):
            raise OSError("simulated terminal journal failure")

        cache.replace_all({
            "source": {
                "ann": announcement,
                "source": "https://source.example",
                "source_did": source.as_did(),
            },
        })
        identity_mode["value"] = "normal"
        monkeypatch.setattr(poll, "_urllib_post_json_pinned_raw", reject_post)
        monkeypatch.setattr(IntentTracker, "mark", fail_terminal_write)
        response = client.post(
            "/api/v2/market/federated/claim",
            json={
                "announcement_id": announcement.announcement_id,
                "federation_key": key,
                "agent_did": spawned["did"],
            },
        )
        assert response.status_code == 503, response.text
        assert response.json()["error"]["code"] == (
            "claim-rejection-persist-failed"
        )
        assert response.json()["claim_intent_state"] == "pending"
    finally:
        client.post(f"/api/v2/agents/{spawned['agent_id']}/stop")
