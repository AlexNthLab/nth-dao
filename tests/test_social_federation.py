"""社交语句联邦:serve 只暴露自己出边、ingest 四道闸(target/去重/验签/落盘)、
两节点端到端互加好友(关注 + 好友请求 + 接受跨 spine 闭环)。"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

pytest.importorskip("nacl")
pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from nth_dao.identity import AgentIdentity
from nth_dao.social import (
    BLOCK,
    FOLLOW,
    FRIEND_REQUEST,
    record_social,
    sign_social_statement,
)
from nth_dao.social.federation import (
    ingest_social_statements,
    local_social_statements,
)
from nth_dao.spine import SignedEventLog
from nth_dao.web import create_app
from nth_dao.web.social_federation_poll import federate_social_once


def _id() -> AgentIdentity:
    return AgentIdentity.generate()


# ── 纯逻辑:serve ───────────────────────────────────────────────

def test_local_serves_only_own_outbound(tmp_path: Path) -> None:
    node, me, other = _id(), _id(), _id()
    spine = SignedEventLog(tmp_path / "s.jsonl", node)
    # 我(me)签发的关注
    record_social(spine, sign_social_statement(
        signer=me, statement_type=FOLLOW, target_did=other.as_did()))
    # 别人(other)发给我的请求(模拟已 ingest 的外部语句)
    record_social(spine, sign_social_statement(
        signer=other, statement_type=FRIEND_REQUEST, target_did=me.as_did()))

    mine = local_social_statements(spine, me.as_did())
    assert len(mine) == 1                       # 只暴露自己签发的
    assert mine[0]["statement"]["actor_did"] == me.as_did()
    # since 游标过滤
    assert local_social_statements(spine, me.as_did(), since_seq=mine[0]["seq"]) == []


def test_block_is_silent_not_served(tmp_path: Path) -> None:
    """静默屏蔽:block/unblock 是本地决定,绝不进联邦流(对方拉不到、无从察觉)。"""
    node, me, x = _id(), _id(), _id()
    spine = SignedEventLog(tmp_path / "s.jsonl", node)
    record_social(spine, sign_social_statement(signer=me, statement_type=FOLLOW, target_did=x.as_did()))
    record_social(spine, sign_social_statement(signer=me, statement_type=BLOCK, target_did=x.as_did()))
    served = local_social_statements(spine, me.as_did())
    types = [s["statement"]["type"] for s in served]
    assert "block" not in types and "unblock" not in types   # 屏蔽不外发
    assert "follow" in types                                  # 普通边照常外发


# ── 纯逻辑:ingest 四道闸 ───────────────────────────────────────

def test_ingest_only_addressed_to_self(tmp_path: Path) -> None:
    node, me, a, b = _id(), _id(), _id(), _id()
    spine = SignedEventLog(tmp_path / "s.jsonl", node)
    to_me = sign_social_statement(signer=a, statement_type=FOLLOW, target_did=me.as_did())
    to_other = sign_social_statement(signer=a, statement_type=FOLLOW, target_did=b.as_did())
    n = ingest_social_statements(spine, [to_me, to_other], me.as_did())
    assert n == 1   # 只收 target==me 的;发给 b 的被拒(防别人往我图塞无关边)


def test_ingest_dedup_and_replay_proof(tmp_path: Path) -> None:
    node, me, a = _id(), _id(), _id()
    spine = SignedEventLog(tmp_path / "s.jsonl", node)
    req = sign_social_statement(signer=a, statement_type=FRIEND_REQUEST, target_did=me.as_did())
    assert ingest_social_statements(spine, [req], me.as_did()) == 1
    # 同一条重投(恶意 peer 重放)→ 0 条(按 sig 去重)
    assert ingest_social_statements(spine, [req, req], me.as_did()) == 0


def test_ingest_rejects_bad_signature(tmp_path: Path) -> None:
    node, me, a = _id(), _id(), _id()
    spine = SignedEventLog(tmp_path / "s.jsonl", node)
    forged = sign_social_statement(signer=a, statement_type=FOLLOW, target_did=me.as_did())
    forged["sig"] = "tampered"
    assert ingest_social_statements(spine, [forged], me.as_did()) == 0


def test_ingest_rejects_blocked_actor(tmp_path: Path) -> None:
    """#3:被我屏蔽的 DID,其联邦投递的语句一律不落地。"""
    node, attacker = _id(), _id()
    spine = SignedEventLog(tmp_path / "s.jsonl", node)
    self_did = node.as_did()
    # 我(node)屏蔽 attacker
    record_social(spine, sign_social_statement(
        signer=node, statement_type=BLOCK, target_did=attacker.as_did()))
    # attacker 通过联邦发来关注(target=我)
    foll = sign_social_statement(
        signer=attacker, statement_type=FOLLOW, target_did=self_did)
    assert ingest_social_statements(spine, [foll], self_did) == 0


def test_ingest_rate_limit_caps_per_cycle(tmp_path: Path) -> None:
    """#3:单轮落盘封顶,余下留待下轮(给 sybil 突发封顶)。"""
    node = _id()
    spine = SignedEventLog(tmp_path / "s.jsonl", node)
    self_did = node.as_did()
    # 5 个不同 DID 各发一条关注(模拟 sybil)
    stmts = [sign_social_statement(signer=_id(), statement_type=FOLLOW, target_did=self_did)
             for _ in range(5)]
    assert ingest_social_statements(spine, stmts, self_did, max_per_cycle=2) == 2
    # 下一轮:已落的 2 条按 sig 去重,剩 3 条再收 2 条
    assert ingest_social_statements(spine, stmts, self_did, max_per_cycle=2) == 2


def test_ingest_rejects_actor_spoofing(tmp_path: Path) -> None:
    """恶意 peer 伪造"受害者自己签发"的语句(actor=victim,却用攻击者私钥签)
    → 必拒(verify 的 actor_did 签名对不上),不能往受害者图里塞它的"自有出边"。"""
    node, me, attacker = _id(), _id(), _id()
    spine = SignedEventLog(tmp_path / "s.jsonl", node)
    # 攻击者签一条,然后把 actor_did 改成受害者(签名仍是攻击者的)
    spoof = sign_social_statement(
        signer=attacker, statement_type=FOLLOW, target_did=me.as_did())
    spoof["actor_did"] = me.as_did()
    assert ingest_social_statements(spine, [spoof], me.as_did()) == 0


# ── 端到端:两节点互加好友(跨 spine)──────────────────────────

def _routed_get(clients: dict):
    """把 federate_social_once 发出的 {base}/... 调用路由到对应节点 TestClient。"""
    def get(url: str):
        for base, c in clients.items():
            if url.startswith(base):
                r = c.get(url[len(base):])
                r.raise_for_status()
                return r.json()
        raise RuntimeError(f"no client for {url}")
    return get


def test_two_node_mutual_friend_end_to_end() -> None:
    a_app = create_app(workspace=tempfile.mkdtemp(), require_console_auth=False)
    b_app = create_app(workspace=tempfile.mkdtemp(), require_console_auth=False)
    A, B = TestClient(a_app), TestClient(b_app)
    a_did = a_app.state.nth.node_identity.as_did()
    b_did = b_app.state.nth.node_identity.as_did()
    a_spine = a_app.state.nth.spine
    b_spine = b_app.state.nth.spine
    A_BASE, B_BASE = "http://a", "http://b"
    http_get = _routed_get({A_BASE: A, B_BASE: B})

    # A 关注 B + 向 B 发好友请求(A 自签,落 A 的 spine)
    assert A.post("/api/v2/social/follow", json={"target_did": b_did}).status_code == 200
    assert A.post("/api/v2/social/friend/request", json={"target_did": b_did}).status_code == 200

    # B 拉 A(peer=A)→ 收到发给自己的关注 + 请求
    got = federate_social_once(b_did, [A_BASE], b_spine, http_get)
    assert got == 2
    me_b = B.get("/api/v2/social/me").json()
    assert a_did in me_b["followers"]          # A 关注了 B
    assert a_did in me_b["pending_incoming"]    # A 的好友请求进了 B 的待确认
    assert me_b["friends"] == []                # 还没接受

    # B 接受 A 的请求(B 自签 friend_accept,落 B 的 spine)
    assert B.post("/api/v2/social/friend/accept", json={"target_did": a_did}).status_code == 200
    me_b2 = B.get("/api/v2/social/me").json()
    assert a_did in me_b2["friends"]            # B 侧:已是好友

    # A 拉 B(peer=B)→ 收到 B 的 accept → A 侧也成好友(端到端闭环)
    got2 = federate_social_once(a_did, [B_BASE], a_spine, http_get)
    assert got2 == 1
    me_a = A.get("/api/v2/social/me").json()
    assert b_did in me_a["friends"]            # A 侧:也成好友 ✓ 双向闭环


def test_two_node_block_stops_federation() -> None:
    """#3 端到端:B 屏蔽 A 后,A 经联邦发来的关注**不落** B 的 spine。"""
    a_app = create_app(workspace=tempfile.mkdtemp(), require_console_auth=False)
    b_app = create_app(workspace=tempfile.mkdtemp(), require_console_auth=False)
    A, B = TestClient(a_app), TestClient(b_app)
    a_did = a_app.state.nth.node_identity.as_did()
    b_did = b_app.state.nth.node_identity.as_did()
    b_spine = b_app.state.nth.spine
    A_BASE = "http://a"
    http_get = _routed_get({A_BASE: A, "http://b": B})

    # B 屏蔽 A;A 关注 B
    assert B.post("/api/v2/social/block", json={"target_did": a_did}).status_code == 200
    assert A.post("/api/v2/social/follow", json={"target_did": b_did}).status_code == 200

    # B 拉 A → A 的关注因屏蔽被拒,0 条落盘
    assert federate_social_once(b_did, [A_BASE], b_spine, http_get) == 0
    me_b = B.get("/api/v2/social/me").json()
    assert a_did not in me_b["followers"]
    assert a_did in me_b["blocked"]
