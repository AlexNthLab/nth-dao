"""社交层:单向关注、双签好友、防单方伪造、交叉请求、解除、record fail-closed。"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("nacl")

from nth_dao.identity import AgentIdentity
from nth_dao.social import (
    FOLLOW,
    FRIEND_ACCEPT,
    FRIEND_DECLINE,
    FRIEND_REMOVE,
    FRIEND_REQUEST,
    UNFOLLOW,
    SocialProjection,
    record_social,
    sign_social_statement,
    verify_social_statement,
)
from nth_dao.spine import SignedEventLog, replay


def _id() -> AgentIdentity:
    return AgentIdentity.generate()


def _proj(spine: SignedEventLog) -> SocialProjection:
    p = SocialProjection()
    replay(spine.read_all(), p)
    return p


# ── 签名 / 校验 ─────────────────────────────────────────────────

def test_sign_verify_tamper() -> None:
    a, b = _id(), _id()
    s = sign_social_statement(signer=a, statement_type=FOLLOW, target_did=b.as_did())
    ok, why = verify_social_statement(s)
    assert ok, why
    s["target_did"] = _id().as_did()      # 改对象 → 签名失配
    bad, _ = verify_social_statement(s)
    assert not bad


def test_cannot_relate_to_self() -> None:
    a = _id()
    with pytest.raises(ValueError, match="yourself"):
        sign_social_statement(signer=a, statement_type=FOLLOW, target_did=a.as_did())


# ── 关注:单向、免确认 ──────────────────────────────────────────

def test_follow_is_one_way_no_confirm(tmp_path: Path) -> None:
    node, a, b = _id(), _id(), _id()
    spine = SignedEventLog(tmp_path / "s.jsonl", node)
    record_social(spine, sign_social_statement(
        signer=a, statement_type=FOLLOW, target_did=b.as_did()))

    ok, why = spine.verify_chain()
    assert ok, why
    p = _proj(spine)
    # A 单方就关注成功,B 不必同意
    assert p.following(a.as_did()) == [b.as_did()]
    assert p.followers(b.as_did()) == [a.as_did()]
    # 但这不是好友,也不是双向
    assert p.friends(a.as_did()) == []
    assert p.following(b.as_did()) == []


def test_unfollow(tmp_path: Path) -> None:
    node, a, b = _id(), _id(), _id()
    spine = SignedEventLog(tmp_path / "s.jsonl", node)
    record_social(spine, sign_social_statement(signer=a, statement_type=FOLLOW, target_did=b.as_did()))
    record_social(spine, sign_social_statement(signer=a, statement_type=UNFOLLOW, target_did=b.as_did()))
    p = _proj(spine)
    assert p.following(a.as_did()) == []
    assert p.followers(b.as_did()) == []


# ── 好友:双签才成立 ────────────────────────────────────────────

def test_friend_request_then_accept(tmp_path: Path) -> None:
    node, a, b = _id(), _id(), _id()
    spine = SignedEventLog(tmp_path / "s.jsonl", node)
    # A 请求 B
    record_social(spine, sign_social_statement(
        signer=a, statement_type=FRIEND_REQUEST, target_did=b.as_did()))
    p = _proj(spine)
    assert p.pending_outgoing(a.as_did()) == [b.as_did()]
    assert p.pending_incoming(b.as_did()) == [a.as_did()]   # 进 B 的收件箱
    assert p.friends(a.as_did()) == []                       # 还不是好友

    # B 接受
    record_social(spine, sign_social_statement(
        signer=b, statement_type=FRIEND_ACCEPT, target_did=a.as_did()))
    p = _proj(spine)
    assert p.friends(a.as_did()) == [b.as_did()]
    assert p.friends(b.as_did()) == [a.as_did()]
    assert p.pending_incoming(b.as_did()) == []              # 请求已消化


def test_accept_without_request_is_rejected(tmp_path: Path) -> None:
    """防伪:没有对方的在册请求,凭空 accept 不能把自己塞进别人好友列表。"""
    node, a, b = _id(), _id(), _id()
    spine = SignedEventLog(tmp_path / "s.jsonl", node)
    # B 没请求过 A,A 却 accept B
    record_social(spine, sign_social_statement(
        signer=a, statement_type=FRIEND_ACCEPT, target_did=b.as_did()))
    p = _proj(spine)
    assert p.friends(a.as_did()) == []
    assert p.friends(b.as_did()) == []


def test_crossed_requests_auto_friend(tmp_path: Path) -> None:
    """双方各自发请求(都签了)→ 视为互相确认,自动成好友,不卡死。"""
    node, a, b = _id(), _id(), _id()
    spine = SignedEventLog(tmp_path / "s.jsonl", node)
    record_social(spine, sign_social_statement(signer=a, statement_type=FRIEND_REQUEST, target_did=b.as_did()))
    record_social(spine, sign_social_statement(signer=b, statement_type=FRIEND_REQUEST, target_did=a.as_did()))
    p = _proj(spine)
    assert p.friends(a.as_did()) == [b.as_did()]
    assert p.friends(b.as_did()) == [a.as_did()]
    assert p.pending_outgoing(a.as_did()) == []
    assert p.pending_incoming(a.as_did()) == []


def test_decline_clears_request(tmp_path: Path) -> None:
    node, a, b = _id(), _id(), _id()
    spine = SignedEventLog(tmp_path / "s.jsonl", node)
    record_social(spine, sign_social_statement(signer=a, statement_type=FRIEND_REQUEST, target_did=b.as_did()))
    record_social(spine, sign_social_statement(signer=b, statement_type=FRIEND_DECLINE, target_did=a.as_did()))
    p = _proj(spine)
    assert p.pending_incoming(b.as_did()) == []
    assert p.pending_outgoing(a.as_did()) == []
    assert p.friends(a.as_did()) == []


def test_remove_unfriends(tmp_path: Path) -> None:
    node, a, b = _id(), _id(), _id()
    spine = SignedEventLog(tmp_path / "s.jsonl", node)
    record_social(spine, sign_social_statement(signer=a, statement_type=FRIEND_REQUEST, target_did=b.as_did()))
    record_social(spine, sign_social_statement(signer=b, statement_type=FRIEND_ACCEPT, target_did=a.as_did()))
    # A 解除好友
    record_social(spine, sign_social_statement(signer=a, statement_type=FRIEND_REMOVE, target_did=b.as_did()))
    p = _proj(spine)
    assert p.friends(a.as_did()) == []
    assert p.friends(b.as_did()) == []


def test_relationship_snapshot(tmp_path: Path) -> None:
    node, a, b = _id(), _id(), _id()
    spine = SignedEventLog(tmp_path / "s.jsonl", node)
    record_social(spine, sign_social_statement(signer=a, statement_type=FOLLOW, target_did=b.as_did()))
    record_social(spine, sign_social_statement(signer=a, statement_type=FRIEND_REQUEST, target_did=b.as_did()))
    p = _proj(spine)
    rel = p.relationship(a.as_did(), b.as_did())
    assert rel["following"] is True
    assert rel["friend"] is False
    assert rel["request_outgoing"] is True
    # 反向视角:B 被 A 关注、收到 A 的请求
    rb = p.relationship(b.as_did(), a.as_did())
    assert rb["followed_by"] is True
    assert rb["request_incoming"] is True


def test_record_fail_closed(tmp_path: Path) -> None:
    node, a, b = _id(), _id(), _id()
    spine = SignedEventLog(tmp_path / "s.jsonl", node)
    s = sign_social_statement(signer=a, statement_type=FOLLOW, target_did=b.as_did())
    s["sig"] = "forged"
    with pytest.raises(ValueError, match="invalid social statement"):
        record_social(spine, s)
