"""社交关系投影 —— 把 spine 的 social.* 事件折叠成关注图 + 好友图(Phase 社交)。

每条声明独立验签(verify_social_statement),验不过丢弃。两类边:

关注(有向,单签即成立):
  follow(A→B)   → A 关注 B(following[A]∋B、followers[B]∋A)
  unfollow(A→B) → 撤销

好友(无向,需双方签名链):
  friend_request(A→B)  A 发出请求(pending_out[A]∋B、pending_in[B]∋A)
  friend_accept(B→A)   B 接受 A 的请求 → 互为好友(必须存在 A 的在册请求,否则丢弃)
  friend_decline(B→A)  B 拒绝 → 清请求
  friend_remove(X→Y)   任一方解除好友/撤回请求

**防伪要点**:friends[A]∋B 当且仅当 spine 上同时存在双方签名——
要么 (B 请求 + A 接受),要么 (双向请求交叉)。单方无法把自己塞进别人好友列表。
两条交叉的 friend_request 视为互相确认(双方都主动签了请求 = 都同意),自动成好友,
避免"两边都请求却卡着不成"的死结。
"""
from __future__ import annotations

from typing import Any, Dict, List, Set

from nth_dao.social.statement import (
    FOLLOW,
    FRIEND_ACCEPT,
    FRIEND_DECLINE,
    FRIEND_REMOVE,
    FRIEND_REQUEST,
    UNFOLLOW,
    verify_social_statement,
)
from nth_dao.spine.event import SpineEvent
from nth_dao.spine.projection import Projection

EVENT_FOLLOW = "social.follow"
EVENT_UNFOLLOW = "social.unfollow"
EVENT_FRIEND_REQUEST = "social.friend_request"
EVENT_FRIEND_ACCEPT = "social.friend_accept"
EVENT_FRIEND_DECLINE = "social.friend_decline"
EVENT_FRIEND_REMOVE = "social.friend_remove"
_SOCIAL_EVENTS = (
    EVENT_FOLLOW, EVENT_UNFOLLOW,
    EVENT_FRIEND_REQUEST, EVENT_FRIEND_ACCEPT,
    EVENT_FRIEND_DECLINE, EVENT_FRIEND_REMOVE,
)


class SocialProjection(Projection):
    """折叠 social.* → 关注图 + 好友图 + 待确认的好友请求。"""

    def __init__(self) -> None:
        self._following: Dict[str, Set[str]] = {}   # actor -> 关注的人
        self._followers: Dict[str, Set[str]] = {}   # target -> 粉丝
        self._friends: Dict[str, Set[str]] = {}      # did -> 好友
        self._pending_out: Dict[str, Set[str]] = {}  # requester -> 已请求的人
        self._pending_in: Dict[str, Set[str]] = {}   # requested -> 请求者(待我确认)

    def reset(self) -> None:
        self._following.clear()
        self._followers.clear()
        self._friends.clear()
        self._pending_out.clear()
        self._pending_in.clear()

    # ── 内部小工具 ──────────────────────────────────────────────

    def _clear_pending(self, requester: str, requested: str) -> None:
        self._pending_out.get(requester, set()).discard(requested)
        self._pending_in.get(requested, set()).discard(requester)

    def _make_friends(self, a: str, b: str) -> None:
        self._friends.setdefault(a, set()).add(b)
        self._friends.setdefault(b, set()).add(a)
        # 成好友后清掉两个方向的悬挂请求
        self._clear_pending(a, b)
        self._clear_pending(b, a)

    # ── 事件折叠 ────────────────────────────────────────────────

    def apply(self, event: SpineEvent) -> None:
        if event.type not in _SOCIAL_EVENTS:
            return
        stmt = event.payload if isinstance(event.payload, dict) else {}
        ok, _ = verify_social_statement(stmt)
        if not ok:
            return
        t = stmt["type"]
        a = stmt["actor_did"]    # 发起方(签名者)
        b = stmt["target_did"]   # 关系对象
        if a == b:
            return

        if t == FOLLOW:
            self._following.setdefault(a, set()).add(b)
            self._followers.setdefault(b, set()).add(a)

        elif t == UNFOLLOW:
            self._following.get(a, set()).discard(b)
            self._followers.get(b, set()).discard(a)

        elif t == FRIEND_REQUEST:
            if b in self._friends.get(a, set()):
                return   # 已是好友,幂等
            # 交叉请求:b 之前已请求过 a(a 的待确认里有 b)→ 视为双方确认
            if b in self._pending_in.get(a, set()):
                self._make_friends(a, b)
            else:
                self._pending_out.setdefault(a, set()).add(b)
                self._pending_in.setdefault(b, set()).add(a)

        elif t == FRIEND_ACCEPT:
            # a 接受 b 的请求:必须存在 b→a 的在册请求(b 在 a 的待确认里)
            if b in self._pending_in.get(a, set()):
                self._make_friends(a, b)
            # 否则丢弃:不能接受不存在的请求(防凭空伪造好友)

        elif t == FRIEND_DECLINE:
            # a 拒绝 b 的请求
            self._clear_pending(b, a)

        elif t == FRIEND_REMOVE:
            # 任一方解除:删好友 + 清两方向悬挂请求
            self._friends.get(a, set()).discard(b)
            self._friends.get(b, set()).discard(a)
            self._clear_pending(a, b)
            self._clear_pending(b, a)

    # ── 查询 ────────────────────────────────────────────────────

    def following(self, did: str) -> List[str]:
        """did 关注的人(单向)。"""
        return sorted(self._following.get(did, set()))

    def followers(self, did: str) -> List[str]:
        """关注 did 的人(粉丝)。"""
        return sorted(self._followers.get(did, set()))

    def friends(self, did: str) -> List[str]:
        """did 的好友(双向已确认)。"""
        return sorted(self._friends.get(did, set()))

    def pending_incoming(self, did: str) -> List[str]:
        """待 did 确认的好友请求(进收件箱)。"""
        return sorted(self._pending_in.get(did, set()))

    def pending_outgoing(self, did: str) -> List[str]:
        """did 发出、尚未被确认的好友请求。"""
        return sorted(self._pending_out.get(did, set()))

    def relationship(self, me: str, other: str) -> Dict[str, bool]:
        """me 视角下与 other 的关系快照(给名册/资料页一眼看清)。"""
        return {
            "following": other in self._following.get(me, set()),
            "followed_by": other in self._followers.get(me, set()),
            "friend": other in self._friends.get(me, set()),
            "request_outgoing": other in self._pending_out.get(me, set()),
            "request_incoming": other in self._pending_in.get(me, set()),
        }
