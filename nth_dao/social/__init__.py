"""Nth DAO 社交子系统(Phase 社交)。

**spine 原生**关系层:无旧 store、无影子,spine 即唯一事实源。发起方签名声明
(follow/unfollow/friend_*),node 经 ``record_social`` 落入统一日志;
``SocialProjection`` 折叠出关注图 + 好友图。

不对称设计(慕强有基座,成熟人要确认):
  - 关注 follow —— 单签单向免确认。
  - 好友 friend —— 双签双向需对方 accept。

本层只管关系图;信誉/协作次数等富集在读端 endpoint 合成,保持模块单一职责。
"""
from typing import Any, Dict

from nth_dao.social.projection import (
    EVENT_FOLLOW,
    EVENT_FRIEND_ACCEPT,
    EVENT_FRIEND_DECLINE,
    EVENT_FRIEND_REMOVE,
    EVENT_FRIEND_REQUEST,
    EVENT_UNFOLLOW,
    SocialProjection,
)
from nth_dao.social.statement import (
    FOLLOW,
    FRIEND_ACCEPT,
    FRIEND_DECLINE,
    FRIEND_REMOVE,
    FRIEND_REQUEST,
    SOCIAL_STATEMENT_KIND,
    UNFOLLOW,
    sign_social_statement,
    verify_social_statement,
)


def record_social(spine: Any, statement: Dict[str, Any]) -> Any:
    """把一条已签社交声明落入 ``spine``(``social.<type>`` 事件),返回 SpineEvent。

    社交关系是 spine 原生记录,故**非** best-effort:声明无效则拒(fail-closed),
    不把垃圾写进权威日志。
    """
    ok, why = verify_social_statement(statement)
    if not ok:
        raise ValueError(f"refusing to record invalid social statement: {why}")
    return spine.append(f"social.{statement['type']}", statement)


__all__ = [
    "SOCIAL_STATEMENT_KIND",
    "FOLLOW",
    "UNFOLLOW",
    "FRIEND_REQUEST",
    "FRIEND_ACCEPT",
    "FRIEND_DECLINE",
    "FRIEND_REMOVE",
    "sign_social_statement",
    "verify_social_statement",
    "EVENT_FOLLOW",
    "EVENT_UNFOLLOW",
    "EVENT_FRIEND_REQUEST",
    "EVENT_FRIEND_ACCEPT",
    "EVENT_FRIEND_DECLINE",
    "EVENT_FRIEND_REMOVE",
    "SocialProjection",
    "record_social",
]
