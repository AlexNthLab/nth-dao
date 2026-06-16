"""社交语句联邦·纯逻辑层(serve + ingest,无传输)。

社交语句自带签名(verify_social_statement),故可安全跨节点搬运——传输与对端
都无需被信任,真伪全靠 payload 里**原作者**的签名:

  - serve:本节点暴露**自己签发**(payload.actor_did == self)的 social.* 语句,
    供对端拉取。只暴露自己的出边(本就是要投递出去的),不转发他人语句。
  - ingest:收下**发给自己**(target_did == self)、验签通过、**未见过**(按 sig
    去重)的外部语句,record 进本地 spine。

这样 B 能收到 A 签的 friend_request(target=B);B accept(target=A)后 A 也能拉到,
"加好友"端到端闭环。记录时事件由本节点签名(链完整性),投影再验 payload 内
原作者签名 —— 与 hub 记录外部争议/认领同构。

去重(按原作者 sig)同时**挡重放**:同一条语句最多被记一次,恶意 peer 重投旧的
friend_request(对方已撤回)也不会再次生效。
"""
from __future__ import annotations

from typing import Any, Dict, List, Set

from nth_dao.social.statement import verify_social_statement

SOCIAL_EVENT_PREFIX = "social."


def _is_social_event(ev: Any) -> bool:
    t = getattr(ev, "type", "")
    return isinstance(t, str) and t.startswith(SOCIAL_EVENT_PREFIX)


def local_social_statements(
    spine: Any, self_did: str, *, since_seq: int = -1, limit: int = 500,
) -> List[Dict[str, Any]]:
    """本节点自己签发(actor==self)、seq>since 的社交语句,供对端拉取。

    返回 [{"seq", "statement"}],按 seq 升序;到 ``limit`` 截断(拉方带
    ``since=last_seq`` 翻页)。
    """
    out: List[Dict[str, Any]] = []
    for ev in spine.read_all():
        if ev.seq <= since_seq or not _is_social_event(ev):
            continue
        stmt = ev.payload if isinstance(ev.payload, dict) else {}
        if stmt.get("actor_did") != self_did:
            continue
        out.append({"seq": ev.seq, "statement": stmt})
        if len(out) >= limit:
            break
    return out


def _recorded_social_sigs(spine: Any) -> Set[str]:
    """本 spine 上已记录的社交语句签名集合(去重 / 防重放用)。"""
    sigs: Set[str] = set()
    for ev in spine.read_all():
        if not _is_social_event(ev):
            continue
        s = ev.payload.get("sig") if isinstance(ev.payload, dict) else None
        if isinstance(s, str):
            sigs.add(s)
    return sigs


def ingest_social_statements(
    spine: Any, statements: List[Dict[str, Any]], self_did: str,
) -> int:
    """收下发给自己、验签通过、未见过的外部社交语句,record 进 spine。返回记录条数。

    四道闸,缺一不收(fail-closed):
      1. ``target_did == self`` —— 只收发给我的(他人无法往我图里塞与我无关的边)。
      2. ``sig`` 未在本 spine 出现过 —— 去重 + 防重放。
      3. ``verify_social_statement`` —— 原作者签名有效。
      4. record_social 落 spine(事件由本节点签名)。
    """
    from nth_dao.social import record_social
    seen = _recorded_social_sigs(spine)
    recorded = 0
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        if stmt.get("target_did") != self_did:
            continue
        sig = stmt.get("sig")
        if not isinstance(sig, str) or not sig or sig in seen:
            continue
        ok, _why = verify_social_statement(stmt)
        if not ok:
            continue
        record_social(spine, stmt)
        seen.add(sig)
        recorded += 1
    return recorded
