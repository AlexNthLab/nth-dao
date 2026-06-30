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

from nth_dao.social.statement import BLOCK, UNBLOCK, verify_social_statement

SOCIAL_EVENT_PREFIX = "social."

# 单轮 ingest 最多落多少条新语句:给未知 sybil 洪流封顶(限流)。throttle 非
# 根治——同一攻击者可跨轮慢灌;但封住突发、给运营者察觉+屏蔽的时间。彻底抗
# 女巫(海量不同 DID 各发一条)是 web-of-trust(信任距离加权)的事,见 docstring。
DEFAULT_MAX_INGEST_PER_CYCLE = 200


def _is_social_event(ev: Any) -> bool:
    t = getattr(ev, "type", "")
    return isinstance(t, str) and t.startswith(SOCIAL_EVENT_PREFIX)


def local_social_statements(
    spine: Any, self_did: str, *, since_seq: int = -1, limit: int = 500,
) -> List[Dict[str, Any]]:
    """本节点自己签发(actor==self)、seq>since 的社交语句,供对端拉取。

    返回 [{"seq", "statement"}],按 seq 升序;到 ``limit`` 截断(拉方带
    ``since=last_seq`` 翻页)。

    **静默屏蔽**:``block`` / ``unblock`` 是**纯本地**治理决定,**不外发** —— 它们
    只影响本节点对入站的过滤(见 ``ingest_social_statements``)与本地投影,绝不进
    联邦流,故被屏蔽方无从察觉(隐形拉黑)。
    """
    out: List[Dict[str, Any]] = []
    for ev in spine.read_all():
        if ev.seq <= since_seq or not _is_social_event(ev):
            continue
        stmt = ev.payload if isinstance(ev.payload, dict) else {}
        if stmt.get("actor_did") != self_did:
            continue
        if stmt.get("type") in (BLOCK, UNBLOCK):
            continue   # 静默:屏蔽决定不外发,对方拉不到
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


def blocked_by(spine: Any, self_did: str) -> Set[str]:
    """``self_did`` 当前屏蔽的 DID 集合(回放本 spine 上 self 的 block/unblock)。"""
    blocked: Set[str] = set()
    for ev in spine.read_all():
        if not _is_social_event(ev):
            continue
        p = ev.payload if isinstance(ev.payload, dict) else {}
        if p.get("actor_did") != self_did:
            continue
        t = p.get("type")
        tgt = p.get("target_did")
        if not isinstance(tgt, str):
            continue
        if t == BLOCK:
            blocked.add(tgt)
        elif t == UNBLOCK:
            blocked.discard(tgt)
    return blocked


def ingest_social_statements(
    spine: Any,
    statements: List[Dict[str, Any]],
    self_did: str,
    *,
    max_per_cycle: int = DEFAULT_MAX_INGEST_PER_CYCLE,
) -> int:
    """收下发给自己、未被屏蔽、验签通过、未见过的外部社交语句,record 进 spine。
    返回本轮记录条数。

    闸门(缺一不收,fail-closed)+ #3 防线:
      1. ``target_did == self`` —— 只收发给我的(他人无法往我图里塞与我无关的边)。
      2. **屏蔽**:``actor_did`` 在我的屏蔽名单里 → 拒(被屏蔽者发啥都不落地)。
      3. ``sig`` 未在本 spine 出现过 —— 去重 + 防重放。
      4. ``verify_social_statement`` —— 原作者签名有效。
      5. **限流**:单轮**实际落盘**最多 ``max_per_cycle`` 条,给未知 sybil 突发封顶
         (skip 的不计数;只数真写入,精确约束 spine 增速)。
    """
    from nth_dao.social import record_social
    seen = _recorded_social_sigs(spine)
    blocked = blocked_by(spine, self_did)
    recorded = 0
    for stmt in statements:
        if recorded >= max_per_cycle:
            break   # 限流:本轮落盘已达上限,余下留待下轮(给运营者察觉/屏蔽的时间)
        if not isinstance(stmt, dict):
            continue
        if stmt.get("target_did") != self_did:
            continue
        if stmt.get("actor_did") in blocked:
            continue   # 屏蔽:被屏蔽者的语句一律不落地
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
