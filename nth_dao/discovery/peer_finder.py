"""
PeerFinder


    finder = PeerFinder(registry)
    pythonistas = finder.find(capability="python", status="idle")
    teammate = finder.best_match(needed_capabilities=["python", "web"])
    finder.exclude_self(my_agent_id)  #


    -  needed_capability  1
    - status=idle  0.5  busy
    -  group  0.3
    -  hostname  0.2
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from .agent_registry import AgentRecord, AgentRegistry


@dataclass
class MatchResult:
    """ score """
    record: AgentRecord
    score: float
    matched_capabilities: List[str]


class PeerFinder:
    """"""

    def __init__(self, registry: AgentRegistry):
        self.registry = registry

    #

    def find(
        self,
        capability: Optional[str] = None,
        backend_id: Optional[str] = None,
        group: Optional[str] = None,
        status: Optional[str] = None,
        only_alive: bool = True,
        exclude_agent_ids: Optional[List[str]] = None,
    ) -> List[AgentRecord]:
        """"""
        records = (
            self.registry.list_alive() if only_alive else self.registry.list_all()
        )
        if capability is not None:
            records = [r for r in records if capability in r.capabilities]
        if backend_id is not None:
            records = [r for r in records if r.backend_id == backend_id]
        if group is not None:
            records = [r for r in records if group in r.groups]
        if status is not None:
            records = [r for r in records if r.status == status]
        if exclude_agent_ids:
            excl = set(exclude_agent_ids)
            records = [r for r in records if r.agent_id not in excl]
        return records

    def find_all(
        self,
        capabilities: Optional[List[str]] = None,
        backend_ids: Optional[List[str]] = None,
        only_alive: bool = True,
    ) -> List[AgentRecord]:
        """ capabilityAND """
        records = (
            self.registry.list_alive() if only_alive else self.registry.list_all()
        )
        if capabilities:
            req = set(capabilities)
            records = [r for r in records if req.issubset(set(r.capabilities))]
        if backend_ids:
            allowed = set(backend_ids)
            records = [r for r in records if r.backend_id in allowed]
        return records

    #

    def best_match(
        self,
        needed_capabilities: List[str],
        prefer_idle: bool = True,
        prefer_group: Optional[str] = None,
        prefer_hostname: Optional[str] = None,
        exclude_agent_ids: Optional[List[str]] = None,
        only_alive: bool = True,
        min_match: int = 1,
    ) -> Optional[MatchResult]:
        """返回最佳匹配；min_match=N 要求至少匹中 N 个 capability。"""
        results = self.rank(
            needed_capabilities=needed_capabilities,
            prefer_idle=prefer_idle,
            prefer_group=prefer_group,
            prefer_hostname=prefer_hostname,
            exclude_agent_ids=exclude_agent_ids,
            only_alive=only_alive,
            min_match=min_match,
        )
        return results[0] if results else None

    def rank(
        self,
        needed_capabilities: List[str],
        prefer_idle: bool = True,
        prefer_group: Optional[str] = None,
        prefer_hostname: Optional[str] = None,
        exclude_agent_ids: Optional[List[str]] = None,
        only_alive: bool = True,
        min_match: int = 1,
    ) -> List[MatchResult]:
        """按 score 排序的匹配结果。

        Args:
            min_match: 最少需要匹中的 capability 数。默认 1（至少 1 个 cap 匹中）。
                       传 0 时退化为"任何活着的 agent"——之前 min_score=0.5 的旧行为
                       会返回 0 个 cap 匹中但 idle 的 agent，这是 H-6 的坑。
        """
        candidates = (
            self.registry.list_alive() if only_alive else self.registry.list_all()
        )
        if exclude_agent_ids:
            excl = set(exclude_agent_ids)
            candidates = [r for r in candidates if r.agent_id not in excl]

        results = []
        for r in candidates:
            matched = [c for c in needed_capabilities if c in r.capabilities]
            if len(matched) < min_match:
                continue
            score = float(len(matched))

            if prefer_idle and r.status == "idle":
                score += 0.5
            if prefer_group and prefer_group in r.groups:
                score += 0.3
            if prefer_hostname and r.hostname == prefer_hostname:
                score += 0.2

            results.append(MatchResult(
                record=r, score=score, matched_capabilities=matched,
            ))

        results.sort(key=lambda x: x.score, reverse=True)
        return results

    #

    def search(
        self,
        query: str,
        *,
        fields: Optional[List[str]] = None,
        limit: int = 10,
        min_score: float = 0.5,
        only_alive: bool = True,
        exclude_agent_ids: Optional[List[str]] = None,
    ) -> List["MatchResult"]:
        """微信式"找人"：模糊搜索 agent_id / label / capabilities / groups。

        Args:
            query: 搜索词（大小写无关）。空串返回 []。
            fields: 要搜的字段子集，默认 ["agent_id", "label", "capabilities", "groups"]
            limit: 最多返回 N 条
            min_score: 低于此评分的丢弃
            only_alive: 只搜索 alive agent
            exclude_agent_ids: 排除特定 agent_id（例如自己）

        Score 规则（命中字段累加）:
            - 完全相等       +3.0
            - 前缀匹配       +1.5
            - 子串包含       +0.8
            - 多字段命中累加；status=idle 再 +0.5

        Returns:
            按 score 降序的 MatchResult 列表；matched_capabilities 字段
            装载本次命中的 (field, value) 对（注意：复用现有字段名做载体）。
        """
        if not query:
            return []
        q = query.lower().strip()
        if not q:
            return []

        all_fields = ["agent_id", "label", "capabilities", "groups"]
        active_fields = [f for f in (fields or all_fields) if f in all_fields]

        candidates = (
            self.registry.list_alive() if only_alive else self.registry.list_all()
        )
        if exclude_agent_ids:
            excl = set(exclude_agent_ids)
            candidates = [r for r in candidates if r.agent_id not in excl]

        results: List[MatchResult] = []
        for r in candidates:
            score, matched_pairs = _score_record(r, q, active_fields)
            if score < min_score:
                continue
            if r.status == "idle":
                score += 0.5
            # MatchResult 复用既有结构：matched_capabilities 改装成 "field:value" 列表
            results.append(MatchResult(
                record=r,
                score=score,
                matched_capabilities=matched_pairs,
            ))

        results.sort(key=lambda m: m.score, reverse=True)
        return results[:limit]

    def count_alive(self) -> int:
        return len(self.registry.list_alive())

    def capability_index(self) -> dict:
        """ {capability: [agent_id, ...]} """
        idx: dict = {}
        for r in self.registry.list_alive():
            for cap in r.capabilities:
                idx.setdefault(cap, []).append(r.agent_id)
        return idx

    def summary_table(self) -> str:  # noqa: E303
        # placeholder anchor — actual definition below
        return _summary_table_impl(self.registry)


# ───────────────────────── fuzzy-search helpers ─────────────────────────


# Score weights — tuned so:
#   "alic" prefix-matching agent_id "alice" → score ≈ 1.5 + maybe 1.5 on label
#   "alice" exact agent_id              → score ≈ 3.0 + label 3.0 = 6.0
def _field_score(haystack: str, needle: str) -> float:
    """Single-field substring/prefix/exact score (case-insensitive)."""
    if not haystack:
        return 0.0
    hay = haystack.lower()
    if hay == needle:
        return 3.0
    if hay.startswith(needle):
        return 1.5
    if needle in hay:
        return 0.8
    return 0.0


def _extract_label(record) -> str:
    """Pull the display label from registry metadata (set by attach.py)."""
    meta = record.metadata or {}
    ident = meta.get("identity") if isinstance(meta, dict) else None
    if isinstance(ident, dict):
        return str(ident.get("label", "") or "")
    return str(meta.get("label", "") or "") if isinstance(meta, dict) else ""


def _score_record(record, q: str, fields):
    """Returns (score, ["field:matched-value", ...]) for one record/query."""
    score = 0.0
    matched = []
    if "agent_id" in fields:
        s = _field_score(record.agent_id, q)
        if s > 0:
            score += s
            matched.append(f"agent_id:{record.agent_id}")
    if "label" in fields:
        label = _extract_label(record)
        if label:
            s = _field_score(label, q)
            if s > 0:
                score += s
                matched.append(f"label:{label}")
    if "capabilities" in fields:
        for cap in record.capabilities:
            s = _field_score(cap, q)
            if s > 0:
                score += s
                matched.append(f"capability:{cap}")
                break  # one capability match is enough for ranking
    if "groups" in fields:
        for g in record.groups:
            s = _field_score(g, q)
            if s > 0:
                score += s
                matched.append(f"group:{g}")
                break
    return score, matched


def _summary_table_impl(registry):
    """ASCII table of alive agents."""
    records = registry.list_alive()
    if not records:
        return "(no agents online)"
    lines = [
        f"{'agent_id':25s} | {'backend':12s} | {'status':8s} | {'capabilities':30s} | last_seen",
        "-" * 100,
    ]
    for r in records:
        caps = ",".join(r.capabilities[:3])
        if len(r.capabilities) > 3:
            caps += f"+{len(r.capabilities) - 3}"
        lines.append(
            f"{r.agent_id:25s} | {r.backend_id:12s} | {r.status:8s} | {caps:30s} | {r.last_seen[:19]}"
        )
    return "\n".join(lines)
