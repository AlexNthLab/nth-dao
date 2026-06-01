"""
Reputation  Agent  +

 Agent  Agent



- 0.0 ~ 5.00 = 5 =
- code_review, security_audit, chat, task_execution, ...
-
- A  B  A
- team_reputation/{rater_agent_id}.json
- /


    ReputationEntry:
        rater: agent_id           #
        subject: agent_id         #
        context: str              #  /  /
        score: float              # 0.0-5.0
        reason: str               #
        timestamp: str
        sig: str                  #
        evidence: dict            #  tx hash


    rep = team.reputation

    #
    rep.rate("bob", context="code_review", score=4.5,
             reason="thorough review, caught 3 edge cases")

    #  agent
    score = rep.get_score("bob", context="code_review")
    print(f"Bob's code review score: {score['weighted_avg']:.1f}/5.0")

    #
    all = rep.get_score("bob")

    #  agent
    rep.import_entry(bob_rates_carol_entry)
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from .identity import AgentIdentity
from .util import atomic_write_json, safe_load_json, safe_id

logger = logging.getLogger("nth_dao.reputation")


#

DEFAULT_REPUTATION_DIR = "team_reputation"
SCORE_MIN = 0.0
SCORE_MAX = 5.0
DEFAULT_WEIGHT = 1.0
# 速率限制：同一 rater 在 RATE_LIMIT_WINDOW 秒内最多对同一 (subject, context) 写一次
RATE_LIMIT_WINDOW_SECONDS = 60 * 60  # 1 小时
# 同一 (rater, subject, context) 总评分条数上限，避免刷分
MAX_ENTRIES_PER_TRIPLE = 30
# Anti-Sybil：每次新 rate 要消耗 1 个 reputation credit；初始 + 每日补给
INITIAL_RATING_CREDITS = 5
DAILY_RATING_CREDIT_REFILL = 3
MAX_RATING_CREDITS = 30


#


@dataclass
class ReputationEntry:
    """"""

    rater: str          #  agent_id
    subject: str        #  agent_id
    context: str        #  "code_review", "chat", "security"
    score: float        # 0.0-5.0
    reason: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    sig: str = ""       #  Ed25519
    evidence: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        #
        self.score = max(SCORE_MIN, min(SCORE_MAX, self.score))

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "ReputationEntry":
        return cls(
            rater=data.get("rater", "?"),
            subject=data.get("subject", "?"),
            context=data.get("context", "unknown"),
            score=float(data.get("score", 2.5)),
            reason=data.get("reason", ""),
            timestamp=data.get("timestamp", ""),
            sig=data.get("sig", ""),
            evidence=data.get("evidence", {}),
        )

    def is_valid(self) -> bool:
        """ + """
        if not self.rater or not self.subject:
            return False
        if self.score < SCORE_MIN or self.score > SCORE_MAX:
            return False
        if self.rater == self.subject:
            return False  #
        return True

    def __repr__(self) -> str:
        return (
            f"[{self.context}] {self.rater[:8]}  {self.subject[:8]}: "
            f"{self.score:.1f}/5.0 ({self.reason[:30]})"
        )


@dataclass
class ReputationScore:
    """Agent  context """

    subject: str
    context: str = "*"  # "*" =
    total_entries: int = 0
    average: float = 0.0
    weighted_average: float = 0.0  #  rater
    min_score: float = 5.0
    max_score: float = 0.0
    raters: List[str] = field(default_factory=list)
    last_rated: str = ""

    def summary(self) -> str:
        if self.total_entries == 0:
            return f"{self.subject[:8]}: no ratings for [{self.context}]"
        return (
            f"{self.subject[:8]} [{self.context}]: "
            f"{self.weighted_average:.1f}/5.0 "
            f"({self.total_entries} ratings from {len(set(self.raters))} peers)"
        )


#  ReputationManager


class ReputationManager:
    """Agent """

    def __init__(
        self,
        workspace: Path,
        agent_id: str,
        identity: Optional[AgentIdentity] = None,
        reputation_dir: str = DEFAULT_REPUTATION_DIR,
    ):
        """
        Args:
            workspace:
            agent_id:  Agent ID
            identity:
            reputation_dir:
        """
        self.workspace = workspace
        self.agent_id = agent_id
        self.identity = identity
        self.base_dir = workspace / reputation_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)

        # 已弃用：原 self._entries 是从未填充的内存缓存。保留以免破坏旧调用。
        self._entries: List[ReputationEntry] = []

        # Anti-Sybil credit file:
        # When a crypto identity is available, scope credits by *pubkey fingerprint*
        # rather than agent_id. Otherwise an attacker can spawn N agent_ids and
        # collect N × INITIAL_RATING_CREDITS free credits. With pubkey scoping,
        # creating new identities costs a (cheap but non-zero) keygen + still
        # only nets you 5 initial credits per *unique keypair* — and the same
        # keypair across machines shares the budget when team_reputation/ is
        # git-synced.
        if identity is not None and getattr(identity, "can_sign", False):
            try:
                cred_id = identity.fingerprint()
            except Exception:
                cred_id = safe_id(agent_id)
        else:
            cred_id = safe_id(agent_id)
        self._credit_file = self.base_dir / f"{cred_id}_credits.json"

    #

    # ───── anti-Sybil rating credits ─────

    def _read_credits(self) -> Dict[str, Any]:
        data = safe_load_json(self._credit_file, fallback=None)
        if isinstance(data, dict) and "balance" in data:
            return data
        return {
            "agent_id": self.agent_id,
            "balance": INITIAL_RATING_CREDITS,
            "last_refill": datetime.now().date().isoformat(),
        }

    def _apply_daily_refill(self, state: Dict[str, Any]) -> Dict[str, Any]:
        try:
            last = datetime.fromisoformat(state.get("last_refill", "")).date()
        except ValueError:
            last = datetime.now().date()
        today = datetime.now().date()
        days = (today - last).days
        if days <= 0:
            return state
        new_balance = min(
            MAX_RATING_CREDITS,
            int(state.get("balance", 0)) + days * DAILY_RATING_CREDIT_REFILL,
        )
        state["balance"] = new_balance
        state["last_refill"] = today.isoformat()
        return state

    def credits(self) -> int:
        """Current rating credit balance after applying daily refill."""
        state = self._apply_daily_refill(self._read_credits())
        atomic_write_json(self._credit_file, state)
        return int(state["balance"])

    def _spend_credit(self) -> None:
        """Charge 1 credit; raises PermissionError if empty."""
        state = self._apply_daily_refill(self._read_credits())
        if int(state["balance"]) <= 0:
            raise PermissionError(
                "out of rating credits — wait for daily refill "
                f"({DAILY_RATING_CREDIT_REFILL}/day, max {MAX_RATING_CREDITS})"
            )
        state["balance"] = int(state["balance"]) - 1
        atomic_write_json(self._credit_file, state)

    def rate(
        self,
        subject: str,
        context: str,
        score: float,
        reason: str = "",
        evidence: Optional[Dict[str, Any]] = None,
        upsert: bool = True,
    ) -> ReputationEntry:
        """Rate 一个 agent。

        Args:
            subject: 被评 agent_id
            context: "code_review" / "chat" / "security" / ...
            score: 0.0-5.0
            reason: 可选解释
            evidence: 可选证据 dict
            upsert: True = 同一 (rater, subject, context) 已存在则覆盖最新；
                    False = 追加新条目（仍受 MAX_ENTRIES_PER_TRIPLE 限制）

        Raises:
            ValueError: subject == self；评分超出范围
            PermissionError: 触发速率限制 / 条目数上限
        """
        if subject == self.agent_id:
            raise ValueError("cannot rate yourself")
        if not (SCORE_MIN <= score <= SCORE_MAX):
            raise ValueError(f"score must be in [{SCORE_MIN}, {SCORE_MAX}]")

        existing_mine = self._my_entries_for_triple(subject, context)
        # 速率限制
        if existing_mine:
            latest = existing_mine[-1]
            try:
                latest_dt = datetime.fromisoformat(latest.timestamp)
            except ValueError:
                latest_dt = None
            if latest_dt and (datetime.now() - latest_dt).total_seconds() < RATE_LIMIT_WINDOW_SECONDS:
                if not upsert:
                    raise PermissionError(
                        f"rate limited: must wait {RATE_LIMIT_WINDOW_SECONDS}s "
                        f"between non-upsert ratings of ({subject}, {context})"
                    )

        # 条目上限
        if len(existing_mine) >= MAX_ENTRIES_PER_TRIPLE and not upsert:
            raise PermissionError(
                f"max {MAX_ENTRIES_PER_TRIPLE} entries reached for "
                f"({subject}, {context})"
            )

        entry = ReputationEntry(
            rater=self.agent_id,
            subject=subject,
            context=context,
            score=score,
            reason=reason,
            evidence=evidence or {},
        )

        if self.identity and self.identity.can_sign:
            payload = {k: v for k, v in entry.to_dict().items() if k != "sig"}
            entry.sig = self.identity.sign_json(payload)

        if upsert and existing_mine:
            # Upsert：替换最新一条而非追加。这种情况下不扣 credit
            # （因为没有新增条目，刷分难度仍由速率限制约束）。
            self._replace_my_entry(existing_mine[-1], entry)
        else:
            # 新增条目 → 消耗 1 anti-Sybil credit
            self._spend_credit()
            self._append(entry)
        return entry

    def _my_entries_for_triple(
        self, subject: str, context: str,
    ) -> List[ReputationEntry]:
        """从当前 agent 自己的文件读 (rater=self, subject, context) 的全部条目。

        关键：只读自己的文件 —— 不调用 _load_all 全盘扫，性能 O(N) 而非 O(N²)。
        """
        data = safe_load_json(self._my_file(), fallback=[])
        if not isinstance(data, list):
            return []
        out = []
        for d in data:
            try:
                e = ReputationEntry.from_dict(d)
            except Exception:
                continue
            if e.rater == self.agent_id and e.subject == subject and e.context == context:
                out.append(e)
        out.sort(key=lambda e: e.timestamp)
        return out

    def _replace_my_entry(
        self,
        old: ReputationEntry,
        new: ReputationEntry,
    ) -> None:
        """在自己文件里把 old 替换为 new（按 timestamp+rater+subject+context 匹配）。"""
        file_path = self._my_file()
        data = safe_load_json(file_path, fallback=[])
        if not isinstance(data, list):
            data = []
        out = []
        replaced = False
        for d in data:
            try:
                e = ReputationEntry.from_dict(d)
            except Exception:
                out.append(d)
                continue
            if (
                not replaced
                and e.rater == old.rater
                and e.subject == old.subject
                and e.context == old.context
                and e.timestamp == old.timestamp
            ):
                out.append(new.to_dict())
                replaced = True
            else:
                out.append(d)
        if not replaced:
            out.append(new.to_dict())
        atomic_write_json(file_path, out)

    def import_entry(self, entry: ReputationEntry) -> bool:
        """从其它节点导入一条评分。

        TODO（仍未做的安全检查）：调用方应已通过签名+pubkey 验证 entry 真出自 entry.rater。
        本函数不做密码学校验，只做去重。

        Returns:
            True 已新增；False 重复或无效
        """
        if not entry.is_valid():
            return False

        # 在 *所有* 文件里查重（不是只在 self._entries 内存缓存里 —— 之前从未填）
        existing_all = self._load_all()
        for existing in existing_all:
            if (existing.rater == entry.rater
                and existing.subject == entry.subject
                and existing.context == entry.context
                and existing.timestamp == entry.timestamp):
                return False

        self._append(entry)
        return True

    #

    def get_score(
        self,
        subject: str,
        context: Optional[str] = None,
        rater_trust: Optional[Dict[str, float]] = None,
        _entries_cache: Optional[List[ReputationEntry]] = None,
    ) -> ReputationScore:
        """Agent 评分（支持传 entries 缓存避免反复 _load_all）。"""
        all_entries = _entries_cache if _entries_cache is not None else self._load_all()
        entries = [
            e for e in all_entries
            if e.subject == subject
            and (context is None or e.context == context)
        ]

        if not entries:
            return ReputationScore(subject=subject, context=context or "*")

        scores = [e.score for e in entries]
        avg = sum(scores) / len(scores)

        weights = rater_trust or {}
        weighted_scores = [
            s * weights.get(e.rater, DEFAULT_WEIGHT)
            for s, e in zip(scores, entries)
        ]
        weight_sum = sum(weights.get(e.rater, DEFAULT_WEIGHT) for e in entries)
        weighted_avg = sum(weighted_scores) / weight_sum if weight_sum > 0 else avg

        return ReputationScore(
            subject=subject,
            context=context or "*",
            total_entries=len(entries),
            average=round(avg, 2),
            weighted_average=round(weighted_avg, 2),
            min_score=min(scores),
            max_score=max(scores),
            raters=[e.rater for e in entries],
            last_rated=max(e.timestamp for e in entries),
        )

    def get_all_scores(
        self,
        subject: Optional[str] = None,
    ) -> Dict[str, Dict[str, ReputationScore]]:
        """每个 agent 在每个 context 下的评分。O(N) 而非 O(N²)。"""
        entries = self._load_all()
        if subject:
            entries = [e for e in entries if e.subject == subject]

        result: Dict[str, Dict[str, ReputationScore]] = defaultdict(dict)
        # 一次性扫一遍，传入 cache 避免 get_score 内再 _load_all
        pairs = {(e.subject, e.context) for e in entries}
        for subj, ctx in pairs:
            score = self.get_score(subj, context=ctx, _entries_cache=entries)
            if score.total_entries > 0:
                result[subj][ctx] = score
        return dict(result)

    def top_agents(
        self,
        context: Optional[str] = None,
        limit: int = 10,
    ) -> List[ReputationScore]:
        """Top N by weighted_average。复用一次性 entries 缓存。"""
        entries = self._load_all()
        subjects = {e.subject for e in entries}
        results = []
        for subj in subjects:
            score = self.get_score(subj, context=context, _entries_cache=entries)
            if score.total_entries > 0:
                results.append(score)
        results.sort(key=lambda s: s.weighted_average, reverse=True)
        return results[:limit]

    #

    def trust_graph(
        self,
        max_depth: int = 2,
    ) -> Dict[str, Any]:
        """

        Returns:
            {
                "nodes": {agent_id: {global_score, rating_count}},
                "edges": [(rater, subject, score, context), ...]
            }
        """
        entries = self._load_all()
        nodes: Dict[str, dict] = {}
        edges: list = []

        for e in entries:
            for agent in [e.rater, e.subject]:
                if agent not in nodes:
                    score = self.get_score(agent)
                    nodes[agent] = {
                        "global_score": score.weighted_average,
                        "rating_count": score.total_entries,
                    }
            edges.append((e.rater, e.subject, e.score, e.context))

        return {"nodes": nodes, "edges": edges}

    def compute_trust_weights(self) -> Dict[str, float]:
        """

        rater

        Returns:
            {rater_id: weight (0.0-1.0)}
        """
        entries = self._load_all()
        raters = set(e.rater for e in entries)
        weights = {}

        for rater in raters:
            score = self.get_score(rater)
            if score.total_entries >= 3:
                #
                weights[rater] = score.weighted_average / SCORE_MAX
            else:
                #
                weights[rater] = 0.5

        return weights

    #   /

    def export_entries(
        self,
        subject: Optional[str] = None,
        context: Optional[str] = None,
        since: Optional[str] = None,
    ) -> List[dict]:
        """"""
        entries = self._load_all()

        if subject:
            entries = [e for e in entries if e.subject == subject]
        if context:
            entries = [e for e in entries if e.context == context]
        if since:
            entries = [e for e in entries if e.timestamp > since]

        return [e.to_dict() for e in entries]

    def import_batch(self, entries_data: List[dict]) -> int:
        """"""
        imported = 0
        for data in entries_data:
            try:
                entry = ReputationEntry.from_dict(data)
                if self.import_entry(entry):
                    imported += 1
            except Exception:
                continue
        return imported

    #

    def stats(self) -> Dict[str, Any]:
        """"""
        entries = self._load_all()
        subjects = set(e.subject for e in entries)
        contexts = set(e.context for e in entries)

        return {
            "total_ratings": len(entries),
            "unique_subjects": len(subjects),
            "unique_contexts": len(contexts),
            "contexts": sorted(contexts),
            "top_rated": [
                {
                    "agent": s,
                    "score": self.get_score(s).weighted_average,
                    "count": self.get_score(s).total_entries,
                }
                for s in sorted(subjects, key=lambda s: self.get_score(s).weighted_average, reverse=True)[:5]
            ],
        }

    #

    def _my_file(self) -> Path:
        return self.base_dir / f"{safe_id(self.agent_id)}.json"

    def _load_all(self) -> List[ReputationEntry]:
        """加载所有 agent 文件的全部 entries。

        注意：调用方应该缓存结果。get_score/get_all_scores 现已重写避免反复调用。
        """
        entries = []
        for f in sorted(self.base_dir.glob("*.json")):
            data = safe_load_json(f, fallback=None)
            if data is None:
                continue
            if isinstance(data, list):
                for item in data:
                    try:
                        entries.append(ReputationEntry.from_dict(item))
                    except Exception:
                        continue
            elif isinstance(data, dict):
                try:
                    entries.append(ReputationEntry.from_dict(data))
                except Exception:
                    continue
        return entries

    def _append(self, entry: ReputationEntry) -> None:
        file_path = self._my_file()
        existing = safe_load_json(file_path, fallback=[])
        if not isinstance(existing, list):
            existing = []
        existing.append(entry.to_dict())
        atomic_write_json(file_path, existing)
