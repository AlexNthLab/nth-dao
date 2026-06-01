"""
Marketplace  Agent  /  /

 Agent  Agent
credits Agent-to-Agent


- open  claimed  in_progress  completed/failed/cancelled
-
- credits
-
-  review
- team_marketplace/orders/{order_id}.json
-  order timeline


      create_order("review PR #42", reward=10)
      claim(order_id)          #
      submit(order_id, proof)  #
      accept(order_id)          #
      reject(order_id, reason)  #


    mkt = team.marketplace

    #
    order = mkt.create_order(
        title="review PR #42",
        description="need thorough code review of the auth module",
        context="code_review",
        reward=10,
        min_reputation=3.0,
    )

    #
    available = mkt.list_open()

    #
    mkt.claim(available[0].order_id)

    #
    mkt.submit(order_id, proof="review completed, 3 issues found")

    #
    mkt.accept(order_id, rating=4.5, note="great work!")
"""

from __future__ import annotations

import json
import logging
import os
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from .identity import AgentIdentity
from .channel import TeamChannel
from .reputation import ReputationManager
from .util import atomic_write_json, safe_load_json, safe_id as _safe_id_util

logger = logging.getLogger("nth_dao.marketplace")


#

DEFAULT_MARKETPLACE_DIR = "team_marketplace"
DEFAULT_CLAIM_TIMEOUT_HOURS = 48  #
DEFAULT_ORDER_EXPIRY_DAYS = 7     #


#


class OrderStatus(str, Enum):
    OPEN = "open"
    CLAIMED = "claimed"
    IN_PROGRESS = "in_progress"
    SUBMITTED = "submitted"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    DISPUTED = "disputed"
    EXPIRED = "expired"


#


@dataclass
class TaskOrder:
    """"""

    order_id: str
    creator: str          #  agent_id
    title: str
    description: str = ""
    context: str = "general"  # code_review / bug_fix / research / write_docs / deploy / custom
    reward: float = 0.0   #
    deadline: str = ""    # ISO timestamp =
    tags: List[str] = field(default_factory=list)
    requirements: Dict[str, Any] = field(default_factory=dict)  # min_reputation, capabilities

    #
    status: OrderStatus = OrderStatus.OPEN
    claimant: str = ""    #  agent_id
    submission_proof: str = ""  #
    submission_at: str = ""
    rating: float = 0.0   #
    feedback: str = ""     #

    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    claimed_at: str = ""
    completed_at: str = ""

    # timeline
    timeline: List[Dict[str, Any]] = field(default_factory=list)

    #
    creator_sig: str = ""
    claimant_sig: str = ""

    def __post_init__(self):
        if not self.timeline:
            self.timeline = [{
                "action": "created",
                "actor": self.creator,
                "timestamp": self.created_at,
            }]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "TaskOrder":
        status_raw = data.get("status", "open")
        try:
            status = OrderStatus(status_raw)
        except ValueError:
            status = OrderStatus.OPEN

        return cls(
            order_id=data.get("order_id", ""),
            creator=data.get("creator", ""),
            title=data.get("title", ""),
            description=data.get("description", ""),
            context=data.get("context", "general"),
            reward=float(data.get("reward", 0)),
            deadline=data.get("deadline", ""),
            tags=data.get("tags", []),
            requirements=data.get("requirements", {}),
            status=status,
            claimant=data.get("claimant", ""),
            submission_proof=data.get("submission_proof", ""),
            submission_at=data.get("submission_at", ""),
            rating=float(data.get("rating", 0)),
            feedback=data.get("feedback", ""),
            created_at=data.get("created_at", ""),
            claimed_at=data.get("claimed_at", ""),
            completed_at=data.get("completed_at", ""),
            timeline=data.get("timeline", []),
            creator_sig=data.get("creator_sig", ""),
            claimant_sig=data.get("claimant_sig", ""),
        )

    @property
    def is_active(self) -> bool:
        return self.status in (
            OrderStatus.OPEN,
            OrderStatus.CLAIMED,
            OrderStatus.IN_PROGRESS,
            OrderStatus.SUBMITTED,
            OrderStatus.DISPUTED,
        )

    @property
    def is_finished(self) -> bool:
        return self.status in (
            OrderStatus.COMPLETED,
            OrderStatus.FAILED,
            OrderStatus.CANCELLED,
            OrderStatus.EXPIRED,
        )

    @property
    def short_id(self) -> str:
        return self.order_id[:8]

    def __repr__(self) -> str:
        return (
            f"[{self.status.value}] {self.short_id}: {self.title[:40]} "
            f"(reward={self.reward}, creator={self.creator[:8]})"
        )


#  TaskMarketplace


class TaskMarketplace:
    """Agent """

    def __init__(
        self,
        workspace: Path,
        agent_id: str,
        identity: Optional[AgentIdentity] = None,
        channel: Optional[TeamChannel] = None,
        reputation: Optional[ReputationManager] = None,
        marketplace_dir: str = DEFAULT_MARKETPLACE_DIR,
    ):
        """
        Args:
            workspace:
            agent_id:  Agent ID
            identity:
            channel:
            reputation:
            marketplace_dir:
        """
        self.workspace = workspace
        self.agent_id = agent_id
        self.identity = identity
        self.channel = channel
        self.reputation = reputation
        self.orders_dir = workspace / marketplace_dir
        self.orders_dir.mkdir(parents=True, exist_ok=True)

        # 同一进程内对 credits 做线程互斥；跨进程靠 atomic_write_json + file lock
        self._credit_lock = threading.RLock()
        self._credit_file = workspace / marketplace_dir / f"{self._safe_id(agent_id)}_credits.json"
        self._credit_ledger = workspace / marketplace_dir / f"{self._safe_id(agent_id)}_credits.ledger.jsonl"
        self._init_credits()

    #

    def _init_credits(self) -> None:
        if not self._credit_file.exists():
            self._write_credits(100.0, txn=None)  # 新 agent 100 起手

    def _read_credits(self) -> float:
        data = safe_load_json(self._credit_file, fallback=None)
        if not isinstance(data, dict):
            return 0.0
        try:
            return float(data.get("balance", 0))
        except (TypeError, ValueError):
            return 0.0

    def _write_credits(self, balance: float, txn: Optional[Dict[str, Any]]) -> None:
        """更新余额并追加一条 ledger 记录。

        ledger 是 append-only jsonl，每次变动一行 {ts, balance_before, balance_after, txn}。
        即使余额文件丢失也可以从 ledger 重建，便于审计 / 双花检测。
        """
        atomic_write_json(
            self._credit_file,
            {"agent_id": self.agent_id, "balance": round(balance, 2)},
        )
        if txn is not None:
            entry = {
                "ts": datetime.now().isoformat(),
                "agent_id": self.agent_id,
                "balance_after": round(balance, 2),
                **txn,
            }
            self._credit_ledger.parent.mkdir(parents=True, exist_ok=True)
            with open(self._credit_ledger, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def _transfer_credits(
        self,
        delta: float,
        order_id: str,
        kind: str,
    ) -> float:
        """原子地 +/- 余额。delta<0 时检查不能透支。

        Returns:
            新余额
        Raises:
            ValueError: 余额不足
        """
        with self._credit_lock:
            before = self._read_credits()
            after = round(before + delta, 2)
            if after < 0 - 1e-9:
                raise ValueError(
                    f"insufficient credits: balance={before}, requested delta={delta}"
                )
            self._write_credits(after, txn={
                "kind": kind,
                "delta": round(delta, 2),
                "balance_before": before,
                "order_id": order_id,
            })
            return after

    @property
    def balance(self) -> float:
        return self._read_credits()

    #

    def create_order(
        self,
        title: str,
        description: str = "",
        context: str = "general",
        reward: float = 0.0,
        deadline: Optional[str] = None,
        tags: Optional[List[str]] = None,
        min_reputation: float = 0.0,
        required_capabilities: Optional[List[str]] = None,
    ) -> TaskOrder:
        """

        Args:
            title:
            description:
            context:
            reward:
            deadline: ISO
            tags:
            min_reputation:
            required_capabilities:

        Returns:


        Raises:
            ValueError:
        """
        # 预扣验证（真正的扣款放到 order 创建后做，否则 fail 时会扣了又退）
        if reward < 0:
            raise ValueError("reward must be >= 0")
        if reward > 0 and self._read_credits() < reward:
            raise ValueError(
                f"Insufficient credits: balance={self._read_credits()}, "
                f"reward={reward}"
            )

        order = TaskOrder(
            order_id=uuid.uuid4().hex,
            creator=self.agent_id,
            title=title,
            description=description,
            context=context,
            reward=reward,
            deadline=deadline or "",
            tags=tags or [],
            requirements={
                "min_reputation": min_reputation,
                "capabilities": required_capabilities or [],
            },
        )

        #
        if self.identity and self.identity.can_sign:
            payload = {
                "order_id": order.order_id,
                "creator": order.creator,
                "title": order.title,
                "reward": order.reward,
                "created_at": order.created_at,
            }
            order.creator_sig = self.identity.sign_json(payload)

        # 通过 ledger 扣款（双花防护）
        if reward > 0:
            self._transfer_credits(-reward, order_id=order.order_id, kind="escrow_lock")

        self._save(order)

        #
        if self.channel:
            self.channel.send(
                f" New task: {title} (reward={reward} credits, context={context})",
                scope="team",
                metadata={"type": "marketplace", "order_id": order.order_id},
            )

        return order

    #

    def claim(self, order_id: str) -> TaskOrder:
        """

        Args:
            order_id:  ID

        Raises:
            ValueError:
            PermissionError:
        """
        order = self._load(order_id)
        if order is None:
            raise ValueError(f"Order not found: {order_id}")

        if order.status != OrderStatus.OPEN:
            raise ValueError(f"Order {order_id[:8]} is {order.status.value}, not open")

        if order.creator == self.agent_id:
            raise ValueError("Cannot claim your own order")

        #
        min_rep = order.requirements.get("min_reputation", 0)
        if min_rep > 0 and self.reputation:
            score = self.reputation.get_score(self.agent_id, context=order.context)
            if score.weighted_average < min_rep:
                raise PermissionError(
                    f"Reputation too low: {score.weighted_average:.1f} < {min_rep} "
                    f"for context [{order.context}]"
                )

        now = datetime.now().isoformat()
        order.status = OrderStatus.CLAIMED
        order.claimant = self.agent_id
        order.claimed_at = now
        order.timeline.append({
            "action": "claimed",
            "actor": self.agent_id,
            "timestamp": now,
        })

        #
        if self.identity and self.identity.can_sign:
            payload = {
                "order_id": order.order_id,
                "claimant": self.agent_id,
                "claimed_at": now,
            }
            order.claimant_sig = self.identity.sign_json(payload)

        self._save(order)

        #
        if self.channel:
            self.channel.dm(
                order.creator,
                f" Your task '{order.title}' was claimed by "
                f"{self.agent_id[:8]}",
            )

        return order

    #

    def start_work(self, order_id: str) -> TaskOrder:
        """"""
        order = self._require_my_claim(order_id)
        order.status = OrderStatus.IN_PROGRESS
        order.timeline.append({
            "action": "started",
            "actor": self.agent_id,
            "timestamp": datetime.now().isoformat(),
        })
        self._save(order)
        return order

    def submit(self, order_id: str, proof: str) -> TaskOrder:
        """

        Args:
            order_id:  ID
            proof:  /

        Raises:
            ValueError:
        """
        order = self._require_my_claim(order_id)
        if order.status not in (OrderStatus.CLAIMED, OrderStatus.IN_PROGRESS):
            raise ValueError(
                f"Order {order_id[:8]} is {order.status.value}, "
                f"cannot submit"
            )

        now = datetime.now().isoformat()
        order.status = OrderStatus.SUBMITTED
        order.submission_proof = proof
        order.submission_at = now
        order.timeline.append({
            "action": "submitted",
            "actor": self.agent_id,
            "timestamp": now,
            "proof": proof[:200],
        })

        self._save(order)

        #
        if self.channel:
            self.channel.dm(
                order.creator,
                f" Task '{order.title}' submitted by {self.agent_id[:8]}: "
                f"{proof[:100]}",
            )

        return order

    #

    def accept(
        self,
        order_id: str,
        rating: float = 5.0,
        feedback: str = "",
    ) -> TaskOrder:
        """

        Args:
            order_id:  ID
            rating:  (0.0-5.0)
            feedback:
        """
        order = self._require_my_order(order_id)
        if order.status != OrderStatus.SUBMITTED:
            raise ValueError(
                f"Order {order_id[:8]} is {order.status.value}, not submitted"
            )

        now = datetime.now().isoformat()
        order.status = OrderStatus.COMPLETED
        order.rating = max(0, min(5, rating))
        order.feedback = feedback
        order.completed_at = now
        order.timeline.append({
            "action": "completed",
            "actor": self.agent_id,
            "timestamp": now,
            "rating": order.rating,
        })

        self._save(order)

        #
        if self.reputation:
            self.reputation.rate(
                subject=order.claimant,
                context=order.context,
                score=order.rating,
                reason=feedback or f"Completed: {order.title}",
            )

        #
        if self.channel:
            self.channel.dm(
                order.claimant,
                f" Your task '{order.title}' was accepted! "
                f"Rating: {order.rating}/5.0. You earned {order.reward} credits.",
            )

        return order

    def reject(
        self,
        order_id: str,
        reason: str = "",
    ) -> TaskOrder:
        """驳回 submitted 状态的订单，重新开放。

        修复了原版本两个 bug：
            1) hasattr 检查不存在的 claimant_history → DM 永远发到 "unknown"
            2) 先清空 claimant 再用 claimant → 通知发不到原 claimant
        现在：先记下 claimant，再清空，最后 DM。
        """
        order = self._require_my_order(order_id)
        if order.status != OrderStatus.SUBMITTED:
            raise ValueError(
                f"Order {order_id[:8]} is {order.status.value}, not submitted"
            )

        rejected_claimant = order.claimant  # 先记下来！
        now = datetime.now().isoformat()
        order.status = OrderStatus.OPEN
        order.claimant = ""
        order.claimant_sig = ""
        order.submission_proof = ""
        order.submission_at = ""
        order.timeline.append({
            "action": "rejected",
            "actor": self.agent_id,
            "timestamp": now,
            "reason": reason,
            "rejected_claimant": rejected_claimant,
        })

        self._save(order)

        if self.channel and rejected_claimant:
            try:
                self.channel.dm(
                    rejected_claimant,
                    f"Your submission for '{order.title}' was rejected: {reason}",
                )
            except Exception as e:
                logger.warning("reject DM failed: %s", e)

        return order

    def cancel(self, order_id: str) -> TaskOrder:
        """"""
        order = self._require_my_order(order_id)
        if order.status not in (OrderStatus.OPEN, OrderStatus.EXPIRED):
            raise ValueError(
                f"Cannot cancel order in {order.status.value} state"
            )

        order.status = OrderStatus.CANCELLED
        order.timeline.append({
            "action": "cancelled",
            "actor": self.agent_id,
            "timestamp": datetime.now().isoformat(),
        })

        # 取消订单 → 退还冻结金额
        if order.reward > 0:
            self._transfer_credits(
                +order.reward, order_id=order.order_id, kind="escrow_refund_cancel"
            )

        self._save(order)
        return order

    def fail(self, order_id: str, reason: str = "") -> TaskOrder:
        """"""
        order = self._require_my_claim(order_id)
        if order.status not in (OrderStatus.CLAIMED, OrderStatus.IN_PROGRESS):
            raise ValueError(
                f"Order {order_id[:8]} is {order.status.value}, cannot fail"
            )

        order.status = OrderStatus.FAILED
        order.timeline.append({
            "action": "failed",
            "actor": self.agent_id,
            "timestamp": datetime.now().isoformat(),
            "reason": reason,
        })

        self._save(order)
        return order

    #

    def list_open(self, context: Optional[str] = None) -> List[TaskOrder]:
        """"""
        orders = []
        for f in self.orders_dir.glob("*.json"):
            try:
                o = TaskOrder.from_dict(json.loads(f.read_text(encoding="utf-8")))
                if o.status == OrderStatus.OPEN:
                    if context is None or o.context == context:
                        orders.append(o)
            except Exception:
                continue

        #
        orders.sort(key=lambda o: o.created_at, reverse=True)
        return orders

    def list_my_orders(
        self,
        status: Optional[OrderStatus] = None,
    ) -> List[TaskOrder]:
        """"""
        orders = []
        for f in self.orders_dir.glob("*.json"):
            try:
                o = TaskOrder.from_dict(json.loads(f.read_text(encoding="utf-8")))
                if o.creator == self.agent_id or o.claimant == self.agent_id:
                    if status is None or o.status == status:
                        orders.append(o)
            except Exception:
                continue

        orders.sort(key=lambda o: o.created_at, reverse=True)
        return orders

    def list_by_context(self, context: str) -> List[TaskOrder]:
        """"""
        return self.list_open(context=context)

    def get_order(self, order_id: str) -> Optional[TaskOrder]:
        return self._load(order_id)

    #

    def stats(self) -> Dict[str, Any]:
        stats = {
            "total": 0,
            "open": 0,
            "claimed": 0,
            "in_progress": 0,
            "submitted": 0,
            "completed": 0,
            "failed": 0,
            "cancelled": 0,
            "total_reward": 0.0,
        }

        for f in self.orders_dir.glob("*.json"):
            try:
                o = TaskOrder.from_dict(json.loads(f.read_text(encoding="utf-8")))
                stats["total"] += 1
                stats[o.status.value] = stats.get(o.status.value, 0) + 1
                if o.status == OrderStatus.COMPLETED:
                    stats["total_reward"] += o.reward
            except Exception:
                continue

        stats["balance"] = self.balance
        return stats

    #

    def check_expired(self) -> int:
        """"""
        now = datetime.now()
        expired_count = 0

        for f in self.orders_dir.glob("*.json"):
            try:
                o = TaskOrder.from_dict(json.loads(f.read_text(encoding="utf-8")))
                if not o.is_active:
                    continue

                created = datetime.fromisoformat(o.created_at)

                #
                if o.status == OrderStatus.OPEN:
                    if (now - created).days >= DEFAULT_ORDER_EXPIRY_DAYS:
                        o.status = OrderStatus.EXPIRED
                        o.timeline.append({
                            "action": "expired",
                            "actor": "system",
                            "timestamp": now.isoformat(),
                        })
                        self._save(o)
                        # 到期 → 退还冻结金额
                        if o.reward > 0:
                            self._transfer_credits(
                                +o.reward,
                                order_id=o.order_id,
                                kind="escrow_refund_expired",
                            )
                        expired_count += 1

                #
                if o.status in (OrderStatus.CLAIMED, OrderStatus.IN_PROGRESS) and o.claimed_at:
                    claimed = datetime.fromisoformat(o.claimed_at)
                    if (now - claimed).total_seconds() > DEFAULT_CLAIM_TIMEOUT_HOURS * 3600:
                        o.status = OrderStatus.OPEN
                        o.claimant = ""
                        o.claimant_sig = ""
                        o.timeline.append({
                            "action": "claim_expired",
                            "actor": "system",
                            "timestamp": now.isoformat(),
                        })
                        self._save(o)
                        expired_count += 1

            except Exception:
                continue

        return expired_count

    #

    def _require_my_order(self, order_id: str) -> TaskOrder:
        order = self._load(order_id)
        if order is None:
            raise ValueError(f"Order not found: {order_id}")
        if order.creator != self.agent_id:
            raise PermissionError(
                f"Order {order_id[:8]} belongs to {order.creator[:8]}, not you"
            )
        return order

    def _require_my_claim(self, order_id: str) -> TaskOrder:
        order = self._load(order_id)
        if order is None:
            raise ValueError(f"Order not found: {order_id}")
        if order.claimant != self.agent_id:
            raise PermissionError(
                f"Order {order_id[:8]} is claimed by "
                f"{order.claimant[:8] if order.claimant else 'no one'}, not you"
            )
        return order

    def _load(self, order_id: str) -> Optional[TaskOrder]:
        path = self.orders_dir / f"{_safe_id_util(order_id)}.json"
        data = safe_load_json(path, fallback=None)
        if data is None:
            return None
        try:
            return TaskOrder.from_dict(data)
        except Exception:
            return None

    def _save(self, order: TaskOrder) -> None:
        path = self.orders_dir / f"{_safe_id_util(order.order_id)}.json"
        atomic_write_json(path, order.to_dict())

    @staticmethod
    def _safe_id(agent_id: str) -> str:
        return _safe_id_util(agent_id)
