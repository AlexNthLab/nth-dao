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
from .util import atomic_write_json, file_lock, safe_append_jsonl, safe_load_json, safe_id as _safe_id_util

logger = logging.getLogger("nth_dao.marketplace")


#

DEFAULT_MARKETPLACE_DIR = "team_marketplace"
DEFAULT_CLAIM_TIMEOUT_HOURS = 48  #
DEFAULT_ORDER_EXPIRY_DAYS = 7     #
# 终态订单(完成/失败/取消/过期)本地热缓存保留天数,超期由 prune_finished
# 清理(2026-06-14:存储膨胀的正解是老化终态订单,而非给开放订单设上限)。
DEFAULT_FINISHED_RETENTION_DAYS = 30


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
        # 2026-06-14 审查补:没有 order_id 的记录不是订单。orders_dir 里还
        # 混着同名 *.json 的非订单文件(如 {agent}_credits.json),此前会被
        # from_dict 容忍成"空 OPEN 订单",污染 list_open/stats/check_expired
        # 计数。这里直接拒,各 glob 循环已 catch ValueError 会干净跳过。
        order_id = data.get("order_id", "")
        if not order_id:
            raise ValueError(
                "TaskOrder.from_dict: missing order_id (not an order record)"
            )
        status_raw = data.get("status", "open")
        try:
            status = OrderStatus(status_raw)
        except ValueError:
            status = OrderStatus.OPEN

        return cls(
            order_id=order_id,
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
        finished_retention_days: Optional[int] = None,
    ):
        """
        Args:
            workspace:
            agent_id:  Agent ID
            identity:
            channel:
            reputation:
            marketplace_dir:
            finished_retention_days: 终态订单(完成/失败/取消/过期)在本地热
                缓存的保留天数,超期由 prune_finished() 清理。None →
                NTH_MARKETPLACE_FINISHED_RETENTION_DAYS / 默认 30;<=0 不清理。
        """
        self.workspace = workspace
        self.agent_id = agent_id
        self.identity = identity
        self.channel = channel
        self.reputation = reputation
        # 终态订单本地保留期(2026-06-14:不给开放订单设上限——那是待办的真
        # 实工作;存储膨胀的真因是终态订单永不清理。按"完成的本地缓存一段
        # 时间→温冷处理"的设计,过保留期由 prune_finished 清理。签名证据
        # (receipt/reputation)在各自的 store 里持久,清的只是操作态订单文件。
        if finished_retention_days is None:
            try:
                _ret = int(os.environ.get(
                    "NTH_MARKETPLACE_FINISHED_RETENTION_DAYS", "30"))
            except (TypeError, ValueError):
                _ret = 30
            self._finished_retention_days = _ret if _ret >= 0 else 30
        else:
            self._finished_retention_days = finished_retention_days
        self.orders_dir = workspace / marketplace_dir
        self.orders_dir.mkdir(parents=True, exist_ok=True)

        # Use a thread lock for in-process credit updates; file locks cover cross-process updates
        self._credit_lock = threading.RLock()
        self._credit_file = workspace / marketplace_dir / f"{self._safe_id(agent_id)}_credits.json"
        self._credit_ledger = workspace / marketplace_dir / f"{self._safe_id(agent_id)}_credits.ledger.jsonl"
        self._init_credits()

    #

    def _init_credits(self) -> None:
        if not self._credit_file.exists():
            self._write_credits(100.0, txn=None)  # new agent starts with 100 credits

    def _read_credits(self) -> float:
        data = safe_load_json(self._credit_file, fallback=None)
        if not isinstance(data, dict):
            return 0.0
        try:
            return float(data.get("balance", 0))
        except (TypeError, ValueError):
            return 0.0

    def _write_credits(self, balance: float, txn: Optional[Dict[str, Any]]) -> None:
        """Update balance and append one ledger record.

        The ledger is append-only JSONL: one {ts, balance_before, balance_after, txn} row per change.
        The balance can be rebuilt from the ledger for audit and double-spend detection.
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
            # PR-0 (audit CRITICAL #1) + G-6 (Voss audit): the
            # ledger append happens INSIDE _transfer_credits' file
            # lock (.credit.lock). Tell safe_append_jsonl not to
            # take its own .jsonl.lock - otherwise the credit-file
            # update and the ledger append are in two different
            # transactions, and a crash in between leaves them
            # inconsistent (the audit's reconstructability promise
            # breaks).
            safe_append_jsonl(
                self._credit_ledger, entry, external_lock_held=True,
            )

    def _transfer_credits(
        self,
        delta: float,
        order_id: str,
        kind: str,
    ) -> float:
        """Atomically add/subtract balance. Negative deltas cannot overdraw.

        PR-0 (audit CRITICAL #2 - double-spend race):
            Previously the read-check-write was guarded only by an
            in-process threading.RLock, so two processes that both
            read balance=100 then debited 50 each ended at balance=50
            but had actually spent 100. The InterProcessLock around
            the whole read-check-write closes that window.

        Returns:
            New balance
        Raises:
            ValueError: insufficient balance
        """
        # Threading lock guards INTRA-process concurrency; file lock
        # guards CROSS-process. Both are required.
        with self._credit_lock, file_lock(
            self._credit_file.with_suffix(".credit.lock"), timeout=10.0,
        ):
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
        """Create a new task order.

        Args:
            title: Short task title.
            description: Detailed task description.
            context: Task context (code_review, bug_fix, research, etc.).
            reward: Credits offered for completing this task.
            deadline: ISO timestamp deadline (optional).
            tags: Free-form tags for filtering.
            min_reputation: Minimum reputation score required to claim.
            required_capabilities: Capabilities the claimant must possess.

        Returns:
            The created TaskOrder.

        Raises:
            ValueError: If reward < 0 or insufficient credits.
        """
        # Pre-validate balance before creating the order (actual debit after creation,
        # so failed order creation doesn't require a compensating credit).
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

        # Debit via ledger (double-spend protection)
        if reward > 0:
            self._transfer_credits(-reward, order_id=order.order_id, kind="escrow_lock")

        self._save(order)

        # Broadcast to team channel
        if self.channel:
            self.channel.send(
                f" New task: {title} (reward={reward} credits, context={context})",
                scope="team",
                metadata={"type": "marketplace", "order_id": order.order_id},
            )

        return order

    #

    def claim(self, order_id: str) -> TaskOrder:
        """Claim an open order.

        Args:
            order_id: The order ID.

        Raises:
            ValueError: Order not found, not open, or is your own.
            PermissionError: Reputation score too low for the order context.
        """
        order = self._load(order_id)
        if order is None:
            raise ValueError(f"Order not found: {order_id}")

        if order.status != OrderStatus.OPEN:
            raise ValueError(f"Order {order_id[:8]} is {order.status.value}, not open")

        if order.creator == self.agent_id:
            raise ValueError("Cannot claim your own order")

        # Check reputation requirement
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
        """Reject a submitted order and reopen it.

        Fixes two bugs in the original implementation:
            1) A hasattr check against missing claimant_history sent DMs to "unknown".
            2) Clearing claimant before using it prevented notifying the original claimant.
        Now: remember claimant first, clear it, then send the DM.
        """
        order = self._require_my_order(order_id)
        if order.status != OrderStatus.SUBMITTED:
            raise ValueError(
                f"Order {order_id[:8]} is {order.status.value}, not submitted"
            )

        rejected_claimant = order.claimant  # remember before clearing
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

        # Cancel order -> refund escrowed credits
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
            except (AttributeError, KeyError, OSError, json.JSONDecodeError, TypeError, ValueError) as e:
                logger.debug("skipping unreadable marketplace order %s: %s", f, e)
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
            except (AttributeError, KeyError, OSError, json.JSONDecodeError, TypeError, ValueError) as e:
                logger.debug("skipping unreadable marketplace order %s: %s", f, e)
                continue

        orders.sort(key=lambda o: o.created_at, reverse=True)
        return orders

    def list_by_context(self, context: str) -> List[TaskOrder]:
        """"""
        return self.list_open(context=context)

    def broadcast_order(
        self,
        title: str,
        description: str = "",
        *,
        context: str = "",
        reward: float = 0.0,
        capability: str = "",
        finder: Any = None,   # PeerFinder - avoid circular import
        channel: Any = None,  # TeamChannel - avoid circular import
    ) -> TaskOrder:
        """Create an order and fanout to capable agents via channel.

        When *finder* and *channel* are provided, finds agents with
        ``accepting_tasks=True`` and the required *capability*, then
        DMs each one.  The DM includes the order's ``creator_sig`` so
        the receiver can verify authenticity when the channel has an
        identity configured.  The order is stored with ``creator``
        set to this agent for auditability.

        Usage::

            order = team.marketplace.broadcast_order(
                title="code review PR #42",
                capability="code_review",
                finder=team.finder,
                channel=team.channel,
            )
        """
        order = self.create_order(
            title=title,
            description=description,
            context=context,
            reward=reward,
        )

        # Actual broadcast: fanout to accepting agents
        if finder is not None and channel is not None and capability:
            try:
                targets = finder.find(capability=capability, only_alive=True)
                # Build signed message payload for receiver verification
                sig_info = ""
                if order.creator_sig:
                    sig_info = (
                        f"\nCreator: {order.creator}\n"
                        f"Created: {order.created_at}\n"
                        f"Signature: {order.creator_sig}"
                    )
                for t in targets:
                    # Never broadcast to self
                    if t.agent_id == self.agent_id:
                        continue
                    if getattr(t, "accepting_tasks", False):
                        try:
                            channel.dm(
                                t.agent_id,
                                f"[New Task] {order.title}\n"
                                f"Reward: {order.reward} credits\n"
                                f"ID: {order.order_id}"
                                f"{sig_info}",
                            )
                        except (OSError, RuntimeError, ValueError) as e:
                            logger.debug("broadcast dm to %s failed: %s", t.agent_id, e)
            except (AttributeError, TypeError, ValueError) as e:
                logger.debug("broadcast find failed for %r: %s", capability, e)

        return order

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
            except (AttributeError, KeyError, OSError, json.JSONDecodeError, TypeError, ValueError) as e:
                logger.debug("skipping unreadable marketplace order %s: %s", f, e)
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
                        # Expired -> refund escrowed credits
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

            except (AttributeError, KeyError, OSError, json.JSONDecodeError, TypeError, ValueError) as e:
                logger.debug("skipping unreadable marketplace order %s: %s", f, e)
                continue

        return expired_count

    def prune_finished(self, older_than_days: Optional[int] = None) -> int:
        """老化清理:删除超过保留期的终态订单文件(完成/失败/取消/过期)。

        这是"存储膨胀"的正解(替代之前误加的开放订单上限):开放订单是
        待办的真实工作不该被拒,真正会无界增长的是终态订单永不清理。按
        "完成的本地缓存一段时间→温冷处理":过保留期就从本地热存清掉。
        签名证据(execution receipt、reputation 评分)在各自 store 持久,
        这里清的只是操作态订单文件,不损审计性。

        Args:
            older_than_days: 覆盖默认保留期;None 用实例配置。<=0 不清理。
        Returns:
            清理的订单数。
        """
        retention = (
            self._finished_retention_days if older_than_days is None
            else older_than_days
        )
        if retention <= 0:
            return 0
        cutoff = datetime.now() - timedelta(days=retention)
        pruned = 0
        for f in self.orders_dir.glob("*.json"):
            try:
                o = TaskOrder.from_dict(json.loads(f.read_text(encoding="utf-8")))
            except (AttributeError, KeyError, OSError, json.JSONDecodeError,
                    TypeError, ValueError) as e:
                # 非订单文件(如 {agent}_credits.json)/损坏 → 跳过。
                logger.debug("prune_finished skip %s: %s", f, e)
                continue
            if not o.is_finished:
                continue
            # 终态时间:取 timeline 末条时间戳,回退 completed_at / created_at。
            ts_str = ""
            if o.timeline:
                ts_str = o.timeline[-1].get("timestamp", "") or ""
            ts_str = ts_str or o.completed_at or o.created_at
            try:
                finished_at = datetime.fromisoformat(ts_str)
            except (TypeError, ValueError):
                continue  # 无法判龄 → 保守保留
            if finished_at < cutoff:
                try:
                    f.unlink()
                    pruned += 1
                except OSError as e:
                    logger.debug("prune_finished unlink %s failed: %s", f, e)
        return pruned

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
        except (TypeError, ValueError) as e:
            logger.debug("invalid marketplace order %s: %s", order_id, e)
            return None

    def _save(self, order: TaskOrder) -> None:
        path = self.orders_dir / f"{_safe_id_util(order.order_id)}.json"
        atomic_write_json(path, order.to_dict())

    @staticmethod
    def _safe_id(agent_id: str) -> str:
        return _safe_id_util(agent_id)
