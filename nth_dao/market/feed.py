"""MarketFeed —— 主动任务市场的"单元模块"（内核心脏）。

修的是 C1：旧 ``broadcast_order`` 是 fire-and-forget DM，Agent 当时
离线就永久错过任务。MarketFeed 把它换成一个**持久、append-only、带
游标可补齐**的时间线：

  - publish(ann)        发布方写入（先验签，再落盘，fsync）
  - poll(since_seq)     Agent 用上次的游标拉取"之后的全部公告"

游标用**序号（append 顺序的行号）**而不是时间戳：
  - append-only 日志永不重排，所以行号单调、稳定。
  - 时间戳游标在"同毫秒两条公告"或时钟回拨时会漏掉记录；序号不会。

这就是 GitHub"快照列表"和主动市场"feed"的根本区别：feed 是
**时间线 + 游标**，离线不丢任务 —— Agent 上线拿旧游标 poll 即补齐。

M1 的 poll 返回"游标之后的全部"，不做能力/兴趣过滤（那是 M2 的
``match.py``）。但 poll 会跳过：验签失败的行（防伪造混入）、已过期
的公告（除非 include_expired=True）。

存储布局：
    <root>/market_feed/announcements.jsonl   # append-only，一行一公告
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, List, Optional, Union

from nth_dao.market.announcement import (
    TaskAnnouncement,
    verify_announcement,
)
from nth_dao.market.projection import EVENT_MARKET_ANNOUNCE
from nth_dao.util.io import InterProcessLock
from nth_dao.util.jsonl_safe import safe_append_jsonl

if TYPE_CHECKING:
    from nth_dao.spine.log import SignedEventLog

logger = logging.getLogger("nth_dao.market.feed")

PathLike = Union[str, Path]


@dataclass
class PollResult:
    """一次 poll 的结果。

    ``announcements`` 按发布顺序（FIFO）排列 —— 先发的先补。
    ``cursor`` 是"下次 poll 应传的 since_seq"：等于本次**实际返回的
    最后一条**公告的序号。若被 limit 截断，cursor 停在已返回的末尾,
    所以下次 poll 会从未读的下一条继续，不会跳过尾巴。
    """

    announcements: List[TaskAnnouncement] = field(default_factory=list)
    cursor: int = -1


class MarketFeed:
    """单 DAO 的任务公告 feed。文件持久、append-only、游标可补齐。"""

    def __init__(
        self, root: PathLike, *, spine: "Optional[SignedEventLog]" = None,
    ) -> None:
        self.root = Path(root) / "market_feed"
        self.root.mkdir(parents=True, exist_ok=True)
        self.log_path = self.root / "announcements.jsonl"
        # Phase 2 影子双写:接线后 publish 同时把公告记入 spine(可选,默认关)。
        self._spine = spine

    # ── 发布 ─────────────────────────────────────────────────────

    def publish(self, ann: TaskAnnouncement) -> None:
        """验签后把公告追加到 feed。

        先验签再落盘是 defense in depth：feed 的持久日志里**永远不会**
        出现一条无法独立验证的公告。这样 poll 的消费者拿到的每一条都
        是可信来源（约束 E），且 C1 的补齐只会补到有效公告。

        Raises:
            ValueError —— 公告验签不过（reason 带在消息里，便于运维定位）。
        """
        ok, reason = verify_announcement(ann)
        if not ok:
            raise ValueError(
                f"refusing to publish unverifiable announcement "
                f"{ann.announcement_id!r}: {reason}"
            )
        # safe_append_jsonl 持锁 + fsync：跨进程并发发布安全，且
        # crash 不会丢已确认的 append。
        safe_append_jsonl(self.log_path, ann.to_dict())
        # Phase 2 影子双写:同时把公告记入 spine(若已接线)。feed 仍是当前
        # 事实源,故 spine 失败**不阻断发布**(best-effort,仅告警);后续 Phase
        # 把读路径切到 spine 前,会反转顺序并改成强一致。
        if self._spine is not None:
            try:
                self._spine.append(EVENT_MARKET_ANNOUNCE, ann.to_dict())
            except Exception:  # noqa: BLE001
                logger.warning(
                    "spine shadow-write failed for announcement %s",
                    ann.announcement_id, exc_info=True,
                )

    # ── 拉取（补齐）──────────────────────────────────────────────

    def poll(
        self,
        since_seq: int = -1,
        *,
        limit: Optional[int] = None,
        include_expired: bool = False,
        now_ms_override: int = 0,
    ) -> PollResult:
        """拉取序号 > since_seq 的公告（FIFO）。

        Args:
            since_seq: 上次的游标。-1（默认）= 从头拉全部。
            limit: 最多返回多少条。None = 不限。截断时 cursor 停在
                已返回的末尾，保证下次从未读处继续。
            include_expired: 默认跳过 not_after 已过的公告。
            now_ms_override: 测试用，钉死"现在"。

        Returns:
            PollResult(announcements=[...], cursor=新游标)。
            无新公告时 announcements 为空、cursor == since_seq。
        """
        records = self._read_all()  # list[(seq, dict)]，seq 即行号

        result = PollResult(announcements=[], cursor=since_seq)
        for seq, raw in records:
            if seq <= since_seq:
                continue
            ann = self._safe_parse(seq, raw)
            if ann is None:
                # 解析/验签失败的行：不计入返回，但 cursor 仍要推进过
                # 它，否则每次 poll 都会卡在这条坏行上反复尝试。
                result.cursor = seq
                continue
            if not include_expired and ann.is_expired(now_ms_override):
                result.cursor = seq
                continue
            if limit is not None and len(result.announcements) >= limit:
                # 已达上限：停止，cursor 停在上一条已返回的位置
                # （不推进到本条，下次 poll 从本条继续）。
                break
            result.announcements.append(ann)
            result.cursor = seq

        return result

    def latest_seq(self) -> int:
        """当前 feed 的最高序号（空 feed 返回 -1）。运维 / 测试用。"""
        records = self._read_all()
        return records[-1][0] if records else -1

    def get(
        self,
        announcement_id: str,
        *,
        include_expired: bool = True,
        now_ms_override: int = 0,
    ) -> Optional[TaskAnnouncement]:
        """按 id 取一条已验签的公告（M3 认领前的查找）。

        feed 是 append-only，理论上同一 id 不会重复；若真重复（异常），
        返回最早的那条（FIFO，第一个写入的为准）。验签不过的跳过。
        include_expired 默认 True —— 认领路径会单独检查过期并给出明确
        reason，所以这里先把公告取出来。
        """
        for seq, raw in self._read_all():
            ann = self._safe_parse(seq, raw)
            if ann is None:
                continue
            if ann.announcement_id == announcement_id:
                if not include_expired and ann.is_expired(now_ms_override):
                    return None
                return ann
        return None

    # ── 内部 ─────────────────────────────────────────────────────

    def _read_all(self) -> List[tuple]:
        """读全部行，返回 [(seq, raw_dict), ...]。

        seq 是 0-based 行号（append-only 保证稳定）。损坏的行仍占一个
        seq（保留位置），但 raw 为 None，由调用方决定怎么处理。

        切行必须用 ``split("\\n")`` 而**不是** ``str.splitlines()``：
        ``safe_append_jsonl`` 用 ``ensure_ascii=False`` 落盘，而
        ``json.dumps`` 只转义 ``\\n``/``\\r``，**不**转义 Unicode 行
        分隔符（U+2028 LINE SEPARATOR / U+2029 / U+0085 NEL /
        U+000B-000C / U+001C-001E）。``splitlines()`` 会在这些字符上
        断行，导致标题/正文里带 U+2028 的公告被切成两半、双双解析失败
        → **永久丢失**（直接违反 C1 "无丢失"）。``json.dumps`` 保证
        一条记录内不会出现裸 ``\\n``，所以 ``split("\\n")`` 是唯一安全的
        行边界。中文/多语种内容里这类字符并不罕见，必须按 \\n 切。
        """
        if not self.log_path.exists():
            return []
        # M4 加固（此前 M1/M3 标的 deferred 读锁项）：读取时持与
        # safe_append_jsonl 同一把 InterProcessLock，关掉"并发 append
        # 写到一半时被读到半行"的窗口。append 写整行+fsync 在锁内完成,
        # 读也在锁内 → 读到的永远是完整行。锁路径 = log_path+".lock",
        # 与 append 一致，二者串行。读很快，锁占用极短。
        try:
            with InterProcessLock(self.log_path):
                text = self.log_path.read_text(encoding="utf-8")
        except OSError as e:
            logger.warning("market feed read failed at %s: %s", self.log_path, e)
            return []
        if not text:
            return []
        lines = text.split("\n")
        # safe_append_jsonl 每条都写成 ``line + "\n"``，所以文件恒为
        # ``r0\nr1\n...rN\n``，split 后末尾必有一个空串 —— 去掉它，让
        # seq / latest_seq 与真实记录数对齐。中间的空行（异常/篡改）
        # 仍占一个 seq 位（raw=None），保持游标稳定。
        if lines and lines[-1] == "":
            lines.pop()
        out: List[tuple] = []
        for seq, line in enumerate(lines):
            stripped = line.strip()
            if not stripped:
                out.append((seq, None))
                continue
            try:
                out.append((seq, json.loads(stripped)))
            except json.JSONDecodeError:
                logger.warning(
                    "corrupt market feed line seq=%d at %s", seq, self.log_path,
                )
                out.append((seq, None))
        return out

    @staticmethod
    def _safe_parse(seq: int, raw: Optional[dict]) -> Optional[TaskAnnouncement]:
        """把一行 raw dict 解析成已验签的公告；任何问题返回 None。"""
        if not isinstance(raw, dict):
            return None
        try:
            ann = TaskAnnouncement.from_dict(raw)
        except (TypeError, ValueError):
            logger.warning("market feed seq=%d not a TaskAnnouncement", seq)
            return None
        ok, reason = verify_announcement(ann)
        if not ok:
            # feed 里出现验签不过的公告 = 落盘后被篡改，或绕过 publish
            # 直接写文件。两种都该警告并丢弃。
            logger.warning(
                "market feed seq=%d failed verify (%s) — dropping", seq, reason,
            )
            return None
        return ann
