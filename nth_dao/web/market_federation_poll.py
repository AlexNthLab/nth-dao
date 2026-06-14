"""任务市场联邦·拉取侧(FED-2)。

对每个 peer:拉 digest → ``verify_digest``(provenance)→ 据 refs 拉全文 →
``verify_announcement``(真相)→ 收下未过期的。两层验签照搬 federation.py 的
信任模型:digest 是不可信提示,全文的 publisher_sig 才是权威。

传输可注入(``http_get``):生产用 urllib,测试用另一节点的 TestClient ——
核心拉取/验签逻辑与网络解耦,可纯函数测试。

注意:本节点**只展示**联邦发现到的外部公告(放进内存缓存,不写本地 feed、
不进自己的 digest →不放大转发)。认领权威仍在公告的主 DAO(见
federation.py docstring),跨 DAO 认领是后续的事。
"""
from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional

from nth_dao.execution_receipt import now_ms
from nth_dao.market.announcement import TaskAnnouncement, verify_announcement
from nth_dao.market.federation import FeedDigest, verify_digest

logger = logging.getLogger(__name__)

# url -> 解析好的 JSON(dict/list);失败抛异常。
HttpGetJson = Callable[[str], Any]

_PULL_BATCH = 100   # 一次 pull 的 id 上限(serve 侧封顶 200,这里留余量)
_MAX_DIGEST_PAGES = 50   # digest 翻页安全上限(防恶意 peer 永不收敛)
_HTTP_TIMEOUT_S = 8.0


def _urllib_get_json(url: str) -> Any:
    req = urllib.request.Request(
        url, headers={"Accept": "application/json"}, method="GET")
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_S) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8"))


def _collect_ids_via_digest(
    base: str, http_get: HttpGetJson,
) -> Optional[List[str]]:
    """增量翻页拉对端 digest,收集所有 ref 的 announcement_id(去重保序)。

    带 ``since=high_seq`` 一页页翻,直到游标不再推进(到底)或撞安全上限。
    任一页 provenance 验不过 → 返回 None(整个 peer 不可信,fail-closed)。
    """
    collected: List[str] = []
    seen: set = set()
    cursor = -1
    for _ in range(_MAX_DIGEST_PAGES):
        try:
            draw = http_get(
                f"{base}/api/v2/market/federation/digest?since={cursor}")
        except Exception as exc:  # noqa: BLE001
            logger.debug("fed: digest fetch failed %s: %s", base, exc)
            break
        if not isinstance(draw, dict):
            break
        try:
            digest = FeedDigest.from_dict(draw)
        except Exception:  # noqa: BLE001
            break
        ok, why = verify_digest(digest)   # provenance:source_did 签的这批 refs
        if not ok:
            logger.warning("fed: peer %s digest verify failed: %s", base, why)
            return None
        for r in digest.refs:
            if isinstance(r, dict) and isinstance(r.get("announcement_id"), str):
                aid = r["announcement_id"]
                if aid not in seen:
                    seen.add(aid)
                    collected.append(aid)
        if digest.high_seq <= cursor:   # 游标没推进 → 到底/防死循环
            break
        cursor = digest.high_seq
    return collected


def pull_from_peer(
    peer_base: str, http_get: HttpGetJson = _urllib_get_json,
) -> List[TaskAnnouncement]:
    """从一个 peer 拉取**已双层验签**的开放公告(digest 翻页 + 全文分批拉)。

    provenance 验不过 / 任何失败 → 返回 [](fail-closed)。
    """
    base = peer_base.rstrip("/")
    ids = _collect_ids_via_digest(base, http_get)
    if not ids:   # None(不可信)或 [](无活)
        return []
    out: List[TaskAnnouncement] = []
    for i in range(0, len(ids), _PULL_BATCH):
        batch = ids[i:i + _PULL_BATCH]
        try:
            praw = http_get(
                f"{base}/api/v2/market/federation/pull?ids={','.join(batch)}")
        except Exception as exc:  # noqa: BLE001
            logger.debug("fed: pull failed %s: %s", base, exc)
            continue
        if not isinstance(praw, list):
            continue
        for item in praw:
            if not isinstance(item, dict):
                continue
            try:
                ann = TaskAnnouncement.from_dict(item)
            except Exception:  # noqa: BLE001
                continue
            vok, _ = verify_announcement(ann)   # 真相层:publisher_sig 必须过
            if vok:
                out.append(ann)
    return out


def federate_once(
    peers: List[str],
    http_get: HttpGetJson = _urllib_get_json,
    *,
    now_ms_override: int = 0,
) -> Dict[str, Dict[str, Any]]:
    """对所有 peer 拉一轮,返回 {announcement_id: {"ann":.., "source": peer}}。

    去重(多 peer 中继同一公告 → 先到先得)+ 跳过已过期。
    """
    now = now_ms_override or now_ms()
    merged: Dict[str, Dict[str, Any]] = {}
    for peer in peers:
        for ann in pull_from_peer(peer, http_get):
            if ann.announcement_id in merged:
                continue
            if ann.is_expired(now_ms_override=now):
                continue
            merged[ann.announcement_id] = {"ann": ann, "source": peer}
    return merged


class FederationCache:
    """联邦发现缓存:{id: {"ann": TaskAnnouncement, "source": peer}}。

    poller 整体替换(replace_all),market/open 读快照(snapshot)。整体替换
    +快照拷贝避免读写竞争。
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._data: Dict[str, Dict[str, Any]] = {}

    def replace_all(self, entries: Dict[str, Dict[str, Any]]) -> None:
        with self._lock:
            self._data = entries

    def snapshot(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return dict(self._data)


def start_poller(
    get_peers: Callable[[], List[str]],
    cache: FederationCache,
    *,
    interval_s: float = 20.0,
    http_get: HttpGetJson = _urllib_get_json,
) -> threading.Thread:
    """起后台 poller:周期性 federate_once → 刷新 cache。daemon,整体 try 兜底。"""

    def loop() -> None:
        while True:
            try:
                peers = [p for p in get_peers() if p]
                if peers:
                    cache.replace_all(federate_once(peers, http_get))
            except Exception as exc:  # noqa: BLE001
                logger.warning("fed poller cycle failed: %s", exc)
            time.sleep(interval_s)

    th = threading.Thread(target=loop, daemon=True, name="nth-market-federation")
    th.start()
    return th
