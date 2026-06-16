"""社交语句联邦·拉取侧。

对每个 peer(配置的 seed + gossip 传递发现的)拉 ``/social/federation/pull``,
只留 ``target==自己`` 的语句,交 ``ingest_social_statements`` 验签 + 去重 + 落本地
spine。复用 market 联邦的 SSRF 公网校验与 peer 成员发现(同一 /federation/peers),
不另造一套传输。

传输可注入(``http_get``):生产用 urllib,测试用对端 TestClient —— 拉取逻辑与
网络解耦,可纯函数测两节点端到端。
"""
from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Any, Callable, List

from nth_dao.social.federation import ingest_social_statements

from .market_federation_poll import (
    _MAX_GOSSIP_PEERS,
    HttpGetJson,
    _is_safe_gossip_url,
    _urllib_get_json,
    fetch_peer_list,
)

logger = logging.getLogger(__name__)

_PULL_PAGE = 500
_MAX_PULL_PAGES = 20   # 翻页安全上限,防恶意 peer 永不收敛


def pull_social_from_peer(
    peer_base: str, http_get: HttpGetJson, *, target_did: str,
) -> List[dict]:
    """翻页拉一个 peer 的社交语句,留下 ``target==target_did`` 的(原始,未验签;
    验签 + 去重在 ingest 统一做)。任何失败 → 已拉到的照常返回(best-effort)。"""
    base = peer_base.rstrip("/")
    out: List[dict] = []
    since = -1
    for _ in range(_MAX_PULL_PAGES):
        try:
            raw = http_get(
                f"{base}/api/v2/social/federation/pull?since={since}")
        except Exception as exc:  # noqa: BLE001
            logger.debug("social-fed: pull failed %s: %s", base, exc)
            break
        if not isinstance(raw, list) or not raw:
            break
        page_max = since
        for item in raw:
            if not isinstance(item, dict):
                continue
            seq = item.get("seq")
            stmt = item.get("statement")
            if isinstance(seq, int) and seq > page_max:
                page_max = seq
            if isinstance(stmt, dict) and stmt.get("target_did") == target_did:
                out.append(stmt)
        if page_max <= since:   # 游标没推进 → 到底
            break
        since = page_max
        if len(raw) < _PULL_PAGE:
            break
    return out


def federate_social_once(
    self_did: str,
    peers: List[str],
    spine: Any,
    http_get: HttpGetJson = _urllib_get_json,
    *,
    resolve: Callable[..., list] = socket.getaddrinfo,
    max_peers: int = _MAX_GOSSIP_PEERS,
) -> int:
    """对 peer 图做 BFS:拉每个 peer 给我的社交语句 + 学它的 peer 列表传递发现,
    汇总后一次性 ingest 进本地 spine。返回记录条数。

    seed peer(运营者配置)直连不过 SSRF 校验;**gossip 发现的**(不可信)peer
    必须过公网校验才入队(挡 SSRF),与 market 联邦同一套防护。
    """
    seen: set = set()
    queue: List[str] = list(dict.fromkeys(
        p.rstrip("/") for p in peers if p and p.strip()))
    collected: List[dict] = []
    while queue and len(seen) < max_peers:
        peer = queue.pop(0)
        if peer in seen:
            continue
        seen.add(peer)
        collected.extend(
            pull_social_from_peer(peer, http_get, target_did=self_did))
        for p in fetch_peer_list(peer, http_get):
            nxt = p.rstrip("/")
            if (
                nxt and nxt not in seen and nxt not in queue
                and _is_safe_gossip_url(nxt, resolve=resolve)
                and len(seen) + len(queue) < max_peers
            ):
                queue.append(nxt)
    return ingest_social_statements(spine, collected, self_did)


def start_social_poller(
    get_self_did: Callable[[], str],
    get_peers: Callable[[], List[str]],
    get_spine: Callable[[], Any],
    *,
    interval_s: float = 20.0,
    http_get: HttpGetJson = _urllib_get_json,
) -> threading.Thread:
    """起后台 poller:周期性 federate_social_once。daemon,整体 try 兜底。"""

    def loop() -> None:
        while True:
            try:
                did = get_self_did()
                peers = [p for p in get_peers() if p]
                spine = get_spine()
                if did and peers and spine is not None:
                    n = federate_social_once(did, peers, spine, http_get)
                    if n:
                        logger.info("social-fed: ingested %d statement(s)", n)
            except Exception as exc:  # noqa: BLE001
                logger.warning("social fed poller cycle failed: %s", exc)
            time.sleep(interval_s)

    th = threading.Thread(target=loop, daemon=True, name="nth-social-federation")
    th.start()
    return th
