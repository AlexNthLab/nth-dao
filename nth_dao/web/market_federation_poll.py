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

import http.client
import ipaddress
import json
import logging
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlsplit

from nth_dao.execution_receipt import now_ms
from nth_dao.market.announcement import TaskAnnouncement, verify_announcement
from nth_dao.market.federation import FeedDigest, verify_digest

logger = logging.getLogger(__name__)

# url -> 解析好的 JSON(dict/list);失败抛异常。
HttpGetJson = Callable[[str], Any]

_PULL_BATCH = 100   # 一次 pull 的 id 上限(serve 侧封顶 200,这里留余量)
_MAX_DIGEST_PAGES = 50   # digest 翻页安全上限(防恶意 peer 永不收敛)
_MAX_GOSSIP_PEERS = 64   # 一轮 BFS 最多访问多少 peer(传递发现的安全上限)
_HTTP_TIMEOUT_S = 8.0
_MAX_GOSSIP_PEER_LIST = 64
_MAX_HTTP_JSON_BYTES = 512 * 1024


def _urllib_get_json(url: str) -> Any:
    req = urllib.request.Request(
        url, headers={"Accept": "application/json"}, method="GET")
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_S) as resp:  # noqa: S310
        body = resp.read(_MAX_HTTP_JSON_BYTES + 1)
    if len(body) > _MAX_HTTP_JSON_BYTES:
        raise ValueError(f"HTTP response exceeds {_MAX_HTTP_JSON_BYTES} bytes")
    return json.loads(body.decode("utf-8"))


def _urllib_get_bytes_pinned(
    url: str,
    resolved_ip: str,
    *,
    timeout_s: float = _HTTP_TIMEOUT_S,
    max_bytes: int = _MAX_HTTP_JSON_BYTES,
) -> bytes:
    """GET over a previously validated IP while preserving Host/SNI."""
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("pinned HTTP fetch requires an absolute HTTP(S) URL")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("URL contains an invalid port") from exc
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    host_header = parsed.hostname
    if ":" in host_header and not host_header.startswith("["):
        host_header = f"[{host_header}]"
    if port not in {80, 443}:
        host_header = f"{host_header}:{port}"

    sock = socket.create_connection((resolved_ip, port), timeout=timeout_s)
    try:
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=parsed.hostname)
        request = (
            f"GET {target} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "Accept: application/json\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        sock.sendall(request)
        response = http.client.HTTPResponse(sock)
        response.begin()
        if response.status < 200 or response.status >= 300:
            raise urllib.error.HTTPError(
                url,
                response.status,
                response.reason,
                response.headers,
                None,
            )
        body = response.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise ValueError(f"HTTP response exceeds {max_bytes} bytes")
        return body
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _urllib_get_json_pinned(url: str, resolved_ip: str) -> Any:
    return json.loads(
        _urllib_get_bytes_pinned(url, resolved_ip).decode("utf-8")
    )


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


def fetch_peer_list(
    peer_base: str, http_get: HttpGetJson = _urllib_get_json,
) -> List[str]:
    """拉一个 peer 公开的 peer 列表(gossip 的「成员」层)。失败 → []。

    这是**不可信提示**:对端报的 peer 只是线索,本节点会直连那个 peer 再
    双层验签它的任务 —— 恶意 peer 报假地址至多让你白连一次,伪造不了任务。
    """
    base = peer_base.rstrip("/")
    try:
        raw = http_get(f"{base}/api/v2/market/federation/peers")
    except Exception as exc:  # noqa: BLE001
        logger.debug("fed: peer-list fetch failed %s: %s", base, exc)
        return []
    if isinstance(raw, dict):
        peers = raw.get("peers")
        if isinstance(peers, list):
            return [
                p for p in peers
                if isinstance(p, str) and p.strip()
            ][:_MAX_GOSSIP_PEER_LIST]
    return []


def _ip_is_internal(ip: Any) -> bool:
    """该 IP 是否落在内网/元数据/不可路由段(SSRF 必拒)。"""
    return bool(
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


def _is_safe_gossip_url(
    url: str, *, resolve: Callable[..., list] = socket.getaddrinfo,
) -> bool:
    """对 **gossip 发现的(不可信)** peer URL 做 SSRF 防护:必须 https + 公网 host。

    拒 localhost/.local;原始 IP 直接判段;**域名则解析,任一 A/AAAA 落内网/元数据
    段即拒**(挡"注册一个指向内网的域名"绕过 IP 守卫的 SSRF)。解析失败 →
    fail-closed(拒)。

    ⚠️ 残留:DNS rebinding(校验通过后、连接前改解析)需把连接**钉死到已校验的
    IP** 才能根治;正式上线前应叠**网络层出口管控**(只禁 RFC1918/链路本地)做纵深
    防御(见 docs/federation.md)。

    配置的 seed peer **不**走这个(运营者自负其责,允许 http://localhost 等本地联调)。
    ``resolve`` 可注入,默认 ``socket.getaddrinfo``(便于测试不起真 DNS)。
    """
    try:
        u = urlsplit(url)
    except Exception:  # noqa: BLE001
        return False
    if u.scheme != "https":
        return False
    host = (u.hostname or "").lower()
    if not host or host == "localhost" or host.endswith(".local"):
        return False
    # 原始 IP:直接判段(无需解析)。
    try:
        return not _ip_is_internal(ipaddress.ip_address(host))
    except ValueError:
        pass
    # 域名:解析,任一返回 IP 落内网即拒;解析失败/无结果 → fail-closed。
    try:
        infos = resolve(host, None)
    except Exception:  # noqa: BLE001
        return False
    if not infos:
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except (ValueError, IndexError, TypeError):
            return False   # 解析结果不可解读 → 当不安全
        if _ip_is_internal(ip):
            return False
    return True


def _resolve_safe_gossip_ip(
    url: str, *, resolve: Callable[..., list] = socket.getaddrinfo,
) -> Optional[str]:
    """Return one validated public IP for a gossip URL.

    The caller must use this IP for the subsequent socket connection. A
    boolean-only DNS check followed by a hostname connection is vulnerable
    to DNS rebinding.
    """
    try:
        parsed = urlsplit(url)
        if parsed.scheme != "https":
            return None
        host = (parsed.hostname or "").lower()
        if not host or host == "localhost" or host.endswith(".local"):
            return None
        ip = ipaddress.ip_address(host)
        return host if not _ip_is_internal(ip) else None
    except ValueError:
        pass
    except Exception:  # noqa: BLE001
        return None

    try:
        infos = resolve(host, None)
    except Exception:  # noqa: BLE001
        return None
    if not infos:
        return None
    resolved: List[str] = []
    for info in infos:
        try:
            address = ipaddress.ip_address(info[4][0])
        except (ValueError, IndexError, TypeError):
            return None
        if _ip_is_internal(address):
            return None
        resolved.append(str(address))
    return resolved[0] if resolved else None


def _gossip_host_key(url: str) -> Optional[tuple[str, str, int]]:
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return parsed.scheme, parsed.hostname.lower(), port
    except (TypeError, ValueError):
        return None


def federate_once(
    peers: List[str],
    http_get: HttpGetJson = _urllib_get_json,
    *,
    now_ms_override: int = 0,
    max_peers: int = _MAX_GOSSIP_PEERS,
    resolve: Callable[..., list] = socket.getaddrinfo,
    verify_gossip_peer: Optional[Callable[[str, str], bool]] = None,
    verify_seed_peer: Optional[Callable[[str], bool]] = None,
    max_duration_s: float = 0.0,
) -> Dict[str, Dict[str, Any]]:
    """对 peer 图做 **BFS 传递发现**:从 seed 出发,拉每个 peer 的任务 + 它的
    peer 列表(gossip 成员),把新 peer 入队继续展开,直到无新 peer 或撞
    ``max_peers``。返回 {announcement_id: {"ann":.., "source": peer}}。

    任务仍**直连源 DAO 拉取 + 双层验签**(信任模型不变);gossip 只扩大「连谁」。
    seen 去重 + max_peers 上限 → 防环、防恶意 peer 把图撑爆。
    """
    now = now_ms_override or now_ms()
    deadline = (
        time.monotonic() + max_duration_s
        if max_duration_s and max_duration_s > 0
        else None
    )

    def within_budget() -> bool:
        return deadline is None or time.monotonic() < deadline

    merged: Dict[str, Dict[str, Any]] = {}
    seen: set = set()
    queue: List[str] = list(dict.fromkeys(
        p.rstrip("/") for p in peers if p and p.strip()))
    seed_peers = set(queue)
    pinned_ips: Dict[tuple[str, str, int], str] = {}

    def federation_http_get(url: str) -> Any:
        key = _gossip_host_key(url)
        resolved_ip = pinned_ips.get(key) if key is not None else None
        if resolved_ip and http_get is _urllib_get_json:
            return _urllib_get_json_pinned(url, resolved_ip)
        return http_get(url)

    def gossip_peer_allowed(url: str, resolved_ip: str) -> bool:
        if verify_gossip_peer is None:
            return True
        try:
            return bool(verify_gossip_peer(url, resolved_ip))
        except Exception as exc:  # noqa: BLE001
            logger.warning("fed: gossip identity preflight failed %s: %s", url, exc)
            return False

    while queue and len(seen) < max_peers and within_budget():
        peer = queue.pop(0)
        if peer in seen:
            continue
        seen.add(peer)
        if peer in seed_peers and verify_seed_peer is not None:
            try:
                if not verify_seed_peer(peer):
                    logger.warning("fed: rejected configured seed identity %s", peer)
                    continue
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "fed: configured seed preflight failed %s: %s", peer, exc,
                )
                continue
        # 任务:直连该 peer 拉全文 + 验签。
        for ann in pull_from_peer(peer, federation_http_get):
            if ann.announcement_id in merged:
                continue
            if ann.is_expired(now_ms_override=now):
                continue
            merged[ann.announcement_id] = {"ann": ann, "source": peer}
        # gossip:学这个 peer 的 peer 列表 → 传递发现下一跳。
        # 发现到的是不可信网络数据 → 必须过 SSRF 公网校验才入队。
        candidates_considered = 0
        for p in fetch_peer_list(peer, federation_http_get):
            if not within_budget():
                break
            if (
                len(seen) + len(queue) + candidates_considered
                >= max_peers
            ):
                break
            candidates_considered += 1
            nxt = p.rstrip("/")
            resolved_ip = _resolve_safe_gossip_ip(nxt, resolve=resolve)
            if (
                nxt and nxt not in seen and nxt not in queue
                and len(seen) + len(queue) < max_peers
                and resolved_ip is not None
                and gossip_peer_allowed(nxt, resolved_ip)
            ):
                key = _gossip_host_key(nxt)
                if key is not None:
                    pinned_ips[key] = resolved_ip
                queue.append(nxt)
    return merged


class FederationCache:
    """联邦发现缓存:{id: {"ann": TaskAnnouncement, "source": peer}}。

    poller 整体替换(replace_all),market/open 读快照(snapshot)。整体替换
    +快照拷贝避免读写竞争。
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._data: Dict[str, Dict[str, Any]] = {}
        self._last_refresh_ms = 0
        self._last_error = ""
        self._last_peer_count = 0

    def replace_all(
        self,
        entries: Dict[str, Dict[str, Any]],
        *,
        peer_count: int = 0,
    ) -> None:
        with self._lock:
            self._data = entries
            self._last_refresh_ms = now_ms()
            self._last_error = ""
            self._last_peer_count = max(0, int(peer_count or 0))

    def mark_error(self, error: str, *, peer_count: int = 0) -> None:
        with self._lock:
            self._last_refresh_ms = now_ms()
            self._last_error = str(error or "")[:500]
            self._last_peer_count = max(0, int(peer_count or 0))

    def snapshot(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return dict(self._data)

    def status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "cached_announcements": len(self._data),
                "last_refresh_ms": self._last_refresh_ms,
                "last_error": self._last_error,
                "last_peer_count": self._last_peer_count,
            }


def start_poller(
    get_peers: Callable[[], List[str]],
    cache: FederationCache,
    *,
    interval_s: float = 20.0,
    http_get: HttpGetJson = _urllib_get_json,
    verify_gossip_peer: Optional[Callable[[str, str], bool]] = None,
    verify_seed_peer: Optional[Callable[[str], bool]] = None,
    max_duration_s: float = 30.0,
) -> threading.Thread:
    """起后台 poller:周期性 federate_once → 刷新 cache。daemon,整体 try 兜底。"""

    def loop() -> None:
        while True:
            try:
                peers = [p for p in get_peers() if p]
                if peers:
                    cache.replace_all(
                        federate_once(
                            peers,
                            http_get,
                            verify_gossip_peer=verify_gossip_peer,
                            verify_seed_peer=verify_seed_peer,
                            max_duration_s=max_duration_s,
                        ),
                        peer_count=len(peers),
                    )
                else:
                    cache.replace_all({}, peer_count=0)
            except Exception as exc:  # noqa: BLE001
                try:
                    cache.mark_error(str(exc), peer_count=len(get_peers()))
                except Exception:  # noqa: BLE001
                    pass
                logger.warning("fed poller cycle failed: %s", exc)
            time.sleep(interval_s)

    th = threading.Thread(target=loop, daemon=True, name="nth-market-federation")
    th.start()
    return th
