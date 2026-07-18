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

from dataclasses import dataclass, field
import http.client
import ipaddress
import json
import logging
import math
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Set
from urllib.parse import urlencode, urlsplit

from nth_dao.execution_receipt import now_ms
from nth_dao.did_key import is_did_key
from nth_dao.market.announcement import (
    TaskAnnouncement,
    announcement_federation_key,
    verify_announcement,
)
from nth_dao.market.federation import FeedDigest, verify_digest

logger = logging.getLogger(__name__)

# url -> 解析好的 JSON(dict/list);失败抛异常。
HttpGetJson = Callable[[str], Any]
HttpPostJson = Callable[[str, Dict[str, Any]], Any]

_PULL_BATCH = 100   # 一次 pull 的 id 上限(serve 侧封顶 200,这里留余量)
_MAX_DIGEST_PAGES = 50   # digest 翻页安全上限(防恶意 peer 永不收敛)
_MAX_GOSSIP_PEERS = 64   # 一轮 BFS 最多访问多少 peer(传递发现的安全上限)
_HTTP_TIMEOUT_S = 8.0
_MAX_GOSSIP_PEER_LIST = 64
_MAX_HTTP_JSON_BYTES = 512 * 1024
_DEFAULT_STALE_TTL_MS = 2 * 60 * 1000


@dataclass
class FederationCycleReport:
    """Completion metadata for one bounded federation traversal."""

    attempted_sources: Set[str] = field(default_factory=set)
    completed_sources: Set[str] = field(default_factory=set)
    deadline_exhausted: bool = False
    cancelled: bool = False


def _urllib_get_json(url: str) -> Any:
    req = urllib.request.Request(
        url, headers={"Accept": "application/json"}, method="GET")
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_S) as resp:  # noqa: S310
        body = resp.read(_MAX_HTTP_JSON_BYTES + 1)
    if len(body) > _MAX_HTTP_JSON_BYTES:
        raise ValueError(f"HTTP response exceeds {_MAX_HTTP_JSON_BYTES} bytes")
    return json.loads(body.decode("utf-8"))


def _urllib_post_json(url: str, payload: Dict[str, Any]) -> Any:
    body = json.dumps(
        payload, ensure_ascii=True, separators=(",", ":"),
    ).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_S) as resp:  # noqa: S310
        response_body = resp.read(_MAX_HTTP_JSON_BYTES + 1)
    if len(response_body) > _MAX_HTTP_JSON_BYTES:
        raise ValueError(f"HTTP response exceeds {_MAX_HTTP_JSON_BYTES} bytes")
    return json.loads(response_body.decode("utf-8"))


def announce_peer_hello(
    seed_peers: List[str],
    *,
    peer_url: str,
    did: str,
    http_post: HttpPostJson = _urllib_post_json,
) -> Dict[str, str]:
    """Tell configured seeds how to dial this node.

    The hello body is only a hint. A conforming receiver independently fetches
    and verifies the signed identity card at ``peer_url`` before learning it.
    Per-seed failures are isolated so reverse discovery cannot interrupt feed
    pulling.
    """
    from nth_dao.did_key import is_did_key
    from nth_dao.discovery.federation_registry import normalize_learned_peer_url

    normalized = normalize_learned_peer_url(peer_url)
    if not isinstance(did, str) or len(did) > 512 or not is_did_key(did):
        raise ValueError("peer hello requires a valid Ed25519 did:key identifier")
    results: Dict[str, str] = {}
    for raw_seed in list(dict.fromkeys(seed_peers))[:_MAX_GOSSIP_PEERS]:
        seed = str(raw_seed or "").rstrip("/")
        if not seed:
            continue
        try:
            response = http_post(
                f"{seed}/api/v2/market/federation/hello",
                {"peer_url": normalized, "did": did},
            )
            if not isinstance(response, dict) or response.get("learned") is not True:
                raise ValueError("peer hello response did not confirm learning")
            results[seed] = ""
        except Exception as exc:  # noqa: BLE001
            results[seed] = f"{type(exc).__name__}: {exc}"[:500]
            logger.debug("fed: peer hello failed %s: %s", seed, exc)
    return results


def _urllib_request_bytes_pinned(
    url: str,
    resolved_ip: str,
    *,
    method: str,
    body: bytes = b"",
    timeout_s: float = _HTTP_TIMEOUT_S,
    max_bytes: int = _MAX_HTTP_JSON_BYTES,
) -> tuple[int, str, Any, bytes]:
    """Send one bounded HTTP request to a validated IP with Host/SNI intact."""
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
    if any(ch in target for ch in ("\r", "\n", "\x00")):
        raise ValueError("pinned HTTP target contains control characters")
    normalized_method = str(method or "").upper()
    if normalized_method not in {"GET", "POST"}:
        raise ValueError("pinned HTTP method is not supported")
    host_header = parsed.hostname
    if ":" in host_header and not host_header.startswith("["):
        host_header = f"[{host_header}]"
    if port not in {80, 443}:
        host_header = f"{host_header}:{port}"

    deadline = time.monotonic() + timeout_s
    sock = socket.create_connection((resolved_ip, port), timeout=timeout_s)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        sock.close()
        raise TimeoutError("pinned HTTP connection exceeded its absolute deadline")
    socket_holder = {"socket": sock}
    deadline_expired = threading.Event()

    def abort_slow_response() -> None:
        deadline_expired.set()
        active = socket_holder.get("socket")
        if active is None:
            return
        try:
            active.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            active.close()
        except OSError:
            pass

    deadline_timer = threading.Timer(remaining, abort_slow_response)
    deadline_timer.daemon = True
    deadline_timer.start()
    try:
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=parsed.hostname)
            socket_holder["socket"] = sock
        request_head = (
            f"{normalized_method} {target} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "Accept: application/json\r\n"
        )
        if normalized_method == "POST":
            request_head += (
                "Content-Type: application/json; charset=utf-8\r\n"
                f"Content-Length: {len(body)}\r\n"
            )
        request_head += "Connection: close\r\n\r\n"
        sock.sendall(request_head.encode("ascii") + body)
        response = http.client.HTTPResponse(sock)
        response.begin()
        response_body = response.read(max_bytes + 1)
        if deadline_expired.is_set() or time.monotonic() > deadline:
            raise TimeoutError("pinned HTTP response exceeded its absolute deadline")
        if len(response_body) > max_bytes:
            raise ValueError(f"HTTP response exceeds {max_bytes} bytes")
        return response.status, str(response.reason or ""), response.headers, response_body
    except Exception as exc:
        if isinstance(exc, TimeoutError):
            raise
        if deadline_expired.is_set() or time.monotonic() > deadline:
            raise TimeoutError(
                "pinned HTTP response exceeded its absolute deadline"
            ) from exc
        raise
    finally:
        deadline_timer.cancel()
        socket_holder["socket"] = None
        try:
            sock.close()
        except OSError:
            pass


def _urllib_get_bytes_pinned(
    url: str,
    resolved_ip: str,
    *,
    timeout_s: float = _HTTP_TIMEOUT_S,
    max_bytes: int = _MAX_HTTP_JSON_BYTES,
) -> bytes:
    """GET over a previously validated IP while preserving Host/SNI."""
    status, reason, headers, body = _urllib_request_bytes_pinned(
        url,
        resolved_ip,
        method="GET",
        timeout_s=timeout_s,
        max_bytes=max_bytes,
    )
    if status < 200 or status >= 300:
        raise urllib.error.HTTPError(url, status, reason, headers, None)
    return body


def _urllib_post_json_pinned_raw(
    url: str,
    resolved_ip: str,
    payload: Dict[str, Any],
    *,
    timeout_s: float = _HTTP_TIMEOUT_S,
    max_bytes: int = _MAX_HTTP_JSON_BYTES,
) -> tuple[int, bytes]:
    """POST JSON to the exact IP used for fresh endpoint verification."""
    body = json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")
    status, _reason, _headers, response_body = _urllib_request_bytes_pinned(
        url,
        resolved_ip,
        method="POST",
        body=body,
        timeout_s=timeout_s,
        max_bytes=max_bytes,
    )
    return status, response_body


def _urllib_get_json_pinned(url: str, resolved_ip: str) -> Any:
    return json.loads(
        _urllib_get_bytes_pinned(url, resolved_ip).decode("utf-8")
    )


def _collect_refs_via_digest(
    base: str,
    http_get: HttpGetJson,
    *,
    expected_source_did: str,
) -> Optional[List[Dict[str, str]]]:
    """增量翻页拉对端 digest,收集所有 ref 的 announcement_id(去重保序)。

    带 ``since=high_seq`` 一页页翻,直到游标不再推进(到底)或撞安全上限。
    任一页 provenance 验不过 → 返回 None(整个 peer 不可信,fail-closed)。
    """
    collected: List[Dict[str, str]] = []
    seen: set = set()
    cursor = -1
    for _ in range(_MAX_DIGEST_PAGES):
        try:
            draw = http_get(
                f"{base}/api/v2/market/federation/digest?since={cursor}")
        except Exception as exc:  # noqa: BLE001
            logger.debug("fed: digest fetch failed %s: %s", base, exc)
            return None
        if not isinstance(draw, dict):
            return None
        try:
            digest = FeedDigest.from_dict(draw)
        except Exception:  # noqa: BLE001
            return None
        ok, why = verify_digest(digest)   # provenance:source_did 签的这批 refs
        if not ok:
            logger.warning("fed: peer %s digest verify failed: %s", base, why)
            return None
        if digest.source_did != expected_source_did:
            logger.warning(
                "fed: peer %s digest source %s does not match endpoint identity %s",
                base,
                digest.source_did,
                expected_source_did,
            )
            return None
        for r in digest.refs:
            if not isinstance(r, dict) or not isinstance(
                r.get("announcement_id"), str,
            ):
                continue
            aid = r["announcement_id"]
            federation_key = r.get("federation_key")
            dedupe_key = (
                federation_key
                if isinstance(federation_key, str) and federation_key
                else f"legacy-id:{aid}"
            )
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            item = {"announcement_id": aid}
            if isinstance(federation_key, str) and federation_key:
                item["federation_key"] = federation_key
            collected.append(item)
        if digest.high_seq <= cursor:   # 游标没推进 → 到底/防死循环
            return collected if not digest.refs else None
        cursor = digest.high_seq
    # A peer that keeps advancing beyond the hard page cap did not provide a
    # complete open-set snapshot. Do not publish a silently truncated view.
    return None


def _pull_from_peer_snapshot(
    peer_base: str,
    http_get: HttpGetJson = _urllib_get_json,
    *,
    expected_source_did: str,
) -> Optional[List[TaskAnnouncement]]:
    """从一个 peer 拉取**已双层验签**的开放公告(digest 翻页 + 全文分批拉)。

    provenance 验不过 / 任何失败 → 返回 [](fail-closed)。
    """
    base = peer_base.rstrip("/")
    if not isinstance(expected_source_did, str) or not is_did_key(
        expected_source_did
    ):
        logger.warning("fed: peer %s has no verified endpoint DID", base)
        return None
    refs = _collect_refs_via_digest(
        base,
        http_get,
        expected_source_did=expected_source_did,
    )
    if refs is None:
        return None
    if not refs:
        return []
    out: List[TaskAnnouncement] = []
    verified_listings: Dict[str, Any] = {}
    keyed = [r["federation_key"] for r in refs if r.get("federation_key")]
    legacy_ids = [r["announcement_id"] for r in refs if not r.get("federation_key")]
    for parameter, values in (("keys", keyed), ("ids", legacy_ids)):
        for i in range(0, len(values), _PULL_BATCH):
            batch = values[i:i + _PULL_BATCH]
            query = urlencode({parameter: ",".join(batch)})
            try:
                praw = http_get(
                    f"{base}/api/v2/market/federation/pull?{query}")
            except Exception as exc:  # noqa: BLE001
                logger.debug("fed: pull failed %s: %s", base, exc)
                return None
            if not isinstance(praw, list):
                return None
            requested = set(batch)
            for item in praw:
                if not isinstance(item, dict):
                    return None
                try:
                    ann = TaskAnnouncement.from_dict(item)
                except Exception:  # noqa: BLE001
                    return None
                selector = (
                    announcement_federation_key(ann)
                    if parameter == "keys"
                    else ann.announcement_id
                )
                if selector not in requested:
                    logger.warning(
                        "fed: peer %s returned an unrequested announcement", base,
                    )
                    return None
                vok, _ = verify_announcement(ann)
                if (
                    vok
                    and ann.effective_authority_did() == expected_source_did
                    and _verify_pulled_listing(
                        base, ann, http_get, verified_listings,
                    )
                ):
                    out.append(ann)
                elif vok:
                    logger.warning(
                        "fed: peer %s served announcement %s for publisher %s "
                        "without an authority delegation",
                        base,
                        ann.announcement_id,
                        ann.effective_authority_did(),
                    )
                    return None
                else:
                    return None
    return out


def _verify_pulled_listing(
    base: str,
    ann: TaskAnnouncement,
    http_get: HttpGetJson,
    verified_listings: Dict[str, Any],
) -> bool:
    """Resolve and bind commerce summaries; legacy task announcements pass."""
    from nth_dao.market.announcement import NTH_ANNOUNCEMENT_KIND_V3

    if ann.kind != NTH_ANNOUNCEMENT_KIND_V3:
        return True
    from nth_dao.commerce.listing import SignedListing
    from nth_dao.commerce.listing_announcement import (
        listing_offer_uri,
        verify_listing_announcement_binding,
    )

    if ann.offer_uri != listing_offer_uri(ann.offer_digest):
        return False
    listing = verified_listings.get(ann.offer_digest)
    if listing is None:
        try:
            raw = http_get(f"{base}{ann.offer_uri}")
            listing = SignedListing.from_dict(raw)
        except (OSError, TypeError, ValueError, urllib.error.URLError):
            return False
    ok, _ = verify_listing_announcement_binding(listing, ann)
    if not ok:
        return False
    # Cache the immutable listing bytes, not the binding result. Every signed
    # announcement must still be rebound: the same seller can sign multiple
    # summaries for one digest, and only some may match its price/type/expiry.
    verified_listings[ann.offer_digest] = listing
    return True


def pull_from_peer(
    peer_base: str,
    http_get: HttpGetJson = _urllib_get_json,
    *,
    expected_source_did: str,
    _completion: Optional[Dict[str, bool]] = None,
) -> List[TaskAnnouncement]:
    """Return a verified snapshot, preserving the historical list API."""
    snapshot = _pull_from_peer_snapshot(
        peer_base,
        http_get,
        expected_source_did=expected_source_did,
    )
    if _completion is not None:
        _completion["complete"] = snapshot is not None
    return snapshot if snapshot is not None else []


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
    untrusted_peers: Optional[List[str]] = None,
    now_ms_override: int = 0,
    max_peers: int = _MAX_GOSSIP_PEERS,
    resolve: Callable[..., list] = socket.getaddrinfo,
    verify_gossip_peer: Optional[Callable[[str, str], Optional[str]]] = None,
    verify_seed_peer: Optional[Callable[[str], Optional[str]]] = None,
    max_duration_s: float = 0.0,
    cancelled: Optional[Callable[[], bool]] = None,
    start_offset: int = 0,
    cycle_report: Optional[FederationCycleReport] = None,
) -> Dict[str, Dict[str, Any]]:
    """对 peer 图做 **BFS 传递发现**:从 seed 出发,拉每个 peer 的任务 + 它的
    peer 列表(gossip 成员),把新 peer 入队继续展开,直到无新 peer 或撞
    ``max_peers``。返回 {content-bound federation_key: {"ann":..,
    "source": peer}}。

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
        if cancelled is not None and cancelled():
            return False
        return deadline is None or time.monotonic() < deadline

    merged: Dict[str, Dict[str, Any]] = {}
    seen: set = set()
    operator_peers = list(dict.fromkeys(
        p.rstrip("/") for p in peers if p and p.strip()))
    seed_peers = set(operator_peers)
    learned_peers = list(dict.fromkeys(
        p.rstrip("/")
        for p in (untrusted_peers or [])
        if p and p.strip() and p.rstrip("/") not in seed_peers
    ))
    untrusted_initial = set(learned_peers)
    initial_queue = operator_peers + learned_peers
    if initial_queue:
        offset = max(0, int(start_offset)) % len(initial_queue)
        queue = initial_queue[offset:] + initial_queue[:offset]
    else:
        queue = []
    pinned_ips: Dict[tuple[str, str, int], str] = {}
    verified_peer_dids: Dict[str, str] = {}

    def federation_http_get(url: str) -> Any:
        if not within_budget():
            raise TimeoutError("federation cycle deadline or shutdown reached")
        key = _gossip_host_key(url)
        resolved_ip = pinned_ips.get(key) if key is not None else None
        if resolved_ip and http_get is _urllib_get_json:
            return _urllib_get_json_pinned(url, resolved_ip)
        return http_get(url)

    def gossip_peer_identity(url: str, resolved_ip: str) -> str:
        if verify_gossip_peer is None:
            return ""
        try:
            did = verify_gossip_peer(url, resolved_ip)
            return did if isinstance(did, str) and is_did_key(did) else ""
        except Exception as exc:  # noqa: BLE001
            logger.warning("fed: gossip identity preflight failed %s: %s", url, exc)
            return ""

    def seed_peer_identity(url: str) -> str:
        if verify_seed_peer is None:
            return ""
        try:
            did = verify_seed_peer(url)
            return did if isinstance(did, str) and is_did_key(did) else ""
        except Exception as exc:  # noqa: BLE001
            logger.warning("fed: configured seed preflight failed %s: %s", url, exc)
            return ""

    while queue and len(seen) < max_peers and within_budget():
        peer = queue.pop(0)
        if peer in seen:
            continue
        seen.add(peer)
        if cycle_report is not None:
            cycle_report.attempted_sources.add(peer)
        if peer in untrusted_initial:
            resolved_ip = _resolve_safe_gossip_ip(peer, resolve=resolve)
            peer_did = (
                gossip_peer_identity(peer, resolved_ip)
                if resolved_ip is not None
                else ""
            )
            if resolved_ip is None or not peer_did:
                logger.warning("fed: rejected learned peer identity %s", peer)
                continue
            verified_peer_dids[peer] = peer_did
            key = _gossip_host_key(peer)
            if key is not None:
                pinned_ips[key] = resolved_ip
        elif peer in seed_peers:
            peer_did = seed_peer_identity(peer)
            if not peer_did:
                logger.warning("fed: rejected configured seed identity %s", peer)
                continue
            verified_peer_dids[peer] = peer_did
        peer_did = verified_peer_dids.get(peer, "")
        if not peer_did:
            logger.warning("fed: peer %s has no identity-bound authority", peer)
            continue
        # 任务:直连该 peer 拉全文 + 验签。
        completion: Dict[str, bool] = {}
        snapshot = pull_from_peer(
            peer,
            federation_http_get,
            expected_source_did=peer_did,
            _completion=completion,
        )
        # Injected legacy pullers return a list without filling the optional
        # report; their historical contract treats that list as complete.
        if not completion.get("complete", True):
            continue
        if cycle_report is not None:
            cycle_report.completed_sources.add(peer)
        for ann in snapshot:
            federation_key = announcement_federation_key(ann)
            if federation_key in merged:
                continue
            if ann.is_expired(now_ms_override=now):
                continue
            merged[federation_key] = {
                "ann": ann,
                "source": peer,
                "source_did": peer_did,
                "federation_key": federation_key,
            }
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
            candidate_did = (
                gossip_peer_identity(nxt, resolved_ip)
                if resolved_ip is not None
                else ""
            )
            if (
                nxt and nxt not in seen and nxt not in queue
                and len(seen) + len(queue) < max_peers
                and resolved_ip is not None
                and candidate_did
            ):
                key = _gossip_host_key(nxt)
                if key is not None:
                    pinned_ips[key] = resolved_ip
                verified_peer_dids[nxt] = candidate_did
                queue.append(nxt)
    if cycle_report is not None:
        cycle_report.cancelled = bool(cancelled is not None and cancelled())
        cycle_report.deadline_exhausted = bool(
            queue
            and not cycle_report.cancelled
            and deadline is not None
            and time.monotonic() >= deadline
        )
    return merged


def _isolated_cache_entry(
    entry: Dict[str, Any],
    *,
    federation_key: str,
    stale: bool,
    last_verified_ms: int,
) -> Dict[str, Any]:
    """Copy one verified record across the cache ownership boundary."""
    ann = entry.get("ann")
    if not isinstance(ann, TaskAnnouncement):
        raise TypeError("federation cache entry requires a TaskAnnouncement")
    return {
        "ann": TaskAnnouncement.from_dict(ann.to_dict()),
        "source": str(entry.get("source") or "").rstrip("/"),
        "source_did": str(entry.get("source_did") or ""),
        "federation_key": federation_key,
        "stale": bool(stale),
        "last_verified_ms": int(last_verified_ms),
    }


class FederationCache:
    """Federated discovery cache keyed by signed announcement content.

    poller 整体替换(replace_all),market/open 读快照(snapshot)。整体替换
    +快照拷贝避免读写竞争。
    """

    def __init__(self, *, stale_ttl_ms: int = _DEFAULT_STALE_TTL_MS) -> None:
        if stale_ttl_ms <= 0:
            raise ValueError("stale_ttl_ms must be positive")
        self._lock = threading.Lock()
        self._data: Dict[str, Dict[str, Any]] = {}
        self._stale_ttl_ms = int(stale_ttl_ms)
        self._last_refresh_ms = 0
        self._last_error = ""
        self._last_peer_count = 0

    def replace_all(
        self,
        entries: Dict[str, Dict[str, Any]],
        *,
        peer_count: int = 0,
    ) -> None:
        normalized: Dict[str, Dict[str, Any]] = {}
        for entry in entries.values():
            if not isinstance(entry, dict):
                continue
            ann = entry.get("ann")
            if not isinstance(ann, TaskAnnouncement):
                continue
            key = announcement_federation_key(ann)
            normalized[key] = _isolated_cache_entry(
                entry,
                federation_key=key,
                stale=False,
                last_verified_ms=now_ms(),
            )
        with self._lock:
            self._data = normalized
            self._last_refresh_ms = now_ms()
            self._last_error = ""
            self._last_peer_count = max(0, int(peer_count or 0))

    def apply_cycle(
        self,
        entries: Dict[str, Dict[str, Any]],
        *,
        completed_sources: Set[str],
        peer_count: int = 0,
        error: str = "",
        now_ms_override: int = 0,
    ) -> None:
        """Commit complete source snapshots and retain bounded stale hints."""
        observed_at = int(now_ms_override or now_ms())
        completed = {str(source).rstrip("/") for source in completed_sources}
        incoming: Dict[str, Dict[str, Any]] = {}
        for entry in entries.values():
            if not isinstance(entry, dict):
                continue
            ann = entry.get("ann")
            source = str(entry.get("source") or "").rstrip("/")
            if not isinstance(ann, TaskAnnouncement) or source not in completed:
                continue
            key = announcement_federation_key(ann)
            incoming[key] = _isolated_cache_entry(
                {**entry, "source": source},
                federation_key=key,
                stale=False,
                last_verified_ms=observed_at,
            )

        with self._lock:
            retained: Dict[str, Dict[str, Any]] = {}
            for key, entry in self._data.items():
                source = str(entry.get("source") or "").rstrip("/")
                if source in completed:
                    continue
                ann = entry.get("ann")
                verified_at = int(entry.get("last_verified_ms") or 0)
                if not isinstance(ann, TaskAnnouncement):
                    continue
                if ann.is_expired(now_ms_override=observed_at):
                    continue
                if verified_at <= 0 or observed_at - verified_at > self._stale_ttl_ms:
                    continue
                retained[key] = {**entry, "stale": True}
            retained.update(incoming)
            self._data = retained
            self._last_refresh_ms = observed_at
            self._last_error = str(error or "")[:500]
            self._last_peer_count = max(0, int(peer_count or 0))

    def evict_source(self, source: str) -> None:
        """Immediately remove cached entries for an operator-removed source."""
        normalized = str(source or "").rstrip("/")
        with self._lock:
            self._data = {
                key: entry for key, entry in self._data.items()
                if str(entry.get("source") or "").rstrip("/") != normalized
            }

    def mark_error(self, error: str, *, peer_count: int = 0) -> None:
        self.apply_cycle(
            {},
            completed_sources=set(),
            peer_count=peer_count,
            error=error,
        )

    def snapshot(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            captured = list(self._data.items())
        return {
            key: _isolated_cache_entry(
                entry,
                federation_key=key,
                stale=bool(entry.get("stale")),
                last_verified_ms=int(entry.get("last_verified_ms") or 0),
            )
            for key, entry in captured
        }

    def status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "cached_announcements": len(self._data),
                "last_refresh_ms": self._last_refresh_ms,
                "last_error": self._last_error,
                "last_peer_count": self._last_peer_count,
                "stale_announcements": sum(
                    1 for entry in self._data.values() if entry.get("stale") is True
                ),
            }


def start_poller(
    get_peers: Callable[[], List[str]],
    cache: FederationCache,
    *,
    get_untrusted_peers: Optional[Callable[[], List[str]]] = None,
    announce_self: Optional[Callable[[List[str]], Any]] = None,
    hello_interval_s: float = 300.0,
    stop_event: Optional[threading.Event] = None,
    interval_s: float = 20.0,
    http_get: HttpGetJson = _urllib_get_json,
    verify_gossip_peer: Optional[Callable[[str, str], Optional[str]]] = None,
    verify_seed_peer: Optional[Callable[[str], Optional[str]]] = None,
    max_duration_s: float = 30.0,
) -> threading.Thread:
    """起后台 poller:周期性 federate_once → 刷新 cache。daemon,整体 try 兜底。"""
    if not math.isfinite(interval_s) or interval_s <= 0:
        raise ValueError("federation poll interval must be a positive finite number")
    if not math.isfinite(hello_interval_s) or hello_interval_s <= 0:
        raise ValueError("federation hello interval must be a positive finite number")
    shutdown = stop_event if stop_event is not None else threading.Event()

    def loop() -> None:
        last_hello_at = 0.0
        rotation_offset = 0
        while not shutdown.is_set():
            try:
                peers = [p for p in get_peers() if p]
                untrusted_peers = (
                    [p for p in get_untrusted_peers() if p]
                    if get_untrusted_peers is not None
                    else []
                )
                all_peers = set(peers) | set(untrusted_peers)
                if all_peers:
                    hello_now = time.monotonic()
                    if (
                        peers
                        and announce_self is not None
                        and hello_now - last_hello_at >= max(60.0, hello_interval_s)
                    ):
                        try:
                            announce_self(peers)
                        except Exception as exc:  # noqa: BLE001
                            logger.warning("fed: reverse peer hello failed: %s", exc)
                        finally:
                            last_hello_at = hello_now
                    report = FederationCycleReport()
                    entries = federate_once(
                        peers,
                        http_get,
                        untrusted_peers=untrusted_peers,
                        verify_gossip_peer=verify_gossip_peer,
                        verify_seed_peer=verify_seed_peer,
                        max_duration_s=max_duration_s,
                        cancelled=shutdown.is_set,
                        start_offset=rotation_offset,
                        cycle_report=report,
                    )
                    rotation_offset += 1
                    cache.apply_cycle(
                        entries,
                        completed_sources=report.completed_sources,
                        peer_count=len(all_peers),
                    )
                else:
                    cache.replace_all({}, peer_count=0)
                    # No configured or learned peer remains. End this worker
                    # so adding a future peer starts a fresh lifecycle-owned
                    # poller instead of leaving an idle daemon forever.
                    shutdown.set()
                    break
            except Exception as exc:  # noqa: BLE001
                try:
                    configured = set(get_peers())
                    learned = (
                        set(get_untrusted_peers())
                        if get_untrusted_peers is not None
                        else set()
                    )
                    cache.mark_error(
                        str(exc), peer_count=len(configured | learned),
                    )
                except Exception:  # noqa: BLE001
                    pass
                logger.warning("fed poller cycle failed: %s", exc)
            if shutdown.wait(interval_s):
                break

    th = threading.Thread(target=loop, daemon=True, name="nth-market-federation")
    th.start()
    return th
