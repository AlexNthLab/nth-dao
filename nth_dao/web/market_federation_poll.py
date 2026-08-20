"""Federated pull side of the task and trade-offer market.

Each peer digest is verified as a provenance hint before referenced documents
are fetched and independently verified. A signed digest is not authority over
the referenced content; each publisher signature remains authoritative.

Transport is injectable for deterministic tests. Remote announcements are held
in a bounded local cache and are not republished through the local feed.
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
_DEFAULT_MAX_RECORDS_PER_PEER = 2_000
_DEFAULT_MAX_CACHE_RECORDS = 10_000
_DEFAULT_MAX_CACHE_RECORDS_PER_SOURCE = 2_000
_DEFAULT_MAX_CACHE_BYTES = 64 * 1024 * 1024
_DEFAULT_FULL_RECONCILE_MS = 60_000


class FederationCacheCapacityError(RuntimeError):
    """A complete federation snapshot exceeds configured local capacity."""


@dataclass
class FederationCycleReport:
    """Completion metadata for one bounded federation traversal."""

    attempted_sources: Set[str] = field(default_factory=set)
    completed_sources: Set[str] = field(default_factory=set)
    full_sources: Set[str] = field(default_factory=set)
    source_high_seq: Dict[str, int] = field(default_factory=dict)
    source_dids: Dict[str, str] = field(default_factory=dict)
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
    max_records: int = _DEFAULT_MAX_RECORDS_PER_PEER,
    since_seq: int = -1,
    cursor_out: Optional[Dict[str, int]] = None,
) -> Optional[List[Dict[str, str]]]:
    """Collect bounded, ordered refs from incrementally paged peer digests.

    Return ``None`` if any page fails provenance verification or pagination
    does not converge within the hard page cap.
    """
    if (
        isinstance(max_records, bool)
        or not isinstance(max_records, int)
        or max_records <= 0
    ):
        raise ValueError("max_records must be a positive integer")
    if type(since_seq) is not int or since_seq < -1:
        raise ValueError("since_seq must be an integer >= -1")
    collected: List[Dict[str, str]] = []
    seen: set = set()
    cursor = since_seq
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
            if len(collected) >= max_records:
                logger.warning(
                    "fed: peer %s exceeded the per-peer record limit", base,
                )
                return None
            seen.add(dedupe_key)
            item = {"announcement_id": aid}
            if isinstance(federation_key, str) and federation_key:
                item["federation_key"] = federation_key
            collected.append(item)
        if digest.high_seq <= cursor:  # End of stream or non-advancing cursor.
            if cursor_out is not None:
                cursor_out["high_seq"] = cursor
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
    verified_documents: Optional[Dict[str, Any]] = None,
    max_records: int = _DEFAULT_MAX_RECORDS_PER_PEER,
    now_ms_override: int = 0,
    since_seq: int = -1,
    cursor_out: Optional[Dict[str, int]] = None,
) -> Optional[List[TaskAnnouncement]]:
    """Pull open announcements after digest and document verification.

    Return ``None`` on an incomplete or invalid snapshot so callers fail closed.
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
        max_records=max_records,
        since_seq=since_seq,
        cursor_out=cursor_out,
    )
    if refs is None:
        return None
    if not refs:
        if verified_documents is not None:
            verified_documents.clear()
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
            returned: Set[str] = set()
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
                if selector in returned:
                    logger.warning(
                        "fed: peer %s returned a duplicate announcement", base,
                    )
                    return None
                returned.add(selector)
                vok, _ = verify_announcement(ann)
                if (
                    vok
                    and ann.effective_authority_did() == expected_source_did
                    and _verify_pulled_listing(
                        base,
                        ann,
                        http_get,
                        verified_listings,
                        now_ms_override=now_ms_override,
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
            if returned != requested:
                logger.warning(
                    "fed: peer %s returned an incomplete announcement batch",
                    base,
                )
                return None
    if verified_documents is not None:
        verified_documents.clear()
        verified_documents.update(verified_listings)
    return out


def _verify_pulled_listing(
    base: str,
    ann: TaskAnnouncement,
    http_get: HttpGetJson,
    verified_listings: Dict[str, Any],
    *,
    now_ms_override: int = 0,
) -> bool:
    """Resolve and bind full market documents; legacy tasks pass."""
    from nth_dao.market.announcement import (
        NTH_ANNOUNCEMENT_KIND_V3,
        NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1,
    )

    if ann.kind not in {
        NTH_ANNOUNCEMENT_KIND_V3,
        NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1,
    }:
        return True
    if ann.kind == NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1:
        from nth_dao.market.trade_offer_announcement import (
            VerifiedTradeOfferHeadProof,
            trade_offer_head_proof_uri,
            trade_offer_uri,
            verify_trade_offer_announcement_binding,
        )

        if ann.offer_uri != trade_offer_uri(ann.offer_digest):
            return False
        proof = verified_listings.get(ann.offer_digest)
        if proof is None:
            try:
                raw = http_get(
                    f"{base}{trade_offer_head_proof_uri(ann.offer_digest)}"
                )
                proof = VerifiedTradeOfferHeadProof.from_dict(
                    raw,
                    now_ms_override=now_ms_override,
                )
            except (OSError, TypeError, ValueError, urllib.error.URLError):
                return False
        if not isinstance(proof, VerifiedTradeOfferHeadProof):
            return False
        if proof.announcement.to_dict() != ann.to_dict():
            return False
        ok, _ = verify_trade_offer_announcement_binding(proof.head, ann)
        if not ok:
            return False
        verified_listings[ann.offer_digest] = proof
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
    _verified_documents: Optional[Dict[str, Any]] = None,
    _max_records: int = _DEFAULT_MAX_RECORDS_PER_PEER,
    _now_ms_override: int = 0,
    _since_seq: int = -1,
    _cursor_out: Optional[Dict[str, int]] = None,
) -> List[TaskAnnouncement]:
    """Return a verified snapshot, preserving the historical list API."""
    snapshot = _pull_from_peer_snapshot(
        peer_base,
        http_get,
        expected_source_did=expected_source_did,
        verified_documents=_verified_documents,
        max_records=_max_records,
        now_ms_override=_now_ms_override,
        since_seq=_since_seq,
        cursor_out=_cursor_out,
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
    verified_seed_ips: Optional[Dict[str, str]] = None,
    pinned_http_get: Optional[Callable[[str, str], Any]] = None,
    max_duration_s: float = 0.0,
    cancelled: Optional[Callable[[], bool]] = None,
    start_offset: int = 0,
    cycle_report: Optional[FederationCycleReport] = None,
    source_since: Optional[Callable[[str, str], int]] = None,
    max_records: int = _DEFAULT_MAX_CACHE_RECORDS,
) -> Dict[str, Dict[str, Any]]:
    """Traverse the bounded peer graph and return verified announcements.

    Gossip only supplies connection hints. Each source is contacted directly,
    each digest and document is verified, and ``max_peers`` bounds graph growth.
    """
    now = now_ms_override or now_ms()
    if (
        isinstance(max_records, bool)
        or not isinstance(max_records, int)
        or max_records <= 0
    ):
        raise ValueError("max_records must be a positive integer")
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
        if resolved_ip:
            if pinned_http_get is not None:
                return pinned_http_get(url, resolved_ip)
            if http_get is _urllib_get_json:
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
            if verified_seed_ips is not None:
                resolved_ip = verified_seed_ips.get(peer)
                try:
                    safe_ip = ipaddress.ip_address(resolved_ip or "")
                except ValueError:
                    safe_ip = None
                if safe_ip is None or _ip_is_internal(safe_ip):
                    logger.warning("fed: rejected configured seed IP binding %s", peer)
                    continue
                key = _gossip_host_key(peer)
                if key is None:
                    logger.warning("fed: rejected configured seed origin %s", peer)
                    continue
                pinned_ips[key] = str(safe_ip)
            verified_peer_dids[peer] = peer_did
        peer_did = verified_peer_dids.get(peer, "")
        if not peer_did:
            logger.warning("fed: peer %s has no identity-bound authority", peer)
            continue
        # Pull documents directly from this peer and verify their signatures.
        completion: Dict[str, bool] = {}
        since_seq = source_since(peer, peer_did) if source_since else -1
        if type(since_seq) is not int or since_seq < -1:
            logger.warning("fed: invalid local cursor for peer %s", peer)
            since_seq = -1
        verified_documents: Dict[str, Any] = {}
        cursor_result: Dict[str, int] = {}
        snapshot = pull_from_peer(
            peer,
            federation_http_get,
            expected_source_did=peer_did,
            _completion=completion,
            _verified_documents=verified_documents,
            _now_ms_override=now,
            _since_seq=since_seq,
            _cursor_out=cursor_result,
        )
        # Injected legacy pullers return a list without filling the optional
        # report; their historical contract treats that list as complete.
        if not completion.get("complete", True):
            continue
        if cycle_report is not None:
            cycle_report.completed_sources.add(peer)
            if since_seq == -1:
                cycle_report.full_sources.add(peer)
            cycle_report.source_high_seq[peer] = cursor_result.get(
                "high_seq", since_seq,
            )
            cycle_report.source_dids[peer] = peer_did
        for ann in snapshot:
            federation_key = announcement_federation_key(ann)
            if federation_key in merged:
                continue
            if len(merged) >= max_records:
                raise FederationCacheCapacityError(
                    "federation cycle exceeds the global record limit"
                )
            if ann.is_expired(now_ms_override=now):
                continue
            entry: Dict[str, Any] = {
                "ann": ann,
                "source": peer,
                "source_did": peer_did,
                "federation_key": federation_key,
            }
            from nth_dao.market.announcement import (
                NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1,
            )
            if ann.kind == NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1:
                from nth_dao.market.trade_offer_announcement import (
                    VerifiedTradeOfferHeadProof,
                )

                head_proof = verified_documents.get(ann.offer_digest)
                if not isinstance(head_proof, VerifiedTradeOfferHeadProof):
                    logger.warning(
                        "fed: verified Trade Offer head proof missing for %s from %s",
                        ann.offer_digest,
                        peer,
                    )
                    continue
                entry["trade_offer"] = head_proof.head
                entry["trade_offer_head_proof"] = head_proof
            merged[federation_key] = entry
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
    now_ms_override: int = 0,
) -> Dict[str, Any]:
    """Copy one verified record across the cache ownership boundary."""
    ann = entry.get("ann")
    if not isinstance(ann, TaskAnnouncement):
        raise TypeError("federation cache entry requires a TaskAnnouncement")
    isolated: Dict[str, Any] = {
        "ann": TaskAnnouncement.from_dict(ann.to_dict()),
        "source": str(entry.get("source") or "").rstrip("/"),
        "source_did": str(entry.get("source_did") or ""),
        "federation_key": federation_key,
        "stale": bool(stale),
        "last_verified_ms": int(last_verified_ms),
    }
    from nth_dao.market.announcement import (
        NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1,
    )
    if ann.kind == NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1:
        from nth_dao.market.trade_offer_announcement import (
            VerifiedTradeOfferHeadProof,
            verify_trade_offer_announcement_binding,
        )

        raw_proof = entry.get("trade_offer_head_proof")
        if not isinstance(raw_proof, VerifiedTradeOfferHeadProof):
            raise TypeError(
                "exchange federation cache entry requires a verified head proof"
            )
        proof = VerifiedTradeOfferHeadProof.from_dict(
            raw_proof.to_dict(),
            now_ms_override=now_ms_override,
        )
        if proof.announcement.to_dict() != ann.to_dict():
            raise ValueError("federated Trade Offer head claim mismatch")
        offer = proof.head
        ok, reason = verify_trade_offer_announcement_binding(offer, ann)
        if not ok:
            raise ValueError(f"federated Trade Offer binding failed: {reason}")
        if isolated["source_did"] != ann.effective_authority_did():
            raise ValueError("federated Trade Offer source DID mismatch")
        isolated["trade_offer"] = offer
        isolated["trade_offer_head_proof"] = proof
    return isolated


def _snapshot_cache_entry(
    entry: Dict[str, Any],
    *,
    federation_key: str,
) -> Dict[str, Any]:
    """Detach mutable cache metadata without repeating signature checks.

    Entries reach ``_data`` only through ``_isolated_cache_entry``, which
    verifies every signed record and replaces caller-owned mutable values.
    TradeOffer and VerifiedTradeOfferHeadProof are frozen wrappers over
    immutable ``bytes``; sharing those wrappers across a read snapshot is
    safe. Revalidating them here would turn every public market read into an
    attacker-controlled number of Ed25519 verifications.
    """

    from nth_dao.market.announcement import (
        NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1,
    )
    from nth_dao.market.trade_offer_announcement import (
        VerifiedTradeOfferHeadProof,
    )
    from nth_dao.trade_rules.offer import TradeOffer

    ann = entry.get("ann")
    if not isinstance(ann, TaskAnnouncement):
        raise TypeError("federation cache contains an invalid announcement")
    detached: Dict[str, Any] = {
        "ann": TaskAnnouncement.from_dict(ann.to_dict()),
        "source": str(entry.get("source") or ""),
        "source_did": str(entry.get("source_did") or ""),
        "federation_key": federation_key,
        "stale": bool(entry.get("stale")),
        "last_verified_ms": int(entry.get("last_verified_ms") or 0),
    }
    if ann.kind == NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1:
        offer = entry.get("trade_offer")
        proof = entry.get("trade_offer_head_proof")
        if not isinstance(offer, TradeOffer) or not isinstance(
            proof, VerifiedTradeOfferHeadProof
        ):
            raise TypeError("federation cache contains an invalid head proof")
        detached["trade_offer"] = offer
        detached["trade_offer_head_proof"] = proof
    return detached


class FederationCache:
    """Federated discovery cache keyed by signed announcement content.

    poller 整体替换(replace_all),market/open 读快照(snapshot)。整体替换
    +快照拷贝避免读写竞争。
    """

    def __init__(
        self,
        *,
        stale_ttl_ms: int = _DEFAULT_STALE_TTL_MS,
        max_records: int = _DEFAULT_MAX_CACHE_RECORDS,
        max_records_per_source: int = _DEFAULT_MAX_CACHE_RECORDS_PER_SOURCE,
        max_bytes: int = _DEFAULT_MAX_CACHE_BYTES,
    ) -> None:
        if stale_ttl_ms <= 0:
            raise ValueError("stale_ttl_ms must be positive")
        for label, value in (
            ("max_records", max_records),
            ("max_records_per_source", max_records_per_source),
            ("max_bytes", max_bytes),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{label} must be a positive integer")
        self._lock = threading.Lock()
        self._data: Dict[str, Dict[str, Any]] = {}
        self._offer_index: Dict[str, Set[str]] = {}
        self._stale_ttl_ms = int(stale_ttl_ms)
        self._max_records = max_records
        self._max_records_per_source = max_records_per_source
        self._max_bytes = max_bytes
        self._last_refresh_ms = 0
        self._last_error = ""
        self._last_peer_count = 0
        self._source_cursors: Dict[str, tuple[str, int, int]] = {}

    def since_for_source(
        self,
        source: str,
        source_did: str,
        *,
        now_ms_override: int = 0,
        full_reconcile_ms: Optional[int] = None,
    ) -> int:
        """Choose delta or full sync without treating a cursor as authority."""
        interval = (
            min(_DEFAULT_FULL_RECONCILE_MS, max(1, self._stale_ttl_ms // 2))
            if full_reconcile_ms is None
            else full_reconcile_ms
        )
        if type(interval) is not int or interval <= 0:
            raise ValueError("full_reconcile_ms must be a positive integer")
        if interval >= self._stale_ttl_ms:
            return -1
        if (
            isinstance(now_ms_override, bool)
            or not isinstance(now_ms_override, int)
            or now_ms_override < 0
        ):
            raise ValueError("now_ms_override must be a non-negative integer")
        if not isinstance(source_did, str) or not source_did:
            raise ValueError("source_did must be a non-empty string")
        normalized = str(source or "").rstrip("/")
        observed_at = int(now_ms_override or now_ms())
        with self._lock:
            state = self._source_cursors.get(normalized)
        if state is None:
            return -1
        did, cursor, last_full_ms = state
        if (
            did != source_did
            or observed_at < last_full_ms
            or observed_at - last_full_ms >= interval
        ):
            return -1
        return cursor

    @staticmethod
    def _entry_size_bytes(entry: Dict[str, Any]) -> int:
        ann = entry.get("ann")
        body: Dict[str, Any] = {
            "ann": ann.to_dict() if isinstance(ann, TaskAnnouncement) else None,
            "source": entry.get("source"),
            "source_did": entry.get("source_did"),
            "federation_key": entry.get("federation_key"),
            "stale": bool(entry.get("stale")),
            "last_verified_ms": int(entry.get("last_verified_ms") or 0),
        }
        trade_offer = entry.get("trade_offer")
        if trade_offer is not None and hasattr(trade_offer, "to_dict"):
            body["trade_offer"] = trade_offer.to_dict()
        head_proof = entry.get("trade_offer_head_proof")
        if head_proof is not None and hasattr(head_proof, "to_dict"):
            body["trade_offer_head_proof"] = head_proof.to_dict()
        return len(json.dumps(
            body,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8"))

    def _validate_capacity(self, entries: Dict[str, Dict[str, Any]]) -> None:
        if len(entries) > self._max_records:
            raise FederationCacheCapacityError(
                "federation cache exceeds the global record limit"
            )
        per_source: Dict[str, int] = {}
        total_bytes = 0
        for entry in entries.values():
            source = str(entry.get("source") or "")
            per_source[source] = per_source.get(source, 0) + 1
            if per_source[source] > self._max_records_per_source:
                raise FederationCacheCapacityError(
                    "federation cache exceeds the per-source record limit"
                )
            total_bytes += self._entry_size_bytes(entry)
            if total_bytes > self._max_bytes:
                raise FederationCacheCapacityError(
                    "federation cache exceeds the byte limit"
                )

    def _rebuild_offer_index_locked(self) -> None:
        index: Dict[str, Set[str]] = {}
        for key, entry in self._data.items():
            ann = entry.get("ann")
            if not isinstance(ann, TaskAnnouncement):
                continue
            digest = str(getattr(ann, "offer_digest", "") or "")
            if digest and "trade_offer_head_proof" in entry:
                index.setdefault(digest, set()).add(key)
        self._offer_index = index

    def replace_all(
        self,
        entries: Dict[str, Dict[str, Any]],
        *,
        peer_count: int = 0,
    ) -> None:
        observed_at = now_ms()
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
                last_verified_ms=observed_at,
                now_ms_override=observed_at,
            )
        self._validate_capacity(normalized)
        with self._lock:
            self._data = normalized
            self._source_cursors = {}
            self._rebuild_offer_index_locked()
            self._last_refresh_ms = now_ms()
            self._last_error = ""
            self._last_peer_count = max(0, int(peer_count or 0))

    def apply_cycle(
        self,
        entries: Dict[str, Dict[str, Any]],
        *,
        completed_sources: Set[str],
        full_sources: Optional[Set[str]] = None,
        source_high_seq: Optional[Dict[str, int]] = None,
        source_dids: Optional[Dict[str, str]] = None,
        peer_count: int = 0,
        error: str = "",
        now_ms_override: int = 0,
    ) -> None:
        """Commit complete source snapshots and retain bounded stale hints."""
        observed_at = int(now_ms_override or now_ms())
        completed = {str(source).rstrip("/") for source in completed_sources}
        full = (
            set(completed)
            if full_sources is None
            else {str(source).rstrip("/") for source in full_sources}
        )
        if not full <= completed:
            raise ValueError("full_sources must be a subset of completed_sources")
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
                now_ms_override=observed_at,
            )

        with self._lock:
            retained: Dict[str, Dict[str, Any]] = {}
            for key, entry in self._data.items():
                source = str(entry.get("source") or "").rstrip("/")
                if source in full:
                    continue
                ann = entry.get("ann")
                verified_at = int(entry.get("last_verified_ms") or 0)
                if not isinstance(ann, TaskAnnouncement):
                    continue
                if ann.is_expired(now_ms_override=observed_at):
                    continue
                if verified_at <= 0 or observed_at - verified_at > self._stale_ttl_ms:
                    continue
                retained[key] = (
                    entry if source in completed else {**entry, "stale": True}
                )
            retained.update(incoming)
            self._validate_capacity(retained)
            self._data = retained
            progress = source_high_seq or {}
            dids = source_dids or {}
            for source in completed:
                cursor = progress.get(source)
                did = dids.get(source)
                if type(cursor) is not int or cursor < -1 or not isinstance(did, str):
                    self._source_cursors.pop(source, None)
                    continue
                previous = self._source_cursors.get(source)
                last_full_ms = (
                    observed_at
                    if source in full
                    else previous[2] if previous is not None else 0
                )
                self._source_cursors[source] = (did, cursor, last_full_ms)
            self._rebuild_offer_index_locked()
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
            self._rebuild_offer_index_locked()
            self._source_cursors.pop(normalized, None)

    def mark_error(self, error: str, *, peer_count: int = 0) -> None:
        self.apply_cycle(
            {},
            completed_sources=set(),
            peer_count=peer_count,
            error=error,
        )

    def _entry_is_current(
        self,
        entry: Dict[str, Any],
        observed_at: int,
    ) -> bool:
        ann = entry.get("ann")
        verified_at = int(entry.get("last_verified_ms") or 0)
        if not isinstance(ann, TaskAnnouncement):
            return False
        if ann.is_expired(now_ms_override=observed_at):
            return False
        age = observed_at - verified_at
        return verified_at > 0 and 0 <= age <= self._stale_ttl_ms

    def _prune_expired_locked(self, observed_at: int) -> None:
        retained: Dict[str, Dict[str, Any]] = {}
        for key, entry in self._data.items():
            if self._entry_is_current(entry, observed_at):
                retained[key] = entry
        self._data = retained
        self._rebuild_offer_index_locked()

    def snapshot(
        self,
        *,
        now_ms_override: int = 0,
    ) -> Dict[str, Dict[str, Any]]:
        observed_at = int(now_ms_override or now_ms())
        with self._lock:
            self._prune_expired_locked(observed_at)
            captured = list(self._data.items())
        return {
            key: _snapshot_cache_entry(
                entry,
                federation_key=key,
            )
            for key, entry in captured
        }

    def trade_offer_snapshot(
        self,
        digest: str,
        *,
        now_ms_override: int = 0,
    ) -> List[Dict[str, Any]]:
        observed_at = int(now_ms_override or now_ms())
        with self._lock:
            indexed_keys = set(self._offer_index.get(digest, set()))
            captured = []
            for key in sorted(indexed_keys):
                entry = self._data.get(key)
                if entry is None or not self._entry_is_current(entry, observed_at):
                    self._data.pop(key, None)
                    self._offer_index.get(digest, set()).discard(key)
                    continue
                captured.append((key, entry))
            if not self._offer_index.get(digest):
                self._offer_index.pop(digest, None)
        return [
            _snapshot_cache_entry(
                entry,
                federation_key=key,
            )
            for key, entry in captured
        ]

    def status(self) -> Dict[str, Any]:
        with self._lock:
            self._prune_expired_locked(now_ms())
            return {
                "cached_announcements": len(self._data),
                "last_refresh_ms": self._last_refresh_ms,
                "last_error": self._last_error,
                "last_peer_count": self._last_peer_count,
                "stale_announcements": sum(
                    1 for entry in self._data.values() if entry.get("stale") is True
                ),
                "incremental_source_cursors": len(self._source_cursors),
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
                        source_since=cache.since_for_source,
                    )
                    rotation_offset += 1
                    cache.apply_cycle(
                        entries,
                        completed_sources=report.completed_sources,
                        full_sources=report.full_sources,
                        source_high_seq=report.source_high_seq,
                        source_dids=report.source_dids,
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
