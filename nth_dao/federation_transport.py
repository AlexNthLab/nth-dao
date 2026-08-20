"""Bounded, IP-pinned HTTPS transport for untrusted federation hints."""

from __future__ import annotations

import http.client
import ipaddress
import queue
import socket
import ssl
import threading
import time
from collections.abc import Callable
from typing import Any, Optional
from urllib.parse import urlsplit


_MAX_DNS_WORKERS = 4
_DNS_SLOTS = threading.BoundedSemaphore(_MAX_DNS_WORKERS)


def _public_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("resolved federation address is not an IP address") from exc
    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        raise ValueError("resolved federation address is not globally routable")
    return str(address)


def validate_configured_peer_ip(value: str) -> str:
    """Accept a selected LAN/loopback host, excluding special-use targets."""

    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("resolved federation address is not an IP address") from exc
    if (
        address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        raise ValueError(
            "resolved federation address is not an allowed configured host"
        )
    return str(address)


def _timeout(value: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not 0.05 <= float(value) <= 30.0
    ):
        raise ValueError("federation transport timeout must be between 0.05 and 30")
    return float(value)


def _ascii_hostname(value: str) -> str:
    try:
        return value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("federation hostname is invalid") from exc


def _resolve_peer_ip(
    url: str,
    *,
    timeout_s: float,
    public_https_only: bool,
    resolve: Optional[Callable[..., list[Any]]] = None,
) -> Optional[str]:
    """Resolve one peer URL within a hard caller deadline.

    CPython does not expose a portable timeout for ``getaddrinfo``. Each lookup
    therefore runs in a daemon worker, while a process-wide semaphore bounds
    permanently wedged OS resolver calls. The caller always regains control by
    ``timeout_s``; at most four stuck resolver threads can exist per process.
    """

    budget = _timeout(timeout_s)
    if not isinstance(url, str):
        raise TypeError("federation URL must be text")
    try:
        parsed = urlsplit(url.strip())
        parsed.port
    except ValueError as exc:
        raise ValueError("federation URL is invalid") from exc
    allowed_schemes = {"https"} if public_https_only else {"http", "https"}
    if (
        parsed.scheme.lower() not in allowed_schemes
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        requirement = "HTTPS" if public_https_only else "HTTP(S)"
        raise ValueError(f"federation URL must be credential-free {requirement}")
    host = _ascii_hostname(parsed.hostname)
    validate_ip = _public_ip if public_https_only else validate_configured_peer_ip
    try:
        return validate_ip(host)
    except ValueError:
        pass

    deadline = time.monotonic() + budget
    remaining = deadline - time.monotonic()
    if remaining <= 0 or not _DNS_SLOTS.acquire(timeout=remaining):
        return None
    resolver = socket.getaddrinfo if resolve is None else resolve
    if not callable(resolver):
        _DNS_SLOTS.release()
        raise TypeError("resolve must be callable")
    result_queue: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

    def lookup() -> None:
        try:
            result_queue.put((True, resolver(host, None)), block=False)
        except Exception as exc:  # noqa: BLE001 - transported to the caller
            result_queue.put((False, exc), block=False)
        finally:
            _DNS_SLOTS.release()

    worker = threading.Thread(
        target=lookup,
        name="nth-federation-dns",
        daemon=True,
    )
    worker.start()
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    try:
        succeeded, value = result_queue.get(timeout=remaining)
    except queue.Empty:
        return None
    if not succeeded:
        return None
    if not isinstance(value, list) or not value:
        return None
    resolved: list[str] = []
    for item in value:
        try:
            candidate = validate_ip(item[4][0])
        except (IndexError, TypeError, ValueError):
            return None
        resolved.append(candidate)
    return resolved[0] if resolved else None


def resolve_safe_public_https_ip(
    url: str,
    *,
    timeout_s: float,
    resolve: Optional[Callable[..., list[Any]]] = None,
) -> Optional[str]:
    """Resolve an untrusted public HTTPS hint within a hard deadline."""

    return _resolve_peer_ip(
        url,
        timeout_s=timeout_s,
        public_https_only=True,
        resolve=resolve,
    )


def resolve_configured_peer_ip(
    url: str,
    *,
    timeout_s: float,
    resolve: Optional[Callable[..., list[Any]]] = None,
) -> Optional[str]:
    """Resolve an operator-selected HTTP(S) or LAN peer within a hard deadline."""

    return _resolve_peer_ip(
        url,
        timeout_s=timeout_s,
        public_https_only=False,
        resolve=resolve,
    )


def _get_bytes_pinned(
    url: str,
    resolved_ip: str,
    *,
    timeout_s: float,
    max_bytes: int,
    public_https_only: bool,
) -> bytes:
    """GET one origin from an already validated IP, preserving the Host header."""

    budget = _timeout(timeout_s)
    if type(max_bytes) is not int or not 1 <= max_bytes <= 4 * 1024 * 1024:
        raise ValueError("federation response limit is invalid")
    validate_ip = _public_ip if public_https_only else validate_configured_peer_ip
    pinned_ip = validate_ip(resolved_ip)
    try:
        parsed = urlsplit(url)
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except ValueError as exc:
        raise ValueError("federation URL contains an invalid port") from exc
    allowed_schemes = {"https"} if public_https_only else {"http", "https"}
    if (
        parsed.scheme.lower() not in allowed_schemes
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        requirement = "public HTTPS" if public_https_only else "HTTP(S)"
        raise ValueError(
            f"pinned federation fetch requires credential-free {requirement}"
        )
    hostname = _ascii_hostname(parsed.hostname)
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in target):
        raise ValueError("pinned federation target contains control characters")
    host_header = f"[{hostname}]" if ":" in hostname else hostname
    if port != 443:
        host_header = f"{host_header}:{port}"

    deadline = time.monotonic() + budget
    sock = socket.create_connection((pinned_ip, port), timeout=budget)
    socket_holder: dict[str, Any] = {"socket": sock}
    expired = threading.Event()

    def abort() -> None:
        expired.set()
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

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        sock.close()
        raise TimeoutError("pinned federation connection exceeded its deadline")
    timer = threading.Timer(remaining, abort)
    timer.daemon = True
    timer.start()
    try:
        if parsed.scheme.lower() == "https":
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=hostname)
            socket_holder["socket"] = sock
        request = (
            f"GET {target} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "Accept: application/json\r\n"
            "Connection: close\r\n\r\n"
        )
        sock.sendall(request.encode("ascii"))
        response = http.client.HTTPResponse(sock)
        response.begin()
        body = response.read(max_bytes + 1)
        if expired.is_set() or time.monotonic() > deadline:
            raise TimeoutError("pinned federation response exceeded its deadline")
        if response.status < 200 or response.status >= 300:
            raise OSError(f"federation HTTP status {response.status}")
        if len(body) > max_bytes:
            raise ValueError(f"federation response exceeds {max_bytes} bytes")
        return body
    except Exception as exc:
        if isinstance(exc, TimeoutError):
            raise
        if expired.is_set() or time.monotonic() > deadline:
            raise TimeoutError(
                "pinned federation response exceeded its deadline"
            ) from exc
        raise
    finally:
        timer.cancel()
        socket_holder["socket"] = None
        try:
            sock.close()
        except OSError:
            pass


def get_https_bytes_pinned(
    url: str,
    resolved_ip: str,
    *,
    timeout_s: float,
    max_bytes: int,
) -> bytes:
    """GET public HTTPS from a validated, pinned address."""

    return _get_bytes_pinned(
        url,
        resolved_ip,
        timeout_s=timeout_s,
        max_bytes=max_bytes,
        public_https_only=True,
    )


def get_configured_peer_bytes_pinned(
    url: str,
    resolved_ip: str,
    *,
    timeout_s: float,
    max_bytes: int,
) -> bytes:
    """GET an explicitly selected HTTP(S)/LAN peer at a pinned address."""

    return _get_bytes_pinned(
        url,
        resolved_ip,
        timeout_s=timeout_s,
        max_bytes=max_bytes,
        public_https_only=False,
    )


__all__ = [
    "get_configured_peer_bytes_pinned",
    "get_https_bytes_pinned",
    "resolve_configured_peer_ip",
    "resolve_safe_public_https_ip",
    "validate_configured_peer_ip",
]
