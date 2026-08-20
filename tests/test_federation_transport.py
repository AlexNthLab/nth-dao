"""Hard-deadline and SSRF tests for neutral federation transport."""

from __future__ import annotations

import threading
import time

import pytest

from nth_dao.federation_transport import (
    resolve_configured_peer_ip,
    resolve_safe_public_https_ip,
    validate_configured_peer_ip,
)


def _answers(*addresses: str):
    return [(None, None, None, None, (address, 443)) for address in addresses]


def test_bounded_resolver_returns_before_a_wedged_os_lookup() -> None:
    entered = threading.Event()
    release = threading.Event()

    def blocked(_host, _port):
        entered.set()
        release.wait(5.0)
        return _answers("93.184.216.34")

    started = time.monotonic()
    try:
        assert resolve_safe_public_https_ip(
            "https://peer.example",
            timeout_s=0.1,
            resolve=blocked,
        ) is None
        elapsed = time.monotonic() - started
        assert entered.wait(0.5)
        assert elapsed < 0.5
    finally:
        release.set()


def test_bounded_resolver_rejects_non_https_private_and_mixed_dns() -> None:
    def public(_host, _port):
        return _answers("93.184.216.34")

    def private(_host, _port):
        return _answers("10.0.0.7")

    def mixed(_host, _port):
        return _answers("93.184.216.34", "127.0.0.1")

    assert resolve_safe_public_https_ip(
        "https://peer.example", timeout_s=0.5, resolve=public,
    ) == "93.184.216.34"
    with pytest.raises(ValueError, match="credential-free HTTPS"):
        resolve_safe_public_https_ip(
            "http://peer.example", timeout_s=0.5, resolve=public,
        )
    assert resolve_safe_public_https_ip(
        "https://peer.example", timeout_s=0.5, resolve=private,
    ) is None
    assert resolve_safe_public_https_ip(
        "https://peer.example", timeout_s=0.5, resolve=mixed,
    ) is None


def test_configured_peer_allows_lan_but_rejects_special_use_targets() -> None:
    assert validate_configured_peer_ip("127.0.0.1") == "127.0.0.1"
    assert validate_configured_peer_ip("192.168.1.20") == "192.168.1.20"

    for forbidden in (
        "169.254.169.254",
        "fe80::1",
        "224.0.0.1",
        "240.0.0.1",
        "0.0.0.0",
    ):
        with pytest.raises(ValueError, match="not an allowed configured host"):
            validate_configured_peer_ip(forbidden)

    assert resolve_configured_peer_ip(
        "http://lan.example:8080",
        timeout_s=0.5,
        resolve=lambda _host, _port: _answers("192.168.1.20"),
    ) == "192.168.1.20"
    assert resolve_configured_peer_ip(
        "http://metadata.example",
        timeout_s=0.5,
        resolve=lambda _host, _port: _answers("169.254.169.254"),
    ) is None
