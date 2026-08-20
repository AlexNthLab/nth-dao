"""Production-boundary tests for federation peer identity verification."""

from __future__ import annotations

import json

import pytest

from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.plugins.federation_trust import FederationTrustKernel


pytestmark = pytest.mark.skipif(
    not crypto_available(),
    reason="PyNaCl is required for signed federation identity tests",
)


def _signed_card(identity: AgentIdentity, peer_url: str) -> dict:
    card = {
        "kind": "nth-dao-identity-card-v1",
        "did": identity.as_did(),
        "pubkey_hex": identity.pubkey_hex,
        "federation": {
            "enabled": True,
            "peer_url": peer_url,
            "protocol": "nth-dao-federation-v1",
        },
    }
    card["sig"] = identity.sign_json(card)
    return card


def _dns_answers(*addresses: str):
    return [
        (None, None, None, None, (address, 443))
        for address in addresses
    ]


def test_production_resolver_rejects_non_https_private_and_mixed_dns() -> None:
    from nth_dao.web.market_federation_poll import _resolve_safe_gossip_ip

    def public(_host, _port):
        return _dns_answers("93.184.216.34")

    def private(_host, _port):
        return _dns_answers("10.0.0.7")

    def mixed(_host, _port):
        return _dns_answers("93.184.216.34", "127.0.0.1")

    assert (
        _resolve_safe_gossip_ip("https://peer.example", resolve=public)
        == "93.184.216.34"
    )
    assert _resolve_safe_gossip_ip("http://peer.example", resolve=public) is None
    assert _resolve_safe_gossip_ip("https://peer.example", resolve=private) is None
    assert _resolve_safe_gossip_ip("https://peer.example", resolve=mixed) is None


def test_kernel_pins_signed_identity_fetch_to_the_validated_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.plugins.federation_trust as trust
    import nth_dao.web.market_federation_poll as poll

    identity = AgentIdentity.generate(label="remote")
    peer_url = "https://peer.example"
    card = _signed_card(identity, peer_url)
    calls = []

    monkeypatch.setattr(
        poll,
        "_resolve_safe_gossip_ip",
        lambda url: calls.append(("resolve", url)) or "93.184.216.34",
    )

    def open_card(url: str, timeout_seconds: float, resolved_ip: str = "") -> bytes:
        calls.append(("fetch", url, timeout_seconds, resolved_ip))
        return json.dumps(card).encode("utf-8")

    monkeypatch.setattr(trust, "open_federation_identity_card", open_card)

    endpoint = FederationTrustKernel().verify_seed(peer_url)

    assert endpoint is not None
    assert endpoint.did == identity.as_did()
    assert endpoint.resolved_ip == "93.184.216.34"
    assert calls == [
        ("resolve", peer_url),
        (
            "fetch",
            f"{peer_url}/.well-known/nth-dao/identity.json",
            5.0,
            "93.184.216.34",
        ),
    ]


def test_kernel_rejects_private_binding_even_if_resolver_regresses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.plugins.federation_trust as trust
    import nth_dao.web.market_federation_poll as poll

    identity = AgentIdentity.generate(label="remote")
    monkeypatch.setattr(
        poll,
        "_resolve_safe_gossip_ip",
        lambda _url: "10.0.0.7",
    )
    monkeypatch.setattr(
        trust,
        "fetch_and_verify_federation_identity",
        lambda *_args, **_kwargs: ({"did": identity.as_did()}, ""),
    )

    with pytest.raises(ValueError, match="globally routable"):
        FederationTrustKernel().verify_seed("https://peer.example")


def test_kernel_rejects_a_valid_signature_bound_to_another_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.plugins.federation_trust as trust
    import nth_dao.web.market_federation_poll as poll

    identity = AgentIdentity.generate(label="remote")
    card = _signed_card(identity, "https://other.example")
    monkeypatch.setattr(
        poll,
        "_resolve_safe_gossip_ip",
        lambda _url: "93.184.216.34",
    )
    monkeypatch.setattr(
        trust,
        "open_federation_identity_card",
        lambda *_args, **_kwargs: json.dumps(card).encode("utf-8"),
    )

    assert FederationTrustKernel().verify_seed("https://peer.example") is None
