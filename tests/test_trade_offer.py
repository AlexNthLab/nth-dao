import copy
import hashlib
from datetime import datetime, timezone

import pytest

import nth_dao.trade_rules.offer as offer_module
from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.trade_rules import (
    OFFER_SIGNING_DOMAIN,
    InspectedTradeOffer,
    OfferRejected,
    TradeOffer,
    evaluate_offer,
    offer_body,
    offer_digest,
    offer_inspection_digest,
    offer_signing_input,
    sign_offer,
    verify_offer,
    verify_offer_successor,
)

pytestmark = pytest.mark.skipif(
    not crypto_available(), reason="Trade Offer signatures require PyNaCl"
)


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _leg(
    leg_id: str,
    *,
    resource_type: str = "service",
    resource_id: str = "urn:nthdao:service:code-review",
    quantity: str = "1",
    unit: str = "job",
    descriptor_digest: str = "",
):
    if not descriptor_digest:
        descriptor_digest = _digest(
            f"{resource_type}:{resource_id}".encode("utf-8")
        )
    return {
        "leg_id": leg_id,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "quantity": quantity,
        "unit": unit,
        "descriptor_digest": descriptor_digest,
    }


def _body(identity: AgentIdentity, **overrides):
    values = {
        "offer_id": "org.nthdao.test/code-review",
        "publisher_did": identity.as_did(),
        "title": "Code review",
        "summary": "A content-addressed review result.",
        "provides": [_leg("review")],
        "requests": [],
        "rule_refs": [],
        "published_at": "2026-07-29T00:00:00Z",
        "not_after": "2027-07-29T00:00:00Z",
    }
    values.update(overrides)
    return offer_body(**values)


def _signed(identity: AgentIdentity | None = None):
    identity = identity or AgentIdentity.generate(label="offer-publisher")
    return identity, sign_offer(
        identity,
        _body(identity),
        created="2026-07-29T00:00:01Z",
    )


def test_free_offer_sign_verify_digest_and_round_trip():
    _, offer = _signed()
    assert offer.verified
    assert verify_offer(offer) == (True, "ok")
    assert offer.to_dict()["requests"] == []
    assert offer_signing_input(offer.to_dict()).startswith(
        OFFER_SIGNING_DOMAIN + b"\x00"
    )
    loaded = TradeOffer.from_json(offer.canonical_bytes)
    assert loaded.canonical_bytes == offer.canonical_bytes
    assert offer_digest(loaded) == offer_digest(offer)


def test_arbitrary_asset_swap_has_no_privileged_currency():
    identity = AgentIdentity.generate()
    body = _body(
        identity,
        title="BTC for a Solana asset",
        provides=[
            _leg(
                "btc",
                resource_type="asset:fungible",
                resource_id="bitcoin:btc",
                quantity="0.01",
                unit="btc",
            )
        ],
        requests=[
            _leg(
                "meme",
                resource_type="asset:fungible",
                resource_id="solana:spl:ExampleMint",
                quantity="1000",
                unit="token",
            )
        ],
    )
    offer = sign_offer(identity, body, created="2026-07-29T00:00:01Z")
    document = offer.to_dict()
    assert document["provides"][0]["resource_id"] == "bitcoin:btc"
    assert document["requests"][0]["resource_id"].startswith("solana:spl:")
    assert "price" not in document
    assert verify_offer(offer) == (True, "ok")


def test_product_for_service_and_exact_rule_binding():
    identity = AgentIdentity.generate()
    rule_digest = _digest(b"community escrow rule")
    body = _body(
        identity,
        provides=[
            _leg(
                "laptop",
                resource_type="product:physical",
                resource_id="urn:example:inventory:laptop-42",
                unit="item",
                descriptor_digest=_digest(b"laptop descriptor"),
            )
        ],
        requests=[
            _leg(
                "translation",
                resource_type="service",
                resource_id="urn:example:service:translation",
                quantity="20",
                unit="page",
            )
        ],
        rule_refs=[
            {
                "rule_id": "org.example.community/escrow",
                "digest": rule_digest,
            }
        ],
    )
    offer = sign_offer(identity, body, created="2026-07-29T00:00:01Z")
    assert offer.to_dict()["rule_refs"] == [
        {
            "rule_id": "org.example.community/escrow",
            "digest": rule_digest,
        }
    ]


@pytest.mark.parametrize(
    "quantity",
    ["0", "-1", "01", "1.0", "1.", ".5", "1e3", "NaN", "0.0000000000000000000000000000001"],
)
def test_offer_rejects_noncanonical_or_unsafe_quantities(quantity):
    identity = AgentIdentity.generate()
    with pytest.raises(OfferRejected, match="quantity"):
        _body(identity, provides=[_leg("item", quantity=quantity)])


def test_offer_rejects_duplicate_leg_id_across_sides():
    identity = AgentIdentity.generate()
    with pytest.raises(OfferRejected, match="unique across"):
        _body(
            identity,
            provides=[_leg("same")],
            requests=[_leg("same", resource_id="urn:example:other")],
        )


def test_offer_rejects_missing_provided_value():
    identity = AgentIdentity.generate()
    with pytest.raises(OfferRejected, match="provides"):
        _body(identity, provides=[])


@pytest.mark.parametrize(
    "resource_id",
    [
        "../secret",
        "javascript:alert(1)",
        "data:text/plain,unsafe",
        "file:///tmp/key",
        "not-namespaced",
        "contains space:value",
    ],
)
def test_offer_rejects_unsafe_or_ambiguous_resource_ids(resource_id):
    identity = AgentIdentity.generate()
    with pytest.raises(OfferRejected, match="resource_id"):
        _body(
            identity,
            provides=[
                _leg(
                    "item",
                    resource_id=resource_id,
                    descriptor_digest=_digest(b"descriptor"),
                )
            ],
        )


def test_offer_requires_every_resource_descriptor_to_be_content_bound():
    identity = AgentIdentity.generate()
    leg = _leg("item")
    leg["descriptor_digest"] = None
    with pytest.raises(OfferRejected, match="descriptor_digest"):
        _body(identity, provides=[leg])


def test_offer_builder_normalizes_leg_and_rule_order():
    identity = AgentIdentity.generate()
    rule_a = {"rule_id": "org.example/a", "digest": _digest(b"a")}
    rule_z = {"rule_id": "org.example/z", "digest": _digest(b"z")}
    body = _body(
        identity,
        provides=[_leg("z"), _leg("a", resource_id="urn:example:a")],
        rule_refs=[rule_z, rule_a],
    )
    assert [leg["leg_id"] for leg in body["provides"]] == ["a", "z"]
    assert [rule["rule_id"] for rule in body["rule_refs"]] == [
        "org.example/a",
        "org.example/z",
    ]


def test_offer_rejects_signer_publisher_mismatch():
    publisher = AgentIdentity.generate()
    attacker = AgentIdentity.generate()
    with pytest.raises(OfferRejected, match="signer"):
        sign_offer(
            attacker,
            _body(publisher),
            created="2026-07-29T00:00:01Z",
        )


@pytest.mark.parametrize(
    "path, value",
    [
        (("title",), "Tampered title"),
        (("provides", 0, "quantity"), "2"),
        (("proof", "created"), "2026-07-29T00:00:02Z"),
        (("proof", "proof_purpose"), "authentication"),
    ],
)
def test_offer_tampering_fails_verification(path, value):
    _, offer = _signed()
    document = offer.to_dict()
    target = document
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    assert verify_offer(document)[0] is False
    with pytest.raises(OfferRejected):
        TradeOffer.from_dict(document)


def test_offer_rejects_unknown_unsigned_field():
    _, offer = _signed()
    document = offer.to_dict()
    document["negotiated_price"] = "1"
    assert verify_offer(document)[0] is False


def test_inspected_offer_cannot_be_promoted_to_verified_digest():
    _, offer = _signed()
    document = offer.to_dict()
    document["proof"]["proof_value"] = "A" * 86
    inspected = InspectedTradeOffer.from_dict(document)
    assert not inspected.verified
    with pytest.raises(OfferRejected, match="verified offer"):
        offer_digest(inspected)
    assert offer_inspection_digest(inspected).startswith("unverified-sha256:")


def test_offer_wrapper_copies_mutable_inputs_and_outputs():
    identity = AgentIdentity.generate()
    provides = [_leg("review")]
    body = _body(identity, provides=provides)
    provides[0]["quantity"] = "999"
    assert body["provides"][0]["quantity"] == "1"
    offer = sign_offer(identity, body, created="2026-07-29T00:00:01Z")
    returned = offer.to_dict()
    returned["provides"][0]["quantity"] = "999"
    assert offer.to_dict()["provides"][0]["quantity"] == "1"


def test_offer_json_parser_rejects_duplicate_keys():
    _, offer = _signed()
    raw = offer.canonical_bytes.decode("utf-8")
    duplicated = '{"kind":"org.nthdao.trade.offer",' + raw[1:]
    with pytest.raises(OfferRejected, match="duplicate"):
        TradeOffer.from_json(duplicated)


def test_offer_digest_rejects_tampered_mapping():
    _, offer = _signed()
    document = copy.deepcopy(offer.to_dict())
    document["summary"] = "tampered"
    with pytest.raises(OfferRejected, match="signature"):
        offer_digest(document)


def test_offer_revision_chain_and_withdrawal_are_append_only():
    identity, first = _signed()
    second_body = _body(
        identity,
        revision=2,
        previous_offer_digest=offer_digest(first),
        published_at="2026-07-30T00:00:00Z",
        not_after="2027-07-30T00:00:00Z",
    )
    second = sign_offer(identity, second_body, created="2026-07-30T00:00:01Z")
    assert verify_offer_successor(first, second) == (True, "ok")

    withdrawal_body = _body(
        identity,
        revision=3,
        previous_offer_digest=offer_digest(second),
        state="withdrawn",
        published_at="2026-07-31T00:00:00Z",
        not_after="2027-07-31T00:00:00Z",
    )
    withdrawal = sign_offer(
        identity, withdrawal_body, created="2026-07-31T00:00:01Z"
    )
    assert verify_offer_successor(second, withdrawal) == (True, "ok")

    revival_body = _body(
        identity,
        revision=4,
        previous_offer_digest=offer_digest(withdrawal),
        published_at="2026-08-01T00:00:00Z",
        not_after="2027-08-01T00:00:00Z",
    )
    revival = sign_offer(identity, revival_body, created="2026-08-01T00:00:01Z")
    assert verify_offer_successor(withdrawal, revival) == (
        False,
        "withdrawal_is_terminal",
    )


@pytest.mark.parametrize(
    "overrides, reason",
    [
        ({"revision": 0}, "revision"),
        ({"revision": True}, "revision"),
        (
            {"revision": 1, "previous_offer_digest": "sha256:" + ("0" * 64)},
            "must not declare",
        ),
        ({"revision": 2, "previous_offer_digest": None}, "previous_offer_digest"),
        ({"state": "withdrawn"}, "initial offer"),
        ({"state": "deleted"}, "state"),
    ],
)
def test_offer_rejects_invalid_lifecycle_shape(overrides, reason):
    identity = AgentIdentity.generate()
    with pytest.raises(OfferRejected, match=reason):
        _body(identity, **overrides)


def test_offer_successor_rejects_forks_and_broken_chains():
    identity, first = _signed()
    wrong_previous = _body(
        identity,
        revision=2,
        previous_offer_digest="sha256:" + ("0" * 64),
        published_at="2026-07-30T00:00:00Z",
        not_after="2027-07-30T00:00:00Z",
    )
    fork = sign_offer(identity, wrong_previous, created="2026-07-30T00:00:01Z")
    assert verify_offer_successor(first, fork) == (
        False,
        "previous_digest_mismatch",
    )


def test_evaluate_offer_separates_integrity_from_current_activity():
    identity, active = _signed()
    assert evaluate_offer(
        active, at=datetime(2026, 7, 29, 0, 0, 2, tzinfo=timezone.utc)
    ) == (True, "active")
    assert evaluate_offer(
        active, at=datetime(2026, 7, 28, 23, 59, 59, tzinfo=timezone.utc)
    ) == (False, "not_yet_active")
    assert evaluate_offer(
        active, at=datetime(2027, 7, 29, 0, 0, 0, tzinfo=timezone.utc)
    ) == (False, "expired")
    with pytest.raises(ValueError, match="timezone-aware"):
        evaluate_offer(active, at=datetime(2026, 7, 29))


def test_offer_wrapper_has_no_public_trust_forging_constructor():
    with pytest.raises(TypeError):
        TradeOffer(b"{}", True)


def test_offer_private_factory_cannot_forge_verified_state():
    forged = TradeOffer._create(b"{}")
    assert forged.verified is False


def test_offer_verifies_the_same_snapshot_that_it_stores(monkeypatch):
    _, valid_offer = _signed()
    valid_document = valid_offer.to_dict()
    shared_document = copy.deepcopy(valid_document)
    shared_document["title"] = "tampered before verification"
    real_verify = offer_module._verify_snapshot_signature

    def mutate_caller_then_verify(snapshot):
        shared_document.clear()
        shared_document.update(copy.deepcopy(valid_document))
        return real_verify(snapshot)

    monkeypatch.setattr(
        offer_module,
        "_verify_snapshot_signature",
        mutate_caller_then_verify,
    )
    with pytest.raises(OfferRejected, match="signature"):
        TradeOffer.from_dict(shared_document)


@pytest.mark.parametrize(
    "mutator",
    [
        lambda document: document.__setitem__(1, "bad-key"),
        lambda document: document["provides"][0].__setitem__("quantity", []),
        lambda document: document["proof"].__setitem__("created", []),
        lambda document: document["extensions"].__setitem__(1, {}),
    ],
)
def test_from_dict_type_confusion_fails_as_offer_rejected(mutator):
    _, offer = _signed()
    document = offer.to_dict()
    mutator(document)
    with pytest.raises(OfferRejected):
        InspectedTradeOffer.from_dict(document)
