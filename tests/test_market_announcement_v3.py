import pytest

from nth_dao.commerce.listing import (
    ListingStore,
    SignedListing,
    listing_digest,
    sign_listing,
)
from nth_dao.commerce.listing_announcement import (
    listing_offer_uri,
    publish_listing_announcement,
    verify_listing_announcement_binding,
)
from nth_dao.identity import AgentIdentity
from nth_dao.b64u import b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.market import NTH_ANNOUNCEMENT_KIND_V3, announcement_listing_type
from nth_dao.market.announcement import (
    REJECT_ANN_SCHEMA_INVALID,
    sign_announcement,
    verify_announcement,
)
from nth_dao.market.feed import MarketFeed
from nth_dao.market.federation import FeedDigest, build_digest, verify_digest


def _v3(publisher):
    return sign_announcement(
        publisher=publisher,
        title="Signed review service",
        capability_set=["code_review"],
        reward_minor=50_000_000,
        reward_asset="USDC",
        kind=NTH_ANNOUNCEMENT_KIND_V3,
        listing_type="service",
        offer_digest="sha256:" + "a" * 64,
        offer_uri=listing_offer_uri("sha256:" + "a" * 64),
        price_minor=50_000_000,
        price_asset="USDC",
        availability_summary={"status": "available"},
    )


def _published_v3(root, publisher):
    listing = sign_listing(
        publisher,
        SignedListing(
            listing_id="svc-review-v1",
            listing_type="service",
            seller_did=publisher.as_did(),
            title="Signed review service",
            description="One review",
            price_value="50",
            price_currency="USDC",
            settlement_methods=["x402:usdc"],
            published_at_ms=1_000,
            not_after_ms=9_999_999_999_999,
        ),
    )
    feed = MarketFeed(root)
    announcement = publish_listing_announcement(
        ListingStore(root),
        feed,
        seller=publisher,
        listing=listing,
        capability_set=["code_review"],
        availability_summary={"status": "available"},
    )
    return listing, announcement, feed


def test_v3_announcement_round_trip_through_feed(tmp_path):
    publisher = AgentIdentity.generate()
    _, ann, feed = _published_v3(tmp_path, publisher)
    assert verify_announcement(ann) == (True, "")
    assert announcement_listing_type(ann) == "service"
    loaded = feed.get(ann.announcement_id)
    assert loaded is not None
    assert loaded.offer_digest == ann.offer_digest
    assert verify_announcement(loaded) == (True, "")
    digest = build_digest(feed, publisher)
    assert verify_digest(digest) == (True, "")
    assert digest.refs[0]["listing_type"] == "service"
    assert digest.refs[0]["offer_digest"] == ann.offer_digest


def test_legacy_listing_type_remains_compatible():
    publisher = AgentIdentity.generate()
    ann = sign_announcement(
        publisher=publisher,
        title="Legacy product",
        input_schema={"__nth_listing_type": "product"},
    )
    assert announcement_listing_type(ann) == "product"
    assert verify_announcement(ann) == (True, "")


def test_legacy_signature_cannot_authenticate_injected_v3_fields():
    publisher = AgentIdentity.generate()
    ann = sign_announcement(publisher=publisher, title="Task")
    ann.listing_type = "service"
    ann.offer_digest = "sha256:" + "a" * 64
    assert verify_announcement(ann) == (False, REJECT_ANN_SCHEMA_INVALID)


def test_announcement_rejects_noncanonical_padded_signature():
    publisher = AgentIdentity.generate()
    ann = _v3(publisher)
    ann.publisher_sig += "=="

    assert verify_announcement(ann)[0] is False


def test_v3_requires_content_addressed_offer():
    publisher = AgentIdentity.generate()
    try:
        sign_announcement(
            publisher=publisher,
            title="Bad offer",
            kind=NTH_ANNOUNCEMENT_KIND_V3,
            listing_type="service",
            offer_digest="https://seller.example/offer",
            price_asset="USDC",
        )
    except ValueError as exc:
        assert "schema" in str(exc)
    else:
        raise AssertionError("non-content-addressed v3 offer was signed")


def test_v3_rejects_availability_summary_too_large_for_federation():
    publisher = AgentIdentity.generate()
    with pytest.raises(ValueError, match="schema"):
        sign_announcement(
            publisher=publisher,
            title="Oversized availability",
            reward_minor=1,
            reward_asset="USDC",
            kind=NTH_ANNOUNCEMENT_KIND_V3,
            listing_type="service",
            offer_digest="sha256:" + "a" * 64,
            price_minor=1,
            price_asset="USDC",
            availability_summary={"note": "x" * 4_097},
        )


def test_signed_wire_parsers_reject_unknown_fields():
    publisher = AgentIdentity.generate()
    ann = _v3(publisher)
    ann_data = ann.to_dict()
    ann_data["unsigned_surprise"] = "available"
    with pytest.raises(ValueError, match="unknown fields"):
        type(ann).from_dict(ann_data)

    digest_data = FeedDigest(
        source_did=publisher.as_did(),
        generated_at_ms=1,
        high_seq=-1,
    ).to_dict()
    digest_data["unsigned_surprise"] = True
    with pytest.raises(ValueError, match="unknown fields"):
        FeedDigest.from_dict(digest_data)


def _listing_announcement_pair():
    seller = AgentIdentity.generate()
    listing = sign_listing(
        seller,
        SignedListing(
            listing_id="svc-review-v1",
            listing_type="service",
            seller_did=seller.as_did(),
            title="Signed review service",
            description="One review",
            price_value="50",
            price_currency="USDC",
            settlement_methods=["x402:usdc"],
            published_at_ms=1_000,
            not_after_ms=10_000,
        ),
    )
    announcement = sign_announcement(
        publisher=seller,
        title=listing.title,
        description=listing.description,
        reward_minor=50_000_000,
        reward_asset="USDC",
        kind=NTH_ANNOUNCEMENT_KIND_V3,
        listing_type=listing.listing_type,
        offer_digest=listing_digest(listing),
        offer_uri=listing_offer_uri(listing_digest(listing)),
        price_minor=50_000_000,
        price_asset="USDC",
        availability_summary={"status": "publisher-asserted-available"},
        published_at_ms=2_000,
        not_after=9_000,
    )
    return seller, listing, announcement


def test_v3_summary_is_bound_to_verified_full_listing():
    _, listing, announcement = _listing_announcement_pair()
    assert verify_listing_announcement_binding(
        listing, announcement
    ) == (True, "ok")


@pytest.mark.parametrize(
    "updates",
    [
        {"title": "Misleading title"},
        {"description": "Misleading description"},
        {"listing_type": "product"},
        {"offer_digest": "sha256:" + "b" * 64},
        {"price_minor": 49_000_000, "reward_minor": 49_000_000},
        {"price_asset": "NTH-TEST", "reward_asset": "NTH-TEST"},
        {"not_after": 11_000},
    ],
)
def test_v3_summary_binding_rejects_divergence(updates):
    seller, listing, announcement = _listing_announcement_pair()
    for field, value in updates.items():
        setattr(announcement, field, value)
    announcement.publisher_sig = ""
    announcement = sign_announcement(
        publisher=seller,
        **{
            key: val
            for key, val in announcement.to_dict().items()
            if key not in {"publisher_did", "publisher_sig"}
        },
    )
    ok, _ = verify_listing_announcement_binding(listing, announcement)
    assert ok is False


def _resign_digest(digest, identity):
    digest.digest_sig = b64u_encode(identity.sign(canonical_json(digest.signing_body())))
    return digest


@pytest.mark.parametrize(
    "mutate",
    [
        lambda ref: ref.__setitem__("price_minor", ref["price_minor"] + 1),
        lambda ref: ref.__setitem__("unsigned_surprise", True),
        lambda ref: ref.__setitem__("availability_summary", {"note": "x" * 4_097}),
    ],
)
def test_v3_federation_ref_rejects_inconsistent_or_unbounded_summary(
    tmp_path, mutate
):
    publisher = AgentIdentity.generate()
    _, _, feed = _published_v3(tmp_path, publisher)
    digest = build_digest(feed, publisher)
    mutate(digest.refs[0])
    _resign_digest(digest, publisher)
    assert verify_digest(digest) == (False, "digest-schema-invalid")


def test_feed_rejects_signed_v3_summary_without_bound_listing(tmp_path):
    publisher = AgentIdentity.generate()

    with pytest.raises(ValueError, match="no verified local listing"):
        MarketFeed(tmp_path).publish(_v3(publisher))
