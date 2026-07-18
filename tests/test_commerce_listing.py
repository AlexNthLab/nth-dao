from nth_dao.commerce.listing import (
    LISTING_SERVICE,
    ListingStore,
    SignedListing,
    sign_listing,
    verify_listing,
)
from nth_dao.identity import AgentIdentity
from nth_dao.util.io import atomic_write_json


def _listing(seller, now=1_800_000_000_000):
    return sign_listing(
        seller,
        SignedListing(
            listing_id="svc-code-review-v1",
            listing_type=LISTING_SERVICE,
            seller_did=seller.as_did(),
            title="Adversarial code review",
            description="Signed review service",
            price_value="50.00",
            price_currency="USDC",
            settlement_methods=["x402:usdc"],
            details={"service_code": "review", "fulfillment_type": "digital"},
            published_at_ms=now,
            not_after_ms=now + 86_400_000,
        ),
    )


def test_signed_listing_round_trip(tmp_path):
    seller = AgentIdentity.generate()
    listing = _listing(seller)
    assert verify_listing(listing) == (True, "ok")
    store = ListingStore(tmp_path)
    digest = store.save(listing)
    loaded = store.get(digest)
    assert loaded is not None
    assert loaded.to_dict() == listing.to_dict()
    assert store.save(listing) == digest


def test_tampered_listing_is_rejected():
    seller = AgentIdentity.generate()
    listing = _listing(seller)
    listing.price_value = "5.00"
    ok, reason = verify_listing(listing)
    assert not ok
    assert "signature" in reason


def test_corrupt_content_address_is_not_overwritten(tmp_path):
    seller = AgentIdentity.generate()
    listing = _listing(seller)
    store = ListingStore(tmp_path)
    digest = store.save(listing)
    path = store._path(digest)
    path.write_text("{broken", encoding="utf-8")
    try:
        store.save(listing)
    except ValueError as exc:
        assert "refuse to overwrite" in str(exc)
    else:
        raise AssertionError("corrupt signed content was overwritten")


def test_store_rejects_unsigned_unknown_listing_field(tmp_path):
    seller = AgentIdentity.generate()
    listing = _listing(seller)
    store = ListingStore(tmp_path)
    digest = store.save(listing)
    document = listing.to_dict()
    document["unsigned_surprise"] = "available"
    atomic_write_json(store._path(digest), document)

    assert store.get(digest) is None


def test_listing_signature_input_is_bounded_and_exact_length():
    seller = AgentIdentity.generate()
    listing = _listing(seller)
    listing.seller_sig = "A" * 129
    assert verify_listing(listing) == (False, "seller signature invalid")
    listing.seller_sig = "AA"
    assert verify_listing(listing) == (False, "seller signature invalid")
    listing = _listing(seller)
    listing.seller_sig += "=="
    assert verify_listing(listing) == (False, "seller signature invalid")


def test_listing_validation_fails_closed_on_recursive_details():
    seller = AgentIdentity.generate()
    recursive = {}
    recursive["self"] = recursive
    listing = SignedListing(
        listing_id="recursive",
        listing_type=LISTING_SERVICE,
        seller_did=seller.as_did(),
        title="Recursive input",
        description="",
        price_value="1",
        price_currency="USDC",
        settlement_methods=["x402:usdc"],
        details=recursive,
        published_at_ms=1_000,
        not_after_ms=2_000,
    )

    ok, reason = verify_listing(listing)

    assert not ok
    assert "details are not canonical JSON" in reason
