"""Verification bridge between a full listing and its discovery summary."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from nth_dao.commerce.listing import (
    ListingStore,
    SignedListing,
    listing_digest,
    verify_listing,
)
from nth_dao.commerce.money import decimal_to_minor
from nth_dao.market.announcement import (
    NTH_ANNOUNCEMENT_KIND_V3,
    TaskAnnouncement,
    sign_announcement,
    verify_announcement,
)


def listing_offer_uri(digest: str) -> str:
    """Return the only v1 federation route allowed for a listing digest."""
    return f"/api/v2/commerce/federation/listings/{digest}"


def publish_listing_announcement(
    listing_store: ListingStore,
    feed: Any,
    *,
    seller: Any,
    listing: SignedListing,
    capability_set: Optional[List[str]] = None,
    context: str = "commerce",
    availability_summary: Optional[Dict[str, Any]] = None,
    announcement_id: str = "",
    published_at_ms: int = 0,
    not_after: int = 0,
) -> TaskAnnouncement:
    """Persist one signed listing and publish its derived discovery summary."""
    if seller.as_did() != listing.seller_did:
        raise ValueError("announcement signer does not match listing seller")
    digest = listing_store.save(listing)
    effective_published = published_at_ms or listing.published_at_ms
    effective_expiry = not_after or listing.not_after_ms
    price_minor = decimal_to_minor(
        listing.price_value, listing.price_currency, require_positive=True,
    )
    announcement = sign_announcement(
        publisher=seller,
        title=listing.title,
        description=listing.description,
        capability_set=list(capability_set or []),
        context=context,
        reward_minor=price_minor,
        reward_asset=listing.price_currency,
        announcement_id=announcement_id,
        published_at_ms=effective_published,
        not_after=effective_expiry,
        kind=NTH_ANNOUNCEMENT_KIND_V3,
        listing_type=listing.listing_type,
        offer_digest=digest,
        offer_uri=listing_offer_uri(digest),
        price_minor=price_minor,
        price_asset=listing.price_currency,
        availability_summary=dict(availability_summary or {}),
    )
    ok, reason = verify_listing_announcement_binding(listing, announcement)
    if not ok:
        raise ValueError(f"listing announcement rejected: {reason}")
    feed.publish(announcement)
    return announcement


def verify_listing_announcement_binding(
    listing: SignedListing,
    announcement: TaskAnnouncement,
) -> Tuple[bool, str]:
    """Verify that a signed v3 discovery summary names this signed listing.

    ``availability_summary`` is intentionally not compared: it is a fresh,
    signed publisher assertion that may change without changing the immutable
    offer. Consumers must not treat it as proof of stock or deliverability.
    """
    ok, reason = verify_listing(listing)
    if not ok:
        return False, f"listing verification failed: {reason}"
    ok, reason = verify_announcement(announcement)
    if not ok:
        return False, f"announcement verification failed: {reason}"
    if announcement.kind != NTH_ANNOUNCEMENT_KIND_V3:
        return False, "announcement is not a commerce v3 summary"

    expected = {
        "publisher_did": listing.seller_did,
        "authority_did": listing.seller_did,
        "title": listing.title,
        "description": listing.description,
        "listing_type": listing.listing_type,
        "offer_digest": listing_digest(listing),
        "price_minor": decimal_to_minor(
            listing.price_value,
            listing.price_currency,
            require_positive=True,
        ),
        "price_asset": listing.price_currency,
        "offer_uri": listing_offer_uri(listing_digest(listing)),
    }
    for field, value in expected.items():
        if getattr(announcement, field) != value:
            return False, f"listing/announcement binding mismatch: {field}"
    if announcement.published_at_ms < listing.published_at_ms:
        return False, "announcement predates the listing"
    if not announcement.not_after:
        return False, "commerce announcement must expire"
    if announcement.not_after > listing.not_after_ms:
        return False, "announcement outlives the listing"
    return True, "ok"
