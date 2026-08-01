from __future__ import annotations

from copy import deepcopy

import pytest

from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.market import (
    MAX_TRADE_OFFER_ANNOUNCEMENT_TTL_MS,
    MarketFeed,
    NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1,
    announcement_listing_type,
    create_trade_offer_announcement,
    trade_offer_uri,
    verify_trade_offer_announcement_binding,
)
from nth_dao.market.announcement import sign_announcement
from nth_dao.market.federation import build_digest, verify_digest
from nth_dao.trade_rules import OfferStore, offer_body, offer_digest, sign_offer
from nth_dao.web.market_federation_poll import _verify_pulled_listing

pytestmark = pytest.mark.skipif(
    not crypto_available(),
    reason="Trade Offer announcement requires PyNaCl",
)

_PUBLISHED_MS = 1_785_542_400_000
_EXPIRES_MS = 1_817_078_400_000


def _offer(
    identity,
    *,
    state="active",
    not_after="2027-08-01T00:00:00Z",
    revision=1,
    previous_offer_digest=None,
    published_at="2026-08-01T00:00:00Z",
    proof_created="2026-08-01T00:00:01Z",
):
    return sign_offer(
        identity,
        offer_body(
            offer_id="org.nthdao.tests/swap",
            revision=revision,
            previous_offer_digest=previous_offer_digest,
            state=state,
            publisher_did=identity.as_did(),
            title="Compute for design",
            summary="Exchange one compute task for one design review.",
            provides=[
                {
                    "leg_id": "compute",
                    "resource_type": "service:compute",
                    "resource_id": "urn:nth:test:compute",
                    "quantity": "1",
                    "unit": "task",
                    "descriptor_digest": "sha256:" + ("a" * 64),
                }
            ],
            requests=[
                {
                    "leg_id": "review",
                    "resource_type": "service:design-review",
                    "resource_id": "urn:nth:test:design-review",
                    "quantity": "1",
                    "unit": "review",
                    "descriptor_digest": "sha256:" + ("b" * 64),
                }
            ],
            published_at=published_at,
            not_after=not_after,
        ),
        created=proof_created,
    )


def _fractional_offer(identity):
    body = _offer(identity).to_dict()
    body.pop("proof")
    body["published_at"] = "2026-08-01T00:00:00.000000001Z"
    return sign_offer(
        identity,
        body,
        created="2026-08-01T00:00:01Z",
    )


def _announcement(identity, offer):
    return create_trade_offer_announcement(
        identity,
        offer,
        capability_set=["design-review", "compute"],
        availability_summary={"status": "publisher-asserted-available"},
        published_at_ms=_PUBLISHED_MS + 2_000,
        not_after_ms=_PUBLISHED_MS + MAX_TRADE_OFFER_ANNOUNCEMENT_TTL_MS,
    )


def test_trade_offer_announcement_binds_exact_signed_offer():
    publisher = AgentIdentity.generate(label="publisher")
    offer = _offer(publisher)
    announcement = _announcement(publisher, offer)

    assert announcement.kind == NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1
    assert announcement_listing_type(announcement) == "exchange"
    assert announcement.offer_digest == offer_digest(offer)
    assert announcement.offer_uri == trade_offer_uri(offer_digest(offer))
    assert announcement.price_minor == 0
    assert announcement.price_asset == ""
    assert verify_trade_offer_announcement_binding(
        offer, announcement
    ) == (True, "ok")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("title", "Misleading title"),
        ("not_after", _EXPIRES_MS + 1),
    ],
)
def test_trade_offer_announcement_rejects_resigned_divergence(field, value):
    publisher = AgentIdentity.generate(label="publisher")
    offer = _offer(publisher)
    source = _announcement(publisher, offer).to_dict()
    source[field] = value
    source.pop("publisher_did")
    source.pop("publisher_sig")
    resigned = sign_announcement(publisher=publisher, **source)

    ok, _reason = verify_trade_offer_announcement_binding(offer, resigned)
    assert ok is False


def test_trade_offer_announcement_rejects_resigned_digest_and_uri_pair():
    publisher = AgentIdentity.generate(label="publisher")
    offer = _offer(publisher)
    source = _announcement(publisher, offer).to_dict()
    forged_digest = "sha256:" + ("f" * 64)
    source["offer_digest"] = forged_digest
    source["offer_uri"] = trade_offer_uri(forged_digest)
    source.pop("publisher_did")
    source.pop("publisher_sig")
    resigned = sign_announcement(publisher=publisher, **source)

    ok, reason = verify_trade_offer_announcement_binding(offer, resigned)
    assert ok is False
    assert "offer_digest" in reason


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("offer_uri", "/api/v2/trade/federation/offers/incorrect"),
        ("listing_type", "service"),
        ("reward_minor", 1),
        ("reward_asset", "credit"),
    ],
)
def test_trade_offer_announcement_schema_rejects_invalid_resigned_body(
    field, value
):
    publisher = AgentIdentity.generate(label="publisher")
    source = _announcement(publisher, _offer(publisher)).to_dict()
    source[field] = value
    source.pop("publisher_did")
    source.pop("publisher_sig")

    with pytest.raises(ValueError, match="invalid announcement schema"):
        sign_announcement(publisher=publisher, **source)


def test_trade_offer_announcement_rejects_resigned_revision_mismatch():
    publisher = AgentIdentity.generate(label="publisher")
    offer = _offer(publisher)
    source = _announcement(publisher, offer).to_dict()
    source["availability_summary"]["revision"] = 2
    source.pop("publisher_did")
    source.pop("publisher_sig")
    resigned = sign_announcement(publisher=publisher, **source)

    ok, reason = verify_trade_offer_announcement_binding(offer, resigned)
    assert ok is False
    assert "revision" in reason


def test_trade_offer_announcement_rejects_wrong_signer_and_unbounded_offer():
    publisher = AgentIdentity.generate(label="publisher")
    attacker = AgentIdentity.generate(label="attacker")

    with pytest.raises(ValueError, match="signer"):
        _announcement(attacker, _offer(publisher))
    with pytest.raises(ValueError, match="requires expiry"):
        _announcement(publisher, _offer(publisher, not_after=None))


def test_trade_offer_announcement_never_predates_fractional_publication():
    publisher = AgentIdentity.generate(label="publisher")
    offer = _fractional_offer(publisher)

    with pytest.raises(ValueError, match="must not predate"):
        create_trade_offer_announcement(
            publisher,
            offer,
            published_at_ms=_PUBLISHED_MS,
            not_after_ms=_EXPIRES_MS - 1_000,
        )
    announcement = create_trade_offer_announcement(
        publisher,
        offer,
        published_at_ms=_PUBLISHED_MS + 1,
        not_after_ms=(
            _PUBLISHED_MS + 1 + MAX_TRADE_OFFER_ANNOUNCEMENT_TTL_MS
        ),
    )
    assert verify_trade_offer_announcement_binding(offer, announcement) == (
        True,
        "ok",
    )


def test_trade_offer_announcement_has_a_hard_discovery_ttl():
    publisher = AgentIdentity.generate(label="publisher")
    offer = _offer(publisher)
    announcement = create_trade_offer_announcement(
        publisher,
        offer,
        published_at_ms=_PUBLISHED_MS,
    )
    assert (
        announcement.not_after - announcement.published_at_ms
        == MAX_TRADE_OFFER_ANNOUNCEMENT_TTL_MS
    )

    with pytest.raises(ValueError, match="lifetime exceeds 24 hours"):
        create_trade_offer_announcement(
            publisher,
            offer,
            published_at_ms=_PUBLISHED_MS,
            not_after_ms=(
                _PUBLISHED_MS + MAX_TRADE_OFFER_ANNOUNCEMENT_TTL_MS + 1
            ),
        )

    source = announcement.to_dict()
    source["not_after"] += 1
    source.pop("publisher_did")
    source.pop("publisher_sig")
    resigned = sign_announcement(publisher=publisher, **source)
    assert verify_trade_offer_announcement_binding(offer, resigned) == (
        False,
        "Trade Offer announcement lifetime exceeds 24 hours",
    )


@pytest.mark.parametrize("published_at_ms", [True, "1785542400000", 1.5])
def test_trade_offer_announcement_rejects_non_integer_publication_time(
    published_at_ms,
):
    publisher = AgentIdentity.generate(label="publisher")
    with pytest.raises(ValueError, match="publication must be an integer"):
        create_trade_offer_announcement(
            publisher,
            _offer(publisher),
            published_at_ms=published_at_ms,
        )


def test_trade_offer_announcement_rejects_reserved_availability_override():
    publisher = AgentIdentity.generate(label="publisher")
    with pytest.raises(ValueError, match="reserved"):
        create_trade_offer_announcement(
            publisher,
            _offer(publisher),
            availability_summary={"revision": 999},
            published_at_ms=_PUBLISHED_MS + 2_000,
        )


def test_trade_offer_announcement_binding_rejects_different_offer():
    publisher = AgentIdentity.generate(label="publisher")
    offer = _offer(publisher)
    announcement = _announcement(publisher, offer)
    other_body = deepcopy(offer.to_dict())
    other_body["title"] = "Different"
    other_body.pop("proof")
    other_offer = sign_offer(
        publisher,
        other_body,
        created="2026-08-01T00:00:01Z",
    )

    assert not verify_trade_offer_announcement_binding(
        other_offer, announcement
    )[0]


def test_market_feed_requires_and_rebinds_locally_stored_trade_offer(tmp_path):
    publisher = AgentIdentity.generate(label="publisher")
    offer = _offer(publisher)
    OfferStore(tmp_path).publish(offer)
    announcement = _announcement(publisher, offer)
    feed = MarketFeed(tmp_path)

    feed.publish(announcement)

    loaded = feed.get(announcement.announcement_id)
    assert loaded is not None
    assert verify_trade_offer_announcement_binding(offer, loaded) == (True, "ok")
    digest = build_digest(feed, publisher)
    assert verify_digest(digest) == (True, "")
    assert digest.refs[0]["listing_type"] == "exchange"
    assert digest.refs[0]["offer_digest"] == offer_digest(offer)


def test_market_feed_rejects_trade_offer_announcement_without_offer(tmp_path):
    publisher = AgentIdentity.generate(label="publisher")

    with pytest.raises(ValueError, match="no verified local Offer"):
        MarketFeed(tmp_path).publish(_announcement(publisher, _offer(publisher)))


def test_market_feed_drops_withdrawn_head_and_rejects_old_revision(tmp_path):
    publisher = AgentIdentity.generate(label="publisher")
    offer = _offer(publisher)
    store = OfferStore(tmp_path)
    store.publish(offer)
    announcement = _announcement(publisher, offer)
    feed = MarketFeed(tmp_path)
    feed.publish(announcement)

    withdrawn = _offer(
        publisher,
        state="withdrawn",
        revision=2,
        previous_offer_digest=offer_digest(offer),
        published_at="2026-08-01T00:01:00Z",
        proof_created="2026-08-01T00:01:01Z",
    )
    store.publish(withdrawn)

    assert feed.get(announcement.announcement_id) is None
    assert feed.poll(since_seq=-1).announcements == []
    with pytest.raises(ValueError, match="canonical chain head"):
        feed.publish(_announcement(publisher, offer))


def test_remote_trade_offer_is_fetched_verified_and_rebound():
    publisher = AgentIdentity.generate(label="publisher")
    offer = _offer(publisher)
    announcement = _announcement(publisher, offer)
    cache = {}
    fetches = 0

    def fetch_offer(url):
        nonlocal fetches
        fetches += 1
        assert url.endswith(announcement.offer_uri)
        return offer.to_dict()

    assert _verify_pulled_listing(
        "https://publisher.example", announcement, fetch_offer, cache
    )
    assert _verify_pulled_listing(
        "https://publisher.example", announcement, fetch_offer, cache
    )
    assert fetches == 1


def test_remote_trade_offer_rejects_wrong_full_document():
    publisher = AgentIdentity.generate(label="publisher")
    other = AgentIdentity.generate(label="other")
    offer = _offer(publisher)
    announcement = _announcement(publisher, offer)

    assert not _verify_pulled_listing(
        "https://publisher.example",
        announcement,
        lambda _url: _offer(other).to_dict(),
        {},
    )
