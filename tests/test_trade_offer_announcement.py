from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

import nth_dao.market.trade_offer_announcement as head_proof_module
from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.market import (
    MAX_TRADE_OFFER_HEAD_PROOF_BYTES,
    MAX_TRADE_OFFER_HEAD_PROOF_CLOCK_SKEW_MS,
    MAX_TRADE_OFFER_HEAD_PROOF_REVISIONS,
    MAX_TRADE_OFFER_ANNOUNCEMENT_TTL_MS,
    TRADE_OFFER_HEAD_PROOF_KIND_V1,
    MarketFeed,
    NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1,
    VerifiedTradeOfferHeadProof,
    announcement_federation_key,
    announcement_listing_type,
    build_trade_offer_head_proof,
    create_trade_offer_announcement,
    trade_offer_head_proof_uri,
    trade_offer_uri,
    verify_trade_offer_announcement_binding,
)
from nth_dao.market.announcement import sign_announcement
from nth_dao.market.federation import build_digest, verify_digest
from nth_dao.spine.event import MAX_SPINE_PAYLOAD_BYTES
from nth_dao.spine.log import SignedEventLog
from nth_dao.trade_rules import (
    MAX_TRADE_JSON_BYTES,
    OfferStore,
    offer_body,
    offer_digest,
    sign_offer,
)
from nth_dao.web.market_federation_poll import (
    FederationCache,
    _verify_pulled_listing,
)

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
    extensions=None,
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
            extensions=extensions,
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


def _successor(identity, previous):
    document = previous.to_dict()
    document.pop("proof")
    published = datetime.fromisoformat(
        document["published_at"].replace("Z", "+00:00")
    ) + timedelta(seconds=1)
    document["revision"] += 1
    document["previous_offer_digest"] = offer_digest(previous)
    document["published_at"] = published.astimezone(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    return sign_offer(
        identity,
        document,
        created=(published + timedelta(milliseconds=500))
        .astimezone(timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%S.500Z"),
    )


def _offer_chain(identity, length):
    chain = [_offer(identity)]
    for _ in range(1, length):
        chain.append(_successor(identity, chain[-1]))
    return chain


def test_trade_offer_announcement_binds_exact_signed_offer():
    publisher = AgentIdentity.generate(label="publisher")
    offer = _offer(publisher)
    announcement = _announcement(publisher, offer)

    assert announcement.kind == NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1
    assert announcement_listing_type(announcement) == "exchange"
    assert announcement.offer_digest == offer_digest(offer)
    assert announcement.offer_uri == trade_offer_uri(offer_digest(offer))
    assert trade_offer_head_proof_uri(offer_digest(offer)) == (
        f"{announcement.offer_uri}/head-proof"
    )
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


def test_trade_offer_head_proof_binds_complete_signed_revision_chain():
    publisher = AgentIdentity.generate(label="publisher")
    first = _offer(publisher)
    second = _offer(
        publisher,
        revision=2,
        previous_offer_digest=offer_digest(first),
        published_at="2026-08-01T00:01:00Z",
        proof_created="2026-08-01T00:01:01Z",
    )
    announcement = create_trade_offer_announcement(
        publisher,
        second,
        published_at_ms=_PUBLISHED_MS + 62_000,
        not_after_ms=(
            _PUBLISHED_MS + 62_000
            + MAX_TRADE_OFFER_ANNOUNCEMENT_TTL_MS
        ),
    )

    wire = build_trade_offer_head_proof(
        announcement,
        [first, second],
        now_ms_override=_PUBLISHED_MS + 63_000,
    )
    verified = VerifiedTradeOfferHeadProof.from_dict(
        wire,
        now_ms_override=_PUBLISHED_MS + 63_000,
    )

    assert wire["kind"] == TRADE_OFFER_HEAD_PROOF_KIND_V1
    assert verified.announcement.to_dict() == announcement.to_dict()
    assert tuple(offer_digest(item) for item in verified.offers) == (
        offer_digest(first),
        offer_digest(second),
    )
    assert verified.head.canonical_bytes == second.canonical_bytes
    assert verified.to_dict() == wire


def test_trade_offer_head_proof_accepts_64_real_revisions_and_spine_roundtrip(
    tmp_path,
):
    publisher = AgentIdentity.generate(label="publisher")
    offers = _offer_chain(publisher, MAX_TRADE_OFFER_HEAD_PROOF_REVISIONS)
    announced_at = _PUBLISHED_MS + 65_000
    announcement = create_trade_offer_announcement(
        publisher,
        offers[-1],
        published_at_ms=announced_at,
        not_after_ms=announced_at + MAX_TRADE_OFFER_ANNOUNCEMENT_TTL_MS,
    )
    wire = build_trade_offer_head_proof(
        announcement,
        offers,
        now_ms_override=announced_at + 1_000,
    )

    assert len(wire["offers"]) == MAX_TRADE_OFFER_HEAD_PROOF_REVISIONS
    assert (
        MAX_SPINE_PAYLOAD_BYTES
        - MAX_TRADE_OFFER_HEAD_PROOF_BYTES
        - MAX_TRADE_JSON_BYTES
        >= 256 * 1024
    )
    event = SignedEventLog(
        tmp_path / "spine.jsonl",
        publisher,
    ).append(
        "trade.offer.import.proposed",
        {
            "offer_digest": offer_digest(offers[-1]),
            "offer": offers[-1].to_dict(),
            "head_proof": wire,
            "source_kind": "federation-cache",
            "source_id": publisher.as_did(),
            "discovery": {"source_peer": "https://peer.example"},
            "discovery_sources": 1,
        },
        ts_ms=announced_at + 2_000,
    )
    reopened = SignedEventLog(tmp_path / "spine.jsonl", publisher)

    assert reopened.verify_chain() == (True, "ok")
    assert reopened.verified_snapshot()[0].event_id == event.event_id
    assert reopened.verified_snapshot()[0].payload["head_proof"] == wire


def test_near_maximum_head_proof_roundtrips_through_spine(tmp_path):
    publisher = AgentIdentity.generate(label="publisher")
    extensions = {
        f"org.nthdao.tests/padding-{suffix}": {"blob": "x" * 60_000}
        for suffix in ("a", "b", "c", "d")
    }
    first = _offer(publisher, extensions=extensions)
    second = _successor(publisher, first)
    announced_at = _PUBLISHED_MS + 3_000
    announcement = create_trade_offer_announcement(
        publisher,
        second,
        published_at_ms=announced_at,
        not_after_ms=announced_at + MAX_TRADE_OFFER_ANNOUNCEMENT_TTL_MS,
    )
    wire = build_trade_offer_head_proof(
        announcement,
        [first, second],
        now_ms_override=announced_at + 1_000,
    )
    proof = VerifiedTradeOfferHeadProof.from_dict(
        wire,
        now_ms_override=announced_at + 1_000,
    )

    assert 450 * 1024 <= len(proof.canonical_bytes)
    assert len(proof.canonical_bytes) <= MAX_TRADE_OFFER_HEAD_PROOF_BYTES
    event = SignedEventLog(
        tmp_path / "near-maximum-spine.jsonl",
        publisher,
    ).append(
        "trade.offer.import.proposed",
        {
            "offer_digest": offer_digest(second),
            "offer": second.to_dict(),
            "head_proof": wire,
            "source_kind": "federation-cache",
            "source_id": publisher.as_did(),
            "discovery": {"source_peer": "https://peer.example"},
            "discovery_sources": 1,
        },
        ts_ms=announced_at + 2_000,
    )
    reopened = SignedEventLog(tmp_path / "near-maximum-spine.jsonl", publisher)

    assert reopened.verify_chain() == (True, "ok")
    assert reopened.verified_snapshot()[0].event_id == event.event_id


def test_trade_offer_head_proof_rejects_65_revisions_before_record_parsing():
    publisher = AgentIdentity.generate(label="publisher")
    offer = _offer(publisher)
    wire = {
        "kind": TRADE_OFFER_HEAD_PROOF_KIND_V1,
        "announcement": _announcement(publisher, offer).to_dict(),
        "offers": [offer.to_dict()] * (
            MAX_TRADE_OFFER_HEAD_PROOF_REVISIONS + 1
        ),
    }

    with pytest.raises(ValueError, match="revision count"):
        VerifiedTradeOfferHeadProof.from_dict(
            wire,
            now_ms_override=_PUBLISHED_MS + 3_000,
        )


def test_trade_offer_head_proof_enforces_exact_encoded_byte_boundary(
    monkeypatch,
):
    publisher = AgentIdentity.generate(label="publisher")
    offer = _offer(publisher)
    wire = {
        "kind": TRADE_OFFER_HEAD_PROOF_KIND_V1,
        "announcement": _announcement(publisher, offer).to_dict(),
        "offers": [offer.to_dict()],
    }
    encoded_size = len(
        VerifiedTradeOfferHeadProof.from_dict(
            wire,
            now_ms_override=_PUBLISHED_MS + 3_000,
        ).canonical_bytes
    )

    monkeypatch.setattr(
        head_proof_module,
        "MAX_TRADE_OFFER_HEAD_PROOF_BYTES",
        encoded_size,
    )
    VerifiedTradeOfferHeadProof.from_dict(
        wire,
        now_ms_override=_PUBLISHED_MS + 3_000,
    )
    monkeypatch.setattr(
        head_proof_module,
        "MAX_TRADE_OFFER_HEAD_PROOF_BYTES",
        encoded_size - 1,
    )
    with pytest.raises(ValueError, match="byte limit"):
        VerifiedTradeOfferHeadProof.from_dict(
            wire,
            now_ms_override=_PUBLISHED_MS + 3_000,
        )


def test_trade_offer_head_proof_rejects_oversize_before_signed_record_parsing(
    monkeypatch,
):
    monkeypatch.setattr(
        head_proof_module,
        "MAX_TRADE_OFFER_HEAD_PROOF_BYTES",
        512,
    )
    oversized_invalid_wire = {
        "kind": TRADE_OFFER_HEAD_PROOF_KIND_V1,
        "announcement": None,
        "offers": [{"untrusted_padding": "x" * 1_024}],
    }

    with pytest.raises(ValueError, match="byte limit"):
        VerifiedTradeOfferHeadProof.from_dict(oversized_invalid_wire)


def test_trade_offer_head_proof_future_clock_skew_boundary():
    publisher = AgentIdentity.generate(label="publisher")
    offer = _offer(publisher)
    announcement = _announcement(publisher, offer)
    wire = {
        "kind": TRADE_OFFER_HEAD_PROOF_KIND_V1,
        "announcement": announcement.to_dict(),
        "offers": [offer.to_dict()],
    }
    boundary = (
        announcement.published_at_ms
        - MAX_TRADE_OFFER_HEAD_PROOF_CLOCK_SKEW_MS
    )

    VerifiedTradeOfferHeadProof.from_dict(wire, now_ms_override=boundary)
    with pytest.raises(ValueError, match="time is not currently valid"):
        VerifiedTradeOfferHeadProof.from_dict(
            wire,
            now_ms_override=boundary - 1,
        )


@pytest.mark.parametrize(
    "mutation",
    ["missing-genesis", "reordered", "wrong-head", "expired"],
)
def test_trade_offer_head_proof_rejects_incomplete_or_false_claim(
    mutation,
):
    publisher = AgentIdentity.generate(label="publisher")
    first = _offer(publisher)
    second = _offer(
        publisher,
        revision=2,
        previous_offer_digest=offer_digest(first),
        published_at="2026-08-01T00:01:00Z",
        proof_created="2026-08-01T00:01:01Z",
    )
    announcement = create_trade_offer_announcement(
        publisher,
        second,
        published_at_ms=_PUBLISHED_MS + 62_000,
        not_after_ms=(
            _PUBLISHED_MS + 62_000
            + MAX_TRADE_OFFER_ANNOUNCEMENT_TTL_MS
        ),
    )
    offers = [first.to_dict(), second.to_dict()]
    now_ms_override = _PUBLISHED_MS + 63_000
    if mutation == "missing-genesis":
        offers = offers[1:]
    elif mutation == "reordered":
        offers.reverse()
    elif mutation == "wrong-head":
        announcement = _announcement(publisher, first)
    else:
        now_ms_override = announcement.not_after + 1
    wire = {
        "kind": TRADE_OFFER_HEAD_PROOF_KIND_V1,
        "announcement": announcement.to_dict(),
        "offers": offers,
    }

    with pytest.raises(ValueError):
        VerifiedTradeOfferHeadProof.from_dict(
            wire,
            now_ms_override=now_ms_override,
        )


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
    digest = build_digest(
        feed,
        publisher,
        now_ms_override=_PUBLISHED_MS + 3_000,
    )
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
    proof = build_trade_offer_head_proof(
        announcement,
        [offer],
        now_ms_override=_PUBLISHED_MS + 3_000,
    )
    cache = {}
    fetches = 0

    def fetch_offer(url):
        nonlocal fetches
        fetches += 1
        assert url.endswith(f"{announcement.offer_uri}/head-proof")
        return proof

    assert _verify_pulled_listing(
        "https://publisher.example",
        announcement,
        fetch_offer,
        cache,
        now_ms_override=_PUBLISHED_MS + 3_000,
    )
    assert _verify_pulled_listing(
        "https://publisher.example",
        announcement,
        fetch_offer,
        cache,
        now_ms_override=_PUBLISHED_MS + 3_000,
    )
    assert fetches == 1
    assert isinstance(cache[offer_digest(offer)], VerifiedTradeOfferHeadProof)


def test_remote_trade_offer_does_not_reuse_proof_for_another_announcement():
    publisher = AgentIdentity.generate(label="publisher")
    offer = _offer(publisher)
    first = _announcement(publisher, offer)
    second = create_trade_offer_announcement(
        publisher,
        offer,
        capability_set=["design-review", "compute"],
        availability_summary={"status": "publisher-asserted-available"},
        announcement_id="different-signed-announcement",
        published_at_ms=_PUBLISHED_MS + 3_000,
        not_after_ms=_PUBLISHED_MS + MAX_TRADE_OFFER_ANNOUNCEMENT_TTL_MS,
    )
    proof = build_trade_offer_head_proof(
        first,
        [offer],
        now_ms_override=_PUBLISHED_MS + 4_000,
    )
    cache = {}

    assert _verify_pulled_listing(
        "https://publisher.example",
        first,
        lambda _url: proof,
        cache,
        now_ms_override=_PUBLISHED_MS + 4_000,
    )
    assert not _verify_pulled_listing(
        "https://publisher.example",
        second,
        lambda _url: pytest.fail("cached proof should not be fetched again"),
        cache,
        now_ms_override=_PUBLISHED_MS + 4_000,
    )


def test_federation_cache_uses_the_cycle_verification_clock():
    publisher = AgentIdentity.generate(label="publisher")
    offer = _offer(publisher)
    announcement = _announcement(publisher, offer)
    observed_at = _PUBLISHED_MS + 3_000
    proof = VerifiedTradeOfferHeadProof.from_dict(
        build_trade_offer_head_proof(
            announcement,
            [offer],
            now_ms_override=observed_at,
        ),
        now_ms_override=observed_at,
    )
    federation_key = announcement_federation_key(announcement)
    entry = {
        "ann": announcement,
        "source": "https://publisher.example",
        "source_did": publisher.as_did(),
        "federation_key": federation_key,
        "trade_offer": offer,
        "trade_offer_head_proof": proof,
    }
    cache = FederationCache()

    cache.apply_cycle(
        {federation_key: entry},
        completed_sources={"https://publisher.example"},
        now_ms_override=observed_at,
    )

    snapshot = cache.trade_offer_snapshot(
        offer_digest(offer),
        now_ms_override=observed_at,
    )
    assert len(snapshot) == 1
    assert snapshot[0]["trade_offer_head_proof"].canonical_bytes == (
        proof.canonical_bytes
    )


def test_federation_cache_reads_do_not_repeat_head_proof_verification(
    monkeypatch,
):
    publisher = AgentIdentity.generate(label="publisher")
    offer = _offer(publisher)
    announcement = _announcement(publisher, offer)
    observed_at = _PUBLISHED_MS + 3_000
    proof = VerifiedTradeOfferHeadProof.from_dict(
        build_trade_offer_head_proof(
            announcement,
            [offer],
            now_ms_override=observed_at,
        ),
        now_ms_override=observed_at,
    )
    federation_key = announcement_federation_key(announcement)
    cache = FederationCache()
    cache.apply_cycle(
        {
            federation_key: {
                "ann": announcement,
                "source": "https://publisher.example",
                "source_did": publisher.as_did(),
                "federation_key": federation_key,
                "trade_offer": offer,
                "trade_offer_head_proof": proof,
            }
        },
        completed_sources={"https://publisher.example"},
        now_ms_override=observed_at,
    )

    def unexpected_reverification(*_args, **_kwargs):
        raise AssertionError("cache read repeated head proof verification")

    monkeypatch.setattr(
        VerifiedTradeOfferHeadProof,
        "from_dict",
        classmethod(unexpected_reverification),
    )
    all_entries = cache.snapshot(now_ms_override=observed_at)
    offer_entries = cache.trade_offer_snapshot(
        offer_digest(offer),
        now_ms_override=observed_at,
    )

    cached_proof = all_entries[federation_key]["trade_offer_head_proof"]
    assert offer_entries[0]["trade_offer_head_proof"] is cached_proof
    assert cached_proof.canonical_bytes == proof.canonical_bytes
    all_entries[federation_key]["ann"].title = "caller mutation"
    assert cache.snapshot(now_ms_override=observed_at)[federation_key][
        "ann"
    ].title == announcement.title


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
