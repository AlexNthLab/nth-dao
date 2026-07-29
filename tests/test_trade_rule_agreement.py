import copy
import hashlib
import json
import multiprocessing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import nth_dao.trade_rules as trade_rules_api

from nth_dao.canonical_json import canonical_json
from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.spine import SignedEventLog
from nth_dao.trade_rules import (
    RulePackageStore,
    RuleResolutionPolicy,
    TradeAcceptance,
    TradeAgreementRejected,
    TradeOrder,
    TradeOrderConflict,
    TradeOrderRejected,
    TradeOrderStore,
    TradeOrderStoreCapacity,
    TradeProposal,
    acceptance_digest,
    create_trade_order,
    create_trade_acceptance,
    create_trade_proposal,
    manifest_body,
    offer_body,
    offer_digest,
    proposal_digest,
    resolve_canonical_offer_rules,
    sign_manifest,
    sign_offer,
    trade_order_digest,
    verify_acceptance_binding,
)
from nth_dao.trade_rules.store import OfferStore
from nth_dao.trade_rules.agreement_conformance import (
    ACCEPTANCE_SCHEMA_PATH,
    ORDER_AUDIT_SCHEMA_PATH,
    ORDER_SCHEMA_PATH,
    PROPOSAL_SCHEMA_PATH,
    VECTORS_PATH,
    generate_vectors,
)
from nth_dao.trade_rules.agreement import (
    _sign_acceptance_body,
    _sign_proposal_body,
)
from nth_dao.trade_rules.order_audit import (
    EVENT_TRADE_ORDER_ACCEPTED,
    MAX_ORDER_AUDIT_RECORD_BYTES,
    ORDER_AUDIT_ERROR_SPINE,
    TradeOrderAuditCapacity,
    TradeOrderAuditCoordinator,
    TradeOrderAuditError,
    TradeOrderAuditOutbox,
    order_audit_payload,
    validate_order_audit_payload,
)
from nth_dao.trade_rules.order_execution import (
    TradeOrderExecutionRejected,
    verify_trade_order_execution,
)

pytestmark = pytest.mark.skipif(
    not crypto_available(), reason="Trade Rule signatures require PyNaCl"
)

_AT = datetime(2026, 8, 1, tzinfo=timezone.utc)
_ACCEPTED_AT = datetime(2026, 8, 1, 1, tzinfo=timezone.utc)
_CREATED = "2026-08-01T00:00:00Z"
_EXPIRES = "2026-08-02T00:00:00Z"


def _utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _process_put_order(root, order, output):
    try:
        stored = TradeOrderStore(root, lock_timeout=10).put(order)
        output.put(("ok", stored.order_id, trade_order_digest(stored)))
    except Exception as exc:
        output.put(("error", type(exc).__name__, str(exc)))


def _process_accept_audited_order(
    root,
    identity_path,
    order,
    now_ms,
    output,
):
    try:
        identity = AgentIdentity.load(identity_path)
        coordinator = TradeOrderAuditCoordinator(
            TradeOrderAuditOutbox(root, lock_timeout=20),
            TradeOrderStore(root, lock_timeout=20),
            SignedEventLog(
                Path(root) / "spine.jsonl",
                identity,
                lock_timeout=20,
            ),
        )
        result = coordinator.accept(order, now_ms=now_ms)
        output.put(
            (
                "ok",
                result.created,
                result.cache_created,
                result.anchor_created,
                result.record.event_id,
            )
        )
    except Exception as exc:
        output.put(("error", type(exc).__name__, str(exc)))


def _setup(tmp_path):
    maker = AgentIdentity.generate()
    taker = AgentIdentity.generate()
    rule_publisher = AgentIdentity.generate()
    package_store = RulePackageStore(tmp_path)
    offer_store = OfferStore(tmp_path)
    dependency_resource = b'{"rule":"settlement"}'
    dependency_resource_digest = _digest(dependency_resource)
    dependency_manifest = sign_manifest(
        rule_publisher,
        manifest_body(
            rule_id="org.nthdao.test.settlement",
            version="1.0.0",
            publisher_did=rule_publisher.as_did(),
            summary="Settlement dependency test rule",
            applies_to=["service"],
            families=["settlement"],
            resources=[{
                "purpose": "terms",
                "media_type": "application/json",
                "digest": dependency_resource_digest,
                "size": len(dependency_resource),
            }],
            published_at="2026-07-01T00:00:00Z",
            not_after="2027-01-01T00:00:00Z",
        ),
        created="2026-07-01T00:00:00Z",
    )
    dependency_digest = package_store.install(
        dependency_manifest,
        {dependency_resource_digest: dependency_resource},
    ).digest
    resource = b'{"rule":"delivery"}'
    resource_digest = _digest(resource)
    manifest = sign_manifest(
        rule_publisher,
        manifest_body(
            rule_id="org.nthdao.test.delivery",
            version="1.0.0",
            publisher_did=rule_publisher.as_did(),
            summary="Delivery agreement test rule",
            applies_to=["service"],
            families=["fulfillment"],
            dependencies=[{
                "rule_id": dependency_manifest.rule_id,
                "digest": dependency_digest,
            }],
            resources=[{
                "purpose": "terms",
                "media_type": "application/json",
                "digest": resource_digest,
                "size": len(resource),
            }],
            published_at="2026-07-01T00:00:00Z",
            not_after="2027-01-01T00:00:00Z",
        ),
        created="2026-07-01T00:00:00Z",
    )
    package_digest = package_store.install(
        manifest,
        {resource_digest: resource},
    ).digest
    descriptor_digest = _digest(b"service descriptor")
    offer = sign_offer(
        maker,
        offer_body(
            offer_id="org.nthdao.offer/agreement-test",
            publisher_did=maker.as_did(),
            title="Agreement test service",
            summary="One immutable service unit",
            provides=[{
                "leg_id": "service",
                "resource_type": "service",
                "resource_id": "urn:nth:test-service",
                "quantity": "1",
                "unit": "unit",
                "descriptor_digest": descriptor_digest,
            }],
            rule_refs=[{
                "rule_id": manifest.rule_id,
                "digest": package_digest,
            }],
            published_at="2026-07-01T00:00:00Z",
            not_after="2027-01-01T00:00:00Z",
        ),
        created="2026-07-01T00:00:00Z",
    )
    offer_store.publish(offer)
    taker_policy = RuleResolutionPolicy(
        accepted_publishers={rule_publisher.as_did()}
    )
    maker_policy = RuleResolutionPolicy(
        accepted_package_digests={package_digest, dependency_digest}
    )
    taker_resolution = resolve_canonical_offer_rules(
        maker.as_did(),
        offer.offer_id,
        offer_store,
        package_store,
        taker_policy,
        at=_AT,
    )
    maker_resolution = resolve_canonical_offer_rules(
        maker.as_did(),
        offer.offer_id,
        offer_store,
        package_store,
        maker_policy,
        at=datetime(2026, 8, 1, 1, tzinfo=timezone.utc),
    )
    return {
        "maker": maker,
        "taker": taker,
        "offer": offer,
        "offer_store": offer_store,
        "package_store": package_store,
        "dependency_digest": dependency_digest,
        "taker_policy": taker_policy,
        "maker_policy": maker_policy,
        "taker_resolution": taker_resolution,
        "maker_resolution": maker_resolution,
    }


def _proposal(context):
    return create_trade_proposal(
        context["taker"],
        resolution=context["taker_resolution"],
        offer=context["offer"],
        offer_resolver=context["offer_store"],
        terms={"requested_quantity": "1"},
        created_at=_CREATED,
        not_after=_EXPIRES,
        now=_AT,
    )


def _acceptance(context, proposal):
    return create_trade_acceptance(
        context["maker"],
        proposal=proposal,
        resolution=context["maker_resolution"],
        offer=context["offer"],
        offer_resolver=context["offer_store"],
        created_at="2026-08-01T01:00:00Z",
        now=_ACCEPTED_AT,
    )


def test_proposal_and_acceptance_round_trip_with_independent_policy(tmp_path):
    context = _setup(tmp_path)
    proposal = _proposal(context)
    acceptance = _acceptance(context, proposal)

    assert TradeProposal.from_json(proposal.canonical_bytes) == proposal
    assert TradeAcceptance.from_json(acceptance.canonical_bytes) == acceptance
    assert proposal_digest(proposal).startswith("sha256:")
    assert acceptance_digest(acceptance).startswith("sha256:")
    assert proposal.to_dict()["taker_policy_digest"] != (
        acceptance.to_dict()["maker_policy_digest"]
    )
    assert verify_acceptance_binding(proposal, acceptance) == (True, "ok")


def test_proposal_tampering_breaks_signature(tmp_path):
    proposal = _proposal(_setup(tmp_path))
    document = proposal.to_dict()
    document["terms"]["requested_quantity"] = "2"

    with pytest.raises(TradeAgreementRejected, match="signature invalid"):
        TradeProposal.from_dict(document)


def test_acceptance_tampering_breaks_signature(tmp_path):
    context = _setup(tmp_path)
    proposal = _proposal(context)
    acceptance = _acceptance(context, proposal)
    document = acceptance.to_dict()
    document["maker_policy"]["max_depth"] -= 1
    document["maker_policy_digest"] = _digest(
        json.dumps(
            document["maker_policy"],
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )

    with pytest.raises(TradeAgreementRejected, match="signature invalid"):
        TradeAcceptance.from_dict(document)


def test_wrong_principals_cannot_sign_statements(tmp_path):
    context = _setup(tmp_path)
    proposal = _proposal(context)
    with pytest.raises(TradeAgreementRejected, match="acceptance signer"):
        create_trade_acceptance(
            context["taker"],
            proposal=proposal,
            resolution=context["maker_resolution"],
            offer=context["offer"],
            offer_resolver=context["offer_store"],
            created_at="2026-08-01T01:00:00Z",
            now=_ACCEPTED_AT,
        )
    assert not hasattr(trade_rules_api, "sign_proposal")
    assert not hasattr(trade_rules_api, "sign_acceptance")


def test_same_principal_cannot_be_maker_and_taker(tmp_path):
    context = _setup(tmp_path)
    with pytest.raises(TradeAgreementRejected, match="different principals"):
        create_trade_proposal(
            context["maker"],
            resolution=context["taker_resolution"],
            offer=context["offer"],
            offer_resolver=context["offer_store"],
            terms={},
            created_at=_CREATED,
            not_after=_EXPIRES,
            now=_AT,
        )


def test_forged_resolution_binding_is_rejected(tmp_path):
    context = _setup(tmp_path)
    forged = replace(
        context["taker_resolution"],
        offer_digest="sha256:" + ("0" * 64),
    )

    with pytest.raises(TradeAgreementRejected, match="canonical Offer"):
        create_trade_proposal(
            context["taker"],
            resolution=forged,
            offer=context["offer"],
            offer_resolver=context["offer_store"],
            terms={},
            created_at=_CREATED,
            not_after=_EXPIRES,
            now=_AT,
        )


def test_stale_offer_cannot_be_signed_as_current_canonical_head(tmp_path):
    context = _setup(tmp_path)
    original = context["offer"].to_dict()
    successor = sign_offer(
        context["maker"],
        offer_body(
            offer_id=original["offer_id"],
            revision=2,
            previous_offer_digest=offer_digest(context["offer"]),
            publisher_did=original["publisher_did"],
            title="Updated agreement test service",
            summary=original["summary"],
            provides=original["provides"],
            requests=original["requests"],
            rule_refs=original["rule_refs"],
            published_at="2026-07-02T00:00:00Z",
            not_after=original["not_after"],
            extensions=original["extensions"],
        ),
        created="2026-07-02T00:00:00Z",
    )
    context["offer_store"].publish(successor)

    with pytest.raises(TradeAgreementRejected, match="current canonical"):
        create_trade_proposal(
            context["taker"],
            resolution=context["taker_resolution"],
            offer=context["offer"],
            offer_resolver=context["offer_store"],
            terms={},
            created_at=_CREATED,
            not_after=_EXPIRES,
            now=_AT,
        )


def test_resolution_time_is_bound_to_each_signed_statement(tmp_path):
    context = _setup(tmp_path)
    with pytest.raises(TradeAgreementRejected, match="taker resolution time"):
        create_trade_proposal(
            context["taker"],
            resolution=context["taker_resolution"],
            offer=context["offer"],
            offer_resolver=context["offer_store"],
            terms={},
            created_at="2026-08-01T00:00:01Z",
            not_after=_EXPIRES,
            now=_AT,
        )

    with pytest.raises(TradeAgreementRejected, match="maker resolution time"):
        create_trade_acceptance(
            context["maker"],
            proposal=_proposal(context),
            resolution=context["maker_resolution"],
            offer=context["offer"],
            offer_resolver=context["offer_store"],
            created_at="2026-08-01T01:00:01Z",
            now=_ACCEPTED_AT,
        )


def test_proposal_cannot_outlive_offer_and_acceptance_cannot_predate_it(
    tmp_path,
):
    context = _setup(tmp_path)
    with pytest.raises(TradeAgreementRejected, match="lifetime"):
        create_trade_proposal(
            context["taker"],
            resolution=context["taker_resolution"],
            offer=context["offer"],
            offer_resolver=context["offer_store"],
            terms={},
            created_at=_CREATED,
            not_after="2027-01-01T00:00:01Z",
            now=_AT,
        )

    with pytest.raises(TradeAgreementRejected, match="predate"):
        create_trade_acceptance(
            context["maker"],
            proposal=_proposal(context),
            resolution=replace(
                context["maker_resolution"],
                evaluated_at="2026-07-31T23:59:59Z",
            ),
            offer=context["offer"],
            offer_resolver=context["offer_store"],
            created_at="2026-07-31T23:59:59Z",
            now=_utc("2026-07-31T23:59:59Z"),
        )


def test_local_signing_time_and_proposal_ttl_are_bounded(tmp_path):
    context = _setup(tmp_path)
    with pytest.raises(TradeAgreementRejected, match="clock-skew"):
        create_trade_proposal(
            context["taker"],
            resolution=context["taker_resolution"],
            offer=context["offer"],
            offer_resolver=context["offer_store"],
            terms={},
            created_at=_CREATED,
            not_after=_EXPIRES,
            now=_AT + timedelta(minutes=6),
        )
    with pytest.raises(TradeAgreementRejected, match="lifetime"):
        create_trade_proposal(
            context["taker"],
            resolution=context["taker_resolution"],
            offer=context["offer"],
            offer_resolver=context["offer_store"],
            terms={},
            created_at=_CREATED,
            not_after="2026-08-08T00:00:01Z",
            now=_AT,
        )
    with pytest.raises(TradeAgreementRejected, match="timezone-aware"):
        create_trade_proposal(
            context["taker"],
            resolution=context["taker_resolution"],
            offer=context["offer"],
            offer_resolver=context["offer_store"],
            terms={},
            created_at=_CREATED,
            not_after=_EXPIRES,
            now=datetime(2026, 8, 1),
        )
    with pytest.raises(TradeAgreementRejected, match="finite"):
        create_trade_proposal(
            context["taker"],
            resolution=context["taker_resolution"],
            offer=context["offer"],
            offer_resolver=context["offer_store"],
            terms={},
            created_at=_CREATED,
            not_after=_EXPIRES,
            now=_AT,
            max_ttl_seconds=float("inf"),
        )

    proposal = _proposal(context)
    with pytest.raises(TradeAgreementRejected, match="clock-skew"):
        create_trade_acceptance(
            context["maker"],
            proposal=proposal,
            resolution=context["maker_resolution"],
            offer=context["offer"],
            offer_resolver=context["offer_store"],
            created_at="2026-08-01T01:00:00Z",
            now=datetime(2026, 8, 2, tzinfo=timezone.utc),
        )


def test_canonical_head_is_rechecked_after_signature(tmp_path):
    context = _setup(tmp_path)
    original = context["offer"].to_dict()
    successor = sign_offer(
        context["maker"],
        offer_body(
            offer_id=original["offer_id"],
            revision=2,
            previous_offer_digest=offer_digest(context["offer"]),
            publisher_did=original["publisher_did"],
            title="Revision published during signing",
            summary=original["summary"],
            provides=original["provides"],
            requests=original["requests"],
            rule_refs=original["rule_refs"],
            published_at="2026-07-02T00:00:00Z",
            not_after=original["not_after"],
            extensions=original["extensions"],
        ),
        created="2026-07-02T00:00:00Z",
    )

    class RacingIdentity:
        def as_did(self):
            return context["taker"].as_did()

        def sign(self, payload):
            context["offer_store"].publish(successor)
            return context["taker"].sign(payload)

    with pytest.raises(TradeAgreementRejected, match="current canonical"):
        create_trade_proposal(
            RacingIdentity(),
            resolution=context["taker_resolution"],
            offer=context["offer"],
            offer_resolver=context["offer_store"],
            terms={},
            created_at=_CREATED,
            not_after=_EXPIRES,
            now=_AT,
        )


def test_maker_resolution_must_match_signed_proposal(tmp_path):
    context = _setup(tmp_path)
    proposal = _proposal(context)
    mismatched = replace(
        context["maker_resolution"],
        policy_digest="sha256:" + ("0" * 64),
    )

    with pytest.raises(TradeAgreementRejected, match="canonical Offer"):
        create_trade_acceptance(
            context["maker"],
            proposal=proposal,
            resolution=mismatched,
            offer=context["offer"],
            offer_resolver=context["offer_store"],
            created_at="2026-08-01T01:00:00Z",
            now=_ACCEPTED_AT,
        )


@pytest.mark.parametrize(
    "created_at",
    ["2026-08-02T00:00:00Z", "2026-08-02T00:00:01Z"],
)
def test_acceptance_at_or_after_expiry_is_rejected(tmp_path, created_at):
    context = _setup(tmp_path)
    with pytest.raises(TradeAgreementRejected, match="expired"):
        create_trade_acceptance(
            context["maker"],
            proposal=_proposal(context),
            resolution=replace(
                context["maker_resolution"],
                evaluated_at=created_at,
            ),
            offer=context["offer"],
            offer_resolver=context["offer_store"],
            created_at=created_at,
            now=_utc(created_at),
        )


def test_acceptance_cannot_be_rebound_to_another_proposal(tmp_path):
    context = _setup(tmp_path)
    first = _proposal(context)
    acceptance = _acceptance(context, first)
    second = create_trade_proposal(
        context["taker"],
        resolution=context["taker_resolution"],
        offer=context["offer"],
        offer_resolver=context["offer_store"],
        terms={"requested_quantity": "1", "note": "second"},
        created_at=_CREATED,
        not_after=_EXPIRES,
        now=_AT,
    )

    ok, reason = verify_acceptance_binding(second, acceptance)

    assert ok is False
    assert "proposal digest mismatch" in reason


def test_unknown_fields_and_noncanonical_rule_order_fail_closed(tmp_path):
    proposal = _proposal(_setup(tmp_path))
    document = proposal.to_dict()
    document["unexpected"] = True
    with pytest.raises(TradeAgreementRejected, match="unknown fields"):
        TradeProposal.from_dict(document)

    document = proposal.to_dict()
    document["rule_bindings"] = list(reversed(document["rule_bindings"]))
    if len(document["rule_bindings"]) == 1:
        duplicate = copy.deepcopy(document["rule_bindings"][0])
        duplicate["rule_id"] = "org.nthdao.test.aaa"
        document["rule_bindings"].append(duplicate)
    with pytest.raises(TradeAgreementRejected, match="sorted"):
        TradeProposal.from_dict(document)


def test_oversized_terms_and_direct_construction_are_rejected(tmp_path):
    context = _setup(tmp_path)
    with pytest.raises(TradeAgreementRejected, match="terms exceeds"):
        create_trade_proposal(
            context["taker"],
            resolution=context["taker_resolution"],
            offer=context["offer"],
            offer_resolver=context["offer_store"],
            terms={"payload": "x" * (64 * 1024)},
            created_at=_CREATED,
            not_after=_EXPIRES,
            now=_AT,
        )
    with pytest.raises(TypeError):
        TradeProposal(b"{}")
    with pytest.raises(TypeError):
        TradeAcceptance(b"{}")


def test_order_is_deterministic_self_verifying_snapshot(tmp_path):
    context = _setup(tmp_path)
    proposal = _proposal(context)
    acceptance = _acceptance(context, proposal)

    first = create_trade_order(
        offer=context["offer"],
        proposal=proposal,
        acceptance=acceptance,
    )
    second = create_trade_order(
        offer=context["offer"],
        proposal=proposal,
        acceptance=acceptance,
    )

    assert first == second
    assert first.order_id.endswith(proposal_digest(proposal).split(":", 1)[1])
    assert TradeOrder.from_json(first.canonical_bytes) == first
    assert trade_order_digest(first).startswith("sha256:")
    assert first.to_dict()["snapshot"]["offer"] == context["offer"].to_dict()


def test_order_rejects_nested_snapshot_tampering(tmp_path):
    context = _setup(tmp_path)
    proposal = _proposal(context)
    order = create_trade_order(
        offer=context["offer"],
        proposal=proposal,
        acceptance=_acceptance(context, proposal),
    )
    document = order.to_dict()
    document["snapshot"]["proposal"]["terms"]["requested_quantity"] = "9"

    with pytest.raises(TradeOrderRejected, match="snapshot rejected"):
        TradeOrder.from_dict(document)


def test_order_rejects_signed_attempt_to_drop_required_offer_rules(tmp_path):
    context = _setup(tmp_path)
    valid_proposal = _proposal(context).to_dict()
    valid_proposal.pop("proof")
    valid_proposal["rule_bindings"] = []
    forged_proposal = _sign_proposal_body(
        context["taker"],
        valid_proposal,
    )

    valid_acceptance = _acceptance(
        context,
        _proposal(context),
    ).to_dict()
    valid_acceptance.pop("proof")
    valid_acceptance["proposal_digest"] = proposal_digest(forged_proposal)
    valid_acceptance["rule_bindings"] = []
    forged_acceptance = _sign_acceptance_body(
        context["maker"],
        valid_acceptance,
    )

    with pytest.raises(TradeOrderRejected, match="required Offer root Rule"):
        create_trade_order(
            offer=context["offer"],
            proposal=forged_proposal,
            acceptance=forged_acceptance,
        )


def test_order_rejects_acceptance_from_another_proposal(tmp_path):
    context = _setup(tmp_path)
    first = _proposal(context)
    second = create_trade_proposal(
        context["taker"],
        resolution=context["taker_resolution"],
        offer=context["offer"],
        offer_resolver=context["offer_store"],
        terms={"note": "different"},
        created_at=_CREATED,
        not_after=_EXPIRES,
        now=_AT,
    )

    with pytest.raises(TradeOrderRejected, match="proposal digest mismatch"):
        create_trade_order(
            offer=context["offer"],
            proposal=second,
            acceptance=_acceptance(context, first),
        )


def test_order_store_is_idempotent_and_detects_equivocation(tmp_path):
    context = _setup(tmp_path)
    proposal = _proposal(context)
    first_acceptance = _acceptance(context, proposal)
    first = create_trade_order(
        offer=context["offer"],
        proposal=proposal,
        acceptance=first_acceptance,
    )
    store = TradeOrderStore(tmp_path)

    assert store.put(first) == first
    assert store.put(first) == first
    assert store.get(first.order_id) == first
    assert store.list_ids() == (first.order_id,)

    second_acceptance = create_trade_acceptance(
        context["maker"],
        proposal=proposal,
        resolution=replace(
            context["maker_resolution"],
            evaluated_at="2026-08-01T02:00:00Z",
        ),
        offer=context["offer"],
        offer_resolver=context["offer_store"],
        created_at="2026-08-01T02:00:00Z",
        now=_utc("2026-08-01T02:00:00Z"),
    )
    second = create_trade_order(
        offer=context["offer"],
        proposal=proposal,
        acceptance=second_acceptance,
    )
    assert second.order_id == first.order_id
    assert second.canonical_bytes != first.canonical_bytes
    with pytest.raises(TradeOrderConflict, match="different accepted bytes"):
        store.put(second)
    with pytest.raises(TradeOrderConflict, match="multiple retained"):
        store.get(first.order_id)
    with pytest.raises(TradeOrderConflict, match="multiple retained"):
        store.put(first)
    assert store.list_conflicts(first.order_id) == (second,)
    assert store.list_ids() == (first.order_id,)


def test_order_store_rejects_orphaned_or_corrupt_conflict_records(tmp_path):
    context = _setup(tmp_path)
    proposal = _proposal(context)
    first = create_trade_order(
        offer=context["offer"],
        proposal=proposal,
        acceptance=_acceptance(context, proposal),
    )
    later_acceptance = create_trade_acceptance(
        context["maker"],
        proposal=proposal,
        resolution=replace(
            context["maker_resolution"],
            evaluated_at="2026-08-01T02:00:00Z",
        ),
        offer=context["offer"],
        offer_resolver=context["offer_store"],
        created_at="2026-08-01T02:00:00Z",
        now=_utc("2026-08-01T02:00:00Z"),
    )
    second = create_trade_order(
        offer=context["offer"],
        proposal=proposal,
        acceptance=later_acceptance,
    )
    store = TradeOrderStore(tmp_path)
    store.put(first)
    with pytest.raises(TradeOrderConflict):
        store.put(second)

    conflict_path = store._conflict_path(second)
    conflict_path.write_bytes(b"{}")
    with pytest.raises(TradeOrderRejected):
        store.get(first.order_id)

    conflict_path.write_bytes(second.canonical_bytes)
    store._path(first.order_id).unlink()
    with pytest.raises(TradeOrderConflict, match="no primary"):
        store.get(first.order_id)
    with pytest.raises(TradeOrderConflict, match="no primary"):
        store.list_ids()


def test_order_store_concurrent_put_has_one_snapshot(tmp_path):
    context = _setup(tmp_path)
    proposal = _proposal(context)
    order = create_trade_order(
        offer=context["offer"],
        proposal=proposal,
        acceptance=_acceptance(context, proposal),
    )
    store = TradeOrderStore(tmp_path)

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _index: store.put(order), range(16)))

    assert all(result == order for result in results)
    assert store.list_ids() == (order.order_id,)


def test_order_store_cross_process_put_is_idempotent(tmp_path):
    context = _setup(tmp_path)
    proposal = _proposal(context)
    order = create_trade_order(
        offer=context["offer"],
        proposal=proposal,
        acceptance=_acceptance(context, proposal),
    )
    process_root = tmp_path / "process-store"
    context_mp = multiprocessing.get_context("spawn")
    output = context_mp.Queue()
    processes = [
        context_mp.Process(
            target=_process_put_order,
            args=(process_root, order.to_dict(), output),
        )
        for _ in range(4)
    ]

    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=20)
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
            pytest.fail("cross-process Trade Order put did not terminate")
        assert process.exitcode == 0

    results = [output.get(timeout=5) for _ in processes]
    assert all(result[0] == "ok" for result in results), results
    assert len({result[1] for result in results}) == 1
    assert len({result[2] for result in results}) == 1
    assert TradeOrderStore(process_root).list_ids() == (order.order_id,)


def test_order_store_fails_closed_on_corruption_and_bad_ids(tmp_path):
    context = _setup(tmp_path)
    proposal = _proposal(context)
    order = create_trade_order(
        offer=context["offer"],
        proposal=proposal,
        acceptance=_acceptance(context, proposal),
    )
    store = TradeOrderStore(tmp_path)
    store.put(order)
    path = store._path(order.order_id)
    path.write_bytes(b"{}")

    with pytest.raises(TradeOrderRejected):
        store.get(order.order_id)
    with pytest.raises(TradeOrderRejected, match="order_id"):
        store.get("../../identity.json")


def test_order_store_scopes_conflict_reads_and_rejects_crash_residue(tmp_path):
    context = _setup(tmp_path)
    proposal = _proposal(context)
    order = create_trade_order(
        offer=context["offer"],
        proposal=proposal,
        acceptance=_acceptance(context, proposal),
    )
    store = TradeOrderStore(tmp_path)
    store.put(order)
    unrelated_prefix = "f" * 16
    assert not order.order_id.removeprefix(
        "nth-trade-order-sha256:"
    ).startswith(unrelated_prefix)
    unrelated = (
        store.root
        / f"{unrelated_prefix}.{'0' * 64}.conflict.json"
    )
    unrelated.write_bytes(b"{}")

    assert store.get(order.order_id) == order
    unrelated.unlink()
    (store.root / "interrupted-write.tmp").write_bytes(b"partial")
    with pytest.raises(TradeOrderRejected, match="crash residue"):
        store.get(order.order_id)
    report = store.reconcile()
    assert report.temporary_files == ("interrupted-write.tmp",)
    assert report.removed_temporary_files == ()
    assert (store.root / "interrupted-write.tmp").exists()

    pruned = store.reconcile(prune=True)
    assert pruned.removed_temporary_files == ("interrupted-write.tmp",)
    assert store.get(order.order_id) == order


def test_order_store_checks_link_targets_before_creating_directories(
    tmp_path,
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (workspace / "trade").symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")

    context = _setup(tmp_path / "fixtures")
    proposal = _proposal(context)
    order = create_trade_order(
        offer=context["offer"],
        proposal=proposal,
        acceptance=_acceptance(context, proposal),
    )

    with pytest.raises(TradeOrderRejected, match="symlinks or junctions"):
        TradeOrderStore(workspace).put(order)
    assert list(outside.iterdir()) == []


def test_order_store_runs_link_check_before_mkdir(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    context = _setup(tmp_path / "fixtures")
    proposal = _proposal(context)
    order = create_trade_order(
        offer=context["offer"],
        proposal=proposal,
        acceptance=_acceptance(context, proposal),
    )
    real_check = TradeOrderStore._is_linklike

    def linklike(path):
        return path == workspace / "trade" or real_check(path)

    monkeypatch.setattr(
        TradeOrderStore,
        "_is_linklike",
        staticmethod(linklike),
    )
    with pytest.raises(TradeOrderRejected, match="symlinks or junctions"):
        TradeOrderStore(workspace).put(order)
    assert not (workspace / "trade").exists()


def test_order_store_capacity_and_unknown_fields_are_bounded(tmp_path):
    context = _setup(tmp_path)
    proposal = _proposal(context)
    order = create_trade_order(
        offer=context["offer"],
        proposal=proposal,
        acceptance=_acceptance(context, proposal),
    )
    store = TradeOrderStore(tmp_path, max_orders=1)
    store.put(order)

    conflicting_acceptance = create_trade_acceptance(
        context["maker"],
        proposal=proposal,
        resolution=replace(
            context["maker_resolution"],
            evaluated_at="2026-08-01T02:00:00Z",
        ),
        offer=context["offer"],
        offer_resolver=context["offer_store"],
        created_at="2026-08-01T02:00:00Z",
        now=_utc("2026-08-01T02:00:00Z"),
    )
    conflicting_order = create_trade_order(
        offer=context["offer"],
        proposal=proposal,
        acceptance=conflicting_acceptance,
    )
    with pytest.raises(
        TradeOrderStoreCapacity,
        match="max_orders prevents conflict",
    ):
        store.put(conflicting_order)
    assert store.list_conflicts(order.order_id) == ()

    second_proposal = create_trade_proposal(
        context["taker"],
        resolution=replace(
            context["taker_resolution"],
            evaluated_at="2026-08-01T00:00:01Z",
        ),
        offer=context["offer"],
        offer_resolver=context["offer_store"],
        terms={"note": "another proposal"},
        created_at="2026-08-01T00:00:01Z",
        not_after=_EXPIRES,
        now=_utc("2026-08-01T00:00:01Z"),
    )
    second_order = create_trade_order(
        offer=context["offer"],
        proposal=second_proposal,
        acceptance=_acceptance(context, second_proposal),
    )
    with pytest.raises(TradeOrderStoreCapacity, match="max_orders"):
        store.put(second_order)

    document = order.to_dict()
    document["unexpected"] = True
    with pytest.raises(TradeOrderRejected, match="unknown fields"):
        TradeOrder.from_dict(document)


def test_agreement_conformance_vector_is_current_and_self_verifying():
    stored = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))

    assert stored == generate_vectors()
    proposal = TradeProposal.from_dict(stored["proposal"])
    acceptance = TradeAcceptance.from_dict(stored["acceptance"])
    order = TradeOrder.from_dict(stored["order"])
    assert proposal_digest(proposal) == stored["proposal_digest"]
    assert acceptance_digest(acceptance) == stored["acceptance_digest"]
    assert trade_order_digest(order) == stored["order_digest"]
    assert verify_acceptance_binding(proposal, acceptance) == (True, "ok")
    assert stored["order_audit"]["event_type"] == EVENT_TRADE_ORDER_ACCEPTED
    assert validate_order_audit_payload(
        stored["order_audit"]["payload"]
    ) == order_audit_payload(order)


def test_negative_agreement_vectors_fail_closed():
    stored = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    parsers = {
        "proposal": TradeProposal.from_dict,
        "acceptance": TradeAcceptance.from_dict,
        "order": TradeOrder.from_dict,
        "order_audit_payload": validate_order_audit_payload,
    }

    assert len(stored["negative_cases"]) >= 4
    for case in stored["negative_cases"]:
        assert case["expected_valid"] is False
        with pytest.raises(
            (
                TradeAgreementRejected,
                TradeOrderAuditError,
                TradeOrderRejected,
            )
        ):
            parsers[case["target"]](case["document"])


def test_agreement_schemas_are_packaged_and_match_wire_constants():
    proposal = json.loads(PROPOSAL_SCHEMA_PATH.read_text(encoding="utf-8"))
    acceptance = json.loads(
        ACCEPTANCE_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    order = json.loads(ORDER_SCHEMA_PATH.read_text(encoding="utf-8"))
    order_audit = json.loads(
        ORDER_AUDIT_SCHEMA_PATH.read_text(encoding="utf-8")
    )

    assert proposal["$schema"].endswith("2020-12/schema")
    assert proposal["properties"]["kind"]["const"] == (
        "nth.dao.trade.proposal"
    )
    assert proposal["properties"]["protocol_version"]["const"] == "1"
    assert "taker_policy" in proposal["required"]
    assert proposal["properties"]["taker_policy"]["$ref"].endswith("policy")
    assert proposal["properties"]["rule_bindings"]["$ref"].endswith(
        "ruleBindings"
    )
    assert acceptance["properties"]["kind"]["const"] == (
        "nth.dao.trade.acceptance"
    )
    assert "maker_policy" in acceptance["required"]
    assert acceptance["properties"]["proof"]["allOf"][1]["properties"][
        "proof_purpose"
    ]["const"] == "tradeAcceptance"
    assert order["properties"]["kind"]["const"] == "nth.dao.trade.order"
    assert order["properties"]["snapshot"]["additionalProperties"] is False
    snapshot = order["properties"]["snapshot"]["properties"]
    assert snapshot["offer"]["$ref"] == (
        "https://nthdao.org/schemas/trade-offer-v2.json"
    )
    assert snapshot["proposal"]["$ref"] == proposal["$id"]
    assert snapshot["acceptance"]["$ref"] == acceptance["$id"]
    assert order["properties"]["rule_bindings"]["$ref"].split("#", 1)[0] == (
        proposal["$id"]
    )
    assert order_audit["additionalProperties"] is False
    assert order_audit["properties"]["protocol_version"]["const"] == "1"
    assert order_audit["properties"]["order_id"]["pattern"].startswith(
        "^nth-trade-order-sha256:"
    )
    assert (
        order_audit["$id"]
        == "https://nthdao.org/schemas/trade-order-audit-payload-v1.json"
    )


def _order(context):
    proposal = _proposal(context)
    return create_trade_order(
        offer=context["offer"],
        proposal=proposal,
        acceptance=_acceptance(context, proposal),
    )


def _audit_runtime(tmp_path):
    identity = AgentIdentity.generate()
    outbox = TradeOrderAuditOutbox(tmp_path)
    order_store = TradeOrderStore(tmp_path)
    spine = SignedEventLog(tmp_path / "spine.jsonl", identity)
    coordinator = TradeOrderAuditCoordinator(outbox, order_store, spine)
    return outbox, order_store, spine, coordinator


def test_order_audit_accept_is_write_ahead_and_idempotent(tmp_path):
    order = _order(_setup(tmp_path))
    outbox, order_store, spine, coordinator = _audit_runtime(tmp_path)

    first = coordinator.accept(order, now_ms=1_800_000_000_000)
    second = coordinator.accept(order, now_ms=1_800_000_000_001)

    assert first.created is True
    assert first.cache_created is True
    assert first.anchor_created is True
    assert second.created is False
    assert second.cache_created is False
    assert second.anchor_created is False
    assert second.record.status == "anchored"
    assert order_store.get(order.order_id) == order
    assert outbox.get(trade_order_digest(order)).status == "anchored"
    events = [
        event
        for event in spine.read_all()
        if event.type == EVENT_TRADE_ORDER_ACCEPTED
    ]
    assert len(events) == 1
    assert events[0].payload == order_audit_payload(order)
    assert events[0].content_hash == second.record.event_id


@pytest.mark.parametrize("crash_point", ["prepared", "cached", "appended"])
def test_order_audit_recovers_each_cross_file_crash_window(
    tmp_path,
    crash_point,
):
    order = _order(_setup(tmp_path))
    outbox, order_store, spine, coordinator = _audit_runtime(tmp_path)
    record, created = outbox.prepare(order, now_ms=1_800_000_000_000)
    assert created is True
    if crash_point in {"cached", "appended"}:
        order_store.put(order)
        record = outbox.transition(
            record.order_digest,
            expected=frozenset({"prepared"}),
            status="cached",
            now_ms=1_800_000_000_001,
        )
    if crash_point == "appended":
        spine.append(
            EVENT_TRADE_ORDER_ACCEPTED,
            order_audit_payload(order),
            ts_ms=1_800_000_000_002,
        )

    report = coordinator.reconcile(
        limit=10,
        now_ms=1_800_000_000_003,
    )

    assert report.scanned == 1
    assert report.anchored == 1
    assert report.blocked == 0
    assert report.failed == 0
    stored = outbox.get(record.order_digest)
    assert stored.status == "anchored"
    assert order_store.get(order.order_id) == order
    assert len([
        event
        for event in spine.read_all()
        if event.type == EVENT_TRADE_ORDER_ACCEPTED
    ]) == 1


def test_order_audit_fails_closed_on_conflicting_spine_anchor(tmp_path):
    order = _order(_setup(tmp_path))
    outbox, order_store, spine, coordinator = _audit_runtime(tmp_path)
    record, _created = outbox.prepare(order, now_ms=1_800_000_000_000)
    order_store.put(order)
    outbox.transition(
        record.order_digest,
        expected=frozenset({"prepared"}),
        status="cached",
        now_ms=1_800_000_000_001,
    )
    conflicting = order_audit_payload(order)
    conflicting["acceptance_digest"] = "sha256:" + "0" * 64
    spine.append(
        EVENT_TRADE_ORDER_ACCEPTED,
        conflicting,
        ts_ms=1_800_000_000_002,
    )

    with pytest.raises(TradeOrderAuditError, match="conflicting anchor"):
        coordinator.accept(order, now_ms=1_800_000_000_003)

    retained = outbox.get(record.order_digest)
    assert retained.status == "cached"
    assert retained.last_error == ORDER_AUDIT_ERROR_SPINE
    assert retained.attempts == 1


def test_order_audit_outbox_detects_record_tampering(tmp_path):
    order = _order(_setup(tmp_path))
    outbox = TradeOrderAuditOutbox(tmp_path)
    record, _created = outbox.prepare(order, now_ms=1_800_000_000_000)
    path = outbox._path(record.order_digest)
    value = json.loads(path.read_bytes())
    value["order_digest"] = "sha256:" + "f" * 64
    path.write_bytes(canonical_json(value))

    with pytest.raises(
        TradeOrderAuditError,
        match="filename does not match|digest binding mismatch",
    ):
        outbox.get(record.order_digest)


def test_order_audit_outbox_bounds_existing_oversized_record(tmp_path):
    order = _order(_setup(tmp_path))
    outbox = TradeOrderAuditOutbox(tmp_path)
    record, _created = outbox.prepare(order, now_ms=1_800_000_000_000)
    path = outbox._path(record.order_digest)
    path.write_bytes(b"x" * (MAX_ORDER_AUDIT_RECORD_BYTES + 1))

    with pytest.raises(
        TradeOrderAuditError,
        match="record exceeds byte limit",
    ):
        outbox.get(record.order_digest)

    bounded = TradeOrderAuditOutbox(
        tmp_path,
        max_bytes=MAX_ORDER_AUDIT_RECORD_BYTES,
    )
    with pytest.raises(
        TradeOrderAuditCapacity,
        match="existing audit outbox exceeds max_bytes",
    ):
        bounded.get(record.order_digest)


def test_order_audit_concurrent_accept_appends_one_anchor(tmp_path):
    order = _order(_setup(tmp_path))
    _outbox, _order_store, spine, coordinator = _audit_runtime(tmp_path)

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(
            executor.map(
                lambda index: coordinator.accept(
                    order,
                    now_ms=1_800_000_000_000 + index,
                ),
                range(8),
            )
        )

    assert sum(result.created for result in results) == 1
    assert sum(result.cache_created for result in results) == 1
    assert sum(result.anchor_created for result in results) == 1
    assert len([
        event
        for event in spine.read_all()
        if event.type == EVENT_TRADE_ORDER_ACCEPTED
    ]) == 1


def test_order_audit_cross_process_accept_is_exactly_once(tmp_path):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    runtime_root = tmp_path / "runtime"
    identity_path = tmp_path / "node-identity.json"
    identity = AgentIdentity.generate(save_path=identity_path)
    process_context = multiprocessing.get_context("spawn")
    output = process_context.Queue()
    processes = [
        process_context.Process(
            target=_process_accept_audited_order,
            args=(
                str(runtime_root),
                str(identity_path),
                order.to_dict(),
                1_800_000_000_000 + index,
                output,
            ),
        )
        for index in range(5)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=45)
        assert process.exitcode == 0
    results = [output.get(timeout=5) for _ in processes]
    assert all(result[0] == "ok" for result in results), results
    assert sum(result[1] for result in results) == 1
    assert sum(result[2] for result in results) == 1
    assert sum(result[3] for result in results) == 1
    assert len({result[4] for result in results}) == 1

    outbox = TradeOrderAuditOutbox(runtime_root)
    stored = outbox.get(trade_order_digest(order))
    assert stored.status == "anchored"
    assert TradeOrderStore(runtime_root).get(order.order_id) == order
    spine = SignedEventLog(runtime_root / "spine.jsonl", identity)
    events = [
        event
        for event in spine.read_all()
        if event.type == EVENT_TRADE_ORDER_ACCEPTED
    ]
    assert len(events) == 1
    assert spine.verify_chain() == (True, "ok")


def test_order_audit_revalidates_anchored_status_against_spine(tmp_path):
    order = _order(_setup(tmp_path))
    outbox, _order_store, _spine, coordinator = _audit_runtime(tmp_path)
    accepted = coordinator.accept(order, now_ms=1_800_000_000_000)
    path = outbox._path(accepted.record.order_digest)
    value = json.loads(path.read_bytes())
    value["event_id"] = "f" * 64
    path.write_bytes(canonical_json(value))

    with pytest.raises(
        TradeOrderAuditError,
        match="does not match the Spine event",
    ):
        coordinator.accept(order, now_ms=1_800_000_000_001)

    report = coordinator.reconcile(now_ms=1_800_000_000_002)
    assert report.scanned == 1
    assert report.verified_anchored == 0
    assert report.failed == 1


def test_order_audit_state_machine_cannot_regress_anchored_record(tmp_path):
    order = _order(_setup(tmp_path))
    outbox, _store, _spine, coordinator = _audit_runtime(tmp_path)
    accepted = coordinator.accept(order, now_ms=1_800_000_000_000)

    with pytest.raises(TradeOrderAuditError, match="invalid audit transition"):
        outbox.transition(
            accepted.record.order_digest,
            expected=frozenset({"anchored"}),
            status="prepared",
            now_ms=1_800_000_000_001,
        )
    assert outbox.get(accepted.record.order_digest).status == "anchored"


def test_order_audit_rejects_anchor_time_before_signed_acceptance(tmp_path):
    order = _order(_setup(tmp_path))
    outbox, order_store, spine, coordinator = _audit_runtime(tmp_path)

    with pytest.raises(
        TradeOrderAuditError,
        match="precedes the signed Acceptance",
    ):
        coordinator.accept(order, now_ms=1)
    assert outbox.get(trade_order_digest(order)) is None
    assert order_store.get(order.order_id) is None
    assert list(spine.read_all()) == []


def test_order_audit_restores_rolled_back_cache_before_trusting_anchor(
    tmp_path,
):
    order = _order(_setup(tmp_path))
    _outbox, order_store, spine, coordinator = _audit_runtime(tmp_path)
    coordinator.accept(order, now_ms=1_800_000_000_000)
    order_store._path(order.order_id).unlink()
    assert order_store.get(order.order_id) is None

    recovered = coordinator.accept(order, now_ms=1_800_000_000_001)

    assert recovered.cache_created is True
    assert recovered.anchor_created is False
    assert order_store.get(order.order_id) == order
    assert len([
        event
        for event in spine.read_all()
        if event.type == EVENT_TRADE_ORDER_ACCEPTED
    ]) == 1


def test_order_audit_rejects_any_malformed_order_anchor(tmp_path):
    order = _order(_setup(tmp_path))
    _outbox, _store, spine, coordinator = _audit_runtime(tmp_path)
    spine.append(
        EVENT_TRADE_ORDER_ACCEPTED,
        {"order_id": "not-a-complete-anchor"},
        ts_ms=1_800_000_000_000,
    )

    with pytest.raises(
        TradeOrderAuditError,
        match="missing or unknown fields",
    ):
        coordinator.accept(order, now_ms=1_800_000_000_001)


def test_order_audit_rejects_anchor_with_invalid_agreement_timestamp(
    tmp_path,
):
    order = _order(_setup(tmp_path))
    _outbox, _store, spine, coordinator = _audit_runtime(tmp_path)
    malformed = order_audit_payload(order)
    malformed["created_at"] = "not-rfc3339"
    spine.append(
        EVENT_TRADE_ORDER_ACCEPTED,
        malformed,
        ts_ms=1_800_000_000_000,
    )

    with pytest.raises(
        TradeOrderAuditError,
        match="UTC RFC3339",
    ):
        coordinator.accept(order, now_ms=1_800_000_000_001)


def test_order_execution_gate_replays_all_transitive_dependencies(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)

    readiness = verify_trade_order_execution(
        order,
        context["package_store"],
        context["taker_policy"],
        at=datetime(2026, 9, 1, tzinfo=timezone.utc),
    )

    assert readiness.order_digest == trade_order_digest(order)
    assert readiness.executor_policy_digest == context["taker_policy"].digest
    assert context["dependency_digest"] in readiness.ordered_package_digests
    assert len(readiness.ordered_package_digests) == 2
    assert readiness.evaluated_at == "2026-09-01T00:00:00Z"


def test_order_execution_gate_rejects_missing_transitive_dependency(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)

    class MissingDependencyResolver:
        def load(self, digest):
            if digest == context["dependency_digest"]:
                return None
            return context["package_store"].load(digest)

    with pytest.raises(
        TradeOrderExecutionRejected,
        match="required rule package is unavailable",
    ):
        verify_trade_order_execution(
            order,
            MissingDependencyResolver(),
            context["taker_policy"],
            at=datetime(2026, 9, 1, tzinfo=timezone.utc),
        )


def test_order_execution_gate_honors_current_executor_revocation(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    revoked_policy = RuleResolutionPolicy()

    with pytest.raises(
        TradeOrderExecutionRejected,
        match="current executor policy.*not accepted",
    ):
        verify_trade_order_execution(
            order,
            context["package_store"],
            revoked_policy,
            at=datetime(2026, 9, 1, tzinfo=timezone.utc),
        )


def test_order_execution_gate_rejects_package_expired_after_agreement(
    tmp_path,
):
    context = _setup(tmp_path)
    order = _order(context)

    with pytest.raises(
        TradeOrderExecutionRejected,
        match="not execution-current",
    ):
        verify_trade_order_execution(
            order,
            context["package_store"],
            context["taker_policy"],
            at=datetime(2027, 2, 1, tzinfo=timezone.utc),
        )


def test_order_execution_gate_rejects_backdated_execution_time(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)

    with pytest.raises(
        TradeOrderExecutionRejected,
        match="precedes the signed Acceptance",
    ):
        verify_trade_order_execution(
            order,
            context["package_store"],
            context["taker_policy"],
            at=datetime(2026, 7, 31, tzinfo=timezone.utc),
        )


def test_rule_resolution_policy_snapshot_parser_is_exact_and_canonical():
    policy = RuleResolutionPolicy(
        allowed_permissions={"network.read"},
        available_capabilities={"http"},
    )
    document = json.loads(policy.canonical_bytes)
    assert RuleResolutionPolicy.from_dict(document) == policy

    document["unknown"] = True
    with pytest.raises(ValueError, match="missing or unknown"):
        RuleResolutionPolicy.from_dict(document)


def test_order_audit_and_execution_gate_are_public_trade_rule_apis():
    assert trade_rules_api.TradeOrderAuditCoordinator is (
        TradeOrderAuditCoordinator
    )
    assert trade_rules_api.verify_trade_order_execution is (
        verify_trade_order_execution
    )
    assert (
        trade_rules_api.EVENT_TRADE_ORDER_ACCEPTED
        == EVENT_TRADE_ORDER_ACCEPTED
    )
