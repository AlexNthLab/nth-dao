import copy
import hashlib
import json
import multiprocessing
import tempfile
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
    TradeExecutionAdapterPolicy,
    TradeExecutionAdapter,
    TradeExecutionAdapterRejected,
    TradeExecutionAuditError,
    TradeExecutionAuditCapacity,
    TradeExecutionReceiptConflict,
    TradeExecutionAuditOutbox,
    TradeExecutionCoordinator,
    TradeExecutionReceiptStore,
    TradeExecutionReceiptStoreError,
    TradeOrder,
    TradeOrderConflict,
    TradeOrderRejected,
    TradeOrderStore,
    TradeOrderStoreCapacity,
    TradeProposal,
    TradeExecutionReceipt,
    TradeExecutionReceiptRejected,
    JsonSchema202012Validator,
    EXECUTION_TERMS_KEY,
    acceptance_digest,
    build_execution_adapter,
    create_trade_order,
    create_trade_acceptance,
    create_trade_proposal,
    execution_receipt_digest,
    execution_audit_payload,
    manifest_body,
    offer_body,
    offer_digest,
    proposal_digest,
    resolve_canonical_offer_rules,
    sign_manifest,
    sign_offer,
    trade_order_digest,
    validate_execution_audit_binding,
    validate_execution_audit_payload,
    verify_acceptance_binding,
    verify_execution_receipt_order_binding,
    verify_execution_receipt_under_policy,
)
from nth_dao.trade_rules.execution_receipt import (
    _create_trade_execution_receipt,
)
from nth_dao.trade_rules.receipt_review import (
    RECEIPT_REVIEW_SIGNING_DOMAIN,
    TradeReceiptReview,
    TradeReceiptReviewRejected,
    create_trade_receipt_review,
    receipt_review_digest,
    verify_trade_receipt_review_under_policy,
)
from nth_dao.trade_rules.receipt_review_store import (
    TradeReceiptReviewConflict,
    TradeReceiptReviewStore,
)
from nth_dao.trade_rules.receipt_review_audit import (
    EVENT_TRADE_RECEIPT_REVIEW_CONFLICTED,
    EVENT_TRADE_RECEIPT_REVIEWED,
    TradeReceiptReviewAuditError,
    TradeReceiptReviewCoordinator,
    receipt_review_audit_payload,
    validate_receipt_review_audit_binding,
    validate_receipt_review_conflict_audit_payload,
)
from nth_dao.trade_rules.store import OfferStore
from nth_dao.trade_rules.agreement_conformance import (
    ACCEPTANCE_SCHEMA_PATH,
    EXECUTION_AUDIT_SCHEMA_PATH,
    EXECUTION_ADAPTER_SCHEMA_PATH,
    EXECUTION_ADAPTER_POLICY_SCHEMA_PATH,
    EXECUTION_RECEIPT_SCHEMA_PATH,
    RECEIPT_REVIEW_AUDIT_SCHEMA_PATH,
    RECEIPT_REVIEW_CONFLICT_AUDIT_SCHEMA_PATH,
    RECEIPT_REVIEW_SCHEMA_PATH,
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
from nth_dao.trade_rules.signing import (
    encode_ed25519_signature,
    signed_document_input,
)

pytestmark = pytest.mark.skipif(
    not crypto_available(), reason="Trade Rule signatures require PyNaCl"
)

_AT = datetime(2026, 8, 1, tzinfo=timezone.utc)
_ACCEPTED_AT = datetime(2026, 8, 1, 1, tzinfo=timezone.utc)
_CREATED = "2026-08-01T00:00:00Z"
_EXPIRES = "2026-08-02T00:00:00Z"


class _AdapterResolver:
    def __init__(self, *adapters, artifacts=None):
        self.adapters = {adapter.digest: adapter for adapter in adapters}
        self.artifacts = dict(artifacts or {})

    def load(self, digest):
        return self.adapters.get(digest)

    def load_artifact(self, digest):
        return self.artifacts.get(digest)


class _ContentResolver:
    def __init__(self, *payloads):
        self.content = {_digest(payload): payload for payload in payloads}

    def add(self, payload):
        self.content[_digest(payload)] = payload

    def load(self, digest, *, max_bytes):
        payload = self.content.get(digest)
        if payload is not None and len(payload) > max_bytes:
            raise ValueError("content exceeds max_bytes")
        return payload


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


def _process_put_execution_receipt(root, receipt, order, output):
    try:
        stored = TradeExecutionReceiptStore(root, lock_timeout=20).put(
            receipt,
            order=order,
        )
        output.put(("ok", stored.execution_id))
    except Exception as exc:
        output.put(("error", type(exc).__name__, str(exc)))


def _process_put_receipt_review(root, review, receipt, order, output):
    try:
        stored, created = TradeReceiptReviewStore(
            root,
            lock_timeout=20,
        ).put_with_status(
            review,
            receipt=receipt,
            order=order,
        )
        output.put(("ok", stored.review_id, created))
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


def _setup(
    tmp_path,
    *,
    dependency_permissions=(),
    hook_permissions=(),
):
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
            execution_mode=(
                "adapter" if dependency_permissions else "declarative"
            ),
            permissions=dependency_permissions,
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
    input_schema = trade_rules_api.trade_canonical_json({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "required": ["order"],
        "properties": {
            "order": {"const": "deliver"},
        },
    })
    output_schema = trade_rules_api.trade_canonical_json({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "required": ["status"],
        "properties": {
            "status": {"const": "ok"},
        },
    })
    input_schema_digest = _digest(input_schema)
    output_schema_digest = _digest(output_schema)
    manifest = sign_manifest(
        rule_publisher,
        manifest_body(
            rule_id="org.nthdao.test.delivery",
            version="1.0.0",
            publisher_did=rule_publisher.as_did(),
            summary="Delivery agreement test rule",
            applies_to=["service"],
            families=["fulfillment"],
            hook_contracts=[{
                "name": "fulfillment.deliver",
                "version": "1",
                "input_schema_digest": input_schema_digest,
                "output_schema_digest": output_schema_digest,
                "side_effect": "none",
                "permissions": list(hook_permissions),
            }],
            dependencies=[{
                "rule_id": dependency_manifest.rule_id,
                "digest": dependency_digest,
            }],
            resources=[
                {
                    "purpose": "execution-input-schema",
                    "media_type": "application/schema+json",
                    "digest": input_schema_digest,
                    "size": len(input_schema),
                },
                {
                    "purpose": "execution-output-schema",
                    "media_type": "application/schema+json",
                    "digest": output_schema_digest,
                    "size": len(output_schema),
                },
                {
                    "purpose": "terms",
                    "media_type": "application/json",
                    "digest": resource_digest,
                    "size": len(resource),
                },
            ],
            published_at="2026-07-01T00:00:00Z",
            not_after="2027-01-01T00:00:00Z",
            execution_mode=("adapter" if hook_permissions else "declarative"),
            permissions=hook_permissions,
        ),
        created="2026-07-01T00:00:00Z",
    )
    package_digest = package_store.install(
        manifest,
        {
            resource_digest: resource,
            input_schema_digest: input_schema,
            output_schema_digest: output_schema,
        },
    ).digest
    adapter_artifact = b"test adapter artifact v1"
    adapter = build_execution_adapter(
        adapter_id="org.nthdao.test/declarative",
        adapter_version="1.0.0",
        artifact_digest=_digest(adapter_artifact),
        execution_modes=[
            "adapter" if hook_permissions else "declarative"
        ],
        hooks=[{
            "rule_id": manifest.rule_id,
            "hook_name": "fulfillment.deliver",
            "hook_version": "1",
        }],
        permissions=list(hook_permissions),
    )
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
    execution_modes = (
        {"declarative", "adapter"}
        if dependency_permissions or hook_permissions
        else {"declarative"}
    )
    approved_executable_digests = set()
    if dependency_permissions:
        approved_executable_digests.add(dependency_digest)
    if hook_permissions:
        approved_executable_digests.add(package_digest)
    taker_policy = RuleResolutionPolicy(
        accepted_publishers={rule_publisher.as_did()},
        allowed_permissions=set(dependency_permissions) | set(hook_permissions),
        allowed_execution_modes=execution_modes,
        approved_executable_digests=approved_executable_digests,
    )
    maker_policy = RuleResolutionPolicy(
        accepted_package_digests={package_digest, dependency_digest},
        allowed_permissions=set(dependency_permissions) | set(hook_permissions),
        allowed_execution_modes=execution_modes,
        approved_executable_digests=approved_executable_digests,
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
        "package_digest": package_digest,
        "adapter": adapter,
        "adapter_resolver": _AdapterResolver(
            adapter,
            artifacts={_digest(adapter_artifact): adapter_artifact},
        ),
        "adapter_policy": TradeExecutionAdapterPolicy(
            accepted_adapter_digests={adapter.digest},
            allowed_execution_modes=execution_modes,
            allowed_permissions=(
                set(dependency_permissions) | set(hook_permissions)
            ),
        ),
        "content_resolver": _ContentResolver(
            b'{"order":"deliver"}',
            b'{"status":"ok"}',
        ),
        "schema_validator": JsonSchema202012Validator(),
        "input_schema_digest": input_schema_digest,
        "output_schema_digest": output_schema_digest,
        "taker_policy": taker_policy,
        "maker_policy": maker_policy,
        "taker_resolution": taker_resolution,
        "maker_resolution": maker_resolution,
    }


def _proposal(context, *, grants=None):
    execution_grants = grants or [{
        "operation_id": "deliver-service",
        "rule_id": "org.nthdao.test.delivery",
        "package_digest": context["package_digest"],
        "hook_name": "fulfillment.deliver",
        "hook_version": "1",
        "executor_role": "maker",
    }]
    return create_trade_proposal(
        context["taker"],
        resolution=context["taker_resolution"],
        offer=context["offer"],
        offer_resolver=context["offer_store"],
        terms={
            "requested_quantity": "1",
            EXECUTION_TERMS_KEY: {
                "grants": sorted(
                    execution_grants,
                    key=lambda item: item["operation_id"],
                )
            },
        },
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
    adapter = TradeExecutionAdapter.from_dict(stored["execution_adapter"])
    assert adapter.digest == stored["execution_adapter_digest"]
    adapter_artifact = bytes.fromhex(
        stored["execution_adapter_artifact_hex"]
    )
    assert _digest(adapter_artifact) == (
        adapter.to_dict()["artifact_digest"]
    )
    assert verify_acceptance_binding(proposal, acceptance) == (True, "ok")
    assert stored["order_audit"]["event_type"] == EVENT_TRADE_ORDER_ACCEPTED
    assert validate_order_audit_payload(
        stored["order_audit"]["payload"]
    ) == order_audit_payload(order)
    execution_receipt = TradeExecutionReceipt.from_dict(
        stored["execution_receipt"],
        order=order,
    )
    assert execution_receipt_digest(execution_receipt) == (
        stored["execution_receipt_digest"]
    )
    assert execution_receipt.to_dict()["adapter"]["adapter_digest"] == (
        adapter.digest
    )
    assert validate_execution_audit_binding(
        stored["execution_audit"]["payload"],
        receipt=execution_receipt,
        order=order,
    ) == execution_audit_payload(execution_receipt, order=order)
    receipt_review = TradeReceiptReview.from_dict(
        stored["receipt_review"],
        receipt=execution_receipt,
        order=order,
    )
    assert receipt_review_digest(receipt_review) == (
        stored["receipt_review_digest"]
    )
    assert stored["receipt_review_audit"]["event_type"] == (
        EVENT_TRADE_RECEIPT_REVIEWED
    )
    assert validate_receipt_review_audit_binding(
        stored["receipt_review_audit"]["payload"],
        review=receipt_review,
        receipt=execution_receipt,
        order=order,
    ) == receipt_review_audit_payload(
        receipt_review,
        receipt=execution_receipt,
        order=order,
    )
    package_vector = stored["rule_package"]
    with tempfile.TemporaryDirectory() as directory:
        package_store = RulePackageStore(directory)
        installed = package_store.install(
            trade_rules_api.TradeRuleManifest.from_dict(
                package_vector["manifest"]
            ),
            {
                item["digest"]: bytes.fromhex(item["bytes_hex"])
                for item in package_vector["resources"]
            },
        )
        assert installed.digest == package_vector["digest"]
        adapter_policy = TradeExecutionAdapterPolicy(
            accepted_adapter_digests=stored["adapter_policy"][
                "accepted_adapter_digests"
            ],
            allowed_execution_modes=stored["adapter_policy"][
                "allowed_execution_modes"
            ],
            allowed_permissions=stored["adapter_policy"][
                "allowed_permissions"
            ],
        )
        content_resolver = trade_rules_api.MappingTradeExecutionContentResolver({
            item["digest"]: bytes.fromhex(item["bytes_hex"])
            for item in stored["execution_content"]
        })
        replayed = verify_execution_receipt_under_policy(
            execution_receipt,
            order,
            package_store,
            RuleResolutionPolicy.from_dict(stored["verifier_policy"]),
            _AdapterResolver(
                adapter,
                artifacts={
                    adapter.to_dict()["artifact_digest"]: adapter_artifact
                },
            ),
            adapter_policy,
            content_resolver,
            JsonSchema202012Validator(),
        )
    assert replayed.to_dict() == stored["expected_execution_readiness"]


def test_negative_agreement_vectors_fail_closed():
    stored = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    parsers = {
        "proposal": TradeProposal.from_dict,
        "acceptance": TradeAcceptance.from_dict,
        "order": TradeOrder.from_dict,
        "order_audit_payload": validate_order_audit_payload,
        "execution_receipt": lambda document: (
            TradeExecutionReceipt.from_dict(
                document,
                order=stored["order"],
            )
        ),
        "execution_audit_payload": validate_execution_audit_payload,
        "execution_audit_binding": lambda document: (
            validate_execution_audit_binding(
                document,
                receipt=stored["execution_receipt"],
                order=stored["order"],
            )
        ),
        "execution_adapter": TradeExecutionAdapter.from_dict,
        "receipt_review": lambda document: TradeReceiptReview.from_dict(
            document,
            receipt=stored["execution_receipt"],
            order=stored["order"],
        ),
        "receipt_review_audit_binding": lambda document: (
            validate_receipt_review_audit_binding(
                document,
                review=stored["receipt_review"],
                receipt=stored["execution_receipt"],
                order=stored["order"],
            )
        ),
    }

    assert len(stored["negative_cases"]) >= 4
    for case in stored["negative_cases"]:
        assert case["expected_valid"] is False
        with pytest.raises(
            (
                TradeAgreementRejected,
                TradeOrderAuditError,
                TradeOrderRejected,
                TradeExecutionReceiptRejected,
                TradeExecutionAdapterRejected,
                TradeExecutionAuditError,
                TradeReceiptReviewRejected,
                TradeReceiptReviewAuditError,
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
    execution_receipt = json.loads(
        EXECUTION_RECEIPT_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    execution_audit = json.loads(
        EXECUTION_AUDIT_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    execution_adapter = json.loads(
        EXECUTION_ADAPTER_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    execution_adapter_policy = json.loads(
        EXECUTION_ADAPTER_POLICY_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    receipt_review = json.loads(
        RECEIPT_REVIEW_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    receipt_review_audit = json.loads(
        RECEIPT_REVIEW_AUDIT_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    receipt_review_conflict_audit = json.loads(
        RECEIPT_REVIEW_CONFLICT_AUDIT_SCHEMA_PATH.read_text(
            encoding="utf-8"
        )
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
    assert execution_receipt["additionalProperties"] is False
    assert execution_receipt["properties"]["kind"]["const"] == (
        "nth.dao.trade.execution-receipt"
    )
    assert execution_receipt["properties"]["proof"]["$ref"].endswith(
        "/proof"
    )
    assert execution_receipt["$defs"]["proof"]["properties"][
        "proof_purpose"
    ]["const"] == "tradeExecution"
    assert execution_audit["additionalProperties"] is False
    assert execution_audit["properties"]["protocol_version"]["const"] == "1"
    assert execution_audit["properties"]["execution_id"][
        "pattern"
    ].startswith("^nth-trade-execution-sha256:")
    assert execution_audit["$id"] == (
        "https://nthdao.org/schemas/"
        "trade-execution-audit-payload-v1.json"
    )
    assert execution_adapter["additionalProperties"] is False
    assert execution_adapter["properties"]["kind"]["const"] == (
        "nth.dao.trade.execution-adapter"
    )
    assert execution_adapter["properties"]["artifact_digest"]["$ref"].endswith(
        "/digest"
    )
    assert execution_adapter_policy["additionalProperties"] is False
    assert execution_adapter_policy["properties"]["kind"]["const"] == (
        "nth.dao.trade.execution-adapter-policy"
    )
    assert receipt_review["additionalProperties"] is False
    assert receipt_review["properties"]["kind"]["const"] == (
        "nth.dao.trade.receipt-review"
    )
    assert receipt_review["$defs"]["proof"]["properties"][
        "proof_purpose"
    ]["const"] == "tradeReceiptReview"
    assert receipt_review_audit["additionalProperties"] is False
    assert receipt_review_audit["properties"]["review_id"][
        "pattern"
    ].startswith("^nth-trade-review-sha256:")
    assert receipt_review_conflict_audit["additionalProperties"] is False
    assert receipt_review_conflict_audit["properties"][
        "candidate_review_digest"
    ]["$ref"].endswith("/digest")


def test_execution_schemas_validate_public_vectors_and_reject_shape_drift():
    jsonschema = pytest.importorskip("jsonschema")
    stored = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    receipt_schema = json.loads(
        EXECUTION_RECEIPT_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    adapter_schema = json.loads(
        EXECUTION_ADAPTER_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    adapter_policy_schema = json.loads(
        EXECUTION_ADAPTER_POLICY_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    audit_schema = json.loads(
        EXECUTION_AUDIT_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    review_schema = json.loads(
        RECEIPT_REVIEW_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    review_audit_schema = json.loads(
        RECEIPT_REVIEW_AUDIT_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    review_conflict_audit_schema = json.loads(
        RECEIPT_REVIEW_CONFLICT_AUDIT_SCHEMA_PATH.read_text(
            encoding="utf-8"
        )
    )
    receipt_validator = jsonschema.validators.validator_for(receipt_schema)
    adapter_validator = jsonschema.validators.validator_for(adapter_schema)
    adapter_policy_validator = jsonschema.validators.validator_for(
        adapter_policy_schema
    )
    audit_validator = jsonschema.validators.validator_for(audit_schema)
    review_validator = jsonschema.validators.validator_for(review_schema)
    review_audit_validator = jsonschema.validators.validator_for(
        review_audit_schema
    )
    review_conflict_audit_validator = jsonschema.validators.validator_for(
        review_conflict_audit_schema
    )
    receipt_validator.check_schema(receipt_schema)
    adapter_validator.check_schema(adapter_schema)
    adapter_policy_validator.check_schema(adapter_policy_schema)
    audit_validator.check_schema(audit_schema)
    review_validator.check_schema(review_schema)
    review_audit_validator.check_schema(review_audit_schema)
    review_conflict_audit_validator.check_schema(
        review_conflict_audit_schema
    )

    receipt_validator(receipt_schema).validate(
        stored["execution_receipt"]
    )
    adapter_validator(adapter_schema).validate(
        stored["execution_adapter"]
    )
    adapter_policy_validator(adapter_policy_schema).validate(
        stored["adapter_policy"]
    )
    audit_validator(audit_schema).validate(
        stored["execution_audit"]["payload"]
    )
    review_validator(review_schema).validate(stored["receipt_review"])
    review_audit_validator(review_audit_schema).validate(
        stored["receipt_review_audit"]["payload"]
    )
    review_conflict_audit_validator(
        review_conflict_audit_schema
    ).validate(stored["receipt_review_conflict_audit"]["payload"])

    bad_time = copy.deepcopy(stored["execution_receipt"])
    bad_time["started_at"] = "2026-08-01T02:00:00.000000001Z"
    with pytest.raises(jsonschema.ValidationError):
        receipt_validator(receipt_schema).validate(bad_time)
    bad_adapter = copy.deepcopy(stored["execution_adapter"])
    bad_adapter["execution_modes"].append("declarative")
    with pytest.raises(jsonschema.ValidationError):
        adapter_validator(adapter_schema).validate(bad_adapter)
    bad_audit = copy.deepcopy(stored["execution_audit"]["payload"])
    bad_audit["unexpected"] = True
    with pytest.raises(jsonschema.ValidationError):
        audit_validator(audit_schema).validate(bad_audit)
    bad_review = copy.deepcopy(stored["receipt_review"])
    bad_review["decision"] = "unknown"
    with pytest.raises(jsonschema.ValidationError):
        review_validator(review_schema).validate(bad_review)


def _order(context):
    proposal = _proposal(context)
    return create_trade_order(
        offer=context["offer"],
        proposal=proposal,
        acceptance=_acceptance(context, proposal),
    )


def _order_for_operation(context, operation_id):
    proposal = _proposal(
        context,
        grants=[{
            "operation_id": operation_id,
            "rule_id": "org.nthdao.test.delivery",
            "package_digest": context["package_digest"],
            "hook_name": "fulfillment.deliver",
            "hook_version": "1",
            "executor_role": "maker",
        }],
    )
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


def _execution_receipt(
    context,
    order,
    *,
    identity=None,
    role="maker",
    coordinator=None,
    execution_mode="declarative",
    operation_id="deliver-service",
    outcome="succeeded",
    operation_input_payload=None,
    result=None,
    result_payload=None,
    evidence=None,
    started_at="2026-09-01T00:00:00Z",
    completed_at="2026-09-01T00:01:00Z",
    now=None,
):
    if operation_input_payload is None:
        operation_input_payload = b'{"order":"deliver"}'
    if result_payload is None:
        result_payload = b'{"status":"ok"}'
    add_content = getattr(context["content_resolver"], "add", None)
    if callable(add_content):
        add_content(operation_input_payload)
        add_content(result_payload)
    issue = (
        coordinator.issue
        if coordinator is not None
        else _create_trade_execution_receipt
    )
    return issue(
        identity or context[role],
        order=order,
        package_resolver=context["package_store"],
        executor_policy=context[f"{role}_policy"],
        adapter_resolver=context["adapter_resolver"],
        adapter_policy=context["adapter_policy"],
        content_resolver=context["content_resolver"],
        schema_validator=context["schema_validator"],
        executor_role=role,
        adapter_id=context["adapter"].to_dict()["adapter_id"],
        adapter_version=context["adapter"].to_dict()["adapter_version"],
        adapter_digest=context["adapter"].digest,
        execution_mode=execution_mode,
        operation_id=operation_id,
        operation_input={
            "media_type": "application/json",
            "digest": _digest(operation_input_payload),
            "size_bytes": len(operation_input_payload),
        },
        outcome=outcome,
        result=result or {
            "media_type": "application/json",
            "digest": _digest(result_payload),
            "size_bytes": len(result_payload),
        },
        evidence=evidence or [],
        started_at=started_at,
        completed_at=completed_at,
        now=now or _utc(completed_at),
    )


def _resign_execution_receipt(identity, document):
    document["proof"]["proof_value"] = encode_ed25519_signature(
        identity.sign(
            signed_document_input(
                trade_rules_api.EXECUTION_RECEIPT_SIGNING_DOMAIN,
                document,
            )
        )
    )
    return document


def test_execution_receipt_round_trip_binds_order_and_readiness(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)

    receipt = _execution_receipt(context, order)
    document = receipt.to_dict()

    assert TradeExecutionReceipt.from_json(
        receipt.canonical_bytes,
        order=order,
    ) == receipt
    assert document["order_digest"] == trade_order_digest(order)
    assert document["executor_did"] == context["maker"].as_did()
    assert document["executor_role"] == "maker"
    assert document["operation"]["operation_id"] == "deliver-service"
    assert document["operation"]["hook_name"] == "fulfillment.deliver"
    assert document["operation"]["input_schema_digest"] == (
        context["input_schema_digest"]
    )
    assert document["operation"]["output_schema_digest"] == (
        context["output_schema_digest"]
    )
    assert document["readiness"]["order_digest"] == trade_order_digest(order)
    assert document["readiness_digest"].startswith("sha256:")
    assert execution_receipt_digest(receipt).startswith("sha256:")
    verify_execution_receipt_order_binding(receipt, order)


def test_execution_receipt_rejects_unavailable_operation_content(tmp_path):
    context = _setup(tmp_path)
    context["content_resolver"].content.clear()

    with pytest.raises(
        trade_rules_api.TradeExecutionContentRejected,
        match="operation.input content is unavailable",
    ):
        _create_trade_execution_receipt(
            context["maker"],
            order=_order(context),
            package_resolver=context["package_store"],
            executor_policy=context["maker_policy"],
            adapter_resolver=context["adapter_resolver"],
            adapter_policy=context["adapter_policy"],
            content_resolver=context["content_resolver"],
            schema_validator=context["schema_validator"],
            executor_role="maker",
            adapter_id=context["adapter"].to_dict()["adapter_id"],
            adapter_version=context["adapter"].to_dict()["adapter_version"],
            adapter_digest=context["adapter"].digest,
            execution_mode="declarative",
            operation_id="deliver-service",
            operation_input={
                "media_type": "application/json",
                "digest": _digest(b'{"order":"deliver"}'),
                "size_bytes": len(b'{"order":"deliver"}'),
            },
            outcome="succeeded",
            result={
                "media_type": "application/json",
                "digest": _digest(b'{"status":"ok"}'),
                "size_bytes": len(b'{"status":"ok"}'),
            },
            started_at="2026-09-01T00:00:00Z",
            completed_at="2026-09-01T00:01:00Z",
            now=_utc("2026-09-01T00:01:00Z"),
        )


def test_execution_receipt_rejects_content_resolver_substitution(tmp_path):
    context = _setup(tmp_path)

    class SubstitutingContentResolver:
        def load(self, _digest_value, *, max_bytes):
            assert max_bytes > 0
            return b'{"order":"substituted"}'

    context["content_resolver"] = SubstitutingContentResolver()
    with pytest.raises(
        trade_rules_api.TradeExecutionContentRejected,
        match="operation.input size mismatch|operation.input digest mismatch",
    ):
        _execution_receipt(context, _order(context))


def test_execution_receipt_rejects_input_that_violates_hook_schema(tmp_path):
    context = _setup(tmp_path)

    with pytest.raises(
        trade_rules_api.TradeExecutionContentRejected,
        match="violates Hook schema",
    ):
        _execution_receipt(
            context,
            _order(context),
            operation_input_payload=b'{"order":"pickup"}',
        )


def test_execution_receipt_rejects_success_result_that_violates_schema(
    tmp_path,
):
    context = _setup(tmp_path)

    with pytest.raises(
        trade_rules_api.TradeExecutionContentRejected,
        match="violates Hook schema",
    ):
        _execution_receipt(
            context,
            _order(context),
            result_payload=b'{"status":"pending"}',
        )


def test_execution_schema_validator_rejects_external_reference():
    with pytest.raises(
        trade_rules_api.TradeExecutionContentRejected,
        match="must not use external references",
    ):
        JsonSchema202012Validator().validate(
            {},
            {"$ref": "https://example.invalid/schema.json"},
        )


def test_execution_receipt_receiver_revalidates_content(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)

    class SubstitutingContentResolver:
        def load(self, _digest_value, *, max_bytes):
            assert max_bytes > 0
            return b"{}"

    with pytest.raises(
        trade_rules_api.TradeExecutionContentRejected,
        match="operation.input size mismatch|operation.input digest mismatch",
    ):
        verify_execution_receipt_under_policy(
            receipt,
            order,
            context["package_store"],
            context["taker_policy"],
            context["adapter_resolver"],
            context["adapter_policy"],
            SubstitutingContentResolver(),
            context["schema_validator"],
        )


def test_execution_receipt_id_is_idempotent_and_scope_bound(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)

    first = _execution_receipt(context, order)
    retry = _execution_receipt(context, order)
    assert first.execution_id == retry.execution_id
    assert "idempotency_key_digest" not in first.to_dict()


def test_execution_receipt_id_scopes_same_key_by_operation(tmp_path):
    context = _setup(tmp_path)
    grants = [
        {
            "operation_id": operation_id,
            "rule_id": "org.nthdao.test.delivery",
            "package_digest": context["package_digest"],
            "hook_name": "fulfillment.deliver",
            "hook_version": "1",
            "executor_role": "maker",
        }
        for operation_id in ("deliver-primary", "deliver-secondary")
    ]
    proposal = _proposal(context, grants=grants)
    order = create_trade_order(
        offer=context["offer"],
        proposal=proposal,
        acceptance=_acceptance(context, proposal),
    )

    primary = _execution_receipt(
        context,
        order,
        operation_id="deliver-primary",
    )
    secondary = _execution_receipt(
        context,
        order,
        operation_id="deliver-secondary",
    )

    assert primary.execution_id != secondary.execution_id


def test_execution_receipt_store_is_idempotent_and_retains_conflict(
    tmp_path,
):
    context = _setup(tmp_path)
    order = _order(context)
    succeeded = _execution_receipt(context, order)
    failed = _execution_receipt(
        context,
        order,
        outcome="failed",
        result_payload=b'{"error":"delivery failed"}',
        result={
            "media_type": "application/problem+json",
            "digest": _digest(b'{"error":"delivery failed"}'),
            "size_bytes": len(b'{"error":"delivery failed"}'),
        },
    )
    assert succeeded.execution_id == failed.execution_id
    assert succeeded.canonical_bytes != failed.canonical_bytes
    store = TradeExecutionReceiptStore(tmp_path)

    assert store.put(succeeded, order=order) == succeeded
    assert store.put(succeeded, order=order) == succeeded
    with pytest.raises(
        TradeExecutionReceiptConflict,
        match="different signed bytes",
    ):
        store.put(failed, order=order)
    with pytest.raises(
        TradeExecutionReceiptConflict,
        match="contradictory retained",
    ):
        store.get(succeeded.execution_id, order=order)
    with pytest.raises(
        TradeExecutionReceiptConflict,
        match="contradictory retained",
    ):
        store.put(succeeded, order=order)
    assert store.list_conflicts(
        succeeded.execution_id,
        order=order,
    ) == (failed,)


def test_execution_coordinator_makes_cas_mandatory(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    store = TradeExecutionReceiptStore(tmp_path)
    audit_outbox = TradeExecutionAuditOutbox(tmp_path)
    coordinator = TradeExecutionCoordinator(
        store,
        audit_outbox,
        SignedEventLog(
            tmp_path / "execution-spine.jsonl",
            context["maker"],
        ),
    )

    first = _execution_receipt(
        context,
        order,
        coordinator=coordinator,
    )
    assert _execution_receipt(
        context,
        order,
        coordinator=coordinator,
    ) == first
    with pytest.raises(TradeExecutionReceiptConflict):
        _execution_receipt(
            context,
            order,
            coordinator=coordinator,
            outcome="failed",
            result_payload=b'{"error":"contradiction"}',
            result={
                "media_type": "application/problem+json",
                "digest": _digest(b'{"error":"contradiction"}'),
                "size_bytes": len(b'{"error":"contradiction"}'),
            },
        )
    with pytest.raises(TradeExecutionReceiptConflict):
        store.get(first.execution_id, order=order)
    record = audit_outbox.get(first.execution_id)
    assert record is not None
    assert record.status == "blocked"
    assert record.event_id
    report = coordinator.reconcile(
        now_ms=int(_utc("2026-09-01T00:02:00Z").timestamp() * 1000)
    )
    assert report.blocked == 1
    assert report.verified_blocked == 1
    assert report.failed == 0


def _execution_audit_components(tmp_path, context):
    store = TradeExecutionReceiptStore(tmp_path)
    outbox = TradeExecutionAuditOutbox(tmp_path)
    spine = SignedEventLog(
        tmp_path / "execution-spine.jsonl",
        context["maker"],
    )
    return store, outbox, spine, TradeExecutionCoordinator(
        store,
        outbox,
        spine,
    )


def test_execution_coordinator_anchors_once_and_is_idempotent(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    store, outbox, spine, coordinator = _execution_audit_components(
        tmp_path,
        context,
    )

    first = _execution_receipt(context, order, coordinator=coordinator)
    second = _execution_receipt(context, order, coordinator=coordinator)

    assert second == first
    assert store.get(first.execution_id, order=order) == first
    record = outbox.get(first.execution_id)
    assert record is not None
    assert record.status == "anchored"
    events = list(spine.read_all())
    assert len(events) == 1
    assert events[0].payload == execution_audit_payload(first, order=order)
    assert events[0].event_id == record.event_id


@pytest.mark.parametrize("crash_after", ["prepare", "store", "spine"])
def test_execution_audit_reconciles_each_crash_window(
    tmp_path,
    crash_after,
):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    store, outbox, spine, coordinator = _execution_audit_components(
        tmp_path,
        context,
    )
    now_ms = int(_utc("2026-09-01T00:02:00Z").timestamp() * 1000)
    outbox.prepare(receipt, order=order, now_ms=now_ms)
    if crash_after in {"store", "spine"}:
        store.put(receipt, order=order)
    if crash_after == "spine":
        spine.append(
            trade_rules_api.EVENT_TRADE_EXECUTION_RECORDED,
            execution_audit_payload(receipt, order=order),
            ts_ms=now_ms,
        )

    report = coordinator.reconcile(now_ms=now_ms)

    assert report.failed == 0
    assert report.anchored == 1
    record = outbox.get(receipt.execution_id)
    assert record is not None
    assert record.status == "anchored"
    assert store.get(receipt.execution_id, order=order) == receipt
    assert len(list(spine.read_all())) == 1


def test_execution_audit_recovery_survives_wall_clock_rollback(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    _, outbox, spine, coordinator = _execution_audit_components(
        tmp_path,
        context,
    )
    prepared_at = int(
        _utc("2026-09-01T00:02:00Z").timestamp() * 1000
    )
    outbox.prepare(receipt, order=order, now_ms=prepared_at)

    report = coordinator.reconcile(now_ms=1)

    assert report.anchored == 1
    assert report.failed == 0
    record = outbox.get(receipt.execution_id)
    assert record is not None
    assert record.status == "anchored"
    assert record.updated_at_ms == prepared_at
    assert list(spine.read_all())[0].ts_ms == prepared_at


def test_execution_audit_recovers_when_append_commits_then_raises(
    tmp_path,
    monkeypatch,
):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    _, outbox, spine, coordinator = _execution_audit_components(
        tmp_path,
        context,
    )
    now_ms = int(_utc("2026-09-01T00:02:00Z").timestamp() * 1000)
    outbox.prepare(receipt, order=order, now_ms=now_ms)
    append_unique = spine.append_unique

    def append_then_raise(*args, **kwargs):
        append_unique(*args, **kwargs)
        raise OSError("simulated post-append crash")

    monkeypatch.setattr(spine, "append_unique", append_then_raise)
    first = coordinator.reconcile(now_ms=now_ms)

    assert first.failed == 1
    pending = outbox.get(receipt.execution_id)
    assert pending is not None
    assert pending.status == "stored"
    assert pending.last_error == "spine-anchor-failed"
    assert len(list(spine.read_all())) == 1

    monkeypatch.setattr(spine, "append_unique", append_unique)
    second = coordinator.reconcile(now_ms=now_ms)

    assert second.anchored == 1
    assert second.failed == 0
    assert outbox.get(receipt.execution_id).status == "anchored"
    assert len(list(spine.read_all())) == 1


def test_execution_audit_ignores_bounded_crash_temporary_file(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    outbox = TradeExecutionAuditOutbox(tmp_path)
    now_ms = int(_utc("2026-09-01T00:02:00Z").timestamp() * 1000)
    outbox.prepare(receipt, order=order, now_ms=now_ms)
    root = tmp_path / "trade" / "execution_audit_outbox_v1"
    record_path = next(root.glob("*.json"))
    temporary = root / f"{record_path.name}.deadbeef.tmp"
    temporary.write_bytes(b'{"incomplete":')

    assert outbox.get(receipt.execution_id) is not None
    with pytest.raises(TradeExecutionAuditCapacity, match="max_records"):
        TradeExecutionAuditOutbox(
            tmp_path,
            max_records=1,
        ).get(receipt.execution_id)


def test_execution_audit_prepare_counts_temporary_files_in_capacity(
    tmp_path,
):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    record_root = tmp_path / "record-cap" / "trade" / (
        "execution_audit_outbox_v1"
    )
    record_root.mkdir(parents=True)
    for index in range(2):
        (record_root / f"{index:064x}.json.deadbeef{index}.tmp").write_bytes(
            b"x"
        )
    record_limited = TradeExecutionAuditOutbox(
        tmp_path / "record-cap",
        max_records=2,
    )

    with pytest.raises(TradeExecutionAuditCapacity, match="max_records"):
        record_limited.prepare(
            receipt,
            order=order,
            now_ms=int(_utc("2026-09-01T00:02:00Z").timestamp() * 1000),
        )
    assert not tuple(record_root.glob("*.json"))

    measure_root = tmp_path / "measure"
    measured = TradeExecutionAuditOutbox(measure_root)
    measured.prepare(
        receipt,
        order=order,
        now_ms=int(_utc("2026-09-01T00:02:00Z").timestamp() * 1000),
    )
    record_size = next(
        (
            measure_root
            / "trade"
            / "execution_audit_outbox_v1"
        ).glob("*.json")
    ).stat().st_size
    byte_root = tmp_path / "byte-cap" / "trade" / (
        "execution_audit_outbox_v1"
    )
    byte_root.mkdir(parents=True)
    (byte_root / f"{0:064x}.json.deadbeef.tmp").write_bytes(b"x" * 11)
    byte_limited = TradeExecutionAuditOutbox(
        tmp_path / "byte-cap",
        max_bytes=record_size + 10,
    )

    with pytest.raises(TradeExecutionAuditCapacity, match="max_bytes"):
        byte_limited.prepare(
            receipt,
            order=order,
            now_ms=int(_utc("2026-09-01T00:02:00Z").timestamp() * 1000),
        )
    assert not tuple(byte_root.glob("*.json"))


def test_execution_audit_reconcile_limit_pages_all_statuses(tmp_path):
    context = _setup(tmp_path)
    _, _, _, coordinator = _execution_audit_components(
        tmp_path,
        context,
    )
    for index in range(3):
        operation_id = f"deliver-service-{index}"
        order = _order_for_operation(context, operation_id)
        _execution_receipt(
            context,
            order,
            coordinator=coordinator,
            operation_id=operation_id,
        )

    cursor = None
    reports = []
    while True:
        report = coordinator.reconcile(
            limit=1,
            after_execution_id=cursor,
            now_ms=int(_utc("2026-09-01T00:02:00Z").timestamp() * 1000),
        )
        reports.append(report)
        assert report.scanned <= 1
        if not report.has_more:
            break
        assert report.next_cursor
        cursor = report.next_cursor

    assert len(reports) == 3
    assert sum(report.scanned for report in reports) == 3
    assert sum(report.verified_anchored for report in reports) == 3
    assert reports[-1].next_cursor is None


def test_execution_audit_concurrent_issue_has_one_anchor(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    _, outbox, spine, coordinator = _execution_audit_components(
        tmp_path,
        context,
    )

    with ThreadPoolExecutor(max_workers=8) as executor:
        receipts = list(
            executor.map(
                lambda _: _execution_receipt(
                    context,
                    order,
                    coordinator=coordinator,
                ),
                range(8),
            )
        )

    assert all(receipt == receipts[0] for receipt in receipts)
    assert outbox.get(receipts[0].execution_id).status == "anchored"
    assert len(list(spine.read_all())) == 1


def test_execution_audit_does_not_claim_unretained_cas_conflict(
    tmp_path,
    monkeypatch,
):
    context = _setup(tmp_path)
    order = _order(context)
    store, outbox, _, coordinator = _execution_audit_components(
        tmp_path,
        context,
    )
    first = _execution_receipt(context, order, coordinator=coordinator)

    def fail_before_retention(*args, **kwargs):
        raise TradeExecutionReceiptStoreError("simulated CAS damage")

    monkeypatch.setattr(store, "put", fail_before_retention)
    with pytest.raises(
        TradeExecutionAuditError,
        match="without retaining conflict evidence",
    ):
        _execution_receipt(
            context,
            order,
            coordinator=coordinator,
            outcome="failed",
            result_payload=b'{"error":"contradiction"}',
            result={
                "media_type": "application/problem+json",
                "digest": _digest(b'{"error":"contradiction"}'),
                "size_bytes": len(b'{"error":"contradiction"}'),
            },
        )

    record = outbox.get(first.execution_id)
    assert record is not None
    assert record.status == "anchored"


def test_execution_audit_rejects_forged_blocked_status(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    _, outbox, _, coordinator = _execution_audit_components(
        tmp_path,
        context,
    )
    receipt = _execution_receipt(
        context,
        order,
        coordinator=coordinator,
    )
    root = tmp_path / "trade" / "execution_audit_outbox_v1"
    record_path = next(root.glob("*.json"))
    document = json.loads(record_path.read_text(encoding="utf-8"))
    document["status"] = "blocked"
    document["last_error"] = "receipt-conflict"
    record_path.write_bytes(canonical_json(document))

    report = coordinator.reconcile(
        now_ms=int(_utc("2026-09-01T00:02:00Z").timestamp() * 1000)
    )

    assert report.scanned == 1
    assert report.blocked == 0
    assert report.verified_blocked == 0
    assert report.failed == 1
    assert outbox.get(receipt.execution_id).status == "blocked"


def test_execution_audit_rejects_corrupt_record_and_duplicate_anchor(
    tmp_path,
):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    _, outbox, spine, coordinator = _execution_audit_components(
        tmp_path,
        context,
    )
    now_ms = int(_utc("2026-09-01T00:02:00Z").timestamp() * 1000)
    outbox.prepare(receipt, order=order, now_ms=now_ms)
    payload = execution_audit_payload(receipt, order=order)
    spine.append(
        trade_rules_api.EVENT_TRADE_EXECUTION_RECORDED,
        payload,
        ts_ms=now_ms,
    )
    spine.append(
        trade_rules_api.EVENT_TRADE_EXECUTION_RECORDED,
        payload,
        ts_ms=now_ms,
    )

    with pytest.raises(
        TradeExecutionAuditError,
        match="duplicate or conflicting",
    ):
        coordinator.reconcile(now_ms=now_ms)

    record_path = next(
        (tmp_path / "trade" / "execution_audit_outbox_v1").glob("*.json")
    )
    document = json.loads(record_path.read_text(encoding="utf-8"))
    record_path.write_text(
        json.dumps(document, indent=2),
        encoding="utf-8",
    )
    with pytest.raises(TradeExecutionAuditError, match="not canonical"):
        outbox.get(receipt.execution_id)

    original_status = document["status"]
    document["status"] = []
    record_path.write_bytes(canonical_json(document))
    with pytest.raises(TradeExecutionAuditError, match="status is invalid"):
        outbox.get(receipt.execution_id)

    document["status"] = original_status
    document["receipt_digest"] = "sha256:" + ("0" * 64)
    record_path.write_bytes(canonical_json(document))
    with pytest.raises(TradeExecutionAuditError, match="digest binding"):
        outbox.get(receipt.execution_id)
    with pytest.raises(TradeExecutionAuditError, match="execution_id"):
        outbox.get("invalid")


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("order_id", "nth-trade-order-sha256:short"),
        ("operation_id", "Uppercase"),
        ("execution_id", 1),
        ("executor_did", 1),
        ("outcome", []),
        ("completed_at", "2026-02-30T00:00:00Z"),
        ("completed_at", "2026-09-01T00:00:00.000000Z"),
    ],
)
def test_execution_audit_payload_validation_is_strict(
    tmp_path,
    field,
    invalid,
):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    payload = execution_audit_payload(receipt, order=order)
    payload[field] = invalid

    with pytest.raises(TradeExecutionAuditError):
        validate_execution_audit_payload(payload)


def test_execution_receipt_store_cross_process_same_bytes_is_once(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    process_context = multiprocessing.get_context("spawn")
    output = process_context.Queue()
    workers = [
        process_context.Process(
            target=_process_put_execution_receipt,
            args=(
                str(tmp_path),
                receipt.to_dict(),
                order.to_dict(),
                output,
            ),
        )
        for _ in range(6)
    ]

    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(30)
        assert worker.exitcode == 0
    responses = [output.get(timeout=5) for _ in workers]

    assert responses == [("ok", receipt.execution_id)] * len(workers)
    store = TradeExecutionReceiptStore(tmp_path)
    assert store.get(receipt.execution_id, order=order) == receipt
    assert store.list_conflicts(receipt.execution_id, order=order) == ()


def test_execution_receipt_store_cross_process_conflict_fails_closed(
    tmp_path,
):
    context = _setup(tmp_path)
    order = _order(context)
    first = _execution_receipt(context, order)
    second = _execution_receipt(
        context,
        order,
        outcome="failed",
        result_payload=b'{"error":"conflict"}',
        result={
            "media_type": "application/problem+json",
            "digest": _digest(b'{"error":"conflict"}'),
            "size_bytes": len(b'{"error":"conflict"}'),
        },
    )
    process_context = multiprocessing.get_context("spawn")
    output = process_context.Queue()
    workers = [
        process_context.Process(
            target=_process_put_execution_receipt,
            args=(
                str(tmp_path),
                candidate.to_dict(),
                order.to_dict(),
                output,
            ),
        )
        for candidate in (first, second)
    ]

    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(30)
        assert worker.exitcode == 0
    responses = [output.get(timeout=5) for _ in workers]

    assert sorted(item[0] for item in responses) == ["error", "ok"]
    assert any(
        item[1] == "TradeExecutionReceiptConflict"
        for item in responses
        if item[0] == "error"
    )
    store = TradeExecutionReceiptStore(tmp_path)
    with pytest.raises(TradeExecutionReceiptConflict):
        store.get(first.execution_id, order=order)
    assert len(
        store.list_conflicts(first.execution_id, order=order)
    ) == 1


def test_execution_receipt_capacity_failure_leaves_conflict_marker(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    first = _execution_receipt(context, order)
    second = _execution_receipt(
        context,
        order,
        outcome="failed",
        result_payload=b'{"error":"capacity"}',
        result={
            "media_type": "application/problem+json",
            "digest": _digest(b'{"error":"capacity"}'),
            "size_bytes": len(b'{"error":"capacity"}'),
        },
    )
    store = TradeExecutionReceiptStore(
        tmp_path,
        max_bytes=len(first.canonical_bytes) + 1,
    )
    store.put(first, order=order)

    with pytest.raises(
        trade_rules_api.TradeExecutionReceiptStoreCapacity,
        match="max_bytes prevents conflict retention",
    ):
        store.put(second, order=order)
    with pytest.raises(
        TradeExecutionReceiptConflict,
        match="contradictory retained",
    ):
        store.get(first.execution_id, order=order)
    assert store._conflict_marker_path(first.execution_id).exists()
    status = store.conflict_status(first.execution_id, order=order)
    assert status.has_conflict is True
    assert status.marker_candidate_digest == execution_receipt_digest(
        second,
        order=order,
    )
    assert status.retained_receipt_digests == (
        execution_receipt_digest(first, order=order),
    )
    assert status.retention_complete is False


def test_conflict_status_does_not_treat_primary_digest_as_full_retention(
    tmp_path,
):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    store = TradeExecutionReceiptStore(tmp_path)
    store.put(receipt, order=order)
    primary_digest = execution_receipt_digest(receipt, order=order)
    store._atomic_write(
        store._conflict_marker_path(receipt.execution_id),
        trade_rules_api.trade_canonical_json({
            "candidate_digest": primary_digest,
            "execution_id": receipt.execution_id,
        }),
    )

    status = store.conflict_status(receipt.execution_id, order=order)
    assert status.has_conflict is True
    assert status.retained_receipt_digests == (primary_digest,)
    assert status.retention_complete is False


def test_execution_receipt_retry_repairs_marker_only_crash_residue(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    first = _execution_receipt(context, order)
    second = _execution_receipt(
        context,
        order,
        outcome="failed",
        result_payload=b'{"error":"crash"}',
        result={
            "media_type": "application/problem+json",
            "digest": _digest(b'{"error":"crash"}'),
            "size_bytes": len(b'{"error":"crash"}'),
        },
    )
    store = TradeExecutionReceiptStore(tmp_path)
    store.put(first, order=order)
    store._mark_conflict(second, order)
    assert store.list_conflicts(first.execution_id, order=order) == ()
    incomplete = store.conflict_status(first.execution_id, order=order)
    assert incomplete.has_conflict is True
    assert incomplete.retention_complete is False

    with pytest.raises(
        TradeExecutionReceiptConflict,
        match="different signed bytes",
    ):
        store.put(second, order=order)

    assert store.list_conflicts(
        first.execution_id,
        order=order,
    ) == (second,)
    repaired = store.conflict_status(first.execution_id, order=order)
    assert repaired.has_conflict is True
    assert repaired.retention_complete is True
    assert len(repaired.retained_receipt_digests) == 2


def test_execution_receipt_store_fails_closed_on_corruption(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    store = TradeExecutionReceiptStore(tmp_path)
    store.put(receipt, order=order)
    store._path(receipt.execution_id).write_bytes(b"{}")

    with pytest.raises(TradeExecutionReceiptRejected):
        store.get(receipt.execution_id, order=order)


def test_execution_receipt_store_rejects_unknown_files(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    store = TradeExecutionReceiptStore(tmp_path)
    store.put(receipt, order=order)
    (store.root / "operator-note.txt").write_text(
        "not protocol data",
        encoding="utf-8",
    )

    with pytest.raises(
        trade_rules_api.TradeExecutionReceiptStoreError,
        match="unknown file",
    ):
        store.get(receipt.execution_id, order=order)


def test_execution_receipt_rejects_wrong_party_role(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)

    with pytest.raises(
        TradeExecutionReceiptRejected,
        match="does not match executor_role",
    ):
        _execution_receipt(
            context,
            order,
            identity=context["taker"],
            role="maker",
        )


def test_execution_receipt_rejects_party_without_operation_grant(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)

    with pytest.raises(
        TradeExecutionReceiptRejected,
        match="does not authorize executor_role",
    ):
        _execution_receipt(
            context,
            order,
            identity=context["taker"],
            role="taker",
        )


def test_execution_receipt_input_tamper_breaks_signature(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    document = receipt.to_dict()
    document["operation"]["input"]["digest"] = _digest(b"other input")

    with pytest.raises(
        TradeExecutionReceiptRejected,
        match="signature invalid",
    ):
        TradeExecutionReceipt.from_dict(document, order=order)


def test_execution_receipt_result_tamper_breaks_signature(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    document = receipt.to_dict()
    document["result"]["digest"] = _digest(b"tampered")

    with pytest.raises(
        TradeExecutionReceiptRejected,
        match="signature invalid",
    ):
        TradeExecutionReceipt.from_dict(document, order=order)


def test_execution_receipt_rejects_execution_id_rebinding(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    document = receipt.to_dict()
    document["execution_id"] = (
        trade_rules_api.EXECUTION_RECEIPT_ID_PREFIX + ("0" * 64)
    )

    with pytest.raises(
        TradeExecutionReceiptRejected,
        match="execution_id binding mismatch",
    ):
        TradeExecutionReceipt.from_dict(document, order=order)


def test_execution_receipt_public_parser_requires_order(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)

    with pytest.raises(TypeError, match="order"):
        TradeExecutionReceipt.from_dict(receipt.to_dict())  # type: ignore[call-arg]
    with pytest.raises(TypeError, match="order"):
        execution_receipt_digest(receipt.to_dict())


def test_execution_receipt_rejects_malformed_order_id_before_trust(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    document = receipt.to_dict()
    document["order_id"] = "not-an-order"

    with pytest.raises(
        TradeExecutionReceiptRejected,
        match="order_id is invalid",
    ):
        TradeExecutionReceipt.from_dict(document, order=order)


def test_execution_receipt_rejects_different_order_binding(tmp_path):
    context = _setup(tmp_path / "first")
    receipt = _execution_receipt(context, _order(context))
    other_context = _setup(tmp_path / "second")
    other_order = _order(other_context)

    with pytest.raises(
        TradeExecutionReceiptRejected,
        match="order_id does not match",
    ):
        verify_execution_receipt_order_binding(receipt, other_order)


def test_execution_receipt_rejects_signed_attempt_to_drop_order_rule(
    tmp_path,
):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    document = receipt.to_dict()
    document["readiness"]["ordered_package_digests"].pop()
    document["readiness_digest"] = (
        "sha256:"
        + hashlib.sha256(
            trade_rules_api.trade_canonical_json(document["readiness"])
        ).hexdigest()
    )
    _resign_execution_receipt(context["maker"], document)

    with pytest.raises(
        TradeExecutionReceiptRejected,
        match="packages do not match Order",
    ):
        TradeExecutionReceipt.from_dict(document, order=order)


def test_execution_receipt_receiver_replays_readiness_under_local_policy(
    tmp_path,
):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)

    replayed = verify_execution_receipt_under_policy(
        receipt,
        order,
        context["package_store"],
        context["taker_policy"],
        context["adapter_resolver"],
        context["adapter_policy"],
        context["content_resolver"],
        context["schema_validator"],
    )

    assert replayed.ordered_package_digests == tuple(
        receipt.to_dict()["readiness"]["ordered_package_digests"]
    )


def test_execution_receipt_receiver_rejects_signed_false_readiness(
    tmp_path,
):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    document = receipt.to_dict()
    document["readiness"]["ordered_package_digests"].reverse()
    document["readiness_digest"] = (
        "sha256:"
        + hashlib.sha256(
            trade_rules_api.trade_canonical_json(document["readiness"])
        ).hexdigest()
    )
    _resign_execution_receipt(context["maker"], document)
    signed_claim = TradeExecutionReceipt.from_dict(document, order=order)

    with pytest.raises(
        TradeExecutionReceiptRejected,
        match="disagrees with verifier policy",
    ):
        verify_execution_receipt_under_policy(
            signed_claim,
            order,
            context["package_store"],
            context["taker_policy"],
            context["adapter_resolver"],
            context["adapter_policy"],
            context["content_resolver"],
            context["schema_validator"],
        )


def test_execution_receipt_receiver_rejects_signed_hook_schema_lie(
    tmp_path,
):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    document = receipt.to_dict()
    document["operation"]["output_schema_digest"] = _digest(
        b"forged output schema"
    )
    _resign_execution_receipt(context["maker"], document)
    signed_claim = TradeExecutionReceipt.from_dict(document, order=order)

    with pytest.raises(
        TradeExecutionReceiptRejected,
        match="operation disagrees with Rule Hook",
    ):
        verify_execution_receipt_under_policy(
            signed_claim,
            order,
            context["package_store"],
            context["taker_policy"],
            context["adapter_resolver"],
            context["adapter_policy"],
            context["content_resolver"],
            context["schema_validator"],
        )


def test_execution_receipt_rejects_signed_role_redirection(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    document = receipt.to_dict()
    document["executor_role"] = "taker"
    document["operation"]["executor_role"] = "taker"
    _resign_execution_receipt(context["maker"], document)

    with pytest.raises(
        TradeExecutionReceiptRejected,
        match="signer does not match executor_role",
    ):
        TradeExecutionReceipt.from_dict(document, order=order)


def test_execution_receipt_rejects_unapproved_adapter_mode(tmp_path):
    context = _setup(tmp_path)

    with pytest.raises(
        TradeExecutionReceiptRejected,
        match="execution Adapter rejected.*mode is not locally allowed",
    ):
        _execution_receipt(
            context,
            _order(context),
            execution_mode="python",
        )


def test_execution_receipt_rejects_control_character_adapter_mode(tmp_path):
    context = _setup(tmp_path)

    with pytest.raises(
        TradeExecutionReceiptRejected,
        match="execution_mode is invalid",
    ):
        _execution_receipt(
            context,
            _order(context),
            execution_mode="declarative\nforged",
        )


def test_execution_receipt_requires_locally_accepted_adapter_digest(tmp_path):
    context = _setup(tmp_path)
    context["adapter_policy"] = TradeExecutionAdapterPolicy(
        accepted_adapter_digests=frozenset(),
    )

    with pytest.raises(
        TradeExecutionReceiptRejected,
        match="Adapter rejected.*digest is not accepted",
    ):
        _execution_receipt(context, _order(context))


def test_execution_receipt_rejects_adapter_without_authorized_hook(tmp_path):
    context = _setup(tmp_path)
    artifact = b"wrong hook adapter"
    adapter = build_execution_adapter(
        adapter_id="org.nthdao.test/declarative",
        adapter_version="1.0.0",
        artifact_digest=_digest(artifact),
        execution_modes=["declarative"],
        hooks=[{
            "rule_id": "org.nthdao.test.delivery",
            "hook_name": "fulfillment.cancel",
            "hook_version": "1",
        }],
    )
    context["adapter"] = adapter
    context["adapter_resolver"] = _AdapterResolver(
        adapter,
        artifacts={_digest(artifact): artifact},
    )
    context["adapter_policy"] = TradeExecutionAdapterPolicy(
        accepted_adapter_digests={adapter.digest},
    )

    with pytest.raises(
        TradeExecutionReceiptRejected,
        match="does not support the authorized Rule Hook",
    ):
        _execution_receipt(context, _order(context))


def test_execution_receipt_rejects_adapter_permission_drift(tmp_path):
    context = _setup(tmp_path)
    artifact = b"overprivileged adapter"
    adapter = build_execution_adapter(
        adapter_id="org.nthdao.test/declarative",
        adapter_version="1.0.0",
        artifact_digest=_digest(artifact),
        execution_modes=["declarative"],
        hooks=[{
            "rule_id": "org.nthdao.test.delivery",
            "hook_name": "fulfillment.deliver",
            "hook_version": "1",
        }],
        permissions=["network.read"],
    )
    context["adapter"] = adapter
    context["adapter_resolver"] = _AdapterResolver(
        adapter,
        artifacts={_digest(artifact): artifact},
    )
    context["adapter_policy"] = TradeExecutionAdapterPolicy(
        accepted_adapter_digests={adapter.digest},
        allowed_permissions={"network.read"},
    )

    with pytest.raises(
        TradeExecutionReceiptRejected,
        match="permissions do not exactly match the Rule",
    ):
        _execution_receipt(context, _order(context))


def test_execution_receipt_binds_transitive_rule_permissions(tmp_path):
    context = _setup(
        tmp_path,
        dependency_permissions=("network.read",),
    )
    order = _order(context)
    receipt = _execution_receipt(context, order)

    assert receipt.to_dict()["readiness"]["required_permissions"] == [
        "network.read"
    ]
    verify_execution_receipt_under_policy(
        receipt,
        order,
        context["package_store"],
        context["taker_policy"],
        context["adapter_resolver"],
        context["adapter_policy"],
        context["content_resolver"],
        context["schema_validator"],
    )


def test_execution_receipt_does_not_grant_dependency_permission_to_hook(
    tmp_path,
):
    context = _setup(
        tmp_path,
        dependency_permissions=("network.read",),
    )
    artifact = b"underprivileged adapter"
    adapter = build_execution_adapter(
        adapter_id="org.nthdao.test/declarative",
        adapter_version="1.0.0",
        artifact_digest=_digest(artifact),
        execution_modes=["declarative"],
        hooks=[{
            "rule_id": "org.nthdao.test.delivery",
            "hook_name": "fulfillment.deliver",
            "hook_version": "1",
        }],
        permissions=[],
    )
    context["adapter"] = adapter
    context["adapter_resolver"] = _AdapterResolver(
        adapter,
        artifacts={_digest(artifact): artifact},
    )
    context["adapter_policy"] = TradeExecutionAdapterPolicy(
        accepted_adapter_digests={adapter.digest},
        allowed_permissions={"network.read"},
    )

    receipt = _execution_receipt(context, _order(context))
    assert receipt.to_dict()["readiness"]["required_permissions"] == [
        "network.read"
    ]
    assert context["adapter"].to_dict()["permissions"] == []


def test_execution_receipt_requires_exact_hook_scoped_permissions(tmp_path):
    context = _setup(
        tmp_path,
        hook_permissions=("network.read",),
    )
    order = _order(context)
    receipt = _execution_receipt(
        context,
        order,
        execution_mode="adapter",
    )
    assert receipt.to_dict()["readiness"]["required_permissions"] == [
        "network.read"
    ]
    artifact = b"underprivileged adapter"
    adapter = build_execution_adapter(
        adapter_id="org.nthdao.test/declarative",
        adapter_version="1.0.0",
        artifact_digest=_digest(artifact),
        execution_modes=["adapter"],
        hooks=[{
            "rule_id": "org.nthdao.test.delivery",
            "hook_name": "fulfillment.deliver",
            "hook_version": "1",
        }],
        permissions=[],
    )
    context["adapter"] = adapter
    context["adapter_resolver"] = _AdapterResolver(
        adapter,
        artifacts={_digest(artifact): artifact},
    )
    context["adapter_policy"] = TradeExecutionAdapterPolicy(
        accepted_adapter_digests={adapter.digest},
        allowed_execution_modes={"adapter"},
        allowed_permissions={"network.read"},
    )

    with pytest.raises(
        TradeExecutionReceiptRejected,
        match="permissions do not exactly match the Rule",
    ):
        _execution_receipt(
            context,
            order,
            execution_mode="adapter",
        )


def test_execution_receipt_policy_rejects_signed_adapter_substitution(
    tmp_path,
):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    substituted = build_execution_adapter(
        adapter_id="org.nthdao.test/declarative",
        adapter_version="1.0.0",
        artifact_digest=_digest(b"substituted adapter artifact"),
        execution_modes=["declarative"],
        hooks=[{
            "rule_id": "org.nthdao.test.delivery",
            "hook_name": "fulfillment.deliver",
            "hook_version": "1",
        }],
    )
    document = receipt.to_dict()
    document["adapter"]["adapter_digest"] = substituted.digest
    _resign_execution_receipt(context["maker"], document)
    signed_claim = TradeExecutionReceipt.from_dict(document, order=order)

    with pytest.raises(
        TradeExecutionReceiptRejected,
        match="Adapter rejected.*digest is not accepted",
    ):
        verify_execution_receipt_under_policy(
            signed_claim,
            order,
            context["package_store"],
            context["taker_policy"],
            context["adapter_resolver"],
            context["adapter_policy"],
            context["content_resolver"],
            context["schema_validator"],
        )


def test_execution_adapter_resolver_cannot_substitute_content(tmp_path):
    context = _setup(tmp_path)
    substituted = build_execution_adapter(
        adapter_id="org.nthdao.test/declarative",
        adapter_version="1.0.0",
        artifact_digest=_digest(b"resolver substitution"),
        execution_modes=["declarative"],
        hooks=[{
            "rule_id": "org.nthdao.test.delivery",
            "hook_name": "fulfillment.deliver",
            "hook_version": "1",
        }],
    )

    class SubstitutingResolver:
        def load(self, _digest_value):
            return substituted

        def load_artifact(self, _digest_value):
            return b"resolver substitution"

    context["adapter_resolver"] = SubstitutingResolver()

    with pytest.raises(
        TradeExecutionReceiptRejected,
        match="Adapter content digest mismatch",
    ):
        _execution_receipt(context, _order(context))


def test_execution_adapter_resolver_cannot_substitute_artifact(tmp_path):
    context = _setup(tmp_path)
    context["adapter_resolver"] = _AdapterResolver(
        context["adapter"],
        artifacts={
            context["adapter"].to_dict()["artifact_digest"]:
            b"tampered adapter artifact"
        },
    )

    with pytest.raises(
        TradeExecutionReceiptRejected,
        match="Adapter artifact content digest mismatch",
    ):
        _execution_receipt(context, _order(context))


def test_execution_adapter_policy_normalizes_mutable_sets(tmp_path):
    context = _setup(tmp_path)
    accepted = {context["adapter"].digest}
    policy = TradeExecutionAdapterPolicy(
        accepted_adapter_digests=accepted,
    )
    accepted.clear()

    assert policy.accepted_adapter_digests == frozenset(
        {context["adapter"].digest}
    )


def test_execution_adapter_policy_has_canonical_protocol_digest(tmp_path):
    context = _setup(tmp_path)
    policy = context["adapter_policy"]
    restored = TradeExecutionAdapterPolicy.from_dict(policy.to_dict())

    assert restored == policy
    assert restored.canonical_bytes == policy.canonical_bytes
    assert restored.digest == (
        "sha256:" + hashlib.sha256(policy.canonical_bytes).hexdigest()
    )
    assert policy.to_dict()["kind"] == (
        "nth.dao.trade.execution-adapter-policy"
    )
    digest = next(iter(policy.accepted_adapter_digests))
    with pytest.raises(
        TradeExecutionAdapterRejected,
        match="sorted and unique",
    ):
        TradeExecutionAdapterPolicy.from_dict(
            {
                **policy.to_dict(),
                "accepted_adapter_digests": [digest, digest],
            }
        )


def test_execution_receipt_creation_honors_current_policy(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)

    with pytest.raises(
        TradeOrderExecutionRejected,
        match="current executor policy.*not accepted",
    ):
        TradeExecutionCoordinator(
            TradeExecutionReceiptStore(tmp_path),
            TradeExecutionAuditOutbox(tmp_path),
            SignedEventLog(
                tmp_path / "execution-spine.jsonl",
                context["maker"],
            ),
        ).issue(
            context["maker"],
            order=order,
            package_resolver=context["package_store"],
            executor_policy=RuleResolutionPolicy(),
            adapter_resolver=context["adapter_resolver"],
            adapter_policy=context["adapter_policy"],
            content_resolver=context["content_resolver"],
            schema_validator=context["schema_validator"],
            executor_role="maker",
            adapter_id=context["adapter"].to_dict()["adapter_id"],
            adapter_version=context["adapter"].to_dict()["adapter_version"],
            adapter_digest=context["adapter"].digest,
            execution_mode="declarative",
            operation_id="deliver-service",
            operation_input={
                "media_type": "application/json",
                "digest": _digest(b'{"order":"deliver"}'),
                "size_bytes": len(b'{"order":"deliver"}'),
            },
            outcome="failed",
            result={
                "media_type": "application/problem+json",
                "digest": _digest(b'{"error":"revoked"}'),
                "size_bytes": len(b'{"error":"revoked"}'),
            },
            started_at="2026-09-01T00:00:00Z",
            completed_at="2026-09-01T00:01:00Z",
            now=_utc("2026-09-01T00:01:00Z"),
        )


def test_execution_receipt_rejects_invalid_times(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)

    with pytest.raises(
        TradeExecutionReceiptRejected,
        match="completed_at precedes",
    ):
        _execution_receipt(
            context,
            order,
            started_at="2026-09-01T00:02:00Z",
            completed_at="2026-09-01T00:01:00Z",
        )
    with pytest.raises(
        TradeExecutionReceiptRejected,
        match="clock-skew",
    ):
        _execution_receipt(
            context,
            order,
            now=_utc("2026-09-02T00:00:00Z"),
        )


def test_execution_receipt_preserves_microsecond_start_binding(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(
        context,
        order,
        started_at="2026-09-01T00:00:00.000001Z",
        completed_at="2026-09-01T00:01:00.000002Z",
        now=_utc("2026-09-01T00:01:00Z"),
    )

    assert receipt.to_dict()["readiness"]["evaluated_at"] == (
        "2026-09-01T00:00:00.000001Z"
    )
    tampered = receipt.to_dict()
    tampered["readiness"]["evaluated_at"] = (
        "2026-09-01T00:00:00.000002Z"
    )
    tampered["readiness_digest"] = (
        "sha256:"
        + hashlib.sha256(
            trade_rules_api.trade_canonical_json(tampered["readiness"])
        ).hexdigest()
    )
    with pytest.raises(
        TradeExecutionReceiptRejected,
        match="must equal started_at",
    ):
        TradeExecutionReceipt.from_dict(tampered, order=order)


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-09-01T00:00:00.000000001Z",
        "2026-09-01T00:00:00.000000Z",
        "2026-09-01T00:00:00.1Z",
    ],
)
def test_execution_receipt_rejects_noncanonical_time_precision(
    tmp_path,
    timestamp,
):
    context = _setup(tmp_path)
    with pytest.raises(
        TradeExecutionReceiptRejected,
        match="UTC RFC3339|omit zero",
    ):
        _execution_receipt(
            context,
            _order(context),
            started_at=timestamp,
        )


def test_execution_receipt_sorts_evidence_and_rejects_duplicates(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    log_digest = _digest(b"log")
    artifact_digest = _digest(b"artifact")
    receipt = _execution_receipt(
        context,
        order,
        evidence=[
            {
                "evidence_type": "log",
                "media_type": "text/plain",
                "digest": log_digest,
                "size_bytes": 3,
            },
            {
                "evidence_type": "artifact",
                "media_type": "application/octet-stream",
                "digest": artifact_digest,
                "size_bytes": 8,
            },
        ],
    )
    assert [item["evidence_type"] for item in receipt.to_dict()["evidence"]] == [
        "artifact",
        "log",
    ]

    duplicate = receipt.to_dict()
    duplicate["evidence"].append(copy.deepcopy(duplicate["evidence"][0]))
    with pytest.raises(
        TradeExecutionReceiptRejected,
        match="duplicate",
    ):
        TradeExecutionReceipt.from_dict(duplicate, order=order)


def test_execution_readiness_serialization_and_digest_are_stable(tmp_path):
    context = _setup(tmp_path)
    readiness = verify_trade_order_execution(
        _order(context),
        context["package_store"],
        context["maker_policy"],
        at=_utc("2026-09-01T00:00:00Z"),
    )

    assert readiness.to_dict()["kind"] == (
        trade_rules_api.EXECUTION_READINESS_KIND
    )
    assert readiness.digest == (
        "sha256:" + hashlib.sha256(
            trade_rules_api.trade_canonical_json(
                readiness.to_dict()
            )
        ).hexdigest()
    )


def test_execution_receipt_is_public_trade_rule_api():
    assert trade_rules_api.TradeExecutionReceipt is TradeExecutionReceipt
    assert trade_rules_api.TradeExecutionCoordinator is (
        TradeExecutionCoordinator
    )
    assert not hasattr(
        trade_rules_api,
        "create_trade_execution_receipt",
    )


def _receipt_review(context, order, receipt, **changes):
    identity = changes.pop("identity", context["taker"])
    arguments = {
        "receipt": receipt,
        "order": order,
        "package_resolver": context["package_store"],
        "verifier_policy": context["taker_policy"],
        "adapter_resolver": context["adapter_resolver"],
        "adapter_policy": context["adapter_policy"],
        "content_resolver": context["content_resolver"],
        "schema_validator": context["schema_validator"],
        "decision": "accepted",
        "reason_codes": [],
        "reviewed_at": "2026-09-01T00:02:00Z",
        "now": _utc("2026-09-01T00:02:00Z"),
    }
    arguments.update(changes)
    return create_trade_receipt_review(
        identity,
        **arguments,
    )


def test_receipt_review_round_trip_requires_independent_counterparty(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)

    review = _receipt_review(context, order, receipt)
    document = review.to_dict()

    assert document["reviewer_role"] == "taker"
    assert document["reviewer_did"] == context["taker"].as_did()
    assert document["receipt_digest"] == execution_receipt_digest(receipt)
    assert receipt_review_digest(review).startswith("sha256:")
    assert TradeReceiptReview.from_json(
        review.canonical_bytes,
        receipt=receipt,
        order=order,
    ) == review
    verify_trade_receipt_review_under_policy(
        review,
        receipt=receipt,
        order=order,
        package_resolver=context["package_store"],
        verifier_policy=context["taker_policy"],
        adapter_resolver=context["adapter_resolver"],
        adapter_policy=context["adapter_policy"],
        content_resolver=context["content_resolver"],
        schema_validator=context["schema_validator"],
    )

    with pytest.raises(
        TradeReceiptReviewRejected,
        match="counterparty",
    ):
        _receipt_review(
            context,
            order,
            receipt,
            identity=context["maker"],
        )


def test_receipt_review_reverse_role_taker_executes_maker_reviews(tmp_path):
    context = _setup(tmp_path)
    proposal = _proposal(
        context,
        grants=[
            {
                "operation_id": "deliver-service",
                "rule_id": "org.nthdao.test.delivery",
                "package_digest": context["package_digest"],
                "hook_name": "fulfillment.deliver",
                "hook_version": "1",
                "executor_role": "taker",
            }
        ],
    )
    order = create_trade_order(
        offer=context["offer"],
        proposal=proposal,
        acceptance=_acceptance(context, proposal),
    )
    receipt = _execution_receipt(context, order, role="taker")
    review = _receipt_review(
        context,
        order,
        receipt,
        identity=context["maker"],
        verifier_policy=context["maker_policy"],
    )

    assert receipt.to_dict()["executor_role"] == "taker"
    assert review.to_dict()["reviewer_role"] == "maker"
    assert review.to_dict()["reviewer_did"] == context["maker"].as_did()
    assert TradeReceiptReview.from_json(
        review.canonical_bytes,
        receipt=receipt,
        order=order,
    ) == review


def test_receipt_review_is_public_trade_rule_api():
    assert trade_rules_api.TradeReceiptReview is TradeReceiptReview
    assert trade_rules_api.TradeReceiptReviewStore is TradeReceiptReviewStore
    assert (
        trade_rules_api.TradeReceiptReviewCoordinator
        is TradeReceiptReviewCoordinator
    )
    assert trade_rules_api.create_trade_receipt_review is (
        create_trade_receipt_review
    )
    assert trade_rules_api.EVENT_TRADE_RECEIPT_REVIEWED == (
        EVENT_TRADE_RECEIPT_REVIEWED
    )


def test_receipt_review_tamper_and_rebinding_fail_closed(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _receipt_review(context, order, receipt)

    tampered = review.to_dict()
    tampered["decision"] = "disputed"
    tampered["reason_codes"] = ["result.mismatch"]
    with pytest.raises(TradeReceiptReviewRejected, match="signature invalid"):
        TradeReceiptReview.from_dict(
            tampered,
            receipt=receipt,
            order=order,
        )

    rebound = review.to_dict()
    rebound["receipt_digest"] = "sha256:" + "0" * 64
    rebound["proof"]["proof_value"] = encode_ed25519_signature(
        context["taker"].sign(
            signed_document_input(RECEIPT_REVIEW_SIGNING_DOMAIN, rebound)
        )
    )
    with pytest.raises(
        TradeReceiptReviewRejected,
        match="receipt_digest binding mismatch",
    ):
        TradeReceiptReview.from_dict(
            rebound,
            receipt=receipt,
            order=order,
        )


def test_receipt_review_rejects_ambiguous_negative_and_failed_acceptance(
    tmp_path,
):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)

    with pytest.raises(
        TradeReceiptReviewRejected,
        match="require a reason",
    ):
        _receipt_review(
            context,
            order,
            receipt,
            decision="rejected",
        )

    failed = _execution_receipt(
        context,
        order,
        outcome="failed",
        result_payload=b'{"status":"failed"}',
    )
    with pytest.raises(
        TradeReceiptReviewRejected,
        match="succeeded Receipt",
    ):
        _receipt_review(context, order, failed)


def test_receipt_review_binds_verifier_policy_snapshot(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _receipt_review(context, order, receipt)
    different_policy = replace(
        context["taker_policy"],
        max_packages=context["taker_policy"].max_packages - 1,
    )

    with pytest.raises(
        TradeReceiptReviewRejected,
        match="verifier_policy_digest",
    ):
        verify_trade_receipt_review_under_policy(
            review,
            receipt=receipt,
            order=order,
            package_resolver=context["package_store"],
            verifier_policy=different_policy,
            adapter_resolver=context["adapter_resolver"],
            adapter_policy=context["adapter_policy"],
            content_resolver=context["content_resolver"],
            schema_validator=context["schema_validator"],
        )


def test_receipt_review_store_is_idempotent_and_retains_equivocation(
    tmp_path,
):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    accepted = _receipt_review(context, order, receipt)
    disputed = _receipt_review(
        context,
        order,
        receipt,
        decision="disputed",
        reason_codes=["result.mismatch"],
        reviewed_at="2026-09-01T00:03:00Z",
        now=_utc("2026-09-01T00:03:00Z"),
    )
    store = TradeReceiptReviewStore(tmp_path / "store")

    assert store.put(
        accepted,
        receipt=receipt,
        order=order,
    ) == accepted
    assert store.put(
        accepted,
        receipt=receipt,
        order=order,
    ) == accepted
    with pytest.raises(TradeReceiptReviewConflict):
        store.put(disputed, receipt=receipt, order=order)
    with pytest.raises(TradeReceiptReviewConflict):
        store.get(accepted.review_id, receipt=receipt, order=order)

    status = store.conflict_status(
        accepted.review_id,
        receipt=receipt,
        order=order,
    )
    assert status.has_conflict is True
    assert status.retention_complete is True
    assert len(status.retained_review_digests) == 2
    assert store.list_conflicts(
        accepted.review_id,
        receipt=receipt,
        order=order,
    ) == (disputed,)


def test_receipt_review_digest_rejects_partial_binding(tmp_path):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _receipt_review(context, order, receipt)

    with pytest.raises(TypeError, match="provided together"):
        receipt_review_digest(review, receipt=receipt)
    with pytest.raises(TypeError, match="provided together"):
        receipt_review_digest(review, order=order)
    assert receipt_review_digest(
        review,
        receipt=receipt,
        order=order,
    ) == receipt_review_digest(review)


def test_receipt_review_conflicts_are_scoped_across_orders(tmp_path):
    first_context = _setup(tmp_path / "first-fixtures")
    first_order = _order(first_context)
    first_receipt = _execution_receipt(first_context, first_order)
    first_primary = _receipt_review(
        first_context,
        first_order,
        first_receipt,
    )
    first_conflict = _receipt_review(
        first_context,
        first_order,
        first_receipt,
        decision="disputed",
        reason_codes=["result.mismatch"],
        reviewed_at="2026-09-01T00:03:00Z",
        now=_utc("2026-09-01T00:03:00Z"),
    )
    second_context = _setup(tmp_path / "second-fixtures")
    second_order = _order(second_context)
    second_receipt = _execution_receipt(second_context, second_order)
    second_primary = _receipt_review(
        second_context,
        second_order,
        second_receipt,
    )
    second_conflict = _receipt_review(
        second_context,
        second_order,
        second_receipt,
        decision="rejected",
        reason_codes=["result.invalid"],
        reviewed_at="2026-09-01T00:03:00Z",
        now=_utc("2026-09-01T00:03:00Z"),
    )
    store = TradeReceiptReviewStore(tmp_path / "store")

    store.put(first_primary, receipt=first_receipt, order=first_order)
    with pytest.raises(TradeReceiptReviewConflict):
        store.put(
            first_conflict,
            receipt=first_receipt,
            order=first_order,
        )
    store.put(second_primary, receipt=second_receipt, order=second_order)
    with pytest.raises(TradeReceiptReviewConflict):
        store.put(
            second_conflict,
            receipt=second_receipt,
            order=second_order,
        )

    assert store.list_conflicts(
        first_primary.review_id,
        receipt=first_receipt,
        order=first_order,
    ) == (first_conflict,)
    assert store.list_conflicts(
        second_primary.review_id,
        receipt=second_receipt,
        order=second_order,
    ) == (second_conflict,)
    assert store.conflict_status(
        first_primary.review_id,
        receipt=first_receipt,
        order=first_order,
    ).retention_complete is True
    assert store.conflict_status(
        second_primary.review_id,
        receipt=second_receipt,
        order=second_order,
    ).retention_complete is True


def test_receipt_review_store_serializes_concurrent_retries(tmp_path):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _receipt_review(context, order, receipt)
    store = TradeReceiptReviewStore(tmp_path / "store")

    def put(_index):
        return store.put(review, receipt=receipt, order=order)

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(put, range(16)))

    assert all(result == review for result in results)
    assert store.get(
        review.review_id,
        receipt=receipt,
        order=order,
    ) == review


def test_receipt_review_store_cross_process_created_flag_is_exactly_once(
    tmp_path,
):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _receipt_review(context, order, receipt)
    root = tmp_path / "store"
    process_context = multiprocessing.get_context("spawn")
    output = process_context.Queue()
    processes = [
        process_context.Process(
            target=_process_put_receipt_review,
            args=(
                root,
                review.to_dict(),
                receipt.to_dict(),
                order.to_dict(),
                output,
            ),
        )
        for _index in range(4)
    ]

    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=30)
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
            pytest.fail("cross-process Receipt Review put did not terminate")
        assert process.exitcode == 0

    results = [output.get(timeout=5) for _process in processes]
    assert all(result[0] == "ok" for result in results), results
    assert {result[1] for result in results} == {review.review_id}
    assert sum(result[2] for result in results) == 1


def test_receipt_review_store_rejects_signed_file_substitution(tmp_path):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    first_receipt = _execution_receipt(context, order)
    first_review = _receipt_review(context, order, first_receipt)
    second_order = _order_for_operation(context, "verify-service")
    second_receipt = _execution_receipt(
        context,
        second_order,
        operation_id="verify-service",
    )
    second_review = _receipt_review(context, second_order, second_receipt)
    store = TradeReceiptReviewStore(tmp_path / "store")
    store.put(first_review, receipt=first_receipt, order=order)
    store._path(first_review.review_id).write_bytes(
        second_review.canonical_bytes
    )

    with pytest.raises(
        trade_rules_api.TradeReceiptReviewStoreError,
        match="primary filename",
    ):
        store.get(
            first_review.review_id,
            receipt=second_receipt,
            order=second_order,
        )


def test_receipt_review_coordinator_anchors_once_and_recovers_retry(tmp_path):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _receipt_review(context, order, receipt)
    store = TradeReceiptReviewStore(tmp_path / "runtime")
    spine = SignedEventLog(
        tmp_path / "runtime" / "review-spine.jsonl",
        context["maker"],
    )
    coordinator = TradeReceiptReviewCoordinator(store, spine)

    first = coordinator.record(review, receipt=receipt, order=order)
    second = coordinator.record(review, receipt=receipt, order=order)

    assert first.store_created is True
    assert first.anchor_created is True
    assert second.store_created is False
    assert second.anchor_created is False
    assert first.event == second.event
    assert first.event.type == EVENT_TRADE_RECEIPT_REVIEWED
    assert validate_receipt_review_audit_binding(
        first.event.payload,
        review=review,
        receipt=receipt,
        order=order,
    ) == receipt_review_audit_payload(
        review,
        receipt=receipt,
        order=order,
    )
    assert spine.verify_chain() == (True, "ok")


def test_receipt_review_coordinator_projects_late_equivocation(tmp_path):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    accepted = _receipt_review(context, order, receipt)
    disputed = _receipt_review(
        context,
        order,
        receipt,
        decision="disputed",
        reason_codes=["result.mismatch"],
        reviewed_at="2026-09-01T00:03:00Z",
        now=_utc("2026-09-01T00:03:00Z"),
    )
    store = TradeReceiptReviewStore(tmp_path / "runtime")
    spine = SignedEventLog(
        tmp_path / "runtime" / "review-spine.jsonl",
        context["maker"],
    )
    coordinator = TradeReceiptReviewCoordinator(store, spine)

    coordinator.record(accepted, receipt=receipt, order=order)
    with pytest.raises(TradeReceiptReviewConflict):
        coordinator.record(disputed, receipt=receipt, order=order)
    with pytest.raises(TradeReceiptReviewConflict):
        coordinator.record(disputed, receipt=receipt, order=order)

    events = spine.verified_snapshot()
    assert [event.type for event in events] == [
        EVENT_TRADE_RECEIPT_REVIEWED,
        EVENT_TRADE_RECEIPT_REVIEW_CONFLICTED,
    ]
    conflict_payload = validate_receipt_review_conflict_audit_payload(
        events[1].payload
    )
    assert conflict_payload["primary_review_digest"] == (
        receipt_review_digest(
            accepted,
            receipt=receipt,
            order=order,
        )
    )
    assert conflict_payload["candidate_review_digest"] == (
        receipt_review_digest(
            disputed,
            receipt=receipt,
            order=order,
        )
    )
    assert conflict_payload["retention_complete"] is True
    assert spine.verify_chain() == (True, "ok")


def test_receipt_review_coordinator_retains_each_distinct_equivocation(
    tmp_path,
):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    accepted = _receipt_review(context, order, receipt)
    disputed = _receipt_review(
        context,
        order,
        receipt,
        decision="disputed",
        reason_codes=["result.mismatch"],
        reviewed_at="2026-09-01T00:03:00Z",
        now=_utc("2026-09-01T00:03:00Z"),
    )
    rejected = _receipt_review(
        context,
        order,
        receipt,
        decision="rejected",
        reason_codes=["result.invalid"],
        reviewed_at="2026-09-01T00:04:00Z",
        now=_utc("2026-09-01T00:04:00Z"),
    )
    runtime = tmp_path / "runtime"
    store = TradeReceiptReviewStore(runtime)
    spine = SignedEventLog(
        runtime / "review-spine.jsonl",
        context["maker"],
    )
    coordinator = TradeReceiptReviewCoordinator(store, spine)

    coordinator.record(accepted, receipt=receipt, order=order)
    for candidate in (disputed, rejected):
        with pytest.raises(TradeReceiptReviewConflict):
            coordinator.record(candidate, receipt=receipt, order=order)

    status = store.conflict_status(
        accepted.review_id,
        receipt=receipt,
        order=order,
    )
    assert len(status.retained_review_digests) == 3
    assert set(store.list_conflicts(
        accepted.review_id,
        receipt=receipt,
        order=order,
    )) == {disputed, rejected}
    events = spine.verified_snapshot()
    assert [event.type for event in events] == [
        EVENT_TRADE_RECEIPT_REVIEWED,
        EVENT_TRADE_RECEIPT_REVIEW_CONFLICTED,
        EVENT_TRADE_RECEIPT_REVIEW_CONFLICTED,
    ]
    assert {
        event.payload["candidate_review_digest"]
        for event in events[1:]
    } == {
        receipt_review_digest(disputed),
        receipt_review_digest(rejected),
    }


def test_receipt_review_projection_failure_leaves_recoverable_cas(
    tmp_path,
    monkeypatch,
):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _receipt_review(context, order, receipt)
    store = TradeReceiptReviewStore(tmp_path / "runtime")
    spine = SignedEventLog(
        tmp_path / "runtime" / "review-spine.jsonl",
        context["maker"],
    )
    coordinator = TradeReceiptReviewCoordinator(store, spine)
    original = spine.append_unique

    def fail_before_append(*args, **kwargs):
        raise OSError("simulated projection outage")

    monkeypatch.setattr(spine, "append_unique", fail_before_append)
    with pytest.raises(TradeReceiptReviewAuditError, match="projection outage"):
        coordinator.record(review, receipt=receipt, order=order)
    assert store.get(
        review.review_id,
        receipt=receipt,
        order=order,
    ) == review
    assert spine.verified_snapshot() == ()

    monkeypatch.setattr(spine, "append_unique", original)
    recovered = coordinator.record(review, receipt=receipt, order=order)
    assert recovered.store_created is False
    assert recovered.anchor_created is True


def test_receipt_review_restarts_and_reconciles_without_resubmission(
    tmp_path,
    monkeypatch,
):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _receipt_review(context, order, receipt)
    runtime = tmp_path / "runtime"
    store = TradeReceiptReviewStore(runtime)
    spine = SignedEventLog(
        runtime / "review-spine.jsonl",
        context["maker"],
    )
    first_process = TradeReceiptReviewCoordinator(store, spine)

    def fail_before_append(*args, **kwargs):
        raise OSError("simulated process crash before Spine append")

    monkeypatch.setattr(spine, "append_unique", fail_before_append)
    with pytest.raises(
        TradeReceiptReviewAuditError,
        match="process crash",
    ):
        first_process.record(review, receipt=receipt, order=order)
    assert spine.verified_snapshot() == ()

    restarted_spine = SignedEventLog(
        runtime / "review-spine.jsonl",
        context["maker"],
    )
    restarted = TradeReceiptReviewCoordinator(store, restarted_spine)
    reconciled = restarted.reconcile()

    assert reconciled.scanned == 1
    assert reconciled.anchored == 1
    assert reconciled.verified_anchored == 0
    assert reconciled.failed == 0
    assert reconciled.has_more is False
    events = restarted_spine.verified_snapshot()
    assert len(events) == 1
    assert events[0].type == EVENT_TRADE_RECEIPT_REVIEWED
    assert validate_receipt_review_audit_binding(
        events[0].payload,
        review=review,
        receipt=receipt,
        order=order,
    )


def test_receipt_review_conflict_reconciles_after_restart(
    tmp_path,
    monkeypatch,
):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    accepted = _receipt_review(context, order, receipt)
    disputed = _receipt_review(
        context,
        order,
        receipt,
        decision="disputed",
        reason_codes=["result.mismatch"],
        reviewed_at="2026-09-01T00:03:00Z",
        now=_utc("2026-09-01T00:03:00Z"),
    )
    runtime = tmp_path / "runtime"
    store = TradeReceiptReviewStore(runtime)
    spine = SignedEventLog(
        runtime / "review-spine.jsonl",
        context["maker"],
    )
    first_process = TradeReceiptReviewCoordinator(store, spine)
    first_process.record(accepted, receipt=receipt, order=order)
    original_append = spine.append_unique

    def fail_conflict_append(event_type, *args, **kwargs):
        if event_type == EVENT_TRADE_RECEIPT_REVIEW_CONFLICTED:
            raise OSError("simulated conflict projection crash")
        return original_append(event_type, *args, **kwargs)

    monkeypatch.setattr(spine, "append_unique", fail_conflict_append)
    with pytest.raises(
        TradeReceiptReviewAuditError,
        match="conflict projection crash",
    ):
        first_process.record(disputed, receipt=receipt, order=order)

    restarted_spine = SignedEventLog(
        runtime / "review-spine.jsonl",
        context["maker"],
    )
    restarted = TradeReceiptReviewCoordinator(store, restarted_spine)
    reconciled = restarted.reconcile()

    assert reconciled.scanned == 2
    assert reconciled.anchored == 1
    assert reconciled.verified_anchored == 1
    assert reconciled.conflicted == 1
    assert reconciled.failed == 0
    assert [event.type for event in restarted_spine.verified_snapshot()] == [
        EVENT_TRADE_RECEIPT_REVIEWED,
        EVENT_TRADE_RECEIPT_REVIEW_CONFLICTED,
    ]


def test_receipt_review_outbox_rejects_artifact_tamper(tmp_path):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _receipt_review(context, order, receipt)
    outbox = trade_rules_api.TradeReceiptReviewOutbox(tmp_path / "runtime")
    record, _created = outbox.prepare(
        review,
        receipt=receipt,
        order=order,
        now_ms=1,
    )
    path = outbox._path(record.review_digest)
    document = json.loads(path.read_text(encoding="utf-8"))
    replacement = "A" if document["review_b64u"][-1] != "A" else "B"
    document["review_b64u"] = document["review_b64u"][:-1] + replacement
    path.write_bytes(canonical_json(document))

    with pytest.raises(
        trade_rules_api.TradeReceiptReviewOutboxError,
        match="invalid signed artifacts|encoding",
    ):
        outbox.pending()


def test_receipt_review_outbox_rejects_status_event_mismatch(tmp_path):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _receipt_review(context, order, receipt)
    outbox = trade_rules_api.TradeReceiptReviewOutbox(tmp_path / "runtime")
    record, _created = outbox.prepare(
        review,
        receipt=receipt,
        order=order,
        now_ms=1,
    )
    path = outbox._path(record.review_digest)
    document = json.loads(path.read_text(encoding="utf-8"))
    document["status"] = "reviewed"
    document["event_type"] = EVENT_TRADE_RECEIPT_REVIEW_CONFLICTED
    path.write_bytes(canonical_json(document))

    with pytest.raises(
        trade_rules_api.TradeReceiptReviewOutboxError,
        match="status does not match",
    ):
        outbox.pending()


def test_receipt_review_store_failure_is_durable_and_retryable(tmp_path):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _receipt_review(context, order, receipt)
    runtime = tmp_path / "runtime"
    constrained = TradeReceiptReviewStore(runtime, max_bytes=1)
    spine = SignedEventLog(
        runtime / "review-spine.jsonl",
        context["maker"],
    )
    coordinator = TradeReceiptReviewCoordinator(constrained, spine)

    with pytest.raises(trade_rules_api.TradeReceiptReviewStoreCapacity):
        coordinator.record(review, receipt=receipt, order=order)
    records, _has_more = coordinator.audit_outbox.pending()
    assert len(records) == 1
    assert records[0].status == "prepared"
    assert records[0].attempts == 1
    assert records[0].last_error == "receipt-review-store-failed"

    recovered = TradeReceiptReviewCoordinator(
        TradeReceiptReviewStore(runtime),
        spine,
    ).reconcile()
    assert recovered.anchored == 1
    assert recovered.failed == 0


def test_receipt_review_reconcile_detects_anchored_spine_rollback(tmp_path):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _receipt_review(context, order, receipt)
    runtime = tmp_path / "runtime"
    store = TradeReceiptReviewStore(runtime)
    spine_path = runtime / "review-spine.jsonl"
    spine = SignedEventLog(spine_path, context["maker"])
    TradeReceiptReviewCoordinator(store, spine).record(
        review,
        receipt=receipt,
        order=order,
    )
    spine_path.write_bytes(b"")

    restarted = TradeReceiptReviewCoordinator(
        store,
        SignedEventLog(spine_path, context["maker"]),
    )
    result = restarted.reconcile()

    assert result.scanned == 1
    assert result.anchored == 0
    assert result.failed == 1


def test_receipt_review_projection_recovers_commit_then_raise(
    tmp_path,
    monkeypatch,
):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _receipt_review(context, order, receipt)
    store = TradeReceiptReviewStore(tmp_path / "runtime")
    spine = SignedEventLog(
        tmp_path / "runtime" / "review-spine.jsonl",
        context["maker"],
    )
    coordinator = TradeReceiptReviewCoordinator(store, spine)
    original = spine.append_unique

    def append_then_raise(*args, **kwargs):
        original(*args, **kwargs)
        raise OSError("simulated lost acknowledgement")

    monkeypatch.setattr(spine, "append_unique", append_then_raise)
    with pytest.raises(
        TradeReceiptReviewAuditError,
        match="lost acknowledgement",
    ):
        coordinator.record(review, receipt=receipt, order=order)
    assert len(spine.verified_snapshot()) == 1

    monkeypatch.setattr(spine, "append_unique", original)
    recovered = coordinator.record(review, receipt=receipt, order=order)
    assert recovered.store_created is False
    assert recovered.anchor_created is False
    assert len(spine.verified_snapshot()) == 1


def test_receipt_review_capacity_failure_leaves_conflict_marker(tmp_path):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    accepted = _receipt_review(context, order, receipt)
    rejected = _receipt_review(
        context,
        order,
        receipt,
        decision="rejected",
        reason_codes=["result.invalid"],
        reviewed_at="2026-09-01T00:03:00Z",
        now=_utc("2026-09-01T00:03:00Z"),
    )
    store = TradeReceiptReviewStore(
        tmp_path / "store",
        max_reviews=2,
    )
    store.put(accepted, receipt=receipt, order=order)

    with pytest.raises(
        trade_rules_api.TradeReceiptReviewStoreCapacity,
        match="max_reviews",
    ):
        store.put(rejected, receipt=receipt, order=order)
    status = store.conflict_status(
        accepted.review_id,
        receipt=receipt,
        order=order,
    )
    assert status.has_conflict is True
    assert status.retention_complete is False
    assert status.marker_candidate_digest == receipt_review_digest(rejected)
    with pytest.raises(TradeReceiptReviewConflict):
        store.get(accepted.review_id, receipt=receipt, order=order)


def test_receipt_review_marker_only_conflict_repairs_after_capacity_increase(
    tmp_path,
):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    accepted = _receipt_review(context, order, receipt)
    rejected = _receipt_review(
        context,
        order,
        receipt,
        decision="rejected",
        reason_codes=["result.invalid"],
        reviewed_at="2026-09-01T00:03:00Z",
        now=_utc("2026-09-01T00:03:00Z"),
    )
    root = tmp_path / "store"
    constrained = TradeReceiptReviewStore(root, max_reviews=2)
    constrained.put(accepted, receipt=receipt, order=order)
    with pytest.raises(trade_rules_api.TradeReceiptReviewStoreCapacity):
        constrained.put(rejected, receipt=receipt, order=order)

    repaired = TradeReceiptReviewStore(root, max_reviews=3)
    with pytest.raises(TradeReceiptReviewConflict):
        repaired.put(rejected, receipt=receipt, order=order)
    status = repaired.conflict_status(
        accepted.review_id,
        receipt=receipt,
        order=order,
    )
    assert status.retention_complete is True
    assert status.marker_candidate_digest in status.retained_review_digests
    assert repaired.list_conflicts(
        accepted.review_id,
        receipt=receipt,
        order=order,
    ) == (rejected,)


def test_receipt_review_primary_digest_marker_is_not_complete(tmp_path):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    accepted = _receipt_review(context, order, receipt)
    store = TradeReceiptReviewStore(tmp_path / "store")
    store.put(accepted, receipt=receipt, order=order)
    primary_digest = receipt_review_digest(
        accepted,
        receipt=receipt,
        order=order,
    )
    store._atomic_write(
        store._marker_path(accepted.review_id),
        canonical_json(
            {
                "candidate_digest": primary_digest,
                "review_id": accepted.review_id,
            }
        ),
    )

    status = store.conflict_status(
        accepted.review_id,
        receipt=receipt,
        order=order,
    )
    assert status.has_conflict is True
    assert status.primary_review_digest == primary_digest
    assert status.marker_candidate_digest == primary_digest
    assert status.retention_complete is False
