"""Deterministic conformance vector for bilateral Trade Agreement v1."""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any

from nth_dao.identity import AgentID, AgentIdentity
from nth_dao.trade_rules.agreement import (
    _sign_acceptance_body,
    _sign_proposal_body,
    acceptance_digest,
    create_trade_acceptance,
    create_trade_proposal,
    proposal_digest,
)
from nth_dao.trade_rules.agreement_order import (
    ORDER_ID_PREFIX,
    create_trade_order,
    trade_order_digest,
)
from nth_dao.trade_rules.agreement_transport import (
    create_trade_proposal_intake_receipt,
    create_trade_proposal_delivery,
    trade_proposal_delivery_digest,
    trade_proposal_intake_receipt_digest,
)
from nth_dao.trade_rules.execution_receipt import (
    EXECUTION_TERMS_KEY,
    _create_trade_execution_receipt,
    execution_receipt_digest,
)
from nth_dao.trade_rules.execution_audit import (
    EVENT_TRADE_EXECUTION_RECORDED,
    execution_audit_payload,
)
from nth_dao.trade_rules.receipt_review import (
    create_trade_receipt_review,
    receipt_review_digest,
)
from nth_dao.trade_rules.receipt_review_audit import (
    EVENT_TRADE_RECEIPT_REVIEW_CONFLICTED,
    EVENT_TRADE_RECEIPT_REVIEWED,
    receipt_review_conflict_audit_payload,
    receipt_review_audit_payload,
)
from nth_dao.trade_rules.receipt_review_store import (
    TradeReceiptReviewConflictStatus,
)
from nth_dao.trade_rules.execution_adapter import (
    TradeExecutionAdapterPolicy,
    build_execution_adapter,
)
from nth_dao.trade_rules.execution_content import (
    JsonSchema202012Validator,
    MappingTradeExecutionContentResolver,
)
from nth_dao.trade_rules.canonical import trade_canonical_json
from nth_dao.trade_rules.manifest import (
    manifest_body,
    sign_manifest,
)
from nth_dao.trade_rules.negotiation import (
    RuleResolutionPolicy,
    resolve_canonical_offer_rules,
)
from nth_dao.trade_rules.order_audit import (
    EVENT_TRADE_ORDER_ACCEPTED,
    order_audit_payload,
)
from nth_dao.trade_rules.order_transport import (
    create_trade_order_delivery,
    create_trade_order_intake_receipt,
    trade_order_delivery_digest,
    trade_order_intake_receipt_digest,
)
from nth_dao.trade_rules.order_dispatch import (
    EVENT_TRADE_ORDER_INTAKE_ACKNOWLEDGED,
    TradeOrderAcknowledgement,
    acknowledgement_audit_payload,
)
from nth_dao.trade_rules.offer import offer_body, sign_offer
from nth_dao.trade_rules.package_store import RulePackageStore
from nth_dao.trade_rules.store import OfferStore

VECTORS_PATH = Path(__file__).with_name("vectors") / "agreement-v1.json"
PROPOSAL_SCHEMA_PATH = (
    Path(__file__).with_name("schemas") / "trade-proposal.schema.json"
)
PROPOSAL_DELIVERY_SCHEMA_PATH = (
    Path(__file__).with_name("schemas")
    / "trade-proposal-delivery.schema.json"
)
PROPOSAL_INTAKE_RECEIPT_SCHEMA_PATH = (
    Path(__file__).with_name("schemas")
    / "trade-proposal-intake-receipt.schema.json"
)
ACCEPTANCE_SCHEMA_PATH = (
    Path(__file__).with_name("schemas") / "trade-acceptance.schema.json"
)
ORDER_SCHEMA_PATH = (
    Path(__file__).with_name("schemas") / "trade-order.schema.json"
)
ORDER_DELIVERY_SCHEMA_PATH = (
    Path(__file__).with_name("schemas") / "trade-order-delivery.schema.json"
)
ORDER_INTAKE_RECEIPT_SCHEMA_PATH = (
    Path(__file__).with_name("schemas")
    / "trade-order-intake-receipt.schema.json"
)
ORDER_AUDIT_SCHEMA_PATH = (
    Path(__file__).with_name("schemas")
    / "trade-order-audit-payload.schema.json"
)
ORDER_INTAKE_ACKNOWLEDGEMENT_AUDIT_SCHEMA_PATH = (
    Path(__file__).with_name("schemas")
    / "trade-order-intake-acknowledgement-audit-payload.schema.json"
)
EXECUTION_RECEIPT_SCHEMA_PATH = (
    Path(__file__).with_name("schemas")
    / "trade-execution-receipt.schema.json"
)
EXECUTION_AUDIT_SCHEMA_PATH = (
    Path(__file__).with_name("schemas")
    / "trade-execution-audit-payload.schema.json"
)
EXECUTION_ADAPTER_SCHEMA_PATH = (
    Path(__file__).with_name("schemas")
    / "trade-execution-adapter.schema.json"
)
EXECUTION_ADAPTER_POLICY_SCHEMA_PATH = (
    Path(__file__).with_name("schemas")
    / "trade-execution-adapter-policy.schema.json"
)
RECEIPT_REVIEW_SCHEMA_PATH = (
    Path(__file__).with_name("schemas")
    / "trade-receipt-review.schema.json"
)
RECEIPT_REVIEW_AUDIT_SCHEMA_PATH = (
    Path(__file__).with_name("schemas")
    / "trade-receipt-review-audit-payload.schema.json"
)
RECEIPT_REVIEW_CONFLICT_AUDIT_SCHEMA_PATH = (
    Path(__file__).with_name("schemas")
    / "trade-receipt-review-conflict-audit-payload.schema.json"
)


class _AdapterResolver:
    def __init__(self, adapter, artifact):
        self._adapter = adapter
        self._artifact = artifact

    def load(self, digest):
        return self._adapter if digest == self._adapter.digest else None

    def load_artifact(self, digest):
        return (
            self._artifact
            if digest == self._adapter.to_dict()["artifact_digest"]
            else None
        )


def _identity(label: bytes) -> AgentIdentity:
    try:
        from nacl.signing import SigningKey
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "regenerating Trade Agreement vectors requires PyNaCl"
        ) from exc
    signing_key = SigningKey(hashlib.sha256(label).digest())
    verify_key = signing_key.verify_key.encode()
    return AgentIdentity(
        agent_id=AgentID.from_pubkey(verify_key.hex()),
        label="public-conformance-only",
        _signing_key=signing_key.encode(),
        _verify_key=verify_key,
    )


def generate_vectors() -> dict[str, Any]:
    maker = _identity(b"NTH Trade Agreement v1 maker public seed")
    taker = _identity(b"NTH Trade Agreement v1 taker public seed")
    rule_publisher = _identity(
        b"NTH Trade Agreement v1 rule publisher public seed"
    )
    resource = b'{"rule":"delivery"}'
    resource_digest = "sha256:" + hashlib.sha256(resource).hexdigest()
    input_schema = trade_canonical_json({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "required": ["order"],
        "properties": {"order": {"const": "deliver"}},
    })
    output_schema = trade_canonical_json({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "required": ["status"],
        "properties": {"status": {"const": "completed"}},
    })
    input_schema_digest = (
        "sha256:" + hashlib.sha256(input_schema).hexdigest()
    )
    output_schema_digest = (
        "sha256:" + hashlib.sha256(output_schema).hexdigest()
    )
    manifest = sign_manifest(
        rule_publisher,
        manifest_body(
            rule_id="org.nthdao.reference.delivery",
            version="1.0.0",
            publisher_did=rule_publisher.as_did(),
            summary="Public bilateral agreement conformance rule.",
            applies_to=["service"],
            families=["fulfillment"],
            hook_contracts=[{
                "name": "fulfillment.deliver",
                "version": "1",
                "input_schema_digest": input_schema_digest,
                "output_schema_digest": output_schema_digest,
                "side_effect": "none",
                "permissions": [],
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
        ),
        created="2026-07-01T00:00:00Z",
    )
    with tempfile.TemporaryDirectory() as directory:
        package_store = RulePackageStore(directory)
        offer_store = OfferStore(directory)
        package_digest = package_store.install(
            manifest,
            {
                resource_digest: resource,
                input_schema_digest: input_schema,
                output_schema_digest: output_schema,
            },
        ).digest
        offer = sign_offer(
            maker,
            offer_body(
                offer_id="org.nthdao.reference/agreement",
                publisher_did=maker.as_did(),
                title="Public agreement conformance service",
                summary="Never use these deterministic identities for trust.",
                provides=[{
                    "leg_id": "service",
                    "resource_type": "service",
                    "resource_id": "urn:nth:conformance-service",
                    "quantity": "1",
                    "unit": "unit",
                    "descriptor_digest": (
                        "sha256:"
                        + hashlib.sha256(b"agreement descriptor").hexdigest()
                    ),
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
        taker_resolution = resolve_canonical_offer_rules(
            maker.as_did(),
            offer.offer_id,
            offer_store,
            package_store,
            RuleResolutionPolicy(
                accepted_publishers={rule_publisher.as_did()}
            ),
            at=_utc("2026-08-01T00:00:00Z"),
        )
        maker_resolution = resolve_canonical_offer_rules(
            maker.as_did(),
            offer.offer_id,
            offer_store,
            package_store,
            RuleResolutionPolicy(
                accepted_package_digests={package_digest}
            ),
            at=_utc("2026-08-01T01:00:00Z"),
        )
        proposal = create_trade_proposal(
            taker,
            resolution=taker_resolution,
            offer=offer,
            offer_resolver=offer_store,
            terms={
                "requested_quantity": "1",
                EXECUTION_TERMS_KEY: {
                    "grants": [{
                        "operation_id": "deliver-service",
                        "rule_id": manifest.rule_id,
                        "package_digest": package_digest,
                        "hook_name": "fulfillment.deliver",
                        "hook_version": "1",
                        "executor_role": "maker",
                    }]
                },
            },
            created_at="2026-08-01T00:00:00Z",
            not_after="2026-08-02T00:00:00Z",
            now=_utc("2026-08-01T00:00:00Z"),
        )
        proposal_delivery = create_trade_proposal_delivery(
            taker,
            proposal=proposal,
            created_at="2026-08-01T00:00:00Z",
            not_after="2026-08-01T00:10:00Z",
            nonce="0123456789abcdef0123456789abcdef",
            now=_utc("2026-08-01T00:00:00Z"),
        )
        proposal_intake_receipt = create_trade_proposal_intake_receipt(
            maker,
            delivery=proposal_delivery,
            received_at="2026-08-01T00:00:01Z",
        )
        acceptance = create_trade_acceptance(
            maker,
            proposal=proposal,
            resolution=maker_resolution,
            offer=offer,
            offer_resolver=offer_store,
            created_at="2026-08-01T01:00:00Z",
            now=_utc("2026-08-01T01:00:00Z"),
        )
        order = create_trade_order(
            offer=offer,
            proposal=proposal,
            acceptance=acceptance,
        )
        order_delivery = create_trade_order_delivery(
            maker,
            order=order,
            created_at="2026-08-01T01:00:01Z",
            not_after="2026-08-01T01:10:01Z",
            nonce="abcdef0123456789abcdef0123456789",
            now=_utc("2026-08-01T01:00:01Z"),
        )
        order_intake_receipt = create_trade_order_intake_receipt(
            taker,
            delivery=order_delivery,
            received_at="2026-08-01T01:05:00Z",
            audit_event_id="1" * 64,
        )
        order_intake_acknowledgement = TradeOrderAcknowledgement(
            order_digest=trade_order_digest(order),
            target_url="https://taker.example",
            delivery=order_delivery,
            receipt=order_intake_receipt,
            remote_event_id="1" * 64,
            observed_at_ms=1_775_179_500_000,
        )
        adapter_artifact = b"public declarative adapter artifact v1"
        adapter = build_execution_adapter(
            adapter_id="org.nthdao.reference/declarative",
            adapter_version="1.0.0",
            artifact_digest=(
                "sha256:"
                + hashlib.sha256(
                    adapter_artifact
                ).hexdigest()
            ),
            execution_modes=["declarative"],
            hooks=[{
                "rule_id": manifest.rule_id,
                "hook_name": "fulfillment.deliver",
                "hook_version": "1",
            }],
        )
        execution_result = b'{"status":"completed"}'
        execution_input = b'{"order":"deliver"}'
        verifier_policy = RuleResolutionPolicy(
            accepted_package_digests={package_digest}
        )
        adapter_policy = TradeExecutionAdapterPolicy(
            accepted_adapter_digests={adapter.digest},
        )
        execution_content = {
            (
                "sha256:" + hashlib.sha256(execution_input).hexdigest()
            ): execution_input,
            (
                "sha256:" + hashlib.sha256(execution_result).hexdigest()
            ): execution_result,
        }
        execution_receipt = _create_trade_execution_receipt(
            maker,
            order=order,
            package_resolver=package_store,
            executor_policy=verifier_policy,
            adapter_resolver=_AdapterResolver(adapter, adapter_artifact),
            adapter_policy=adapter_policy,
            content_resolver=MappingTradeExecutionContentResolver(
                execution_content
            ),
            schema_validator=JsonSchema202012Validator(),
            executor_role="maker",
            adapter_id=adapter.to_dict()["adapter_id"],
            adapter_version=adapter.to_dict()["adapter_version"],
            adapter_digest=adapter.digest,
            execution_mode="declarative",
            operation_id="deliver-service",
            operation_input={
                "media_type": "application/json",
                "digest": (
                    "sha256:"
                    + hashlib.sha256(execution_input).hexdigest()
                ),
                "size_bytes": len(execution_input),
            },
            outcome="succeeded",
            result={
                "media_type": "application/json",
                "digest": (
                    "sha256:" + hashlib.sha256(execution_result).hexdigest()
                ),
                "size_bytes": len(execution_result),
            },
            evidence=[],
            started_at="2026-08-01T02:00:00Z",
            completed_at="2026-08-01T02:01:00Z",
            now=_utc("2026-08-01T02:01:00Z"),
        )
        receipt_review = create_trade_receipt_review(
            taker,
            receipt=execution_receipt,
            order=order,
            package_resolver=package_store,
            verifier_policy=verifier_policy,
            adapter_resolver=_AdapterResolver(adapter, adapter_artifact),
            adapter_policy=adapter_policy,
            content_resolver=MappingTradeExecutionContentResolver(
                execution_content
            ),
            schema_validator=JsonSchema202012Validator(),
            decision="accepted",
            reviewed_at="2026-08-01T02:02:00Z",
            now=_utc("2026-08-01T02:02:00Z"),
        )
        conflicting_receipt_review = create_trade_receipt_review(
            taker,
            receipt=execution_receipt,
            order=order,
            package_resolver=package_store,
            verifier_policy=verifier_policy,
            adapter_resolver=_AdapterResolver(adapter, adapter_artifact),
            adapter_policy=adapter_policy,
            content_resolver=MappingTradeExecutionContentResolver(
                execution_content
            ),
            schema_validator=JsonSchema202012Validator(),
            decision="disputed",
            reason_codes=["result.mismatch"],
            reviewed_at="2026-08-01T02:03:00Z",
            now=_utc("2026-08-01T02:03:00Z"),
        )
        omitted_rules_body = proposal.to_dict()
        omitted_rules_body.pop("proof")
        omitted_rules_body["rule_bindings"] = []
        omitted_rules_proposal = _sign_proposal_body(
            taker,
            omitted_rules_body,
        )
        omitted_acceptance_body = acceptance.to_dict()
        omitted_acceptance_body.pop("proof")
        omitted_acceptance_body["proposal_digest"] = proposal_digest(
            omitted_rules_proposal
        )
        omitted_acceptance_body["rule_bindings"] = []
        omitted_rules_acceptance = _sign_acceptance_body(
            maker,
            omitted_acceptance_body,
        )
        omitted_order = order.to_dict()
        omitted_order["proposal_digest"] = proposal_digest(
            omitted_rules_proposal
        )
        omitted_order["acceptance_digest"] = acceptance_digest(
            omitted_rules_acceptance
        )
        omitted_order["order_id"] = (
            ORDER_ID_PREFIX
            + omitted_order["proposal_digest"].removeprefix("sha256:")
        )
        omitted_order["rule_bindings"] = []
        omitted_order["snapshot"]["proposal"] = (
            omitted_rules_proposal.to_dict()
        )
        omitted_order["snapshot"]["acceptance"] = (
            omitted_rules_acceptance.to_dict()
        )

        proposal_unknown_field = proposal.to_dict()
        proposal_unknown_field["unexpected"] = True
        proposal_delivery_tamper = proposal_delivery.to_dict()
        proposal_delivery_tamper["nonce"] = (
            "fedcba9876543210fedcba9876543210"
        )
        proposal_delivery_tamper["delivery_id"] = (
            "nth:trade:proposal-delivery:"
            + proposal_delivery_tamper["nonce"]
        )
        order_delivery_tamper = order_delivery.to_dict()
        order_delivery_tamper["not_after"] = "2026-08-01T01:09:01Z"
        order_delivery_nested_tamper = order_delivery.to_dict()
        order_delivery_nested_tamper["order"]["snapshot"]["proposal"][
            "terms"
        ]["requested_quantity"] = "999"
        order_intake_receipt_tamper = order_intake_receipt.to_dict()
        order_intake_receipt_tamper["audit_event_id"] = "2" * 64
        proposal_intake_tamper = proposal_intake_receipt.to_dict()
        proposal_intake_tamper["delivery_digest"] = "sha256:" + ("0" * 64)
        acceptance_policy_mismatch = acceptance.to_dict()
        acceptance_policy_mismatch["maker_policy_digest"] = (
            "sha256:" + ("0" * 64)
        )
        order_nested_tamper = copy.deepcopy(order.to_dict())
        order_nested_tamper["snapshot"]["proposal"]["terms"][
            "requested_quantity"
        ] = "2"
        audit_payload = order_audit_payload(order)
        audit_bad_binding = copy.deepcopy(audit_payload)
        audit_bad_binding["proposal_digest"] = "sha256:" + ("0" * 64)
        audit_unknown_field = copy.deepcopy(audit_payload)
        audit_unknown_field["unexpected"] = True
        execution_audit = execution_audit_payload(
            execution_receipt,
            order=order,
        )
        execution_audit_bad_order = copy.deepcopy(execution_audit)
        execution_audit_bad_order["order_id"] = (
            ORDER_ID_PREFIX + ("0" * 64)
        )
        execution_audit_unknown_field = copy.deepcopy(execution_audit)
        execution_audit_unknown_field["unexpected"] = True
        execution_result_tamper = execution_receipt.to_dict()
        execution_result_tamper["result"]["digest"] = (
            "sha256:" + ("0" * 64)
        )
        execution_unknown_field = execution_receipt.to_dict()
        execution_unknown_field["unexpected"] = True
        execution_operation_tamper = execution_receipt.to_dict()
        execution_operation_tamper["operation"]["hook_name"] = (
            "fulfillment.cancel"
        )
        adapter_unknown_field = adapter.to_dict()
        adapter_unknown_field["unexpected"] = True
        receipt_review_tamper = receipt_review.to_dict()
        receipt_review_tamper["decision"] = "disputed"
        receipt_review_tamper["reason_codes"] = ["result.mismatch"]
        receipt_review_audit = receipt_review_audit_payload(
            receipt_review,
            receipt=execution_receipt,
            order=order,
        )
        primary_review_digest = receipt_review_digest(receipt_review)
        conflicting_review_digest = receipt_review_digest(
            conflicting_receipt_review
        )
        receipt_review_conflict_audit = (
            receipt_review_conflict_audit_payload(
                conflicting_receipt_review,
                receipt=execution_receipt,
                order=order,
                status=TradeReceiptReviewConflictStatus(
                    review_id=receipt_review.review_id,
                    has_conflict=True,
                    primary_review_digest=primary_review_digest,
                    marker_candidate_digest=conflicting_review_digest,
                    retained_review_digests=(
                        primary_review_digest,
                        conflicting_review_digest,
                    ),
                    retention_complete=True,
                ),
            )
        )
        receipt_review_audit_tamper = copy.deepcopy(receipt_review_audit)
        receipt_review_audit_tamper["receipt_digest"] = (
            "sha256:" + ("0" * 64)
        )
    return {
        "format": "nth-trade-agreement-conformance-v1",
        "schema_version": 1,
        "warning": "Deterministic public test keys; never trust or reuse them.",
        "proposal": proposal.to_dict(),
        "proposal_digest": proposal_digest(proposal),
        "proposal_delivery": proposal_delivery.to_dict(),
        "proposal_delivery_digest": trade_proposal_delivery_digest(
            proposal_delivery
        ),
        "proposal_intake_receipt": proposal_intake_receipt.to_dict(),
        "proposal_intake_receipt_digest": (
            trade_proposal_intake_receipt_digest(proposal_intake_receipt)
        ),
        "proposal_delivery_verification_cases": [
            {
                "case": "valid-recipient-and-window",
                "recipient_did": maker.as_did(),
                "at": "2026-08-01T00:00:01Z",
                "max_ttl_seconds": 600,
                "clock_skew_seconds": 300,
                "expected_valid": True,
            },
            {
                "case": "wrong-recipient",
                "recipient_did": taker.as_did(),
                "at": "2026-08-01T00:00:01Z",
                "max_ttl_seconds": 600,
                "clock_skew_seconds": 300,
                "expected_valid": False,
            },
            {
                "case": "expired-at-exclusive-boundary",
                "recipient_did": maker.as_did(),
                "at": "2026-08-01T00:10:00Z",
                "max_ttl_seconds": 600,
                "clock_skew_seconds": 300,
                "expected_valid": False,
            },
            {
                "case": "created-too-far-in-future",
                "recipient_did": maker.as_did(),
                "at": "2026-07-31T23:54:59Z",
                "max_ttl_seconds": 600,
                "clock_skew_seconds": 300,
                "expected_valid": False,
            },
        ],
        "acceptance": acceptance.to_dict(),
        "acceptance_digest": acceptance_digest(acceptance),
        "order": order.to_dict(),
        "order_digest": trade_order_digest(order),
        "order_delivery": order_delivery.to_dict(),
        "order_delivery_digest": trade_order_delivery_digest(order_delivery),
        "order_intake_receipt": order_intake_receipt.to_dict(),
        "order_intake_receipt_digest": trade_order_intake_receipt_digest(
            order_intake_receipt
        ),
        "order_delivery_verification_cases": [
            {
                "case": "valid-recipient-and-window",
                "recipient_did": taker.as_did(),
                "at": "2026-08-01T01:05:00Z",
                "max_ttl_seconds": 600,
                "clock_skew_seconds": 300,
                "expected_valid": True,
            },
            {
                "case": "wrong-recipient",
                "recipient_did": maker.as_did(),
                "at": "2026-08-01T01:05:00Z",
                "max_ttl_seconds": 600,
                "clock_skew_seconds": 300,
                "expected_valid": False,
            },
            {
                "case": "expired-after-clock-skew",
                "recipient_did": taker.as_did(),
                "at": "2026-08-01T01:15:02Z",
                "max_ttl_seconds": 600,
                "clock_skew_seconds": 300,
                "expected_valid": False,
            },
        ],
        "execution_adapter": adapter.to_dict(),
        "execution_adapter_digest": adapter.digest,
        "execution_adapter_artifact_hex": adapter_artifact.hex(),
        "rule_package": {
            "digest": package_digest,
            "manifest": manifest.to_dict(),
            "resources": [
                {
                    "digest": digest,
                    "bytes_hex": payload.hex(),
                }
                for digest, payload in sorted({
                    resource_digest: resource,
                    input_schema_digest: input_schema,
                    output_schema_digest: output_schema,
                }.items())
            ],
        },
        "verifier_policy": json.loads(verifier_policy.canonical_bytes),
        "adapter_policy": adapter_policy.to_dict(),
        "execution_content": [
            {
                "digest": digest,
                "bytes_hex": payload.hex(),
            }
            for digest, payload in sorted(execution_content.items())
        ],
        "execution_receipt": execution_receipt.to_dict(),
        "execution_receipt_digest": execution_receipt_digest(
            execution_receipt
        ),
        "receipt_review": receipt_review.to_dict(),
        "receipt_review_digest": receipt_review_digest(receipt_review),
        "expected_execution_readiness": (
            execution_receipt.to_dict()["readiness"]
        ),
        "order_audit": {
            "event_type": EVENT_TRADE_ORDER_ACCEPTED,
            "payload": audit_payload,
        },
        "order_intake_acknowledgement_audit": {
            "event_type": EVENT_TRADE_ORDER_INTAKE_ACKNOWLEDGED,
            "payload": acknowledgement_audit_payload(
                order_intake_acknowledgement
            ),
        },
        "execution_audit": {
            "event_type": EVENT_TRADE_EXECUTION_RECORDED,
            "payload": execution_audit,
        },
        "receipt_review_audit": {
            "event_type": EVENT_TRADE_RECEIPT_REVIEWED,
            "payload": receipt_review_audit,
        },
        "receipt_review_conflict_audit": {
            "event_type": EVENT_TRADE_RECEIPT_REVIEW_CONFLICTED,
            "payload": receipt_review_conflict_audit,
        },
        "negative_cases": [
            {
                "case": "signed-order-omits-required-offer-root-rule",
                "target": "order",
                "expected_valid": False,
                "document": omitted_order,
            },
            {
                "case": "proposal-unknown-field",
                "target": "proposal",
                "expected_valid": False,
                "document": proposal_unknown_field,
            },
            {
                "case": "proposal-delivery-signed-nonce-tamper",
                "target": "proposal_delivery",
                "expected_valid": False,
                "document": proposal_delivery_tamper,
            },
            {
                "case": "proposal-intake-receipt-delivery-tamper",
                "target": "proposal_intake_receipt",
                "expected_valid": False,
                "document": proposal_intake_tamper,
            },
            {
                "case": "acceptance-policy-digest-mismatch",
                "target": "acceptance",
                "expected_valid": False,
                "document": acceptance_policy_mismatch,
            },
            {
                "case": "order-nested-proposal-tamper",
                "target": "order",
                "expected_valid": False,
                "document": order_nested_tamper,
            },
            {
                "case": "order-delivery-signed-window-tamper",
                "target": "order_delivery",
                "expected_valid": False,
                "document": order_delivery_tamper,
            },
            {
                "case": "order-delivery-nested-order-tamper",
                "target": "order_delivery",
                "expected_valid": False,
                "document": order_delivery_nested_tamper,
            },
            {
                "case": "order-intake-receipt-audit-event-tamper",
                "target": "order_intake_receipt",
                "expected_valid": False,
                "document": order_intake_receipt_tamper,
            },
            {
                "case": "order-audit-id-proposal-binding-mismatch",
                "target": "order_audit_payload",
                "expected_valid": False,
                "document": audit_bad_binding,
            },
            {
                "case": "order-audit-unknown-field",
                "target": "order_audit_payload",
                "expected_valid": False,
                "document": audit_unknown_field,
            },
            {
                "case": "execution-receipt-result-tamper",
                "target": "execution_receipt",
                "expected_valid": False,
                "document": execution_result_tamper,
            },
            {
                "case": "execution-audit-order-binding-mismatch",
                "target": "execution_audit_binding",
                "expected_valid": False,
                "document": execution_audit_bad_order,
            },
            {
                "case": "execution-audit-unknown-field",
                "target": "execution_audit_payload",
                "expected_valid": False,
                "document": execution_audit_unknown_field,
            },
            {
                "case": "execution-receipt-unknown-field",
                "target": "execution_receipt",
                "expected_valid": False,
                "document": execution_unknown_field,
            },
            {
                "case": "execution-receipt-operation-tamper",
                "target": "execution_receipt",
                "expected_valid": False,
                "document": execution_operation_tamper,
            },
            {
                "case": "execution-adapter-unknown-field",
                "target": "execution_adapter",
                "expected_valid": False,
                "document": adapter_unknown_field,
            },
            {
                "case": "receipt-review-signed-decision-tamper",
                "target": "receipt_review",
                "expected_valid": False,
                "document": receipt_review_tamper,
            },
            {
                "case": "receipt-review-audit-binding-tamper",
                "target": "receipt_review_audit_binding",
                "expected_valid": False,
                "document": receipt_review_audit_tamper,
            },
        ],
    }


def _utc(value: str):
    from datetime import datetime

    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def write_vectors(path: str | Path = VECTORS_PATH) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(
            generate_vectors(),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    return destination


__all__ = [
    "ACCEPTANCE_SCHEMA_PATH",
    "EXECUTION_RECEIPT_SCHEMA_PATH",
    "EXECUTION_AUDIT_SCHEMA_PATH",
    "EXECUTION_ADAPTER_SCHEMA_PATH",
    "EXECUTION_ADAPTER_POLICY_SCHEMA_PATH",
    "ORDER_SCHEMA_PATH",
    "ORDER_DELIVERY_SCHEMA_PATH",
    "ORDER_INTAKE_RECEIPT_SCHEMA_PATH",
    "ORDER_INTAKE_ACKNOWLEDGEMENT_AUDIT_SCHEMA_PATH",
    "ORDER_AUDIT_SCHEMA_PATH",
    "PROPOSAL_SCHEMA_PATH",
    "PROPOSAL_DELIVERY_SCHEMA_PATH",
    "PROPOSAL_INTAKE_RECEIPT_SCHEMA_PATH",
    "RECEIPT_REVIEW_AUDIT_SCHEMA_PATH",
    "RECEIPT_REVIEW_CONFLICT_AUDIT_SCHEMA_PATH",
    "RECEIPT_REVIEW_SCHEMA_PATH",
    "VECTORS_PATH",
    "generate_vectors",
    "write_vectors",
]
