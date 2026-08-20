import asyncio
import copy
import hashlib
import inspect
import json
import multiprocessing
import os
import re
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import urllib.error
import urllib.request
from urllib.parse import urlsplit

import pytest

import nth_dao.trade_rules.dispute_statement as dispute_statement_module
import uvicorn
import nth_dao.trade_rules as trade_rules_api
import nth_dao.trade_rules.order_dispatch as order_dispatch_api
import nth_dao.web.v2_api as web_v2_api
from fastapi.testclient import TestClient

from nth_dao.canonical_json import canonical_json
from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.spine import SignedEventLog, SpineEvent
from nth_dao.util import InterProcessLock
from nth_dao.web import _FederationBodyLimitMiddleware, create_app
from nth_dao.web.market_federation_poll import _urllib_get_bytes_pinned
from nth_dao.web.rate_limit import RateLimiter
from nth_dao.trade_rules import (
    RulePackageStore,
    RulePackageCorruptionError,
    RuleResolutionPolicy,
    RuleRecognitionTrustPolicy,
    TradeAcceptance,
    TradeAgreementRejected,
    TradeExecutionAdapterPolicy,
    TradeExecutionAdapter,
    TradeExecutionAdapterRejected,
    TradeExecutionAuditError,
    TradeExecutionAuditBusy,
    TradeExecutionAuditCapacity,
    TradeExecutionReceiptConflict,
    TradeExecutionRuntimeHealth,
    TradeExecutionAuditOutbox,
    TradeExecutionCoordinator,
    TradeExecutionReceiptStore,
    TradeExecutionReceiptStoreError,
    TradeDisputeStatementFetchJournal,
    TradeOrder,
    TradeOrderConflict,
    TradeOrderRejected,
    TradeOrderStore,
    TradeOrderStoreCapacity,
    TradeOrderDelivery,
    TradeOrderDeliveryRejected,
    TradeOrderIntakeReceipt,
    TradeOrderIntakeReceiptRejected,
    TradeOrderIntakeCoordinator,
    TradeOrderDispatchCoordinator,
    TradeOrderDispatchResidue,
    TradeOrderDispatchStore,
    TradeProposal,
    TradeProposalDelivery,
    TradeProposalDeliveryRejected,
    TradeProposalIntakeReceipt,
    TradeProposalIntakeReceiptRejected,
    TradeProposalAuditCoordinator,
    TradeProposalAuditError,
    TradeProposalArchiveResult,
    TradeProposalInbox,
    TradeProposalInboxBusy,
    TradeProposalInboxCapacity,
    TradeProposalInboxCorruption,
    TradeProposalInboxError,
    TradeProposalInboxRejected,
    TradeExecutionReceipt,
    TradeExecutionReceiptRejected,
    JsonSchema202012Validator,
    EXECUTION_TERMS_KEY,
    acceptance_digest,
    build_execution_adapter,
    create_trade_order,
    create_rule_recognition,
    create_trade_acceptance,
    create_trade_proposal,
    create_trade_proposal_delivery,
    create_trade_proposal_intake_receipt,
    execution_receipt_digest,
    execution_audit_payload,
    project_trade_order_execution,
    manifest_body,
    offer_body,
    offer_digest,
    evaluate_rule_recognition,
    proposal_digest,
    trade_proposal_delivery_digest,
    trade_proposal_intake_receipt_digest,
    EVENT_TRADE_PROPOSAL_ARCHIVED,
    EVENT_TRADE_PROPOSAL_RECEIVED,
    resolve_canonical_offer_rules,
    sign_manifest,
    sign_offer,
    sign_offer_package_binding,
    build_rule_recognition_proof_bundle,
    parse_rule_recognition_proof_bundle,
    trade_order_digest,
    create_trade_order_delivery,
    create_trade_order_intake_receipt,
    trade_order_delivery_digest,
    trade_order_intake_receipt_digest,
    EVENT_TRADE_ORDER_INTAKE_ACKNOWLEDGED,
    verify_trade_order_delivery,
    verify_trade_order_intake_receipt,
    validate_execution_audit_binding,
    validate_execution_audit_payload,
    verify_acceptance_binding,
    verify_trade_proposal_under_local_state,
    verify_trade_proposal_delivery,
    verify_trade_proposal_intake_receipt,
    validate_proposal_received_audit_payload,
    verify_execution_receipt_order_binding,
    verify_execution_receipt_under_policy,
)
from nth_dao.trade_rules.dispute_statement import (
    MAX_TRADE_DISPUTE_CONTENT_BYTES,
    MAX_TRADE_DISPUTE_EVIDENCE,
    MAX_TRADE_DISPUTE_TOTAL_EVIDENCE_BYTES,
    TradeDisputeStatement,
    TradeDisputeStatementRejected,
    TradeDisputeStatementResolutionError,
    UnresolvedTradeDisputeStatement,
    create_trade_dispute_statement,
    trade_dispute_id,
    trade_dispute_statement_digest,
    verify_trade_dispute_statement,
)
from nth_dao.trade_rules.dispute_statement_transport import (
    TradeDisputeStatementAcknowledgement,
    TradeDisputeStatementAcknowledgementRejected,
    TradeDisputeStatementDelivery,
    TradeDisputeStatementDeliveryRejected,
    create_trade_dispute_statement_acknowledgement,
    create_trade_dispute_statement_delivery,
    verify_trade_dispute_statement_acknowledgement,
)
from nth_dao.trade_rules.dispute_statement_retrieval import (
    DISPUTE_STATEMENT_FETCH_REQUEST_SIGNING_DOMAIN,
    TradeDisputeStatementFetchRequest,
    TradeDisputeStatementFetchRequestRejected,
    TradeDisputeStatementFetchResponse,
    TradeDisputeStatementFetchResponseRejected,
    create_trade_dispute_statement_fetch_request,
    create_trade_dispute_statement_fetch_response,
    trade_dispute_statement_fetch_request_digest,
    trade_dispute_statement_fetch_response_digest,
    verify_trade_dispute_statement_fetch_request,
    verify_trade_dispute_statement_fetch_response,
)
from nth_dao.trade_rules.dispute_statement_intake import (
    TradeDisputeStatementIntakeJournal,
)
from nth_dao.trade_rules.dispute_statement_dispatch import (
    EVENT_TRADE_DISPUTE_STATEMENT_ACKNOWLEDGED,
)
from nth_dao.trade_rules.execution_receipt import (
    _create_trade_execution_receipt,
)
from nth_dao.trade_rules.execution_transport import (
    TradeExecutionReceiptAcknowledgement,
    TradeExecutionReceiptAcknowledgementRejected,
    TradeExecutionReceiptDelivery,
    TradeExecutionReceiptDeliveryRejected,
    create_trade_execution_receipt_acknowledgement,
    create_trade_execution_receipt_delivery,
    trade_execution_receipt_acknowledgement_digest,
    trade_execution_receipt_delivery_digest,
    verify_trade_execution_receipt_acknowledgement,
    verify_trade_execution_receipt_delivery,
)
from nth_dao.trade_rules.execution_intake import (
    TradeExecutionReceiptIntakeCoordinator,
)
from nth_dao.trade_rules.execution_dispatch import (
    EVENT_TRADE_EXECUTION_RECEIPT_ACKNOWLEDGED,
    TradeExecutionReceiptDispatchBusy,
    TradeExecutionReceiptDispatchCapacity,
    TradeExecutionReceiptDispatchCoordinator,
    TradeExecutionReceiptDispatchError,
    TradeExecutionReceiptDispatchStore,
    execution_receipt_acknowledgement_audit_payload,
)
from nth_dao.trade_rules.receipt_review import (
    RECEIPT_REVIEW_SIGNING_DOMAIN,
    TradeReceiptReview,
    TradeReceiptReviewRejected,
    create_trade_receipt_review,
    receipt_review_digest,
    verify_trade_receipt_review_under_policy,
)
from nth_dao.trade_rules.receipt_review_transport import (
    TradeReceiptReviewAcknowledgement,
    TradeReceiptReviewAcknowledgementRejected,
    TradeReceiptReviewDelivery,
    TradeReceiptReviewDeliveryRejected,
    create_trade_receipt_review_acknowledgement,
    create_trade_receipt_review_delivery,
    trade_receipt_review_acknowledgement_digest,
    trade_receipt_review_delivery_digest,
    verify_trade_receipt_review_acknowledgement,
    verify_trade_receipt_review_delivery,
)
from nth_dao.trade_rules.receipt_review_intake import (
    TradeReceiptReviewIntakeCoordinator,
)
from nth_dao.trade_rules.receipt_review_dispatch import (
    EVENT_TRADE_RECEIPT_REVIEW_ACKNOWLEDGED,
    TradeReceiptReviewDispatchCoordinator,
    TradeReceiptReviewDispatchError,
    TradeReceiptReviewDispatchStore,
    receipt_review_acknowledgement_audit_payload,
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
    DISPUTE_STATEMENT_FETCH_AUDIT_SCHEMA_PATH,
    DISPUTE_STATEMENT_FETCH_REQUEST_SCHEMA_PATH,
    DISPUTE_STATEMENT_FETCH_RESPONSE_SCHEMA_PATH,
    EXECUTION_AUDIT_SCHEMA_PATH,
    EXECUTION_ADAPTER_SCHEMA_PATH,
    EXECUTION_ADAPTER_POLICY_SCHEMA_PATH,
    EXECUTION_RECEIPT_SCHEMA_PATH,
    EXECUTION_RECEIPT_ACKNOWLEDGEMENT_SCHEMA_PATH,
    EXECUTION_RECEIPT_DELIVERY_SCHEMA_PATH,
    RECEIPT_REVIEW_AUDIT_SCHEMA_PATH,
    RECEIPT_REVIEW_ACKNOWLEDGEMENT_SCHEMA_PATH,
    RECEIPT_REVIEW_CONFLICT_AUDIT_SCHEMA_PATH,
    RECEIPT_REVIEW_DELIVERY_SCHEMA_PATH,
    RECEIPT_REVIEW_SCHEMA_PATH,
    TRADE_DISPUTE_STATEMENT_SCHEMA_PATH,
    RULE_PACKAGE_BUNDLE_SCHEMA_PATH,
    ORDER_AUDIT_SCHEMA_PATH,
    ORDER_DELIVERY_SCHEMA_PATH,
    ORDER_INTAKE_RECEIPT_SCHEMA_PATH,
    ORDER_INTAKE_ACKNOWLEDGEMENT_AUDIT_SCHEMA_PATH,
    ORDER_SCHEMA_PATH,
    PROPOSAL_SCHEMA_PATH,
    PROPOSAL_DELIVERY_SCHEMA_PATH,
    PROPOSAL_INTAKE_RECEIPT_SCHEMA_PATH,
    VECTORS_PATH,
    generate_vectors,
)
from nth_dao.trade_rules.package_transport import (
    RULE_PACKAGE_BUNDLE_KIND,
    RULE_PACKAGE_BUNDLE_PROTOCOL_VERSION,
    RulePackageBundleRejected,
    parse_rule_package_bundle,
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
from nth_dao.trade_rules.order_dispatch import (
    MAX_DISPATCH_RECORD_BYTES,
    TradeOrderDispatchCapacity,
    TradeOrderDispatchError,
)
from nth_dao.trade_rules.signing import (
    encode_ed25519_signature,
    signed_document_input,
    verification_method_for_did,
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


class _StaticRulePackageResolver:
    def __init__(self, package):
        self._package = package
        self.loads = 0

    def load(self, digest):
        self.loads += 1
        return self._package if digest == self._package.digest else None


class _SyntheticResolverUnavailable(Exception):
    pass


class _FailingRulePackageResolver:
    def load(self, _digest):
        raise _SyntheticResolverUnavailable(
            "sensitive resolver failure at C:\\operator-home"
        )


class _DuckTypedRulePackageResolver:
    def __init__(self, package):
        self._package = package

    def load(self, _digest):
        class PackageLike:
            pass

        value = PackageLike()
        value.digest = self._package.digest
        value.manifest = self._package.manifest
        value.resources = self._package.resources
        return value


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


def _process_put_trade_proposal(
    root, receiver_did, delivery, receipt, output,
):
    try:
        result = TradeProposalInbox(
            root,
            receiver_did=receiver_did,
            lock_timeout=20,
        ).put(
            delivery,
            receipt,
        )
        output.put(("ok", result.appended, result.digest))
    except Exception as exc:
        output.put(("error", type(exc).__name__, str(exc)))


def _process_list_trade_proposals(root, receiver_did, output):
    try:
        values = TradeProposalInbox(
            root,
            receiver_did=receiver_did,
            lock_timeout=0.2,
        ).list_digests()
        output.put(("ok", values))
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
    maker=None,
    taker=None,
    dependency_permissions=(),
    hook_permissions=(),
):
    maker = maker or AgentIdentity.generate()
    taker = taker or AgentIdentity.generate()
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
        source="local",
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
        source="local",
    ).digest
    adapter_artifact = b"test adapter artifact v1"
    adapter = build_execution_adapter(
        adapter_id="org.nthdao.test/declarative",
        adapter_version="1.0.0",
        artifact_digest=_digest(adapter_artifact),
        execution_modes=["adapter" if hook_permissions else "declarative"],
        hooks=[
            {
                "rule_id": manifest.rule_id,
                "hook_name": "fulfillment.deliver",
                "hook_version": "1",
            }
        ],
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


def test_receiver_replays_proposal_against_local_offer_and_rules(tmp_path):
    context = _setup(tmp_path)
    proposal = _proposal(context)

    assert verify_trade_proposal_under_local_state(
        proposal,
        context["offer_store"],
        context["package_store"],
        at=_AT,
    ) == (True, "ok")


def test_receiver_rejects_self_consistent_proposal_for_wrong_offer_head(tmp_path):
    context = _setup(tmp_path)
    body = _proposal(context).to_dict()
    body.pop("proof")
    wrong_digest = "sha256:" + ("c" * 64)
    body["offer_digest"] = wrong_digest
    body["canonical_chain_digests"][-1] = wrong_digest
    proposal = _sign_proposal_body(context["taker"], body)

    ok, reason = verify_trade_proposal_under_local_state(
        proposal,
        context["offer_store"],
        context["package_store"],
        at=_AT,
    )

    assert ok is False
    assert "offer_digest does not match local replay" in reason


def test_receiver_rejects_proposal_when_rule_package_is_unavailable(tmp_path):
    context = _setup(tmp_path / "source")
    proposal = _proposal(context)
    empty_packages = RulePackageStore(tmp_path / "receiver")

    ok, reason = verify_trade_proposal_under_local_state(
        proposal,
        context["offer_store"],
        empty_packages,
        at=_AT,
    )

    assert ok is False
    assert "required rule package is unavailable" in reason


def test_receiver_maps_offer_store_failure_to_rejection(tmp_path):
    context = _setup(tmp_path)

    class BrokenOfferResolver:
        def canonical_snapshot(self, _publisher_did, _offer_id):
            raise RuntimeError("simulated Offer Store corruption")

    ok, reason = verify_trade_proposal_under_local_state(
        _proposal(context),
        BrokenOfferResolver(),
        context["package_store"],
        at=_AT,
    )

    assert ok is False
    assert reason == "simulated Offer Store corruption"


@pytest.mark.parametrize(
    ("at", "expected"),
    [
        (_AT - timedelta(minutes=6), "too far in the future"),
        (_utc(_EXPIRES), "proposal has expired"),
    ],
)
def test_receiver_enforces_proposal_receive_time(
    tmp_path,
    at,
    expected,
):
    context = _setup(tmp_path)

    ok, reason = verify_trade_proposal_under_local_state(
        _proposal(context),
        context["offer_store"],
        context["package_store"],
        at=at,
    )

    assert ok is False
    assert expected in reason


def test_receiver_preserves_nanoseconds_at_proposal_expiry(tmp_path):
    context = _setup(tmp_path)
    body = _proposal(context).to_dict()
    body.pop("proof")
    body["not_after"] = "2026-08-02T00:00:00.000000001Z"
    proposal = _sign_proposal_body(context["taker"], body)

    assert verify_trade_proposal_under_local_state(
        proposal,
        context["offer_store"],
        context["package_store"],
        at=_utc("2026-08-02T00:00:00Z"),
    ) == (True, "ok")


def test_receiver_preserves_nanoseconds_at_future_skew_boundary(tmp_path):
    context = _setup(tmp_path)
    body = _proposal(context).to_dict()
    body.pop("proof")
    body["created_at"] = "2026-08-01T00:00:00.000000001Z"
    proposal = _sign_proposal_body(context["taker"], body)

    ok, reason = verify_trade_proposal_under_local_state(
        proposal,
        context["offer_store"],
        context["package_store"],
        at=_AT,
        clock_skew_seconds=0,
    )

    assert ok is False
    assert reason == "proposal creation time is too far in the future"


def _delivery(context, proposal=None):
    selected = proposal or _proposal(context)
    return create_trade_proposal_delivery(
        context["taker"],
        proposal=selected,
        created_at="2026-08-01T00:00:00Z",
        not_after="2026-08-01T00:10:00Z",
        nonce="a" * 32,
        now=_AT,
    )


def _intake_receipt(context, delivery):
    return create_trade_proposal_intake_receipt(
        context["maker"],
        delivery=delivery,
        received_at="2026-08-01T00:00:00Z",
    )


def _put_inbox(inbox, context, proposal):
    delivery = _delivery(context, proposal)
    return inbox.put(delivery, _intake_receipt(context, delivery))


def test_proposal_delivery_round_trip_binds_both_parties_and_proposal(tmp_path):
    context = _setup(tmp_path)
    proposal = _proposal(context)
    delivery = _delivery(context, proposal)

    assert TradeProposalDelivery.from_json(delivery.canonical_bytes) == delivery
    assert delivery.proposal == proposal
    assert delivery.to_dict()["proposal_digest"] == proposal_digest(proposal)
    assert trade_proposal_delivery_digest(delivery).startswith("sha256:")
    assert verify_trade_proposal_delivery(
        delivery,
        recipient_did=context["maker"].as_did(),
        at=_AT,
    ) == (True, "ok")


def test_proposal_delivery_tampering_breaks_outer_signature(tmp_path):
    context = _setup(tmp_path)
    document = _delivery(context).to_dict()
    document["nonce"] = "b" * 32
    document["delivery_id"] = "nth:trade:proposal-delivery:" + "b" * 32

    with pytest.raises(
        TradeProposalDeliveryRejected,
        match="signature invalid",
    ):
        TradeProposalDelivery.from_dict(document)


def test_proposal_transport_revalidates_preconstructed_instances(tmp_path):
    context = _setup(tmp_path)
    delivery = _delivery(context)
    delivery_document = delivery.to_dict()
    delivery_document["proof"]["proof_value"] = "A" * 86
    forged_delivery = TradeProposalDelivery._create(
        trade_rules_api.trade_canonical_json(delivery_document),
        delivery.proposal,
    )

    ok, reason = verify_trade_proposal_delivery(
        forged_delivery,
        recipient_did=context["maker"].as_did(),
        at=_AT,
    )

    assert ok is False
    assert reason == "signature invalid"
    with pytest.raises(TradeProposalDeliveryRejected, match="signature invalid"):
        trade_proposal_delivery_digest(forged_delivery)

    receipt = _intake_receipt(context, delivery)
    receipt_document = receipt.to_dict()
    receipt_document["proof"]["proof_value"] = "A" * 86
    forged_receipt = TradeProposalIntakeReceipt._create(
        trade_rules_api.trade_canonical_json(receipt_document)
    )

    ok, reason = verify_trade_proposal_intake_receipt(
        forged_receipt,
        delivery=delivery,
        receiver_did=context["maker"].as_did(),
    )

    assert ok is False
    assert reason == "signature invalid"
    with pytest.raises(
        TradeProposalIntakeReceiptRejected,
        match="signature invalid",
    ):
        trade_proposal_intake_receipt_digest(forged_receipt)


def test_proposal_delivery_rejects_wrong_receiver(tmp_path):
    context = _setup(tmp_path)

    ok, reason = verify_trade_proposal_delivery(
        _delivery(context),
        recipient_did=AgentIdentity.generate().as_did(),
        at=_AT,
    )

    assert ok is False
    assert reason == "delivery is addressed to another recipient"


@pytest.mark.parametrize(
    ("at", "expected"),
    [
        (_AT - timedelta(minutes=6), "too far in the future"),
        (_AT + timedelta(minutes=10), "delivery has expired"),
    ],
)
def test_proposal_delivery_enforces_receive_time(tmp_path, at, expected):
    context = _setup(tmp_path)

    ok, reason = verify_trade_proposal_delivery(
        _delivery(context),
        recipient_did=context["maker"].as_did(),
        at=at,
    )

    assert ok is False
    assert expected in reason


def test_proposal_delivery_creation_rejects_excessive_ttl(tmp_path):
    context = _setup(tmp_path)

    with pytest.raises(
        TradeProposalDeliveryRejected,
        match="lifetime exceeds",
    ):
        create_trade_proposal_delivery(
            context["taker"],
            proposal=_proposal(context),
            created_at="2026-08-01T00:00:00Z",
            not_after="2026-08-01T00:10:01Z",
            nonce="a" * 32,
            now=_AT,
        )


def test_proposal_delivery_rejects_odd_length_hex_nonce(tmp_path):
    context = _setup(tmp_path)

    with pytest.raises(
        TradeProposalDeliveryRejected,
        match="16 to 64 bytes",
    ):
        create_trade_proposal_delivery(
            context["taker"],
            proposal=_proposal(context),
            created_at="2026-08-01T00:00:00Z",
            not_after="2026-08-01T00:10:00Z",
            nonce="a" * 33,
            now=_AT,
        )


@pytest.mark.parametrize(
    ("created_at", "not_after", "expected"),
    [
        (
            "2026-07-31T23:59:59Z",
            "2026-08-01T00:05:00Z",
            "cannot predate",
        ),
        (
            "2026-08-01T00:00:00Z",
            "2026-08-02T00:00:01Z",
            "cannot outlive",
        ),
    ],
)
def test_proposal_delivery_is_temporally_bounded_by_proposal(
    tmp_path,
    created_at,
    not_after,
    expected,
):
    context = _setup(tmp_path)

    with pytest.raises(TradeProposalDeliveryRejected, match=expected):
        create_trade_proposal_delivery(
            context["taker"],
            proposal=_proposal(context),
            created_at=created_at,
            not_after=not_after,
            nonce="a" * 32,
            now=_AT,
            max_ttl_seconds=2 * 24 * 60 * 60,
        )


def test_proposal_delivery_ttl_preserves_nanosecond_boundary(tmp_path):
    context = _setup(tmp_path)

    with pytest.raises(
        TradeProposalDeliveryRejected,
        match="lifetime exceeds",
    ):
        create_trade_proposal_delivery(
            context["taker"],
            proposal=_proposal(context),
            created_at="2026-08-01T00:00:00.000000001Z",
            not_after="2026-08-01T00:00:00.000000002Z",
            nonce="a" * 32,
            now=_AT,
            max_ttl_seconds=0,
        )


def test_proposal_delivery_receive_is_durable_and_exactly_once(tmp_path):
    context = _setup(tmp_path)
    inbox = TradeProposalInbox(
        tmp_path, receiver_did=context["maker"].as_did()
    )
    spine = SignedEventLog(tmp_path / "spine.jsonl", context["maker"])
    coordinator = TradeProposalAuditCoordinator(inbox, spine, context["maker"])
    delivery = _delivery(context)

    first = coordinator.receive(
        delivery,
        recipient_did=context["maker"].as_did(),
        offer_resolver=context["offer_store"],
        rule_resolver=context["package_store"],
        at=_AT,
    )
    retry = coordinator.receive(
        delivery.to_dict(),
        recipient_did=context["maker"].as_did(),
        offer_resolver=context["offer_store"],
        rule_resolver=context["package_store"],
        at=_AT,
    )

    assert first.inbox.appended is True
    assert first.anchor_created is True
    assert retry.inbox.appended is False
    assert retry.anchor_created is False
    assert retry.event.event_id == first.event.event_id
    assert inbox.get(first.inbox.digest) == delivery.proposal
    events = spine.verified_snapshot()
    assert [event.type for event in events] == [EVENT_TRADE_PROPOSAL_RECEIVED]
    assert validate_proposal_received_audit_payload(
        events[0].payload,
        proposal=delivery.proposal,
    ) == events[0].payload


def test_proposal_delivery_retry_returns_committed_result_after_offer_change(
    tmp_path,
):
    context = _setup(tmp_path)
    inbox = TradeProposalInbox(
        tmp_path, receiver_did=context["maker"].as_did()
    )
    spine = SignedEventLog(tmp_path / "spine.jsonl", context["maker"])
    coordinator = TradeProposalAuditCoordinator(inbox, spine, context["maker"])
    delivery = _delivery(context)
    first = coordinator.receive(
        delivery,
        recipient_did=context["maker"].as_did(),
        offer_resolver=context["offer_store"],
        rule_resolver=context["package_store"],
        at=_AT,
    )
    previous = context["offer"].to_dict()
    withdrawn = sign_offer(
        context["maker"],
        offer_body(
            offer_id=previous["offer_id"],
            revision=2,
            previous_offer_digest=offer_digest(context["offer"]),
            state="withdrawn",
            publisher_did=previous["publisher_did"],
            title=previous["title"],
            summary=previous["summary"],
            provides=previous["provides"],
            requests=previous["requests"],
            rule_refs=previous["rule_refs"],
            published_at="2026-08-01T00:00:01Z",
            not_after=previous["not_after"],
            extensions=previous["extensions"],
        ),
        created="2026-08-01T00:00:01Z",
    )
    context["offer_store"].publish(withdrawn)

    retry = coordinator.receive(
        delivery,
        recipient_did=context["maker"].as_did(),
        offer_resolver=context["offer_store"],
        rule_resolver=context["package_store"],
        at=_utc("2026-08-01T00:01:00Z"),
    )

    assert retry.inbox.appended is False
    assert retry.event.event_id == first.event.event_id


def test_proposal_reconciliation_ignores_unsigned_orphan_delivery(tmp_path):
    context = _setup(tmp_path)
    delivery = _delivery(context)
    inbox = TradeProposalInbox(
        tmp_path, receiver_did=context["maker"].as_did()
    )
    inbox.deliveries_root.mkdir(parents=True)
    path = inbox.deliveries_root / f"{proposal_digest(delivery.proposal)[7:]}.json"
    path.write_bytes(delivery.canonical_bytes)
    spine = SignedEventLog(tmp_path / "spine.jsonl", context["maker"])
    coordinator = TradeProposalAuditCoordinator(inbox, spine, context["maker"])

    report = coordinator.reconcile()

    assert report.scanned == 0
    assert report.anchored == 0
    assert spine.verified_snapshot() == ()


def test_proposal_reconciliation_rejects_foreign_receiver_intake(tmp_path):
    foreign_workspace = tmp_path / "foreign"
    context = _setup(foreign_workspace)
    local_identity = AgentIdentity.generate()
    foreign_inbox = TradeProposalInbox(
        tmp_path,
        receiver_did=local_identity.as_did(),
    )
    delivery = _delivery(context)
    receipt = _intake_receipt(context, delivery)

    with pytest.raises(
        TradeProposalInboxRejected,
        match="another receiver",
    ):
        foreign_inbox.put(delivery, receipt)

    digest = proposal_digest(delivery.proposal)
    foreign_inbox.deliveries_root.mkdir(parents=True)
    foreign_inbox.receipts_root.mkdir(parents=True)
    foreign_inbox._delivery_path(digest).write_bytes(delivery.canonical_bytes)
    foreign_inbox._receipt_path(digest).write_bytes(receipt.canonical_bytes)
    assert foreign_inbox.reconcile_usage() == {"records": 0, "bytes": 0}
    assert foreign_inbox.list_digests() == ()
    quarantine = foreign_inbox.quarantine_root / digest[7:]
    assert (quarantine / "delivery.json").read_bytes() == delivery.canonical_bytes
    assert (quarantine / "intake_receipt.json").read_bytes() == receipt.canonical_bytes

    spine = SignedEventLog(tmp_path / "spine.jsonl", local_identity)
    coordinator = TradeProposalAuditCoordinator(
        foreign_inbox, spine, local_identity
    )

    report = coordinator.reconcile()

    assert report.scanned == 0
    assert report.failed == 0
    assert report.anchored == 0
    assert spine.verified_snapshot() == ()


def test_proposal_reconciliation_batch_scans_spine_once(tmp_path, monkeypatch):
    context = _setup(tmp_path)
    first = _proposal(context)
    body = first.to_dict()
    body.pop("proof")
    body["terms"]["requested_quantity"] = "2"
    second = _sign_proposal_body(context["taker"], body)
    inbox = TradeProposalInbox(
        tmp_path, receiver_did=context["maker"].as_did()
    )
    _put_inbox(inbox, context, first)
    _put_inbox(inbox, context, second)
    spine = SignedEventLog(tmp_path / "spine.jsonl", context["maker"])
    coordinator = TradeProposalAuditCoordinator(inbox, spine, context["maker"])
    original = spine._verified_events_unlocked
    scans = 0

    def counted_scan():
        nonlocal scans
        scans += 1
        return original()

    monkeypatch.setattr(spine, "_verified_events_unlocked", counted_scan)
    report = coordinator.reconcile()

    assert report.scanned == 2
    assert report.anchored == 2
    assert report.failed == 0
    assert scans == 1


def test_proposal_reconciliation_preserves_structured_failure(tmp_path, monkeypatch):
    context = _setup(tmp_path)
    inbox = TradeProposalInbox(
        tmp_path, receiver_did=context["maker"].as_did()
    )
    retained = _put_inbox(inbox, context, _proposal(context))
    spine = SignedEventLog(tmp_path / "spine.jsonl", context["maker"])
    coordinator = TradeProposalAuditCoordinator(inbox, spine, context["maker"])

    def corrupt_entry(_digest):
        raise TradeProposalInboxCorruption("intake receipt hash mismatch")

    monkeypatch.setattr(coordinator, "_verified_entry", corrupt_entry)
    report = coordinator.reconcile()

    assert report.failed == 1
    assert report.failure_digests == (retained.digest,)
    assert len(report.failures) == 1
    assert report.failures[0].digest == retained.digest
    assert report.failures[0].error_code == "inbox-corruption"
    assert report.failures[0].message == "intake receipt hash mismatch"


def test_expired_proposal_archives_after_signed_tombstone_and_frees_capacity(
    tmp_path,
):
    context = _setup(tmp_path)
    first = _proposal(context)
    body = first.to_dict()
    body.pop("proof")
    body["terms"]["requested_quantity"] = "2"
    second = _sign_proposal_body(context["taker"], body)
    inbox = TradeProposalInbox(
        tmp_path,
        receiver_did=context["maker"].as_did(),
        max_proposals=1,
    )
    spine = SignedEventLog(tmp_path / "spine.jsonl", context["maker"])
    coordinator = TradeProposalAuditCoordinator(inbox, spine, context["maker"])
    first_retained = _put_inbox(inbox, context, first)

    report = coordinator.archive_expired(
        at=_utc("2026-08-02T00:00:00Z")
    )

    assert report.scanned == 1
    assert report.archived == 1
    assert report.failure_digests == ()
    assert inbox.list_digests() == ()
    archive = inbox.archive_root / first_retained.digest[7:]
    assert (archive / "delivery.json").is_file()
    assert (archive / "intake_receipt.json").is_file()
    events = spine.verified_snapshot()
    assert [event.type for event in events] == [EVENT_TRADE_PROPOSAL_ARCHIVED]
    assert events[0].payload["proposal_digest"] == first_retained.digest
    assert _put_inbox(inbox, context, second).appended is True


def test_archive_copy_failure_keeps_active_commit_marker(tmp_path, monkeypatch):
    context = _setup(tmp_path)
    inbox = TradeProposalInbox(
        tmp_path, receiver_did=context["maker"].as_did()
    )
    retained = _put_inbox(inbox, context, _proposal(context))
    original = inbox._atomic_write

    def fail_archive_receipt(path, payload):
        if path.name == "intake_receipt.json":
            raise TradeProposalInboxError("simulated archive outage")
        return original(path, payload)

    monkeypatch.setattr(inbox, "_atomic_write", fail_archive_receipt)
    with pytest.raises(TradeProposalInboxError, match="archive outage"):
        inbox.archive_digests((retained.digest,))

    assert inbox.list_digests() == (retained.digest,)
    assert inbox.get(retained.digest) == retained.proposal


def test_receive_archives_expired_record_on_capacity_and_retries(tmp_path):
    context = _setup(tmp_path)
    inbox = TradeProposalInbox(
        tmp_path,
        receiver_did=context["maker"].as_did(),
        max_proposals=1,
    )
    expired = _put_inbox(inbox, context, _proposal(context))
    moment = _utc("2026-08-02T00:01:00Z")
    resolution = resolve_canonical_offer_rules(
        context["maker"].as_did(),
        context["offer"].offer_id,
        context["offer_store"],
        context["package_store"],
        context["taker_policy"],
        at=moment,
    )
    proposal = create_trade_proposal(
        context["taker"],
        resolution=resolution,
        offer=context["offer"],
        offer_resolver=context["offer_store"],
        terms={"requested_quantity": "2"},
        created_at="2026-08-02T00:01:00Z",
        not_after="2026-08-03T00:01:00Z",
        now=moment,
    )
    delivery = create_trade_proposal_delivery(
        context["taker"],
        proposal=proposal,
        created_at="2026-08-02T00:01:00Z",
        not_after="2026-08-02T00:11:00Z",
        nonce="d" * 32,
        now=moment,
    )
    spine = SignedEventLog(tmp_path / "spine.jsonl", context["maker"])
    coordinator = TradeProposalAuditCoordinator(inbox, spine, context["maker"])

    result = coordinator.receive(
        delivery,
        recipient_did=context["maker"].as_did(),
        offer_resolver=context["offer_store"],
        rule_resolver=context["package_store"],
        at=moment,
    )

    assert result.inbox.appended is True
    assert inbox.list_digests() == (proposal_digest(proposal),)
    assert (inbox.archive_root / expired.digest[7:]).is_dir()
    assert [event.type for event in spine.verified_snapshot()] == [
        EVENT_TRADE_PROPOSAL_ARCHIVED,
        EVENT_TRADE_PROPOSAL_RECEIVED,
    ]


def test_proposal_delivery_rejects_before_inbox_or_spine(tmp_path):
    context = _setup(tmp_path)
    inbox = TradeProposalInbox(
        tmp_path, receiver_did=context["maker"].as_did()
    )
    spine = SignedEventLog(tmp_path / "spine.jsonl", context["maker"])
    coordinator = TradeProposalAuditCoordinator(inbox, spine, context["maker"])

    with pytest.raises(TradeProposalDeliveryRejected, match="another recipient"):
        coordinator.receive(
            _delivery(context),
            recipient_did=AgentIdentity.generate().as_did(),
            offer_resolver=context["offer_store"],
            rule_resolver=context["package_store"],
            at=_AT,
        )

    assert inbox.list_digests() == ()
    assert spine.verified_snapshot() == ()


def test_proposal_delivery_spine_failure_reconciles_without_resubmission(
    tmp_path,
    monkeypatch,
):
    context = _setup(tmp_path)
    inbox = TradeProposalInbox(
        tmp_path, receiver_did=context["maker"].as_did()
    )
    spine = SignedEventLog(tmp_path / "spine.jsonl", context["maker"])
    coordinator = TradeProposalAuditCoordinator(inbox, spine, context["maker"])

    def fail_before_append(*args, **kwargs):
        raise OSError("simulated projection outage")

    monkeypatch.setattr(spine, "append_unique", fail_before_append)
    with pytest.raises(TradeProposalAuditError, match="projection outage"):
        coordinator.receive(
            _delivery(context),
            recipient_did=context["maker"].as_did(),
            offer_resolver=context["offer_store"],
            rule_resolver=context["package_store"],
            at=_AT,
        )
    assert len(inbox.list_digests()) == 1
    assert spine.verified_snapshot() == ()
    pending_view = coordinator.get_received(inbox.list_digests()[0])
    assert pending_view is not None
    assert pending_view.audit_verified is False

    restarted = TradeProposalAuditCoordinator(
        TradeProposalInbox(
            tmp_path, receiver_did=context["maker"].as_did()
        ),
        SignedEventLog(tmp_path / "spine.jsonl", context["maker"]),
        context["maker"],
    )
    report = restarted.reconcile()

    assert report.scanned == 1
    assert report.anchored == 1
    assert report.verified_anchored == 0
    assert report.failed == 0
    assert report.has_more is False
    recovered_view = restarted.get_received(inbox.list_digests()[0])
    assert recovered_view is not None
    assert recovered_view.audit_verified is True


def test_proposal_delivery_projection_recovers_commit_then_raise(
    tmp_path,
    monkeypatch,
):
    context = _setup(tmp_path)
    inbox = TradeProposalInbox(
        tmp_path, receiver_did=context["maker"].as_did()
    )
    spine = SignedEventLog(tmp_path / "spine.jsonl", context["maker"])
    coordinator = TradeProposalAuditCoordinator(inbox, spine, context["maker"])
    original = spine.append_unique

    def append_then_raise(*args, **kwargs):
        original(*args, **kwargs)
        raise OSError("simulated lost acknowledgement")

    monkeypatch.setattr(spine, "append_unique", append_then_raise)
    result = coordinator.receive(
        _delivery(context),
        recipient_did=context["maker"].as_did(),
        offer_resolver=context["offer_store"],
        rule_resolver=context["package_store"],
        at=_AT,
    )

    assert result.inbox.appended is True
    assert result.anchor_created is False
    assert len(spine.verified_snapshot()) == 1


def test_proposal_delivery_projection_does_not_mask_spine_corruption(
    tmp_path,
    monkeypatch,
):
    context = _setup(tmp_path)
    inbox = TradeProposalInbox(
        tmp_path, receiver_did=context["maker"].as_did()
    )
    spine_path = tmp_path / "spine.jsonl"
    spine = SignedEventLog(spine_path, context["maker"])
    coordinator = TradeProposalAuditCoordinator(inbox, spine, context["maker"])

    def corrupt_then_raise(*args, **kwargs):
        spine_path.write_bytes(b"not-json\n")
        raise OSError("simulated projection outage")

    monkeypatch.setattr(spine, "append_unique", corrupt_then_raise)
    with pytest.raises(
        TradeProposalAuditError,
        match="Spine integrity check failed",
    ):
        coordinator.receive(
            _delivery(context),
            recipient_did=context["maker"].as_did(),
            offer_resolver=context["offer_store"],
            rule_resolver=context["package_store"],
            at=_AT,
        )


def test_proposal_delivery_view_rejects_signed_malformed_audit_payload(
    tmp_path,
):
    context = _setup(tmp_path)
    proposal = _proposal(context)
    inbox = TradeProposalInbox(
        tmp_path, receiver_did=context["maker"].as_did()
    )
    retained = _put_inbox(inbox, context, proposal)
    spine = SignedEventLog(tmp_path / "spine.jsonl", context["maker"])
    payload = trade_rules_api.proposal_received_audit_payload(proposal)
    payload["maker_did"] = "not-a-did"
    spine.append(EVENT_TRADE_PROPOSAL_RECEIVED, payload)

    with pytest.raises(
        TradeProposalAuditError,
        match="maker_did is invalid",
    ):
        TradeProposalAuditCoordinator(
            inbox, spine, context["maker"]
        ).get_received(
            retained.digest
        )


def _live_proposal_delivery(tmp_path, app, *, nonce="b" * 32):
    context = _setup(tmp_path, maker=app.state.nth.node_identity)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    created_at = now.isoformat().replace("+00:00", "Z")
    proposal_not_after = (now + timedelta(hours=1)).isoformat().replace(
        "+00:00",
        "Z",
    )
    live_resolution = resolve_canonical_offer_rules(
        context["maker"].as_did(),
        context["offer"].offer_id,
        context["offer_store"],
        context["package_store"],
        context["taker_policy"],
        at=now,
    )
    proposal = create_trade_proposal(
        context["taker"],
        resolution=live_resolution,
        offer=context["offer"],
        offer_resolver=context["offer_store"],
        terms={"requested_quantity": "1"},
        created_at=created_at,
        not_after=proposal_not_after,
        now=now,
    )
    delivery = create_trade_proposal_delivery(
        context["taker"],
        proposal=proposal,
        created_at=created_at,
        not_after=(now + timedelta(minutes=10)).isoformat().replace(
            "+00:00",
            "Z",
        ),
        nonce=nonce,
        now=now,
    )
    return context, proposal, delivery, created_at, proposal_not_after


def test_public_proposal_delivery_endpoint_retains_but_does_not_accept(
    tmp_path,
):
    app = create_app(tmp_path, require_console_auth=True)
    context, proposal, delivery, created_at, proposal_not_after = (
        _live_proposal_delivery(tmp_path, app)
    )
    client = TestClient(app)

    first = client.post(
        "/api/v2/trade/federation/proposals",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )
    retry = client.post(
        "/api/v2/trade/federation/proposals",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )

    assert first.status_code == 202
    assert first.json()["status"] == "retained-unaccepted"
    assert first.json()["inbox_appended"] is True
    assert first.json()["audit_anchor_created"] is True
    assert retry.status_code == 202
    assert retry.json()["inbox_appended"] is False
    assert retry.json()["audit_anchor_created"] is False
    assert retry.json()["audit_event_id"] == first.json()["audit_event_id"]
    unauthenticated = client.get("/api/v2/trade/proposals")
    authenticated = client.get(
        "/api/v2/trade/proposals",
        headers={
            "Authorization": f"Bearer {app.state.nth_console_token}",
        },
    )
    detail = client.get(
        "/api/v2/trade/proposals/" + first.json()["proposal_digest"],
        headers={
            "Authorization": f"Bearer {app.state.nth_console_token}",
        },
    )

    assert unauthenticated.status_code == 401
    assert authenticated.status_code == 200
    assert authenticated.json()["items"] == [{
        "proposal_digest": proposal_digest(proposal),
        "offer_digest": proposal.to_dict()["offer_digest"],
        "offer_id": proposal.to_dict()["offer_id"],
        "offer_revision": 1,
        "maker_did": context["maker"].as_did(),
        "taker_did": context["taker"].as_did(),
        "created_at": created_at,
        "not_after": proposal_not_after,
        "rule_bindings_count": 2,
        "status": "retained-unaccepted",
        "audit_verified": True,
        "audit_event_id": first.json()["audit_event_id"],
    }]
    assert detail.status_code == 200
    assert detail.json()["proposal"] == proposal.to_dict()


def test_proposal_reconcile_endpoint_repairs_without_peer_resubmission(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path, require_console_auth=True)
    _context, _proposal_value, delivery, _created, _expiry = (
        _live_proposal_delivery(tmp_path, app)
    )
    spine = app.state.nth.spine
    original = spine.append_unique

    def fail_projection(*args, **kwargs):
        raise OSError("simulated projection outage")

    monkeypatch.setattr(spine, "append_unique", fail_projection)
    client = TestClient(app)
    pending = client.post(
        "/api/v2/trade/federation/proposals",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )
    monkeypatch.setattr(spine, "append_unique", original)

    assert pending.status_code == 503
    assert "simulated projection outage" not in pending.text
    assert pending.json()["detail"] == {
        "code": "trade-proposal-audit-incomplete",
        "message": "Proposal was retained but its audit projection is incomplete",
        "retryable_without_resubmission": True,
    }
    assert client.post("/api/v2/trade/proposals/reconcile").status_code == 401
    recovered = client.post(
        "/api/v2/trade/proposals/reconcile",
        headers={
            "Authorization": f"Bearer {app.state.nth_console_token}",
        },
    )
    assert recovered.status_code == 200
    assert recovered.json()["anchored"] == 1
    assert recovered.json()["failed"] == 0
    assert recovered.json()["failure_digests"] == []
    assert recovered.json()["failures"] == []


def test_proposal_reconciliation_status_is_authenticated_and_tracks_lag(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path, require_console_auth=True)
    _context, _proposal_value, delivery, _created, _expiry = (
        _live_proposal_delivery(tmp_path, app)
    )
    spine = app.state.nth.spine
    original = spine.append_unique

    def fail_projection(*args, **kwargs):
        raise OSError("simulated projection outage")

    monkeypatch.setattr(spine, "append_unique", fail_projection)
    client = TestClient(app)
    pending = client.post(
        "/api/v2/trade/federation/proposals",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )
    monkeypatch.setattr(spine, "append_unique", original)
    auth = {"Authorization": f"Bearer {app.state.nth_console_token}"}

    assert pending.status_code == 503
    assert client.get(
        "/api/v2/trade/proposal-reconciliation/status"
    ).status_code == 401
    before = client.get(
        "/api/v2/trade/proposal-reconciliation/status",
        headers=auth,
    )
    assert before.status_code == 200
    assert before.json()["active_records"] == 1
    assert before.json()["pending_anchors"] == 1
    assert before.json()["oldest_pending_age_seconds"] >= 0
    assert before.json()["measured_at"].endswith("Z")

    recovered = client.post(
        "/api/v2/trade/proposals/reconcile",
        headers=auth,
    )
    after = client.get(
        "/api/v2/trade/proposal-reconciliation/status",
        headers=auth,
    )
    assert recovered.status_code == 200
    assert after.status_code == 200
    assert after.json()["active_records"] == 1
    assert after.json()["pending_anchors"] == 0
    assert after.json()["oldest_pending_age_seconds"] is None


def test_web_bootstrap_drains_all_expired_proposal_archive_pages(
    tmp_path,
    monkeypatch,
):
    calls = 0

    def archive_pages(self, *, at=None, limit=1_000):
        nonlocal calls
        calls += 1
        assert at is not None
        assert limit == 1_000
        scanned = 1_000 if calls == 1 else 1
        return TradeProposalArchiveResult(
            scanned=scanned,
            archived=scanned,
            already_anchored=0,
            failure_digests=(),
        )

    monkeypatch.setattr(
        TradeProposalAuditCoordinator,
        "archive_expired",
        archive_pages,
    )

    create_app(tmp_path)

    assert calls == 2


def test_proposal_reconcile_api_exposes_bounded_structured_failures(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path, require_console_auth=True)
    _context, _proposal_value, delivery, _created, _expiry = (
        _live_proposal_delivery(tmp_path, app)
    )
    client = TestClient(app)
    accepted = client.post(
        "/api/v2/trade/federation/proposals",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )
    assert accepted.status_code == 202

    def corrupt_entry(_digest):
        raise TradeProposalInboxCorruption("receipt mismatch: " + ("x" * 500))

    monkeypatch.setattr(
        app.state.nth.trade_proposal_audit,
        "_verified_entry",
        corrupt_entry,
    )
    response = client.post(
        "/api/v2/trade/proposals/reconcile",
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["failed"] == 1
    assert body["failure_digests"] == [accepted.json()["proposal_digest"]]
    assert body["failures"][0]["digest"] == accepted.json()["proposal_digest"]
    assert body["failures"][0]["error_code"] == "inbox-corruption"
    assert body["failures"][0]["message"].startswith("receipt mismatch:")
    assert len(body["failures"][0]["message"]) == 300


def test_public_proposal_receiver_does_not_expose_local_io_paths(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path, require_console_auth=True)
    _context, _proposal_value, delivery, _created, _expiry = (
        _live_proposal_delivery(tmp_path, app)
    )

    def fail_with_private_path(*args, **kwargs):
        raise TradeProposalInboxError(
            r"write failed at X:\operator-home\identity.json"
        )

    monkeypatch.setattr(
        app.state.nth.trade_proposal_audit,
        "receive",
        fail_with_private_path,
    )
    response = TestClient(app).post(
        "/api/v2/trade/federation/proposals",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 503
    assert "operator-home" not in response.text
    assert "identity.json" not in response.text
    assert response.json()["detail"] == {
        "code": "trade-proposal-inbox-unavailable",
        "message": "Proposal receiver persistence is unavailable",
    }


def test_public_proposal_delivery_endpoint_enforces_preparse_body_limit(
    tmp_path,
):
    client = TestClient(create_app(tmp_path, require_console_auth=True))

    response = client.post(
        "/api/v2/trade/federation/proposals",
        content=b"{" + (b"x" * (256 * 1024)) + b"}",
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert "256 KiB" in response.json()["detail"]


def test_public_proposal_delivery_endpoint_has_global_crypto_budget(tmp_path):
    app = create_app(tmp_path, require_console_auth=True)
    app.state.nth.trade_proposal_delivery_global_limiter = RateLimiter(
        max_per_window=1,
        window_seconds=60,
    )
    client = TestClient(app)

    first = client.post(
        "/api/v2/trade/federation/proposals",
        content=b"{}",
        headers={"Content-Type": "application/json"},
    )
    second = client.post(
        "/api/v2/trade/federation/proposals",
        content=b"{}",
        headers={"Content-Type": "application/json"},
    )

    assert first.status_code == 400
    assert second.status_code == 429
    assert second.json()["detail"] == (
        "global trade Proposal delivery rate exceeded"
    )


def test_trade_proposal_audit_recovers_on_web_restart_without_resubmission(
    tmp_path,
    monkeypatch,
):
    first_app = create_app(tmp_path, require_console_auth=True)
    _context, proposal, delivery, _created, _expiry = _live_proposal_delivery(
        tmp_path,
        first_app,
        nonce="c" * 32,
    )

    def fail_before_append(*args, **kwargs):
        raise OSError("simulated Spine outage")

    monkeypatch.setattr(
        first_app.state.nth.spine,
        "append_unique",
        fail_before_append,
    )
    failed = TestClient(first_app).post(
        "/api/v2/trade/federation/proposals",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )
    assert failed.status_code == 503
    assert failed.json()["detail"]["retryable_without_resubmission"] is True

    restarted = create_app(tmp_path, require_console_auth=True)
    recovered = TestClient(restarted).get(
        "/api/v2/trade/proposals",
        headers={
            "Authorization": f"Bearer {restarted.state.nth_console_token}",
        },
    )

    assert recovered.status_code == 200
    assert recovered.json()["items"][0]["proposal_digest"] == (
        proposal_digest(proposal)
    )
    assert recovered.json()["items"][0]["audit_verified"] is True


def test_proposal_inbox_is_content_addressed_and_idempotent(tmp_path):
    context = _setup(tmp_path)
    proposal = _proposal(context)
    inbox = TradeProposalInbox(
        tmp_path, receiver_did=context["maker"].as_did()
    )

    first = _put_inbox(inbox, context, proposal)
    retry = inbox.put(
        _delivery(context, proposal).to_dict(),
        _intake_receipt(context, _delivery(context, proposal)).to_dict(),
    )

    assert first.appended is True
    assert retry.appended is False
    assert first.digest == proposal_digest(proposal)
    assert retry.proposal.canonical_bytes == proposal.canonical_bytes
    assert inbox.get(first.digest) == proposal
    assert inbox.list_digests() == (first.digest,)


def test_proposal_inbox_listing_has_deterministic_cursor_pagination(tmp_path):
    context = _setup(tmp_path)
    first = _proposal(context)
    body = first.to_dict()
    body.pop("proof")
    body["terms"]["requested_quantity"] = "2"
    second = _sign_proposal_body(context["taker"], body)
    inbox = TradeProposalInbox(
        tmp_path, receiver_did=context["maker"].as_did()
    )
    digests = sorted(
        _put_inbox(inbox, context, proposal).digest
        for proposal in (first, second)
    )

    assert inbox.list_digests(limit=1) == (digests[0],)
    assert inbox.list_digests(limit=1, after=digests[0]) == (digests[1],)
    assert inbox.list_digests(limit=1, after=digests[1]) == ()


def test_proposal_inbox_rejects_before_persistence(tmp_path):
    context = _setup(tmp_path)
    body = _proposal(context).to_dict()
    body.pop("proof")
    wrong_digest = "sha256:" + ("c" * 64)
    body["offer_digest"] = wrong_digest
    body["canonical_chain_digests"][-1] = wrong_digest
    proposal = _sign_proposal_body(context["taker"], body)
    inbox = TradeProposalInbox(
        tmp_path, receiver_did=context["maker"].as_did()
    )
    spine = SignedEventLog(tmp_path / "spine.jsonl", context["maker"])
    coordinator = TradeProposalAuditCoordinator(
        inbox, spine, context["maker"]
    )

    with pytest.raises(
        TradeProposalInboxRejected,
        match="offer_digest does not match local replay",
    ):
        coordinator.receive(
            _delivery(context, proposal),
            recipient_did=context["maker"].as_did(),
            offer_resolver=context["offer_store"],
            rule_resolver=context["package_store"],
            at=_AT,
        )

    assert inbox.list_digests() == ()


def test_proposal_inbox_normalizes_malformed_input_to_rejection(tmp_path):
    inbox = TradeProposalInbox(
        tmp_path,
        receiver_did=AgentIdentity.generate().as_did(),
    )

    with pytest.raises(TradeProposalInboxRejected):
        inbox.put({"not": "a Delivery"}, {"not": "an intake receipt"})

    assert inbox.list_digests() == ()


@pytest.mark.parametrize("limit_kind", ["records", "bytes"])
def test_proposal_inbox_enforces_capacity_before_second_write(
    tmp_path,
    limit_kind,
):
    context = _setup(tmp_path)
    first = _proposal(context)
    body = first.to_dict()
    body.pop("proof")
    body["terms"]["requested_quantity"] = "2"
    second = _sign_proposal_body(context["taker"], body)
    inbox = TradeProposalInbox(
        tmp_path,
        receiver_did=context["maker"].as_did(),
        max_proposals=1 if limit_kind == "records" else 10,
        max_bytes=(
            10_000_000
            if limit_kind == "records"
            else (
                len(_delivery(context, first).canonical_bytes)
                + len(
                    _intake_receipt(
                        context, _delivery(context, first)
                    ).canonical_bytes
                )
                + len(_delivery(context, second).canonical_bytes)
                + len(
                    _intake_receipt(
                        context, _delivery(context, second)
                    ).canonical_bytes
                )
                - 1
            )
        ),
    )
    _put_inbox(inbox, context, first)

    with pytest.raises(TradeProposalInboxCapacity):
        _put_inbox(inbox, context, second)

    assert inbox.list_digests() == (proposal_digest(first),)


@pytest.mark.parametrize(
    ("limit_field", "expected"),
    [("taker", "taker capacity"), ("offer", "Offer capacity")],
)
def test_proposal_inbox_enforces_principal_and_offer_quotas(
    tmp_path,
    limit_field,
    expected,
):
    context = _setup(tmp_path)
    first = _proposal(context)
    body = first.to_dict()
    body.pop("proof")
    body["terms"]["requested_quantity"] = "2"
    second = _sign_proposal_body(context["taker"], body)
    inbox = TradeProposalInbox(
        tmp_path,
        receiver_did=context["maker"].as_did(),
        max_per_taker=1 if limit_field == "taker" else 10,
        max_per_offer=1 if limit_field == "offer" else 10,
    )
    _put_inbox(inbox, context, first)

    with pytest.raises(TradeProposalInboxCapacity, match=expected):
        _put_inbox(inbox, context, second)


def test_proposal_inbox_usage_avoids_history_scan_on_each_write(
    tmp_path,
    monkeypatch,
):
    context = _setup(tmp_path)
    first = _proposal(context)
    body = first.to_dict()
    body.pop("proof")
    body["terms"]["requested_quantity"] = "2"
    second = _sign_proposal_body(context["taker"], body)
    inbox = TradeProposalInbox(
        tmp_path, receiver_did=context["maker"].as_did()
    )
    _put_inbox(inbox, context, first)

    def unexpected_scan():
        raise AssertionError("committed history was rescanned")

    monkeypatch.setattr(inbox, "_proposal_files", unexpected_scan)
    result = _put_inbox(inbox, context, second)

    assert result.appended is True


def test_proposal_inbox_usage_recovers_failed_reservation(tmp_path, monkeypatch):
    context = _setup(tmp_path)
    proposal = _proposal(context)
    inbox = TradeProposalInbox(
        tmp_path,
        receiver_did=context["maker"].as_did(),
        max_proposals=1,
    )
    original = inbox._atomic_write
    calls = 0

    def fail_first_payload(path, payload):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise TradeProposalInboxError("simulated payload outage")
        return original(path, payload)

    monkeypatch.setattr(inbox, "_atomic_write", fail_first_payload)
    with pytest.raises(TradeProposalInboxError, match="payload outage"):
        _put_inbox(inbox, context, proposal)
    monkeypatch.setattr(inbox, "_atomic_write", original)

    assert inbox.reconcile_usage() == {"records": 0, "bytes": 0}
    assert _put_inbox(inbox, context, proposal).appended is True


def test_proposal_inbox_detects_replaced_content_address(tmp_path):
    context = _setup(tmp_path)
    first = _proposal(context)
    body = first.to_dict()
    body.pop("proof")
    body["terms"]["requested_quantity"] = "2"
    replacement = _sign_proposal_body(context["taker"], body)
    inbox = TradeProposalInbox(
        tmp_path, receiver_did=context["maker"].as_did()
    )
    result = _put_inbox(inbox, context, first)
    stored_path = inbox.proposals_root / f"{result.digest[7:]}.json"
    stored_path.write_bytes(_delivery(context, replacement).canonical_bytes)

    with pytest.raises(
        TradeProposalInboxCorruption,
        match="unbound",
    ):
        inbox.get(result.digest)


def test_proposal_inbox_is_exactly_once_across_processes(tmp_path):
    context = _setup(tmp_path)
    proposal = _proposal(context)
    delivery = _delivery(context, proposal)
    receipt = _intake_receipt(context, delivery)
    process_context = multiprocessing.get_context("spawn")
    output = process_context.Queue()
    processes = [
        process_context.Process(
            target=_process_put_trade_proposal,
            args=(
                str(tmp_path),
                context["maker"].as_did(),
                delivery.to_dict(),
                receipt.to_dict(),
                output,
            ),
        )
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=30)
    try:
        assert [process.exitcode for process in processes] == [0, 0]
        results = [output.get(timeout=2) for _ in processes]
        assert all(result[0] == "ok" for result in results)
        assert sorted(result[1] for result in results) == [False, True]
        assert {result[2] for result in results} == {
            proposal_digest(proposal)
        }
        assert TradeProposalInbox(
            tmp_path,
            receiver_did=context["maker"].as_did(),
        ).list_digests() == (
            proposal_digest(proposal),
        )
    finally:
        for process in processes:
            if process.is_alive():
                process.kill()
                process.join(timeout=5)


def test_proposal_inbox_listing_uses_the_cross_process_write_lock(tmp_path):
    receiver_did = AgentIdentity.generate().as_did()
    inbox = TradeProposalInbox(tmp_path, receiver_did=receiver_did)
    process_context = multiprocessing.get_context("spawn")
    output = process_context.Queue()
    with inbox._acquire():
        process = process_context.Process(
            target=_process_list_trade_proposals,
            args=(str(tmp_path), receiver_did, output),
        )
        process.start()
        process.join(timeout=10)
    try:
        assert process.exitcode == 0
        assert output.get(timeout=2) == (
            "error",
            TradeProposalInboxBusy.__name__,
            "Proposal inbox is busy",
        )
    finally:
        if process.is_alive():
            process.kill()
            process.join(timeout=5)


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


def test_rule_bindings_reject_one_digest_under_multiple_rule_ids(tmp_path):
    proposal = _proposal(_setup(tmp_path))
    document = proposal.to_dict()
    duplicate = copy.deepcopy(document["rule_bindings"][0])
    duplicate["rule_id"] = "org.nthdao.test.second-binding"
    document["rule_bindings"] = sorted(
        [*document["rule_bindings"], duplicate],
        key=lambda item: (item["rule_id"], item["digest"]),
    )

    with pytest.raises(
        TradeAgreementRejected,
        match="one digest to multiple rule_ids",
    ):
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
    assert not order.order_id.removeprefix("nth-trade-order-sha256:").startswith(
        unrelated_prefix
    )
    unrelated = store.root / f"{unrelated_prefix}.{'0' * 64}.conflict.json"
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
    proposal_delivery = TradeProposalDelivery.from_dict(
        stored["proposal_delivery"]
    )
    proposal_intake_receipt = TradeProposalIntakeReceipt.from_dict(
        stored["proposal_intake_receipt"]
    )
    acceptance = TradeAcceptance.from_dict(stored["acceptance"])
    order = TradeOrder.from_dict(stored["order"])
    order_delivery = TradeOrderDelivery.from_dict(stored["order_delivery"])
    order_intake_receipt = TradeOrderIntakeReceipt.from_dict(
        stored["order_intake_receipt"]
    )
    assert proposal_digest(proposal) == stored["proposal_digest"]
    assert trade_proposal_delivery_digest(proposal_delivery) == (
        stored["proposal_delivery_digest"]
    )
    assert proposal_delivery.proposal == proposal
    assert trade_proposal_intake_receipt_digest(
        proposal_intake_receipt
    ) == stored["proposal_intake_receipt_digest"]
    assert verify_trade_proposal_intake_receipt(
        proposal_intake_receipt,
        delivery=proposal_delivery,
        receiver_did=proposal.to_dict()["maker_did"],
    ) == (True, "ok")
    for case in stored["proposal_delivery_verification_cases"]:
        ok, _reason = verify_trade_proposal_delivery(
            proposal_delivery,
            recipient_did=case["recipient_did"],
            at=_utc(case["at"]),
            max_ttl_seconds=case["max_ttl_seconds"],
            clock_skew_seconds=case["clock_skew_seconds"],
        )
        assert ok is case["expected_valid"], case["case"]
    assert acceptance_digest(acceptance) == stored["acceptance_digest"]
    assert trade_order_digest(order) == stored["order_digest"]
    assert trade_order_delivery_digest(order_delivery) == (
        stored["order_delivery_digest"]
    )
    assert order_delivery.order == order
    assert trade_order_intake_receipt_digest(order_intake_receipt) == (
        stored["order_intake_receipt_digest"]
    )
    assert verify_trade_order_intake_receipt(
        order_intake_receipt,
        delivery=order_delivery,
        receiver_did=order.to_dict()["taker_did"],
        audit_event_id=order_intake_receipt.to_dict()["audit_event_id"],
    ) == (True, "ok")
    order_clock_skew_receipt = TradeOrderIntakeReceipt.from_dict(
        stored["order_intake_receipt_clock_skew"]
    )
    assert trade_order_intake_receipt_digest(order_clock_skew_receipt) == (
        stored["order_intake_receipt_clock_skew_digest"]
    )
    for case in stored[
        "order_intake_receipt_clock_skew_verification_cases"
    ]:
        ok, _reason = verify_trade_order_intake_receipt(
            order_clock_skew_receipt,
            delivery=order_delivery,
            receiver_did=case["receiver_did"],
            audit_event_id=case["audit_event_id"],
            at=_utc(case["at"]),
            clock_skew_seconds=case["clock_skew_seconds"],
        )
        assert ok is case["expected_valid"], case["case"]
    for case in stored["order_delivery_verification_cases"]:
        ok, _reason = verify_trade_order_delivery(
            order_delivery,
            recipient_did=case["recipient_did"],
            at=_utc(case["at"]),
            max_ttl_seconds=case["max_ttl_seconds"],
            clock_skew_seconds=case["clock_skew_seconds"],
        )
        assert ok is case["expected_valid"], case["case"]
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
    assert stored["order_intake_acknowledgement_audit"]["event_type"] == (
        EVENT_TRADE_ORDER_INTAKE_ACKNOWLEDGED
    )
    execution_receipt = TradeExecutionReceipt.from_dict(
        stored["execution_receipt"],
        order=order,
    )
    assert (
        execution_receipt_digest(execution_receipt)
        == (stored["execution_receipt_digest"])
    )
    assert execution_receipt.to_dict()["adapter"]["adapter_digest"] == (adapter.digest)
    assert validate_execution_audit_binding(
        stored["execution_audit"]["payload"],
        receipt=execution_receipt,
        order=order,
    ) == execution_audit_payload(execution_receipt, order=order)
    execution_delivery = TradeExecutionReceiptDelivery.from_dict(
        stored["execution_receipt_delivery"],
        order=order,
    )
    execution_acknowledgement = (
        TradeExecutionReceiptAcknowledgement.from_dict(
            stored["execution_receipt_acknowledgement"]
        )
    )
    assert execution_delivery.receipt == execution_receipt
    assert trade_execution_receipt_delivery_digest(
        execution_delivery,
        order=order,
    ) == stored["execution_receipt_delivery_digest"]
    assert verify_trade_execution_receipt_delivery(
        execution_delivery,
        order=order,
        recipient_did=order.to_dict()["taker_did"],
        at=_utc("2026-08-01T02:02:00Z"),
    ) == (True, "ok")
    for case in stored[
        "execution_receipt_delivery_verification_cases"
    ]:
        ok, _reason = verify_trade_execution_receipt_delivery(
            execution_delivery,
            order=order,
            recipient_did=case["recipient_did"],
            at=_utc(case["at"]),
            max_ttl_seconds=case["max_ttl_seconds"],
            clock_skew_seconds=case["clock_skew_seconds"],
        )
        assert ok is case["expected_valid"], case["case"]
    assert trade_execution_receipt_acknowledgement_digest(
        execution_acknowledgement
    ) == stored["execution_receipt_acknowledgement_digest"]
    assert verify_trade_execution_receipt_acknowledgement(
        execution_acknowledgement,
        delivery=execution_delivery,
        order=order,
        receiver_did=order.to_dict()["taker_did"],
        audit_event_id="3" * 64,
    ) == (True, "ok")
    for case in stored[
        "execution_receipt_acknowledgement_verification_cases"
    ]:
        ok, _reason = verify_trade_execution_receipt_acknowledgement(
            execution_acknowledgement,
            delivery=execution_delivery,
            order=order,
            receiver_did=case["receiver_did"],
            audit_event_id=case["audit_event_id"],
            at=_utc(case["at"]),
            clock_skew_seconds=case["clock_skew_seconds"],
        )
        assert ok is case["expected_valid"], case["case"]
    execution_clock_skew_ack = TradeExecutionReceiptAcknowledgement.from_dict(
        stored["execution_receipt_acknowledgement_clock_skew"]
    )
    assert (
        trade_execution_receipt_acknowledgement_digest(execution_clock_skew_ack)
        == stored["execution_receipt_acknowledgement_clock_skew_digest"]
    )
    for case in stored[
        "execution_receipt_acknowledgement_clock_skew_verification_cases"
    ]:
        ok, _reason = verify_trade_execution_receipt_acknowledgement(
            execution_clock_skew_ack,
            delivery=execution_delivery,
            order=order,
            receiver_did=case["receiver_did"],
            audit_event_id=case["audit_event_id"],
            at=_utc(case["at"]),
            clock_skew_seconds=case["clock_skew_seconds"],
        )
        assert ok is case["expected_valid"], case["case"]
    receipt_review = TradeReceiptReview.from_dict(
        stored["receipt_review"],
        receipt=execution_receipt,
        order=order,
    )
    assert receipt_review_digest(receipt_review) == (
        stored["receipt_review_digest"]
    )
    disputed_receipt_review = TradeReceiptReview.from_dict(
        stored["disputed_receipt_review"],
        receipt=execution_receipt,
        order=order,
    )
    assert receipt_review_digest(
        disputed_receipt_review,
        receipt=execution_receipt,
        order=order,
    ) == stored["disputed_receipt_review_digest"]
    unresolved_dispute_statement = UnresolvedTradeDisputeStatement.from_dict(
        stored["trade_dispute_statement"],
        review=disputed_receipt_review,
        receipt=execution_receipt,
        order=order,
    )
    package_vector = stored["rule_package"]
    dispute_package = trade_rules_api.build_rule_package(
        package_vector["manifest"],
        {
            item["digest"]: bytes.fromhex(item["bytes_hex"])
            for item in package_vector["resources"]
        },
    )
    dispute_package_resolver = _StaticRulePackageResolver(dispute_package)
    dispute_statement = unresolved_dispute_statement.resolve(
        review=disputed_receipt_review,
        receipt=execution_receipt,
        order=order,
        package_resolver=dispute_package_resolver,
    )
    assert trade_dispute_statement_digest(
        dispute_statement,
        review=disputed_receipt_review,
        receipt=execution_receipt,
        order=order,
    ) == stored["trade_dispute_statement_digest"]
    for case in stored["trade_dispute_statement_verification_cases"]:
        ok, _reason = verify_trade_dispute_statement(
            dispute_statement,
            review=disputed_receipt_review,
            receipt=execution_receipt,
            order=order,
            package_resolver=dispute_package_resolver,
            at=_utc(case["at"]),
            clock_skew_seconds=case["clock_skew_seconds"],
        )
        assert ok is case["expected_valid"], case["case"]
    for case in stored["trade_dispute_statement_signed_negative_cases"]:
        signed_review = TradeReceiptReview.from_dict(
            case["signed_review"],
            receipt=execution_receipt,
            order=order,
        )
        verification_review = TradeReceiptReview.from_dict(
            case["verification_review"],
            receipt=execution_receipt,
            order=order,
        )
        signed_statement = TradeDisputeStatement.from_dict(
            case["document"],
            review=signed_review,
            receipt=execution_receipt,
            order=order,
        )
        assert signed_statement.canonical_bytes
        ok, reason = verify_trade_dispute_statement(
            case["document"],
            review=verification_review,
            receipt=execution_receipt,
            order=order,
            at=_utc(case["at"]),
            clock_skew_seconds=case["clock_skew_seconds"],
        )
        assert ok is case["expected_valid"], case["case"]
        assert case["expected_reason"] in reason, case["case"]
    fetch_request = TradeDisputeStatementFetchRequest.from_dict(
        stored["trade_dispute_statement_fetch_request"],
        review=disputed_receipt_review,
        receipt=execution_receipt,
        order=order,
    )
    assert trade_dispute_statement_fetch_request_digest(
        fetch_request,
        review=disputed_receipt_review,
        receipt=execution_receipt,
        order=order,
    ) == stored["trade_dispute_statement_fetch_request_digest"]
    for case in stored[
        "trade_dispute_statement_fetch_request_verification_cases"
    ]:
        ok, _reason = verify_trade_dispute_statement_fetch_request(
            fetch_request,
            review=disputed_receipt_review,
            receipt=execution_receipt,
            order=order,
            responder_did=case["responder_did"],
            at=_utc(case["at"]),
            max_ttl_seconds=case["max_ttl_seconds"],
            clock_skew_seconds=case["clock_skew_seconds"],
        )
        assert ok is case["expected_valid"], case["case"]
    fetch_response = TradeDisputeStatementFetchResponse.from_dict(
        stored["trade_dispute_statement_fetch_response"],
        request=fetch_request,
        review=disputed_receipt_review,
        receipt=execution_receipt,
        order=order,
    )
    assert fetch_response.statement.canonical_bytes == (
        unresolved_dispute_statement.canonical_bytes
    )
    assert trade_dispute_statement_fetch_response_digest(
        fetch_response,
        request=fetch_request,
        review=disputed_receipt_review,
        receipt=execution_receipt,
        order=order,
    ) == stored["trade_dispute_statement_fetch_response_digest"]
    for case in stored[
        "trade_dispute_statement_fetch_response_verification_cases"
    ]:
        ok, _reason = verify_trade_dispute_statement_fetch_response(
            fetch_response,
            request=fetch_request,
            review=disputed_receipt_review,
            receipt=execution_receipt,
            order=order,
            at=_utc(case["at"]),
            max_ttl_seconds=case["max_ttl_seconds"],
            clock_skew_seconds=case["clock_skew_seconds"],
        )
        assert ok is case["expected_valid"], case["case"]
    failure_audit = stored["trade_dispute_statement_creation_failure_audit"]
    assert failure_audit["event_type"] == (
        trade_rules_api.EVENT_TRADE_DISPUTE_STATEMENT_CREATE_ATTEMPT_FAILED
    )
    assert (
        trade_rules_api.validate_trade_dispute_statement_create_failure_payload(
            failure_audit["payload"]
        )
        == failure_audit["payload"]
    )
    for case in stored[
        "trade_dispute_statement_creation_failure_negative_cases"
    ]:
        with pytest.raises(
            trade_rules_api.TradeDisputeStatementAuditError,
            match=case["expected_reason"],
        ):
            trade_rules_api.validate_trade_dispute_statement_create_failure_payload(
                case["payload"]
            )
    reservation = stored["trade_dispute_statement_creation_reservation"]
    assert reservation["event_type"] == (
        trade_rules_api.EVENT_TRADE_DISPUTE_STATEMENT_CREATE_RESERVED
    )
    assert trade_rules_api.trade_dispute_statement_create_reservation_payload(
        **reservation["input"]
    ) == reservation["payload"]
    assert trade_rules_api.validate_trade_dispute_statement_create_reservation_binding(
        reservation["payload"],
        **reservation["input"],
    ) == reservation["payload"]

    graph_vector = stored["trade_dispute_statement_graph_snapshot"]
    graph_records = [
        (
            item["statement_digest"],
            TradeDisputeStatement.from_dict(
                item["statement"],
                review=disputed_receipt_review,
                receipt=execution_receipt,
                order=order,
                package_resolver=dispute_package_resolver,
            ),
        )
        for item in graph_vector["input"]["records"]
    ]
    graph_projection = trade_rules_api.project_trade_dispute_graph(
        graph_records,
        known_review_digests=graph_vector["input"]["known_review_digests"],
        expected_review_digest=(
            graph_vector["input"]["expected_review_digest"]
        ),
        expected_dispute_id=graph_vector["input"]["expected_dispute_id"],
        clock_skew_seconds=graph_vector["input"]["clock_skew_seconds"],
    )
    assert graph_projection.to_dict() == graph_vector["projection"]
    page_vector = stored["trade_dispute_statement_page_snapshot"]
    assert page_vector["snapshot_token"] == graph_projection.snapshot_token
    assert page_vector["items"] == [graph_vector["input"]["records"][0]]
    assert re.fullmatch(
        r"v1:[0-9a-f]{64}:[0-9a-f]{64}",
        page_vector["next_cursor"],
    )

    context_input = stored["trade_dispute_statement_graph_context_input"]
    context_statement = TradeDisputeStatement.from_dict(
        context_input["record"]["statement"],
        review=disputed_receipt_review,
        receipt=execution_receipt,
        order=order,
    )
    context_tokens = []
    for case in stored["trade_dispute_statement_graph_context_cases"]:
        projection = trade_rules_api.project_trade_dispute_graph(
            [(context_input["record"]["statement_digest"], context_statement)],
            known_review_digests=case["known_review_digests"],
            expected_review_digest=context_input["expected_review_digest"],
            expected_dispute_id=context_input["expected_dispute_id"],
            clock_skew_seconds=context_input["clock_skew_seconds"],
        )
        assert projection.to_dict() == case["projection"], case["case"]
        context_tokens.append(projection.snapshot_token)
    assert len(set(context_tokens)) == len(context_tokens)
    receipt_review_delivery = TradeReceiptReviewDelivery.from_dict(
        stored["receipt_review_delivery"],
        receipt=execution_receipt,
        order=order,
    )
    receipt_review_acknowledgement = (
        TradeReceiptReviewAcknowledgement.from_dict(
            stored["receipt_review_acknowledgement"]
        )
    )
    assert receipt_review_delivery.review == receipt_review
    assert trade_receipt_review_delivery_digest(
        receipt_review_delivery,
        receipt=execution_receipt,
        order=order,
    ) == stored["receipt_review_delivery_digest"]
    for case in stored["receipt_review_delivery_verification_cases"]:
        ok, _reason = verify_trade_receipt_review_delivery(
            receipt_review_delivery,
            receipt=execution_receipt,
            order=order,
            recipient_did=case["recipient_did"],
            at=_utc(case["at"]),
            max_ttl_seconds=case["max_ttl_seconds"],
            clock_skew_seconds=case["clock_skew_seconds"],
        )
        assert ok is case["expected_valid"], case["case"]
    assert trade_receipt_review_acknowledgement_digest(
        receipt_review_acknowledgement
    ) == stored["receipt_review_acknowledgement_digest"]
    for case in stored[
        "receipt_review_acknowledgement_verification_cases"
    ]:
        ok, _reason = verify_trade_receipt_review_acknowledgement(
            receipt_review_acknowledgement,
            delivery=receipt_review_delivery,
            receipt=execution_receipt,
            order=order,
            receiver_did=case["receiver_did"],
            audit_event_id=case["audit_event_id"],
            at=_utc(case["at"]),
            clock_skew_seconds=case["clock_skew_seconds"],
        )
        assert ok is case["expected_valid"], case["case"]
    receipt_review_clock_skew_ack = (
        TradeReceiptReviewAcknowledgement.from_dict(
            stored["receipt_review_acknowledgement_clock_skew"]
        )
    )
    assert trade_receipt_review_acknowledgement_digest(
        receipt_review_clock_skew_ack
    ) == stored["receipt_review_acknowledgement_clock_skew_digest"]
    for case in stored[
        "receipt_review_acknowledgement_clock_skew_verification_cases"
    ]:
        ok, _reason = verify_trade_receipt_review_acknowledgement(
            receipt_review_clock_skew_ack,
            delivery=receipt_review_delivery,
            receipt=execution_receipt,
            order=order,
            receiver_did=case["receiver_did"],
            audit_event_id=case["audit_event_id"],
            at=_utc(case["at"]),
            clock_skew_seconds=case["clock_skew_seconds"],
        )
        assert ok is case["expected_valid"], case["case"]
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
    package_bundle = stored["rule_package_bundle"]
    parsed_bundle = parse_rule_package_bundle(
        package_bundle,
        expected_offer_digest=order.to_dict()["offer_digest"],
        expected_package_digest=package_vector["digest"],
        expected_offer_publisher_did=stored["proposal"]["offer_publisher_did"],
    )
    assert parsed_bundle.digest == package_vector["digest"]
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
            source="local",
        )
        assert installed.digest == package_vector["digest"]
        adapter_policy = TradeExecutionAdapterPolicy(
            accepted_adapter_digests=stored["adapter_policy"][
                "accepted_adapter_digests"
            ],
            allowed_execution_modes=stored["adapter_policy"]["allowed_execution_modes"],
            allowed_permissions=stored["adapter_policy"]["allowed_permissions"],
        )
        content_resolver = trade_rules_api.MappingTradeExecutionContentResolver(
            {
                item["digest"]: bytes.fromhex(item["bytes_hex"])
                for item in stored["execution_content"]
            }
        )
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
        verify_trade_receipt_review_under_policy(
            receipt_review,
            receipt=execution_receipt,
            order=order,
            package_resolver=package_store,
            verifier_policy=receipt_review_delivery.verifier_policy,
            adapter_resolver=_AdapterResolver(
                adapter,
                artifacts={
                    adapter.to_dict()["artifact_digest"]: adapter_artifact
                },
            ),
            adapter_policy=receipt_review_delivery.adapter_policy,
            content_resolver=content_resolver,
            schema_validator=JsonSchema202012Validator(),
        )
    assert replayed.to_dict() == stored["expected_execution_readiness"]


def test_negative_agreement_vectors_fail_closed():
    stored = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    parsers = {
        "proposal": TradeProposal.from_dict,
        "proposal_delivery": TradeProposalDelivery.from_dict,
        "proposal_intake_receipt": TradeProposalIntakeReceipt.from_dict,
        "acceptance": TradeAcceptance.from_dict,
        "order": TradeOrder.from_dict,
        "order_delivery": TradeOrderDelivery.from_dict,
        "order_intake_receipt": TradeOrderIntakeReceipt.from_dict,
        "order_audit_payload": validate_order_audit_payload,
        "execution_receipt": lambda document: (
            TradeExecutionReceipt.from_dict(
                document,
                order=stored["order"],
            )
        ),
        "execution_receipt_delivery": lambda document: (
            TradeExecutionReceiptDelivery.from_dict(
                document,
                order=stored["order"],
            )
        ),
        "execution_receipt_acknowledgement": (
            TradeExecutionReceiptAcknowledgement.from_dict
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
        "trade_dispute_statement": lambda document: (
            TradeDisputeStatement.from_dict(
                document,
                review=stored["disputed_receipt_review"],
                receipt=stored["execution_receipt"],
                order=stored["order"],
            )
        ),
        "trade_dispute_statement_delivery": lambda document: (
            TradeDisputeStatementDelivery.from_dict(
                document,
                review=stored["disputed_receipt_review"],
                receipt=stored["execution_receipt"],
                order=stored["order"],
            )
        ),
        "trade_dispute_statement_acknowledgement": (
            TradeDisputeStatementAcknowledgement.from_dict
        ),
        "trade_dispute_statement_fetch_request": lambda document: (
            TradeDisputeStatementFetchRequest.from_dict(
                document,
                review=stored["disputed_receipt_review"],
                receipt=stored["execution_receipt"],
                order=stored["order"],
            )
        ),
        "trade_dispute_statement_fetch_response": lambda document: (
            TradeDisputeStatementFetchResponse.from_dict(
                document,
                request=stored["trade_dispute_statement_fetch_request"],
                review=stored["disputed_receipt_review"],
                receipt=stored["execution_receipt"],
                order=stored["order"],
            )
        ),
        "receipt_review_delivery": lambda document: (
            TradeReceiptReviewDelivery.from_dict(
                document,
                receipt=stored["execution_receipt"],
                order=stored["order"],
            )
        ),
        "receipt_review_acknowledgement": (
            TradeReceiptReviewAcknowledgement.from_dict
        ),
        "receipt_review_audit_binding": lambda document: (
            validate_receipt_review_audit_binding(
                document,
                review=stored["receipt_review"],
                receipt=stored["execution_receipt"],
                order=stored["order"],
            )
        ),
        "rule_package_bundle": lambda document: parse_rule_package_bundle(
            document,
            expected_offer_digest=stored["rule_package_bundle"][
                "offer_digest"
            ],
            expected_package_digest=stored["rule_package"]["digest"],
            expected_offer_publisher_did=stored["proposal"][
                "offer_publisher_did"
            ],
        ),
    }

    assert "rule-package-bundle-binding-wrong-signer" in {
        case["case"] for case in stored["negative_cases"]
    }
    for case in stored["negative_cases"]:
        assert case["expected_valid"] is False
        with pytest.raises(
            (
                TradeAgreementRejected,
                TradeProposalDeliveryRejected,
                TradeProposalIntakeReceiptRejected,
                TradeOrderAuditError,
                TradeOrderRejected,
                TradeOrderDeliveryRejected,
                TradeOrderIntakeReceiptRejected,
                TradeExecutionReceiptRejected,
                TradeExecutionReceiptDeliveryRejected,
                TradeExecutionReceiptAcknowledgementRejected,
                TradeExecutionAdapterRejected,
                TradeExecutionAuditError,
                TradeReceiptReviewRejected,
                TradeReceiptReviewDeliveryRejected,
                TradeReceiptReviewAcknowledgementRejected,
                TradeReceiptReviewAuditError,
                TradeDisputeStatementRejected,
                TradeDisputeStatementDeliveryRejected,
                TradeDisputeStatementAcknowledgementRejected,
                TradeDisputeStatementFetchRequestRejected,
                TradeDisputeStatementFetchResponseRejected,
                RulePackageBundleRejected,
            )
        ):
            parsers[case["target"]](case["document"])


def test_agreement_schemas_are_packaged_and_match_wire_constants():
    proposal = json.loads(PROPOSAL_SCHEMA_PATH.read_text(encoding="utf-8"))
    proposal_delivery = json.loads(
        PROPOSAL_DELIVERY_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    proposal_intake_receipt = json.loads(
        PROPOSAL_INTAKE_RECEIPT_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    acceptance = json.loads(
        ACCEPTANCE_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    order = json.loads(ORDER_SCHEMA_PATH.read_text(encoding="utf-8"))
    order_delivery = json.loads(
        ORDER_DELIVERY_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    order_intake_receipt = json.loads(
        ORDER_INTAKE_RECEIPT_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    order_audit = json.loads(
        ORDER_AUDIT_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    order_intake_acknowledgement_audit = json.loads(
        ORDER_INTAKE_ACKNOWLEDGEMENT_AUDIT_SCHEMA_PATH.read_text(
            encoding="utf-8"
        )
    )
    execution_receipt = json.loads(
        EXECUTION_RECEIPT_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    execution_receipt_delivery = json.loads(
        EXECUTION_RECEIPT_DELIVERY_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    execution_receipt_acknowledgement = json.loads(
        EXECUTION_RECEIPT_ACKNOWLEDGEMENT_SCHEMA_PATH.read_text(
            encoding="utf-8"
        )
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
    receipt_review_delivery = json.loads(
        RECEIPT_REVIEW_DELIVERY_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    receipt_review_acknowledgement = json.loads(
        RECEIPT_REVIEW_ACKNOWLEDGEMENT_SCHEMA_PATH.read_text(
            encoding="utf-8"
        )
    )
    receipt_review_audit = json.loads(
        RECEIPT_REVIEW_AUDIT_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    receipt_review_conflict_audit = json.loads(
        RECEIPT_REVIEW_CONFLICT_AUDIT_SCHEMA_PATH.read_text(
            encoding="utf-8"
        )
    )
    trade_dispute_statement = json.loads(
        TRADE_DISPUTE_STATEMENT_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    dispute_statement_fetch_request = json.loads(
        DISPUTE_STATEMENT_FETCH_REQUEST_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    dispute_statement_fetch_response = json.loads(
        DISPUTE_STATEMENT_FETCH_RESPONSE_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    dispute_statement_fetch_audit = json.loads(
        DISPUTE_STATEMENT_FETCH_AUDIT_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    rule_package_bundle = json.loads(
        RULE_PACKAGE_BUNDLE_SCHEMA_PATH.read_text(encoding="utf-8")
    )

    assert proposal["$schema"].endswith("2020-12/schema")
    assert receipt_review_delivery["properties"]["proof"]["$ref"].endswith("proof")
    assert (
        receipt_review_delivery["properties"]["review"]["$ref"]
        == (receipt_review["$id"])
    )
    assert (
        receipt_review_acknowledgement["properties"]["status"]["const"]
        == "review-retained-verified"
    )
    assert rule_package_bundle["properties"]["kind"]["const"] == (
        RULE_PACKAGE_BUNDLE_KIND
    )
    assert rule_package_bundle["properties"]["protocol_version"][
        "const"
    ] == RULE_PACKAGE_BUNDLE_PROTOCOL_VERSION
    assert rule_package_bundle["properties"]["manifest"]["$ref"] == (
        "urn:nth-dao:schema:trade-rule-manifest:1"
    )
    assert rule_package_bundle["properties"]["resources"][
        "maxItems"
    ] == 128
    assert proposal["properties"]["kind"]["const"] == (
        "nth.dao.trade.proposal"
    )
    assert proposal["properties"]["protocol_version"]["const"] == "1"
    assert "taker_policy" in proposal["required"]
    assert proposal["properties"]["taker_policy"]["$ref"].endswith("policy")
    assert proposal["properties"]["rule_bindings"]["$ref"].endswith(
        "ruleBindings"
    )
    assert proposal_delivery["properties"]["kind"]["const"] == (
        "nth.dao.trade.proposal-delivery"
    )
    assert proposal_delivery["properties"]["proposal"]["$ref"] == (proposal["$id"])
    assert (
        proposal_delivery["properties"]["proof"]["properties"]["proof_purpose"]["const"]
        == "tradeProposalDelivery"
    )
    assert proposal_intake_receipt["properties"]["kind"]["const"] == (
        "nth.dao.trade.proposal-intake-receipt"
    )
    assert (
        proposal_intake_receipt["properties"]["proof"]["properties"]["proof_purpose"][
            "const"
        ]
        == "tradeProposalIntakeReceipt"
    )
    assert acceptance["properties"]["kind"]["const"] == ("nth.dao.trade.acceptance")
    assert "maker_policy" in acceptance["required"]
    assert acceptance["properties"]["proof"]["allOf"][1]["properties"][
        "proof_purpose"
    ]["const"] == "tradeAcceptance"
    assert order["properties"]["kind"]["const"] == "nth.dao.trade.order"
    assert order_delivery["properties"]["kind"]["const"] == (
        "nth.dao.trade.order-delivery"
    )
    assert order_delivery["properties"]["order"]["$ref"] == order["$id"]
    assert order_delivery["properties"]["proof"]["properties"][
        "proof_purpose"
    ]["const"] == "tradeOrderDelivery"
    assert order_intake_receipt["properties"]["kind"]["const"] == (
        "nth.dao.trade.order-intake-receipt"
    )
    assert order_intake_receipt["properties"]["proof"]["properties"][
        "proof_purpose"
    ]["const"] == "tradeOrderIntakeReceipt"
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
    assert order_intake_acknowledgement_audit["additionalProperties"] is False
    assert order_intake_acknowledgement_audit["properties"][
        "protocol_version"
    ]["const"] == "1"
    assert "retention claim" in order_intake_acknowledgement_audit[
        "$comment"
    ]
    assert execution_receipt["additionalProperties"] is False
    assert execution_receipt["properties"]["kind"]["const"] == (
        "nth.dao.trade.execution-receipt"
    )
    assert execution_receipt["properties"]["proof"]["$ref"].endswith("/proof")
    assert (
        execution_receipt["$defs"]["proof"]["properties"]["proof_purpose"]["const"]
        == "tradeExecution"
    )
    assert execution_receipt_delivery["properties"]["kind"]["const"] == (
        "nth.dao.trade.execution-receipt-delivery"
    )
    assert execution_receipt_delivery["properties"]["receipt"]["$ref"] == (
        execution_receipt["$id"]
    )
    assert execution_receipt_delivery["properties"]["proof"]["properties"][
        "proof_purpose"
    ]["const"] == "tradeExecutionReceiptDelivery"
    assert execution_receipt_acknowledgement["properties"]["kind"][
        "const"
    ] == "nth.dao.trade.execution-receipt-acknowledgement"
    assert execution_receipt_acknowledgement["properties"]["status"][
        "const"
    ] == "retained-verified"
    assert execution_audit["additionalProperties"] is False
    assert execution_audit["properties"]["protocol_version"]["const"] == "1"
    assert execution_audit["properties"]["execution_id"][
        "pattern"
    ].startswith("^nth-trade-execution-sha256:")
    assert execution_audit["$id"] == (
        "https://nthdao.org/schemas/trade-execution-audit-payload-v1.json"
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
    assert trade_dispute_statement["additionalProperties"] is False
    assert trade_dispute_statement["properties"]["kind"]["const"] == (
        "nth.dao.trade.dispute-statement"
    )
    assert trade_dispute_statement["$defs"]["proof"]["properties"][
        "proof_purpose"
    ]["const"] == "tradeDisputeStatement"
    assert dispute_statement_fetch_request["properties"]["kind"]["const"] == (
        "nth.dao.trade.dispute-statement-fetch-request"
    )
    assert dispute_statement_fetch_request["$defs"]["proof"]["properties"][
        "proof_purpose"
    ]["const"] == "tradeDisputeStatementFetchRequest"
    assert dispute_statement_fetch_response["properties"]["statement"]["$ref"] == (
        trade_dispute_statement["$id"]
    )
    assert (
        dispute_statement_fetch_response["$defs"]["proof"]["properties"][
            "proof_purpose"
        ]["const"]
        == "tradeDisputeStatementFetchResponse"
    )
    assert dispute_statement_fetch_audit["properties"]["status"]["const"] == ("served")


def test_trade_dispute_statement_schema_validates_public_vector():
    jsonschema = pytest.importorskip("jsonschema")
    stored = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    schema = json.loads(
        TRADE_DISPUTE_STATEMENT_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    validator = jsonschema.validators.validator_for(schema)
    validator.check_schema(schema)
    validator(schema).validate(stored["trade_dispute_statement"])
    for case in stored["trade_dispute_statement_signed_negative_cases"]:
        validator(schema).validate(case["document"])

    minimal_rule_id = copy.deepcopy(stored["trade_dispute_statement"])
    minimal_rule_id["rule_action"]["rule_id"] = "a.b"
    validator(schema).validate(minimal_rule_id)

    unknown = copy.deepcopy(stored["trade_dispute_statement"])
    unknown["unexpected"] = True
    with pytest.raises(jsonschema.ValidationError):
        validator(schema).validate(unknown)

    empty_response = copy.deepcopy(stored["trade_dispute_statement"])
    empty_response["reason_codes"] = []
    with pytest.raises(jsonschema.ValidationError):
        validator(schema).validate(empty_response)

    missing_claim = copy.deepcopy(stored["trade_dispute_statement"])
    missing_claim["claim"] = None
    with pytest.raises(jsonschema.ValidationError):
        validator(schema).validate(missing_claim)

    evidence_with_claim = copy.deepcopy(stored["trade_dispute_statement"])
    evidence_with_claim["statement_type"] = "evidence"
    evidence_with_claim["reason_codes"] = []
    with pytest.raises(jsonschema.ValidationError):
        validator(schema).validate(evidence_with_claim)

    evidence_statement = copy.deepcopy(stored["trade_dispute_statement"])
    evidence_statement["statement_type"] = "evidence"
    evidence_statement["reason_codes"] = []
    evidence_statement["claim"] = None
    validator(schema).validate(evidence_statement)

    remedy_statement = copy.deepcopy(stored["trade_dispute_statement"])
    remedy_statement["statement_type"] = "remedy-proposal"
    validator(schema).validate(remedy_statement)


def test_dispute_statement_fetch_schemas_validate_public_vectors():
    jsonschema = pytest.importorskip("jsonschema")
    referencing = pytest.importorskip("referencing")
    stored = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    statement_schema = json.loads(
        TRADE_DISPUTE_STATEMENT_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    request_schema = json.loads(
        DISPUTE_STATEMENT_FETCH_REQUEST_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    response_schema = json.loads(
        DISPUTE_STATEMENT_FETCH_RESPONSE_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    audit_schema = json.loads(
        DISPUTE_STATEMENT_FETCH_AUDIT_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    request_validator = jsonschema.validators.validator_for(request_schema)
    response_validator = jsonschema.validators.validator_for(response_schema)
    audit_validator = jsonschema.validators.validator_for(audit_schema)
    request_validator.check_schema(request_schema)
    response_validator.check_schema(response_schema)
    audit_validator.check_schema(audit_schema)
    request_validator(request_schema).validate(
        stored["trade_dispute_statement_fetch_request"]
    )
    registry = referencing.Registry().with_resource(
        statement_schema["$id"],
        referencing.Resource.from_contents(statement_schema),
    )
    response_validator(response_schema, registry=registry).validate(
        stored["trade_dispute_statement_fetch_response"]
    )
    audit_validator(audit_schema).validate(
        stored["trade_dispute_statement_fetch_audit"]["payload"]
    )

    malformed_request = copy.deepcopy(
        stored["trade_dispute_statement_fetch_request"]
    )
    malformed_request["unexpected"] = True
    with pytest.raises(jsonschema.ValidationError):
        request_validator(request_schema).validate(malformed_request)

    malformed_response = copy.deepcopy(
        stored["trade_dispute_statement_fetch_response"]
    )
    malformed_response["statement"]["unexpected"] = True
    with pytest.raises(jsonschema.ValidationError):
        response_validator(response_schema, registry=registry).validate(
            malformed_response
        )
    malformed_audit = copy.deepcopy(
        stored["trade_dispute_statement_fetch_audit"]["payload"]
    )
    malformed_audit["status"] = "settled"
    with pytest.raises(jsonschema.ValidationError):
        audit_validator(audit_schema).validate(malformed_audit)


def test_proposal_transport_schemas_resolve_and_validate_public_vectors():
    jsonschema = pytest.importorskip("jsonschema")
    referencing = pytest.importorskip("referencing")
    stored = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    proposal_schema = json.loads(
        PROPOSAL_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    delivery_schema = json.loads(
        PROPOSAL_DELIVERY_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    intake_schema = json.loads(
        PROPOSAL_INTAKE_RECEIPT_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    registry = referencing.Registry().with_resource(
        proposal_schema["$id"],
        referencing.Resource.from_contents(proposal_schema),
    )
    delivery_validator = jsonschema.validators.validator_for(delivery_schema)
    intake_validator = jsonschema.validators.validator_for(intake_schema)
    delivery_validator.check_schema(delivery_schema)
    intake_validator.check_schema(intake_schema)
    delivery_validator(delivery_schema, registry=registry).validate(
        stored["proposal_delivery"]
    )
    intake_validator(intake_schema).validate(
        stored["proposal_intake_receipt"]
    )

    malformed = copy.deepcopy(stored["proposal_delivery"])
    malformed["proposal"]["unexpected"] = True
    with pytest.raises(jsonschema.ValidationError):
        delivery_validator(delivery_schema, registry=registry).validate(
            malformed
        )


def test_order_acknowledgement_audit_schema_validates_public_vector():
    jsonschema = pytest.importorskip("jsonschema")
    stored = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    schema = json.loads(
        ORDER_INTAKE_ACKNOWLEDGEMENT_AUDIT_SCHEMA_PATH.read_text(
            encoding="utf-8"
        )
    )
    validator = jsonschema.validators.validator_for(schema)
    validator.check_schema(schema)
    payload = stored["order_intake_acknowledgement_audit"]["payload"]
    validator(schema).validate(payload)

    malformed = copy.deepcopy(payload)
    malformed["unexpected"] = True
    with pytest.raises(jsonschema.ValidationError):
        validator(schema).validate(malformed)


def test_execution_schemas_validate_public_vectors_and_reject_shape_drift():
    jsonschema = pytest.importorskip("jsonschema")
    referencing = pytest.importorskip("referencing")
    stored = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    receipt_schema = json.loads(
        EXECUTION_RECEIPT_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    delivery_schema = json.loads(
        EXECUTION_RECEIPT_DELIVERY_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    acknowledgement_schema = json.loads(
        EXECUTION_RECEIPT_ACKNOWLEDGEMENT_SCHEMA_PATH.read_text(
            encoding="utf-8"
        )
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
    review_delivery_schema = json.loads(
        RECEIPT_REVIEW_DELIVERY_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    review_acknowledgement_schema = json.loads(
        RECEIPT_REVIEW_ACKNOWLEDGEMENT_SCHEMA_PATH.read_text(
            encoding="utf-8"
        )
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
    delivery_validator = jsonschema.validators.validator_for(delivery_schema)
    acknowledgement_validator = jsonschema.validators.validator_for(
        acknowledgement_schema
    )
    adapter_validator = jsonschema.validators.validator_for(adapter_schema)
    adapter_policy_validator = jsonschema.validators.validator_for(
        adapter_policy_schema
    )
    audit_validator = jsonschema.validators.validator_for(audit_schema)
    review_validator = jsonschema.validators.validator_for(review_schema)
    review_delivery_validator = jsonschema.validators.validator_for(
        review_delivery_schema
    )
    review_acknowledgement_validator = jsonschema.validators.validator_for(
        review_acknowledgement_schema
    )
    review_audit_validator = jsonschema.validators.validator_for(
        review_audit_schema
    )
    review_conflict_audit_validator = jsonschema.validators.validator_for(
        review_conflict_audit_schema
    )
    receipt_validator.check_schema(receipt_schema)
    delivery_validator.check_schema(delivery_schema)
    acknowledgement_validator.check_schema(acknowledgement_schema)
    adapter_validator.check_schema(adapter_schema)
    adapter_policy_validator.check_schema(adapter_policy_schema)
    audit_validator.check_schema(audit_schema)
    review_validator.check_schema(review_schema)
    review_delivery_validator.check_schema(review_delivery_schema)
    review_acknowledgement_validator.check_schema(
        review_acknowledgement_schema
    )
    review_audit_validator.check_schema(review_audit_schema)
    review_conflict_audit_validator.check_schema(
        review_conflict_audit_schema
    )

    receipt_validator(receipt_schema).validate(
        stored["execution_receipt"]
    )
    registry = referencing.Registry().with_resource(
        receipt_schema["$id"],
        referencing.Resource.from_contents(receipt_schema),
    )
    delivery_validator(delivery_schema, registry=registry).validate(
        stored["execution_receipt_delivery"]
    )
    acknowledgement_validator(acknowledgement_schema).validate(
        stored["execution_receipt_acknowledgement"]
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
    review_registry = referencing.Registry()
    for referenced_schema in (
        review_schema,
        json.loads(
            PROPOSAL_SCHEMA_PATH.read_text(encoding="utf-8")
        ),
        adapter_policy_schema,
    ):
        review_registry = review_registry.with_resource(
            referenced_schema["$id"],
            referencing.Resource.from_contents(referenced_schema),
        )
    review_delivery_validator(
        review_delivery_schema,
        registry=review_registry,
    ).validate(stored["receipt_review_delivery"])
    review_acknowledgement_validator(
        review_acknowledgement_schema
    ).validate(stored["receipt_review_acknowledgement"])
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
    bad_delivery = copy.deepcopy(stored["execution_receipt_delivery"])
    bad_delivery["unexpected"] = True
    with pytest.raises(jsonschema.ValidationError):
        delivery_validator(delivery_schema, registry=registry).validate(
            bad_delivery
        )
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
    bad_review_delivery = copy.deepcopy(stored["receipt_review_delivery"])
    bad_review_delivery["verifier_policy"]["unexpected"] = True
    with pytest.raises(jsonschema.ValidationError):
        review_delivery_validator(
            review_delivery_schema,
            registry=review_registry,
        ).validate(bad_review_delivery)


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


def _order_delivery(context):
    return create_trade_order_delivery(
        context["maker"],
        order=_order(context),
        created_at="2026-08-01T01:01:00Z",
        not_after="2026-08-01T01:06:00Z",
        nonce="ab" * 16,
        now=_utc("2026-08-01T01:01:00Z"),
    )


def test_order_delivery_round_trip_binds_complete_order_and_destination(
    tmp_path,
):
    context = _setup(tmp_path)
    delivery = _order_delivery(context)

    assert TradeOrderDelivery.from_json(delivery.canonical_bytes) == delivery
    assert delivery.order == _order(context)
    assert trade_order_delivery_digest(delivery).startswith("sha256:")
    assert verify_trade_order_delivery(
        delivery,
        recipient_did=context["taker"].as_did(),
        at=_utc("2026-08-01T01:03:00Z"),
    ) == (True, "ok")


def test_order_delivery_rejects_role_and_embedded_order_tampering(tmp_path):
    context = _setup(tmp_path)
    document = _order_delivery(context).to_dict()
    document["recipient_did"] = AgentIdentity.generate().as_did()
    with pytest.raises(
        TradeOrderDeliveryRejected,
        match="recipient_did does not match Order taker",
    ):
        TradeOrderDelivery.from_dict(document)

    document = _order_delivery(context).to_dict()
    document["order"]["snapshot"]["proposal"]["terms"][
        "requested_quantity"
    ] = "999"
    with pytest.raises(TradeOrderDeliveryRejected, match="embedded Order"):
        TradeOrderDelivery.from_dict(document)


def test_order_delivery_rejects_wrong_recipient_and_expired_window(tmp_path):
    context = _setup(tmp_path)
    delivery = _order_delivery(context)

    ok, reason = verify_trade_order_delivery(
        delivery,
        recipient_did=AgentIdentity.generate().as_did(),
        at=_utc("2026-08-01T01:03:00Z"),
    )
    assert ok is False
    assert "recipient does not match" in reason
    ok, reason = verify_trade_order_delivery(
        delivery,
        recipient_did=context["taker"].as_did(),
        at=_utc("2026-08-01T01:20:01Z"),
    )
    assert ok is False
    assert "expired" in reason


def test_order_delivery_creation_rejects_wrong_signer_and_long_ttl(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    with pytest.raises(
        TradeOrderDeliveryRejected,
        match="signer does not match Order maker",
    ):
        create_trade_order_delivery(
            context["taker"],
            order=order,
            created_at="2026-08-01T01:01:00Z",
            not_after="2026-08-01T01:06:00Z",
            now=_utc("2026-08-01T01:01:00Z"),
        )
    with pytest.raises(
        TradeOrderDeliveryRejected,
        match="lifetime exceeds",
    ):
        create_trade_order_delivery(
            context["maker"],
            order=order,
            created_at="2026-08-01T01:01:00Z",
            not_after="2026-08-01T01:20:00Z",
            now=_utc("2026-08-01T01:01:00Z"),
        )


def test_order_delivery_rejects_odd_length_hex_nonce(tmp_path):
    context = _setup(tmp_path)

    with pytest.raises(
        TradeOrderDeliveryRejected,
        match="16 to 64 bytes",
    ):
        create_trade_order_delivery(
            context["maker"],
            order=_order(context),
            created_at="2026-08-01T01:01:00Z",
            not_after="2026-08-01T01:06:00Z",
            nonce="a" * 33,
            now=_utc("2026-08-01T01:01:00Z"),
        )


def test_order_delivery_signature_domain_rejects_envelope_mutation(tmp_path):
    context = _setup(tmp_path)
    document = _order_delivery(context).to_dict()
    document["not_after"] = "2026-08-01T01:05:00Z"

    with pytest.raises(TradeOrderDeliveryRejected, match="signature invalid"):
        TradeOrderDelivery.from_dict(document)


def test_order_delivery_revalidates_preconstructed_instances(tmp_path):
    context = _setup(tmp_path)
    delivery = _order_delivery(context)
    document = delivery.to_dict()
    document["proof"]["proof_value"] = "A" * 86
    forged = TradeOrderDelivery._create(
        trade_rules_api.trade_canonical_json(document),
        delivery.order,
    )

    ok, reason = verify_trade_order_delivery(
        forged,
        recipient_did=context["taker"].as_did(),
        at=_utc("2026-08-01T01:03:00Z"),
    )

    assert ok is False
    assert reason == "signature invalid"
    with pytest.raises(TradeOrderDeliveryRejected, match="signature invalid"):
        trade_order_delivery_digest(forged)


def test_order_intake_receipt_revalidates_and_binds_spine_event(tmp_path):
    context = _setup(tmp_path)
    delivery = _order_delivery(context)
    receipt = create_trade_order_intake_receipt(
        context["taker"],
        delivery=delivery,
        received_at="2026-08-01T01:03:00Z",
        audit_event_id="1" * 64,
    )

    assert verify_trade_order_intake_receipt(
        receipt,
        delivery=delivery,
        receiver_did=context["taker"].as_did(),
        audit_event_id="1" * 64,
    ) == (True, "ok")
    ok, reason = verify_trade_order_intake_receipt(
        receipt,
        delivery=delivery,
        receiver_did=context["taker"].as_did(),
        audit_event_id="2" * 64,
    )
    assert ok is False
    assert "audit_event_id" in reason

    document = receipt.to_dict()
    document["proof"]["proof_value"] = "A" * 86
    forged = TradeOrderIntakeReceipt._create(
        trade_rules_api.trade_canonical_json(document)
    )
    ok, reason = verify_trade_order_intake_receipt(
        forged,
        delivery=delivery,
        receiver_did=context["taker"].as_did(),
        audit_event_id="1" * 64,
    )
    assert ok is False
    assert reason == "signature invalid"
    with pytest.raises(
        TradeOrderIntakeReceiptRejected,
        match="signature invalid",
    ):
        trade_order_intake_receipt_digest(forged)


def test_order_intake_receipt_rejects_impossible_chronology(tmp_path):
    context = _setup(tmp_path)
    delivery = _order_delivery(context)

    with pytest.raises(
        TradeOrderIntakeReceiptRejected,
        match="within the signed Delivery lifetime",
    ):
        create_trade_order_intake_receipt(
            context["taker"],
            delivery=delivery,
            received_at="2099-01-01T00:00:00Z",
            audit_event_id="1" * 64,
        )

    future = create_trade_order_intake_receipt(
        context["taker"],
        delivery=delivery,
        received_at="2099-01-01T00:00:00Z",
        audit_event_id="1" * 64,
        clock_skew_seconds=3_000_000_000,
    )
    ok, reason = verify_trade_order_intake_receipt(
        future,
        delivery=delivery,
        receiver_did=context["taker"].as_did(),
        audit_event_id="1" * 64,
        at=_utc("2026-08-01T01:03:00Z"),
    )

    assert ok is False
    assert "outside the signed Delivery lifetime" in reason


def test_order_intake_receipt_allows_symmetric_clock_skew(tmp_path):
    context = _setup(tmp_path)
    delivery = _order_delivery(context)
    received_at = "2026-08-01T01:00:59Z"

    receipt = create_trade_order_intake_receipt(
        context["taker"],
        delivery=delivery,
        received_at=received_at,
        audit_event_id="1" * 64,
        clock_skew_seconds=2,
    )

    assert verify_trade_order_intake_receipt(
        receipt,
        delivery=delivery,
        receiver_did=context["taker"].as_did(),
        audit_event_id="1" * 64,
        at=_utc(received_at),
        clock_skew_seconds=2,
    ) == (True, "ok")
    with pytest.raises(
        TradeOrderIntakeReceiptRejected,
        match="within the signed Delivery lifetime",
    ):
        create_trade_order_intake_receipt(
            context["taker"],
            delivery=delivery,
            received_at=received_at,
            audit_event_id="1" * 64,
            clock_skew_seconds=0,
        )


def test_order_intake_receipt_validation_keeps_ack_error_contract(tmp_path):
    context = _setup(tmp_path)
    delivery = _order_delivery(context)

    with pytest.raises(
        TradeOrderIntakeReceiptRejected,
        match="received_at must be a UTC RFC3339 timestamp",
    ):
        create_trade_order_intake_receipt(
            context["taker"],
            delivery=delivery,
            received_at="not-a-timestamp",
            audit_event_id="1" * 64,
        )
    with pytest.raises(
        TradeOrderIntakeReceiptRejected,
        match="clock_skew_seconds must be a finite non-negative number",
    ):
        create_trade_order_intake_receipt(
            context["taker"],
            delivery=delivery,
            received_at="2026-08-01T01:03:00Z",
            audit_event_id="1" * 64,
            clock_skew_seconds=float("nan"),
        )

    receipt = create_trade_order_intake_receipt(
        context["taker"],
        delivery=delivery,
        received_at="2026-08-01T01:03:00Z",
        audit_event_id="1" * 64,
    )
    malformed = receipt.to_dict()
    malformed["proof"]["created"] = "not-a-timestamp"
    with pytest.raises(
        TradeOrderIntakeReceiptRejected,
        match="proof.created must be a UTC RFC3339 timestamp",
    ):
        TradeOrderIntakeReceipt.from_dict(malformed)


def _order_intake_runtime(tmp_path, context):
    outbox, order_store, spine, order_audit = _audit_runtime(tmp_path)
    intake = TradeOrderIntakeCoordinator(
        order_audit,
        receiver_identity=context["taker"],
    )
    return outbox, order_store, spine, intake


def test_order_intake_verifies_before_durable_acceptance(tmp_path):
    context = _setup(tmp_path / "fixtures")
    delivery = _order_delivery(context)
    outbox, order_store, spine, intake = _order_intake_runtime(
        tmp_path / "runtime", context
    )

    result = intake.receive(
        delivery,
        at=_utc("2026-08-01T01:03:00Z"),
    )

    assert result.delivery == delivery
    assert result.delivery_digest == trade_order_delivery_digest(delivery)
    assert result.audit.created is True
    assert result.audit.cache_created is True
    assert result.audit.anchor_created is True
    assert result.receipt_digest == trade_order_intake_receipt_digest(
        result.receipt
    )
    assert verify_trade_order_intake_receipt(
        result.receipt,
        delivery=delivery,
        receiver_did=context["taker"].as_did(),
        audit_event_id=result.audit.record.event_id,
    ) == (True, "ok")
    assert order_store.get(delivery.order.to_dict()["order_id"]) == (
        delivery.order
    )
    assert outbox.get(trade_order_digest(delivery.order)) is None
    assert len([
        event
        for event in spine.read_all()
        if event.type == EVENT_TRADE_ORDER_ACCEPTED
    ]) == 1


def test_order_dispatch_persists_receipt_before_retiring_pending(tmp_path):
    context = _setup(tmp_path / "fixtures")
    delivery = _order_delivery(context)
    store = TradeOrderDispatchStore(tmp_path / "runtime")
    spine = SignedEventLog(
        tmp_path / "runtime" / "spine.jsonl",
        context["maker"],
    )
    coordinator = TradeOrderDispatchCoordinator(store, spine)
    pending = coordinator.prepare(
        delivery,
        target_url="http://peer.example:8080",
        now_ms=1_800_000_000_000,
    )
    receipt = create_trade_order_intake_receipt(
        context["taker"],
        delivery=delivery,
        received_at="2026-08-01T01:03:00Z",
        audit_event_id="1" * 64,
    )

    acknowledgement = coordinator.acknowledge(
        delivery,
        receipt,
        target_url="http://peer.example:8080",
        remote_event_id="1" * 64,
        observed_at_ms=1_800_000_000_001,
    )

    assert pending.order_digest == acknowledgement.order_digest
    assert store.get_pending(pending.order_digest) is None
    assert store.get_acknowledgement(pending.order_digest) == acknowledgement
    events = [
        event for event in spine.read_all()
        if event.type == EVENT_TRADE_ORDER_INTAKE_ACKNOWLEDGED
    ]
    assert len(events) == 1
    assert events[0].payload["receipt_digest"] == acknowledgement.receipt_digest


def test_order_dispatch_recovers_receipt_written_before_spine(tmp_path):
    context = _setup(tmp_path / "fixtures")
    delivery = _order_delivery(context)
    store = TradeOrderDispatchStore(tmp_path / "runtime")
    store.prepare(
        delivery,
        target_url="http://peer.example:8080",
        now_ms=1_800_000_000_000,
    )
    receipt = create_trade_order_intake_receipt(
        context["taker"],
        delivery=delivery,
        received_at="2026-08-01T01:03:00Z",
        audit_event_id="2" * 64,
    )
    acknowledgement = store.put_acknowledgement(
        delivery,
        receipt,
        target_url="http://peer.example:8080",
        remote_event_id="2" * 64,
        observed_at_ms=1_800_000_000_001,
    )
    spine = SignedEventLog(
        tmp_path / "runtime" / "spine.jsonl",
        context["maker"],
    )

    report = TradeOrderDispatchCoordinator(store, spine).reconcile()

    assert report.scanned == 1
    assert report.anchored == 1
    assert report.completed == 1
    assert report.failed == 0
    assert store.get_pending(acknowledgement.order_digest) is None
    assert len(list(spine.read_all())) == 1


def test_order_dispatch_failure_survives_store_restart(tmp_path):
    context = _setup(tmp_path / "fixtures")
    delivery = _order_delivery(context)
    root = tmp_path / "runtime"
    store = TradeOrderDispatchStore(root)
    record = store.prepare(
        delivery,
        target_url="http://peer.example:8080",
        now_ms=1_800_000_000_000,
    )
    store.note_failure(
        record.order_digest,
        error="peer unavailable\nlocal detail",
        now_ms=1_800_000_000_001,
    )

    recovered = TradeOrderDispatchStore(root).get_pending(
        record.order_digest
    )

    assert recovered is not None
    assert recovered.target_url == "http://peer.example:8080"
    assert recovered.attempts == 1
    assert recovered.last_error == "peer unavailable local detail"


def test_order_dispatch_retry_reuses_exact_delivery_and_pinned_target(tmp_path):
    context = _setup(tmp_path / "fixtures")
    first = _order_delivery(context)
    second = create_trade_order_delivery(
        context["maker"],
        order=first.order,
        created_at="2026-08-01T01:02:00Z",
        not_after="2026-08-01T01:07:00Z",
        nonce="cd" * 16,
        now=_utc("2026-08-01T01:02:00Z"),
    )
    store = TradeOrderDispatchStore(tmp_path / "runtime")
    prepared = store.prepare(
        first,
        target_url="http://peer.example:8080",
        now_ms=1_785_546_180_000,
    )

    retried = store.prepare(
        second,
        target_url="http://peer.example:8080",
        now_ms=1_785_546_181_000,
    )

    assert retried.delivery.canonical_bytes == prepared.delivery.canonical_bytes
    with pytest.raises(TradeOrderDispatchError, match="target cannot change"):
        store.prepare(
            second,
            target_url="http://other.example:8080",
            now_ms=1_785_546_182_000,
        )


def test_order_dispatch_renews_only_an_expired_delivery_generation(tmp_path):
    context = _setup(tmp_path / "fixtures")
    first = _order_delivery(context)
    replacement = create_trade_order_delivery(
        context["maker"],
        order=first.order,
        created_at="2026-08-01T01:12:00Z",
        not_after="2026-08-01T01:17:00Z",
        nonce="cd" * 16,
        now=_utc("2026-08-01T01:12:00Z"),
    )
    root = tmp_path / "runtime"
    store = TradeOrderDispatchStore(root)
    original = store.prepare(
        first,
        target_url="http://peer.example:8080",
        now_ms=1_785_546_120_000,
    )

    renewed = store.prepare(
        replacement,
        target_url="http://peer.example:8080",
        now_ms=1_785_546_960_000,
    )

    assert renewed.generation == 2
    assert renewed.delivery == replacement
    assert renewed.superseded_delivery_digests == (
        trade_order_delivery_digest(original.delivery),
    )
    assert TradeOrderDispatchStore(root).get_pending(
        renewed.order_digest
    ) == renewed


def test_order_dispatch_migrates_legacy_pending_record_on_write(tmp_path):
    context = _setup(tmp_path / "fixtures")
    delivery = _order_delivery(context)
    store = TradeOrderDispatchStore(tmp_path / "runtime")
    record = store.prepare(
        delivery,
        target_url="http://peer.example:8080",
        now_ms=1_785_546_120_000,
    )
    path = store._path(store.pending_root, record.order_digest)
    legacy = json.loads(path.read_bytes())
    legacy["protocol_version"] = "1"
    legacy.pop("generation")
    legacy.pop("superseded_delivery_digests")
    path.write_bytes(canonical_json(legacy))

    loaded = store.get_pending(record.order_digest)
    assert loaded is not None and loaded.generation == 1
    store.note_failure(
        record.order_digest,
        error="retry",
        now_ms=1_785_546_121_000,
    )
    migrated = json.loads(path.read_bytes())
    assert migrated["protocol_version"] == "2"
    assert migrated["generation"] == 1
    assert migrated["superseded_delivery_digests"] == []


def test_order_dispatch_rejects_conflicting_acknowledgement(tmp_path):
    context = _setup(tmp_path / "fixtures")
    delivery = _order_delivery(context)
    store = TradeOrderDispatchStore(tmp_path / "runtime")
    store.prepare(
        delivery,
        target_url="http://peer.example:8080",
        now_ms=1_785_546_180_000,
    )
    first = create_trade_order_intake_receipt(
        context["taker"],
        delivery=delivery,
        received_at="2026-08-01T01:03:00Z",
        audit_event_id="1" * 64,
    )
    second = create_trade_order_intake_receipt(
        context["taker"],
        delivery=delivery,
        received_at="2026-08-01T01:03:01Z",
        audit_event_id="2" * 64,
    )
    store.put_acknowledgement(
        delivery,
        first,
        target_url="http://peer.example:8080",
        remote_event_id="1" * 64,
        observed_at_ms=1_785_546_181_000,
    )

    with pytest.raises(TradeOrderDispatchError, match="conflicts"):
        store.put_acknowledgement(
            delivery,
            second,
            target_url="http://peer.example:8080",
            remote_event_id="2" * 64,
            observed_at_ms=1_785_546_182_000,
        )


def test_order_dispatch_rejects_acknowledgement_without_pending_work(tmp_path):
    context = _setup(tmp_path / "fixtures")
    delivery = _order_delivery(context)
    receipt = create_trade_order_intake_receipt(
        context["taker"],
        delivery=delivery,
        received_at="2026-08-01T01:03:00Z",
        audit_event_id="1" * 64,
    )
    store = TradeOrderDispatchStore(tmp_path / "runtime")

    with pytest.raises(TradeOrderDispatchError, match="no pending"):
        store.put_acknowledgement(
            delivery,
            receipt,
            target_url="http://peer.example:8080",
            remote_event_id="1" * 64,
            observed_at_ms=1_785_546_181_000,
        )


def test_order_dispatch_observation_uses_receipt_clock_skew(tmp_path):
    context = _setup(tmp_path / "fixtures")
    delivery = _order_delivery(context)
    receipt = create_trade_order_intake_receipt(
        context["taker"],
        delivery=delivery,
        received_at="2026-08-01T01:03:00Z",
        audit_event_id="1" * 64,
    )
    received_ms = 1_785_546_180_000
    accepted = TradeOrderDispatchStore(tmp_path / "accepted")
    accepted.prepare(
        delivery,
        target_url="http://peer.example:8080",
        now_ms=received_ms - 299_000,
    )
    accepted.put_acknowledgement(
        delivery,
        receipt,
        target_url="http://peer.example:8080",
        remote_event_id="1" * 64,
        observed_at_ms=received_ms - 299_000,
    )

    rejected = TradeOrderDispatchStore(tmp_path / "rejected")
    rejected.prepare(
        delivery,
        target_url="http://peer.example:8080",
        now_ms=received_ms - 301_000,
    )
    with pytest.raises(TradeOrderDispatchError, match="predates"):
        rejected.put_acknowledgement(
            delivery,
            receipt,
            target_url="http://peer.example:8080",
            remote_event_id="1" * 64,
            observed_at_ms=received_ms - 301_000,
        )


def test_order_dispatch_completion_verifies_acknowledgement_binding(tmp_path):
    context = _setup(tmp_path / "fixtures")
    delivery = _order_delivery(context)
    store = TradeOrderDispatchStore(tmp_path / "runtime")
    record = store.prepare(
        delivery,
        target_url="http://peer.example:8080",
        now_ms=1_785_546_180_000,
    )
    receipt = create_trade_order_intake_receipt(
        context["taker"],
        delivery=delivery,
        received_at="2026-08-01T01:03:00Z",
        audit_event_id="1" * 64,
    )
    store.put_acknowledgement(
        delivery,
        receipt,
        target_url="http://peer.example:8080",
        remote_event_id="1" * 64,
        observed_at_ms=1_785_546_181_000,
    )
    acknowledgement_path = store._path(store.ack_root, record.order_digest)
    tampered = json.loads(acknowledgement_path.read_bytes())
    tampered["target_url"] = "http://other.example:8080"
    acknowledgement_path.write_bytes(canonical_json(tampered))

    with pytest.raises(TradeOrderDispatchError, match="conflicts"):
        store.complete_pending(record.order_digest)
    assert store.get_pending(record.order_digest) is not None


def test_order_dispatch_batch_state_scans_each_directory_once(
    tmp_path,
    monkeypatch,
):
    context = _setup(tmp_path / "fixtures")
    delivery = _order_delivery(context)
    store = TradeOrderDispatchStore(tmp_path / "runtime")
    record = store.prepare(
        delivery,
        target_url="http://peer.example:8080",
        now_ms=1_785_546_180_000,
    )
    original = store._files_and_usage
    scanned = []

    def counted(directory):
        scanned.append(directory)
        return original(directory)

    monkeypatch.setattr(store, "_files_and_usage", counted)
    states = store.get_states((record.order_digest,))

    assert states[record.order_digest][0] == record
    assert scanned == [store.pending_root, store.ack_root]


def test_order_dispatch_crash_residue_counts_toward_capacity(tmp_path):
    context = _setup(tmp_path / "fixtures")
    delivery = _order_delivery(context)
    store = TradeOrderDispatchStore(tmp_path / "runtime", max_pending=1)
    store.pending_root.mkdir(parents=True)
    suffix = trade_order_digest(delivery.order).removeprefix("sha256:")
    (store.pending_root / f"{suffix}.json.crash.tmp").write_bytes(b"x")

    with pytest.raises(TradeOrderDispatchCapacity, match="max_pending"):
        store.prepare(
            delivery,
            target_url="http://peer.example:8080",
            now_ms=1_800_000_000_000,
        )


def test_order_dispatch_crash_residue_requires_unchanged_inspection(tmp_path):
    store = TradeOrderDispatchStore(tmp_path / "runtime")
    store.pending_root.mkdir(parents=True)
    suffix = "1" * 64
    residue = store.pending_root / f"{suffix}.json.crash.tmp"
    residue.write_bytes(b"partial")
    inspected = store.inspect_crash_residue()
    assert len(inspected) == 1
    assert inspected[0].filename == residue.name

    residue.write_bytes(b"changed")
    with pytest.raises(TradeOrderDispatchError, match="changed"):
        store.prune_crash_residue(expected=inspected)
    refreshed = store.inspect_crash_residue()
    assert store.prune_crash_residue(expected=refreshed) == 1
    assert not residue.exists()


def test_order_dispatch_residue_keeps_legacy_constructor_compatible():
    residue = TradeOrderDispatchResidue(
        area="pending",
        filename="record.tmp",
        size_bytes=7,
        modified_at_ns=9,
    )

    assert residue.content_sha256 == ""


def test_order_dispatch_residue_rejects_path_swap_while_opening(
    tmp_path,
    monkeypatch,
):
    store = TradeOrderDispatchStore(tmp_path / "runtime")
    store.pending_root.mkdir(parents=True)
    suffix = "2" * 64
    residue = store.pending_root / f"{suffix}.json.crash.tmp"
    replacement = store.pending_root / f"{suffix}.json.replacement.tmp"
    residue.write_bytes(b"first")
    replacement.write_bytes(b"other")
    original_open = os.open
    swapped = False

    def swap_before_open(path, flags, *args, **kwargs):
        nonlocal swapped
        if Path(path) == residue and not swapped:
            swapped = True
            replacement.replace(residue)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(order_dispatch_api.os, "open", swap_before_open)

    with pytest.raises(TradeOrderDispatchError, match="changed while opening"):
        store.inspect_crash_residue()


def test_order_dispatch_prune_does_not_delete_post_inspection_replacement(
    tmp_path,
    monkeypatch,
):
    store = TradeOrderDispatchStore(tmp_path / "runtime")
    store.pending_root.mkdir(parents=True)
    suffix = "3" * 64
    residue = store.pending_root / f"{suffix}.json.crash.tmp"
    attacker = tmp_path / "replacement.bin"
    residue.write_bytes(b"inspected residue")
    attacker.write_bytes(b"replacement must survive")
    inspected = store.inspect_crash_residue()
    original_replace = os.replace
    swapped = False

    def swap_before_quarantine(source, destination):
        nonlocal swapped
        if Path(source) == residue and not swapped:
            swapped = True
            original_replace(attacker, residue)
        return original_replace(source, destination)

    monkeypatch.setattr(order_dispatch_api.os, "replace", swap_before_quarantine)

    with pytest.raises(TradeOrderDispatchError, match="changed during prune"):
        store.prune_crash_residue(expected=inspected)

    assert swapped is True
    assert residue.read_bytes() == b"replacement must survive"
    assert not list(store.pending_root.glob("*.prune-*.tmp"))


def test_order_dispatch_reads_are_bounded_before_json_decode(tmp_path):
    context = _setup(tmp_path / "fixtures")
    delivery = _order_delivery(context)
    store = TradeOrderDispatchStore(tmp_path / "runtime")
    suffix = trade_order_digest(delivery.order).removeprefix("sha256:")
    store.pending_root.mkdir(parents=True)
    (store.pending_root / f"{suffix}.json").write_bytes(
        b"x" * (MAX_DISPATCH_RECORD_BYTES + 1)
    )

    with pytest.raises(TradeOrderDispatchError, match="too large"):
        store.get_pending(trade_order_digest(delivery.order))


def test_order_dispatch_rejects_control_characters_in_target_url(tmp_path):
    context = _setup(tmp_path / "fixtures")
    delivery = _order_delivery(context)
    store = TradeOrderDispatchStore(tmp_path / "runtime")

    with pytest.raises(TradeOrderDispatchError, match="control characters"):
        store.prepare(
            delivery,
            target_url="http://peer.example:8080/\nforged",
            now_ms=1_800_000_000_000,
        )


def test_order_dispatch_acknowledgements_use_stable_digest_pagination(
    tmp_path,
    monkeypatch,
):
    store = TradeOrderDispatchStore(tmp_path / "runtime")
    store.ack_root.mkdir(parents=True)
    suffixes = [f"{value:064x}" for value in (1, 2, 3)]
    for suffix in suffixes:
        (store.ack_root / f"{suffix}.json").write_bytes(b"placeholder")
    monkeypatch.setattr(store, "_read_ack", lambda path: path.stem)

    first, cursor = store.list_acknowledgements(limit=2)
    second, final_cursor = store.list_acknowledgements(
        limit=2,
        after=cursor,
    )

    assert first == tuple(suffixes[:2])
    assert cursor == f"sha256:{suffixes[1]}"
    assert second == (suffixes[2],)
    assert final_cursor == ""


def test_order_intake_replay_and_new_nonce_are_order_idempotent(tmp_path):
    context = _setup(tmp_path / "fixtures")
    first_delivery = _order_delivery(context)
    second_delivery = create_trade_order_delivery(
        context["maker"],
        order=first_delivery.order,
        created_at="2026-08-01T01:02:00Z",
        not_after="2026-08-01T01:07:00Z",
        nonce="cd" * 16,
        now=_utc("2026-08-01T01:02:00Z"),
    )
    _outbox, _store, spine, intake = _order_intake_runtime(
        tmp_path / "runtime", context
    )

    first = intake.receive(
        first_delivery,
        at=_utc("2026-08-01T01:03:00Z"),
    )
    replay = intake.receive(
        first_delivery,
        at=_utc("2026-08-01T01:03:01Z"),
    )
    new_envelope = intake.receive(
        second_delivery,
        at=_utc("2026-08-01T01:03:02Z"),
    )

    assert first.audit.anchor_created is True
    assert replay.audit.created is False
    assert replay.audit.anchor_created is False
    assert new_envelope.audit.created is False
    assert new_envelope.audit.anchor_created is False
    assert first.delivery_digest != new_envelope.delivery_digest
    assert len([
        event
        for event in spine.read_all()
        if event.type == EVENT_TRADE_ORDER_ACCEPTED
    ]) == 1


def test_completed_order_work_does_not_consume_outbox_lifetime_capacity(
    tmp_path,
):
    context = _setup(tmp_path / "fixtures")
    first_order = _order(context)
    second_proposal = create_trade_proposal(
        context["taker"],
        resolution=replace(
            context["taker_resolution"],
            evaluated_at="2026-08-01T00:00:01Z",
        ),
        offer=context["offer"],
        offer_resolver=context["offer_store"],
        terms={"requested_quantity": "2"},
        created_at="2026-08-01T00:00:01Z",
        not_after=_EXPIRES,
        now=_utc("2026-08-01T00:00:01Z"),
    )
    second_order = create_trade_order(
        offer=context["offer"],
        proposal=second_proposal,
        acceptance=_acceptance(context, second_proposal),
    )
    runtime = tmp_path / "runtime"
    outbox = TradeOrderAuditOutbox(runtime, max_records=1)
    order_store = TradeOrderStore(runtime)
    spine = SignedEventLog(runtime / "spine.jsonl", context["taker"])
    coordinator = TradeOrderAuditCoordinator(outbox, order_store, spine)
    intake = TradeOrderIntakeCoordinator(
        coordinator,
        receiver_identity=context["taker"],
    )

    for index, order in enumerate((first_order, second_order), start=1):
        created = _utc(f"2026-08-01T01:0{index}:00Z")
        delivery = create_trade_order_delivery(
            context["maker"],
            order=order,
            created_at=created.isoformat().replace("+00:00", "Z"),
            not_after=(created + timedelta(minutes=5)).isoformat().replace(
                "+00:00", "Z"
            ),
            nonce=("ab" if index == 1 else "cd") * 16,
            now=created,
        )
        intake.receive(delivery, at=created + timedelta(minutes=1))
        assert outbox.pending() == ()
        assert outbox.records(
            statuses=frozenset({"anchored"}),
            limit=1,
        ) == ()

    assert len(order_store.list_ids()) == 2
    assert len([
        event for event in spine.read_all()
        if event.type == EVENT_TRADE_ORDER_ACCEPTED
    ]) == 2


def test_order_intake_rejects_foreign_recipient_before_any_write(tmp_path):
    context = _setup(tmp_path / "fixtures")
    delivery = _order_delivery(context)
    runtime = tmp_path / "runtime"
    outbox, order_store, spine, order_audit = _audit_runtime(runtime)
    intake = TradeOrderIntakeCoordinator(
        order_audit,
        receiver_identity=AgentIdentity.generate(),
    )

    with pytest.raises(
        TradeOrderDeliveryRejected,
        match="recipient does not match this node",
    ):
        intake.receive(
            delivery,
            at=_utc("2026-08-01T01:03:00Z"),
        )

    assert order_store.list_ids() == ()
    assert outbox.pending() == ()
    assert list(spine.read_all()) == []


def test_order_intake_concurrent_replay_creates_one_anchor(tmp_path):
    context = _setup(tmp_path / "fixtures")
    delivery = _order_delivery(context)
    _outbox, _store, spine, intake = _order_intake_runtime(
        tmp_path / "runtime", context
    )

    with ThreadPoolExecutor(max_workers=6) as executor:
        results = list(executor.map(
            lambda index: intake.receive(
                delivery,
                at=_utc(f"2026-08-01T01:03:0{index}Z"),
            ),
            range(6),
        ))

    assert sum(result.audit.created for result in results) == 1
    assert sum(result.audit.cache_created for result in results) == 1
    assert sum(result.audit.anchor_created for result in results) == 1
    assert len([
        event
        for event in spine.read_all()
        if event.type == EVENT_TRADE_ORDER_ACCEPTED
    ]) == 1


def test_web_bootstrap_recovers_prepared_order_without_resubmission(tmp_path):
    runtime = tmp_path / "runtime"
    first_app = create_app(runtime, require_console_auth=True)
    context = _setup(
        tmp_path / "fixtures",
        taker=first_app.state.nth.node_identity,
    )
    order = _order(context)
    prepared, created = (
        first_app.state.nth.trade_order_audit_outbox.prepare(
            order,
            now_ms=1_800_000_000_000,
        )
    )
    assert created is True
    assert prepared.status == "prepared"
    assert first_app.state.nth.trade_order_store.get(order.order_id) is None

    restarted = create_app(runtime, require_console_auth=True)

    assert restarted.state.nth.trade_order_intake is not None
    assert restarted.state.nth.trade_order_store.get(order.order_id) == order
    recovered = restarted.state.nth.trade_order_audit_outbox.get(
        trade_order_digest(order)
    )
    assert recovered is None
    events = [
        event
        for event in restarted.state.nth.spine.read_all()
        if event.type == EVENT_TRADE_ORDER_ACCEPTED
    ]
    assert len(events) == 1
    assert events[0].payload["order_digest"] == trade_order_digest(order)


def test_web_bootstrap_drains_order_recovery_pages_with_progress(
    tmp_path,
    monkeypatch,
):
    calls = 0

    def reconcile_pages(self, *, limit=100, now_ms=None):
        nonlocal calls
        calls += 1
        assert limit == 1_000
        return type("Recovery", (), {
            "scanned": 1_000 if calls == 1 else 1,
            "anchored": 1_000 if calls == 1 else 1,
            "verified_anchored": 0,
            "blocked": 0,
            "failed": 0,
        })()

    def pending_pages(self, *, limit=100):
        assert limit == 1
        return (object(),) if calls == 1 else ()

    monkeypatch.setattr(
        TradeOrderAuditCoordinator,
        "reconcile",
        reconcile_pages,
    )
    monkeypatch.setattr(
        TradeOrderAuditOutbox,
        "pending",
        pending_pages,
    )

    create_app(tmp_path, require_console_auth=True)

    assert calls == 2


def test_web_bootstrap_bounds_order_recovery_despite_continuous_progress(
    tmp_path,
    monkeypatch,
):
    calls = 0

    def reconcile_forever(self, *, limit=100, now_ms=None):
        nonlocal calls
        calls += 1
        assert limit == 1_000
        return type("Recovery", (), {
            "scanned": 1,
            "anchored": 1,
            "verified_anchored": 0,
            "blocked": 0,
            "failed": 0,
        })()

    def always_pending(self, *, limit=100):
        assert limit == 1
        return (object(),)

    monkeypatch.setattr(
        TradeOrderAuditCoordinator,
        "reconcile",
        reconcile_forever,
    )
    monkeypatch.setattr(
        TradeOrderAuditOutbox,
        "pending",
        always_pending,
    )

    create_app(tmp_path, require_console_auth=True)

    assert calls == 5


def _live_order_delivery(tmp_path, app, *, nonce="ef" * 16):
    context = _setup(
        tmp_path / "fixtures",
        taker=app.state.nth.node_identity,
    )
    order = _order(context)
    created = datetime.now(timezone.utc).replace(microsecond=0)
    not_after = created + timedelta(minutes=5)

    def _wire(moment):
        return moment.isoformat().replace("+00:00", "Z")

    delivery = create_trade_order_delivery(
        context["maker"],
        order=order,
        created_at=_wire(created),
        not_after=_wire(not_after),
        nonce=nonce,
        now=created,
    )
    return context, order, delivery


def _free_tcp_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _process_http_json(url, *, payload=None, headers=None):
    body = None
    request_headers = dict(headers or {})
    method = "GET"
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
        method = "POST"
    request = urllib.request.Request(
        url,
        data=body,
        headers=request_headers,
        method=method,
    )
    with urllib.request.urlopen(request, timeout=20.0) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))


class _UvicornProcessServer:
    """Run one authenticated NTH DAO node in an independent OS process."""

    _BOOT = (
        "import sys,uvicorn;"
        "from pathlib import Path;"
        "from nth_dao.web import create_app;"
        "app=create_app(Path(sys.argv[1]),require_console_auth=True);"
        "Path(sys.argv[3]).write_text(app.state.nth_console_token,encoding='ascii');"
        "uvicorn.run(app,host='127.0.0.1',port=int(sys.argv[2]),"
        "log_level='error',access_log=False)"
    )

    def __init__(self, workspace: Path, port: int) -> None:
        self.workspace = workspace
        self.port = port
        self.url = f"http://127.0.0.1:{port}"
        self.process = None
        self.token = ""
        self._generation = 0

    def start(self) -> None:
        self._generation += 1
        token_path = self.workspace.parent / (
            f"{self.workspace.name}-token-{self._generation}.txt"
        )
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                self._BOOT,
                str(self.workspace),
                str(self.port),
                str(token_path),
            ],
            cwd=str(Path(__file__).resolve().parents[1]),
            env={
                **os.environ,
                "NTH_LAN_PUBLISH": "0",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=(
                subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            ),
        )
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("Rule Package node process exited during startup")
            if token_path.exists():
                try:
                    _process_http_json(
                        f"{self.url}/.well-known/nth-dao/identity.json"
                    )
                except OSError:
                    pass
                else:
                    self.token = token_path.read_text(encoding="ascii")
                    return
            time.sleep(0.025)
        raise RuntimeError("Rule Package node process did not start")

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10.0)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5.0)
        self.process = None

    def restart(self) -> None:
        self.stop()
        self.start()


class _UvicornThreadServer:
    """Expose an in-memory NTH DAO app through a real loopback socket."""

    def __init__(self, app, port: int) -> None:
        self.url = f"http://127.0.0.1:{port}"
        self.server = uvicorn.Server(uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="error",
            access_log=False,
        ))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self):
        self.thread.start()
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if self.server.started:
                return self
            time.sleep(0.025)
        raise RuntimeError("threaded NTH DAO test server did not start")

    def __exit__(self, *_args):
        self.server.should_exit = True
        self.thread.join(timeout=10.0)
        if self.thread.is_alive():
            raise RuntimeError("threaded NTH DAO test server did not stop")


def test_public_order_delivery_retains_agreement_and_operator_can_read(
    tmp_path,
):
    app = create_app(tmp_path, require_console_auth=True)
    _context, order, delivery = _live_order_delivery(tmp_path, app)
    client = TestClient(app)

    accepted = client.post(
        "/api/v2/trade/federation/orders",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )
    replay = client.post(
        "/api/v2/trade/federation/orders",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )
    unauthenticated = client.get("/api/v2/trade/orders")
    auth = {"Authorization": f"Bearer {app.state.nth_console_token}"}
    listed = client.get("/api/v2/trade/orders", headers=auth)
    detail = client.get(
        f"/api/v2/trade/orders/{trade_order_digest(order)}",
        headers=auth,
    )

    assert accepted.status_code == 202
    assert accepted.json()["status"] == "accepted-agreement-retained"
    assert accepted.json()["order_id"] == order.order_id
    assert accepted.json()["order_store_created"] is True
    assert accepted.json()["audit_anchor_created"] is True
    assert accepted.json()["delivery_or_payment_proven"] is False
    intake_receipt = TradeOrderIntakeReceipt.from_dict(
        accepted.json()["intake_receipt"]
    )
    assert trade_order_intake_receipt_digest(intake_receipt) == (
        accepted.json()["intake_receipt_digest"]
    )
    assert verify_trade_order_intake_receipt(
        intake_receipt,
        delivery=delivery,
        receiver_did=app.state.nth.node_identity.as_did(),
        audit_event_id=accepted.json()["audit_event_id"],
    ) == (True, "ok")
    assert replay.status_code == 202
    assert replay.json()["order_store_created"] is False
    assert replay.json()["audit_anchor_created"] is False
    assert unauthenticated.status_code == 401
    assert listed.status_code == 200
    assert listed.json()["items"][0]["audit_status"] == "anchored"
    assert listed.json()["items"][0]["delivery_or_payment_proven"] is False
    assert detail.status_code == 200
    assert detail.json()["order"] == order.to_dict()
    execution = detail.json()["execution"]
    assert execution["order_digest"] == trade_order_digest(order)
    assert execution["coordinator"]["available"] is True
    assert execution["coordinator"]["execution_endpoint_enabled"] is False
    assert execution["local_executor"]["role"] == "taker"
    assert execution["status"] == "blocked"
    assert execution["executor_policy"]["status"] == "not-configured"
    assert execution["funds"]["enabled"] is False
    assert any(skill["status"] == "missing" for skill in execution["skills"])


def test_agreement_rest_reports_execution_recovery_failure_without_false_health(
    tmp_path,
    monkeypatch,
):
    def fail_recovery(self, **_kwargs):
        raise OSError("sensitive-execution-audit-location")

    monkeypatch.setattr(TradeExecutionCoordinator, "reconcile", fail_recovery)
    app = create_app(tmp_path / "node", require_console_auth=True)
    _context, order, delivery = _live_order_delivery(tmp_path, app)
    client = TestClient(app)
    accepted = client.post(
        "/api/v2/trade/federation/orders",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )
    assert accepted.status_code == 202

    detail = client.get(
        f"/api/v2/trade/orders/{trade_order_digest(order)}",
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )

    assert detail.status_code == 200, detail.text
    coordinator = detail.json()["execution"]["coordinator"]
    assert coordinator == {
        "available": True,
        "status": "degraded",
        "receipt_persistence_available": False,
        "recovery_pending": True,
        "error_code": "runtime-recovery-failed",
        "execution_endpoint_enabled": False,
    }
    assert "sensitive-execution-audit-location" not in json.dumps(
        detail.json()
    )


def test_agreement_rest_keeps_verified_order_when_execution_projection_fails(
    tmp_path,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    _context, order, delivery = _live_order_delivery(tmp_path, app)
    client = TestClient(app)
    accepted = client.post(
        "/api/v2/trade/federation/orders",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )
    assert accepted.status_code == 202
    app.state.nth.trade_rule_packages = None

    detail = client.get(
        f"/api/v2/trade/orders/{trade_order_digest(order)}",
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )

    assert detail.status_code == 200, detail.text
    assert detail.json()["order"] == order.to_dict()
    execution = detail.json()["execution"]
    assert execution["status"] == "unavailable"
    assert execution["error_code"] == "projection-failed"
    assert execution["order_digest"] == trade_order_digest(order)
    assert execution["funds"]["enabled"] is False


def test_agreement_rest_keeps_order_with_malformed_execution_extension(
    tmp_path,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context = _setup(
        tmp_path / "fixtures",
        taker=app.state.nth.node_identity,
    )
    body = _proposal(context).to_dict()
    body.pop("proof")
    body["terms"][EXECUTION_TERMS_KEY] = {"grants": "not-a-list"}
    proposal = _sign_proposal_body(context["taker"], body)
    order = create_trade_order(
        offer=context["offer"],
        proposal=proposal,
        acceptance=_acceptance(context, proposal),
    )
    created = datetime.now(timezone.utc).replace(microsecond=0)
    delivery = create_trade_order_delivery(
        context["maker"],
        order=order,
        created_at=created.isoformat().replace("+00:00", "Z"),
        not_after=(created + timedelta(minutes=5)).isoformat().replace(
            "+00:00", "Z"
        ),
        nonce="de" * 16,
        now=created,
    )
    client = TestClient(app)
    accepted = client.post(
        "/api/v2/trade/federation/orders",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )

    detail = client.get(
        f"/api/v2/trade/orders/{trade_order_digest(order)}",
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )

    assert accepted.status_code == 202, accepted.text
    assert detail.status_code == 200, detail.text
    assert detail.json()["order"] == order.to_dict()
    execution = detail.json()["execution"]
    assert execution["status"] == "unavailable"
    assert execution["error_code"] == "projection-failed"
    assert execution["order_digest"] == trade_order_digest(order)
    assert execution["operation_grants"] == []
    assert execution["funds"]["enabled"] is False


def test_agreement_rest_distinguishes_history_failure_from_empty_history(
    tmp_path,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    _context, order, delivery = _live_order_delivery(tmp_path, app)
    client = TestClient(app)
    accepted = client.post(
        "/api/v2/trade/federation/orders",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )
    assert accepted.status_code == 202

    class BrokenHistoryCoordinator:
        def history(self, _order, *, limit, before_seq=None):
            assert limit == 100
            assert before_seq is None
            raise OSError("sensitive-receipt-history-location")

    app.state.nth.trade_execution_coordinator = BrokenHistoryCoordinator()
    detail = client.get(
        f"/api/v2/trade/orders/{trade_order_digest(order)}",
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )

    assert detail.status_code == 200, detail.text
    execution = detail.json()["execution"]
    assert execution["status"] == "blocked"
    assert execution["history"] == {
        "status": "unavailable",
            "items": [],
            "has_more": False,
            "next_cursor": None,
            "error_code": "receipt-history-verification-failed",
        }
    assert execution["coordinator"]["status"] == "degraded"
    assert execution["coordinator"]["error_code"] == (
        "receipt-history-verification-failed"
    )
    serialized = json.dumps(detail.json())
    assert "sensitive-receipt-history-location" not in serialized


def test_agreement_rest_pages_execution_receipts_by_spine_sequence(tmp_path):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context = _setup(
        tmp_path / "fixtures",
        taker=app.state.nth.node_identity,
    )
    operation_ids = [f"deliver-service-rest-{index}" for index in range(3)]
    proposal = _proposal(context, grants=[{
        "operation_id": operation_id,
        "rule_id": "org.nthdao.test.delivery",
        "package_digest": context["package_digest"],
        "hook_name": "fulfillment.deliver",
        "hook_version": "1",
        "executor_role": "maker",
    } for operation_id in operation_ids])
    order = create_trade_order(
        offer=context["offer"],
        proposal=proposal,
        acceptance=_acceptance(context, proposal),
    )
    created = datetime.now(timezone.utc).replace(microsecond=0)
    delivery = create_trade_order_delivery(
        context["maker"],
        order=order,
        created_at=created.isoformat().replace("+00:00", "Z"),
        not_after=(created + timedelta(minutes=5)).isoformat().replace(
            "+00:00", "Z"
        ),
        nonce="ad" * 16,
        now=created,
    )
    client = TestClient(app)
    accepted = client.post(
        "/api/v2/trade/federation/orders",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )
    assert accepted.status_code == 202, accepted.text
    for operation_id in operation_ids:
        _execution_receipt(
            context,
            order,
            coordinator=app.state.nth.trade_execution_coordinator,
            operation_id=operation_id,
        )
    auth = {"Authorization": f"Bearer {app.state.nth_console_token}"}
    path = f"/api/v2/trade/orders/{trade_order_digest(order)}/execution-receipts"

    newest = client.get(path, params={"limit": 2}, headers=auth)
    cursor = newest.json()["next_cursor"]
    older = client.get(
        path,
        params={"limit": 2, "before_seq": cursor},
        headers=auth,
    )

    assert newest.status_code == 200, newest.text
    assert newest.json()["status"] == "available"
    assert newest.json()["has_more"] is True
    assert isinstance(cursor, int)
    assert len(newest.json()["items"]) == 2
    assert older.status_code == 200, older.text
    assert older.json()["has_more"] is False
    assert older.json()["next_cursor"] is None
    assert len(older.json()["items"]) == 1
    assert {
        item["execution_id"]
        for item in newest.json()["items"] + older.json()["items"]
    } == {
        item.receipt.execution_id
        for item in app.state.nth.trade_execution_coordinator.history(
            order,
            limit=3,
        ).items
    }
    assert client.get(path, params={"limit": 2}).status_code == 401
    assert client.get(
        path,
        params={"before_seq": -1},
        headers=auth,
    ).status_code == 400


def test_agreement_rest_projects_explicit_local_execution_runtime(tmp_path):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, delivery = _live_order_delivery(tmp_path, app)
    client = TestClient(app)
    accepted = client.post(
        "/api/v2/trade/federation/orders",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )
    assert accepted.status_code == 202

    # A deployment must configure these local-only trust/runtime objects.
    # They are never copied from the signed bilateral policy by the API.
    app.state.nth.trade_rule_packages = context["package_store"]
    app.state.nth.trade_executor_policy = context["taker_policy"]
    app.state.nth.trade_execution_adapter_resolver = context[
        "adapter_resolver"
    ]
    app.state.nth.trade_execution_adapter_policy = context["adapter_policy"]
    app.state.nth.trade_execution_content_resolver = context[
        "content_resolver"
    ]
    detail = client.get(
        f"/api/v2/trade/orders/{trade_order_digest(order)}",
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )

    assert detail.status_code == 200, detail.text
    execution = detail.json()["execution"]
    assert execution["local_executor"]["role"] == "taker"
    assert execution["executor_policy"]["status"] == "ready"
    assert execution["adapter"]["status"] == "selection-required"
    assert execution["content"] == {
        "resolver_configured": True,
        "contract_schema_content_available": True,
        "runtime_payloads_ready": False,
        "status": "awaiting-operation-input",
    }
    assert execution["funds"]["enabled"] is False
    assert execution["status"] == "blocked"


def test_operator_imports_exact_order_bound_rule_package(tmp_path, monkeypatch):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, delivery = _live_order_delivery(tmp_path, app)
    client = TestClient(app)
    accepted = client.post(
        "/api/v2/trade/federation/orders",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )
    assert accepted.status_code == 202
    package_digest = context["package_digest"]
    package = context["package_store"].load(package_digest)
    assert package is not None
    assert app.state.nth.trade_rule_packages.load(package_digest) is None
    calls = []

    def fetch(
        peer_url,
        *,
        offer_digest,
        package_digest,
        offer_publisher_did,
        timeout_seconds=15.0,
    ):
        calls.append((
            peer_url,
            offer_digest,
            package_digest,
            offer_publisher_did,
            timeout_seconds,
        ))
        return package

    monkeypatch.setattr(
        web_v2_api,
        "_fetch_trade_rule_package_from_peer",
        fetch,
    )
    auth = {"Authorization": f"Bearer {app.state.nth_console_token}"}
    path = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}/rule-packages/"
        f"{package_digest}/import"
    )
    first = client.post(path, json={"peer_url": "http://localhost:19090"}, headers=auth)
    second = client.post(
        path,
        json={"peer_url": "http://localhost:19090/private/operator-path"},
        headers=auth,
    )

    assert first.status_code == 200, first.text
    assert first.json()["status"] == "installed"
    assert first.json()["audit_created"] is True
    assert first.json()["trust_granted"] is False
    assert first.json()["execution_authority_granted"] is False
    assert second.status_code == 200, second.text
    assert second.json()["status"] == "already-installed"
    assert second.json()["audit_created"] is False
    assert second.json()["audit_event_id"] == first.json()["audit_event_id"]
    assert len(calls) == 1
    assert calls[0][2] == package_digest
    assert app.state.nth.trade_rule_packages.load(package_digest).digest == package_digest
    import_events = [
        event
        for event in app.state.nth.spine.verified_snapshot()
        if event.type == "trade.rule-package.imported"
    ]
    assert len(import_events) == 1
    assert import_events[0].event_id == first.json()["audit_event_id"]
    assert import_events[0].payload == {
        "import_id": web_v2_api._trade_rule_package_import_id(
            order_digest=trade_order_digest(order),
            package_digest=package_digest,
        ),
        "order_digest": trade_order_digest(order),
        "offer_digest": calls[0][1],
        "package_digest": package_digest,
        "rule_id": package.manifest.rule_id,
        "package_publisher_did": package.manifest.publisher_did,
        "source_origin": "http://localhost:19090",
        "action": "verified-cache-import",
    }
    proposal_events = [
        event
        for event in app.state.nth.spine.verified_snapshot()
        if event.type == "trade.rule-package.import.proposed"
    ]
    assert len(proposal_events) == 1
    assert proposal_events[0].payload["import_id"] == import_events[0].payload[
        "import_id"
    ]
    assert client.post(
        path,
        json={"peer_url": "http://localhost:19090"},
    ).status_code == 401


def _observed_recognition_proof(context, package):
    issuer = AgentIdentity.generate()
    first = create_rule_recognition(
        issuer,
        package=package,
        decision="recognized",
        issued_at="2026-08-01T00:00:00Z",
        not_after="2026-08-20T00:00:00Z",
        now=_AT,
    )
    revoked = create_rule_recognition(
        issuer,
        package=package,
        decision="revoked",
        reason_codes=["security.withdrawn"],
        issued_at="2026-08-02T00:00:00Z",
        not_after="2026-08-20T00:00:00Z",
        previous=first,
        now=datetime(2026, 8, 2, tzinfo=timezone.utc),
    )
    binding = sign_offer_package_binding(
        context["maker"],
        offer_digest=offer_digest(context["offer"]),
        package_digest=package.digest,
        created="2026-07-01T00:00:00Z",
    )
    proof_now = datetime.now(timezone.utc).replace(microsecond=0)
    wire = build_rule_recognition_proof_bundle(
        package,
        [first, revoked],
        offer_package_binding=binding,
        observer_identity=context["maker"],
        observed_at=proof_now.isoformat().replace("+00:00", "Z"),
        not_after=(proof_now + timedelta(minutes=5)).isoformat().replace(
            "+00:00",
            "Z",
        ),
        now=proof_now,
    )
    proof = parse_rule_recognition_proof_bundle(
        wire,
        package=package,
        expected_offer_digest=offer_digest(context["offer"]),
        expected_offer_publisher_did=context["maker"].as_did(),
        now=proof_now,
    )
    return issuer, first, revoked, proof


def _observed_multi_genesis_recognition_proof(context, package):
    issuer = AgentIdentity.generate()
    recognized = create_rule_recognition(
        issuer,
        package=package,
        decision="recognized",
        issued_at="2026-08-01T00:00:00Z",
        not_after="2026-08-20T00:00:00Z",
        now=datetime(2026, 8, 1, tzinfo=timezone.utc),
    )
    revoked = create_rule_recognition(
        issuer,
        package=package,
        decision="revoked",
        reason_codes=["security.withdrawn"],
        issued_at="2026-08-02T00:00:00Z",
        not_after="2026-08-20T00:00:00Z",
        now=datetime(2026, 8, 2, tzinfo=timezone.utc),
    )
    binding = sign_offer_package_binding(
        context["maker"],
        offer_digest=offer_digest(context["offer"]),
        package_digest=package.digest,
        created="2026-07-01T00:00:00Z",
    )
    proof_now = datetime.now(timezone.utc).replace(microsecond=0)
    wire = build_rule_recognition_proof_bundle(
        package,
        [recognized, revoked],
        offer_package_binding=binding,
        observer_identity=context["maker"],
        observed_at=proof_now.isoformat().replace("+00:00", "Z"),
        not_after=(proof_now + timedelta(minutes=5)).isoformat().replace(
            "+00:00",
            "Z",
        ),
        now=proof_now,
    )
    proof = parse_rule_recognition_proof_bundle(
        wire,
        package=package,
        expected_offer_digest=offer_digest(context["offer"]),
        expected_offer_publisher_did=context["maker"].as_did(),
        now=proof_now,
    )
    return issuer, recognized, revoked, proof


def _refresh_observed_recognition_proof(context, package, proof):
    previous_observed_at = datetime.fromisoformat(
        proof.to_dict()["observed_at"].replace("Z", "+00:00")
    )
    observed_at = previous_observed_at + timedelta(seconds=31)
    binding = sign_offer_package_binding(
        context["maker"],
        offer_digest=offer_digest(context["offer"]),
        package_digest=package.digest,
        created="2026-07-01T00:00:00Z",
    )
    wire = build_rule_recognition_proof_bundle(
        package,
        proof.statements,
        offer_package_binding=binding,
        observer_identity=context["maker"],
        observed_at=observed_at.isoformat().replace("+00:00", "Z"),
        not_after=(observed_at + timedelta(minutes=5)).isoformat().replace(
            "+00:00",
            "Z",
        ),
        now=observed_at,
    )
    return parse_rule_recognition_proof_bundle(
        wire,
        package=package,
        expected_offer_digest=offer_digest(context["offer"]),
        expected_offer_publisher_did=context["maker"].as_did(),
        now=observed_at,
    )


def test_operator_imports_order_bound_recognition_proof_idempotently(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, delivery = _live_order_delivery(tmp_path, app)
    client = TestClient(app)
    assert client.post(
        "/api/v2/trade/federation/orders",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    ).status_code == 202
    package = context["package_store"].load(context["package_digest"])
    assert package is not None
    app.state.nth.trade_rule_packages.install(
        package.manifest,
        package.resources,
        source="local",
    )
    _issuer, first, revoked, proof = _observed_recognition_proof(
        context,
        package,
    )
    calls = []

    def fetch(peer_url, **kwargs):
        calls.append((peer_url, kwargs))
        return proof

    monkeypatch.setattr(
        web_v2_api,
        "_fetch_trade_rule_recognition_proof_from_peer",
        fetch,
    )
    auth = {"Authorization": f"Bearer {app.state.nth_console_token}"}
    path = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}/rule-packages/"
        f"{package.digest}/recognitions/import"
    )

    first_response = client.post(
        path,
        json={"peer_url": "http://localhost:19090"},
        headers=auth,
    )
    duplicate = client.post(
        path,
        json={"peer_url": "http://localhost:19090"},
        headers=auth,
    )

    assert first_response.status_code == 200, first_response.text
    assert first_response.json()["status"] == "imported"
    assert first_response.json()["imported_statement_count"] == 2
    assert first_response.json()["reconciled_anchor_count"] == 0
    assert first_response.json()["global_freshness_proven"] is False
    assert first_response.json()["issuer_trust_granted"] is False
    assert first_response.json()["local_policy_changed"] is False
    assert first_response.json()["execution_authority_granted"] is False
    assert duplicate.status_code == 200, duplicate.text
    assert duplicate.json()["status"] == "already-observed"
    assert duplicate.json()["imported_statement_count"] == 0
    assert duplicate.json()["reconciled_anchor_count"] == 0
    assert duplicate.json()["import_id"] == first_response.json()["import_id"]
    assert duplicate.json()["import_proposal_event_id"] == first_response.json()[
        "import_proposal_event_id"
    ]
    assert duplicate.json()["import_completion_event_id"] == first_response.json()[
        "import_completion_event_id"
    ]
    assert len(calls) == 2
    stored = app.state.nth.trade_rule_recognition_audit.verified_statements(
        package=package,
    )
    assert {item.digest for item in stored} == {first.digest, revoked.digest}
    assert len(first_response.json()["audit_event_ids"]) == 2
    states = trade_rules_api.recognition_proof_import_states(
        app.state.nth.spine.verified_snapshot(),
        package_digest=package.digest,
        order_digest=trade_order_digest(order),
    )
    assert len(states) == 1
    assert states[0].completed_event is not None
    assert states[0].payload["source_origin"] == "http://localhost:19090"
    assert states[0].payload["proof_digest"] == first_response.json()[
        "proof_digest"
    ]
    proof_store = trade_rules_api.RuleRecognitionProofStore(tmp_path / "node")
    assert proof_store.get(states[0].payload["proof_digest"]) == proof.canonical_bytes
    restarted = create_app(tmp_path / "node", require_console_auth=True)
    restarted_states = trade_rules_api.recognition_proof_import_states(
        restarted.state.nth.spine.verified_snapshot(),
        package_digest=package.digest,
        order_digest=trade_order_digest(order),
    )
    assert len(restarted_states) == 1
    assert restarted_states[0].completed_event is not None
    assert trade_rules_api.RuleRecognitionProofStore(
        tmp_path / "node"
    ).get(states[0].payload["proof_digest"]) == proof.canonical_bytes
    assert client.post(
        path,
        json={"peer_url": "http://localhost:19090"},
    ).status_code == 401


def test_operator_import_falls_back_to_signed_recognition_pages(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, delivery = _live_order_delivery(tmp_path, app)
    client = TestClient(app)
    assert client.post(
        "/api/v2/trade/federation/orders",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    ).status_code == 202
    package = context["package_store"].load(context["package_digest"])
    assert package is not None
    app.state.nth.trade_rule_packages.install(
        package.manifest,
        package.resources,
        source="local",
    )
    _issuer, first, revoked, legacy_proof = _observed_recognition_proof(
        context,
        package,
    )
    observed_at = datetime.fromisoformat(
        legacy_proof.to_dict()["observed_at"].replace("Z", "+00:00")
    )
    binding = sign_offer_package_binding(
        context["maker"],
        offer_digest=offer_digest(context["offer"]),
        package_digest=package.digest,
        created="2026-07-01T00:00:00Z",
    )
    monkeypatch.setattr(
        "nth_dao.trade_rules.recognition_transport_pages."
        "MAX_RULE_RECOGNITION_PROOF_PAGE_STATEMENTS",
        1,
    )
    wires = trade_rules_api.build_rule_recognition_proof_pages(
        package,
        legacy_proof.statements,
        offer_package_binding=binding,
        observer_identity=context["maker"],
        observed_at=legacy_proof.to_dict()["observed_at"],
        not_after=legacy_proof.to_dict()["not_after"],
        now=observed_at,
    )
    proof_set = trade_rules_api.parse_rule_recognition_proof_pages(
        wires,
        package=package,
        expected_offer_digest=offer_digest(context["offer"]),
        expected_offer_publisher_did=context["maker"].as_did(),
        now=observed_at,
    )
    page_calls = []

    def legacy_unavailable(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            "http://localhost:19090/recognition-proof",
            503,
            "legacy proof limit exceeded",
            {},
            None,
        )

    monkeypatch.setattr(
        web_v2_api,
        "_fetch_trade_rule_recognition_proof_from_peer",
        legacy_unavailable,
    )
    monkeypatch.setattr(
        web_v2_api,
        "_fetch_trade_rule_recognition_proof_pages_from_peer",
        lambda *_args, **_kwargs: page_calls.append(True) or proof_set,
    )
    auth = {"Authorization": f"Bearer {app.state.nth_console_token}"}
    path = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}/rule-packages/"
        f"{package.digest}/recognitions/import"
    )

    response = client.post(
        path,
        json={"peer_url": "http://localhost:19090"},
        headers=auth,
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["proof_protocol_version"] == "2"
    assert payload["page_count"] == 2
    assert len(payload["proof_digests"]) == 2
    assert len(payload["page_imports"]) == 2
    assert payload["imported_statement_count"] == 2
    assert page_calls == [True]
    assert {
        statement.digest
        for statement in app.state.nth.trade_rule_recognition_audit.verified_statements(
            package=package
        )
    } == {first.digest, revoked.digest}
    imports_path = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}/rule-packages/"
        f"{package.digest}/recognitions/imports"
    )
    healthy = client.get(imports_path, headers=auth)
    assert healthy.status_code == 200, healthy.text
    assert healthy.json()["total"] == 2
    assert {
        item["evidence_status"] for item in healthy.json()["items"]
    } == {"verified"}
    assert sorted(
        item["page_index"] for item in healthy.json()["items"]
    ) == [0, 1]
    assert {
        item["page_count"] for item in healthy.json()["items"]
    } == {2}
    assert {
        item["total_statement_count"] for item in healthy.json()["items"]
    } == {2}

    batch_path = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}/recognitions/imports"
    )
    spine = app.state.nth.trade_rule_recognition_audit.spine
    original_verified_snapshot = spine.verified_snapshot
    snapshot_calls = []

    def counted_verified_snapshot():
        snapshot_calls.append(True)
        return original_verified_snapshot()

    monkeypatch.setattr(spine, "verified_snapshot", counted_verified_snapshot)
    batch = client.get(
        batch_path,
        params=[("package_digest", package.digest)],
        headers=auth,
    )
    assert batch.status_code == 200, batch.text
    assert batch.json() == {
        "order_digest": trade_order_digest(order),
        "package_count": 1,
        "items": [healthy.json()],
    }
    assert snapshot_calls == [True]
    duplicate_batch = client.get(
        batch_path,
        params=[
            ("package_digest", package.digest),
            ("package_digest", package.digest),
        ],
        headers=auth,
    )
    assert duplicate_batch.status_code == 400

    proof_store = trade_rules_api.RuleRecognitionProofStore(tmp_path / "node")
    damaged_digest = proof_set.proof_digests[0]
    proof_store._path(damaged_digest).write_bytes(b"{}")
    degraded = client.get(imports_path, headers=auth)
    assert degraded.status_code == 200, degraded.text
    damaged = [
        item
        for item in degraded.json()["items"]
        if item["proof_digest"] == damaged_digest
    ]
    assert damaged[0]["evidence_status"] == "missing-or-corrupt"

    repaired = client.post(
        imports_path + "/repair",
        content=proof_set.pages[0].canonical_bytes,
        headers={**auth, "Content-Type": "application/json"},
    )
    assert repaired.status_code == 200, repaired.text
    assert repaired.json()["proof_repaired"] is True
    assert repaired.json()["proof_digest"] == damaged_digest
    restored = client.get(imports_path, headers=auth)
    assert {
        item["evidence_status"] for item in restored.json()["items"]
    } == {"verified"}


def test_recognition_import_deduplicates_refreshed_identical_observation(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, delivery = _live_order_delivery(tmp_path, app)
    client = TestClient(app)
    assert client.post(
        "/api/v2/trade/federation/orders",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    ).status_code == 202
    package = context["package_store"].load(context["package_digest"])
    assert package is not None
    app.state.nth.trade_rule_packages.install(
        package.manifest,
        package.resources,
        source="local",
    )
    _issuer, _first, _revoked, proof = _observed_recognition_proof(
        context,
        package,
    )
    refreshed = _refresh_observed_recognition_proof(
        context,
        package,
        proof,
    )
    assert refreshed.canonical_bytes != proof.canonical_bytes
    responses = iter((proof, refreshed))
    monkeypatch.setattr(
        web_v2_api,
        "_fetch_trade_rule_recognition_proof_from_peer",
        lambda *_args, **_kwargs: next(responses),
    )
    auth = {"Authorization": f"Bearer {app.state.nth_console_token}"}
    path = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}/rule-packages/"
        f"{package.digest}/recognitions/import"
    )

    initial = client.post(
        path,
        json={"peer_url": "http://localhost:19090"},
        headers=auth,
    )
    repeated = client.post(
        path,
        json={"peer_url": "http://localhost:19090"},
        headers=auth,
    )

    assert initial.status_code == 200, initial.text
    assert repeated.status_code == 200, repeated.text
    assert repeated.json()["status"] == "already-observed"
    assert repeated.json()["proof_digest"] == initial.json()["proof_digest"]
    assert repeated.json()["import_id"] == initial.json()["import_id"]
    states = trade_rules_api.recognition_proof_import_states(
        app.state.nth.spine.verified_snapshot(),
        package_digest=package.digest,
        order_digest=trade_order_digest(order),
    )
    assert len(states) == 1
    proof_files = list(
        (tmp_path / "node" / "trade" / "rule_recognition_proofs_v1").glob(
            "*.json"
        )
    )
    assert len(proof_files) == 1


def test_recognition_import_crash_prefix_is_incomplete_until_retry(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, delivery = _live_order_delivery(tmp_path, app)
    client = TestClient(app)
    assert client.post(
        "/api/v2/trade/federation/orders",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    ).status_code == 202
    package = context["package_store"].load(context["package_digest"])
    assert package is not None
    app.state.nth.trade_rule_packages.install(
        package.manifest,
        package.resources,
        source="local",
    )
    issuer, first, revoked, proof = _observed_multi_genesis_recognition_proof(
        context,
        package,
    )
    monkeypatch.setattr(
        web_v2_api,
        "_fetch_trade_rule_recognition_proof_from_peer",
        lambda *_args, **_kwargs: proof,
    )
    coordinator = app.state.nth.trade_rule_recognition_audit
    original_write = coordinator.store._atomic_write
    calls = 0

    def crash_during_batch(path, payload):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise trade_rules_api.RuleRecognitionStoreError(
                "simulated crash during Recognition batch"
            )
        return original_write(path, payload)

    monkeypatch.setattr(coordinator.store, "_atomic_write", crash_during_batch)
    auth = {"Authorization": f"Bearer {app.state.nth_console_token}"}
    path = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}/rule-packages/"
        f"{package.digest}/recognitions/import"
    )
    failed = client.post(
        path,
        json={"peer_url": "http://localhost:19090"},
        headers=auth,
    )

    assert failed.status_code == 503
    residue = coordinator.store.list_for_package(package)
    assert len(residue) == 1
    with pytest.raises(
        trade_rules_api.RuleRecognitionAuditIntegrityError,
        match="proof import is incomplete",
    ):
        coordinator.verified_statements(package=package)

    monkeypatch.setattr(coordinator.store, "_atomic_write", original_write)
    monkeypatch.setattr(
        web_v2_api,
        "_fetch_trade_rule_recognition_proof_from_peer",
        lambda *_args, **_kwargs: pytest.fail(
            "recovery must use the durable local proof CAS"
        ),
    )
    recovered = client.post(
        path,
        json={"peer_url": "http://localhost:19090"},
        headers=auth,
    )
    assert recovered.status_code == 200, recovered.text
    assert recovered.json()["imported_statement_count"] == 1
    complete = evaluate_rule_recognition(
        package,
        coordinator.verified_statements(package=package),
        policy=RuleRecognitionTrustPolicy(
            trusted_issuers=frozenset({issuer.as_did()}),
            issuer_rule_scopes={
                issuer.as_did(): (package.manifest.rule_id,)
            },
        ),
        at=datetime(2026, 8, 3, tzinfo=timezone.utc),
    )
    assert complete.observed_quorum_met is False
    assert complete.conflicted_issuers == (issuer.as_did(),)
    assert first.digest in {
        item.digest
        for item in coordinator.verified_statements(package=package)
    }


def test_recognition_import_status_and_exact_proof_repair(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, delivery = _live_order_delivery(tmp_path, app)
    client = TestClient(app)
    assert client.post(
        "/api/v2/trade/federation/orders",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    ).status_code == 202
    package = context["package_store"].load(context["package_digest"])
    assert package is not None
    app.state.nth.trade_rule_packages.install(
        package.manifest,
        package.resources,
        source="local",
    )
    _issuer, first, revoked, proof = _observed_recognition_proof(
        context,
        package,
    )
    proof_store = trade_rules_api.RuleRecognitionProofStore(tmp_path / "node")
    proof_digest, _created = proof_store.put(proof)
    proposed = trade_rules_api.recognition_proof_import_payload(
        proof,
        event_type=(
            trade_rules_api.EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED
        ),
        order_digest=trade_order_digest(order),
        offer_digest=offer_digest(context["offer"]),
        source_origin="http://localhost:19090",
    )
    trade_rules_api.append_recognition_proof_import_event(
        app.state.nth.spine,
        event_type=(
            trade_rules_api.EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED
        ),
        payload=proposed,
    )
    proof_store._path(proof_digest).write_bytes(b"{}")
    monkeypatch.setattr(
        web_v2_api,
        "_fetch_trade_rule_recognition_proof_from_peer",
        lambda *_args, **_kwargs: pytest.fail(
            "exact repair must recover from supplied CAS bytes"
        ),
    )
    auth = {"Authorization": f"Bearer {app.state.nth_console_token}"}
    base = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}/rule-packages/"
        f"{package.digest}/recognitions/imports"
    )

    assert client.get(base).status_code == 401
    degraded = client.get(base, headers=auth)
    assert degraded.status_code == 200, degraded.text
    assert degraded.json()["items"] == [
        {
            "import_id": proposed["import_id"],
            "status": "pending",
            "proof_digest": proof_digest,
            "observer_did": proposed["observer_did"],
            "observed_heads_digest": proposed["observed_heads_digest"],
            "source_origin": "http://localhost:19090",
            "statement_count": 2,
            "evidence_status": "missing-or-corrupt",
            "proposal_event_id": degraded.json()["items"][0][
                "proposal_event_id"
            ],
            "completion_event_id": None,
        }
    ]
    refreshed = _refresh_observed_recognition_proof(
        context,
        package,
        proof,
    )
    wrong = client.post(
        base + "/repair",
        content=refreshed.canonical_bytes,
        headers={**auth, "Content-Type": "application/json"},
    )
    assert wrong.status_code == 409
    repaired = client.post(
        base + "/repair",
        content=proof.canonical_bytes,
        headers={**auth, "Content-Type": "application/json"},
    )
    assert repaired.status_code == 200, repaired.text
    assert repaired.json()["proof_repaired"] is True
    assert repaired.json()["import_id"] == proposed["import_id"]
    assert {
        item.digest
        for item in app.state.nth.trade_rule_recognition_audit.verified_statements(
            package=package
        )
    } == {first.digest, revoked.digest}
    healthy = client.get(base, headers=auth)
    assert healthy.status_code == 200, healthy.text
    assert healthy.json()["items"][0]["status"] == "completed"
    assert healthy.json()["items"][0]["evidence_status"] == "verified"


def test_recognition_import_repair_rejects_oversized_authenticated_body(
    tmp_path,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    client = TestClient(app)
    digest = "sha256:" + ("1" * 64)
    path = (
        f"/api/v2/trade/orders/{digest}/rule-packages/{digest}/"
        "recognitions/imports/repair"
    )

    response = client.post(
        path,
        content=b"x" * ((256 * 1024) + 1),
        headers={
            "Authorization": f"Bearer {app.state.nth_console_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 413
    assert "256 KiB" in response.json()["detail"]


def test_recognition_import_rejects_unbound_or_missing_package_before_fetch(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, delivery = _live_order_delivery(tmp_path, app)
    client = TestClient(app)
    assert client.post(
        "/api/v2/trade/federation/orders",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    ).status_code == 202
    calls = []
    monkeypatch.setattr(
        web_v2_api,
        "_fetch_trade_rule_recognition_proof_from_peer",
        lambda *_args, **_kwargs: calls.append(True),
    )
    auth = {"Authorization": f"Bearer {app.state.nth_console_token}"}
    base = f"/api/v2/trade/orders/{trade_order_digest(order)}/rule-packages"

    missing = client.post(
        f"{base}/{context['package_digest']}/recognitions/import",
        json={"peer_url": "http://localhost:19090"},
        headers=auth,
    )
    unbound = client.post(
        f"{base}/sha256:{'0' * 64}/recognitions/import",
        json={"peer_url": "http://localhost:19090"},
        headers=auth,
    )

    assert missing.status_code == 409
    assert "must be imported" in missing.json()["detail"]
    assert unbound.status_code == 409
    assert "not bound" in unbound.json()["detail"]
    assert calls == []


def test_recognition_import_has_cross_package_global_concurrency_bound(
    tmp_path,
):
    with trade_rules_api.rule_recognition_import_slot(tmp_path):
        with trade_rules_api.rule_recognition_import_slot(tmp_path):
            with pytest.raises(
                trade_rules_api.RuleRecognitionProofImportBusy,
                match="concurrency is full",
            ):
                with trade_rules_api.rule_recognition_import_slot(tmp_path):
                    pytest.fail("a third import slot must not be granted")


def test_recognition_import_retry_repairs_store_first_anchor_failure(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, delivery = _live_order_delivery(tmp_path, app)
    client = TestClient(app)
    assert client.post(
        "/api/v2/trade/federation/orders",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    ).status_code == 202
    package = context["package_store"].load(context["package_digest"])
    assert package is not None
    app.state.nth.trade_rule_packages.install(
        package.manifest,
        package.resources,
        source="local",
    )
    _issuer, first, revoked, proof = _observed_recognition_proof(
        context,
        package,
    )
    monkeypatch.setattr(
        web_v2_api,
        "_fetch_trade_rule_recognition_proof_from_peer",
        lambda *_args, **_kwargs: proof,
    )
    coordinator = app.state.nth.trade_rule_recognition_audit
    original_append_many = coordinator.spine.append_unique_many
    failed_once = False

    def fail_recognition_anchor_batch(event_type, *args, **kwargs):
        nonlocal failed_once
        if (
            event_type
            == trade_rules_api.EVENT_TRADE_RULE_RECOGNITION_RECORDED
            and not failed_once
        ):
            failed_once = True
            raise trade_rules_api.RuleRecognitionAuditError(
                "simulated Spine failure"
            )
        return original_append_many(event_type, *args, **kwargs)

    monkeypatch.setattr(
        coordinator.spine,
        "append_unique_many",
        fail_recognition_anchor_batch,
    )
    auth = {"Authorization": f"Bearer {app.state.nth_console_token}"}
    path = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}/rule-packages/"
        f"{package.digest}/recognitions/import"
    )
    failed = client.post(
        path,
        json={"peer_url": "http://localhost:19090"},
        headers=auth,
    )
    assert failed.status_code == 503
    assert [
        item.digest
        for item in app.state.nth.trade_rule_recognitions.list_for_package(
            package
        )
    ] == [first.digest, revoked.digest]
    assert coordinator.verify_anchors(package=package)[0] is False

    monkeypatch.setattr(
        coordinator.spine,
        "append_unique_many",
        original_append_many,
    )
    monkeypatch.setattr(
        web_v2_api,
        "_fetch_trade_rule_recognition_proof_from_peer",
        lambda *_args, **_kwargs: pytest.fail(
            "recovery must not refetch an already staged proof"
        ),
    )
    recovered = client.post(
        path,
        json={"peer_url": "http://localhost:19090"},
        headers=auth,
    )
    assert recovered.status_code == 200, recovered.text
    assert recovered.json()["reconciled_anchor_count"] == 2
    assert recovered.json()["imported_statement_count"] == 0
    assert coordinator.verify_anchors(package=package) == (True, "ok")
    assert {
        item.digest
        for item in coordinator.verified_statements(package=package)
    } == {first.digest, revoked.digest}


def test_two_nodes_serve_import_restart_and_catalog_rule_package(tmp_path):
    source_workspace = tmp_path / "source"
    target_workspace = tmp_path / "target"
    source_app = create_app(source_workspace, require_console_auth=True)
    target_app = create_app(target_workspace, require_console_auth=True)
    context = _setup(
        tmp_path / "agreement-fixtures",
        maker=source_app.state.nth.node_identity,
        taker=target_app.state.nth.node_identity,
    )
    package_digest = context["package_digest"]
    for digest in (context["dependency_digest"], package_digest):
        package = context["package_store"].load(digest)
        assert package is not None
        source_app.state.nth.trade_rule_packages.install(
            package.manifest,
            package.resources,
            source="local",
        )

    source_client = TestClient(source_app)
    source_auth = {
        "Authorization": f"Bearer {source_app.state.nth_console_token}"
    }
    published = source_client.post(
        "/api/v2/trade/offers",
        json=context["offer"].to_dict(),
        headers=source_auth,
    )
    assert published.status_code == 200, published.text
    source_offer_digest = offer_digest(context["offer"])
    announced = source_client.post(
        f"/api/v2/trade/offers/{source_offer_digest}/announce",
        json={},
        headers=source_auth,
    )
    assert announced.status_code == 200, announced.text

    order = _order(context)
    created = datetime.now(timezone.utc).replace(microsecond=0)
    delivery = create_trade_order_delivery(
        context["maker"],
        order=order,
        created_at=created.isoformat().replace("+00:00", "Z"),
        not_after=(created + timedelta(minutes=5)).isoformat().replace(
            "+00:00", "Z"
        ),
        nonce="9a" * 16,
        now=created,
    )
    target_client = TestClient(target_app)
    accepted = target_client.post(
        "/api/v2/trade/federation/orders",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )
    assert accepted.status_code == 202, accepted.text
    source_client.close()
    target_client.close()
    source_node = _UvicornProcessServer(source_workspace, _free_tcp_port())
    target_node = _UvicornProcessServer(target_workspace, _free_tcp_port())
    import_path = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}/rule-packages/"
        f"{package_digest}/import"
    )
    try:
        source_node.start()
        target_node.start()
        imported = _process_http_json(
            target_node.url + import_path,
            payload={"peer_url": source_node.url},
            headers={"Authorization": f"Bearer {target_node.token}"},
        )
        assert imported["status"] == "installed"
        assert imported["package_digest"] == package_digest
        audit_event_id = imported["audit_event_id"]
        target_node.restart()
        catalog = _process_http_json(
            target_node.url + "/api/v2/trade/rule-packages",
            headers={"Authorization": f"Bearer {target_node.token}"},
        )
    finally:
        target_node.stop()
        source_node.stop()

    assert package_digest in {
        item["package_digest"] for item in catalog["items"]
    }
    catalog_item = next(
        item for item in catalog["items"]
        if item["package_digest"] == package_digest
    )
    assert catalog_item["import_audit"]["status"] == "anchored"
    assert catalog_item["provenance"] == {
        "status": "explicit",
        "sources": ["federated"],
    }
    restarted = create_app(target_workspace, require_console_auth=True)
    import_events = [
        event
        for event in restarted.state.nth.spine.verified_snapshot()
        if event.type == "trade.rule-package.imported"
    ]
    assert len(import_events) == 1
    assert import_events[0].event_id == audit_event_id
    assert import_events[0].payload["source_origin"] == source_node.url


def test_rule_package_detail_does_not_expose_store_exception_text(tmp_path):
    app = create_app(tmp_path / "node", require_console_auth=True)
    package_digest = "sha256:" + ("d" * 64)

    class BrokenPackageStore:
        def load(self, digest):
            assert digest == package_digest
            raise RulePackageCorruptionError(
                "secret-backend-detail token=do-not-leak"
            )

    app.state.nth.trade_rule_packages = BrokenPackageStore()
    response = TestClient(app).get(
        f"/api/v2/trade/rule-packages/{package_digest}",
        headers={
            "Authorization": f"Bearer {app.state.nth_console_token}"
        },
    )

    assert response.status_code == 503
    assert response.json() == {
        "detail": "trade rule package integrity failure"
    }
    assert "secret-backend-detail" not in response.text
    assert "token" not in response.text


def test_operator_package_import_recovers_missing_spine_audit_without_refetch(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, delivery = _live_order_delivery(tmp_path, app)
    client = TestClient(app)
    assert client.post(
        "/api/v2/trade/federation/orders",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    ).status_code == 202
    package_digest = context["package_digest"]
    package = context["package_store"].load(package_digest)
    assert package is not None
    fetch_calls = 0

    def fetch(*_args, **_kwargs):
        nonlocal fetch_calls
        fetch_calls += 1
        return package

    monkeypatch.setattr(
        web_v2_api,
        "_fetch_trade_rule_package_from_peer",
        fetch,
    )
    original_append_unique = app.state.nth.spine.append_unique
    audit_attempts = 0

    def fail_once(*args, **kwargs):
        nonlocal audit_attempts
        audit_attempts += 1
        if audit_attempts == 2:
            raise OSError("simulated Spine outage")
        return original_append_unique(*args, **kwargs)

    monkeypatch.setattr(app.state.nth.spine, "append_unique", fail_once)
    path = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}/rule-packages/"
        f"{package_digest}/import"
    )
    headers = {"Authorization": f"Bearer {app.state.nth_console_token}"}

    failed = client.post(
        path,
        json={"peer_url": "http://localhost:19090"},
        headers=headers,
    )

    assert failed.status_code == 503
    assert failed.headers["retry-after"] == "1"
    assert failed.json()["detail"] == {
        "code": "trade-rule-package-audit-incomplete",
        "message": "signed Trade Rule Package import audit is incomplete",
        "package_digest": package_digest,
        "retryable": True,
    }
    assert app.state.nth.trade_rule_packages.load(package_digest) is not None
    incomplete = client.get(
        f"/api/v2/trade/orders/{trade_order_digest(order)}",
        headers=headers,
    )
    assert incomplete.status_code == 200, incomplete.text
    assert incomplete.json()["execution"]["skills"][0]["status"] == "unavailable"
    catalog = client.get(
        "/api/v2/trade/rule-packages",
        headers=headers,
    )
    assert catalog.status_code == 200, catalog.text
    cached = next(
        item for item in catalog.json()["items"]
        if item["package_digest"] == package_digest
    )
    assert cached["import_audit"] == {
        "status": "incomplete",
        "proposed_count": 1,
        "anchored_count": 0,
        "incomplete_count": 1,
    }
    assert cached["provenance"] == {
        "status": "explicit",
        "sources": ["federated"],
    }
    recovered = client.post(
        path,
        json={"peer_url": "http://localhost:19090"},
        headers=headers,
    )
    assert recovered.status_code == 200, recovered.text
    assert recovered.json()["status"] == "already-installed"
    assert recovered.json()["audit_created"] is True
    assert fetch_calls == 1
    assert audit_attempts == 4
    assert len([
        event
        for event in app.state.nth.spine.verified_snapshot()
        if event.type == "trade.rule-package.imported"
    ]) == 1


def test_import_audit_recomputes_semantic_key_and_blocks_cross_order_cache(
    tmp_path,
):
    identity = AgentIdentity.generate(label="import-audit-reader")
    spine = SignedEventLog(tmp_path / "spine.jsonl", identity)
    package_digest = f"sha256:{'a' * 64}"
    first_order = f"sha256:{'b' * 64}"
    second_order = f"sha256:{'c' * 64}"
    import_id = web_v2_api._trade_rule_package_import_id(
        order_digest=first_order,
        package_digest=package_digest,
    )
    payload = {
        "import_id": import_id,
        "order_digest": first_order,
        "offer_digest": f"sha256:{'d' * 64}",
        "package_digest": package_digest,
        "rule_id": "org.nthdao.rules/delivery",
        "package_publisher_did": identity.as_did(),
        "source_origin": "https://peer.example",
        "action": "verified-cache-import-proposed",
    }
    spine.append("trade.rule-package.import.proposed", payload)
    cached_package = object()

    class Cache:
        @staticmethod
        def provenance_sources(digest):
            assert digest == package_digest
            return ("federated",)

        @staticmethod
        def load(digest):
            assert digest == package_digest
            return cached_package

    resolver = web_v2_api._OrderAuditedRulePackageResolver(
        Cache(),
        spine,
        second_order,
        tmp_path,
    )
    with pytest.raises(RuntimeError, match="audit is incomplete"):
        resolver.load(package_digest)

    spine.append(
        "trade.rule-package.imported",
        {**payload, "action": "verified-cache-import"},
    )
    assert resolver.load(package_digest) is cached_package

    malformed = SignedEventLog(tmp_path / "malformed.jsonl", identity)
    malformed.append(
        "trade.rule-package.import.proposed",
        {**payload, "import_id": "e" * 64},
    )
    with pytest.raises(RuntimeError, match="binding is invalid"):
        web_v2_api._trade_rule_package_import_audit_index(malformed)

    orphan = SignedEventLog(tmp_path / "orphan.jsonl", identity)
    orphan.append(
        "trade.rule-package.imported",
        {**payload, "action": "verified-cache-import"},
    )
    with pytest.raises(RuntimeError, match="missing its write-ahead intent"):
        web_v2_api._trade_rule_package_import_audit_index(orphan)

    conflicting = SignedEventLog(tmp_path / "conflicting.jsonl", identity)
    conflicting.append("trade.rule-package.import.proposed", payload)
    conflicting.append(
        "trade.rule-package.imported",
        {
            **payload,
            "offer_digest": f"sha256:{'e' * 64}",
            "rule_id": "org.nthdao.rules/conflicting",
            "source_origin": "https://other.example",
            "action": "verified-cache-import",
        },
    )
    with pytest.raises(RuntimeError, match="binding conflicts across stages"):
        web_v2_api._trade_rule_package_import_audit_index(conflicting)

    duplicate = SignedEventLog(tmp_path / "duplicate.jsonl", identity)
    duplicate.append("trade.rule-package.import.proposed", payload)
    duplicate.append("trade.rule-package.import.proposed", payload)
    with pytest.raises(RuntimeError, match="duplicate semantic event"):
        web_v2_api._trade_rule_package_import_audit_index(duplicate)


def test_order_audited_resolver_reuses_snapshot_and_shares_import_lock(tmp_path):
    identity = AgentIdentity.generate(label="import-audit-cache")
    signed_spine = SignedEventLog(tmp_path / "spine.jsonl", identity)

    class CountingSpine:
        def __init__(self):
            self.verified_calls = 0

        def storage_token(self):
            return signed_spine.storage_token()

        def verified_snapshot_with_token(self):
            self.verified_calls += 1
            return signed_spine.verified_snapshot_with_token()

    packages = {
        f"sha256:{'6' * 64}": object(),
        f"sha256:{'7' * 64}": object(),
    }

    class Cache:
        @staticmethod
        def provenance_sources(digest):
            assert digest in packages
            return ("local",)

        @staticmethod
        def load(digest):
            return packages.get(digest)

    spine = CountingSpine()
    resolver = web_v2_api._OrderAuditedRulePackageResolver(
        Cache(),
        spine,
        f"sha256:{'8' * 64}",
        tmp_path,
    )
    first_digest, second_digest = packages
    held = InterProcessLock(
        web_v2_api._trade_rule_package_import_lock_target(
            tmp_path,
            first_digest,
        ),
        timeout=1.0,
    )
    held.acquire()
    released = False
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(resolver.load, first_digest)
            time.sleep(0.1)
            assert not pending.done()
            held.release()
            released = True
            assert pending.result(timeout=3) is packages[first_digest]
    finally:
        if not released:
            held.release()

    assert resolver.load(second_digest) is packages[second_digest]
    assert resolver.load(first_digest) is packages[first_digest]
    assert spine.verified_calls == 1


def test_order_audited_resolver_rejects_unclassified_and_unaudited_federation(
    tmp_path,
):
    identity = AgentIdentity.generate(label="provenance-reader")
    spine = SignedEventLog(tmp_path / "spine.jsonl", identity)
    package_digest = f"sha256:{'9' * 64}"
    package = object()

    class Cache:
        sources: tuple[str, ...] = ()

        @classmethod
        def provenance_sources(cls, digest):
            assert digest == package_digest
            return cls.sources

        @staticmethod
        def load(digest):
            assert digest == package_digest
            return package

    resolver = web_v2_api._OrderAuditedRulePackageResolver(
        Cache(),
        spine,
        f"sha256:{'8' * 64}",
        tmp_path,
    )

    with pytest.raises(RuntimeError, match="provenance is unclassified"):
        resolver.load(package_digest)

    Cache.sources = ("federated",)
    with pytest.raises(RuntimeError, match="lacks a signed import anchor"):
        resolver.load(package_digest)

    Cache.sources = ("local",)
    assert resolver.load(package_digest) is package


def test_operator_package_import_rejects_digest_outside_order_before_fetch(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    _context, order, delivery = _live_order_delivery(tmp_path, app)
    client = TestClient(app)
    assert client.post(
        "/api/v2/trade/federation/orders",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    ).status_code == 202

    def forbidden_fetch(*_args, **_kwargs):
        raise AssertionError("unbound package must not trigger network I/O")

    monkeypatch.setattr(
        web_v2_api,
        "_fetch_trade_rule_package_from_peer",
        forbidden_fetch,
    )
    response = client.post(
        f"/api/v2/trade/orders/{trade_order_digest(order)}/rule-packages/"
        f"sha256:{'e' * 64}/import",
        json={"peer_url": "http://localhost:19090"},
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )
    assert response.status_code == 409


def test_operator_package_import_rejects_unknown_request_fields_before_fetch(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, delivery = _live_order_delivery(tmp_path, app)
    client = TestClient(app)
    assert client.post(
        "/api/v2/trade/federation/orders",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    ).status_code == 202

    def forbidden_fetch(*_args, **_kwargs):
        raise AssertionError("invalid request must not trigger network I/O")

    monkeypatch.setattr(
        web_v2_api,
        "_fetch_trade_rule_package_from_peer",
        forbidden_fetch,
    )
    response = client.post(
        f"/api/v2/trade/orders/{trade_order_digest(order)}/rule-packages/"
        f"{context['package_digest']}/import",
        json={
            "peer_url": "http://localhost:19090",
            "unexpected": "silently accepted before this fix",
        },
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )

    assert response.status_code == 422


def test_operator_package_import_single_flights_concurrent_fetches(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, delivery = _live_order_delivery(tmp_path, app)
    client = TestClient(app)
    assert client.post(
        "/api/v2/trade/federation/orders",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    ).status_code == 202
    package_digest = context["package_digest"]
    package = context["package_store"].load(package_digest)
    assert package is not None
    calls = 0
    calls_lock = threading.Lock()

    def fetch(
        peer_url,
        *,
        offer_digest,
        package_digest,
        offer_publisher_did,
        timeout_seconds=15.0,
    ):
        del (
            peer_url,
            offer_digest,
            package_digest,
            offer_publisher_did,
            timeout_seconds,
        )
        nonlocal calls
        with calls_lock:
            calls += 1
        time.sleep(0.2)
        return package

    monkeypatch.setattr(
        web_v2_api,
        "_fetch_trade_rule_package_from_peer",
        fetch,
    )
    path = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}/rule-packages/"
        f"{package_digest}/import"
    )
    headers = {"Authorization": f"Bearer {app.state.nth_console_token}"}

    with ThreadPoolExecutor(max_workers=6) as pool:
        responses = list(pool.map(
            lambda _index: client.post(
                path,
                json={"peer_url": "http://localhost:19090"},
                headers=headers,
            ),
            range(6),
        ))

    assert [response.status_code for response in responses] == [200] * 6
    assert calls == 1
    assert sum(response.json()["installed"] for response in responses) == 1
    assert sum(response.json()["audit_created"] for response in responses) == 1
    assert len({response.json()["audit_event_id"] for response in responses}) == 1
    assert len([
        event
        for event in app.state.nth.spine.verified_snapshot()
        if event.type == "trade.rule-package.imported"
    ]) == 1


def test_operator_package_import_uses_cross_process_global_slots(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, delivery = _live_order_delivery(tmp_path, app)
    client = TestClient(app)
    assert client.post(
        "/api/v2/trade/federation/orders",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    ).status_code == 202
    package_digest = context["package_digest"]
    package = context["package_store"].load(package_digest)
    assert package is not None
    fetch_calls = 0

    def fetch(*_args, **_kwargs):
        nonlocal fetch_calls
        fetch_calls += 1
        return package

    monkeypatch.setattr(
        web_v2_api,
        "_fetch_trade_rule_package_from_peer",
        fetch,
    )
    slot_root = (
        Path(app.state.nth.workspace)
        / "trade"
        / "rule_package_import_slots"
    )
    holders = []
    hold_script = (
        "import sys,time;"
        "from pathlib import Path;"
        "from nth_dao.util import InterProcessLock;"
        "lock=InterProcessLock(Path(sys.argv[1]),timeout=5.0);"
        "lock.acquire();"
        "Path(sys.argv[2]).write_text('ready',encoding='ascii');"
        "time.sleep(120)"
    )
    for index in range(web_v2_api._TRADE_RULE_PACKAGE_IMPORT_MAX_CONCURRENCY):
        ready = tmp_path / f"slot-{index}.ready"
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                hold_script,
                str(slot_root / str(index)),
                str(ready),
            ],
            cwd=str(Path(__file__).resolve().parents[1]),
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=(
                subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            ),
        )
        deadline = time.monotonic() + 10.0
        while not ready.exists() and time.monotonic() < deadline:
            assert process.poll() is None
            time.sleep(0.025)
        assert ready.exists()
        holders.append(process)
    path = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}/rule-packages/"
        f"{package_digest}/import"
    )
    headers = {"Authorization": f"Bearer {app.state.nth_console_token}"}
    try:
        blocked = client.post(
            path,
            json={"peer_url": "http://localhost:19090"},
            headers=headers,
        )
        assert blocked.status_code == 503
        assert blocked.headers["retry-after"] == "1"
        assert blocked.json()["detail"] == (
            "Trade Rule Package import concurrency is full"
        )
        assert fetch_calls == 0

        crashed = holders.pop()
        crashed.terminate()
        crashed.wait(timeout=10.0)
        recovered = client.post(
            path,
            json={"peer_url": "http://localhost:19090"},
            headers=headers,
        )
        assert recovered.status_code == 200, recovered.text
        assert fetch_calls == 1
    finally:
        for process in holders:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=10.0)


def test_agreement_rest_exposes_verified_execution_receipt_history(tmp_path):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, delivery = _live_order_delivery(tmp_path, app)
    client = TestClient(app)
    accepted = client.post(
        "/api/v2/trade/federation/orders",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )
    assert accepted.status_code == 202
    receipt = _execution_receipt(
        context,
        order,
        coordinator=app.state.nth.trade_execution_coordinator,
    )

    detail = client.get(
        f"/api/v2/trade/orders/{trade_order_digest(order)}",
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )

    assert detail.status_code == 200, detail.text
    history = detail.json()["execution"]["history"]
    assert history["status"] == "available"
    assert history["has_more"] is False
    assert history["error_code"] == ""
    assert history["items"] == [{
        "execution_id": receipt.execution_id,
        "receipt_digest": execution_receipt_digest(receipt, order=order),
        "audit_event_id": app.state.nth.spine.verified_snapshot()[-1].event_id,
        "audit_seq": app.state.nth.spine.verified_snapshot()[-1].seq,
        "executor_did": context["maker"].as_did(),
        "executor_role": "maker",
        "operation_id": "deliver-service",
        "hook_name": "fulfillment.deliver",
        "side_effect": "none",
        "adapter_id": context["adapter"].to_dict()["adapter_id"],
        "adapter_version": context["adapter"].to_dict()["adapter_version"],
        "execution_mode": "declarative",
        "outcome": "succeeded",
        "started_at": "2026-09-01T00:00:00Z",
        "completed_at": "2026-09-01T00:01:00Z",
        "federation_status": "local-only",
        "dispatch_target_url": "",
        "dispatch_attempts": 0,
        "dispatch_last_error": "",
        "dispatch_generation": 0,
        "dispatch_superseded_deliveries": 0,
        "remote_acknowledgement_digest": "",
        "remote_receiver_did": "",
        "remote_audit_event_id": "",
        "remote_received_at": "",
    }]


def test_agreement_history_isolates_dispatch_projection_failure(tmp_path):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, delivery = _live_order_delivery(tmp_path, app)
    client = TestClient(app)
    assert client.post(
        "/api/v2/trade/federation/orders",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    ).status_code == 202
    _execution_receipt(
        context,
        order,
        coordinator=app.state.nth.trade_execution_coordinator,
    )

    class BrokenDispatchStore:
        def get_states(self, _receipt_digests):
            raise OSError("sensitive-dispatch-location")

    app.state.nth.trade_execution_dispatch_store = BrokenDispatchStore()
    detail = client.get(
        f"/api/v2/trade/orders/{trade_order_digest(order)}",
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )

    assert detail.status_code == 200, detail.text
    history = detail.json()["execution"]["history"]
    assert history["status"] == "available"
    assert history["items"][0]["federation_status"] == "unavailable"
    assert detail.json()["execution"]["coordinator"]["status"] == "healthy"
    assert "sensitive-dispatch-location" not in json.dumps(detail.json())


def _current_execution_receipt(context, order, *, coordinator=None):
    completed = datetime.now(timezone.utc).replace(microsecond=0)
    started = completed - timedelta(seconds=1)

    def wire(moment):
        return moment.isoformat().replace("+00:00", "Z")

    return _execution_receipt(
        context,
        order,
        coordinator=coordinator,
        started_at=wire(started),
        completed_at=wire(completed),
        now=completed,
    )


def _configure_live_execution_receiver(app, context) -> None:
    app.state.nth.trade_rule_packages = context["package_store"]
    app.state.nth.trade_executor_policy = context["taker_policy"]
    app.state.nth.trade_execution_adapter_resolver = context[
        "adapter_resolver"
    ]
    app.state.nth.trade_execution_adapter_policy = context["adapter_policy"]
    app.state.nth.trade_execution_content_resolver = context[
        "content_resolver"
    ]
    app.state.nth.trade_execution_schema_validator = context[
        "schema_validator"
    ]


def test_public_execution_receipt_delivery_reverifies_and_returns_signed_ack(
    tmp_path,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, order_delivery = _live_order_delivery(tmp_path, app)
    client = TestClient(app)
    accepted = client.post(
        "/api/v2/trade/federation/orders",
        content=order_delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )
    assert accepted.status_code == 202, accepted.text
    app.state.nth.trade_rule_packages = context["package_store"]
    app.state.nth.trade_executor_policy = context["taker_policy"]
    app.state.nth.trade_execution_adapter_resolver = context[
        "adapter_resolver"
    ]
    app.state.nth.trade_execution_adapter_policy = context["adapter_policy"]
    app.state.nth.trade_execution_content_resolver = context[
        "content_resolver"
    ]
    app.state.nth.trade_execution_schema_validator = context[
        "schema_validator"
    ]
    receipt = _current_execution_receipt(context, order)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    delivery = create_trade_execution_receipt_delivery(
        context["maker"],
        receipt=receipt,
        order=order,
        created_at=now.isoformat().replace("+00:00", "Z"),
        not_after=(now + timedelta(minutes=5)).isoformat().replace(
            "+00:00", "Z"
        ),
        now=now,
    )
    path = (
        f"/api/v2/trade/federation/orders/{trade_order_digest(order)}"
        "/execution-receipts"
    )

    first = client.post(
        path,
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )
    retry = client.post(
        path,
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )

    assert first.status_code == 202, first.text
    assert retry.status_code == 202, retry.text
    assert first.json()["status"] == "execution-receipt-retained-verified"
    assert first.json()["receipt_store_created"] is True
    assert retry.json()["receipt_store_created"] is False
    acknowledgement = TradeExecutionReceiptAcknowledgement.from_dict(
        first.json()["acknowledgement"]
    )
    assert verify_trade_execution_receipt_acknowledgement(
        acknowledgement,
        delivery=delivery,
        order=order,
        receiver_did=app.state.nth.node_identity.as_did(),
        audit_event_id=first.json()["audit_event_id"],
    ) == (True, "ok")
    assert retry.json()["acknowledgement"] == first.json()["acknowledgement"]
    anchors = [
        event
        for event in app.state.nth.spine.verified_snapshot()
        if event.type == trade_rules_api.EVENT_TRADE_EXECUTION_RECORDED
    ]
    assert len(anchors) == 1


def test_public_execution_receipt_delivery_requires_explicit_local_runtime(
    tmp_path,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, order_delivery = _live_order_delivery(tmp_path, app)
    client = TestClient(app)
    assert client.post(
        "/api/v2/trade/federation/orders",
        content=order_delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    ).status_code == 202
    receipt = _current_execution_receipt(context, order)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    delivery = create_trade_execution_receipt_delivery(
        context["maker"],
        receipt=receipt,
        order=order,
        created_at=now.isoformat().replace("+00:00", "Z"),
        not_after=(now + timedelta(minutes=5)).isoformat().replace(
            "+00:00", "Z"
        ),
        now=now,
    )

    response = client.post(
        f"/api/v2/trade/federation/orders/{trade_order_digest(order)}"
        "/execution-receipts",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 503
    assert response.json()["detail"]["code"] == (
        "execution-receipt-intake-not-configured"
    )


def test_public_execution_receipt_rejects_unaudited_federated_package(
    tmp_path,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, order_delivery = _live_order_delivery(tmp_path, app)
    client = TestClient(app)
    assert client.post(
        "/api/v2/trade/federation/orders",
        content=order_delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    ).status_code == 202

    class FederatedPackageCache:
        @staticmethod
        def load(package_digest):
            return context["package_store"].load(package_digest)

        @staticmethod
        def provenance_sources(_package_digest):
            return ("federated",)

    app.state.nth.trade_rule_packages = FederatedPackageCache()
    app.state.nth.trade_executor_policy = context["taker_policy"]
    app.state.nth.trade_execution_adapter_resolver = context[
        "adapter_resolver"
    ]
    app.state.nth.trade_execution_adapter_policy = context["adapter_policy"]
    app.state.nth.trade_execution_content_resolver = context[
        "content_resolver"
    ]
    app.state.nth.trade_execution_schema_validator = context[
        "schema_validator"
    ]
    receipt = _current_execution_receipt(context, order)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    delivery = create_trade_execution_receipt_delivery(
        context["maker"],
        receipt=receipt,
        order=order,
        created_at=now.isoformat().replace("+00:00", "Z"),
        not_after=(now + timedelta(minutes=5)).isoformat().replace(
            "+00:00", "Z"
        ),
        now=now,
    )

    response = client.post(
        f"/api/v2/trade/federation/orders/{trade_order_digest(order)}"
        "/execution-receipts",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == ("execution-receipt-policy-rejected")
    assert (
        app.state.nth.trade_execution_receipts.get(
            receipt.execution_id,
            order=order,
        )
        is None
    )


def test_public_execution_receipt_budget_precedes_runtime_disclosure(tmp_path):
    app = create_app(tmp_path / "node", require_console_auth=True)
    per_client = RateLimiter(max_per_window=1, window_seconds=60)
    global_limiter = RateLimiter(max_per_window=1, window_seconds=60)
    per_client.check("testclient")
    global_limiter.check("global")
    app.state.nth.trade_execution_receipt_delivery_limiter = per_client
    app.state.nth.trade_execution_receipt_delivery_global_limiter = (
        global_limiter
    )

    response = TestClient(app).post(
        f"/api/v2/trade/federation/orders/{'sha256:' + '1' * 64}/execution-receipts",
        json={},
    )

    assert response.status_code == 429


def _retain_order_and_receipt(app, context, order, receipt) -> None:
    moment = int(datetime.now(timezone.utc).timestamp() * 1_000)
    app.state.nth.trade_order_audit.accept(order, now_ms=moment)
    app.state.nth.trade_execution_coordinator.record(
        receipt,
        order=order,
        now_ms=moment,
    )


def test_operator_signs_and_reads_local_receipt_review(tmp_path):
    app = create_app(tmp_path / "taker", require_console_auth=True)
    context = _setup(
        tmp_path / "fixtures",
        taker=app.state.nth.node_identity,
    )
    order = _order(context)
    receipt = _current_execution_receipt(context, order)
    _retain_order_and_receipt(app, context, order, receipt)
    _configure_live_execution_receiver(app, context)
    auth = {"Authorization": f"Bearer {app.state.nth_console_token}"}
    path = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}"
        f"/execution-receipts/{receipt.execution_id}/reviews"
    )
    client = TestClient(app)

    created = client.post(
        path,
        json={"decision": "accepted", "reason_codes": []},
        headers=auth,
    )
    fetched = client.get(path, headers=auth)

    assert created.status_code == 201, created.text
    assert created.json()["status"] == "review-signed"
    assert created.json()["review"]["reviewer_did"] == (
        app.state.nth.node_identity.as_did()
    )
    assert created.json()["is_counterparty_claim"] is True
    assert fetched.status_code == 200, fetched.text
    assert fetched.json()["status"] == "reviewed"
    assert fetched.json()["review_id"] == created.json()["review_id"]
    assert fetched.json()["federation"]["status"] == "local-only"
    assert app.state.nth.spine.verify_chain() == (True, "ok")


def test_public_receipt_review_replays_signed_policies_and_returns_ack(
    tmp_path,
):
    app = create_app(tmp_path / "maker", require_console_auth=True)
    context = _setup(
        tmp_path / "fixtures",
        maker=app.state.nth.node_identity,
    )
    order = _order(context)
    receipt = _current_execution_receipt(context, order)
    _retain_order_and_receipt(app, context, order, receipt)
    _configure_live_execution_receiver(app, context)
    reviewed = datetime.now(timezone.utc) + timedelta(seconds=1)
    if reviewed.microsecond == 0:
        reviewed = reviewed.replace(microsecond=1)
    reviewed_at = reviewed.isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )
    review = create_trade_receipt_review(
        context["taker"],
        receipt=receipt,
        order=order,
        package_resolver=context["package_store"],
        verifier_policy=context["taker_policy"],
        adapter_resolver=context["adapter_resolver"],
        adapter_policy=context["adapter_policy"],
        content_resolver=context["content_resolver"],
        schema_validator=context["schema_validator"],
        decision="accepted",
        reviewed_at=reviewed_at,
        now=reviewed,
    )
    delivery = create_trade_receipt_review_delivery(
        context["taker"],
        review=review,
        receipt=receipt,
        order=order,
        verifier_policy=context["taker_policy"],
        adapter_policy=context["adapter_policy"],
        created_at=reviewed_at,
        not_after=(reviewed + timedelta(minutes=5)).isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z"),
        now=reviewed,
    )
    path = (
        f"/api/v2/trade/federation/orders/{trade_order_digest(order)}"
        f"/execution-receipts/{receipt.execution_id}/reviews"
    )

    first = TestClient(app).post(
        path,
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )
    retry = TestClient(app).post(
        path,
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )

    assert first.status_code == 202, first.text
    assert retry.status_code == 202, retry.text
    assert first.json()["status"] == "receipt-review-retained-verified"
    assert first.json()["review_store_created"] is True
    assert retry.json()["review_store_created"] is False
    acknowledgement = TradeReceiptReviewAcknowledgement.from_dict(
        first.json()["acknowledgement"]
    )
    assert verify_trade_receipt_review_acknowledgement(
        acknowledgement,
        delivery=delivery,
        receipt=receipt,
        order=order,
        receiver_did=app.state.nth.node_identity.as_did(),
        audit_event_id=first.json()["audit_event_id"],
    ) == (True, "ok")
    assert retry.json()["acknowledgement"] == first.json()["acknowledgement"]


def test_public_receipt_review_endpoint_enforces_preparse_body_limit(tmp_path):
    client = TestClient(create_app(tmp_path, require_console_auth=True))
    path = (
        "/api/v2/trade/federation/orders/sha256:"
        + ("0" * 64)
        + "/execution-receipts/nth-trade-execution-sha256:"
        + ("1" * 64)
        + "/reviews"
    )

    response = client.post(
        path,
        content=b"{" + (b"x" * (2 * 1024 * 1024)) + b"}",
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert "2048 KiB" in response.json()["detail"]


def test_public_receipt_review_chunked_body_is_bounded_without_length():
    downstream_completed = False

    async def drain(_scope, receive, send):
        nonlocal downstream_completed
        while True:
            message = await receive()
            if not message.get("more_body", False):
                break
        downstream_completed = True
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    chunks = [
        {
            "type": "http.request",
            "body": b"x" * (2 * 1024 * 1024),
            "more_body": True,
        },
        {"type": "http.request", "body": b"x", "more_body": False},
    ]
    sent = []

    async def receive():
        return chunks.pop(0)

    async def send(message):
        sent.append(message)

    asyncio.run(
        _FederationBodyLimitMiddleware(drain)(
            {
                "type": "http",
                "method": "POST",
                "path": (
                    "/api/v2/trade/federation/orders/sha256:"
                    + ("0" * 64)
                    + "/execution-receipts/nth-trade-execution-sha256:"
                    + ("1" * 64)
                    + "/reviews"
                ),
                "headers": [],
            },
            receive,
            send,
        )
    )

    assert downstream_completed is False
    assert sent[0]["status"] == 413


def test_operator_delivers_receipt_review_once_and_projects_ack(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "taker", require_console_auth=True)
    context = _setup(
        tmp_path / "fixtures",
        taker=app.state.nth.node_identity,
    )
    order = _order(context)
    receipt = _current_execution_receipt(context, order)
    _retain_order_and_receipt(app, context, order, receipt)
    _configure_live_execution_receiver(app, context)
    auth = {"Authorization": f"Bearer {app.state.nth_console_token}"}
    base = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}"
        f"/execution-receipts/{receipt.execution_id}/reviews"
    )
    client = TestClient(app)
    created = client.post(
        base,
        json={"decision": "accepted", "reason_codes": []},
        headers=auth,
    )
    assert created.status_code == 201, created.text
    review_id = created.json()["review_id"]
    network_calls = 0

    def receive(
        peer_url,
        sent_order_digest,
        sent_execution_id,
        document,
        *,
        timeout_seconds=15.0,
    ):
        nonlocal network_calls
        network_calls += 1
        assert peer_url == "http://127.0.0.1:18083"
        assert sent_order_digest == trade_order_digest(order)
        assert sent_execution_id == receipt.execution_id
        delivery = TradeReceiptReviewDelivery.from_dict(
            document,
            receipt=receipt,
            order=order,
        )
        acknowledgement = create_trade_receipt_review_acknowledgement(
            context["maker"],
            delivery=delivery,
            receipt=receipt,
            order=order,
            received_at=delivery.to_dict()["created_at"],
            audit_event_id="c" * 64,
        )
        return 202, {
            "status": "receipt-review-retained-verified",
            "audit_event_id": "c" * 64,
            "acknowledgement": acknowledgement.to_dict(),
        }

    monkeypatch.setattr(
        web_v2_api,
        "_post_trade_receipt_review_delivery_to_peer",
        receive,
    )
    delivery_path = f"{base}/{review_id}/deliver"
    first = client.post(
        delivery_path,
        json={"target_url": "http://127.0.0.1:18083"},
        headers=auth,
    )
    retry = client.post(
        delivery_path,
        json={"target_url": "http://127.0.0.1:18083"},
        headers=auth,
    )
    wrong_target = client.post(
        delivery_path,
        json={"target_url": "http://127.0.0.1:18084"},
        headers=auth,
    )
    projected = client.get(base, headers=auth)

    assert first.status_code == 200, first.text
    assert retry.status_code == 200, retry.text
    assert first.json()["status"] == "receipt-review-delivered"
    assert retry.json() == first.json()
    assert wrong_target.status_code == 409, wrong_target.text
    assert "different peer target" in wrong_target.json()["detail"]
    assert network_calls == 1
    assert projected.status_code == 200, projected.text
    assert projected.json()["federation"]["status"] == "acknowledged"
    assert projected.json()["federation"]["remote_receiver_did"] == (
        context["maker"].as_did()
    )
    assert projected.json()["federation"]["remote_audit_event_id"] == (
        "c" * 64
    )


def test_receipt_review_delivery_survives_policy_rotation_and_restart(
    tmp_path,
    monkeypatch,
):
    runtime = tmp_path / "taker"
    app = create_app(runtime, require_console_auth=True)
    context = _setup(
        tmp_path / "fixtures",
        taker=app.state.nth.node_identity,
    )
    order = _order(context)
    receipt = _current_execution_receipt(context, order)
    _retain_order_and_receipt(app, context, order, receipt)
    _configure_live_execution_receiver(app, context)
    client = TestClient(app)
    auth = {"Authorization": f"Bearer {app.state.nth_console_token}"}
    base = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}"
        f"/execution-receipts/{receipt.execution_id}/reviews"
    )
    created = client.post(
        base,
        json={"decision": "accepted", "reason_codes": []},
        headers=auth,
    )
    assert created.status_code == 201, created.text

    restarted = create_app(runtime, require_console_auth=True)
    _configure_live_execution_receiver(restarted, context)
    rotated_policy = TradeExecutionAdapterPolicy(
        accepted_adapter_digests=frozenset(),
        allowed_execution_modes=frozenset({"declarative"}),
        allowed_permissions=frozenset(),
    )
    assert rotated_policy.digest != context["adapter_policy"].digest
    restarted.state.nth.trade_execution_adapter_policy = rotated_policy
    network_calls = 0

    def receive(
        _peer_url,
        _order_digest,
        _execution_id,
        document,
        *,
        timeout_seconds=15.0,
    ):
        nonlocal network_calls
        network_calls += 1
        delivery = TradeReceiptReviewDelivery.from_dict(
            document,
            receipt=receipt,
            order=order,
        )
        assert delivery.adapter_policy.digest == context["adapter_policy"].digest
        acknowledgement = create_trade_receipt_review_acknowledgement(
            context["maker"],
            delivery=delivery,
            receipt=receipt,
            order=order,
            received_at=delivery.to_dict()["created_at"],
            audit_event_id="d" * 64,
        )
        return 202, {
            "audit_event_id": "d" * 64,
            "acknowledgement": acknowledgement.to_dict(),
        }

    monkeypatch.setattr(
        web_v2_api,
        "_post_trade_receipt_review_delivery_to_peer",
        receive,
    )
    restarted_client = TestClient(restarted)
    response = restarted_client.post(
        f"{base}/{created.json()['review_id']}/deliver",
        json={"target_url": "http://127.0.0.1:18083"},
        headers={
            "Authorization": f"Bearer {restarted.state.nth_console_token}"
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "receipt-review-delivered"
    assert network_calls == 1


def test_receipt_review_delivery_rejects_corrupt_policy_before_network(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "taker", require_console_auth=True)
    context = _setup(
        tmp_path / "fixtures",
        taker=app.state.nth.node_identity,
    )
    order = _order(context)
    receipt = _current_execution_receipt(context, order)
    _retain_order_and_receipt(app, context, order, receipt)
    _configure_live_execution_receiver(app, context)
    client = TestClient(app)
    auth = {"Authorization": f"Bearer {app.state.nth_console_token}"}
    base = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}"
        f"/execution-receipts/{receipt.execution_id}/reviews"
    )
    created = client.post(
        base,
        json={"decision": "accepted", "reason_codes": []},
        headers=auth,
    )
    assert created.status_code == 201, created.text
    review_digest = created.json()["review_digest"]
    outbox = app.state.nth.trade_receipt_review_coordinator.audit_outbox
    path = outbox._path(review_digest)
    document = json.loads(path.read_text(encoding="utf-8"))
    document["adapter_policy_b64u"] = "AA"
    path.write_bytes(canonical_json(document))
    network_calls = 0

    def receive(*_args, **_kwargs):
        nonlocal network_calls
        network_calls += 1
        raise AssertionError("network must not receive a corrupt Review")

    monkeypatch.setattr(
        web_v2_api,
        "_post_trade_receipt_review_delivery_to_peer",
        receive,
    )
    response = client.post(
        f"{base}/{created.json()['review_id']}/deliver",
        json={"target_url": "http://127.0.0.1:18083"},
        headers=auth,
    )

    assert response.status_code == 409
    assert response.json()["detail"] == (
        "Receipt Review policy snapshots are unavailable or invalid"
    )
    assert str(path) not in response.text
    assert network_calls == 0


def test_public_receipt_review_budget_precedes_runtime_disclosure(tmp_path):
    app = create_app(tmp_path / "node", require_console_auth=True)
    per_client = RateLimiter(max_per_window=1, window_seconds=60)
    global_limiter = RateLimiter(max_per_window=1, window_seconds=60)
    per_client.check("testclient")
    global_limiter.check("global")
    app.state.nth.trade_receipt_review_delivery_limiter = per_client
    app.state.nth.trade_receipt_review_delivery_global_limiter = global_limiter

    response = TestClient(app).post(
        f"/api/v2/trade/federation/orders/{'sha256:' + '1' * 64}"
        "/execution-receipts/"
        f"{'nth-trade-execution-sha256:' + '2' * 64}/reviews",
        json={},
    )

    assert response.status_code == 429


def _live_dispute_statement_delivery(tmp_path, app, *, receiver_role="taker"):
    assert receiver_role in {"maker", "taker"}
    context = _setup(
        tmp_path / "fixtures",
        **{receiver_role: app.state.nth.node_identity},
    )
    order = _order(context)
    receipt = _current_execution_receipt(context, order)
    _retain_order_and_receipt(app, context, order, receipt)
    _configure_live_execution_receiver(app, context)
    moment = datetime.now(timezone.utc)
    if moment.microsecond == 0:
        moment = moment.replace(microsecond=1)
    reviewed_at = moment.isoformat(timespec="microseconds").replace(
        "+00:00",
        "Z",
    )
    review = create_trade_receipt_review(
        context["taker"],
        receipt=receipt,
        order=order,
        package_resolver=context["package_store"],
        verifier_policy=context["taker_policy"],
        adapter_resolver=context["adapter_resolver"],
        adapter_policy=context["adapter_policy"],
        content_resolver=context["content_resolver"],
        schema_validator=context["schema_validator"],
        decision="disputed",
        reason_codes=["result.mismatch"],
        reviewed_at=reviewed_at,
        now=moment,
    )
    app.state.nth.trade_receipt_review_coordinator.record(
        review,
        receipt=receipt,
        order=order,
        verifier_policy=context["taker_policy"],
        adapter_policy=context["adapter_policy"],
        observed_at_ms=int(moment.timestamp() * 1_000),
    )
    rule_binding = order.to_dict()["rule_bindings"][0]
    statement = create_trade_dispute_statement(
        context["maker"],
        review=review,
        receipt=receipt,
        order=order,
        statement_type="response",
        reason_codes=["executor.contests-review"],
        claim=_dispute_claim(),
        rule_action={
            **rule_binding,
            "hook": "fulfillment.deliver",
            "hook_version": "1",
        },
        package_resolver=context["package_store"],
        created_at=reviewed_at,
        now=moment,
    )
    delivery = create_trade_dispute_statement_delivery(
        context["maker"],
        statement=statement,
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=context["package_store"],
        created_at=reviewed_at,
        not_after=(moment + timedelta(minutes=5)).isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z"),
        now=moment,
    )
    path = (
        f"/api/v2/trade/federation/orders/{trade_order_digest(order)}"
        f"/execution-receipts/{receipt.execution_id}/reviews/"
        f"{review.review_id}/dispute-statements"
    )
    return context, order, receipt, review, delivery, path


def test_public_dispute_statement_replays_context_and_returns_stable_ack(
    tmp_path,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, receipt, _review, delivery, path = _live_dispute_statement_delivery(
        tmp_path, app
    )
    client = TestClient(app)

    first = client.post(
        path,
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )
    replay = client.post(
        path,
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )

    assert first.status_code == 202, first.text
    assert replay.status_code == 202, replay.text
    assert first.json()["status"] == "dispute-statement-retained-verified"
    assert first.json()["statement_store_created"] is True
    assert replay.json()["statement_store_created"] is False
    assert replay.json()["acknowledgement"] == first.json()["acknowledgement"]
    acknowledgement = TradeDisputeStatementAcknowledgement.from_dict(
        first.json()["acknowledgement"]
    )
    assert verify_trade_dispute_statement_acknowledgement(
        acknowledgement,
        delivery=delivery,
        review=_review,
        receipt=receipt,
        order=order,
    ) == (True, "ok")
    assert first.json()["claim_adjudicated_or_proven_true"] is False
    assert app.state.nth.spine.verify_chain() == (True, "ok")


def _live_dispute_statement_fetch(tmp_path, app):
    context, order, receipt, review, delivery, delivery_path = (
        _live_dispute_statement_delivery(tmp_path, app)
    )
    client = TestClient(app)
    retained = client.post(
        delivery_path,
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )
    assert retained.status_code == 202, retained.text
    moment = datetime.now(timezone.utc)
    if moment.microsecond == 0:
        moment = moment.replace(microsecond=1)
    created_at = moment.isoformat(timespec="microseconds").replace(
        "+00:00",
        "Z",
    )
    not_after = (
        (moment + timedelta(minutes=5))
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    statement_digest = delivery.to_dict()["statement_digest"]
    fetch_request = create_trade_dispute_statement_fetch_request(
        context["maker"],
        review=review,
        receipt=receipt,
        order=order,
        statement_digest=statement_digest,
        responder_did=app.state.nth.node_identity.as_did(),
        created_at=created_at,
        not_after=not_after,
        nonce="6a" * 16,
        now=moment,
    )
    return (
        context,
        order,
        receipt,
        review,
        fetch_request,
        delivery_path + "/fetch",
    )


def _resign_fetch_envelope(identity, document):
    rebound = copy.deepcopy(document)
    rebound["requester_did"] = identity.as_did()
    rebound["proof"]["verification_method"] = verification_method_for_did(
        identity.as_did()
    )
    binding = {
        key: copy.deepcopy(value)
        for key, value in rebound.items()
        if key not in {"request_id", "proof"}
    }
    prefix = rebound["request_id"].rsplit(":", 1)[0] + ":"
    rebound["request_id"] = (
        prefix
        + hashlib.sha256(trade_rules_api.trade_canonical_json(binding)).hexdigest()
    )
    rebound["proof"]["proof_value"] = encode_ed25519_signature(
        identity.sign(
            signed_document_input(
                DISPUTE_STATEMENT_FETCH_REQUEST_SIGNING_DOMAIN,
                rebound,
            )
        )
    )
    return rebound


def test_public_dispute_statement_fetch_replays_signed_response(tmp_path):
    app = create_app(tmp_path / "node", require_console_auth=True)
    _context, order, receipt, review, fetch_request, path = (
        _live_dispute_statement_fetch(tmp_path, app)
    )
    client = TestClient(app)

    first = client.post(
        path,
        content=fetch_request.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )
    replay = client.post(
        path,
        content=fetch_request.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )

    assert first.status_code == 200, first.text
    assert replay.status_code == 200, replay.text
    assert first.json()["replayed"] is False
    assert replay.json()["replayed"] is True
    assert replay.json()["response"] == first.json()["response"]
    assert replay.json()["audit_event_id"] == first.json()["audit_event_id"]
    response = TradeDisputeStatementFetchResponse.from_dict(
        first.json()["response"],
        request=fetch_request,
        review=review,
        receipt=receipt,
        order=order,
    )
    assert verify_trade_dispute_statement_fetch_response(
        response,
        request=fetch_request,
        review=review,
        receipt=receipt,
        order=order,
    ) == (True, "ok")
    audit_event = SpineEvent.from_dict(first.json()["audit_event"])
    assert trade_rules_api.verify_trade_dispute_statement_fetch_audit_event(
        audit_event,
        fetch_request,
        response,
        review=review,
        receipt=receipt,
        order=order,
    ) == (True, "ok")
    assert first.json()["imported_by_requester"] is False
    assert first.json()["claim_adjudicated_or_proven_true"] is False
    assert len(app.state.nth.trade_dispute_statement_fetch_coordinators) == 1
    assert app.state.nth.spine.verify_chain() == (True, "ok")


def test_public_dispute_statement_fetch_rejects_tamper_before_lookup(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    _context, _order, _receipt, _review, fetch_request, path = (
        _live_dispute_statement_fetch(tmp_path, app)
    )
    document = fetch_request.to_dict()
    document["proof"]["proof_value"] = "A" * 86
    lookups = 0
    original_get = app.state.nth.trade_dispute_statements.get

    def counted_get(*args, **kwargs):
        nonlocal lookups
        lookups += 1
        return original_get(*args, **kwargs)

    monkeypatch.setattr(app.state.nth.trade_dispute_statements, "get", counted_get)

    def context_must_not_load(*_args, **_kwargs):
        raise AssertionError("invalid signature must fail before context lookup")

    monkeypatch.setattr(
        app.state.nth.trade_order_store,
        "get",
        context_must_not_load,
    )

    response = TestClient(app).post(path, json=document)

    assert response.status_code == 400
    assert lookups == 0


def test_public_fetch_hides_missing_context_from_signed_outsider(tmp_path):
    app = create_app(tmp_path / "node", require_console_auth=True)
    _context, _order, _receipt, _review, fetch_request, path = (
        _live_dispute_statement_fetch(tmp_path, app)
    )
    outsider = AgentIdentity.generate(label="fetch-outsider")
    outsider_request = _resign_fetch_envelope(
        outsider,
        fetch_request.to_dict(),
    )
    client = TestClient(app)

    existing = client.post(path, json=outsider_request)

    missing_document = copy.deepcopy(outsider_request)
    missing_document["order_digest"] = "sha256:" + ("f" * 64)
    missing_document = _resign_fetch_envelope(outsider, missing_document)
    missing_path = path.replace(
        fetch_request.to_dict()["order_digest"],
        missing_document["order_digest"],
    )
    missing = client.post(missing_path, json=missing_document)

    assert existing.status_code == 404
    assert missing.status_code == 404
    assert existing.json() == missing.json()


def test_public_fetch_maps_missing_retry_capacity_and_audit_readback(tmp_path):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, receipt, review, fetch_request, path = (
        _live_dispute_statement_fetch(tmp_path, app)
    )
    moment = datetime.now(timezone.utc)
    if moment.microsecond == 0:
        moment = moment.replace(microsecond=1)
    missing_request = create_trade_dispute_statement_fetch_request(
        context["maker"],
        review=review,
        receipt=receipt,
        order=order,
        statement_digest="sha256:" + ("e" * 64),
        responder_did=app.state.nth.node_identity.as_did(),
        created_at=moment.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        not_after=(moment + timedelta(minutes=5))
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z"),
        nonce="73" * 16,
        now=moment,
    )
    client = TestClient(app)

    json_headers = {"Content-Type": "application/json"}
    missing = client.post(
        path,
        content=missing_request.canonical_bytes,
        headers=json_headers,
    )
    retry = client.post(
        path,
        content=missing_request.canonical_bytes,
        headers=json_headers,
    )

    assert missing.status_code == 404
    assert retry.status_code == 429
    assert retry.headers["retry-after"] == "1"

    capacity_app = create_app(tmp_path / "capacity", require_console_auth=True)
    _context, _order, _receipt, _review, capacity_request, capacity_path = (
        _live_dispute_statement_fetch(tmp_path / "capacity-fixture", capacity_app)
    )
    capacity_app.state.nth.trade_dispute_statement_fetch_journal = (
        TradeDisputeStatementFetchJournal(
            capacity_app.state.nth.workspace,
            max_bytes=1,
        )
    )
    capacity = TestClient(capacity_app).post(
        capacity_path,
        content=capacity_request.canonical_bytes,
        headers=json_headers,
    )
    assert capacity.status_code == 507

    successful = client.post(
        path,
        content=fetch_request.canonical_bytes,
        headers=json_headers,
    )
    assert successful.status_code == 200, successful.text

    def fail_readback(_event_id):
        raise OSError("simulated Spine readback failure")

    app.state.nth.spine.reconcile_append = fail_readback
    audit_unavailable = client.post(
        path,
        content=fetch_request.canonical_bytes,
        headers=json_headers,
    )
    assert audit_unavailable.status_code == 503
    assert audit_unavailable.json()["detail"]["safe_to_retry"] is True


def test_public_dispute_statement_fetch_budget_precedes_context_disclosure(
    tmp_path,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    per_client = RateLimiter(max_per_window=1, window_seconds=60)
    global_limiter = RateLimiter(max_per_window=1, window_seconds=60)
    per_client.check("testclient")
    global_limiter.check("global")
    app.state.nth.trade_dispute_statement_fetch_limiter = per_client
    app.state.nth.trade_dispute_statement_fetch_global_limiter = global_limiter
    path = (
        f"/api/v2/trade/federation/orders/sha256:{'1' * 64}"
        f"/execution-receipts/nth-trade-execution-sha256:{'2' * 64}"
        f"/reviews/nth-trade-review-sha256:{'3' * 64}"
        "/dispute-statements/fetch"
    )

    response = TestClient(app).post(path, json={})

    assert response.status_code == 429


def test_operator_dispute_statement_fetch_verifies_without_importing(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, receipt, review, delivery, federation_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )
    statement = delivery.statement.to_dict()
    statement_digest = delivery.to_dict()["statement_digest"]
    observed_requests = []

    def fetch_from_peer(
        _target_url,
        _order_digest,
        _execution_id,
        _review_id,
        document,
    ):
        fetch_request = TradeDisputeStatementFetchRequest.from_dict(
            document,
            review=review,
            receipt=receipt,
            order=order,
        )
        observed_requests.append(fetch_request)
        response = create_trade_dispute_statement_fetch_response(
            context["taker"],
            request=fetch_request,
            statement=statement,
            review=review,
            receipt=receipt,
            order=order,
            served_at=datetime.now(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
            now=datetime.now(timezone.utc),
        )
        audit_payload = trade_rules_api.trade_dispute_statement_fetch_audit_payload(
            fetch_request,
            response,
            review=review,
            receipt=receipt,
            order=order,
        )
        served_at = datetime.fromisoformat(
            response.to_dict()["served_at"].replace("Z", "+00:00")
        )
        audit_event, _created = SignedEventLog(
            tmp_path / "remote-spine" / "events.jsonl",
            context["taker"],
        ).append_unique(
            trade_rules_api.EVENT_TRADE_DISPUTE_STATEMENT_FETCH_SERVED,
            audit_payload,
            unique_payload_fields=("request_id",),
            ts_ms=int(served_at.timestamp() * 1_000),
        )
        return 200, {
            "request_digest": trade_dispute_statement_fetch_request_digest(
                fetch_request,
                review=review,
                receipt=receipt,
                order=order,
            ),
            "response_digest": trade_dispute_statement_fetch_response_digest(
                response,
                request=fetch_request,
                review=review,
                receipt=receipt,
                order=order,
            ),
            "audit_event_id": audit_event.event_id,
            "audit_event": audit_event.to_dict(),
            "response": response.to_dict(),
        }

    monkeypatch.setattr(
        web_v2_api,
        "_post_trade_dispute_statement_fetch_to_peer",
        fetch_from_peer,
    )
    local_path = (
        federation_path.replace(
            "/api/v2/trade/federation/",
            "/api/v2/trade/",
        )
        + "/fetch"
    )
    response = TestClient(app).post(
        local_path,
        json={
            "target_url": "http://127.0.0.1:18083",
            "statement_digest": statement_digest,
        },
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "dispute-statement-fetched-verified"
    assert response.json()["imported"] is False
    assert response.json()["claim_adjudicated_or_proven_true"] is False
    assert response.json()["remote_audit_event_verified"] is True
    assert response.json()["remote_audit_chain_verified"] is False
    assert len(observed_requests) == 1
    assert observed_requests[0].to_dict()["requester_did"] == (
        context["maker"].as_did()
    )
    assert observed_requests[0].to_dict()["responder_did"] == (
        context["taker"].as_did()
    )

    def network_must_not_run(*_args, **_kwargs):
        raise AssertionError("completed requester outbox must replay offline")

    monkeypatch.setattr(
        web_v2_api,
        "_post_trade_dispute_statement_fetch_to_peer",
        network_must_not_run,
    )
    replay = TestClient(app).post(
        local_path,
        json={
            "target_url": "http://127.0.0.1:18083",
            "statement_digest": statement_digest,
        },
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )
    assert replay.status_code == 200, replay.text
    assert replay.json()["replayed_from_outbox"] is True
    assert replay.json()["request"] == response.json()["request"]

    restarted_app = create_app(tmp_path / "node", require_console_auth=True)
    restarted = TestClient(restarted_app).post(
        local_path,
        json={
            "target_url": "http://127.0.0.1:18083",
            "statement_digest": statement_digest,
        },
        headers={"Authorization": f"Bearer {restarted_app.state.nth_console_token}"},
    )
    assert restarted.status_code == 200, restarted.text
    assert restarted.json()["replayed_from_outbox"] is True
    assert restarted.json()["request"] == response.json()["request"]

    def fetch_with_forged_audit(*args, **kwargs):
        status, peer_body = fetch_from_peer(*args, **kwargs)
        forged = copy.deepcopy(peer_body)
        forged["audit_event"]["payload"]["statement_digest"] = "sha256:" + ("f" * 64)
        return status, forged

    monkeypatch.setattr(
        web_v2_api,
        "_post_trade_dispute_statement_fetch_to_peer",
        fetch_with_forged_audit,
    )
    tampered = TestClient(app).post(
        local_path,
        json={
            "target_url": "http://127.0.0.1:18084",
            "statement_digest": statement_digest,
        },
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )
    assert tampered.status_code == 502
    assert "invalid signed fetch binding" in tampered.json()["detail"]


def test_operator_dispute_statement_fetch_reuses_request_after_timeout(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    _context, _order, _receipt, _review, delivery, federation_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )
    local_path = (
        federation_path.replace(
            "/api/v2/trade/federation/",
            "/api/v2/trade/",
        )
        + "/fetch"
    )
    observed = []

    def timeout_peer(_url, _order, _execution, _review, document):
        observed.append(copy.deepcopy(document))
        raise TimeoutError("simulated lost response")

    monkeypatch.setattr(
        web_v2_api,
        "_post_trade_dispute_statement_fetch_to_peer",
        timeout_peer,
    )
    payload = {
        "target_url": "http://127.0.0.1:18083",
        "statement_digest": delivery.to_dict()["statement_digest"],
    }
    headers = {"Authorization": f"Bearer {app.state.nth_console_token}"}

    first = TestClient(app).post(local_path, json=payload, headers=headers)
    second = TestClient(app).post(local_path, json=payload, headers=headers)

    assert first.status_code == 502
    assert second.status_code == 502
    assert len(observed) == 2
    assert observed[0] == observed[1]


def test_dispute_statement_fetch_real_two_node_wire_and_responder_restart(
    tmp_path,
):
    requester_root = tmp_path / "requester"
    responder_root = tmp_path / "responder"
    requester_app = create_app(requester_root, require_console_auth=True)
    responder_app = create_app(responder_root, require_console_auth=True)
    context = _setup(
        tmp_path / "fixtures",
        maker=requester_app.state.nth.node_identity,
        taker=responder_app.state.nth.node_identity,
    )
    order = _order(context)
    receipt = _current_execution_receipt(context, order)
    for app in (requester_app, responder_app):
        _configure_live_execution_receiver(app, context)
        _retain_order_and_receipt(app, context, order, receipt)

    moment = datetime.now(timezone.utc)
    if moment.microsecond == 0:
        moment = moment.replace(microsecond=1)
    timestamp = moment.isoformat(timespec="microseconds").replace("+00:00", "Z")
    review = create_trade_receipt_review(
        context["taker"],
        receipt=receipt,
        order=order,
        package_resolver=context["package_store"],
        verifier_policy=context["taker_policy"],
        adapter_resolver=context["adapter_resolver"],
        adapter_policy=context["adapter_policy"],
        content_resolver=context["content_resolver"],
        schema_validator=context["schema_validator"],
        decision="disputed",
        reason_codes=["result.mismatch"],
        reviewed_at=timestamp,
        now=moment,
    )
    for app in (requester_app, responder_app):
        app.state.nth.trade_receipt_review_coordinator.record(
            review,
            receipt=receipt,
            order=order,
            verifier_policy=context["taker_policy"],
            adapter_policy=context["adapter_policy"],
            observed_at_ms=int(moment.timestamp() * 1_000),
        )
    rule_binding = order.to_dict()["rule_bindings"][0]
    statement = create_trade_dispute_statement(
        context["maker"],
        review=review,
        receipt=receipt,
        order=order,
        statement_type="response",
        reason_codes=["executor.contests-review"],
        claim=_dispute_claim(),
        rule_action={
            **rule_binding,
            "hook": "fulfillment.deliver",
            "hook_version": "1",
        },
        package_resolver=context["package_store"],
        created_at=timestamp,
        now=moment,
    )
    delivery = create_trade_dispute_statement_delivery(
        context["maker"],
        statement=statement,
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=context["package_store"],
        created_at=timestamp,
        not_after=(moment + timedelta(minutes=5))
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z"),
        now=moment,
    )
    federation_base = (
        f"/api/v2/trade/federation/orders/{trade_order_digest(order)}"
        f"/execution-receipts/{receipt.execution_id}/reviews/{review.review_id}"
    )
    retained = TestClient(responder_app).post(
        federation_base + "/dispute-statements",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )
    assert retained.status_code == 202, retained.text

    port = _free_tcp_port()
    target_url = f"http://127.0.0.1:{port}"
    local_path = (
        federation_base.replace(
            "/api/v2/trade/federation/",
            "/api/v2/trade/",
        )
        + "/dispute-statements/fetch"
    )
    with _UvicornThreadServer(responder_app, port):
        fetched = TestClient(requester_app).post(
            local_path,
            json={
                "target_url": target_url,
                "statement_digest": delivery.to_dict()["statement_digest"],
            },
            headers={
                "Authorization": (f"Bearer {requester_app.state.nth_console_token}")
            },
        )
    assert fetched.status_code == 200, fetched.text
    assert fetched.json()["replayed_from_outbox"] is False
    fetch_request_document = fetched.json()["request"]

    restarted_responder = create_app(responder_root, require_console_auth=True)
    _configure_live_execution_receiver(restarted_responder, context)
    with _UvicornThreadServer(restarted_responder, port):
        status, replay = web_v2_api._post_trade_dispute_statement_fetch_to_peer(
            target_url,
            trade_order_digest(order),
            receipt.execution_id,
            review.review_id,
            fetch_request_document,
        )

    assert status == 200
    assert replay["replayed"] is True
    assert replay["response"] == fetched.json()["response"]
    assert replay["audit_event_id"] == fetched.json()["remote_audit_event_id"]


def test_operator_dispute_statement_fetch_rejects_peer_binding_tamper(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    _context, _order, _receipt, _review, delivery, federation_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )

    def forged_peer(*_args, **_kwargs):
        return 200, {
            "request_digest": "sha256:" + ("0" * 64),
            "response_digest": "sha256:" + ("0" * 64),
            "audit_event_id": "0" * 64,
            "response": {},
        }

    monkeypatch.setattr(
        web_v2_api,
        "_post_trade_dispute_statement_fetch_to_peer",
        forged_peer,
    )
    local_path = (
        federation_path.replace(
            "/api/v2/trade/federation/",
            "/api/v2/trade/",
        )
        + "/fetch"
    )

    response = TestClient(app).post(
        local_path,
        json={
            "target_url": "http://127.0.0.1:18083",
            "statement_digest": delivery.to_dict()["statement_digest"],
        },
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )

    assert response.status_code == 502
    assert "invalid signed fetch response" in response.json()["detail"]


def test_fetch_transport_pins_responder_before_bounded_post(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "node")
    context, order, receipt, review, delivery, _path = _live_dispute_statement_delivery(
        tmp_path,
        app,
        receiver_role="maker",
    )
    moment = datetime.now(timezone.utc)
    if moment.microsecond == 0:
        moment = moment.replace(microsecond=1)
    fetch_request = create_trade_dispute_statement_fetch_request(
        context["maker"],
        review=review,
        receipt=receipt,
        order=order,
        statement_digest=delivery.to_dict()["statement_digest"],
        responder_did=context["taker"].as_did(),
        created_at=moment.isoformat(timespec="microseconds").replace(
            "+00:00",
            "Z",
        ),
        not_after=(moment + timedelta(minutes=5))
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z"),
        now=moment,
    )
    post_calls = 0

    monkeypatch.setattr(
        web_v2_api,
        "_resolve_operator_trade_peer_ips",
        lambda _url: ("203.0.113.20",),
    )
    monkeypatch.setattr(
        web_v2_api,
        "_open_federation_identity_card",
        lambda *_args, **_kwargs: b"{}",
    )
    monkeypatch.setattr(
        web_v2_api,
        "_verify_federation_identity_card",
        lambda *_args, **_kwargs: ({"did": context["maker"].as_did()}, None),
    )

    def post(*_args, **_kwargs):
        nonlocal post_calls
        post_calls += 1
        raise AssertionError("request must not be posted to the wrong DID")

    monkeypatch.setattr(
        "nth_dao.web.market_federation_poll._urllib_post_json_pinned_raw",
        post,
    )

    with pytest.raises(ValueError, match="does not match fetch responder_did"):
        web_v2_api._post_trade_dispute_statement_fetch_to_peer(
            "https://peer.example",
            trade_order_digest(order),
            receipt.execution_id,
            review.review_id,
            fetch_request.to_dict(),
        )
    assert post_calls == 0

    posted = []
    monkeypatch.setattr(
        web_v2_api,
        "_verify_federation_identity_card",
        lambda *_args, **_kwargs: ({"did": context["taker"].as_did()}, None),
    )

    def accept_post(url, resolved_ip, document, **kwargs):
        posted.append((url, resolved_ip, document, kwargs))
        return 200, b'{"status":"ok"}'

    monkeypatch.setattr(
        "nth_dao.web.market_federation_poll._urllib_post_json_pinned_raw",
        accept_post,
    )
    status, body = web_v2_api._post_trade_dispute_statement_fetch_to_peer(
        "https://peer.example",
        trade_order_digest(order),
        receipt.execution_id,
        review.review_id,
        fetch_request.to_dict(),
    )

    assert status == 200
    assert body == {"status": "ok"}
    assert len(posted) == 1
    assert posted[0][1] == "203.0.113.20"
    assert posted[0][2] == fetch_request.to_dict()
    assert posted[0][3]["max_bytes"] == 512 * 1024
    assert posted[0][0].endswith(
        f"/orders/{trade_order_digest(order)}"
        f"/execution-receipts/{receipt.execution_id}"
        f"/reviews/{review.review_id}/dispute-statements/fetch"
    )


def test_public_dispute_statement_maps_resolver_failure_to_503(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    _context, _order, _receipt, _review, delivery, path = (
        _live_dispute_statement_delivery(tmp_path, app)
    )
    monkeypatch.setattr(
        web_v2_api,
        "_trade_order_rule_package_resolver",
        lambda *_args, **_kwargs: _UnavailableDisputePackageResolver(),
    )

    response = TestClient(app).post(
        path,
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 503, response.text
    assert response.headers["retry-after"] == "1"
    assert "dependency is unavailable" in response.json()["detail"]


def test_public_dispute_statement_rejects_path_mismatch_and_wrong_node(tmp_path):
    app = create_app(tmp_path / "target", require_console_auth=True)
    _context, _order_value, _receipt, _review, delivery, path = (
        _live_dispute_statement_delivery(tmp_path / "target-fixture", app)
    )
    client = TestClient(app)
    wrong_review_path = path.replace(
        delivery.statement.to_dict()["review_id"],
        "nth-trade-review-sha256:" + ("f" * 64),
    )

    missing_bound_review = client.post(
        wrong_review_path,
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )

    assert missing_bound_review.status_code == 404

    wrong_app = create_app(tmp_path / "wrong-node", require_console_auth=True)
    (
        _wrong_context,
        _wrong_order,
        _wrong_receipt,
        _wrong_review,
        wrong_delivery,
        wrong_path,
    ) = _live_dispute_statement_delivery(
        tmp_path / "wrong-fixture",
        wrong_app,
        receiver_role="maker",
    )
    wrong_target = TestClient(wrong_app).post(
        wrong_path,
        content=wrong_delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )

    assert wrong_target.status_code == 400
    assert "recipient" in wrong_target.json()["detail"]


def test_public_dispute_statement_enforces_capacity_and_preparse_limit(tmp_path):
    app = create_app(tmp_path / "node", require_console_auth=True)
    _context, _order, _receipt, _review, delivery, path = (
        _live_dispute_statement_delivery(tmp_path, app)
    )
    app.state.nth.trade_dispute_statement_intake_journal = (
        TradeDisputeStatementIntakeJournal(
            app.state.nth.workspace,
            max_bytes=1,
        )
    )
    client = TestClient(app)

    capacity = client.post(
        path,
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )
    oversized = client.post(
        path,
        content=b"{" + (b"x" * (512 * 1024)) + b"}",
        headers={"Content-Type": "application/json"},
    )
    malformed = client.post(
        path,
        content=b"{",
        headers={"Content-Type": "application/json"},
    )

    assert capacity.status_code == 507, capacity.text
    assert oversized.status_code == 413, oversized.text
    assert "512 KiB" in oversized.json()["detail"]
    assert malformed.status_code == 400, malformed.text


def test_corrupt_dispute_statement_journal_disables_only_federated_intake(
    tmp_path,
):
    workspace = tmp_path / "node"
    journal_path = workspace / "trade" / "dispute_statement_intake_v1.sqlite3"
    journal_path.parent.mkdir(parents=True)
    journal_path.write_bytes(b"not-a-sqlite-database")

    app = create_app(workspace, require_console_auth=True)

    assert app.state.nth.trade_dispute_statement_intake_journal is None
    assert app.state.nth.trade_dispute_statement_audit is not None
    assert app.state.nth.spine.verify_chain() == (True, "ok")
    response = TestClient(app).post(
        "/api/v2/trade/federation/orders/sha256:"
        + ("1" * 64)
        + "/execution-receipts/nth-trade-execution-sha256:"
        + ("2" * 64)
        + "/reviews/nth-trade-review-sha256:"
        + ("3" * 64)
        + "/dispute-statements",
        json={},
    )
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == (
        "dispute-statement-intake-not-configured"
    )


def test_unsupported_dispute_dispatch_schema_disables_only_outbound_delivery(
    tmp_path,
):
    workspace = tmp_path / "node"
    dispatch_path = (
        workspace
        / "trade"
        / "dispute_dispatch_v1"
        / "dispatch.sqlite3"
    )
    dispatch_path.parent.mkdir(parents=True)
    with sqlite3.connect(dispatch_path) as connection:
        connection.execute("PRAGMA user_version = 999")

    app = create_app(workspace, require_console_auth=True)

    assert app.state.nth.trade_dispute_statement_dispatch_store is None
    assert app.state.nth.trade_dispute_statement_dispatch is None
    assert app.state.nth.trade_dispute_statement_audit is not None
    assert app.state.nth.spine.verify_chain() == (True, "ok")
    response = TestClient(app).get(
        "/api/state",
        params={"agent_id": "admin"},
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )
    assert response.status_code == 200, response.text


def test_public_dispute_statement_budget_precedes_context_disclosure(tmp_path):
    app = create_app(tmp_path / "node", require_console_auth=True)
    per_client = RateLimiter(max_per_window=1, window_seconds=60)
    global_limiter = RateLimiter(max_per_window=1, window_seconds=60)
    per_client.check("testclient")
    global_limiter.check("global")
    app.state.nth.trade_dispute_statement_delivery_limiter = per_client
    app.state.nth.trade_dispute_statement_delivery_global_limiter = global_limiter

    response = TestClient(app).post(
        "/api/v2/trade/federation/orders/sha256:"
        + ("1" * 64)
        + "/execution-receipts/nth-trade-execution-sha256:"
        + ("2" * 64)
        + "/reviews/nth-trade-review-sha256:"
        + ("3" * 64)
        + "/dispute-statements",
        json={},
    )

    assert response.status_code == 429


def test_operator_creates_and_lists_signed_dispute_statement(tmp_path):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, receipt, review, delivery, _public_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )
    source = delivery.statement.to_dict()
    body = {
        field: source[field]
        for field in (
            "statement_type",
            "parent_statement_digests",
            "reason_codes",
            "claim",
            "evidence",
            "rule_action",
        )
    }
    path = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}"
        f"/execution-receipts/{receipt.execution_id}/reviews/"
        f"{review.review_id}/dispute-statements"
    )
    auth = {
        "Authorization": f"Bearer {app.state.nth_console_token}",
        "Idempotency-Key": "dispute-create-test-0001",
    }
    client = TestClient(app)

    created = client.post(path, json=body, headers=auth)
    listed = client.get(path, headers=auth)
    projected = client.get(path + "?limit=500&include_graph=true", headers=auth)
    graphed = client.get(path + "/graph", headers=auth)
    unauthenticated_graph = client.get(path + "/graph")

    assert created.status_code == 201, created.text
    assert created.json()["status"] == "dispute-statement-signed"
    assert created.json()["statement"]["author_did"] == (
        app.state.nth.node_identity.as_did()
    )
    assert created.json()["statement_store_created"] is True
    assert created.json()["audit_anchor_created"] is True
    assert created.json()["claim_adjudicated_or_proven_true"] is False
    assert listed.status_code == 200, listed.text
    assert listed.json()["status"] == "dispute-statements-listed"
    assert listed.json()["claims_adjudicated_or_proven_true"] is False
    assert listed.json()["graph_endpoint"] == path + "/graph"
    assert projected.status_code == 200, projected.text
    assert projected.json()["snapshot_token"] == (
        projected.json()["graph"]["snapshot_token"]
    )
    assert projected.json()["graph"]["statement_count"] == 1
    assert graphed.status_code == 200, graphed.text
    assert graphed.json()["graph"]["graph_status"] == "complete"
    assert graphed.json()["graph"]["statement_count"] == 1
    assert graphed.json()["graph"]["node_count"] == 1
    assert graphed.json()["graph"]["items_truncated"] is False
    assert listed.json()["snapshot_token"] == graphed.json()["graph"]["snapshot_token"]
    assert graphed.json()["graph"]["adjudicated_or_proven_true"] is False
    assert unauthenticated_graph.status_code == 401
    assert len(listed.json()["items"]) == 1
    assert (
        listed.json()["items"][0]["statement_digest"]
        == (created.json()["statement_digest"])
    )
    assert listed.json()["items"][0]["claim_status"] == ("signed-unadjudicated-claim")
    assert listed.json()["items"][0]["audit_status"] == "anchored"
    assert listed.json()["items"][0]["audit_event_id"] == (
        created.json()["audit_event_id"]
    )
    assert app.state.nth.spine.verify_chain() == (True, "ok")


def test_operator_dispute_statement_rejects_missing_parent_before_retention(
    tmp_path,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, receipt, review, delivery, _public_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )
    path, body, headers = _operator_dispute_statement_request(
        app,
        order,
        receipt,
        review,
        delivery,
        idempotency_key="dispute-create-missing-parent-0001",
    )
    missing = "sha256:" + ("f" * 64)
    body["parent_statement_digests"] = [missing]

    response = TestClient(app).post(path, json=body, headers=headers)
    graph_response = TestClient(app).get(path + "/graph", headers=headers)
    page = app.state.nth.trade_dispute_statements.list_for_review(
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=context["package_store"],
    )

    assert response.status_code == 409, response.text
    assert "parent chain is incomplete" in response.json()["detail"]
    assert graph_response.status_code == 200, graph_response.text
    assert graph_response.json()["graph"]["statement_count"] == 0
    assert graph_response.json()["graph"]["review_digest"] == (
        receipt_review_digest(review, receipt=receipt, order=order)
    )
    assert graph_response.json()["graph"]["dispute_id"] == trade_dispute_id(
        review.review_id
    )
    assert page.statements == ()
    events = app.state.nth.spine.verified_snapshot()
    assert not any(
        event.type == trade_rules_api.EVENT_TRADE_DISPUTE_STATEMENT_RETAINED
        for event in events
    )
    assert not any(
        event.type
        == trade_rules_api.EVENT_TRADE_DISPUTE_STATEMENT_CREATE_RESERVED
        for event in events
    )


def _operator_dispute_statement_request(
    app,
    order,
    receipt,
    review,
    delivery,
    *,
    idempotency_key,
):
    source = delivery.statement.to_dict()
    body = {
        field: source[field]
        for field in (
            "statement_type",
            "parent_statement_digests",
            "reason_codes",
            "claim",
            "evidence",
            "rule_action",
        )
    }
    path = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}"
        f"/execution-receipts/{receipt.execution_id}/reviews/"
        f"{review.review_id}/dispute-statements"
    )
    headers = {
        "Authorization": f"Bearer {app.state.nth_console_token}",
        "Idempotency-Key": idempotency_key,
    }
    return path, body, headers


class _UnavailableDisputePackageResolver:
    def load(self, _digest):
        raise _SyntheticResolverUnavailable("resolver intentionally unavailable")


class _FailSecondDisputePackageLoad:
    def __init__(self, delegate):
        self.delegate = delegate
        self.loads = 0

    def load(self, digest):
        self.loads += 1
        if self.loads == 2:
            raise _SyntheticResolverUnavailable(
                "resolver failed after successful preflight"
            )
        return self.delegate.load(digest)


def test_operator_dispute_statement_preflight_maps_resolver_failure_to_503(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    _context, order, receipt, review, delivery, _public_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )
    path, body, headers = _operator_dispute_statement_request(
        app,
        order,
        receipt,
        review,
        delivery,
        idempotency_key="dispute-create-dependency-0001",
    )
    monkeypatch.setattr(
        web_v2_api,
        "_trade_order_rule_package_resolver",
        lambda *_args, **_kwargs: _UnavailableDisputePackageResolver(),
    )

    response = TestClient(app).post(path, json=body, headers=headers)

    assert response.status_code == 503, response.text
    assert response.headers["retry-after"] == "1"
    assert "dependency is unavailable" in response.json()["detail"]
    assert not any(
        event.type
        == trade_rules_api.EVENT_TRADE_DISPUTE_STATEMENT_CREATE_RESERVED
        for event in app.state.nth.spine.verified_snapshot()
    )


def test_operator_dispute_statement_audits_post_reservation_failure_and_recovers(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, receipt, review, delivery, _public_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )
    path, body, headers = _operator_dispute_statement_request(
        app,
        order,
        receipt,
        review,
        delivery,
        idempotency_key="dispute-create-post-reservation-failure-0001",
    )
    fail_second = _FailSecondDisputePackageLoad(context["package_store"])
    monkeypatch.setattr(
        web_v2_api,
        "_trade_order_rule_package_resolver",
        lambda *_args, **_kwargs: fail_second,
    )
    client = TestClient(app)

    failed = client.post(path, json=body, headers=headers)
    events_after_failure = app.state.nth.spine.verified_snapshot()
    reservations = [
        event
        for event in events_after_failure
        if event.type
        == trade_rules_api.EVENT_TRADE_DISPUTE_STATEMENT_CREATE_RESERVED
    ]
    failures = [
        event
        for event in events_after_failure
        if event.type
        == trade_rules_api.EVENT_TRADE_DISPUTE_STATEMENT_CREATE_ATTEMPT_FAILED
    ]

    assert failed.status_code == 503, failed.text
    assert failed.headers["retry-after"] == "1"
    assert len(reservations) == 1
    assert len(failures) == 1
    failure_payload = (
        trade_rules_api.validate_trade_dispute_statement_create_failure_payload(
            failures[0].payload
        )
    )
    assert failure_payload["operation_id"] == reservations[0].payload["operation_id"]
    assert failure_payload["request_digest"] == reservations[0].payload[
        "request_digest"
    ]
    assert failure_payload["reason_code"] == "dependency-unavailable"
    assert failure_payload["retryable"] is True
    inconsistent_failure = dict(failure_payload)
    inconsistent_failure["retryable"] = False
    with pytest.raises(
        trade_rules_api.TradeDisputeStatementAuditError,
        match="retryability is invalid",
    ):
        trade_rules_api.validate_trade_dispute_statement_create_failure_payload(
            inconsistent_failure
        )
    assert not any(
        event.type == trade_rules_api.EVENT_TRADE_DISPUTE_STATEMENT_RETAINED
        for event in events_after_failure
    )

    monkeypatch.setattr(
        web_v2_api,
        "_trade_order_rule_package_resolver",
        lambda *_args, **_kwargs: context["package_store"],
    )
    recovered = client.post(path, json=body, headers=headers)

    assert recovered.status_code == 201, recovered.text
    assert recovered.json()["reservation_created"] is False
    assert recovered.json()["operation_id"] == failure_payload["operation_id"]
    assert len(
        [
            event
            for event in app.state.nth.spine.verified_snapshot()
            if event.type
            == trade_rules_api.EVENT_TRADE_DISPUTE_STATEMENT_CREATE_ATTEMPT_FAILED
        ]
    ) == 1
    assert app.state.nth.spine.verify_chain() == (True, "ok")


def test_operator_dispute_graph_maps_resolver_failure_to_503(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    _context, order, receipt, review, delivery, _public_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )
    path, body, headers = _operator_dispute_statement_request(
        app,
        order,
        receipt,
        review,
        delivery,
        idempotency_key="dispute-create-dependency-0002",
    )
    client = TestClient(app)
    created = client.post(path, json=body, headers=headers)
    assert created.status_code == 201, created.text
    monkeypatch.setattr(
        web_v2_api,
        "_trade_order_rule_package_resolver",
        lambda *_args, **_kwargs: _UnavailableDisputePackageResolver(),
    )

    response = client.get(path + "/graph", headers=headers)

    assert response.status_code == 503, response.text
    assert response.headers["retry-after"] == "1"
    assert "dependency is unavailable" in response.json()["detail"]


def test_operator_dispute_graph_maps_capacity_to_507(tmp_path, monkeypatch):
    app = create_app(tmp_path / "node", require_console_auth=True)
    _context, order, receipt, review, delivery, _public_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )
    path, _body, headers = _operator_dispute_statement_request(
        app,
        order,
        receipt,
        review,
        delivery,
        idempotency_key="dispute-graph-capacity-0001",
    )

    def capacity_exceeded(**_kwargs):
        raise trade_rules_api.TradeDisputeStatementStoreCapacity(
            "dispute statement graph exceeds max_edges"
        )

    monkeypatch.setattr(
        app.state.nth.trade_dispute_statements,
        "graph_for_review",
        capacity_exceeded,
    )
    response = TestClient(app).get(path + "/graph", headers=headers)

    assert response.status_code == 507, response.text
    assert response.json()["detail"] == (
        "trade Dispute Statement graph capacity exceeded"
    )


def test_operator_dispute_statement_retry_is_content_idempotent(tmp_path):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, receipt, review, delivery, _public_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )
    path, body, headers = _operator_dispute_statement_request(
        app,
        order,
        receipt,
        review,
        delivery,
        idempotency_key="dispute-create-retry-0001",
    )
    client = TestClient(app)

    first = client.post(path, json=body, headers=headers)
    retry = client.post(path, json=body, headers=headers)
    page = app.state.nth.trade_dispute_statements.list_for_review(
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=context["package_store"],
        limit=100,
    )

    assert first.status_code == 201, first.text
    assert retry.status_code == 200, retry.text
    assert first.json()["statement_id"] == retry.json()["statement_id"]
    assert first.json()["statement_digest"] == retry.json()["statement_digest"]
    assert first.json()["operation_id"] == retry.json()["operation_id"]
    assert first.json()["reservation_created"] is True
    assert retry.json()["reservation_created"] is False
    assert retry.json()["statement_store_created"] is False
    assert len(page.statements) == 1


def test_operator_dispute_statement_requires_idempotency_key_without_writes(
    tmp_path,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, receipt, review, delivery, _public_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )
    path, body, headers = _operator_dispute_statement_request(
        app,
        order,
        receipt,
        review,
        delivery,
        idempotency_key="dispute-create-required-0001",
    )
    headers.pop("Idempotency-Key")
    before = tuple(app.state.nth.spine.verified_snapshot())

    response = TestClient(app).post(path, json=body, headers=headers)
    page = app.state.nth.trade_dispute_statements.list_for_review(
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=context["package_store"],
        limit=100,
    )

    assert response.status_code == 400, response.text
    assert "Idempotency-Key" in response.json()["detail"]
    assert tuple(app.state.nth.spine.verified_snapshot()) == before
    assert page.statements == ()


def test_operator_dispute_statement_retry_survives_app_restart(tmp_path):
    workspace = tmp_path / "node"
    app = create_app(workspace, require_console_auth=True)
    persistent_package_store = app.state.nth.trade_rule_packages
    _context, order, receipt, review, delivery, _public_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )
    package = _context["package_store"].load(_context["package_digest"])
    assert package is not None
    persistent_package_store.install(
        package.manifest,
        package.resources,
        source="local",
    )
    app.state.nth.trade_rule_packages = persistent_package_store
    path, body, headers = _operator_dispute_statement_request(
        app,
        order,
        receipt,
        review,
        delivery,
        idempotency_key="dispute-create-restart-0001",
    )
    first = TestClient(app).post(path, json=body, headers=headers)
    assert first.status_code == 201, first.text

    restarted = create_app(workspace, require_console_auth=True)
    restarted_headers = {
        "Authorization": f"Bearer {restarted.state.nth_console_token}",
        "Idempotency-Key": "dispute-create-restart-0001",
    }
    retry = TestClient(restarted).post(
        path,
        json=body,
        headers=restarted_headers,
    )

    assert retry.status_code == 200, retry.text
    assert retry.json()["statement_id"] == first.json()["statement_id"]
    assert retry.json()["statement_digest"] == first.json()["statement_digest"]
    assert retry.json()["operation_id"] == first.json()["operation_id"]
    assert retry.json()["reservation_created"] is False
    assert retry.json()["statement_store_created"] is False
    assert restarted.state.nth.spine.verify_chain() == (True, "ok")


def test_operator_dispute_statement_retry_recovers_store_then_spine_failure(
    tmp_path,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, receipt, review, delivery, _public_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )
    path, body, headers = _operator_dispute_statement_request(
        app,
        order,
        receipt,
        review,
        delivery,
        idempotency_key="dispute-create-recover-0001",
    )
    coordinator = app.state.nth.trade_dispute_statement_audit
    real_anchor = coordinator._anchor
    failed_once = False

    def fail_once(*args, **kwargs):
        nonlocal failed_once
        if not failed_once:
            failed_once = True
            raise RuntimeError("injected Spine failure after Store commit")
        return real_anchor(*args, **kwargs)

    coordinator._anchor = fail_once
    client = TestClient(app)

    failed = client.post(path, json=body, headers=headers)
    recovered = client.post(path, json=body, headers=headers)
    page = app.state.nth.trade_dispute_statements.list_for_review(
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=context["package_store"],
        limit=100,
    )

    assert failed.status_code == 503, failed.text
    assert recovered.status_code == 200, recovered.text
    assert recovered.json()["statement_store_created"] is False
    assert recovered.json()["audit_anchor_created"] is True
    assert len(page.statements) == 1
    assert app.state.nth.spine.verify_chain() == (True, "ok")


def test_dispute_statement_startup_recovers_store_then_spine_failure(tmp_path):
    workspace = tmp_path / "node"
    app = create_app(workspace, require_console_auth=True)
    persistent_package_store = app.state.nth.trade_rule_packages
    context, order, receipt, review, delivery, _public_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )
    package = context["package_store"].load(context["package_digest"])
    assert package is not None
    persistent_package_store.install(
        package.manifest,
        package.resources,
        source="local",
    )
    app.state.nth.trade_rule_packages = persistent_package_store
    path, body, headers = _operator_dispute_statement_request(
        app,
        order,
        receipt,
        review,
        delivery,
        idempotency_key="dispute-create-startup-recovery-0001",
    )
    coordinator = app.state.nth.trade_dispute_statement_audit
    real_anchor = coordinator._anchor

    def fail_anchor(*_args, **_kwargs):
        raise RuntimeError("injected crash before retained anchor")

    coordinator._anchor = fail_anchor
    failed = TestClient(app).post(path, json=body, headers=headers)
    coordinator._anchor = real_anchor
    assert failed.status_code == 503, failed.text
    assert not any(
        event.type == trade_rules_api.EVENT_TRADE_DISPUTE_STATEMENT_RETAINED
        for event in app.state.nth.spine.verified_snapshot()
    )

    restarted = create_app(workspace, require_console_auth=True)
    anchors = [
        event
        for event in restarted.state.nth.spine.verified_snapshot()
        if event.type == trade_rules_api.EVENT_TRADE_DISPUTE_STATEMENT_RETAINED
    ]

    assert len(anchors) == 1
    assert restarted.state.nth.spine.verify_chain() == (True, "ok")


def test_dispute_statement_runtime_worker_recovers_partial_write(
    tmp_path,
    monkeypatch,
):
    workspace = tmp_path / "node"
    app = create_app(workspace, require_console_auth=True)
    persistent_package_store = app.state.nth.trade_rule_packages
    context, order, receipt, review, delivery, _public_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )
    package = context["package_store"].load(context["package_digest"])
    assert package is not None
    persistent_package_store.install(
        package.manifest,
        package.resources,
        source="local",
    )
    app.state.nth.trade_rule_packages = persistent_package_store
    path, body, headers = _operator_dispute_statement_request(
        app,
        order,
        receipt,
        review,
        delivery,
        idempotency_key="dispute-create-runtime-recovery-0001",
    )
    coordinator = app.state.nth.trade_dispute_statement_audit
    real_anchor = coordinator._anchor
    coordinator._anchor = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        RuntimeError("injected transient anchor failure")
    )
    monkeypatch.setattr(
        "nth_dao.web._TRADE_DISPUTE_RECOVERY_POLL_SECONDS",
        0.01,
    )

    with TestClient(app) as client:
        failed = client.post(path, json=body, headers=headers)
        assert failed.status_code == 503, failed.text
        coordinator._anchor = real_anchor
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if any(
                event.type
                == trade_rules_api.EVENT_TRADE_DISPUTE_STATEMENT_RETAINED
                for event in app.state.nth.spine.verified_snapshot()
            ):
                break
            time.sleep(0.01)

    anchors = [
        event
        for event in app.state.nth.spine.verified_snapshot()
        if event.type == trade_rules_api.EVENT_TRADE_DISPUTE_STATEMENT_RETAINED
    ]
    assert len(anchors) == 1
    assert app.state.nth.spine.verify_chain() == (True, "ok")


def test_operator_dispute_statement_idempotency_key_reuse_conflicts(tmp_path):
    app = create_app(tmp_path / "node", require_console_auth=True)
    _context, order, receipt, review, delivery, _public_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )
    path, body, headers = _operator_dispute_statement_request(
        app,
        order,
        receipt,
        review,
        delivery,
        idempotency_key="dispute-create-conflict-0001",
    )
    client = TestClient(app)

    first = client.post(path, json=body, headers=headers)
    conflict = client.post(
        path,
        json={**body, "reason_codes": ["different.claim"]},
        headers=headers,
    )

    assert first.status_code == 201, first.text
    assert conflict.status_code == 409, conflict.text
    assert "Idempotency-Key" in conflict.json()["detail"]


def test_operator_dispute_statement_concurrent_retry_creates_once(tmp_path):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, receipt, review, delivery, _public_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )
    path, body, headers = _operator_dispute_statement_request(
        app,
        order,
        receipt,
        review,
        delivery,
        idempotency_key="dispute-create-concurrent-0001",
    )

    def create_once(_index):
        return TestClient(app).post(path, json=body, headers=headers)

    with ThreadPoolExecutor(max_workers=6) as executor:
        responses = list(executor.map(create_once, range(6)))
    page = app.state.nth.trade_dispute_statements.list_for_review(
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=context["package_store"],
        limit=100,
    )

    assert sorted(response.status_code for response in responses) == [
        200,
        200,
        200,
        200,
        200,
        201,
    ]
    assert len({response.json()["statement_id"] for response in responses}) == 1
    assert len(page.statements) == 1


def test_operator_dispute_statement_write_is_bounded_and_console_only(tmp_path):
    app = create_app(tmp_path / "node", require_console_auth=True)
    _context, order, receipt, review, delivery, _public_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )
    source = delivery.statement.to_dict()
    body = {
        field: source[field]
        for field in (
            "statement_type",
            "parent_statement_digests",
            "reason_codes",
            "claim",
            "evidence",
            "rule_action",
        )
    }
    path = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}"
        f"/execution-receipts/{receipt.execution_id}/reviews/"
        f"{review.review_id}/dispute-statements"
    )
    auth = {
        "Authorization": f"Bearer {app.state.nth_console_token}",
        "Idempotency-Key": "dispute-create-test-0002",
    }
    client = TestClient(app)

    anonymous = client.post(path, json=body)
    unknown = client.post(path, json={**body, "execute": True}, headers=auth)
    oversized = client.post(
        path,
        content=b"{" + (b"x" * (256 * 1024)) + b"}",
        headers={**auth, "Content-Type": "application/json"},
    )
    invalid_cursor = client.get(path + "?after=bad", headers=auth)

    assert anonymous.status_code == 401
    assert unknown.status_code == 400
    assert oversized.status_code == 413
    assert "256 KiB" in oversized.json()["detail"]
    assert invalid_cursor.status_code == 400
    assert not app.state.nth.trade_dispute_statements.root.exists()


def test_operator_dispute_statement_requires_local_order_party(tmp_path):
    app = create_app(tmp_path / "node", require_console_auth=True)
    _context, order, receipt, review, delivery, _public_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )
    source = delivery.statement.to_dict()
    body = {
        field: source[field]
        for field in (
            "statement_type",
            "parent_statement_digests",
            "reason_codes",
            "claim",
            "evidence",
            "rule_action",
        )
    }
    path = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}"
        f"/execution-receipts/{receipt.execution_id}/reviews/"
        f"{review.review_id}/dispute-statements"
    )
    app.state.nth.node_identity = AgentIdentity.generate()

    response = TestClient(app).post(
        path,
        json=body,
        headers={
            "Authorization": f"Bearer {app.state.nth_console_token}",
            "Idempotency-Key": "dispute-create-test-0003",
        },
    )

    assert response.status_code == 403
    assert not app.state.nth.trade_dispute_statements.root.exists()


def test_operator_lists_retained_dispute_statement_as_pending_until_anchored(
    tmp_path,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, receipt, review, delivery, _public_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )
    statement = delivery.statement.resolve(
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=context["package_store"],
    )
    app.state.nth.trade_dispute_statements.put(
        statement,
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=context["package_store"],
    )
    path = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}"
        f"/execution-receipts/{receipt.execution_id}/reviews/"
        f"{review.review_id}/dispute-statements"
    )

    client = TestClient(app)
    response = client.get(
        path,
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )

    assert response.status_code == 200, response.text
    assert len(response.json()["items"]) == 1
    assert response.json()["items"][0]["audit_status"] == (
        "retained-pending-audit"
    )
    assert response.json()["items"][0]["audit_event_id"] == ""
    app.state.nth.trade_dispute_statement_audit.record(
        statement,
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=context["package_store"],
        observed_at_ms=int(datetime.now(timezone.utc).timestamp() * 1_000),
    )
    anchored = client.get(
        path,
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )
    assert anchored.status_code == 200, anchored.text
    assert anchored.json()["items"][0]["audit_status"] == "anchored"
    assert anchored.json()["items"][0]["audit_event_id"]


def test_dispute_statement_projection_uses_atomic_verified_snapshot_and_cache(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    _context, order, receipt, review, _delivery, _public_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )
    spine = app.state.nth.spine
    real_snapshot = spine.verified_snapshot_with_token
    calls = 0

    def snapshot_once():
        nonlocal calls
        if any(
            frame.function == "_stable_audit_events"
            for frame in inspect.stack()
        ):
            calls += 1
        return real_snapshot()

    monkeypatch.setattr(spine, "verified_snapshot_with_token", snapshot_once)
    monkeypatch.setattr(
        spine,
        "read_all",
        lambda: (_ for _ in ()).throw(AssertionError("racy read_all used")),
    )
    monkeypatch.setattr(
        spine,
        "verify_chain",
        lambda: (_ for _ in ()).throw(AssertionError("double verify used")),
    )
    path = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}"
        f"/execution-receipts/{receipt.execution_id}/reviews/"
        f"{review.review_id}/dispute-statements"
    )
    headers = {"Authorization": f"Bearer {app.state.nth_console_token}"}
    client = TestClient(app)

    first = client.get(path, headers=headers)
    cached = client.get(path, headers=headers)

    assert first.status_code == 200, first.text
    assert cached.status_code == 200, cached.text
    assert calls == 1


def test_dispute_statement_projection_rejects_corrupt_spine_chain(tmp_path):
    app = create_app(tmp_path / "node", require_console_auth=True)
    _context, order, receipt, review, _delivery, _public_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )
    spine = app.state.nth.spine
    order_view = app.state.nth.trade_order_audit.get_accepted(
        trade_order_digest(order)
    )
    assert order_view is not None
    spine.append("test.dispute.projection", {"value": "original"})
    lines = spine._path.read_bytes().splitlines()
    document = json.loads(lines[-1])
    document["payload"]["value"] = "tampered"
    lines[-1] = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    spine._path.write_bytes(b"\n".join(lines) + b"\n")
    app.state.nth.trade_order_audit.get_accepted = lambda _digest: order_view
    path = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}"
        f"/execution-receipts/{receipt.execution_id}/reviews/"
        f"{review.review_id}/dispute-statements"
    )

    response = TestClient(app).get(
        path,
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == (
        "trade Dispute Statement audit projection is invalid"
    )


def test_dispute_statement_projection_invalidates_cache_after_concurrent_append(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    _context, order, receipt, review, _delivery, _public_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )
    spine = app.state.nth.spine
    real_snapshot = spine.verified_snapshot_with_token
    injected = False

    def snapshot_then_append():
        nonlocal injected
        token, events = real_snapshot()
        if not injected and any(
            frame.function == "_stable_audit_events"
            for frame in inspect.stack()
        ):
            injected = True
            spine.append(
                trade_rules_api.EVENT_TRADE_DISPUTE_STATEMENT_RETAINED,
                {"statement_digest": "sha256:" + ("2" * 64)},
            )
        return token, events

    monkeypatch.setattr(
        spine,
        "verified_snapshot_with_token",
        snapshot_then_append,
    )
    path = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}"
        f"/execution-receipts/{receipt.execution_id}/reviews/"
        f"{review.review_id}/dispute-statements"
    )
    headers = {"Authorization": f"Bearer {app.state.nth_console_token}"}
    client = TestClient(app)

    first = client.get(path, headers=headers)
    second = client.get(path, headers=headers)

    assert first.status_code == 200, first.text
    assert second.status_code == 409
    assert injected is True


def test_operator_dispute_statement_list_rejects_malformed_typed_audit_event(
    tmp_path,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    _context, order, receipt, review, _delivery, _public_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )
    app.state.nth.spine.append(
        trade_rules_api.EVENT_TRADE_DISPUTE_STATEMENT_RETAINED,
        {"statement_digest": "sha256:" + ("1" * 64)},
    )
    path = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}"
        f"/execution-receipts/{receipt.execution_id}/reviews/"
        f"{review.review_id}/dispute-statements"
    )

    response = TestClient(app).get(
        path,
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == (
        "trade Dispute Statement audit projection is invalid"
    )


def _create_operator_dispute_statement_for_dispatch(
    app,
    order,
    receipt,
    review,
    delivery,
    *,
    idempotency_key,
):
    path, body, headers = _operator_dispute_statement_request(
        app,
        order,
        receipt,
        review,
        delivery,
        idempotency_key=idempotency_key,
    )
    response = TestClient(app).post(path, json=body, headers=headers)
    assert response.status_code == 201, response.text
    return path, headers, response.json()


def test_operator_delivers_dispute_statement_once_and_reuses_durable_ack(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, receipt, review, delivery, _public_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )
    path, headers, created = _create_operator_dispute_statement_for_dispatch(
        app,
        order,
        receipt,
        review,
        delivery,
        idempotency_key="dispute-dispatch-once-0001",
    )
    statement_created = datetime.fromisoformat(
        created["statement"]["created_at"].replace("Z", "+00:00")
    )
    class ImmediateDeliveryDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return statement_created if tz is not None else statement_created.replace(
                tzinfo=None
            )

    monkeypatch.setattr(web_v2_api, "datetime", ImmediateDeliveryDateTime)
    network_calls = 0

    def receive(
        peer_url,
        sent_order_digest,
        sent_execution_id,
        sent_review_id,
        document,
        *,
        timeout_seconds=15.0,
    ):
        nonlocal network_calls
        network_calls += 1
        assert peer_url == "http://peer.example"
        assert sent_order_digest == trade_order_digest(order)
        assert sent_execution_id == receipt.execution_id
        assert sent_review_id == review.review_id
        assert timeout_seconds == 15.0
        signed_delivery = TradeDisputeStatementDelivery.from_dict(
            document,
            review=review,
            receipt=receipt,
            order=order,
        )
        acknowledgement = create_trade_dispute_statement_acknowledgement(
            context["taker"],
            delivery=signed_delivery,
            review=review,
            receipt=receipt,
            order=order,
            received_at=document["created_at"],
            audit_event_id="7" * 64,
        )
        return 202, {
            "acknowledgement": acknowledgement.to_dict(),
            "audit_event_id": "7" * 64,
        }

    monkeypatch.setattr(
        web_v2_api,
        "_post_trade_dispute_statement_delivery_to_peer",
        receive,
    )
    target = f"{path}/{created['statement_digest']}/deliver"
    client = TestClient(app)
    first = client.post(
        target,
        json={"target_url": "http://peer.example/"},
        headers=headers,
    )
    retry = client.post(
        target,
        json={"target_url": "http://peer.example"},
        headers=headers,
    )

    assert first.status_code == 200, first.text
    assert retry.status_code == 200, retry.text
    assert retry.json()["acknowledgement"] == first.json()["acknowledgement"]
    assert first.json()["claim_adjudicated_or_proven_true"] is False
    assert network_calls == 1
    retained = app.state.nth.trade_dispute_statement_dispatch_store.get(
        created["statement_digest"]
    )
    assert retained is not None
    assert first.json()["delivery"] == retained.delivery.to_dict()
    assert retained.acknowledged is True
    assert retained.anchor_event_id
    assert any(
        event.type == EVENT_TRADE_DISPUTE_STATEMENT_ACKNOWLEDGED
        for event in app.state.nth.spine.verified_snapshot()
    )


def test_operator_dispute_statement_delivery_is_single_flight(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, receipt, review, delivery, _public_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )
    path, headers, created = _create_operator_dispute_statement_for_dispatch(
        app,
        order,
        receipt,
        review,
        delivery,
        idempotency_key="dispute-dispatch-single-flight-0001",
    )
    target = f"{path}/{created['statement_digest']}/deliver"
    monkeypatch.setattr(
        web_v2_api,
        "_post_trade_dispute_statement_delivery_to_peer",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("injected first network failure")
        ),
    )
    retained = TestClient(app).post(
        target,
        json={"target_url": "http://peer.example"},
        headers=headers,
    )
    assert retained.status_code == 502, retained.text

    entered = threading.Event()
    release = threading.Event()
    network_calls = 0
    network_lock = threading.Lock()

    def blocking_receive(*args, **_kwargs):
        nonlocal network_calls
        with network_lock:
            network_calls += 1
        document = args[4]
        signed_delivery = TradeDisputeStatementDelivery.from_dict(
            document,
            review=review,
            receipt=receipt,
            order=order,
        )
        entered.set()
        assert release.wait(timeout=10)
        acknowledgement = create_trade_dispute_statement_acknowledgement(
            context["taker"],
            delivery=signed_delivery,
            review=review,
            receipt=receipt,
            order=order,
            received_at=document["created_at"],
            audit_event_id="9" * 64,
        )
        return 202, {
            "acknowledgement": acknowledgement.to_dict(),
            "audit_event_id": "9" * 64,
        }

    monkeypatch.setattr(
        web_v2_api,
        "_post_trade_dispute_statement_delivery_to_peer",
        blocking_receive,
    )
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            active = executor.submit(
                TestClient(app).post,
                target,
                json={"target_url": "http://peer.example"},
                headers=headers,
            )
            assert entered.wait(timeout=10)
            competing = TestClient(app).post(
                target,
                json={"target_url": "http://peer.example"},
                headers=headers,
            )
            assert competing.status_code == 503, competing.text
            assert competing.headers["Retry-After"] == "1"
            release.set()
            completed = active.result(timeout=20)
    finally:
        release.set()

    assert completed.status_code == 200, completed.text
    assert network_calls == 1


def test_operator_rejects_misbound_dispute_statement_ack_and_releases_lease(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, receipt, review, delivery, _public_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )
    path, headers, created = _create_operator_dispute_statement_for_dispatch(
        app,
        order,
        receipt,
        review,
        delivery,
        idempotency_key="dispute-dispatch-misbound-ack-0001",
    )

    def receive(*args, **_kwargs):
        document = args[4]
        signed_delivery = TradeDisputeStatementDelivery.from_dict(
            document,
            review=review,
            receipt=receipt,
            order=order,
        )
        acknowledgement = create_trade_dispute_statement_acknowledgement(
            context["taker"],
            delivery=signed_delivery,
            review=review,
            receipt=receipt,
            order=order,
            received_at=document["created_at"],
            audit_event_id="b" * 64,
        )
        return 202, {
            "acknowledgement": acknowledgement.to_dict(),
            "audit_event_id": "c" * 64,
        }

    monkeypatch.setattr(
        web_v2_api,
        "_post_trade_dispute_statement_delivery_to_peer",
        receive,
    )
    response = TestClient(app).post(
        f"{path}/{created['statement_digest']}/deliver",
        json={"target_url": "http://peer.example"},
        headers=headers,
    )

    assert response.status_code == 502, response.text
    assert response.json()["detail"] == (
        "peer returned an invalid signed acknowledgement"
    )
    retained = app.state.nth.trade_dispute_statement_dispatch_store.get(
        created["statement_digest"]
    )
    assert retained is not None
    assert retained.acknowledged is False
    assert retained.attempts == 1
    assert retained.lease_expires_at_ms == 0


def test_dispute_statement_dispatch_restart_anchors_retained_remote_ack(
    tmp_path,
    monkeypatch,
):
    workspace = tmp_path / "node"
    app = create_app(workspace, require_console_auth=True)
    persistent_packages = app.state.nth.trade_rule_packages
    context, order, receipt, review, delivery, _public_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )
    package = context["package_store"].load(context["package_digest"])
    assert package is not None
    persistent_packages.install(
        package.manifest,
        package.resources,
        source="local",
    )
    app.state.nth.trade_rule_packages = persistent_packages
    path, headers, created = _create_operator_dispute_statement_for_dispatch(
        app,
        order,
        receipt,
        review,
        delivery,
        idempotency_key="dispute-dispatch-restart-0001",
    )
    network_calls = 0

    def receive(*_args, **_kwargs):
        nonlocal network_calls
        network_calls += 1
        document = _args[4]
        signed_delivery = TradeDisputeStatementDelivery.from_dict(
            document,
            review=review,
            receipt=receipt,
            order=order,
        )
        acknowledgement = create_trade_dispute_statement_acknowledgement(
            context["taker"],
            delivery=signed_delivery,
            review=review,
            receipt=receipt,
            order=order,
            received_at=document["created_at"],
            audit_event_id="8" * 64,
        )
        return 202, {
            "acknowledgement": acknowledgement.to_dict(),
            "audit_event_id": "8" * 64,
        }

    monkeypatch.setattr(
        web_v2_api,
        "_post_trade_dispute_statement_delivery_to_peer",
        receive,
    )
    monkeypatch.setattr(
        app.state.nth.trade_dispute_statement_dispatch,
        "_anchor",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("injected local Spine outage")
        ),
    )
    target = f"{path}/{created['statement_digest']}/deliver"
    failed = TestClient(app).post(
        target,
        json={"target_url": "http://peer.example"},
        headers=headers,
    )

    assert failed.status_code == 503, failed.text
    retained = app.state.nth.trade_dispute_statement_dispatch_store.get(
        created["statement_digest"]
    )
    assert retained is not None and retained.acknowledged
    assert retained.anchor_event_id == ""
    assert network_calls == 1

    restarted = create_app(workspace, require_console_auth=True)
    monkeypatch.setattr(
        web_v2_api,
        "_post_trade_dispute_statement_delivery_to_peer",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("retained acknowledgement must prevent network replay")
        ),
    )
    retry = TestClient(restarted).post(
        target,
        json={"target_url": "http://peer.example"},
        headers={
            "Authorization": f"Bearer {restarted.state.nth_console_token}"
        },
    )

    assert retry.status_code == 200, retry.text
    recovered = restarted.state.nth.trade_dispute_statement_dispatch_store.get(
        created["statement_digest"]
    )
    assert recovered is not None and recovered.anchor_event_id
    assert restarted.state.nth.spine.verify_chain() == (True, "ok")


def test_dispute_statement_runtime_worker_anchors_retained_remote_ack(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "node", require_console_auth=True)
    context, order, receipt, review, delivery, _public_path = (
        _live_dispute_statement_delivery(
            tmp_path,
            app,
            receiver_role="maker",
        )
    )
    path, headers, created = _create_operator_dispute_statement_for_dispatch(
        app,
        order,
        receipt,
        review,
        delivery,
        idempotency_key="dispute-dispatch-worker-0001",
    )

    def receive(*args, **_kwargs):
        document = args[4]
        signed_delivery = TradeDisputeStatementDelivery.from_dict(
            document,
            review=review,
            receipt=receipt,
            order=order,
        )
        acknowledgement = create_trade_dispute_statement_acknowledgement(
            context["taker"],
            delivery=signed_delivery,
            review=review,
            receipt=receipt,
            order=order,
            received_at=document["created_at"],
            audit_event_id="a" * 64,
        )
        return 202, {
            "acknowledgement": acknowledgement.to_dict(),
            "audit_event_id": "a" * 64,
        }

    monkeypatch.setattr(
        web_v2_api,
        "_post_trade_dispute_statement_delivery_to_peer",
        receive,
    )
    coordinator = app.state.nth.trade_dispute_statement_dispatch
    real_anchor = coordinator._anchor
    coordinator._anchor = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        OSError("injected transient dispatch anchor outage")
    )
    monkeypatch.setattr(
        "nth_dao.web._TRADE_DISPUTE_RECOVERY_POLL_SECONDS",
        0.01,
    )
    target = f"{path}/{created['statement_digest']}/deliver"

    with TestClient(app) as client:
        recovery_worker = app.state.nth.trade_dispute_statement_recovery_worker
        real_wake = recovery_worker.wake
        wake_calls = []

        def fail_wake(statement_digest, *, urgent_for_s=0.0):
            wake_calls.append((statement_digest, urgent_for_s))
            raise RuntimeError("injected wake failure")

        monkeypatch.setattr(recovery_worker, "wake", fail_wake)
        failed = client.post(
            target,
            json={"target_url": "http://peer.example"},
            headers=headers,
        )
        assert failed.status_code == 503, failed.text
        assert wake_calls == [(created["statement_digest"], 5.0)]
        coordinator._anchor = real_anchor
        monkeypatch.setattr(recovery_worker, "wake", real_wake)
        assert real_wake(created["statement_digest"], urgent_for_s=5.0) is True
        # Urgent wake retries immediately, but recovery still re-verifies the
        # retained Order/Receipt/Review/ACK chain and commits with SQLite FULL
        # sync. This is eventual correctness, not a machine-speed 3 second SLO.
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            retained = app.state.nth.trade_dispute_statement_dispatch_store.get(
                created["statement_digest"]
            )
            if retained is not None and retained.anchor_event_id:
                break
            time.sleep(0.01)

    retained = app.state.nth.trade_dispute_statement_dispatch_store.get(
        created["statement_digest"]
    )
    assert retained is not None and retained.anchor_event_id
    assert app.state.nth.spine.verify_chain() == (True, "ok")


def test_two_nodes_federate_dispute_statement_and_retain_both_sides(
    tmp_path,
    monkeypatch,
):
    source = create_app(tmp_path / "source", require_console_auth=True)
    destination = create_app(
        tmp_path / "destination",
        require_console_auth=True,
    )
    context = _setup(
        tmp_path / "fixtures",
        maker=source.state.nth.node_identity,
        taker=destination.state.nth.node_identity,
    )
    order = _order(context)
    receipt = _current_execution_receipt(context, order)
    for app in (source, destination):
        _retain_order_and_receipt(app, context, order, receipt)
        _configure_live_execution_receiver(app, context)
    moment = datetime.now(timezone.utc)
    if moment.microsecond == 0:
        moment = moment.replace(microsecond=1)
    reviewed_at = moment.isoformat(timespec="microseconds").replace(
        "+00:00",
        "Z",
    )
    review = create_trade_receipt_review(
        context["taker"],
        receipt=receipt,
        order=order,
        package_resolver=context["package_store"],
        verifier_policy=context["taker_policy"],
        adapter_resolver=context["adapter_resolver"],
        adapter_policy=context["adapter_policy"],
        content_resolver=context["content_resolver"],
        schema_validator=context["schema_validator"],
        decision="disputed",
        reason_codes=["result.mismatch"],
        reviewed_at=reviewed_at,
        now=moment,
    )
    for app in (source, destination):
        app.state.nth.trade_receipt_review_coordinator.record(
            review,
            receipt=receipt,
            order=order,
            verifier_policy=context["taker_policy"],
            adapter_policy=context["adapter_policy"],
            observed_at_ms=int(moment.timestamp() * 1_000),
        )
    rule_binding = order.to_dict()["rule_bindings"][0]
    path = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}"
        f"/execution-receipts/{receipt.execution_id}/reviews/"
        f"{review.review_id}/dispute-statements"
    )
    created = TestClient(source).post(
        path,
        json={
            "statement_type": "response",
            "parent_statement_digests": [],
            "reason_codes": ["executor.contests-review"],
            "claim": _dispute_claim(),
            "evidence": [],
            "rule_action": {
                **rule_binding,
                "hook": "fulfillment.deliver",
                "hook_version": "1",
            },
        },
        headers={
            "Authorization": f"Bearer {source.state.nth_console_token}",
            "Idempotency-Key": "dispute-two-node-0001",
        },
    )
    assert created.status_code == 201, created.text
    destination_client = TestClient(destination)
    forwarded = 0

    def forward(
        _peer_url,
        sent_order_digest,
        sent_execution_id,
        sent_review_id,
        document,
        **_kwargs,
    ):
        nonlocal forwarded
        forwarded += 1
        response = destination_client.post(
            f"/api/v2/trade/federation/orders/{sent_order_digest}"
            f"/execution-receipts/{sent_execution_id}/reviews/"
            f"{sent_review_id}/dispute-statements",
            json=document,
        )
        return response.status_code, response.json()

    monkeypatch.setattr(
        web_v2_api,
        "_post_trade_dispute_statement_delivery_to_peer",
        forward,
    )
    result = TestClient(source).post(
        f"{path}/{created.json()['statement_digest']}/deliver",
        json={"target_url": "http://destination.example"},
        headers={
            "Authorization": f"Bearer {source.state.nth_console_token}"
        },
    )

    assert result.status_code == 200, result.text
    assert result.json()["claim_adjudicated_or_proven_true"] is False
    assert forwarded == 1
    page = destination.state.nth.trade_dispute_statements.list_for_review(
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=context["package_store"],
        limit=100,
    )
    assert len(page.statements) == 1
    assert source.state.nth.spine.verify_chain() == (True, "ok")
    assert destination.state.nth.spine.verify_chain() == (True, "ok")


def test_operator_delivers_execution_receipt_and_persists_peer_ack(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path / "maker", require_console_auth=True)
    context = _setup(
        tmp_path / "fixtures",
        maker=app.state.nth.node_identity,
    )
    order = _order(context)
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1_000)
    local_order = app.state.nth.trade_order_audit.accept(
        order,
        now_ms=now_ms,
    )
    assert local_order.record.order_digest == trade_order_digest(order)
    receipt = _current_execution_receipt(
        context,
        order,
        coordinator=app.state.nth.trade_execution_coordinator,
    )
    network_calls = 0

    def receive(peer_url, sent_order_digest, document, *, timeout_seconds=15.0):
        nonlocal network_calls
        network_calls += 1
        assert peer_url == "http://127.0.0.1:18082"
        assert sent_order_digest == trade_order_digest(order)
        delivery = TradeExecutionReceiptDelivery.from_dict(
            document,
            order=order,
        )
        acknowledgement = create_trade_execution_receipt_acknowledgement(
            context["taker"],
            delivery=delivery,
            order=order,
            received_at=delivery.to_dict()["created_at"],
            audit_event_id="6" * 64,
        )
        return 202, {
            "status": "execution-receipt-retained-verified",
            "audit_event_id": "6" * 64,
            "acknowledgement": acknowledgement.to_dict(),
        }

    monkeypatch.setattr(
        web_v2_api,
        "_post_trade_execution_receipt_delivery_to_peer",
        receive,
    )
    path = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}"
        f"/execution-receipts/{receipt.execution_id}/deliver"
    )
    headers = {"Authorization": f"Bearer {app.state.nth_console_token}"}

    first = TestClient(app).post(
        path,
        json={"target_url": "http://127.0.0.1:18082"},
        headers=headers,
    )
    retry = TestClient(app).post(
        path,
        json={"target_url": "http://127.0.0.1:18082"},
        headers=headers,
    )

    assert first.status_code == 200, first.text
    assert retry.status_code == 200, retry.text
    assert first.json()["status"] == "execution-receipt-delivered"
    assert first.json()["acknowledgement_persisted"] is True
    assert retry.json() == first.json()
    assert network_calls == 1
    receipt_digest = execution_receipt_digest(receipt, order=order)
    assert app.state.nth.trade_execution_dispatch_store.get_pending(
        receipt_digest
    ) is None
    assert app.state.nth.trade_execution_dispatch_store.get_acknowledgement(
        receipt_digest
    ) is not None
    anchors = [
        event
        for event in app.state.nth.spine.verified_snapshot()
        if event.type == EVENT_TRADE_EXECUTION_RECEIPT_ACKNOWLEDGED
    ]
    assert len(anchors) == 1
    history = TestClient(app).get(
        f"/api/v2/trade/orders/{trade_order_digest(order)}/execution-receipts",
        headers=headers,
    )
    assert history.status_code == 200, history.text
    projected = history.json()["items"][0]
    assert projected["federation_status"] == "acknowledged"
    assert projected["dispatch_target_url"] == "http://127.0.0.1:18082"
    assert projected["remote_receiver_did"] == context["taker"].as_did()
    assert projected["remote_audit_event_id"] == "6" * 64
    assert projected["remote_acknowledgement_digest"].startswith("sha256:")


def test_order_reconcile_repairs_retained_receipt_ack_without_restart(tmp_path):
    app = create_app(tmp_path / "maker", require_console_auth=True)
    context = _setup(
        tmp_path / "fixtures",
        maker=app.state.nth.node_identity,
    )
    order = _order(context)
    accepted_at = datetime.now(timezone.utc).replace(microsecond=0)
    app.state.nth.trade_order_audit.accept(
        order,
        now_ms=int(accepted_at.timestamp() * 1_000),
    )
    receipt = _current_execution_receipt(
        context,
        order,
        coordinator=app.state.nth.trade_execution_coordinator,
    )
    completed_at = datetime.fromisoformat(
        receipt.to_dict()["completed_at"].replace("Z", "+00:00")
    )
    moment = completed_at + timedelta(seconds=1)
    now_ms = int(moment.timestamp() * 1_000)
    delivery = create_trade_execution_receipt_delivery(
        context["maker"],
        receipt=receipt,
        order=order,
        created_at=moment.isoformat().replace("+00:00", "Z"),
        not_after=(moment + timedelta(minutes=5)).isoformat().replace(
            "+00:00", "Z"
        ),
        nonce="fa" * 16,
        now=moment,
    )
    target = "http://127.0.0.1:18082"
    receipt_digest = execution_receipt_digest(receipt, order=order)
    store = app.state.nth.trade_execution_dispatch_store
    store.prepare(
        delivery,
        order=order,
        target_url=target,
        now_ms=now_ms,
    )
    acknowledgement = create_trade_execution_receipt_acknowledgement(
        context["taker"],
        delivery=delivery,
        order=order,
        received_at=delivery.to_dict()["created_at"],
        audit_event_id="6" * 64,
    )
    store.put_acknowledgement(
        delivery,
        acknowledgement,
        order=order,
        target_url=target,
        remote_event_id="6" * 64,
        observed_at_ms=now_ms,
    )
    headers = {"Authorization": f"Bearer {app.state.nth_console_token}"}
    client = TestClient(app)
    history_path = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}/execution-receipts"
    )

    before = client.get(history_path, headers=headers)

    assert before.status_code == 200, before.text
    assert before.json()["items"][0]["federation_status"] == (
        "acknowledged-pending-anchor"
    )
    repaired = client.post(
        "/api/v2/trade/orders/reconcile",
        headers=headers,
    )

    assert repaired.status_code == 200, repaired.text
    report = repaired.json()
    assert report["receipt_acknowledgements_scanned"] == 1
    assert report["receipt_acknowledgements_anchored"] == 1
    assert report["receipt_dispatches_completed"] == 1
    assert store.get_pending(receipt_digest) is None
    after = client.get(history_path, headers=headers)
    assert after.json()["items"][0]["federation_status"] == "acknowledged"


def test_order_delivery_post_verifies_recipient_on_same_pinned_ip(monkeypatch):
    recipient = AgentIdentity.generate().as_did()
    resolved_ip = "198.51.100.19"
    calls = []
    monkeypatch.setattr(
        web_v2_api,
        "_resolve_operator_trade_peer_ips",
        lambda _url: (resolved_ip,),
    )

    def open_card(url, timeout_seconds, pinned_ip=""):
        calls.append(("identity", url, pinned_ip, timeout_seconds))
        challenge = urlsplit(url).query.removeprefix("challenge=")
        return json.dumps({"challenge": challenge}).encode("utf-8")

    monkeypatch.setattr(
        web_v2_api,
        "_open_federation_identity_card",
        open_card,
    )

    def verify_card(_peer, card, *, expected_challenge=None):
        assert expected_challenge == card["challenge"]
        return ({"did": recipient}, "")

    monkeypatch.setattr(
        web_v2_api,
        "_verify_federation_identity_card",
        verify_card,
    )
    from nth_dao.web import market_federation_poll

    def post(url, pinned_ip, document, **_kwargs):
        calls.append(("post", url, pinned_ip, document))
        return 202, b'{"status":"accepted"}'

    monkeypatch.setattr(
        market_federation_poll,
        "_urllib_post_json_pinned_raw",
        post,
    )

    status, response = web_v2_api._post_trade_order_delivery_to_peer(
        "https://peer.example",
        {"recipient_did": recipient, "order": "private"},
    )

    assert status == 202
    assert response == {"status": "accepted"}
    assert [item[0] for item in calls] == ["identity", "post"]
    assert calls[0][2] == calls[1][2] == resolved_ip


def test_order_delivery_post_rejects_wrong_peer_before_disclosure(monkeypatch):
    recipient = AgentIdentity.generate().as_did()
    wrong_peer = AgentIdentity.generate().as_did()
    post_calls = []
    monkeypatch.setattr(
        web_v2_api,
        "_resolve_operator_trade_peer_ips",
        lambda _url: ("198.51.100.18",),
    )
    monkeypatch.setattr(
        web_v2_api,
        "_open_federation_identity_card",
        lambda url, *_args, **_kwargs: json.dumps({
            "challenge": urlsplit(url).query.removeprefix("challenge=")
        }).encode("utf-8"),
    )
    monkeypatch.setattr(
        web_v2_api,
        "_verify_federation_identity_card",
        lambda *_args, **_kwargs: ({"did": wrong_peer}, ""),
    )
    from nth_dao.web import market_federation_poll

    monkeypatch.setattr(
        market_federation_poll,
        "_urllib_post_json_pinned_raw",
        lambda *_args, **_kwargs: post_calls.append(True),
    )

    with pytest.raises(ValueError, match="does not match Order recipient_did"):
        web_v2_api._post_trade_order_delivery_to_peer(
            "https://peer.example",
            {"recipient_did": recipient, "order": "private"},
        )

    assert post_calls == []


def test_order_delivery_post_rejects_replayed_identity_card(monkeypatch):
    recipient = AgentIdentity.generate().as_did()
    post_calls = []
    monkeypatch.setattr(
        web_v2_api,
        "_resolve_operator_trade_peer_ips",
        lambda _url: ("198.51.100.17",),
    )
    monkeypatch.setattr(
        web_v2_api,
        "_open_federation_identity_card",
        lambda *_args, **_kwargs: b"{}",
    )
    monkeypatch.setattr(
        web_v2_api,
        "_verify_federation_identity_card",
        lambda _peer, _card, **_kwargs: (
            None,
            "identity card challenge did not match",
        ),
    )
    from nth_dao.web import market_federation_poll

    monkeypatch.setattr(
        market_federation_poll,
        "_urllib_post_json_pinned_raw",
        lambda *_args, **_kwargs: post_calls.append(True),
    )

    with pytest.raises(ValueError, match="challenge did not match"):
        web_v2_api._post_trade_order_delivery_to_peer(
            "https://peer.example",
            {"recipient_did": recipient, "order": "private"},
        )

    assert post_calls == []


def test_execution_receipt_post_verifies_recipient_on_same_pinned_ip(
    monkeypatch,
):
    recipient = AgentIdentity.generate().as_did()
    resolved_ip = "198.51.100.20"
    calls = []

    monkeypatch.setattr(
        web_v2_api,
        "_resolve_operator_trade_peer_ips",
        lambda _url: (resolved_ip,),
    )

    def open_card(url, timeout_seconds, pinned_ip=""):
        calls.append(("identity", url, pinned_ip, timeout_seconds))
        challenge = urlsplit(url).query.removeprefix("challenge=")
        return json.dumps({"challenge": challenge}).encode("utf-8")

    monkeypatch.setattr(
        web_v2_api,
        "_open_federation_identity_card",
        open_card,
    )

    def verify_card(_peer, card, *, expected_challenge=None):
        assert expected_challenge == card["challenge"]
        return ({"did": recipient}, "")

    monkeypatch.setattr(
        web_v2_api,
        "_verify_federation_identity_card",
        verify_card,
    )
    from nth_dao.web import market_federation_poll

    def post(url, pinned_ip, document, **_kwargs):
        calls.append(("post", url, pinned_ip, document))
        return 202, b'{"status":"ok"}'

    monkeypatch.setattr(
        market_federation_poll,
        "_urllib_post_json_pinned_raw",
        post,
    )

    status, response = (
        web_v2_api._post_trade_execution_receipt_delivery_to_peer(
            "https://peer.example",
            "sha256:" + "1" * 64,
            {"recipient_did": recipient, "receipt": "private"},
        )
    )

    assert status == 202
    assert response == {"status": "ok"}
    assert [item[0] for item in calls] == ["identity", "post"]
    assert calls[0][2] == calls[1][2] == resolved_ip


def test_execution_receipt_post_rejects_wrong_peer_before_disclosure(
    monkeypatch,
):
    recipient = AgentIdentity.generate().as_did()
    wrong_peer = AgentIdentity.generate().as_did()
    post_calls = []
    monkeypatch.setattr(
        web_v2_api,
        "_resolve_operator_trade_peer_ips",
        lambda _url: ("198.51.100.21",),
    )
    monkeypatch.setattr(
        web_v2_api,
        "_open_federation_identity_card",
        lambda url, *_args, **_kwargs: json.dumps({
            "challenge": urlsplit(url).query.removeprefix("challenge=")
        }).encode("utf-8"),
    )

    def verify_wrong_card(_peer, card, *, expected_challenge=None):
        assert expected_challenge == card["challenge"]
        return ({"did": wrong_peer}, "")

    monkeypatch.setattr(
        web_v2_api,
        "_verify_federation_identity_card",
        verify_wrong_card,
    )
    from nth_dao.web import market_federation_poll

    monkeypatch.setattr(
        market_federation_poll,
        "_urllib_post_json_pinned_raw",
        lambda *_args, **_kwargs: post_calls.append(True),
    )

    with pytest.raises(ValueError, match="does not match Receipt recipient_did"):
        web_v2_api._post_trade_execution_receipt_delivery_to_peer(
            "https://peer.example",
            "sha256:" + "2" * 64,
            {"recipient_did": recipient, "receipt": "private"},
        )

    assert post_calls == []


def test_execution_receipt_post_rejects_replayed_identity_card(
    monkeypatch,
):
    recipient = AgentIdentity.generate().as_did()
    post_calls = []
    monkeypatch.setattr(
        web_v2_api,
        "_resolve_operator_trade_peer_ips",
        lambda _url: ("198.51.100.22",),
    )
    monkeypatch.setattr(
        web_v2_api,
        "_open_federation_identity_card",
        lambda *_args, **_kwargs: b"{}",
    )
    monkeypatch.setattr(
        web_v2_api,
        "_verify_federation_identity_card",
        lambda _peer, _card, **_kwargs: (
            None,
            "identity card challenge did not match",
        ),
    )
    from nth_dao.web import market_federation_poll

    monkeypatch.setattr(
        market_federation_poll,
        "_urllib_post_json_pinned_raw",
        lambda *_args, **_kwargs: post_calls.append(True),
    )

    with pytest.raises(ValueError, match="challenge did not match"):
        web_v2_api._post_trade_execution_receipt_delivery_to_peer(
            "https://peer.example",
            "sha256:" + "3" * 64,
            {"recipient_did": recipient, "receipt": "private"},
        )

    assert post_calls == []


def test_two_live_http_nodes_deliver_and_ack_execution_receipt(tmp_path):
    maker_app = create_app(tmp_path / "maker", require_console_auth=True)
    taker_app = create_app(tmp_path / "taker", require_console_auth=True)
    context = _setup(
        tmp_path / "fixtures",
        maker=maker_app.state.nth.node_identity,
        taker=taker_app.state.nth.node_identity,
    )
    order = _order(context)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    order_delivery = create_trade_order_delivery(
        context["maker"],
        order=order,
        created_at=now.isoformat().replace("+00:00", "Z"),
        not_after=(now + timedelta(minutes=5)).isoformat().replace(
            "+00:00", "Z"
        ),
        nonce="d1" * 16,
        now=now,
    )
    with TestClient(taker_app) as client:
        accepted = client.post(
            "/api/v2/trade/federation/orders",
            content=order_delivery.canonical_bytes,
            headers={"Content-Type": "application/json"},
        )
    assert accepted.status_code == 202, accepted.text
    maker_app.state.nth.trade_order_audit.accept(
        order,
        now_ms=int(now.timestamp() * 1_000),
    )
    receipt = _current_execution_receipt(
        context,
        order,
        coordinator=maker_app.state.nth.trade_execution_coordinator,
    )
    _configure_live_execution_receiver(taker_app, context)
    maker_server = _UvicornThreadServer(maker_app, _free_tcp_port())
    taker_server = _UvicornThreadServer(taker_app, _free_tcp_port())
    path = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}"
        f"/execution-receipts/{receipt.execution_id}/deliver"
    )

    with maker_server, taker_server:
        delivered = _process_http_json(
            maker_server.url + path,
            payload={"target_url": taker_server.url},
            headers={
                "Authorization": (
                    f"Bearer {maker_app.state.nth_console_token}"
                )
            },
        )

    assert delivered["status"] == "execution-receipt-delivered"
    assert delivered["acknowledgement_persisted"] is True
    assert delivered["acknowledgement"]["receiver_did"] == (
        taker_app.state.nth.node_identity.as_did()
    )
    assert taker_app.state.nth.trade_execution_receipts.get(
        receipt.execution_id,
        order=order,
    ) == receipt
    receipt_digest = execution_receipt_digest(receipt, order=order)
    assert maker_app.state.nth.trade_execution_dispatch_store.get_pending(
        receipt_digest
    ) is None
    assert maker_app.state.nth.trade_execution_dispatch_store.get_acknowledgement(
        receipt_digest
    ) is not None


def test_live_http_wrong_did_rejects_before_receipt_post(tmp_path):
    maker_app = create_app(tmp_path / "maker", require_console_auth=True)
    wrong_app = create_app(tmp_path / "wrong", require_console_auth=True)
    intended_taker = AgentIdentity.generate(label="intended-taker")
    context = _setup(
        tmp_path / "fixtures",
        maker=maker_app.state.nth.node_identity,
        taker=intended_taker,
    )
    order = _order(context)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    maker_app.state.nth.trade_order_audit.accept(
        order,
        now_ms=int(now.timestamp() * 1_000),
    )
    receipt = _current_execution_receipt(
        context,
        order,
        coordinator=maker_app.state.nth.trade_execution_coordinator,
    )
    receipt_posts = []

    @wrong_app.middleware("http")
    async def count_receipt_posts(request, call_next):
        if (
            request.method == "POST"
            and request.url.path.endswith("/execution-receipts")
        ):
            receipt_posts.append(request.url.path)
        return await call_next(request)

    maker_server = _UvicornThreadServer(maker_app, _free_tcp_port())
    wrong_server = _UvicornThreadServer(wrong_app, _free_tcp_port())
    path = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}"
        f"/execution-receipts/{receipt.execution_id}/deliver"
    )

    with maker_server, wrong_server:
        with pytest.raises(urllib.error.HTTPError) as caught:
            _process_http_json(
                maker_server.url + path,
                payload={"target_url": wrong_server.url},
                headers={
                    "Authorization": (
                        f"Bearer {maker_app.state.nth_console_token}"
                    )
                },
            )
        error_body = json.loads(caught.value.read().decode("utf-8"))

    assert caught.value.code == 502
    assert "does not match Receipt recipient_did" in error_body["detail"]
    assert receipt_posts == []


def test_two_live_http_nodes_deliver_and_ack_receipt_review(tmp_path):
    maker_app = create_app(tmp_path / "maker", require_console_auth=True)
    taker_app = create_app(tmp_path / "taker", require_console_auth=True)
    context = _setup(
        tmp_path / "fixtures",
        maker=maker_app.state.nth.node_identity,
        taker=taker_app.state.nth.node_identity,
    )
    order = _order(context)
    receipt = _current_execution_receipt(context, order)
    for app in (maker_app, taker_app):
        _retain_order_and_receipt(app, context, order, receipt)
        _configure_live_execution_receiver(app, context)
    maker_server = _UvicornThreadServer(maker_app, _free_tcp_port())
    taker_server = _UvicornThreadServer(taker_app, _free_tcp_port())
    base = (
        f"/api/v2/trade/orders/{trade_order_digest(order)}"
        f"/execution-receipts/{receipt.execution_id}/reviews"
    )

    with maker_server, taker_server:
        signed = _process_http_json(
            taker_server.url + base,
            payload={"decision": "accepted", "reason_codes": []},
            headers={
                "Authorization": (
                    f"Bearer {taker_app.state.nth_console_token}"
                )
            },
        )
        delivered = _process_http_json(
            taker_server.url + f"{base}/{signed['review_id']}/deliver",
            payload={"target_url": maker_server.url},
            headers={
                "Authorization": (
                    f"Bearer {taker_app.state.nth_console_token}"
                )
            },
        )

    assert delivered["status"] == "receipt-review-delivered"
    assert delivered["acknowledgement_persisted"] is True
    assert delivered["acknowledgement"]["receiver_did"] == (
        maker_app.state.nth.node_identity.as_did()
    )
    review = maker_app.state.nth.trade_receipt_reviews.get(
        signed["review_id"],
        receipt=receipt,
        order=order,
    )
    assert review is not None
    review_digest = receipt_review_digest(
        review,
        receipt=receipt,
        order=order,
    )
    assert (
        taker_app.state.nth.trade_receipt_review_dispatch_store.get_pending(
            review_digest
        )
        is None
    )
    assert (
        taker_app.state.nth.trade_receipt_review_dispatch_store
        .get_acknowledgement(review_digest)
        is not None
    )


def test_web_boot_connects_execution_coordinator_without_enabling_funds(
    tmp_path,
):
    app = create_app(tmp_path, require_console_auth=True)

    assert isinstance(
        app.state.nth.trade_execution_coordinator,
        TradeExecutionCoordinator,
    )
    assert app.state.nth.trade_executor_policy is None
    assert app.state.nth.trade_execution_adapter_resolver is None
    assert app.state.nth.trade_execution_adapter_policy is None
    assert app.state.nth.trade_execution_content_resolver is None


def test_operator_accepts_proposal_and_requires_signed_remote_receipt(
    tmp_path,
    monkeypatch,
):
    maker_app = create_app(
        tmp_path / "maker",
        require_console_auth=True,
    )
    context, proposal, proposal_delivery, _created, _expiry = (
        _live_proposal_delivery(tmp_path / "maker", maker_app)
    )
    maker_client = TestClient(maker_app)
    retained = maker_client.post(
        "/api/v2/trade/federation/proposals",
        content=proposal_delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )
    assert retained.status_code == 202

    _outbox, _store, _spine, taker_intake = _order_intake_runtime(
        tmp_path / "taker",
        context,
    )

    received_deliveries = []

    def receive_at_taker(peer_url, document, *, timeout_seconds=15.0):
        assert peer_url == "http://127.0.0.1:18081"
        delivery = TradeOrderDelivery.from_dict(document)
        received_deliveries.append(delivery)
        received = taker_intake.receive(
            delivery,
            at=datetime.now(timezone.utc),
        )
        return 202, {
            "status": "accepted-agreement-retained",
            "audit_event_id": received.audit.record.event_id,
            "intake_receipt": received.receipt.to_dict(),
            "intake_receipt_digest": received.receipt_digest,
        }

    monkeypatch.setattr(
        web_v2_api,
        "_post_trade_order_delivery_to_peer",
        receive_at_taker,
    )
    auth = {"Authorization": f"Bearer {maker_app.state.nth_console_token}"}
    endpoint = (
        "/api/v2/trade/proposals/"
        + proposal_digest(proposal)
        + "/accept"
    )
    accepted = maker_client.post(
        endpoint,
        json={"target_url": "http://127.0.0.1:18081"},
        headers=auth,
    )
    retry = maker_client.post(
        endpoint,
        json={"target_url": "http://127.0.0.1:18081"},
        headers=auth,
    )

    assert accepted.status_code == 200, accepted.text
    assert retry.status_code == 200, retry.text
    assert accepted.json()["status"] == "accepted-and-delivered"
    assert retry.json()["order"] == accepted.json()["order"]
    receipt = TradeOrderIntakeReceipt.from_dict(
        accepted.json()["remote_intake_receipt"]
    )
    assert receipt.to_dict()["receiver_did"] == context["taker"].as_did()
    assert len(received_deliveries) == 1
    acknowledgement = (
        maker_app.state.nth.trade_order_dispatch_store.get_acknowledgement(
            accepted.json()["order_digest"]
        )
    )
    assert acknowledgement is not None
    assert acknowledgement.receipt == receipt
    assert accepted.json()["acknowledgement_persisted"] is True
    assert maker_app.state.nth.trade_order_store.list_ids() == (
        accepted.json()["order"]["order_id"],
    )


def test_operator_rejects_unsigned_order_delivery_acknowledgement(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path, require_console_auth=True)
    _context, proposal, delivery, _created, _expiry = _live_proposal_delivery(
        tmp_path,
        app,
    )
    client = TestClient(app)
    assert client.post(
        "/api/v2/trade/federation/proposals",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    ).status_code == 202
    attempted_deliveries = []

    def unsigned_acknowledgement(_target, document, **_kwargs):
        attempted_deliveries.append(TradeOrderDelivery.from_dict(document))
        return 202, {"status": "accepted"}

    monkeypatch.setattr(
        web_v2_api,
        "_post_trade_order_delivery_to_peer",
        unsigned_acknowledgement,
    )

    response = client.post(
        f"/api/v2/trade/proposals/{proposal_digest(proposal)}/accept",
        json={"target_url": "http://127.0.0.1:18081"},
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )
    retry = client.post(
        f"/api/v2/trade/proposals/{proposal_digest(proposal)}/accept",
        json={"target_url": "http://127.0.0.1:18081"},
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )

    assert response.status_code == 502
    assert retry.status_code == 502
    assert "invalid signed intake receipt" in response.json()["detail"]
    assert len(attempted_deliveries) == 2
    assert attempted_deliveries[0].canonical_bytes == (
        attempted_deliveries[1].canonical_bytes
    )
    assert app.state.nth.trade_order_store.list_ids()
    order_id = app.state.nth.trade_order_store.list_ids()[0]
    order = app.state.nth.trade_order_store.get(order_id)
    pending = app.state.nth.trade_order_dispatch_store.get_pending(
        trade_order_digest(order)
    )
    assert pending is not None
    assert pending.attempts == 2
    auth = {"Authorization": f"Bearer {app.state.nth_console_token}"}
    listed = client.get("/api/v2/trade/orders", headers=auth)
    detail = client.get(
        f"/api/v2/trade/orders/{trade_order_digest(order)}",
        headers=auth,
    )
    for projected in (listed.json()["items"][0], detail.json()):
        assert projected["dispatch_pending"] is True
        assert projected["dispatch_target_url"] == "http://127.0.0.1:18081"
        assert projected["dispatch_attempts"] == 2
        assert projected["dispatch_generation"] == 1
        assert projected["dispatch_superseded_deliveries"] == 0
        assert projected["dispatch_last_error"]
        assert projected["remote_acknowledged"] is False


def test_operator_accept_rejects_malformed_proposal_digest(tmp_path):
    app = create_app(tmp_path, require_console_auth=True)

    response = TestClient(app).post(
        "/api/v2/trade/proposals/not-a-digest/accept",
        json={"target_url": "http://127.0.0.1:18081"},
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "digest must be a lowercase sha256 digest"
    )


@pytest.mark.parametrize(
    ("peer_url", "expected"),
    [
        ("HTTP://Peer.Example:80/path", "http://peer.example"),
        ("https://Peer.Example:443/api", "https://peer.example"),
        ("https://Peer.Example:8443/api", "https://peer.example:8443"),
        ("http://[2001:0db8::1]:8080/path", "http://[2001:db8::1]:8080"),
        ("https://BÜCHER.Example/", "https://xn--bcher-kva.example"),
    ],
)
def test_trade_rule_source_origin_is_canonical(peer_url, expected):
    assert web_v2_api._trade_rule_package_source_origin(peer_url) == expected


def test_trade_peer_resolution_rejects_dns_loopback_rebinding(monkeypatch):
    monkeypatch.setattr(
        web_v2_api.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (
                web_v2_api.socket.AF_INET,
                web_v2_api.socket.SOCK_STREAM,
                6,
                "",
                ("127.0.0.1", 18081),
            )
        ],
    )

    with pytest.raises(ValueError, match="must not redirect.*loopback"):
        web_v2_api._resolve_operator_trade_peer_ip(
            "http://peer.example:18081"
        )
    assert (
        web_v2_api._resolve_operator_trade_peer_ip(
            "http://127.0.0.1:18081"
        )
        == "127.0.0.1"
    )


def test_trade_peer_localhost_dual_stack_uses_dialable_ipv4_fallback():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, _format, *_args):
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    url = f"http://localhost:{server.server_port}/probe"
    try:
        addresses = web_v2_api._resolve_operator_trade_peer_ips(url)
        body = web_v2_api._call_operator_trade_peer_with_fallback(
            url,
            lambda address, remaining: _urllib_get_bytes_pinned(
                url,
                address,
                timeout_s=remaining,
                max_bytes=16,
            ),
            timeout_seconds=2.0,
        )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2.0)

    assert "127.0.0.1" in addresses
    assert body == b"ok"


def test_trade_peer_address_fallback_retries_connections_not_http_errors(monkeypatch):
    monkeypatch.setattr(
        web_v2_api,
        "_resolve_operator_trade_peer_ips",
        lambda _url: ("192.0.2.1", "192.0.2.2"),
    )
    attempted = []

    def operation(address, _remaining):
        attempted.append(address)
        if address == "192.0.2.1":
            raise ConnectionRefusedError("first address unavailable")
        return "connected"

    assert web_v2_api._call_operator_trade_peer_with_fallback(
        "https://peer.example",
        operation,
        timeout_seconds=5.0,
    ) == "connected"
    assert attempted == ["192.0.2.1", "192.0.2.2"]


def test_trade_peer_dns_address_set_is_bounded(monkeypatch):
    monkeypatch.setattr(
        web_v2_api.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (
                web_v2_api.socket.AF_INET,
                web_v2_api.socket.SOCK_STREAM,
                6,
                "",
                (f"8.8.8.{index}", 443),
            )
            for index in range(1, 10)
        ],
    )

    with pytest.raises(ValueError, match="too many addresses"):
        web_v2_api._resolve_operator_trade_peer_ips(
            "https://many.example"
        )


def test_trade_peer_fallback_uses_one_shared_deadline(monkeypatch):
    monkeypatch.setattr(
        web_v2_api,
        "_resolve_operator_trade_peer_ips",
        lambda _url: ("192.0.2.1", "192.0.2.2"),
    )
    moments = iter((100.0, 100.0, 104.0))
    monkeypatch.setattr(
        web_v2_api.time,
        "monotonic",
        lambda: next(moments),
    )
    budgets = []

    def operation(_address, remaining):
        budgets.append(remaining)
        if len(budgets) == 1:
            raise ConnectionRefusedError("retry")
        return "connected"

    assert web_v2_api._call_operator_trade_peer_with_fallback(
        "https://peer.example",
        operation,
        timeout_seconds=5.0,
    ) == "connected"
    assert budgets == [5.0, 1.0]


def test_trade_peer_fallback_stops_when_shared_deadline_expires(monkeypatch):
    monkeypatch.setattr(
        web_v2_api,
        "_resolve_operator_trade_peer_ips",
        lambda _url: ("192.0.2.1", "192.0.2.2"),
    )
    moments = iter((100.0, 100.0, 106.0))
    monkeypatch.setattr(
        web_v2_api.time,
        "monotonic",
        lambda: next(moments),
    )
    attempted = []

    def operation(address, _remaining):
        attempted.append(address)
        raise ConnectionRefusedError("retry")

    with pytest.raises(TimeoutError, match="deadline exceeded"):
        web_v2_api._call_operator_trade_peer_with_fallback(
            "https://peer.example",
            operation,
            timeout_seconds=5.0,
        )
    assert attempted == ["192.0.2.1"]


def test_public_order_delivery_rejects_foreign_recipient_without_write(
    tmp_path,
):
    app = create_app(tmp_path / "runtime", require_console_auth=True)
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    created = datetime.now(timezone.utc).replace(microsecond=0)
    delivery = create_trade_order_delivery(
        context["maker"],
        order=order,
        created_at=created.isoformat().replace("+00:00", "Z"),
        not_after=(created + timedelta(minutes=5)).isoformat().replace(
            "+00:00", "Z"
        ),
        now=created,
    )

    response = TestClient(app).post(
        "/api/v2/trade/federation/orders",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 400
    assert "recipient does not match this node" in response.json()["detail"]
    assert app.state.nth.trade_order_store.list_ids() == ()
    assert app.state.nth.trade_order_audit_outbox.pending() == ()


def test_public_order_delivery_endpoint_enforces_preparse_body_limit(
    tmp_path,
):
    client = TestClient(create_app(tmp_path, require_console_auth=True))

    response = client.post(
        "/api/v2/trade/federation/orders",
        content=b"{" + (b"x" * (256 * 1024)) + b"}",
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert "256 KiB" in response.json()["detail"]


def test_public_order_delivery_endpoint_has_global_crypto_budget(tmp_path):
    app = create_app(tmp_path, require_console_auth=True)
    app.state.nth.trade_order_delivery_global_limiter = RateLimiter(
        max_per_window=1,
        window_seconds=60,
    )
    client = TestClient(app)

    first = client.post(
        "/api/v2/trade/federation/orders",
        content=b"{}",
        headers={"Content-Type": "application/json"},
    )
    second = client.post(
        "/api/v2/trade/federation/orders",
        content=b"{}",
        headers={"Content-Type": "application/json"},
    )

    assert first.status_code == 400
    assert second.status_code == 429
    assert second.json()["detail"] == (
        "global trade Order delivery rate exceeded"
    )


def test_public_order_delivery_endpoint_has_per_source_crypto_budget(tmp_path):
    app = create_app(tmp_path, require_console_auth=True)
    app.state.nth.trade_order_delivery_limiter = RateLimiter(
        max_per_window=1,
        window_seconds=60,
    )
    client = TestClient(app)

    first = client.post(
        "/api/v2/trade/federation/orders",
        content=b"{}",
        headers={"Content-Type": "application/json"},
    )
    second = client.post(
        "/api/v2/trade/federation/orders",
        content=b"{}",
        headers={"Content-Type": "application/json"},
    )

    assert first.status_code == 400
    assert second.status_code == 429
    assert second.json()["detail"] == "trade Order delivery rate exceeded"


@pytest.mark.parametrize("failure_type", [OSError, ValueError])
def test_public_order_delivery_failure_does_not_expose_local_io_path(
    tmp_path,
    monkeypatch,
    failure_type,
):
    app = create_app(tmp_path, require_console_auth=True)
    _context, _order_value, delivery = _live_order_delivery(tmp_path, app)

    def fail_with_private_path(*args, **kwargs):
        raise failure_type(
            r"write failed at X:\\operator-home\\identity.json"
        )

    monkeypatch.setattr(
        app.state.nth.trade_order_intake,
        "receive",
        fail_with_private_path,
    )
    response = TestClient(app).post(
        "/api/v2/trade/federation/orders",
        content=delivery.canonical_bytes,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 503
    assert "operator-home" not in response.text
    assert "identity.json" not in response.text
    assert response.json()["detail"] == {
        "code": "trade-order-acceptance-incomplete",
        "message": "Order acknowledgement is incomplete",
        "safe_to_redeliver": True,
    }


def test_order_audit_records_support_digest_cursor_pagination(tmp_path):
    first_order = _order(_setup(tmp_path / "first"))
    second_order = _order(_setup(tmp_path / "second"))
    outbox = TradeOrderAuditOutbox(tmp_path / "runtime")
    outbox.prepare(first_order, now_ms=1_800_000_000_000)
    outbox.prepare(second_order, now_ms=1_800_000_000_001)
    statuses = frozenset({"prepared", "cached", "anchored", "blocked"})

    all_records = outbox.records(statuses=statuses, limit=10)
    first_page = outbox.records(statuses=statuses, limit=1)
    second_page = outbox.records(
        statuses=statuses,
        limit=1,
        after=first_page[0].order_digest,
    )

    assert len(all_records) == 2
    assert first_page + second_page == all_records
    with pytest.raises(ValueError, match="lowercase sha256"):
        outbox.records(statuses=statuses, limit=1, after="invalid")


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


def test_order_audit_projection_reuses_only_an_unchanged_verified_snapshot(
    tmp_path,
    monkeypatch,
):
    order = _order(_setup(tmp_path))
    _outbox, _order_store, spine, coordinator = _audit_runtime(tmp_path)
    coordinator.accept(order, now_ms=1_800_000_000_000)
    assert len(coordinator.list_accepted(limit=10)) == 1
    original = spine.verified_snapshot_with_token
    scans = 0

    def counted_snapshot():
        nonlocal scans
        scans += 1
        return original()

    monkeypatch.setattr(spine, "verified_snapshot_with_token", counted_snapshot)
    assert len(coordinator.list_accepted(limit=10)) == 1
    assert scans == 0

    spine.append("test.unrelated", {"id": "new"})
    assert len(coordinator.list_accepted(limit=10)) == 1
    assert scans == 1


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
    assert stored is None
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


def test_order_audit_crash_residue_is_bounded_and_operator_prunable(tmp_path):
    order = _order(_setup(tmp_path))
    outbox = TradeOrderAuditOutbox(tmp_path)
    record, _created = outbox.prepare(
        order,
        now_ms=1_800_000_000_000,
    )
    residue_name = f"{record.order_digest[7:]}.json.deadbeef.tmp"
    residue_path = outbox.root / residue_name
    residue_path.write_bytes(b"partial")

    assert outbox.get(record.order_digest) == record
    inspection = outbox.inspect_crash_residue()
    assert inspection.temporary_files == (residue_name,)
    assert inspection.total_bytes == len(b"partial")
    with pytest.raises(TradeOrderAuditCapacity, match="max_records"):
        TradeOrderAuditOutbox(tmp_path, max_records=1).get(
            record.order_digest
        )

    removed = outbox.prune_crash_residue(
        expected_files=inspection.temporary_files
    )

    assert removed.temporary_files == (residue_name,)
    assert not residue_path.exists()
    assert outbox.get(record.order_digest) == record


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


def test_agreement_execution_projection_is_fail_closed_without_local_runtime(
    tmp_path,
):
    context = _setup(tmp_path)
    order = _order(context)

    projection = project_trade_order_execution(
        order,
        context["package_store"],
        local_did=context["maker"].as_did(),
        coordinator_health=TradeExecutionRuntimeHealth(
            status="healthy",
            receipt_persistence_available=True,
        ),
        at=datetime(2026, 9, 1, tzinfo=timezone.utc),
    )

    assert projection["status"] == "blocked"
    assert projection["order_digest"] == trade_order_digest(order)
    assert projection["error_code"] == ""
    assert projection["coordinator"] == {
        "available": True,
        "status": "healthy",
        "receipt_persistence_available": True,
        "recovery_pending": False,
        "error_code": "",
        "execution_endpoint_enabled": False,
    }
    assert projection["local_executor"]["role"] == "maker"
    assert projection["local_executor"]["authorized_operation_count"] == 1
    assert projection["executor_policy"]["status"] == "not-configured"
    assert projection["adapter"]["status"] == "not-configured"
    assert projection["content"]["contract_schema_content_available"] is True
    assert projection["content"]["runtime_payloads_ready"] is False
    assert projection["funds"]["enabled"] is False
    assert {skill["rule_id"] for skill in projection["skills"]} == {
        "org.nthdao.test.delivery",
        "org.nthdao.test.settlement",
    }
    delivery_skill = next(
        skill
        for skill in projection["skills"]
        if skill["rule_id"] == "org.nthdao.test.delivery"
    )
    assert delivery_skill["installed"] is True
    assert delivery_skill["current"] is True
    assert projection["operation_grants"] == [{
        "operation_id": "deliver-service",
        "rule_id": "org.nthdao.test.delivery",
        "package_digest": context["package_digest"],
        "hook_name": "fulfillment.deliver",
        "hook_version": "1",
        "executor_role": "maker",
        "local_executor": True,
        "contract_available": True,
        "input_schema_content_available": True,
        "output_schema_content_available": True,
        "side_effect": "none",
        "permissions": [],
        "funds_execution_enabled": False,
    }]


def test_agreement_execution_projection_accepts_legacy_order_without_grants(
    tmp_path,
):
    context = _setup(tmp_path)
    proposal = create_trade_proposal(
        context["taker"],
        resolution=context["taker_resolution"],
        offer=context["offer"],
        offer_resolver=context["offer_store"],
        terms={"requested_quantity": "1"},
        created_at=_CREATED,
        not_after=_EXPIRES,
        now=_AT,
    )
    order = create_trade_order(
        offer=context["offer"],
        proposal=proposal,
        acceptance=_acceptance(context, proposal),
    )

    projection = project_trade_order_execution(
        order,
        context["package_store"],
        local_did=context["maker"].as_did(),
        coordinator_health=TradeExecutionRuntimeHealth(
            status="healthy",
            receipt_persistence_available=True,
        ),
        at=datetime(2026, 9, 1, tzinfo=timezone.utc),
    )

    assert projection["operation_grants"] == []
    assert projection["local_executor"]["authorized_operation_count"] == 0
    assert "Agreement has no operation grants" in projection[
        "blocking_reasons"
    ]
    assert projection["content"][
        "contract_schema_content_available"
    ] is False
    assert projection["status"] == "blocked"


def test_agreement_execution_projection_revalidates_explicit_local_policy(
    tmp_path,
):
    context = _setup(tmp_path)

    projection = project_trade_order_execution(
        _order(context),
        context["package_store"],
        local_did=context["maker"].as_did(),
        coordinator_health=TradeExecutionRuntimeHealth(
            status="healthy",
            receipt_persistence_available=True,
        ),
        executor_policy=context["maker_policy"],
        adapter_resolver=context["adapter_resolver"],
        adapter_policy=context["adapter_policy"],
        content_resolver=context["content_resolver"],
        at=datetime(2026, 9, 1, tzinfo=timezone.utc),
    )

    assert projection["executor_policy"]["status"] == "ready"
    assert projection["executor_policy"]["readiness"][
        "order_digest"
    ] == trade_order_digest(_order(context))
    assert projection["adapter"]["configured"] is True
    assert projection["adapter"]["status"] == "selection-required"
    assert projection["content"]["resolver_configured"] is True
    assert projection["status"] == "blocked"
    assert any(
        "exact approved Adapter" in reason
        for reason in projection["blocking_reasons"]
    )


def test_agreement_execution_projection_exposes_missing_package_and_observer(
    tmp_path,
):
    context = _setup(tmp_path)
    missing = context["package_digest"]

    class MissingResolver:
        def load(self, digest):
            if digest == missing:
                return None
            return context["package_store"].load(digest)

    projection = project_trade_order_execution(
        _order(context),
        MissingResolver(),
        local_did=AgentIdentity.generate().as_did(),
        coordinator_health=TradeExecutionRuntimeHealth(
            status="unavailable",
            receipt_persistence_available=False,
            error_code="not-configured",
        ),
        at=datetime(2026, 9, 1, tzinfo=timezone.utc),
    )

    assert projection["local_executor"]["role"] == "observer"
    assert projection["local_executor"]["authorized_operation_count"] == 0
    skill = next(
        item for item in projection["skills"] if item["package_digest"] == missing
    )
    assert skill["status"] == "missing"
    assert projection["operation_grants"][0]["contract_available"] is False
    assert "TradeExecutionCoordinator is unavailable" in (
        projection["blocking_reasons"]
    )


def test_agreement_execution_projection_does_not_leak_package_lookup_details(
    tmp_path,
):
    context = _setup(tmp_path)

    class FailingResolver:
        def load(self, _digest):
            raise OSError("sensitive-trade-package-location")

    projection = project_trade_order_execution(
        _order(context),
        FailingResolver(),
        local_did=context["maker"].as_did(),
        coordinator_health=TradeExecutionRuntimeHealth(
            status="healthy",
            receipt_persistence_available=True,
        ),
        at=datetime(2026, 9, 1, tzinfo=timezone.utc),
    )

    assert all(
        "sensitive-trade-package-location" not in skill["reason"]
        for skill in projection["skills"]
    )
    assert {skill["reason"] for skill in projection["skills"]} == {
        "Rule Package lookup failed (OSError)"
    }


def test_agreement_execution_projection_does_not_leak_invalid_package_details(
    tmp_path,
):
    context = _setup(tmp_path)

    class InvalidPackage:
        @property
        def manifest(self):
            raise ValueError("sensitive-invalid-package-location")

    class InvalidResolver:
        def load(self, _digest):
            return InvalidPackage()

    projection = project_trade_order_execution(
        _order(context),
        InvalidResolver(),
        local_did=context["maker"].as_did(),
        coordinator_health=TradeExecutionRuntimeHealth(
            status="healthy",
            receipt_persistence_available=True,
        ),
        at=datetime(2026, 9, 1, tzinfo=timezone.utc),
    )

    serialized = json.dumps(projection)
    assert "sensitive-invalid-package-location" not in serialized
    assert {skill["reason"] for skill in projection["skills"]} == {
        "Installed Rule Package is invalid (ValueError)"
    }


def test_execution_runtime_health_rejects_inconsistent_or_fake_values():
    with pytest.raises(ValueError, match="inconsistent"):
        TradeExecutionRuntimeHealth(
            status="healthy",
            receipt_persistence_available=False,
        )
    with pytest.raises(ValueError, match="error_code"):
        TradeExecutionRuntimeHealth(
            status="degraded",
            receipt_persistence_available=False,
            error_code="invalid error code",
        )
    with pytest.raises(ValueError, match="requires error_code"):
        TradeExecutionRuntimeHealth(
            status="degraded",
            receipt_persistence_available=False,
        )


def test_agreement_execution_projection_rejects_fake_runtime_resolvers(
    tmp_path,
):
    context = _setup(tmp_path)
    policy = context["adapter_policy"]

    with pytest.raises(
        trade_rules_api.TradeExecutionProjectionError,
        match="adapter_resolver must provide",
    ):
        project_trade_order_execution(
            _order(context),
            context["package_store"],
            local_did=context["maker"].as_did(),
            coordinator_health=TradeExecutionRuntimeHealth(
                status="healthy",
                receipt_persistence_available=True,
            ),
            adapter_resolver=object(),
            adapter_policy=policy,
            at=datetime(2026, 9, 1, tzinfo=timezone.utc),
        )

    with pytest.raises(
        trade_rules_api.TradeExecutionProjectionError,
        match="content_resolver must provide",
    ):
        project_trade_order_execution(
            _order(context),
            context["package_store"],
            local_did=context["maker"].as_did(),
            coordinator_health=TradeExecutionRuntimeHealth(
                status="healthy",
                receipt_persistence_available=True,
            ),
            content_resolver=object(),
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


def _execution_receipt_delivery(context, order, receipt=None):
    return create_trade_execution_receipt_delivery(
        context["maker"],
        receipt=receipt or _execution_receipt(context, order),
        order=order,
        created_at="2026-09-01T00:02:00Z",
        not_after="2026-09-01T00:12:00Z",
        nonce="a1" * 16,
        now=_utc("2026-09-01T00:02:00Z"),
    )


def test_execution_receipt_transport_round_trip_and_acknowledgement(
    tmp_path,
):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    delivery = _execution_receipt_delivery(context, order, receipt)

    assert delivery.receipt == receipt
    assert TradeExecutionReceiptDelivery.from_json(
        delivery.canonical_bytes,
        order=order,
    ) == delivery
    assert verify_trade_execution_receipt_delivery(
        delivery,
        order=order,
        recipient_did=context["taker"].as_did(),
        at=_utc("2026-09-01T00:03:00Z"),
    ) == (True, "ok")
    assert trade_execution_receipt_delivery_digest(
        delivery,
        order=order,
    ).startswith("sha256:")

    acknowledgement = create_trade_execution_receipt_acknowledgement(
        context["taker"],
        delivery=delivery,
        order=order,
        received_at="2026-09-01T00:03:00Z",
        audit_event_id="2" * 64,
    )
    assert TradeExecutionReceiptAcknowledgement.from_json(
        acknowledgement.canonical_bytes
    ) == acknowledgement
    assert verify_trade_execution_receipt_acknowledgement(
        acknowledgement,
        delivery=delivery,
        order=order,
        receiver_did=context["taker"].as_did(),
        audit_event_id="2" * 64,
        at=_utc("2026-09-01T00:03:01Z"),
    ) == (True, "ok")
    assert trade_execution_receipt_acknowledgement_digest(
        acknowledgement
    ).startswith("sha256:")


def test_execution_receipt_acknowledgement_allows_symmetric_clock_skew(
    tmp_path,
):
    context = _setup(tmp_path)
    order = _order(context)
    delivery = _execution_receipt_delivery(context, order)
    received_at = "2026-09-01T00:01:59Z"

    acknowledgement = create_trade_execution_receipt_acknowledgement(
        context["taker"],
        delivery=delivery,
        order=order,
        received_at=received_at,
        audit_event_id="2" * 64,
        clock_skew_seconds=2,
    )

    assert verify_trade_execution_receipt_acknowledgement(
        acknowledgement,
        delivery=delivery,
        order=order,
        receiver_did=context["taker"].as_did(),
        audit_event_id="2" * 64,
        at=_utc(received_at),
        clock_skew_seconds=2,
    ) == (True, "ok")
    with pytest.raises(
        TradeExecutionReceiptAcknowledgementRejected,
        match="within signed delivery lifetime",
    ):
        create_trade_execution_receipt_acknowledgement(
            context["taker"],
            delivery=delivery,
            order=order,
            received_at=received_at,
            audit_event_id="2" * 64,
            clock_skew_seconds=0,
        )


def test_execution_receipt_delivery_rejects_tampering_and_wrong_party(
    tmp_path,
):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    delivery = _execution_receipt_delivery(context, order, receipt)

    tampered = delivery.to_dict()
    tampered["receipt"]["outcome"] = "failed"
    with pytest.raises(
        TradeExecutionReceiptDeliveryRejected,
        match="embedded Receipt is invalid",
    ):
        TradeExecutionReceiptDelivery.from_dict(tampered, order=order)

    retargeted = delivery.to_dict()
    retargeted["recipient_did"] = context["maker"].as_did()
    with pytest.raises(
        TradeExecutionReceiptDeliveryRejected,
        match="different principals|opposing Order party",
    ):
        TradeExecutionReceiptDelivery.from_dict(retargeted, order=order)

    with pytest.raises(
        TradeExecutionReceiptDeliveryRejected,
        match="signer does not match Receipt executor",
    ):
        create_trade_execution_receipt_delivery(
            context["taker"],
            receipt=receipt,
            order=order,
            created_at="2026-09-01T00:02:00Z",
            not_after="2026-09-01T00:12:00Z",
            now=_utc("2026-09-01T00:02:00Z"),
        )


def test_execution_receipt_delivery_rejects_wrong_target_and_stale_window(
    tmp_path,
):
    context = _setup(tmp_path)
    order = _order(context)
    delivery = _execution_receipt_delivery(context, order)

    ok, reason = verify_trade_execution_receipt_delivery(
        delivery,
        order=order,
        recipient_did=context["maker"].as_did(),
        at=_utc("2026-09-01T00:03:00Z"),
    )
    assert ok is False
    assert "recipient" in reason

    ok, reason = verify_trade_execution_receipt_delivery(
        delivery,
        order=order,
        recipient_did=context["taker"].as_did(),
        at=_utc("2026-09-01T00:17:01Z"),
    )
    assert ok is False
    assert "expired" in reason


def test_execution_receipt_acknowledgement_rejects_tampered_binding(
    tmp_path,
):
    context = _setup(tmp_path)
    order = _order(context)
    delivery = _execution_receipt_delivery(context, order)
    acknowledgement = create_trade_execution_receipt_acknowledgement(
        context["taker"],
        delivery=delivery,
        order=order,
        received_at="2026-09-01T00:03:00Z",
        audit_event_id="3" * 64,
    )
    tampered = acknowledgement.to_dict()
    tampered["audit_event_id"] = "4" * 64

    with pytest.raises(
        TradeExecutionReceiptAcknowledgementRejected,
        match="signature invalid",
    ):
        TradeExecutionReceiptAcknowledgement.from_dict(tampered)

    ok, reason = verify_trade_execution_receipt_acknowledgement(
        acknowledgement,
        delivery=delivery,
        order=order,
        receiver_did=context["taker"].as_did(),
        audit_event_id="4" * 64,
    )
    assert ok is False
    assert "audit_event_id" in reason


def _execution_receipt_intake(
    tmp_path,
    context,
    *,
    verifier_policy=None,
    content_resolver=None,
):
    store = TradeExecutionReceiptStore(tmp_path)
    outbox = TradeExecutionAuditOutbox(tmp_path)
    spine = SignedEventLog(
        tmp_path / "receipt-intake-spine.jsonl",
        context["taker"],
    )
    coordinator = TradeExecutionCoordinator(store, outbox, spine)
    intake = TradeExecutionReceiptIntakeCoordinator(
        coordinator,
        receiver_identity=context["taker"],
        package_resolver=context["package_store"],
        verifier_policy=verifier_policy or context["taker_policy"],
        adapter_resolver=context["adapter_resolver"],
        adapter_policy=context["adapter_policy"],
        content_resolver=content_resolver or context["content_resolver"],
        schema_validator=context["schema_validator"],
    )
    return store, outbox, spine, intake


def test_execution_receipt_intake_reverifies_then_records_and_acks(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    delivery = _execution_receipt_delivery(context, order, receipt)
    store, outbox, spine, intake = _execution_receipt_intake(
        tmp_path / "receiver",
        context,
    )

    first = intake.receive(
        delivery,
        order=order,
        at=_utc("2026-09-01T00:03:00Z"),
    )
    retry = intake.receive(
        delivery.to_dict(),
        order=order.to_dict(),
        at=_utc("2026-09-01T00:03:00Z"),
    )

    assert first.audit.receipt == receipt
    assert first.audit.prepared_created is True
    assert retry.audit.prepared_created is False
    assert retry.acknowledgement == first.acknowledgement
    assert store.get(receipt.execution_id, order=order) == receipt
    assert outbox.get(receipt.execution_id).status == "anchored"
    assert len(list(spine.read_all())) == 1
    assert verify_trade_execution_receipt_acknowledgement(
        first.acknowledgement,
        delivery=delivery,
        order=order,
        receiver_did=context["taker"].as_did(),
        audit_event_id=first.audit.record.event_id,
    ) == (True, "ok")


def test_execution_receipt_intake_policy_failure_has_no_durable_success(
    tmp_path,
):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    delivery = _execution_receipt_delivery(context, order, receipt)
    store, outbox, spine, intake = _execution_receipt_intake(
        tmp_path / "receiver",
        context,
        verifier_policy=RuleResolutionPolicy(),
    )

    with pytest.raises(
        TradeExecutionReceiptRejected,
        match="not accepted",
    ):
        intake.receive(
            delivery,
            order=order,
            at=_utc("2026-09-01T00:03:00Z"),
        )

    assert store.get(receipt.execution_id, order=order) is None
    assert outbox.get(receipt.execution_id) is None
    assert list(spine.read_all()) == []


def _execution_dispatch_artifacts(tmp_path):
    context = _setup(tmp_path / "setup")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    delivery = _execution_receipt_delivery(context, order, receipt)
    receiver_store, _outbox, _receiver_spine, intake = (
        _execution_receipt_intake(
            tmp_path / "receiver",
            context,
        )
    )
    intake_result = intake.receive(
        delivery,
        order=order,
        at=_utc("2026-09-01T00:03:00Z"),
    )
    assert receiver_store.get(receipt.execution_id, order=order) == receipt
    return context, order, delivery, intake_result


def test_execution_dispatch_store_persists_pending_and_failures(tmp_path):
    _context, order, delivery, _intake_result = (
        _execution_dispatch_artifacts(tmp_path)
    )
    store = TradeExecutionReceiptDispatchStore(tmp_path / "sender")
    receipt_digest = delivery.to_dict()["receipt_digest"]

    first = store.prepare(
        delivery,
        order=order,
        target_url="HTTPS://Peer.Example:443/base/",
        now_ms=1_000,
    )
    retry = store.prepare(
        delivery,
        order=order,
        target_url="https://peer.example:443/base",
        now_ms=2_000,
    )
    failed = store.note_failure(
        receipt_digest,
        error="network\nfailed",
        now_ms=3_000,
    )
    restarted = TradeExecutionReceiptDispatchStore(tmp_path / "sender")

    assert first == retry
    assert first.acknowledged is False
    assert failed.attempts == 1
    assert failed.last_error == "network failed"
    assert restarted.get_pending(receipt_digest) == failed
    with pytest.raises(
        TradeExecutionReceiptDispatchError,
        match="conflicts",
    ):
        restarted.prepare(
            delivery,
            order=order,
            target_url="https://different.example",
        )


def test_execution_dispatch_prepare_is_concurrently_idempotent(tmp_path):
    context, order, delivery, intake_result = (
        _execution_dispatch_artifacts(tmp_path)
    )
    store = TradeExecutionReceiptDispatchStore(tmp_path / "sender")
    deliveries = tuple(
        create_trade_execution_receipt_delivery(
            context["maker"],
            receipt=delivery.receipt,
            order=order,
            created_at="2026-09-01T00:02:00Z",
            not_after="2026-09-01T00:12:00Z",
            nonce=f"{index + 1:032x}",
            now=_utc("2026-09-01T00:02:00Z"),
        )
        for index in range(16)
    )

    def prepare(index):
        return store.prepare(
            deliveries[index],
            order=order,
            target_url="https://peer.example",
            now_ms=1_000,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        records = list(pool.map(prepare, range(16)))

    assert len(set(records)) == 1
    receipt_digest = delivery.to_dict()["receipt_digest"]
    assert store.get_states((receipt_digest,)) == {
        receipt_digest: (records[0], None)
    }


def test_execution_dispatch_writes_do_not_depend_on_post_commit_reads(
    tmp_path,
    monkeypatch,
):
    context, order, delivery, intake_result = (
        _execution_dispatch_artifacts(tmp_path)
    )
    store = TradeExecutionReceiptDispatchStore(tmp_path / "sender")
    monkeypatch.setattr(
        store,
        "get_pending",
        lambda _digest: (_ for _ in ()).throw(
            AssertionError("post-commit pending read is forbidden")
        ),
    )
    prepared = store.prepare(
        delivery,
        order=order,
        target_url="https://peer.example",
        now_ms=int(_utc("2026-09-01T00:03:00Z").timestamp() * 1_000),
    )
    failed = store.note_failure(
        delivery.to_dict()["receipt_digest"],
        error="network failed",
        now_ms=int(_utc("2026-09-01T00:04:00Z").timestamp() * 1_000),
    )
    replacement = create_trade_execution_receipt_delivery(
        context["maker"],
        receipt=delivery.receipt,
        order=order,
        created_at="2026-09-01T00:18:00Z",
        not_after="2026-09-01T00:28:00Z",
        nonce="c1" * 16,
        now=_utc("2026-09-01T00:18:00Z"),
    )
    renewed = store.renew_expired(
        replacement,
        order=order,
        target_url="https://peer.example",
        now_ms=int(_utc("2026-09-01T00:18:00Z").timestamp() * 1_000),
    )

    assert prepared.generation == 1
    assert failed.attempts == 1
    assert renewed.generation == 2
    assert renewed.delivery == replacement

    ack_store = TradeExecutionReceiptDispatchStore(tmp_path / "ack-sender")
    ack_store.prepare(
        delivery,
        order=order,
        target_url="https://peer.example",
        now_ms=int(_utc("2026-09-01T00:03:00Z").timestamp() * 1_000),
    )
    monkeypatch.setattr(
        ack_store,
        "get_acknowledgement",
        lambda _digest: (_ for _ in ()).throw(
            AssertionError("post-commit acknowledgement read is forbidden")
        ),
    )
    retained_ack = ack_store.put_acknowledgement(
        delivery,
        intake_result.acknowledgement,
        order=order,
        target_url="https://peer.example",
        remote_event_id=intake_result.audit.record.event_id,
        observed_at_ms=int(
            _utc("2026-09-01T00:03:01Z").timestamp() * 1_000
        ),
    )
    assert retained_ack.receipt_digest == delivery.to_dict()["receipt_digest"]


def test_execution_dispatch_renews_only_expired_matching_delivery(tmp_path):
    context, order, delivery, _intake_result = (
        _execution_dispatch_artifacts(tmp_path)
    )
    store = TradeExecutionReceiptDispatchStore(tmp_path / "sender")
    target = "https://peer.example"
    receipt_digest = delivery.to_dict()["receipt_digest"]
    store.prepare(
        delivery,
        order=order,
        target_url=target,
        now_ms=int(_utc("2026-09-01T00:03:00Z").timestamp() * 1_000),
    )
    early_replacement = create_trade_execution_receipt_delivery(
        context["maker"],
        receipt=delivery.receipt,
        order=order,
        created_at="2026-09-01T00:10:00Z",
        not_after="2026-09-01T00:20:00Z",
        nonce="b1" * 16,
        now=_utc("2026-09-01T00:10:00Z"),
    )
    replacement = create_trade_execution_receipt_delivery(
        context["maker"],
        receipt=delivery.receipt,
        order=order,
        created_at="2026-09-01T00:18:00Z",
        not_after="2026-09-01T00:28:00Z",
        nonce="b2" * 16,
        now=_utc("2026-09-01T00:18:00Z"),
    )

    with pytest.raises(
        TradeExecutionReceiptDispatchError,
        match="not expired",
    ):
        store.renew_expired(
            early_replacement,
            order=order,
            target_url=target,
            now_ms=int(
                _utc("2026-09-01T00:10:00Z").timestamp() * 1_000
            ),
        )

    renewed = store.renew_expired(
        replacement,
        order=order,
        target_url=target,
        now_ms=int(_utc("2026-09-01T00:18:00Z").timestamp() * 1_000),
    )

    assert renewed.receipt_digest == receipt_digest
    assert renewed.delivery == replacement
    assert renewed.generation == 2
    assert renewed.superseded_delivery_digests == (
        trade_execution_receipt_delivery_digest(
            delivery,
            order=order,
        ),
    )
    assert renewed.attempts == 0


def test_execution_dispatch_usage_counts_generation_history(tmp_path):
    context, order, delivery, _intake_result = (
        _execution_dispatch_artifacts(tmp_path)
    )
    store = TradeExecutionReceiptDispatchStore(tmp_path / "sender")
    store.prepare(
        delivery,
        order=order,
        target_url="https://peer.example",
        now_ms=int(_utc("2026-09-01T00:03:00Z").timestamp() * 1_000),
    )
    replacement = create_trade_execution_receipt_delivery(
        context["maker"],
        receipt=delivery.receipt,
        order=order,
        created_at="2026-09-01T00:18:00Z",
        not_after="2026-09-01T00:28:00Z",
        nonce="b3" * 16,
        now=_utc("2026-09-01T00:18:00Z"),
    )
    renewed = store.renew_expired(
        replacement,
        order=order,
        target_url="https://peer.example",
        now_ms=int(_utc("2026-09-01T00:18:00Z").timestamp() * 1_000),
    )
    history_bytes = json.dumps(
        list(renewed.superseded_delivery_digests),
        separators=(",", ":"),
    ).encode("ascii")

    with store._connect() as connection:
        pending_count, acknowledgement_count, total = store._usage(
            connection
        )

    assert pending_count == 1
    assert acknowledgement_count == 0
    assert total == (
        len(renewed.delivery.canonical_bytes)
        + len(renewed.order.canonical_bytes)
        + len(history_bytes)
    )


def test_execution_dispatch_prepare_reserves_empty_history_bytes(tmp_path):
    _context, order, delivery, _intake_result = (
        _execution_dispatch_artifacts(tmp_path)
    )
    max_without_history = (
        len(delivery.canonical_bytes) + len(order.canonical_bytes)
    )
    store = TradeExecutionReceiptDispatchStore(
        tmp_path / "constrained",
        max_bytes=max_without_history + 1,
    )

    with pytest.raises(
        TradeExecutionReceiptDispatchCapacity,
        match="max_bytes",
    ):
        store.prepare(
            delivery,
            order=order,
            target_url="https://peer.example",
            now_ms=int(
                _utc("2026-09-01T00:03:00Z").timestamp() * 1_000
            ),
        )

    assert store.get_pending(delivery.to_dict()["receipt_digest"]) is None


def test_execution_dispatch_renewal_enforces_projected_bytes(tmp_path):
    context, order, delivery, _intake_result = (
        _execution_dispatch_artifacts(tmp_path)
    )
    root = tmp_path / "sender"
    initial = TradeExecutionReceiptDispatchStore(root)
    retained = initial.prepare(
        delivery,
        order=order,
        target_url="https://peer.example",
        now_ms=int(_utc("2026-09-01T00:03:00Z").timestamp() * 1_000),
    )
    replacement = create_trade_execution_receipt_delivery(
        context["maker"],
        receipt=delivery.receipt,
        order=order,
        created_at="2026-09-01T00:18:00Z",
        not_after="2026-09-01T00:28:00Z",
        nonce="b4" * 16,
        now=_utc("2026-09-01T00:18:00Z"),
    )
    old_digest = trade_execution_receipt_delivery_digest(
        delivery,
        order=order,
    )
    next_history = json.dumps([old_digest], separators=(",", ":")).encode(
        "ascii"
    )
    projected_bytes = (
        len(replacement.canonical_bytes)
        + len(order.canonical_bytes)
        + len(next_history)
    )
    constrained = TradeExecutionReceiptDispatchStore(
        root,
        max_bytes=projected_bytes - 1,
    )

    with pytest.raises(
        TradeExecutionReceiptDispatchCapacity,
        match="max_bytes",
    ):
        constrained.renew_expired(
            replacement,
            order=order,
            target_url="https://peer.example",
            now_ms=int(
                _utc("2026-09-01T00:18:00Z").timestamp() * 1_000
            ),
        )

    assert constrained.get_pending(retained.receipt_digest) == retained


def test_execution_dispatch_ack_preserves_signed_renewal_history(tmp_path):
    context, order, delivery, intake_result = (
        _execution_dispatch_artifacts(tmp_path)
    )
    root = tmp_path / "sender"
    store = TradeExecutionReceiptDispatchStore(root)
    target = "https://peer.example"
    receipt_digest = delivery.to_dict()["receipt_digest"]
    store.prepare(
        delivery,
        order=order,
        target_url=target,
        now_ms=int(_utc("2026-09-01T00:03:00Z").timestamp() * 1_000),
    )
    replacement = create_trade_execution_receipt_delivery(
        context["maker"],
        receipt=delivery.receipt,
        order=order,
        created_at="2026-09-01T00:18:00Z",
        not_after="2026-09-01T00:28:00Z",
        nonce="e1" * 16,
        now=_utc("2026-09-01T00:18:00Z"),
    )
    store.renew_expired(
        replacement,
        order=order,
        target_url=target,
        now_ms=int(_utc("2026-09-01T00:18:00Z").timestamp() * 1_000),
    )
    acknowledgement = create_trade_execution_receipt_acknowledgement(
        context["taker"],
        delivery=replacement,
        order=order,
        received_at="2026-09-01T00:19:00Z",
        audit_event_id=intake_result.audit.record.event_id,
    )
    spine = SignedEventLog(root / "sender-spine.jsonl", context["maker"])
    coordinator = TradeExecutionReceiptDispatchCoordinator(store, spine)

    retained = coordinator.acknowledge(
        replacement,
        acknowledgement,
        order=order,
        target_url=target,
        remote_event_id=intake_result.audit.record.event_id,
        observed_at_ms=int(
            _utc("2026-09-01T00:19:00Z").timestamp() * 1_000
        ),
    )

    assert retained.generation == 2
    assert retained.superseded_delivery_digests == (
        trade_execution_receipt_delivery_digest(delivery, order=order),
    )
    assert store.get_pending(receipt_digest) is None
    assert store.get_acknowledgement(receipt_digest) == retained
    event = list(spine.read_all())[-1]
    assert event.payload["generation"] == 2
    assert event.payload["superseded_delivery_digests"] == list(
        retained.superseded_delivery_digests
    )


def test_execution_dispatch_migrates_ack_generation_history_columns(tmp_path):
    root = tmp_path / "sender"
    database = root / "trade" / "execution_dispatch_v1" / "dispatch.sqlite3"
    database.parent.mkdir(parents=True)
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TABLE acknowledgements (
                receipt_digest TEXT PRIMARY KEY,
                order_digest TEXT NOT NULL,
                target_url TEXT NOT NULL,
                delivery_bytes BLOB NOT NULL,
                order_bytes BLOB NOT NULL,
                acknowledgement_bytes BLOB NOT NULL,
                remote_event_id TEXT NOT NULL,
                observed_at_ms INTEGER NOT NULL
            )
            """
        )

    TradeExecutionReceiptDispatchStore(root)

    with sqlite3.connect(database) as connection:
        columns = {
            row[1] for row in connection.execute(
                "PRAGMA table_info(acknowledgements)"
            )
        }
    assert {"generation", "superseded_delivery_digests"} <= columns


def test_execution_dispatch_ack_is_durable_before_anchor_and_recovers(
    tmp_path,
):
    context, order, delivery, intake_result = (
        _execution_dispatch_artifacts(tmp_path)
    )
    root = tmp_path / "sender"
    store = TradeExecutionReceiptDispatchStore(root)
    receipt_digest = delivery.to_dict()["receipt_digest"]
    store.prepare(
        delivery,
        order=order,
        target_url="https://peer.example",
        now_ms=1_000,
    )
    retained = store.put_acknowledgement(
        delivery,
        intake_result.acknowledgement,
        order=order,
        target_url="https://peer.example",
        remote_event_id=intake_result.audit.record.event_id,
        observed_at_ms=int(
            _utc("2026-09-01T00:03:01Z").timestamp() * 1_000
        ),
    )

    assert store.get_pending(receipt_digest) is not None
    assert store.get_acknowledgement(receipt_digest) == retained
    assert store.get_states((receipt_digest, receipt_digest)) == {
        receipt_digest: (store.get_pending(receipt_digest), retained)
    }
    spine = SignedEventLog(root / "sender-spine.jsonl", context["maker"])
    restarted = TradeExecutionReceiptDispatchCoordinator(
        TradeExecutionReceiptDispatchStore(root),
        spine,
    )
    recovered = restarted.recover_acknowledgement(receipt_digest)

    assert recovered == retained
    assert restarted.store.get_pending(receipt_digest) is None
    events = list(spine.read_all())
    assert len(events) == 1
    assert events[0].type == EVENT_TRADE_EXECUTION_RECEIPT_ACKNOWLEDGED
    assert events[0].payload == (
        execution_receipt_acknowledgement_audit_payload(retained)
    )
    duplicate_envelope = create_trade_execution_receipt_delivery(
        context["maker"],
        receipt=delivery.receipt,
        order=order,
        created_at="2026-09-01T00:04:00Z",
        not_after="2026-09-01T00:14:00Z",
        nonce="d1" * 16,
        now=_utc("2026-09-01T00:04:00Z"),
    )
    already_done = restarted.prepare(
        duplicate_envelope,
        order=order,
        target_url="https://peer.example",
    )
    assert already_done.acknowledged is True
    assert already_done.delivery == delivery


def test_execution_dispatch_does_not_misreport_storage_failure_as_busy(
    tmp_path,
    monkeypatch,
):
    store = TradeExecutionReceiptDispatchStore(tmp_path / "sender")

    def fail_connect():
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(store, "_connect", fail_connect)
    with pytest.raises(TradeExecutionReceiptDispatchError) as caught:
        store.get_states(("sha256:" + "1" * 64,))

    assert not isinstance(caught.value, TradeExecutionReceiptDispatchBusy)
    assert str(caught.value) == "unable to read dispatch states"


def test_execution_dispatch_recovery_ignores_completed_ack_history(tmp_path):
    artifacts = (
        _execution_dispatch_artifacts(tmp_path / "first"),
        _execution_dispatch_artifacts(tmp_path / "second"),
    )
    root = tmp_path / "sender"
    store = TradeExecutionReceiptDispatchStore(root)
    retained = []
    for _context, order, delivery, intake_result in artifacts:
        store.prepare(
            delivery,
            order=order,
            target_url="https://peer.example",
            now_ms=1_000,
        )
        retained.append(store.put_acknowledgement(
            delivery,
            intake_result.acknowledgement,
            order=order,
            target_url="https://peer.example",
            remote_event_id=intake_result.audit.record.event_id,
            observed_at_ms=int(
                _utc("2026-09-01T00:03:01Z").timestamp() * 1_000
            ),
        ))

    retained.sort(key=lambda item: item.receipt_digest)
    completed, recoverable = retained
    assert store.complete_pending(completed.receipt_digest) is True
    assert store.get_pending(recoverable.receipt_digest) is not None
    coordinator = TradeExecutionReceiptDispatchCoordinator(
        store,
        SignedEventLog(
            root / "sender-spine.jsonl",
            artifacts[0][0]["maker"],
        ),
    )

    report = coordinator.reconcile(limit=1)

    assert report.scanned == 1
    assert report.completed == 1
    assert report.has_more is False
    assert store.get_pending(recoverable.receipt_digest) is None


def test_execution_dispatch_coordinator_acknowledges_once(tmp_path):
    context, order, delivery, intake_result = (
        _execution_dispatch_artifacts(tmp_path)
    )
    root = tmp_path / "sender"
    store = TradeExecutionReceiptDispatchStore(root)
    spine = SignedEventLog(root / "sender-spine.jsonl", context["maker"])
    coordinator = TradeExecutionReceiptDispatchCoordinator(store, spine)
    receipt_digest = delivery.to_dict()["receipt_digest"]
    coordinator.prepare(
        delivery,
        order=order,
        target_url="https://peer.example",
        now_ms=1_000,
    )

    first = coordinator.acknowledge(
        delivery,
        intake_result.acknowledgement,
        order=order,
        target_url="https://peer.example",
        remote_event_id=intake_result.audit.record.event_id,
        observed_at_ms=int(
            _utc("2026-09-01T00:03:01Z").timestamp() * 1_000
        ),
    )
    retry = coordinator.acknowledge(
        delivery,
        intake_result.acknowledgement,
        order=order,
        target_url="https://peer.example",
        remote_event_id=intake_result.audit.record.event_id,
        observed_at_ms=int(
            _utc("2026-09-01T00:03:01Z").timestamp() * 1_000
        ),
    )

    assert retry == first
    assert store.get_pending(receipt_digest) is None
    assert len(list(spine.read_all())) == 1


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
    return (
        store,
        outbox,
        spine,
        TradeExecutionCoordinator(
            store,
            outbox,
            spine,
        ),
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


def test_execution_coordinator_records_remote_signed_receipt_once(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    store = TradeExecutionReceiptStore(tmp_path)
    outbox = TradeExecutionAuditOutbox(tmp_path)
    spine = SignedEventLog(
        tmp_path / "receiver-spine.jsonl",
        context["taker"],
    )
    coordinator = TradeExecutionCoordinator(store, outbox, spine)
    now_ms = int(_utc("2026-09-01T00:02:00Z").timestamp() * 1000)

    first = coordinator.record(receipt, order=order, now_ms=now_ms)
    second = coordinator.record(
        receipt.to_dict(),
        order=order.to_dict(),
        now_ms=now_ms,
    )

    assert first.receipt == receipt
    assert first.prepared_created is True
    assert first.store_created is True
    assert first.anchor_created is True
    assert second.receipt == receipt
    assert second.prepared_created is False
    assert second.store_created is False
    assert second.anchor_created is False
    assert store.get(receipt.execution_id, order=order) == receipt
    assert len(list(spine.read_all())) == 1


def test_execution_coordinator_record_rejects_invalid_signed_binding(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    document = receipt.to_dict()
    document["outcome"] = "failed"
    store, outbox, spine, coordinator = _execution_audit_components(
        tmp_path,
        context,
    )

    with pytest.raises(
        TradeExecutionReceiptRejected,
        match="signature invalid",
    ):
        coordinator.record(document, order=order)

    assert store.get(receipt.execution_id, order=order) is None
    assert outbox.get(receipt.execution_id) is None
    assert list(spine.read_all()) == []


def test_execution_coordinator_record_retains_remote_equivocation(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    succeeded = _execution_receipt(context, order)
    failed = _execution_receipt(
        context,
        order,
        outcome="failed",
        result_payload=b'{"error":"remote contradiction"}',
        result={
            "media_type": "application/problem+json",
            "digest": _digest(b'{"error":"remote contradiction"}'),
            "size_bytes": len(b'{"error":"remote contradiction"}'),
        },
    )
    store, outbox, _spine, coordinator = _execution_audit_components(
        tmp_path,
        context,
    )
    now_ms = int(_utc("2026-09-01T00:02:00Z").timestamp() * 1000)

    coordinator.record(succeeded, order=order, now_ms=now_ms)
    with pytest.raises(TradeExecutionReceiptConflict):
        coordinator.record(failed, order=order, now_ms=now_ms)

    status = store.conflict_status(succeeded.execution_id, order=order)
    assert status.has_conflict is True
    assert execution_receipt_digest(
        failed,
        order=order,
    ) in status.retained_receipt_digests
    assert outbox.get(succeeded.execution_id).status == "blocked"


def test_execution_coordinator_history_reverifies_receipt_and_spine(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    _store, _outbox, _spine, coordinator = _execution_audit_components(
        tmp_path,
        context,
    )
    receipt = _execution_receipt(context, order, coordinator=coordinator)

    history = coordinator.history(order)

    assert history.has_more is False
    assert len(history.items) == 1
    assert history.items[0].receipt == receipt
    assert history.items[0].event.payload == execution_audit_payload(
        receipt,
        order=order,
    )
    with pytest.raises(ValueError, match="limit must be in 1..500"):
        coordinator.history(order, limit=0)


def test_execution_history_uses_stable_spine_cursor_and_verified_cache(
    tmp_path,
    monkeypatch,
):
    context = _setup(tmp_path)
    operation_ids = [f"deliver-service-page-{index}" for index in range(3)]
    grants = [{
        "operation_id": operation_id,
        "rule_id": "org.nthdao.test.delivery",
        "package_digest": context["package_digest"],
        "hook_name": "fulfillment.deliver",
        "hook_version": "1",
        "executor_role": "maker",
    } for operation_id in operation_ids]
    proposal = _proposal(context, grants=grants)
    order = create_trade_order(
        offer=context["offer"],
        proposal=proposal,
        acceptance=_acceptance(context, proposal),
    )
    _store, _outbox, spine, coordinator = _execution_audit_components(
        tmp_path,
        context,
    )
    for operation_id in operation_ids:
        _execution_receipt(
            context,
            order,
            coordinator=coordinator,
            operation_id=operation_id,
        )
    original = spine.verified_snapshot_with_token
    snapshot_calls = 0

    def counted_snapshot():
        nonlocal snapshot_calls
        snapshot_calls += 1
        return original()

    monkeypatch.setattr(spine, "verified_snapshot_with_token", counted_snapshot)

    newest = coordinator.history(order, limit=2)
    repeated = coordinator.history(order, limit=2)
    older = coordinator.history(
        order,
        limit=2,
        before_seq=newest.next_cursor,
    )

    assert newest.has_more is True
    assert newest.next_cursor is not None
    assert [item.event.seq for item in newest.items] == [1, 2]
    assert repeated.items == newest.items
    assert older.has_more is False
    assert older.next_cursor is None
    assert [item.event.seq for item in older.items] == [0]
    assert snapshot_calls == 1
    with pytest.raises(ValueError, match="before_seq"):
        coordinator.history(order, before_seq=True)


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
    record_size = (
        next((measure_root / "trade" / "execution_audit_outbox_v1").glob("*.json"))
        .stat()
        .st_size
    )
    byte_root = tmp_path / "byte-cap" / "trade" / ("execution_audit_outbox_v1")
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


def test_execution_audit_pending_recovery_skips_terminal_prefix(tmp_path):
    context = _setup(tmp_path)
    _, outbox, _spine, coordinator = _execution_audit_components(
        tmp_path,
        context,
    )
    for index in range(3):
        operation_id = f"deliver-service-anchored-{index}"
        _execution_receipt(
            context,
            _order_for_operation(context, operation_id),
            coordinator=coordinator,
            operation_id=operation_id,
        )
    pending_order = _order_for_operation(context, "deliver-service-pending")
    pending_receipt = _execution_receipt(
        context,
        pending_order,
        operation_id="deliver-service-pending",
    )
    outbox.prepare(
        pending_receipt,
        order=pending_order,
        now_ms=int(_utc("2026-09-01T00:02:00Z").timestamp() * 1000),
    )

    recovered = coordinator.reconcile(limit=1, pending_only=True)
    empty = coordinator.reconcile(limit=1, pending_only=True)

    assert recovered.scanned == 1
    assert recovered.anchored == 1
    assert recovered.has_more is False
    assert empty.scanned == 0
    assert empty.has_more is False


def test_execution_runtime_recovery_advances_cursor_until_healthy(tmp_path):
    from types import SimpleNamespace

    from nth_dao.web import _advance_trade_execution_recovery

    context = _setup(tmp_path)
    _, outbox, _spine, coordinator = _execution_audit_components(
        tmp_path,
        context,
    )
    for index in range(3):
        operation_id = f"deliver-service-pending-{index}"
        order = _order_for_operation(context, operation_id)
        receipt = _execution_receipt(
            context,
            order,
            operation_id=operation_id,
        )
        outbox.prepare(
            receipt,
            order=order,
            now_ms=int(_utc("2026-09-01T00:02:00Z").timestamp() * 1000),
        )
    state = SimpleNamespace(
        trade_execution_coordinator=coordinator,
        trade_execution_health_lock=threading.RLock(),
        trade_execution_recovery_lock=threading.Lock(),
        trade_execution_recovery_cursor=None,
        trade_execution_recovery_failures=0,
        trade_execution_health=TradeExecutionRuntimeHealth(
            status="unavailable",
            receipt_persistence_available=False,
            error_code="coordinator-not-initialized",
        ),
    )

    reports = [
        _advance_trade_execution_recovery(state, limit=1)
        for _ in range(3)
    ]

    assert [report.scanned for report in reports] == [1, 1, 1]
    assert [report.has_more for report in reports] == [True, True, False]
    assert state.trade_execution_recovery_cursor is None
    assert state.trade_execution_health.status == "healthy"
    assert state.trade_execution_health.recovery_pending is False


def test_execution_runtime_recovery_rejects_concurrent_cursor_advance():
    from types import SimpleNamespace

    from nth_dao.web import _advance_trade_execution_recovery

    entered = threading.Event()
    release = threading.Event()

    class SlowCoordinator:
        def reconcile(self, **_kwargs):
            entered.set()
            assert release.wait(timeout=5.0)
            return type("Recovery", (), {
                "scanned": 0,
                "anchored": 0,
                "blocked": 0,
                "failed": 0,
                "next_cursor": None,
                "has_more": False,
            })()

    state = SimpleNamespace(
        trade_execution_coordinator=SlowCoordinator(),
        trade_execution_health_lock=threading.RLock(),
        trade_execution_recovery_lock=threading.Lock(),
        trade_execution_recovery_cursor=None,
        trade_execution_recovery_failures=0,
        trade_execution_health=TradeExecutionRuntimeHealth(
            status="healthy",
            receipt_persistence_available=True,
        ),
    )
    with ThreadPoolExecutor(max_workers=1) as executor:
        running = executor.submit(_advance_trade_execution_recovery, state)
        assert entered.wait(timeout=5.0)
        with pytest.raises(TradeExecutionAuditBusy, match="already running"):
            _advance_trade_execution_recovery(state)
        release.set()
        running.result(timeout=5.0)

    assert state.trade_execution_health.status == "healthy"


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


def _disputed_receipt_review(context, order, receipt):
    return _receipt_review(
        context,
        order,
        receipt,
        decision="disputed",
        reason_codes=["result.mismatch"],
    )


def _dispute_claim(**changes):
    claim = {
        "claim_type": "receipt-result-assertion",
        "media_type": "application/json",
        "digest": "sha256:" + ("c" * 64),
        "size": 1,
        "schema_digest": None,
    }
    claim.update(changes)
    return claim


def _dispute_statement_fetch_fixture(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _disputed_receipt_review(context, order, receipt)
    rule_binding = order.to_dict()["rule_bindings"][0]
    statement = create_trade_dispute_statement(
        context["maker"],
        review=review,
        receipt=receipt,
        order=order,
        statement_type="response",
        reason_codes=["executor.contests-review"],
        claim=_dispute_claim(),
        rule_action={
            **rule_binding,
            "hook": "fulfillment.deliver",
            "hook_version": "1",
        },
        package_resolver=context["package_store"],
        created_at="2026-09-01T00:03:00Z",
        now=_utc("2026-09-01T00:03:00Z"),
    )
    statement_digest = trade_dispute_statement_digest(
        statement,
        review=review,
        receipt=receipt,
        order=order,
    )
    request = create_trade_dispute_statement_fetch_request(
        context["taker"],
        review=review,
        receipt=receipt,
        order=order,
        statement_digest=statement_digest,
        responder_did=context["maker"].as_did(),
        created_at="2026-09-01T00:04:00Z",
        not_after="2026-09-01T00:09:00Z",
        nonce="cd" * 16,
        now=_utc("2026-09-01T00:04:00Z"),
    )
    response = create_trade_dispute_statement_fetch_response(
        context["maker"],
        request=request,
        statement=statement,
        review=review,
        receipt=receipt,
        order=order,
        served_at="2026-09-01T00:05:00Z",
        now=_utc("2026-09-01T00:05:00Z"),
    )
    return context, order, receipt, review, statement, request, response


def test_dispute_statement_fetch_protocol_round_trip_is_destination_bound(tmp_path):
    context, order, receipt, review, statement, request, response = (
        _dispute_statement_fetch_fixture(tmp_path)
    )

    assert TradeDisputeStatementFetchRequest.from_json(
        request.canonical_bytes,
        review=review,
        receipt=receipt,
        order=order,
    ) == request
    assert verify_trade_dispute_statement_fetch_request(
        request,
        review=review,
        receipt=receipt,
        order=order,
        responder_did=context["maker"].as_did(),
        at=_utc("2026-09-01T00:05:00Z"),
    ) == (True, "ok")
    assert trade_dispute_statement_fetch_request_digest(
        request,
        review=review,
        receipt=receipt,
        order=order,
    ).startswith("sha256:")

    parsed_response = TradeDisputeStatementFetchResponse.from_json(
        response.canonical_bytes,
        request=request,
        review=review,
        receipt=receipt,
        order=order,
    )
    assert parsed_response == response
    assert parsed_response.statement.canonical_bytes == statement.canonical_bytes
    assert verify_trade_dispute_statement_fetch_response(
        response,
        request=request,
        review=review,
        receipt=receipt,
        order=order,
        at=_utc("2026-09-01T00:05:00Z"),
    ) == (True, "ok")
    assert trade_dispute_statement_fetch_response_digest(
        response,
        request=request,
        review=review,
        receipt=receipt,
        order=order,
    ).startswith("sha256:")


def test_dispute_statement_fetch_request_rejects_outsider_and_wrong_destination(
    tmp_path,
):
    context, order, receipt, review, statement, _request, _response = (
        _dispute_statement_fetch_fixture(tmp_path)
    )
    statement_digest = trade_dispute_statement_digest(
        statement,
        review=review,
        receipt=receipt,
        order=order,
    )
    outsider = AgentIdentity.generate()
    common = {
        "review": review,
        "receipt": receipt,
        "order": order,
        "statement_digest": statement_digest,
        "created_at": "2026-09-01T00:04:00Z",
        "not_after": "2026-09-01T00:09:00Z",
        "nonce": "ef" * 16,
        "now": _utc("2026-09-01T00:04:00Z"),
    }

    with pytest.raises(
        TradeDisputeStatementFetchRequestRejected,
        match="requester_did is not a party",
    ):
        create_trade_dispute_statement_fetch_request(
            outsider,
            responder_did=context["maker"].as_did(),
            **common,
        )
    with pytest.raises(
        TradeDisputeStatementFetchRequestRejected,
        match="responder_did is not the opposing Order party",
    ):
        create_trade_dispute_statement_fetch_request(
            context["taker"],
            responder_did=outsider.as_did(),
            **common,
        )


def test_dispute_statement_fetch_rejects_signature_tamper_and_request_rebinding(
    tmp_path,
):
    context, order, receipt, review, statement, request, response = (
        _dispute_statement_fetch_fixture(tmp_path)
    )
    request_tamper = request.to_dict()
    request_tamper["proof"]["proof_value"] = (
        "B" + request_tamper["proof"]["proof_value"][1:]
    )
    assert not verify_trade_dispute_statement_fetch_request(
        request_tamper,
        review=review,
        receipt=receipt,
        order=order,
        responder_did=context["maker"].as_did(),
        at=_utc("2026-09-01T00:05:00Z"),
    )[0]

    response_tamper = response.to_dict()
    response_tamper["proof"]["proof_value"] = (
        "B" + response_tamper["proof"]["proof_value"][1:]
    )
    assert not verify_trade_dispute_statement_fetch_response(
        response_tamper,
        request=request,
        review=review,
        receipt=receipt,
        order=order,
        at=_utc("2026-09-01T00:05:00Z"),
    )[0]

    rebound_request = create_trade_dispute_statement_fetch_request(
        context["taker"],
        review=review,
        receipt=receipt,
        order=order,
        statement_digest=trade_dispute_statement_digest(
            statement,
            review=review,
            receipt=receipt,
            order=order,
        ),
        responder_did=context["maker"].as_did(),
        created_at="2026-09-01T00:04:00Z",
        not_after="2026-09-01T00:09:00Z",
        nonce="ab" * 16,
        now=_utc("2026-09-01T00:04:00Z"),
    )
    ok, reason = verify_trade_dispute_statement_fetch_response(
        response,
        request=rebound_request,
        review=review,
        receipt=receipt,
        order=order,
        at=_utc("2026-09-01T00:05:00Z"),
    )
    assert not ok
    assert "does not match request" in reason


def test_dispute_statement_fetch_response_rejects_wrong_signer_and_bad_time(tmp_path):
    context, order, receipt, review, statement, request, response = (
        _dispute_statement_fetch_fixture(tmp_path)
    )

    with pytest.raises(
        TradeDisputeStatementFetchResponseRejected,
        match="response signer does not match requested responder_did",
    ):
        create_trade_dispute_statement_fetch_response(
            context["taker"],
            request=request,
            statement=statement,
            review=review,
            receipt=receipt,
            order=order,
            served_at="2026-09-01T00:05:00Z",
            now=_utc("2026-09-01T00:05:00Z"),
        )
    with pytest.raises(
        TradeDisputeStatementFetchResponseRejected,
        match="served outside request lifetime",
    ):
        create_trade_dispute_statement_fetch_response(
            context["maker"],
            request=request,
            statement=statement,
            review=review,
            receipt=receipt,
            order=order,
            served_at="2026-08-31T23:55:00Z",
            now=_utc("2026-09-01T00:05:00Z"),
        )
    with pytest.raises(
        TradeDisputeStatementFetchResponseRejected,
        match="served too far in the future",
    ):
        create_trade_dispute_statement_fetch_response(
            context["maker"],
            request=request,
            statement=statement,
            review=review,
            receipt=receipt,
            order=order,
            served_at="2026-09-01T00:09:00Z",
            now=_utc("2026-09-01T00:03:00Z"),
        )
    ok, reason = verify_trade_dispute_statement_fetch_response(
        response,
        request=request,
        review=review,
        receipt=receipt,
        order=order,
        at=_utc("2026-09-01T00:20:00Z"),
    )
    assert not ok
    assert "outside its signed lifetime" in reason


def test_dispute_statement_fetch_bounds_shape_and_has_no_verifier_bypass(tmp_path):
    context, order, receipt, review, _statement, request, _response = (
        _dispute_statement_fetch_fixture(tmp_path)
    )
    request_signature = inspect.signature(
        verify_trade_dispute_statement_fetch_request
    )
    assert request_signature.parameters["responder_did"].default is (
        inspect.Parameter.empty
    )
    assert "verify_signature" not in inspect.signature(
        verify_trade_dispute_statement_fetch_response
    ).parameters

    unknown_request = request.to_dict()
    unknown_request["unexpected"] = True
    with pytest.raises(
        TradeDisputeStatementFetchRequestRejected,
        match="missing or unknown fields",
    ):
        TradeDisputeStatementFetchRequest.from_dict(
            unknown_request,
            review=review,
            receipt=receipt,
            order=order,
        )

    request_document = request.to_dict()
    request_arguments = {
        "review": review,
        "receipt": receipt,
        "order": order,
        "statement_digest": request_document["statement_digest"],
        "responder_did": context["maker"].as_did(),
        "created_at": "2026-09-01T00:04:00Z",
        "now": _utc("2026-09-01T00:04:00Z"),
    }
    with pytest.raises(
        TradeDisputeStatementFetchRequestRejected,
        match="nonce must be",
    ):
        create_trade_dispute_statement_fetch_request(
            context["taker"],
            not_after="2026-09-01T00:09:00Z",
            nonce="AB" * 16,
            **request_arguments,
        )
    with pytest.raises(
        TradeDisputeStatementFetchRequestRejected,
        match="lifetime exceeds max_ttl_seconds",
    ):
        create_trade_dispute_statement_fetch_request(
            context["taker"],
            not_after="2026-09-01T00:09:01Z",
            nonce="12" * 16,
            **request_arguments,
        )

    rule_binding = order.to_dict()["rule_bindings"][0]
    wrong_statement = create_trade_dispute_statement(
        context["maker"],
        review=review,
        receipt=receipt,
        order=order,
        statement_type="response",
        reason_codes=["executor.contests-review"],
        claim=_dispute_claim(digest="sha256:" + ("d" * 64)),
        rule_action={
            **rule_binding,
            "hook": "fulfillment.deliver",
            "hook_version": "1",
        },
        package_resolver=context["package_store"],
        created_at="2026-09-01T00:03:00Z",
        now=_utc("2026-09-01T00:03:00Z"),
    )
    with pytest.raises(
        TradeDisputeStatementFetchResponseRejected,
        match="does not match requested statement_digest",
    ):
        create_trade_dispute_statement_fetch_response(
            context["maker"],
            request=request,
            statement=wrong_statement,
            review=review,
            receipt=receipt,
            order=order,
            served_at="2026-09-01T00:05:00Z",
            now=_utc("2026-09-01T00:05:00Z"),
        )


def test_trade_dispute_statement_round_trip_is_deterministic(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _disputed_receipt_review(context, order, receipt)
    rule_binding = order.to_dict()["rule_bindings"][0]
    arguments = {
        "review": review,
        "receipt": receipt,
        "order": order,
        "statement_type": "response",
        "reason_codes": ["executor.contests-review"],
        "claim": _dispute_claim(),
        "rule_action": {
            **rule_binding,
            "hook": "fulfillment.deliver",
            "hook_version": "1",
        },
        "package_resolver": context["package_store"],
        "created_at": "2026-09-01T00:03:00Z",
        "now": _utc("2026-09-01T00:03:00Z"),
    }

    statement = create_trade_dispute_statement(
        context["maker"],
        **arguments,
    )
    retry = create_trade_dispute_statement(
        context["maker"],
        **arguments,
    )
    assert statement.canonical_bytes == retry.canonical_bytes
    assert statement.dispute_id == trade_dispute_id(review.review_id)
    assert statement.statement_id.startswith(
        "nth-trade-dispute-statement-sha256:"
    )
    assert verify_trade_dispute_statement(
        statement,
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=context["package_store"],
        at=_utc("2026-09-01T00:03:00Z"),
    ) == (True, "ok")
    with pytest.raises(
        TradeDisputeStatementResolutionError,
        match="package resolution failed",
    ):
        verify_trade_dispute_statement(
            statement,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=_FailingRulePackageResolver(),
            at=_utc("2026-09-01T00:03:00Z"),
        )
    assert trade_dispute_statement_digest(
        statement,
        review=review,
        receipt=receipt,
        order=order,
    ).startswith("sha256:")


def test_trade_dispute_rule_resolver_is_single_pass_and_type_strict(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _disputed_receipt_review(context, order, receipt)
    rule_binding = order.to_dict()["rule_bindings"][0]
    package = context["package_store"].load(rule_binding["digest"])
    assert package is not None
    resolver = _StaticRulePackageResolver(package)
    arguments = {
        "review": review,
        "receipt": receipt,
        "order": order,
        "statement_type": "response",
        "reason_codes": ["executor.contests-review"],
        "claim": _dispute_claim(),
        "rule_action": {
            **rule_binding,
            "hook": "fulfillment.deliver",
            "hook_version": "1",
        },
        "package_resolver": resolver,
        "created_at": "2026-09-01T00:03:00Z",
        "now": _utc("2026-09-01T00:03:00Z"),
    }

    statement = create_trade_dispute_statement(
        context["maker"],
        **arguments,
    )
    assert resolver.loads == 1

    parsed = TradeDisputeStatement.from_dict(
        statement.to_dict(),
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
    )
    assert parsed.canonical_bytes == statement.canonical_bytes
    assert resolver.loads == 2

    with pytest.raises(
        TradeDisputeStatementRejected,
        match="verified RulePackage",
    ):
        TradeDisputeStatement.from_dict(
            statement.to_dict(),
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=_DuckTypedRulePackageResolver(package),
        )


def test_trade_dispute_id_groups_signed_review_equivocation(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    first_review = _receipt_review(
        context,
        order,
        receipt,
        decision="disputed",
        reason_codes=["result.mismatch"],
    )
    second_review = _receipt_review(
        context,
        order,
        receipt,
        decision="disputed",
        reason_codes=["result.incomplete"],
    )

    first = create_trade_dispute_statement(
        context["maker"],
        review=first_review,
        receipt=receipt,
        order=order,
        statement_type="response",
        reason_codes=["executor.contests-review"],
        claim=_dispute_claim(),
        created_at="2026-09-01T00:03:00Z",
        now=_utc("2026-09-01T00:03:00Z"),
    )
    second = create_trade_dispute_statement(
        context["maker"],
        review=second_review,
        receipt=receipt,
        order=order,
        statement_type="response",
        reason_codes=["executor.contests-review"],
        claim=_dispute_claim(),
        created_at="2026-09-01T00:03:00Z",
        now=_utc("2026-09-01T00:03:00Z"),
    )

    assert first_review.review_id == second_review.review_id
    assert receipt_review_digest(first_review) != receipt_review_digest(
        second_review
    )
    assert first.dispute_id == second.dispute_id
    assert first.statement_id != second.statement_id


def test_trade_dispute_statement_rejects_wrong_author_and_review_state(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    disputed = _disputed_receipt_review(context, order, receipt)

    with pytest.raises(
        TradeDisputeStatementRejected,
        match="not an Order party",
    ):
        create_trade_dispute_statement(
            AgentIdentity.generate(label="outsider"),
            review=disputed,
            receipt=receipt,
            order=order,
            statement_type="response",
            reason_codes=["outsider.claim"],
            claim=_dispute_claim(),
            created_at="2026-09-01T00:03:00Z",
            now=_utc("2026-09-01T00:03:00Z"),
        )
    with pytest.raises(
        TradeDisputeStatementRejected,
        match="response must be signed by the Receipt executor",
    ):
        create_trade_dispute_statement(
            context["taker"],
            review=disputed,
            receipt=receipt,
            order=order,
            statement_type="response",
            reason_codes=["reviewer.self-response"],
            claim=_dispute_claim(),
            created_at="2026-09-01T00:03:00Z",
            now=_utc("2026-09-01T00:03:00Z"),
        )

    accepted = _receipt_review(context, order, receipt)
    with pytest.raises(
        TradeDisputeStatementRejected,
        match="require a disputed Receipt Review",
    ):
        create_trade_dispute_statement(
            context["maker"],
            review=accepted,
            receipt=receipt,
            order=order,
            statement_type="response",
            reason_codes=["executor.contests-review"],
            claim=_dispute_claim(),
            created_at="2026-09-01T00:03:00Z",
            now=_utc("2026-09-01T00:03:00Z"),
        )


def test_trade_dispute_statement_never_signs_before_preflight(
    tmp_path,
    monkeypatch,
):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _disputed_receipt_review(context, order, receipt)
    calls = []
    original_sign = AgentIdentity.sign

    def counted_sign(identity, payload):
        calls.append(identity.as_did())
        return original_sign(identity, payload)

    monkeypatch.setattr(AgentIdentity, "sign", counted_sign)
    arguments = {
        "review": review,
        "receipt": receipt,
        "order": order,
        "statement_type": "response",
        "reason_codes": ["executor.contests-review"],
        "claim": _dispute_claim(),
        "created_at": "2026-09-01T00:03:00Z",
        "now": _utc("2026-09-01T00:03:00Z"),
    }

    with pytest.raises(
        TradeDisputeStatementRejected,
        match="response must be signed by the Receipt executor",
    ):
        create_trade_dispute_statement(context["taker"], **arguments)
    assert calls == []

    binding = order.to_dict()["rule_bindings"][0]
    with pytest.raises(
        TradeDisputeStatementResolutionError,
        match="package resolution failed",
    ):
        create_trade_dispute_statement(
            context["maker"],
            rule_action={
                **binding,
                "hook": "fulfillment.deliver",
                "hook_version": "1",
            },
            package_resolver=_FailingRulePackageResolver(),
            **arguments,
        )
    assert calls == []

    package = context["package_store"].load(binding["digest"])
    assert package is not None
    with pytest.raises(
        TradeDisputeStatementRejected,
        match="verified RulePackage",
    ):
        create_trade_dispute_statement(
            context["maker"],
            rule_action={
                **binding,
                "hook": "fulfillment.deliver",
                "hook_version": "1",
            },
            package_resolver=_DuckTypedRulePackageResolver(package),
            **arguments,
        )
    assert calls == []

    create_trade_dispute_statement(context["maker"], **arguments)
    assert calls == [context["maker"].as_did()]


def test_trade_dispute_statement_rejects_unbound_rule_and_empty_evidence(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _disputed_receipt_review(context, order, receipt)

    with pytest.raises(
        TradeDisputeStatementRejected,
        match="outside the signed Order rule bindings",
    ):
        create_trade_dispute_statement(
            context["maker"],
            review=review,
            receipt=receipt,
            order=order,
            statement_type="response",
            reason_codes=["executor.contests-review"],
            claim=_dispute_claim(),
            rule_action={
                "rule_id": "org.example.outside/dispute",
                "digest": "sha256:" + ("f" * 64),
                "hook": "dispute.response",
                "hook_version": "1",
            },
            package_resolver=context["package_store"],
            created_at="2026-09-01T00:03:00Z",
            now=_utc("2026-09-01T00:03:00Z"),
        )
    with pytest.raises(
        TradeDisputeStatementRejected,
        match="require at least one evidence reference",
    ):
        create_trade_dispute_statement(
            context["maker"],
            review=review,
            receipt=receipt,
            order=order,
            statement_type="evidence",
            created_at="2026-09-01T00:03:00Z",
            now=_utc("2026-09-01T00:03:00Z"),
        )


def test_trade_dispute_rule_action_requires_exact_package_hook(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _disputed_receipt_review(context, order, receipt)
    binding = order.to_dict()["rule_bindings"][0]
    valid_action = {
        **binding,
        "hook": "fulfillment.deliver",
        "hook_version": "1",
    }
    arguments = {
        "review": review,
        "receipt": receipt,
        "order": order,
        "statement_type": "response",
        "reason_codes": ["executor.contests-review"],
        "claim": _dispute_claim(),
        "created_at": "2026-09-01T00:03:00Z",
        "now": _utc("2026-09-01T00:03:00Z"),
    }

    with pytest.raises(
        TradeDisputeStatementRejected,
        match="requires an exact-digest package_resolver",
    ):
        create_trade_dispute_statement(
            context["maker"],
            rule_action=valid_action,
            **arguments,
        )

    statement = create_trade_dispute_statement(
        context["maker"],
        rule_action=valid_action,
        package_resolver=context["package_store"],
        **arguments,
    )
    with pytest.raises(
        TradeDisputeStatementRejected,
        match="requires an exact-digest package_resolver",
    ):
        TradeDisputeStatement.from_dict(
            statement.to_dict(),
            review=review,
            receipt=receipt,
            order=order,
        )
    unresolved = UnresolvedTradeDisputeStatement.from_dict(
        statement.to_dict(),
        review=review,
        receipt=receipt,
        order=order,
    )
    assert not isinstance(unresolved, TradeDisputeStatement)
    assert unresolved.resolve(
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=context["package_store"],
    ) == statement
    assert verify_trade_dispute_statement(
        statement,
        review=review,
        receipt=receipt,
        order=order,
        at=_utc("2026-09-01T00:03:00Z"),
    ) == (False, "rule_action requires an exact-digest package_resolver")
    assert verify_trade_dispute_statement(
        statement,
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=context["package_store"],
        at=_utc("2026-09-01T00:03:00Z"),
    ) == (True, "ok")

    for field, invalid_value in (
        ("hook", "dispute.response"),
        ("hook_version", "2"),
    ):
        with pytest.raises(
            TradeDisputeStatementRejected,
            match="hook name/version is absent",
        ):
            create_trade_dispute_statement(
                context["maker"],
                rule_action={**valid_action, field: invalid_value},
                package_resolver=context["package_store"],
                **arguments,
            )

    dispute_statement_module._validate_rule_action({
        **binding,
        "hook": "1-fulfillment-hook",
        "hook_version": "1",
    })


def test_trade_dispute_statement_rejects_tamper_and_future_time(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _disputed_receipt_review(context, order, receipt)
    statement = create_trade_dispute_statement(
        context["maker"],
        review=review,
        receipt=receipt,
        order=order,
        statement_type="response",
        reason_codes=["executor.contests-review"],
        claim=_dispute_claim(),
        created_at="2026-09-01T00:03:00Z",
        now=_utc("2026-09-01T00:03:00Z"),
    )
    forged = statement.to_dict()
    forged["proof"]["proof_value"] = "A" * 86

    assert verify_trade_dispute_statement(
        forged,
        review=review,
        receipt=receipt,
        order=order,
    ) == (False, "signature invalid")
    with pytest.raises(
        TradeDisputeStatementRejected,
        match="too far in the future",
    ):
        create_trade_dispute_statement(
            context["maker"],
            review=review,
            receipt=receipt,
            order=order,
            statement_type="response",
            reason_codes=["executor.contests-review"],
            claim=_dispute_claim(),
            created_at="2026-09-01T00:04:00Z",
            now=_utc("2026-09-01T00:03:00Z"),
            clock_skew_seconds=0,
        )


def test_trade_dispute_statement_bounds_clock_skew(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _disputed_receipt_review(context, order, receipt)
    arguments = {
        "review": review,
        "receipt": receipt,
        "order": order,
        "statement_type": "response",
        "reason_codes": ["executor.contests-review"],
        "claim": _dispute_claim(),
        "created_at": "2026-09-01T00:03:00Z",
        "now": _utc("2026-09-01T00:03:00Z"),
    }
    statement = create_trade_dispute_statement(
        context["maker"],
        clock_skew_seconds=86_400,
        **arguments,
    )
    assert verify_trade_dispute_statement(
        statement,
        review=review,
        receipt=receipt,
        order=order,
        at=_utc("2026-09-01T00:03:00Z"),
        clock_skew_seconds=86_400,
    ) == (True, "ok")

    for invalid in (86_400.000_001, 1e300):
        assert verify_trade_dispute_statement(
            statement,
            review=review,
            receipt=receipt,
            order=order,
            at=_utc("2026-09-01T00:03:00Z"),
            clock_skew_seconds=invalid,
        ) == (
            False,
            "clock_skew_seconds must be finite and between 0 and 86400",
        )
        with pytest.raises(
            TradeDisputeStatementRejected,
            match="clock_skew_seconds must be finite and between 0 and 86400",
        ):
            create_trade_dispute_statement(
                context["maker"],
                clock_skew_seconds=invalid,
                **arguments,
            )


def test_trade_dispute_verifier_defaults_to_local_observation_time(
    tmp_path,
    monkeypatch,
):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _disputed_receipt_review(context, order, receipt)
    future = create_trade_dispute_statement(
        context["maker"],
        review=review,
        receipt=receipt,
        order=order,
        statement_type="response",
        reason_codes=["executor.contests-review"],
        claim=_dispute_claim(),
        created_at="2026-09-01T00:04:00Z",
        now=_utc("2026-09-01T00:04:00Z"),
        clock_skew_seconds=0,
    )
    real_utc_now = dispute_statement_module._utc_now
    monkeypatch.setattr(
        dispute_statement_module,
        "_utc_now",
        lambda value: (
            _utc("2026-09-01T00:03:00Z")
            if value is None
            else real_utc_now(value)
        ),
    )

    assert verify_trade_dispute_statement(
        future,
        review=review,
        receipt=receipt,
        order=order,
        clock_skew_seconds=0,
    ) == (False, "trade dispute statement is too far in the future")


def test_trade_dispute_claim_and_evidence_resource_bounds(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _disputed_receipt_review(context, order, receipt)
    arguments = {
        "review": review,
        "receipt": receipt,
        "order": order,
        "created_at": "2026-09-01T00:03:00Z",
        "now": _utc("2026-09-01T00:03:00Z"),
    }

    with pytest.raises(
        TradeDisputeStatementRejected,
        match="require a typed claim",
    ):
        create_trade_dispute_statement(
            context["maker"],
            statement_type="response",
            reason_codes=["executor.contests-review"],
            **arguments,
        )
    with pytest.raises(
        TradeDisputeStatementRejected,
        match="cannot contain a claim",
    ):
        create_trade_dispute_statement(
            context["maker"],
            statement_type="evidence",
            claim=_dispute_claim(),
            evidence=[{
                "purpose": "execution-log",
                "media_type": "text/plain",
                "digest": "sha256:" + ("1" * 64),
                "size": 1,
            }],
            **arguments,
        )
    with pytest.raises(
        TradeDisputeStatementRejected,
        match="claim.size is invalid",
    ):
        create_trade_dispute_statement(
            context["maker"],
            statement_type="response",
            reason_codes=["executor.contests-review"],
            claim=_dispute_claim(size=MAX_TRADE_DISPUTE_CONTENT_BYTES + 1),
            **arguments,
        )

    oversized_evidence = [
        {
            "purpose": f"artifact-{index}",
            "media_type": "application/octet-stream",
            "digest": "sha256:" + (f"{index + 1:x}" * 64),
            "size": MAX_TRADE_DISPUTE_CONTENT_BYTES,
        }
        for index in range(
            (MAX_TRADE_DISPUTE_TOTAL_EVIDENCE_BYTES
             // MAX_TRADE_DISPUTE_CONTENT_BYTES)
            + 1
        )
    ]
    with pytest.raises(
        TradeDisputeStatementRejected,
        match="evidence exceeds its total byte limit",
    ):
        create_trade_dispute_statement(
            context["maker"],
            statement_type="response",
            reason_codes=["executor.contests-review"],
            claim=_dispute_claim(),
            evidence=oversized_evidence,
            **arguments,
        )

    with pytest.raises(
        TradeDisputeStatementRejected,
        match="claim and evidence metadata conflict",
    ):
        create_trade_dispute_statement(
            context["maker"],
            statement_type="response",
            reason_codes=["executor.contests-review"],
            claim=_dispute_claim(),
            evidence=[{
                "purpose": "conflicting-copy",
                "media_type": "text/plain",
                "digest": _dispute_claim()["digest"],
                "size": 2,
            }],
            **arguments,
        )


def test_trade_dispute_statement_bounds_and_normalizes_evidence(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _disputed_receipt_review(context, order, receipt)
    first = {
        "purpose": "z-log",
        "media_type": "text/plain",
        "digest": "sha256:" + ("1" * 64),
        "size": 2,
    }
    second = {
        "purpose": "a-output",
        "media_type": "application/json",
        "digest": "sha256:" + ("2" * 64),
        "size": 1,
    }

    statement = create_trade_dispute_statement(
        context["maker"],
        review=review,
        receipt=receipt,
        order=order,
        statement_type="response",
        reason_codes=["executor.contests-review"],
        claim=_dispute_claim(),
        evidence=[first, second],
        created_at="2026-09-01T00:03:00Z",
        now=_utc("2026-09-01T00:03:00Z"),
    )

    assert [item["purpose"] for item in statement.to_dict()["evidence"]] == [
        "a-output",
        "z-log",
    ]
    with pytest.raises(
        TradeDisputeStatementRejected,
        match="contain no duplicate",
    ):
        create_trade_dispute_statement(
            context["maker"],
            review=review,
            receipt=receipt,
            order=order,
            statement_type="response",
            reason_codes=["executor.contests-review"],
            claim=_dispute_claim(),
            evidence=[first, first],
            created_at="2026-09-01T00:03:00Z",
            now=_utc("2026-09-01T00:03:00Z"),
        )
    with pytest.raises(
        TradeDisputeStatementRejected,
        match=r"evidence\[0\]\.size is invalid",
    ):
        create_trade_dispute_statement(
            context["maker"],
            review=review,
            receipt=receipt,
            order=order,
            statement_type="response",
            reason_codes=["executor.contests-review"],
            claim=_dispute_claim(),
            evidence=[{**first, "size": "2"}],
            created_at="2026-09-01T00:03:00Z",
            now=_utc("2026-09-01T00:03:00Z"),
        )
    with pytest.raises(
        TradeDisputeStatementRejected,
        match="evidence exceeds its item limit",
    ):
        create_trade_dispute_statement(
            context["maker"],
            review=review,
            receipt=receipt,
            order=order,
            statement_type="response",
            reason_codes=["executor.contests-review"],
            claim=_dispute_claim(),
            evidence=(first for _ in range(MAX_TRADE_DISPUTE_EVIDENCE + 1)),
            created_at="2026-09-01T00:03:00Z",
            now=_utc("2026-09-01T00:03:00Z"),
        )
    with pytest.raises(
        TradeDisputeStatementRejected,
        match="cannot declare conflicting metadata",
    ):
        create_trade_dispute_statement(
            context["maker"],
            review=review,
            receipt=receipt,
            order=order,
            statement_type="response",
            reason_codes=["executor.contests-review"],
            claim=_dispute_claim(),
            evidence=[first, {**first, "purpose": "other-log", "size": 3}],
            created_at="2026-09-01T00:03:00Z",
            now=_utc("2026-09-01T00:03:00Z"),
        )
    with pytest.raises(
        TradeDisputeStatementRejected,
        match="reason_codes must be a collection",
    ):
        create_trade_dispute_statement(
            context["maker"],
            review=review,
            receipt=receipt,
            order=order,
            statement_type="response",
            reason_codes="x",
            created_at="2026-09-01T00:03:00Z",
            now=_utc("2026-09-01T00:03:00Z"),
        )
    with pytest.raises(
        TradeDisputeStatementRejected,
        match=r"parent_statement_digests\[1\] must be",
    ):
        create_trade_dispute_statement(
            context["maker"],
            review=review,
            receipt=receipt,
            order=order,
            statement_type="response",
            parent_statement_digests=["sha256:" + ("3" * 64), 1],
            reason_codes=["executor.contests-review"],
            created_at="2026-09-01T00:03:00Z",
            now=_utc("2026-09-01T00:03:00Z"),
        )


def test_trade_dispute_evidence_and_remedy_round_trip(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _disputed_receipt_review(context, order, receipt)
    observed = _utc("2026-09-01T00:03:00Z")
    evidence_statement = create_trade_dispute_statement(
        context["taker"],
        review=review,
        receipt=receipt,
        order=order,
        statement_type="evidence",
        evidence=[{
            "purpose": "review-analysis",
            "media_type": "application/json",
            "digest": "sha256:" + ("d" * 64),
            "size": 128,
        }],
        created_at="2026-09-01T00:03:00Z",
        now=observed,
    )
    evidence_digest = trade_dispute_statement_digest(
        evidence_statement,
        review=review,
        receipt=receipt,
        order=order,
    )
    assert evidence_statement.to_dict()["author_role"] == "taker"
    assert evidence_statement.to_dict()["claim"] is None
    assert TradeDisputeStatement.from_json(
        evidence_statement.canonical_bytes,
        review=review,
        receipt=receipt,
        order=order,
    ) == evidence_statement
    assert verify_trade_dispute_statement(
        evidence_statement,
        review=review,
        receipt=receipt,
        order=order,
        at=observed,
    ) == (True, "ok")

    remedy_statement = create_trade_dispute_statement(
        context["maker"],
        review=review,
        receipt=receipt,
        order=order,
        statement_type="remedy-proposal",
        parent_statement_digests=[evidence_digest],
        reason_codes=["executor.offers-remedy"],
        claim=_dispute_claim(
            claim_type="remedy-proposal",
            digest="sha256:" + ("e" * 64),
            size=256,
        ),
        created_at="2026-09-01T00:04:00Z",
        now=_utc("2026-09-01T00:04:00Z"),
    )
    remedy_document = remedy_statement.to_dict()
    assert remedy_document["author_role"] == "maker"
    assert remedy_document["parent_statement_digests"] == [evidence_digest]
    assert remedy_document["claim"]["claim_type"] == "remedy-proposal"
    assert TradeDisputeStatement.from_json(
        remedy_statement.canonical_bytes,
        review=review,
        receipt=receipt,
        order=order,
    ) == remedy_statement
    assert verify_trade_dispute_statement(
        remedy_statement,
        review=review,
        receipt=receipt,
        order=order,
        at=_utc("2026-09-01T00:04:00Z"),
    ) == (True, "ok")


def test_trade_dispute_statement_is_public_trade_rule_api():
    assert trade_rules_api.TradeDisputeStatement is TradeDisputeStatement
    assert trade_rules_api.UnresolvedTradeDisputeStatement is (
        UnresolvedTradeDisputeStatement
    )
    assert trade_rules_api.create_trade_dispute_statement is (
        create_trade_dispute_statement
    )
    assert trade_rules_api.verify_trade_dispute_statement is (
        verify_trade_dispute_statement
    )


def test_dispute_statement_fetch_protocol_is_public_trade_rule_api():
    assert trade_rules_api.TradeDisputeStatementFetchRequest is (
        TradeDisputeStatementFetchRequest
    )
    assert trade_rules_api.TradeDisputeStatementFetchResponse is (
        TradeDisputeStatementFetchResponse
    )
    assert trade_rules_api.create_trade_dispute_statement_fetch_request is (
        create_trade_dispute_statement_fetch_request
    )
    assert trade_rules_api.create_trade_dispute_statement_fetch_response is (
        create_trade_dispute_statement_fetch_response
    )
    assert trade_rules_api.verify_trade_dispute_statement_fetch_request is (
        verify_trade_dispute_statement_fetch_request
    )
    assert trade_rules_api.verify_trade_dispute_statement_fetch_response is (
        verify_trade_dispute_statement_fetch_response
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


def _receipt_review_delivery(context, order, receipt, review=None):
    verified_review = review or _receipt_review(
        context,
        order,
        receipt,
    )
    reviewer = (
        context["maker"]
        if verified_review.to_dict()["reviewer_role"] == "maker"
        else context["taker"]
    )
    verifier_policy = (
        context["maker_policy"]
        if verified_review.to_dict()["reviewer_role"] == "maker"
        else context["taker_policy"]
    )
    return create_trade_receipt_review_delivery(
        reviewer,
        review=verified_review,
        receipt=receipt,
        order=order,
        verifier_policy=verifier_policy,
        adapter_policy=context["adapter_policy"],
        created_at="2026-09-01T00:03:00Z",
        not_after="2026-09-01T00:13:00Z",
        nonce="b2" * 16,
        now=_utc("2026-09-01T00:03:00Z"),
    )


def test_receipt_review_transport_round_trip_and_acknowledgement(tmp_path):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _receipt_review(context, order, receipt)
    delivery = _receipt_review_delivery(context, order, receipt, review)

    assert delivery.review == review
    assert TradeReceiptReviewDelivery.from_json(
        delivery.canonical_bytes,
        receipt=receipt,
        order=order,
    ) == delivery
    assert verify_trade_receipt_review_delivery(
        delivery,
        receipt=receipt,
        order=order,
        recipient_did=context["maker"].as_did(),
        at=_utc("2026-09-01T00:04:00Z"),
    ) == (True, "ok")
    assert trade_receipt_review_delivery_digest(
        delivery,
        receipt=receipt,
        order=order,
    ).startswith("sha256:")

    acknowledgement = create_trade_receipt_review_acknowledgement(
        context["maker"],
        delivery=delivery,
        receipt=receipt,
        order=order,
        received_at="2026-09-01T00:04:00Z",
        audit_event_id="5" * 64,
    )
    assert TradeReceiptReviewAcknowledgement.from_json(
        acknowledgement.canonical_bytes
    ) == acknowledgement
    assert verify_trade_receipt_review_acknowledgement(
        acknowledgement,
        delivery=delivery,
        receipt=receipt,
        order=order,
        receiver_did=context["maker"].as_did(),
        audit_event_id="5" * 64,
        at=_utc("2026-09-01T00:04:01Z"),
    ) == (True, "ok")
    assert trade_receipt_review_acknowledgement_digest(
        acknowledgement
    ).startswith("sha256:")


def test_receipt_review_acknowledgement_allows_symmetric_clock_skew(
    tmp_path,
):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    delivery = _receipt_review_delivery(context, order, receipt)
    received_at = "2026-09-01T00:02:59Z"

    acknowledgement = create_trade_receipt_review_acknowledgement(
        context["maker"],
        delivery=delivery,
        receipt=receipt,
        order=order,
        received_at=received_at,
        audit_event_id="5" * 64,
        clock_skew_seconds=2,
    )

    assert verify_trade_receipt_review_acknowledgement(
        acknowledgement,
        delivery=delivery,
        receipt=receipt,
        order=order,
        receiver_did=context["maker"].as_did(),
        audit_event_id="5" * 64,
        at=_utc(received_at),
        clock_skew_seconds=2,
    ) == (True, "ok")
    with pytest.raises(
        TradeReceiptReviewAcknowledgementRejected,
        match="within signed delivery lifetime",
    ):
        create_trade_receipt_review_acknowledgement(
            context["maker"],
            delivery=delivery,
            receipt=receipt,
            order=order,
            received_at=received_at,
            audit_event_id="5" * 64,
            clock_skew_seconds=0,
        )


def test_receipt_review_delivery_rejects_tamper_wrong_party_and_expiry(
    tmp_path,
):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _receipt_review(context, order, receipt)
    delivery = _receipt_review_delivery(context, order, receipt, review)

    with pytest.raises(
        TradeReceiptReviewDeliveryRejected,
        match="signer does not match Review signer",
    ):
        create_trade_receipt_review_delivery(
            context["maker"],
            review=review,
            receipt=receipt,
            order=order,
            verifier_policy=context["taker_policy"],
            adapter_policy=context["adapter_policy"],
            created_at="2026-09-01T00:03:00Z",
            not_after="2026-09-01T00:13:00Z",
            now=_utc("2026-09-01T00:03:00Z"),
        )

    tampered = delivery.to_dict()
    tampered["review"]["decision"] = "disputed"
    with pytest.raises(
        TradeReceiptReviewDeliveryRejected,
        match="embedded Receipt Review is invalid",
    ):
        TradeReceiptReviewDelivery.from_dict(
            tampered,
            receipt=receipt,
            order=order,
        )

    retargeted = delivery.to_dict()
    retargeted["recipient_did"] = context["taker"].as_did()
    with pytest.raises(
        TradeReceiptReviewDeliveryRejected,
        match="different principals|Receipt executor|opposing Order party",
    ):
        TradeReceiptReviewDelivery.from_dict(
            retargeted,
            receipt=receipt,
            order=order,
        )

    ok, reason = verify_trade_receipt_review_delivery(
        delivery,
        receipt=receipt,
        order=order,
        recipient_did=context["taker"].as_did(),
        at=_utc("2026-09-01T00:04:00Z"),
    )
    assert ok is False
    assert "recipient" in reason

    ok, reason = verify_trade_receipt_review_delivery(
        delivery,
        receipt=receipt,
        order=order,
        recipient_did=context["maker"].as_did(),
        at=_utc("2026-09-01T00:18:01Z"),
    )
    assert ok is False
    assert "expired" in reason


def test_receipt_review_acknowledgement_rejects_tampered_binding_and_time(
    tmp_path,
):
    context = _setup(tmp_path)
    order = _order(context)
    receipt = _execution_receipt(context, order)
    delivery = _receipt_review_delivery(context, order, receipt)
    acknowledgement = create_trade_receipt_review_acknowledgement(
        context["maker"],
        delivery=delivery,
        receipt=receipt,
        order=order,
        received_at="2026-09-01T00:04:00Z",
        audit_event_id="6" * 64,
    )

    tampered = acknowledgement.to_dict()
    tampered["review_digest"] = "sha256:" + "7" * 64
    with pytest.raises(
        TradeReceiptReviewAcknowledgementRejected,
        match="signature invalid",
    ):
        TradeReceiptReviewAcknowledgement.from_dict(tampered)

    ok, reason = verify_trade_receipt_review_acknowledgement(
        acknowledgement,
        delivery=delivery,
        receipt=receipt,
        order=order,
        receiver_did=context["maker"].as_did(),
        audit_event_id="8" * 64,
    )
    assert ok is False
    assert "audit_event_id" in reason

    ok, reason = verify_trade_receipt_review_acknowledgement(
        acknowledgement,
        delivery=delivery,
        receipt=receipt,
        order=order,
        receiver_did=context["taker"].as_did(),
        audit_event_id="6" * 64,
    )
    assert ok is False
    assert "receiver" in reason

    ok, reason = verify_trade_receipt_review_acknowledgement(
        acknowledgement,
        delivery=delivery,
        receipt=receipt,
        order=order,
        receiver_did=context["maker"].as_did(),
        audit_event_id="6" * 64,
        at=_utc("2026-09-01T00:03:00Z"),
        clock_skew_seconds=0,
    )
    assert ok is False
    assert "future" in reason


def test_receipt_review_transport_supports_reverse_executor_role(tmp_path):
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
    delivery = _receipt_review_delivery(context, order, receipt, review)

    assert delivery.to_dict()["sender_did"] == context["maker"].as_did()
    assert delivery.to_dict()["recipient_did"] == context["taker"].as_did()
    assert verify_trade_receipt_review_delivery(
        delivery,
        receipt=receipt,
        order=order,
        recipient_did=context["taker"].as_did(),
        at=_utc("2026-09-01T00:04:00Z"),
    ) == (True, "ok")


def _receipt_review_intake(tmp_path, context):
    store = TradeReceiptReviewStore(tmp_path)
    spine = SignedEventLog(
        tmp_path / "receipt-review-intake-spine.jsonl",
        context["maker"],
    )
    coordinator = TradeReceiptReviewCoordinator(store, spine)
    intake = TradeReceiptReviewIntakeCoordinator(
        coordinator,
        receiver_identity=context["maker"],
        package_resolver=context["package_store"],
        adapter_resolver=context["adapter_resolver"],
        content_resolver=context["content_resolver"],
        schema_validator=context["schema_validator"],
    )
    return store, spine, intake


def test_receipt_review_intake_reverifies_persists_and_acknowledges(
    tmp_path,
):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _receipt_review(context, order, receipt)
    delivery = _receipt_review_delivery(context, order, receipt, review)
    store, spine, intake = _receipt_review_intake(
        tmp_path / "runtime",
        context,
    )

    result = intake.receive(
        delivery,
        receipt=receipt,
        order=order,
        at=_utc("2026-09-01T00:04:00Z"),
    )
    replay = intake.receive(
        delivery,
        receipt=receipt,
        order=order,
        at=_utc("2026-09-01T00:04:01Z"),
    )

    assert result.audit.store_created is True
    assert result.audit.anchor_created is True
    assert replay.audit.store_created is False
    assert replay.audit.anchor_created is False
    assert result.audit.event == replay.audit.event
    assert result.acknowledgement == replay.acknowledgement
    assert result.acknowledgement.to_dict()["received_at"] == (
        "2026-09-01T00:04:00.000Z"
    )
    assert store.get(
        review.review_id,
        receipt=receipt,
        order=order,
    ) == review
    assert spine.verify_chain() == (True, "ok")
    assert verify_trade_receipt_review_acknowledgement(
        result.acknowledgement,
        delivery=delivery,
        receipt=receipt,
        order=order,
        receiver_did=context["maker"].as_did(),
        audit_event_id=result.audit.event.event_id,
        at=_utc("2026-09-01T00:04:01Z"),
    ) == (True, "ok")


def test_receipt_review_intake_upgrades_legacy_time_before_signing_ack(tmp_path):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _receipt_review(context, order, receipt)
    delivery = _receipt_review_delivery(context, order, receipt, review)
    runtime = tmp_path / "runtime"
    outbox = trade_rules_api.TradeReceiptReviewOutbox(runtime)
    legacy, _created = outbox.prepare_legacy(
        review,
        receipt=receipt,
        order=order,
        now_ms=int(_utc("2026-09-01T00:05:00Z").timestamp() * 1_000),
    )
    _store, _spine, intake = _receipt_review_intake(runtime, context)

    result = intake.receive(
        delivery,
        receipt=receipt,
        order=order,
        at=_utc("2026-09-01T00:04:00Z"),
    )
    replay = intake.receive(
        delivery,
        receipt=receipt,
        order=order,
        at=_utc("2026-09-01T00:04:01Z"),
    )

    assert legacy.protocol_version == "1"
    assert result.acknowledgement == replay.acknowledgement
    assert result.acknowledgement.to_dict()["received_at"] == (
        "2026-09-01T00:04:00.000Z"
    )
    assert outbox.get_policy_snapshots(legacy.review_digest) is not None


def test_receipt_review_intake_rejects_wrong_node_before_retention(tmp_path):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    delivery = _receipt_review_delivery(context, order, receipt)
    store = TradeReceiptReviewStore(tmp_path / "runtime")
    spine = SignedEventLog(
        tmp_path / "runtime" / "receipt-review-intake-spine.jsonl",
        context["taker"],
    )
    intake = TradeReceiptReviewIntakeCoordinator(
        TradeReceiptReviewCoordinator(store, spine),
        receiver_identity=context["taker"],
        package_resolver=context["package_store"],
        adapter_resolver=context["adapter_resolver"],
        content_resolver=context["content_resolver"],
        schema_validator=context["schema_validator"],
    )

    with pytest.raises(
        TradeReceiptReviewDeliveryRejected,
        match="recipient",
    ):
        intake.receive(
            delivery,
            receipt=receipt,
            order=order,
            at=_utc("2026-09-01T00:04:00Z"),
        )
    assert not store.root.exists()
    assert spine.verified_snapshot() == ()


def test_receipt_review_delivery_rejects_policy_outside_order_snapshot(
    tmp_path,
):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    mismatched_policy = replace(
        context["taker_policy"],
        max_depth=context["taker_policy"].max_depth + 1,
    )
    review = _receipt_review(
        context,
        order,
        receipt,
        verifier_policy=mismatched_policy,
    )

    with pytest.raises(
        TradeReceiptReviewDeliveryRejected,
        match="reviewer Order snapshot",
    ):
        create_trade_receipt_review_delivery(
            context["taker"],
            review=review,
            receipt=receipt,
            order=order,
            verifier_policy=mismatched_policy,
            adapter_policy=context["adapter_policy"],
            created_at="2026-09-01T00:03:00Z",
            not_after="2026-09-01T00:13:00Z",
            now=_utc("2026-09-01T00:03:00Z"),
        )


def _receipt_review_dispatch(tmp_path, context):
    store = TradeReceiptReviewDispatchStore(tmp_path)
    spine = SignedEventLog(
        tmp_path / "receipt-review-dispatch-spine.jsonl",
        context["taker"],
    )
    return store, spine, TradeReceiptReviewDispatchCoordinator(store, spine)


def test_receipt_review_dispatch_persists_ack_and_anchors_once(tmp_path):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    delivery = _receipt_review_delivery(context, order, receipt)
    root = tmp_path / "runtime"
    store, spine, dispatch = _receipt_review_dispatch(root, context)
    pending = dispatch.prepare(
        delivery,
        receipt=receipt,
        order=order,
        target_url="https://PEER.example/a2a/",
        now_ms=1_788_221_040_000,
    )
    dispatch.failed(
        pending.review_digest,
        error="temporary\nnetwork failure",
        now_ms=1_788_221_041_000,
    )
    acknowledgement = create_trade_receipt_review_acknowledgement(
        context["maker"],
        delivery=delivery,
        receipt=receipt,
        order=order,
        received_at="2026-09-01T00:04:00Z",
        audit_event_id="9" * 64,
    )
    retained = dispatch.acknowledge(
        delivery,
        acknowledgement,
        receipt=receipt,
        order=order,
        target_url="https://peer.example/a2a",
        remote_event_id="9" * 64,
        observed_at_ms=1_788_221_041_000,
    )

    restarted_store = TradeReceiptReviewDispatchStore(root)
    restarted_spine = SignedEventLog(
        root / "receipt-review-dispatch-spine.jsonl",
        context["taker"],
    )
    restarted = TradeReceiptReviewDispatchCoordinator(
        restarted_store,
        restarted_spine,
    )
    replay = restarted.prepare(
        delivery,
        receipt=receipt,
        order=order,
        target_url="https://peer.example/a2a",
        now_ms=1_788_221_042_000,
    )

    assert pending.target_url == "https://peer.example/a2a"
    assert store.get_pending(pending.review_digest) is None
    assert restarted_store.get_acknowledgement(
        pending.review_digest
    ) == retained
    assert replay.acknowledged is True
    assert replay.delivery == retained.delivery
    assert restarted.recover_acknowledgement(pending.review_digest) == retained
    events = restarted_spine.verified_snapshot()
    assert len(events) == 1
    assert events[0].type == EVENT_TRADE_RECEIPT_REVIEW_ACKNOWLEDGED
    assert events[0].payload == receipt_review_acknowledgement_audit_payload(
        retained
    )
    assert restarted_spine.verify_chain() == (True, "ok")


def test_receipt_review_dispatch_recovers_after_spine_failure(
    tmp_path,
    monkeypatch,
):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    delivery = _receipt_review_delivery(context, order, receipt)
    root = tmp_path / "runtime"
    store, spine, dispatch = _receipt_review_dispatch(root, context)
    pending = dispatch.prepare(
        delivery,
        receipt=receipt,
        order=order,
        target_url="https://peer.example",
        now_ms=1_788_221_040_000,
    )
    acknowledgement = create_trade_receipt_review_acknowledgement(
        context["maker"],
        delivery=delivery,
        receipt=receipt,
        order=order,
        received_at="2026-09-01T00:04:00Z",
        audit_event_id="a" * 64,
    )

    monkeypatch.setattr(
        spine,
        "append_unique",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("spine unavailable")
        ),
    )
    with pytest.raises(OSError, match="spine unavailable"):
        dispatch.acknowledge(
            delivery,
            acknowledgement,
            receipt=receipt,
            order=order,
            target_url="https://peer.example",
            remote_event_id="a" * 64,
            observed_at_ms=1_788_221_041_000,
        )

    assert store.get_pending(pending.review_digest) is not None
    assert store.get_acknowledgement(pending.review_digest) is not None
    recovered_spine = SignedEventLog(
        root / "receipt-review-dispatch-spine.jsonl",
        context["taker"],
    )
    recovered = TradeReceiptReviewDispatchCoordinator(store, recovered_spine)
    result = recovered.reconcile()
    assert result.scanned == 1
    assert result.anchored == 1
    assert result.completed == 1
    assert result.failed == 0
    assert store.get_pending(pending.review_digest) is None
    assert recovered_spine.verify_chain() == (True, "ok")


def test_receipt_review_dispatch_renews_only_expired_envelope(tmp_path):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _receipt_review(context, order, receipt)
    old_delivery = _receipt_review_delivery(
        context,
        order,
        receipt,
        review,
    )
    store = TradeReceiptReviewDispatchStore(tmp_path / "runtime")
    pending = store.prepare(
        old_delivery,
        receipt=receipt,
        order=order,
        target_url="https://peer.example",
        now_ms=1_788_221_040_000,
    )
    replacement = create_trade_receipt_review_delivery(
        context["taker"],
        review=review,
        receipt=receipt,
        order=order,
        verifier_policy=context["taker_policy"],
        adapter_policy=context["adapter_policy"],
        created_at="2026-09-01T00:19:00Z",
        not_after="2026-09-01T00:29:00Z",
        nonce="c3" * 16,
        now=_utc("2026-09-01T00:19:00Z"),
    )

    with pytest.raises(
        TradeReceiptReviewDispatchError,
        match="not expired",
    ):
        store.renew_expired(
            replacement,
            receipt=receipt,
            order=order,
            target_url="https://peer.example",
            now_ms=1_788_221_640_000,
        )

    renewed = store.renew_expired(
        replacement,
        receipt=receipt,
        order=order,
        target_url="https://peer.example",
        now_ms=1_788_221_940_000,
    )
    assert renewed.generation == 2
    assert renewed.attempts == 0
    assert renewed.superseded_delivery_digests == (
        trade_receipt_review_delivery_digest(
            old_delivery,
            receipt=receipt,
            order=order,
        ),
    )
    assert renewed.review_digest == pending.review_digest

    stale_ack = create_trade_receipt_review_acknowledgement(
        context["maker"],
        delivery=old_delivery,
        receipt=receipt,
        order=order,
        received_at="2026-09-01T00:04:00Z",
        audit_event_id="b" * 64,
    )
    with pytest.raises(
        TradeReceiptReviewDispatchError,
        match="delivery_digest|pending delivery",
    ):
        store.put_acknowledgement(
            replacement,
            stale_ack,
            receipt=receipt,
            order=order,
            target_url="https://peer.example",
            remote_event_id="b" * 64,
            observed_at_ms=1_788_221_941_000,
        )


def test_receipt_review_dispatch_rejects_target_scope_change(tmp_path):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    delivery = _receipt_review_delivery(context, order, receipt)
    store = TradeReceiptReviewDispatchStore(tmp_path / "runtime")
    store.prepare(
        delivery,
        receipt=receipt,
        order=order,
        target_url="https://peer.example",
        now_ms=1_788_221_040_000,
    )

    with pytest.raises(
        TradeReceiptReviewDispatchError,
        match="conflicts with Review scope",
    ):
        store.prepare(
            delivery,
            receipt=receipt,
            order=order,
            target_url="https://other.example",
            now_ms=1_788_221_041_000,
        )
    with pytest.raises(
        TradeReceiptReviewDispatchError,
        match="credentials",
    ):
        store.prepare(
            delivery,
            receipt=receipt,
            order=order,
            target_url="https://user:secret@peer.example",
            now_ms=1_788_221_041_000,
        )


def test_receipt_review_is_public_trade_rule_api():
    assert trade_rules_api.TradeReceiptReview is TradeReceiptReview
    assert trade_rules_api.TradeReceiptReviewStore is TradeReceiptReviewStore
    assert (
        trade_rules_api.TradeReceiptReviewCoordinator is TradeReceiptReviewCoordinator
    )
    assert trade_rules_api.create_trade_receipt_review is (create_trade_receipt_review)
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

    first = coordinator.record_legacy(review, receipt=receipt, order=order)
    second = coordinator.record_legacy(review, receipt=receipt, order=order)

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

    coordinator.record_legacy(accepted, receipt=receipt, order=order)
    with pytest.raises(TradeReceiptReviewConflict):
        coordinator.record_legacy(disputed, receipt=receipt, order=order)
    with pytest.raises(TradeReceiptReviewConflict):
        coordinator.record_legacy(disputed, receipt=receipt, order=order)

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

    coordinator.record_legacy(accepted, receipt=receipt, order=order)
    for candidate in (disputed, rejected):
        with pytest.raises(TradeReceiptReviewConflict):
            coordinator.record_legacy(candidate, receipt=receipt, order=order)

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
        coordinator.record_legacy(review, receipt=receipt, order=order)
    assert store.get(
        review.review_id,
        receipt=receipt,
        order=order,
    ) == review
    assert spine.verified_snapshot() == ()

    monkeypatch.setattr(spine, "append_unique", original)
    recovered = coordinator.record_legacy(review, receipt=receipt, order=order)
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
        first_process.record_legacy(review, receipt=receipt, order=order)
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
    first_process.record_legacy(accepted, receipt=receipt, order=order)
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
        first_process.record_legacy(disputed, receipt=receipt, order=order)

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
    record, _created = outbox.prepare_legacy(
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


def test_receipt_review_outbox_upgrades_v1_with_bound_policy_snapshots(
    tmp_path,
):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _receipt_review(context, order, receipt)
    outbox = trade_rules_api.TradeReceiptReviewOutbox(tmp_path / "runtime")
    legacy, created = outbox.prepare_legacy(
        review,
        receipt=receipt,
        order=order,
        now_ms=1,
    )

    upgraded, upgraded_created = outbox.prepare(
        review,
        receipt=receipt,
        order=order,
        now_ms=2,
        verifier_policy=context["taker_policy"],
        adapter_policy=context["adapter_policy"],
    )
    snapshots = outbox.get_policy_snapshots(upgraded.review_digest)

    assert created is True
    assert legacy.protocol_version == "1"
    assert upgraded_created is False
    assert upgraded.protocol_version == "3"
    assert upgraded.updated_at_ms == 2
    assert upgraded.first_observed_at_ms == 2
    assert outbox.observed_at_ms(upgraded.review_digest) == 2
    assert snapshots is not None
    assert snapshots[0].canonical_bytes == context["taker_policy"].canonical_bytes
    assert snapshots[1].canonical_bytes == context["adapter_policy"].canonical_bytes


def test_receipt_review_v3_publication_requires_policy_and_observation(tmp_path):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _receipt_review(context, order, receipt)
    runtime = tmp_path / "runtime"
    outbox = trade_rules_api.TradeReceiptReviewOutbox(runtime)

    with pytest.raises(TypeError, match="verifier_policy"):
        outbox.prepare(
            review,
            receipt=receipt,
            order=order,
            now_ms=1,
        )

    coordinator = TradeReceiptReviewCoordinator(
        TradeReceiptReviewStore(runtime),
        SignedEventLog(runtime / "review-spine.jsonl", context["maker"]),
    )
    with pytest.raises(TypeError, match="verifier_policy"):
        coordinator.record(review, receipt=receipt, order=order)
    with pytest.raises(TypeError, match="observed_at_ms"):
        coordinator.record(
            review,
            receipt=receipt,
            order=order,
            verifier_policy=context["taker_policy"],
            adapter_policy=context["adapter_policy"],
        )


def test_receipt_review_outbox_upgrades_v2_observation_compatibly(tmp_path):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _receipt_review(context, order, receipt)
    outbox = trade_rules_api.TradeReceiptReviewOutbox(tmp_path / "runtime")
    current, _created = outbox.prepare(
        review,
        receipt=receipt,
        order=order,
        now_ms=1,
        verifier_policy=context["taker_policy"],
        adapter_policy=context["adapter_policy"],
    )
    path = outbox._path(current.review_digest)
    legacy_v2 = current.to_dict()
    legacy_v2["protocol_version"] = "2"
    legacy_v2.pop("first_observed_at_ms")
    legacy_v2.update(
        {
            "status": "anchored",
            "event_type": "trade.receipt.reviewed",
            "event_id": "a" * 64,
            "updated_at_ms": 9,
            "attempts": 2,
        }
    )
    path.write_bytes(canonical_json(legacy_v2))

    upgraded, created = outbox.prepare(
        review,
        receipt=receipt,
        order=order,
        now_ms=2,
        verifier_policy=context["taker_policy"],
        adapter_policy=context["adapter_policy"],
    )

    assert created is False
    assert upgraded.protocol_version == "3"
    assert upgraded.first_observed_at_ms == 1
    assert upgraded.updated_at_ms == 9
    assert upgraded.status == "anchored"
    assert upgraded.attempts == 2
    assert outbox.observed_at_ms(upgraded.review_digest) == 1


def test_receipt_review_prepare_only_fully_validates_target_record(
    tmp_path,
    monkeypatch,
):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    first_review = _receipt_review(context, order, receipt)
    second_review = _receipt_review(
        context,
        order,
        receipt,
        reviewed_at="2026-09-01T00:02:01Z",
        now=_utc("2026-09-01T00:02:01Z"),
    )
    outbox = trade_rules_api.TradeReceiptReviewOutbox(tmp_path / "runtime")
    outbox.prepare(
        first_review,
        receipt=receipt,
        order=order,
        now_ms=1,
        verifier_policy=context["taker_policy"],
        adapter_policy=context["adapter_policy"],
    )

    original_read = outbox._read
    read_paths = []

    def counted_read(path):
        read_paths.append(path)
        return original_read(path)

    monkeypatch.setattr(outbox, "_read", counted_read)
    outbox.prepare(
        second_review,
        receipt=receipt,
        order=order,
        now_ms=2,
        verifier_policy=context["taker_policy"],
        adapter_policy=context["adapter_policy"],
    )
    assert read_paths == []

    outbox.prepare(
        first_review,
        receipt=receipt,
        order=order,
        now_ms=3,
        verifier_policy=context["taker_policy"],
        adapter_policy=context["adapter_policy"],
    )
    first_digest = receipt_review_digest(
        first_review,
        receipt=receipt,
        order=order,
    )
    assert read_paths == [outbox._path(first_digest)]


def test_receipt_review_outbox_counts_crash_residue_before_new_record(tmp_path):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _receipt_review(context, order, receipt)
    outbox = trade_rules_api.TradeReceiptReviewOutbox(
        tmp_path / "runtime",
        max_records=1,
    )
    outbox.root.mkdir(parents=True, exist_ok=True)
    (outbox.root / (("0" * 64) + ".json.crash.tmp")).write_bytes(b"x")

    with pytest.raises(
        trade_rules_api.TradeReceiptReviewOutboxCapacity,
        match="max_records",
    ):
        outbox.prepare(
            review,
            receipt=receipt,
            order=order,
            now_ms=1,
            verifier_policy=context["taker_policy"],
            adapter_policy=context["adapter_policy"],
        )


def test_receipt_review_outbox_counts_residue_bytes_before_new_record(tmp_path):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _receipt_review(context, order, receipt)
    baseline = trade_rules_api.TradeReceiptReviewOutbox(tmp_path / "baseline")
    record, _created = baseline.prepare(
        review,
        receipt=receipt,
        order=order,
        now_ms=1,
        verifier_policy=context["taker_policy"],
        adapter_policy=context["adapter_policy"],
    )
    record_size = baseline._path(record.review_digest).stat().st_size
    residue_bytes = b"residue"
    outbox = trade_rules_api.TradeReceiptReviewOutbox(
        tmp_path / "runtime",
        max_bytes=record_size + len(residue_bytes) - 1,
    )
    outbox.root.mkdir(parents=True, exist_ok=True)
    (outbox.root / (("0" * 64) + ".json.crash.tmp")).write_bytes(
        residue_bytes
    )

    with pytest.raises(
        trade_rules_api.TradeReceiptReviewOutboxCapacity,
        match="max_bytes",
    ):
        outbox.prepare(
            review,
            receipt=receipt,
            order=order,
            now_ms=1,
            verifier_policy=context["taker_policy"],
            adapter_policy=context["adapter_policy"],
        )


def test_receipt_review_outbox_counts_crash_residue_during_v2_upgrade(tmp_path):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _receipt_review(context, order, receipt)
    outbox = trade_rules_api.TradeReceiptReviewOutbox(tmp_path / "runtime")
    legacy, _created = outbox.prepare_legacy(
        review,
        receipt=receipt,
        order=order,
        now_ms=1,
    )
    legacy_size = outbox._path(legacy.review_digest).stat().st_size
    residue = outbox.root / (("0" * 64) + ".json.crash.tmp")
    residue.write_bytes(b"residue")
    outbox.max_bytes = legacy_size + residue.stat().st_size

    with pytest.raises(
        trade_rules_api.TradeReceiptReviewOutboxCapacity,
        match="max_bytes",
    ):
        outbox.prepare(
            review,
            receipt=receipt,
            order=order,
            now_ms=2,
            verifier_policy=context["taker_policy"],
            adapter_policy=context["adapter_policy"],
        )


def test_receipt_review_outbox_rejects_policy_snapshot_tamper(tmp_path):
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
        verifier_policy=context["taker_policy"],
        adapter_policy=context["adapter_policy"],
    )
    path = outbox._path(record.review_digest)
    document = json.loads(path.read_text(encoding="utf-8"))
    replacement = (
        "A" if document["adapter_policy_b64u"][-1] != "A" else "B"
    )
    document["adapter_policy_b64u"] = (
        document["adapter_policy_b64u"][:-1] + replacement
    )
    path.write_bytes(canonical_json(document))

    with pytest.raises(
        trade_rules_api.TradeReceiptReviewOutboxError,
        match="policy snapshots|encoding|digest binding",
    ):
        outbox.get_policy_snapshots(record.review_digest)


def test_receipt_review_outbox_rejects_status_event_mismatch(tmp_path):
    context = _setup(tmp_path / "fixtures")
    order = _order(context)
    receipt = _execution_receipt(context, order)
    review = _receipt_review(context, order, receipt)
    outbox = trade_rules_api.TradeReceiptReviewOutbox(tmp_path / "runtime")
    record, _created = outbox.prepare_legacy(
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
        coordinator.record_legacy(review, receipt=receipt, order=order)
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
    TradeReceiptReviewCoordinator(store, spine).record_legacy(
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
        coordinator.record_legacy(review, receipt=receipt, order=order)
    assert len(spine.verified_snapshot()) == 1

    monkeypatch.setattr(spine, "append_unique", original)
    recovered = coordinator.record_legacy(review, receipt=receipt, order=order)
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
