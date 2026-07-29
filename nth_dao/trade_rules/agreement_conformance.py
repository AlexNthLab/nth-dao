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
from nth_dao.trade_rules.offer import offer_body, sign_offer
from nth_dao.trade_rules.package_store import RulePackageStore
from nth_dao.trade_rules.store import OfferStore

VECTORS_PATH = Path(__file__).with_name("vectors") / "agreement-v1.json"
PROPOSAL_SCHEMA_PATH = (
    Path(__file__).with_name("schemas") / "trade-proposal.schema.json"
)
ACCEPTANCE_SCHEMA_PATH = (
    Path(__file__).with_name("schemas") / "trade-acceptance.schema.json"
)
ORDER_SCHEMA_PATH = (
    Path(__file__).with_name("schemas") / "trade-order.schema.json"
)
ORDER_AUDIT_SCHEMA_PATH = (
    Path(__file__).with_name("schemas")
    / "trade-order-audit-payload.schema.json"
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
    manifest = sign_manifest(
        rule_publisher,
        manifest_body(
            rule_id="org.nthdao.reference.delivery",
            version="1.0.0",
            publisher_did=rule_publisher.as_did(),
            summary="Public bilateral agreement conformance rule.",
            applies_to=["service"],
            families=["fulfillment"],
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
    with tempfile.TemporaryDirectory() as directory:
        package_store = RulePackageStore(directory)
        offer_store = OfferStore(directory)
        package_digest = package_store.install(
            manifest,
            {resource_digest: resource},
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
            terms={"requested_quantity": "1"},
            created_at="2026-08-01T00:00:00Z",
            not_after="2026-08-02T00:00:00Z",
            now=_utc("2026-08-01T00:00:00Z"),
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
    return {
        "format": "nth-trade-agreement-conformance-v1",
        "schema_version": 1,
        "warning": "Deterministic public test keys; never trust or reuse them.",
        "proposal": proposal.to_dict(),
        "proposal_digest": proposal_digest(proposal),
        "acceptance": acceptance.to_dict(),
        "acceptance_digest": acceptance_digest(acceptance),
        "order": order.to_dict(),
        "order_digest": trade_order_digest(order),
        "order_audit": {
            "event_type": EVENT_TRADE_ORDER_ACCEPTED,
            "payload": audit_payload,
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
    "ORDER_SCHEMA_PATH",
    "ORDER_AUDIT_SCHEMA_PATH",
    "PROPOSAL_SCHEMA_PATH",
    "VECTORS_PATH",
    "generate_vectors",
    "write_vectors",
]
