"""Deterministic conformance vectors for Trade Offer v2."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from nth_dao.identity import AgentID, AgentIdentity
from nth_dao.market.conformance import generate_vectors as generate_market_vectors
from nth_dao.market.resource_descriptor import (
    MARKET_PUBLICATION_EXTENSION,
    RESOURCE_DESCRIPTOR_EXTENSION,
)
from nth_dao.trade_rules.offer import (
    OFFER_SIGNING_DOMAIN,
    offer_body,
    offer_digest,
    offer_signing_input,
    sign_offer,
)
from nth_dao.trade_rules.signing import (
    encode_ed25519_signature,
    signed_document_input,
)

VECTORS_PATH = Path(__file__).with_name("vectors") / "offer-v2.json"
SCHEMA_PATH = Path(__file__).with_name("schemas") / "trade-offer.schema.json"
_SEED = hashlib.sha256(b"NTH Trade Offer v2 public conformance seed").digest()


def _test_identity() -> AgentIdentity:
    try:
        from nacl.signing import SigningKey
    except ImportError as exc:  # pragma: no cover - optional crypto environment
        raise RuntimeError("regenerating Trade Offer vectors requires PyNaCl") from exc
    signing_key = SigningKey(_SEED)
    verify_key = signing_key.verify_key.encode()
    return AgentIdentity(
        agent_id=AgentID.from_pubkey(verify_key.hex()),
        label="public-conformance-only",
        _signing_key=signing_key.encode(),
        _verify_key=verify_key,
    )


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _sign_semantically_invalid(
    identity: AgentIdentity,
    document: dict[str, Any],
) -> dict[str, Any]:
    """Sign bounded canonical bytes without invoking the Offer validator."""
    value = copy.deepcopy(document)
    value["proof"]["proof_value"] = encode_ed25519_signature(
        identity.sign(signed_document_input(OFFER_SIGNING_DOMAIN, value))
    )
    return value


def generate_vectors() -> dict[str, Any]:
    identity = _test_identity()
    market_vectors = generate_market_vectors()
    descriptor = market_vectors["descriptor"]
    descriptor_digest = market_vectors["expected_descriptor_digest"]
    body = offer_body(
        offer_id="org.nthdao.reference/btc-for-solana-token",
        publisher_did=identity.as_did(),
        title="BTC for a Solana token",
        summary="Public conformance offer; never use this key for real trust.",
        provides=[
            {
                "leg_id": "bitcoin",
                "resource_type": "asset:fungible",
                "resource_id": "bitcoin:btc",
                "quantity": "0.01",
                "unit": "btc",
                "descriptor_digest": descriptor_digest,
            }
        ],
        requests=[
            {
                "leg_id": "solana-token",
                "resource_type": "asset:fungible",
                "resource_id": "solana:spl:ExampleMint",
                "quantity": "1000",
                "unit": "token",
                "descriptor_digest": _digest(b"solana-token-descriptor"),
            }
        ],
        rule_refs=[
            {
                "rule_id": "org.nthdao.reference/atomic-swap",
                "digest": _digest(b"atomic-swap-rule-package"),
            }
        ],
        published_at="2026-07-29T00:00:00Z",
        not_after="2027-07-29T00:00:00Z",
        extensions={
            RESOURCE_DESCRIPTOR_EXTENSION: {
                "descriptors": {descriptor_digest: descriptor},
            },
            MARKET_PUBLICATION_EXTENSION: {
                "category": "other",
                "intent": "exchange",
                "capability_set": ["atomic-swap"],
                "offer_validity_seconds": 31_536_000,
            },
        },
    )
    offer = sign_offer(identity, body, created="2026-07-29T00:00:01Z")
    document = offer.to_dict()
    withdrawal_body = offer_body(
        offer_id=document["offer_id"],
        revision=2,
        previous_offer_digest=offer_digest(offer),
        state="withdrawn",
        publisher_did=identity.as_did(),
        title=document["title"],
        summary=document["summary"],
        provides=document["provides"],
        requests=document["requests"],
        rule_refs=document["rule_refs"],
        published_at="2026-07-30T00:00:00Z",
        not_after="2027-07-30T00:00:00Z",
    )
    withdrawal = sign_offer(
        identity, withdrawal_body, created="2026-07-30T00:00:01Z"
    )

    tampered_summary = copy.deepcopy(document)
    tampered_summary["summary"] = "tampered"
    tampered_quantity = copy.deepcopy(document)
    tampered_quantity["requests"][0]["quantity"] = "2000"
    tampered_signature = copy.deepcopy(document)
    replacement = "A" if document["proof"]["proof_value"][0] != "A" else "B"
    tampered_signature["proof"]["proof_value"] = (
        replacement + document["proof"]["proof_value"][1:]
    )
    empty_provides = copy.deepcopy(document)
    empty_provides["provides"] = []
    empty_provides = _sign_semantically_invalid(identity, empty_provides)
    zero_quantity = copy.deepcopy(document)
    zero_quantity["requests"][0]["quantity"] = "0"
    zero_quantity = _sign_semantically_invalid(identity, zero_quantity)
    unsafe_resource_id = copy.deepcopy(document)
    unsafe_resource_id["provides"][0]["resource_id"] = "../wallet.key"
    unsafe_resource_id = _sign_semantically_invalid(identity, unsafe_resource_id)
    broken_revision = copy.deepcopy(document)
    broken_revision["revision"] = 2
    broken_revision["previous_offer_digest"] = None
    broken_revision = _sign_semantically_invalid(identity, broken_revision)
    invalid_year = copy.deepcopy(document)
    invalid_year["published_at"] = "0000-07-29T00:00:00Z"
    invalid_year["proof"]["created"] = "0000-07-29T00:00:01Z"
    invalid_year = _sign_semantically_invalid(identity, invalid_year)

    return {
        "format": "nth-trade-offer-conformance-v2",
        "schema_version": 1,
        "warning": "The generator uses a deterministic public test seed only.",
        "offer": document,
        "withdrawal_offer": withdrawal.to_dict(),
        "expected_offer_canonical_hex": offer.canonical_bytes.hex(),
        "expected_signing_input_hex": offer_signing_input(document).hex(),
        "expected_offer_digest": offer_digest(offer),
        "expected_withdrawal_digest": offer_digest(withdrawal),
        "market_extensions_vector": "market-extensions-v1.json",
        "negative_offers": [
            {
                "id": "tampered-summary",
                "document": tampered_summary,
                "expected_valid": False,
                "expected_signature_valid": False,
            },
            {
                "id": "tampered-quantity",
                "document": tampered_quantity,
                "expected_valid": False,
                "expected_signature_valid": False,
            },
            {
                "id": "tampered-proof-value",
                "document": tampered_signature,
                "expected_valid": False,
                "expected_signature_valid": False,
            },
            {
                "id": "signed-empty-provides",
                "document": empty_provides,
                "expected_valid": False,
                "expected_signature_valid": True,
            },
            {
                "id": "signed-zero-quantity",
                "document": zero_quantity,
                "expected_valid": False,
                "expected_signature_valid": True,
            },
            {
                "id": "signed-unsafe-resource-id",
                "document": unsafe_resource_id,
                "expected_valid": False,
                "expected_signature_valid": True,
            },
            {
                "id": "signed-broken-revision",
                "document": broken_revision,
                "expected_valid": False,
                "expected_signature_valid": True,
            },
            {
                "id": "signed-invalid-year",
                "document": invalid_year,
                "expected_valid": False,
                "expected_signature_valid": True,
            },
        ],
    }


def encoded_vectors() -> bytes:
    return (
        json.dumps(
            generate_vectors(),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def regenerate_vectors(path: Path = VECTORS_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded_vectors())
    return path


def load_vectors(path: Path = VECTORS_PATH) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Trade Offer conformance vectors must be an object")
    return data


__all__ = [
    "SCHEMA_PATH",
    "VECTORS_PATH",
    "encoded_vectors",
    "generate_vectors",
    "load_vectors",
    "regenerate_vectors",
]
