"""Conformance and negative tests for transport.provider delivery v1."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

import pytest

from nth_dao.canonical_json import canonical_json
from nth_dao.plugins.host import CapabilitySchemas
from nth_dao.plugins.schema import PluginSchemaError
from nth_dao.plugins.transport import (
    TRANSPORT_CAPABILITY_ID,
    TRANSPORT_ERROR_MODEL,
    TRANSPORT_ERROR_SCHEMA,
    TRANSPORT_INPUT_SCHEMA,
    TRANSPORT_LOCAL_CONTRACT,
    TRANSPORT_OUTPUT_SCHEMA,
    TransportOperationError,
    canonical_transport_envelope,
    transport_batch_digest,
    transport_contract_vector,
    transport_envelope_digest,
    transport_protocol_digest,
    transport_protocol_document,
    transport_wire_vectors,
    validate_transport_identifier,
    validate_transport_exchange,
    validate_transport_error,
    validate_transport_input,
    validate_transport_output,
)


VECTOR_DIR = Path(__file__).parents[1] / "nth_dao" / "plugins" / "vectors"
VECTOR_PATH = VECTOR_DIR / "transport-capability-v1.json"


def _envelope() -> str:
    return canonical_json(
        {"id": "msg-1", "payload": {"body": "hello"}, "type": "chat.message"}
    ).decode("utf-8")


def _base_output(operation: str) -> dict:
    return {
        "accepted": False,
        "acknowledged": False,
        "acknowledged_count": 0,
        "batch_sha256": "",
        "delivery_guarantee": "ephemeral-at-least-once-until-ack",
        "delivery_id": "",
        "detail": "",
        "expires_at_ms": 0,
        "found": False,
        "items": [],
        "lease_expires_at_ms": 0,
        "lease_id": "",
        "local_route_id": "loopback:sha256:" + "a" * 64,
        "max_batch_size": 64,
        "max_envelope_bytes": 524_288,
        "max_lease_ms": 300_000,
        "max_ttl_seconds": 604_800,
        "operation": operation,
        "ready": True,
        "receive_id": "",
        "replayed": False,
        "state": "",
        "supports_ack": True,
        "supports_streaming": False,
        "transport_id": "org.nth-dao.transport.loopback",
        "transport_delivery_id": "",
    }


def _leased_output() -> dict:
    body = _envelope()
    item = {
        "accepted_at_ms": 1_750_000_000_000,
        "delivery_id": "delivery-1",
        "envelope_json": body,
        "envelope_sha256": transport_envelope_digest(body),
        "expires_at_ms": 1_750_000_060_000,
        "transport_delivery_id": "delivery:sha256:" + "c" * 64,
    }
    result = _base_output("receive")
    result.update(
        {
            "batch_sha256": transport_batch_digest([item]),
            "found": True,
            "items": [item],
            "lease_expires_at_ms": 1_750_000_030_000,
            "lease_id": "lease-1",
            "receive_id": "receive-1",
            "state": "leased",
        }
    )
    return result


def test_transport_contract_and_checked_in_vectors_match() -> None:
    vector = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    protocol = transport_protocol_document()
    assert vector == transport_contract_vector()
    assert vector["format"] == "nth-dao-plugin-capability-conformance-v1"
    assert vector["capability"] == TRANSPORT_LOCAL_CONTRACT.to_dict()
    assert vector["expected_digest"] == TRANSPORT_LOCAL_CONTRACT.digest
    assert vector["expected_protocol_digest"] == transport_protocol_digest()
    assert json.loads((VECTOR_DIR / vector["input_schema"]).read_text("utf-8")) == (
        protocol["input_schema"]
    )
    assert json.loads((VECTOR_DIR / vector["output_schema"]).read_text("utf-8")) == (
        protocol["output_schema"]
    )
    cases = json.loads((VECTOR_DIR / vector["operation_vectors"]).read_text("utf-8"))
    assert cases == transport_wire_vectors()
    CapabilitySchemas(
        TRANSPORT_INPUT_SCHEMA,
        TRANSPORT_OUTPUT_SCHEMA,
        input_validator=validate_transport_input,
        output_validator=validate_transport_output,
    )


def test_transport_profile_is_non_authoritative_and_retry_safe() -> None:
    assert TRANSPORT_CAPABILITY_ID == "org.nth-dao.transport.delivery"
    assert TRANSPORT_LOCAL_CONTRACT.consistency == "C2"
    assert TRANSPORT_LOCAL_CONTRACT.effects == ("none",)
    assert TRANSPORT_LOCAL_CONTRACT.privacy == "confidential"
    assert TRANSPORT_LOCAL_CONTRACT.security == "verified-input"
    assert TRANSPORT_LOCAL_CONTRACT.retention == "ephemeral"
    assert TRANSPORT_LOCAL_CONTRACT.failure_semantics == "retry-safe"


def test_transport_error_model_is_closed_immutable_and_machine_readable() -> None:
    assert TRANSPORT_ERROR_MODEL
    assert all(
        set(specification) == {"meaning", "retryable"}
        for specification in TRANSPORT_ERROR_MODEL.values()
    )
    error = TransportOperationError("quota-exceeded", "capacity is full")
    assert error.code == "quota-exceeded"
    assert error.retryable is True
    with pytest.raises(TypeError):
        TRANSPORT_ERROR_MODEL["quota-exceeded"]["retryable"] = False  # type: ignore[index]
    with pytest.raises(ValueError, match="unsupported"):
        TransportOperationError("invented", "not in the contract")
    assert TRANSPORT_ERROR_SCHEMA == transport_protocol_document()["error_schema"]
    wire = error.to_wire()
    validate_transport_error(wire)
    rebuilt = TransportOperationError.from_wire(wire)
    assert (rebuilt.code, rebuilt.detail, rebuilt.retryable) == (
        error.code,
        error.detail,
        error.retryable,
    )
    contradictory = dict(wire, retryable=False)
    with pytest.raises(PluginSchemaError, match="contradicts"):
        validate_transport_error(contradictory)


@pytest.mark.parametrize(
    "document",
    [
        {"operation": "probe"},
        {
            "operation": "send",
            "delivery_id": "delivery-1",
            "destination_route_id": "loopback:sha256:" + "b" * 64,
            "envelope_json": _envelope(),
            "envelope_sha256": transport_envelope_digest(_envelope()),
            "expires_at_ms": 1_750_000_060_000,
        },
        {
            "operation": "receive",
            "receive_id": "receive-1",
            "limit": 10,
            "lease_ms": 30_000,
        },
        {
            "operation": "ack",
            "receive_id": "receive-1",
            "lease_id": "lease-1",
            "batch_sha256": "a" * 64,
        },
    ],
)
def test_transport_valid_inputs(document: dict) -> None:
    validate_transport_input(document)


@pytest.mark.parametrize(
    "mutate,match",
    [
        (lambda value: value.update({"source_did": "did:key:zFake"}), "unknown fields"),
        (
            lambda value: value.update({"destination_route_id": "https://peer.test/a2a"}),
            "destination_route_id",
        ),
        (lambda value: value.update({"envelope_sha256": "0" * 64}), "does not bind"),
        (lambda value: value.update({"envelope_json": '{"z":1, "a":2}'}), "canonical"),
    ],
)
def test_transport_send_rejects_authority_smuggling_and_unbound_content(
    mutate,
    match: str,
) -> None:
    body = _envelope()
    value = {
        "operation": "send",
        "delivery_id": "delivery-1",
        "destination_route_id": "route:peer-1",
        "envelope_json": body,
        "envelope_sha256": transport_envelope_digest(body),
        "expires_at_ms": 1_750_000_060_000,
    }
    mutate(value)
    with pytest.raises(PluginSchemaError, match=match):
        validate_transport_input(value)


def test_transport_envelope_rejects_floats_and_unsafe_integers() -> None:
    with pytest.raises(ValueError, match="float"):
        canonical_transport_envelope('{"amount":1.5}')
    with pytest.raises(ValueError, match="safe range"):
        canonical_transport_envelope('{"amount":9007199254740992}')


@pytest.mark.parametrize(
    "value",
    [
        "https://peer.test/a2a",
        "X:/private/secret",
        "route/../secret",
        "route//peer",
        "route:",
    ],
)
def test_transport_route_ids_cannot_be_urls_or_paths(value: str) -> None:
    with pytest.raises(ValueError):
        validate_transport_identifier(value, field="destination_route_id")


def test_transport_valid_outputs_cover_all_operations() -> None:
    probe = _base_output("probe")
    validate_transport_output(probe)

    send = _base_output("send")
    send.update(
        {
            "accepted": True,
            "delivery_id": "delivery-1",
            "expires_at_ms": 1_750_000_060_000,
            "state": "queued",
            "transport_delivery_id": "delivery:sha256:" + "c" * 64,
        }
    )
    validate_transport_output(send)

    receive = _leased_output()
    validate_transport_output(receive)

    ack = _base_output("ack")
    ack.update(
        {
            "acknowledged": True,
            "acknowledged_count": 1,
            "batch_sha256": receive["batch_sha256"],
            "lease_id": "lease-1",
            "receive_id": "receive-1",
            "state": "acknowledged",
        }
    )
    validate_transport_output(ack)


def test_transport_output_rejects_batch_tampering_and_false_streaming_claims() -> None:
    receive = _leased_output()
    receive["items"][0]["delivery_id"] = "substituted"
    with pytest.raises(PluginSchemaError, match="batch_sha256"):
        validate_transport_output(receive)

    probe = _base_output("probe")
    probe["supports_streaming"] = True
    with pytest.raises(PluginSchemaError, match="streaming"):
        validate_transport_output(probe)


@pytest.mark.parametrize("field", ["accepted_at_ms", "expires_at_ms"])
def test_transport_batch_digest_binds_delivery_timestamps(field: str) -> None:
    receive = _leased_output()
    receive["items"][0][field] += 1
    with pytest.raises(PluginSchemaError, match="batch_sha256"):
        validate_transport_output(receive)


def test_transport_exchange_binds_operation_identifiers_and_request_limit() -> None:
    send_request = {
        "operation": "send",
        "delivery_id": "delivery-1",
        "destination_route_id": "route:peer-1",
        "envelope_json": _envelope(),
        "envelope_sha256": transport_envelope_digest(_envelope()),
        "expires_at_ms": 1_750_000_060_000,
    }
    send_response = _base_output("send")
    send_response.update(
        {
            "accepted": True,
            "delivery_id": "substituted",
            "expires_at_ms": send_request["expires_at_ms"],
            "state": "queued",
            "transport_delivery_id": "delivery:sha256:" + "c" * 64,
        }
    )
    validate_transport_output(send_response)
    with pytest.raises(PluginSchemaError, match="delivery_id"):
        validate_transport_exchange(send_request, send_response)

    receive_request = {
        "operation": "receive",
        "receive_id": "receive-1",
        "limit": 1,
        "lease_ms": 30_000,
    }
    receive_response = _leased_output()
    extra = dict(receive_response["items"][0])
    extra["delivery_id"] = "delivery-2"
    extra["transport_delivery_id"] = "delivery:sha256:" + "d" * 64
    receive_response["items"].append(extra)
    receive_response["batch_sha256"] = transport_batch_digest(
        receive_response["items"]
    )
    validate_transport_output(receive_response)
    with pytest.raises(PluginSchemaError, match="input.limit"):
        validate_transport_exchange(receive_request, receive_response)


def test_transport_output_rejects_lease_past_expiry_and_false_batch_limit() -> None:
    past_expiry = _leased_output()
    past_expiry["lease_expires_at_ms"] = past_expiry["items"][0]["expires_at_ms"] + 1
    with pytest.raises(PluginSchemaError, match="expires before the receive lease"):
        validate_transport_output(past_expiry)

    false_limit = _leased_output()
    false_limit["max_batch_size"] = 1
    duplicate = dict(false_limit["items"][0])
    duplicate["delivery_id"] = "delivery-2"
    duplicate["transport_delivery_id"] = "delivery:sha256:" + "d" * 64
    false_limit["items"].append(duplicate)
    false_limit["batch_sha256"] = transport_batch_digest(false_limit["items"])
    with pytest.raises(PluginSchemaError, match="provider batch limit"):
        validate_transport_output(false_limit)


def test_node_consumer_matches_transport_conformance_vectors() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is unavailable for cross-language conformance")
    script = r'''
const crypto = require("crypto");
const fs = require("fs");
function compareCodePoints(left, right) {
  const a = Array.from(left, item => item.codePointAt(0));
  const b = Array.from(right, item => item.codePointAt(0));
  for (let i = 0; i < Math.min(a.length, b.length); i += 1) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}
function canonical(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("unsafe number");
    return String(value);
  }
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (typeof value === "object") {
    return "{" + Object.keys(value).sort(compareCodePoints).map(
      key => JSON.stringify(key) + ":" + canonical(value[key])
    ).join(",") + "}";
  }
  throw new Error("unsupported JSON value");
}
function sha(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}
const root = process.argv[1];
const metadata = JSON.parse(fs.readFileSync(root + "/transport-capability-v1.json", "utf8"));
const cases = JSON.parse(fs.readFileSync(root + "/transport-wire-cases-v1.json", "utf8"));
const inputSchema = JSON.parse(fs.readFileSync(root + "/transport-input-schema-v1.json", "utf8"));
const outputSchema = JSON.parse(fs.readFileSync(root + "/transport-output-schema-v1.json", "utf8"));
if ("sha256:" + sha(canonical(metadata.capability)) !== metadata.expected_digest) {
  throw new Error("capability digest mismatch");
}
if ("sha256:" + sha(canonical(inputSchema)) !== metadata.capability.input_schema_digest) {
  throw new Error("input schema digest mismatch");
}
if ("sha256:" + sha(canonical(outputSchema)) !== metadata.capability.output_schema_digest) {
  throw new Error("output schema digest mismatch");
}
const protocol = {
  capability: metadata.capability,
  canonicalization: cases.canonicalization,
  error_model: cases.error_model,
  error_schema: cases.error_schema,
  identifier_rules: cases.identifier_rules,
  input_schema: inputSchema,
  operation_rules: cases.operation_rules,
  output_schema: outputSchema,
  semantics: cases.semantics,
  wire_limits: cases.wire_limits,
};
if ("sha256:" + sha(canonical(protocol)) !== metadata.expected_protocol_digest) {
  throw new Error("protocol digest mismatch");
}
for (const example of cases.canonical_examples) {
  const encoded = canonical(example.document);
  if (encoded !== example.canonical_utf8 || sha(encoded) !== example.sha256) {
    throw new Error("canonical envelope mismatch");
  }
}
for (const example of cases.batch_digest_examples) {
  const deliveries = example.items.map(item => ({
    accepted_at_ms: item.accepted_at_ms,
    delivery_id: item.delivery_id,
    envelope_sha256: item.envelope_sha256,
    expires_at_ms: item.expires_at_ms,
    transport_delivery_id: item.transport_delivery_id,
  }));
  if (sha(canonical({deliveries})) !== example.sha256) {
    throw new Error("batch digest mismatch");
  }
}
for (const error of cases.valid_errors) {
  const specification = cases.error_model[error.code];
  if (!specification || error.retryable !== specification.retryable) {
    throw new Error("wire error model mismatch");
  }
}
'''
    result = subprocess.run(
        [node, "-e", script, str(VECTOR_DIR)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout
