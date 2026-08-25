"""Conformance and negative tests for the message.store wire contract."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from nth_dao.canonical_json import canonical_json
from nth_dao.plugins.host import CapabilitySchemas
from nth_dao.plugins.message_store import (
    MESSAGE_STORE_CAPABILITY_ID,
    MESSAGE_STORE_CONTRACT,
    MESSAGE_STORE_ERROR_MODEL,
    MESSAGE_STORE_INPUT_SCHEMA,
    MESSAGE_STORE_MAX_DOCUMENT_BYTES,
    MESSAGE_STORE_OUTPUT_SCHEMA,
    MessageStoreOperationError,
    canonical_message_document,
    message_store_message_digest,
    message_store_operation_rule,
    message_store_protocol_digest,
    message_store_protocol_document,
    validate_message_store_identifier,
    validate_message_store_input,
    validate_message_store_output,
)
from nth_dao.plugins.schema import PluginSchemaError, validate_instance


VECTOR_DIR = Path(__file__).parents[1] / "nth_dao" / "plugins" / "vectors"
VECTOR_PATH = VECTOR_DIR / "message-store-capability-v1.json"


def _message_json() -> str:
    return canonical_json({"body": "hello", "kind": "chat"}).decode("utf-8")


def _base_output(operation: str) -> dict:
    return {
        "created_at_ms": 0,
        "deleted": False,
        "deletion_guarantee": "logical-only",
        "delivery_mode": "",
        "detail": "",
        "expires_at_ms": 0,
        "found": False,
        "items": [],
        "max_message_bytes": 524_288,
        "max_records_per_principal": 1_024,
        "max_ttl_seconds": 2_592_000,
        "message_id": "",
        "message_json": "",
        "message_sha256": "",
        "namespace": "",
        "next_sequence": 0,
        "operation": operation,
        "ready": True,
        "replayed": False,
        "retention_mode": "",
        "sequence": 0,
        "store_id": "org.nth-dao.message.memory",
        "supported_delivery_modes": ["consume-on-read", "read-many"],
        "supported_retention_modes": ["session", "ttl"],
    }


def _record_output(operation: str, *, content: bool = False) -> dict:
    body = _message_json()
    result = _base_output(operation)
    result.update(
        {
            "created_at_ms": 1_750_000_000_000,
            "delivery_mode": "consume-on-read" if operation == "consume" else "read-many",
            "expires_at_ms": 0,
            "found": True,
            "message_id": "message-1",
            "message_json": body if content else "",
            "message_sha256": message_store_message_digest(body),
            "namespace": "group:alpha/channel:general",
            "retention_mode": "session",
            "sequence": 1,
        }
    )
    if operation == "consume":
        result["deleted"] = True
    return result


def test_message_store_contract_and_checked_in_vector_match() -> None:
    vector = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    protocol = message_store_protocol_document()
    assert vector["format"] == "nth-dao-plugin-capability-conformance-v1"
    assert vector["schema_version"] == 1
    assert vector["capability"] == MESSAGE_STORE_CONTRACT.to_dict()
    assert vector["expected_digest"] == MESSAGE_STORE_CONTRACT.digest
    assert vector["expected_protocol_digest"] == message_store_protocol_digest()
    assert json.loads((VECTOR_DIR / vector["input_schema"]).read_text("utf-8")) == (
        protocol["input_schema"]
    )
    assert json.loads((VECTOR_DIR / vector["output_schema"]).read_text("utf-8")) == (
        protocol["output_schema"]
    )
    cases = json.loads((VECTOR_DIR / vector["operation_vectors"]).read_text("utf-8"))
    assert cases["canonicalization"] == protocol["canonicalization"]
    assert cases["error_model"] == protocol["error_model"]
    assert cases["identifier_rules"] == protocol["identifier_rules"]
    assert cases["operation_rules"] == protocol["operation_rules"]
    assert cases["semantics"] == protocol["semantics"]
    assert cases["wire_limits"] == protocol["wire_limits"]
    CapabilitySchemas(MESSAGE_STORE_INPUT_SCHEMA, MESSAGE_STORE_OUTPUT_SCHEMA)


def test_message_store_contract_has_bounded_non_authoritative_profile() -> None:
    assert MESSAGE_STORE_CAPABILITY_ID == "org.nth-dao.message.store"
    assert MESSAGE_STORE_CONTRACT.consistency == "C2"
    assert MESSAGE_STORE_CONTRACT.effects == ("none",)
    assert MESSAGE_STORE_CONTRACT.privacy == "confidential"
    assert MESSAGE_STORE_CONTRACT.retention == "ephemeral"
    assert MESSAGE_STORE_CONTRACT.failure_semantics == "at-most-once"


def test_message_store_error_model_is_closed_and_machine_readable() -> None:
    assert MESSAGE_STORE_ERROR_MODEL
    assert all(
        set(specification) == {"meaning", "retryable"}
        for specification in MESSAGE_STORE_ERROR_MODEL.values()
    )
    error = MessageStoreOperationError("quota-exceeded", "capacity is full")
    assert error.code == "quota-exceeded"
    assert error.retryable is True
    assert error.detail == "capacity is full"
    with pytest.raises(ValueError, match="unsupported"):
        MessageStoreOperationError("invented", "not part of the wire contract")


def test_message_store_error_model_is_immutable_and_digest_stable() -> None:
    before = message_store_protocol_digest()
    with pytest.raises(TypeError):
        MESSAGE_STORE_ERROR_MODEL["quota-exceeded"]["retryable"] = False  # type: ignore[index]
    with pytest.raises(TypeError):
        MESSAGE_STORE_ERROR_MODEL["invented"] = {  # type: ignore[index]
            "meaning": "mutable drift",
            "retryable": True,
        }
    assert message_store_protocol_digest() == before


@pytest.mark.parametrize(
    "document",
    [
        {"operation": "probe"},
        {
            "operation": "put",
            "namespace": "group:alpha/channel:general",
            "message_id": "message-1",
            "message_json": _message_json(),
            "message_sha256": message_store_message_digest(_message_json()),
            "retention_mode": "session",
            "delivery_mode": "read-many",
            "expires_at_ms": 0,
        },
        {
            "operation": "list",
            "namespace": "group:alpha/channel:general",
            "after_sequence": 0,
            "limit": 50,
        },
        {
            "operation": "get",
            "namespace": "group:alpha/channel:general",
            "message_id": "message-1",
        },
        {
            "operation": "consume",
            "namespace": "group:alpha/channel:general",
            "message_id": "message-1",
            "expected_message_sha256": message_store_message_digest(_message_json()),
            "expected_sequence": 1,
        },
        {
            "operation": "delete",
            "namespace": "group:alpha/channel:general",
            "message_id": "message-1",
            "expected_message_sha256": message_store_message_digest(_message_json()),
            "expected_sequence": 1,
        },
    ],
)
def test_message_store_valid_inputs(document: dict) -> None:
    validate_message_store_input(document)


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ({"operation": "probe", "namespace": "hidden"}, "does not accept"),
        (
            {
                "operation": "get",
                "namespace": "../escape",
                "message_id": "message-1",
            },
            "namespace",
        ),
        (
            {
                "operation": "put",
                "namespace": "group:alpha",
                "message_id": "message-1",
                "message_json": '{"kind": "chat"}',
                "message_sha256": "0" * 64,
                "retention_mode": "session",
                "delivery_mode": "read-many",
                "expires_at_ms": 0,
            },
            "canonical",
        ),
        (
            {
                "operation": "put",
                "namespace": "group:alpha",
                "message_id": "message-1",
                "message_json": _message_json(),
                "message_sha256": "0" * 64,
                "retention_mode": "session",
                "delivery_mode": "read-many",
                "expires_at_ms": 0,
            },
            "does not bind",
        ),
        (
            {
                "operation": "put",
                "namespace": "group:alpha",
                "message_id": "message-1",
                "message_json": _message_json(),
                "message_sha256": message_store_message_digest(_message_json()),
                "retention_mode": "ttl",
                "delivery_mode": "read-many",
                "expires_at_ms": 0,
            },
            "requires an expiry",
        ),
    ],
)
def test_message_store_rejects_semantic_input_failures(document: dict, message: str) -> None:
    with pytest.raises(PluginSchemaError, match=message):
        validate_message_store_input(document)


def test_message_store_rejects_non_object_and_duplicate_key_payloads() -> None:
    base = {
        "operation": "put",
        "namespace": "group:alpha",
        "message_id": "message-1",
        "message_sha256": "0" * 64,
        "retention_mode": "session",
        "delivery_mode": "read-many",
        "expires_at_ms": 0,
    }
    with pytest.raises(PluginSchemaError, match="JSON object"):
        validate_message_store_input({**base, "message_json": "[]"})
    with pytest.raises(PluginSchemaError, match="canonical"):
        validate_message_store_input({**base, "message_json": '{"a":1,"a":1}'})


def test_message_store_rejects_cross_language_unsafe_message_integer() -> None:
    message_json = '{"value":9007199254740992}'
    document = {
        "operation": "put",
        "namespace": "group:alpha",
        "message_id": "message-1",
        "message_json": message_json,
        "message_sha256": hashlib.sha256(message_json.encode("utf-8")).hexdigest(),
        "retention_mode": "session",
        "delivery_mode": "read-many",
        "expires_at_ms": 0,
    }
    with pytest.raises(PluginSchemaError, match="safe range"):
        validate_message_store_input(document)


@pytest.mark.parametrize(
    "message_json",
    [
        '{"\ue000":1,"\U0001f600":2}',
        '{"outer":{"\u952e":"value"}}',
        '{"":true}',
    ],
)
def test_message_store_rejects_non_portable_object_keys(message_json: str) -> None:
    document = {
        "operation": "put",
        "namespace": "group:alpha",
        "message_id": "message-1",
        "message_json": message_json,
        "message_sha256": hashlib.sha256(message_json.encode("utf-8")).hexdigest(),
        "retention_mode": "session",
        "delivery_mode": "read-many",
        "expires_at_ms": 0,
    }
    with pytest.raises(PluginSchemaError, match="printable ASCII"):
        validate_message_store_input(document)


def test_message_store_accepts_unicode_values_with_ascii_keys() -> None:
    message_json = canonical_json(
        {"body": "\u4f60\u597d \U0001f600", "metadata": {"label": "\u4ea4\u4ed8"}}
    ).decode("utf-8")
    document = {
        "operation": "put",
        "namespace": "group:alpha",
        "message_id": "message-1",
        "message_json": message_json,
        "message_sha256": hashlib.sha256(message_json.encode("utf-8")).hexdigest(),
        "retention_mode": "session",
        "delivery_mode": "read-many",
        "expires_at_ms": 0,
    }
    validate_message_store_input(document)


def test_message_store_rejects_dot_path_segments() -> None:
    with pytest.raises(ValueError, match="invalid"):
        validate_message_store_identifier("group:alpha/../beta", field="namespace")


@pytest.mark.parametrize(
    "namespace",
    [
        "C:/Windows/System32",
        "group:alpha/",
        "group:alpha:",
        "group::alpha",
        "group:alpha//general",
        "group:/alpha",
    ],
)
def test_message_store_rejects_path_like_or_ambiguous_namespaces(
    namespace: str,
) -> None:
    with pytest.raises(ValueError, match="invalid"):
        validate_message_store_identifier(namespace, field="namespace")


def test_message_store_wire_byte_limit_uses_utf8_not_char_count() -> None:
    document = {
        "operation": "put",
        "namespace": "group:alpha",
        "message_id": "message-1",
        "message_json": '{"body":"' + ("\U0001f600" * 140_000) + '"}',
        "message_sha256": "0" * 64,
        "retention_mode": "session",
        "delivery_mode": "read-many",
        "expires_at_ms": 0,
    }
    validate_instance(document, MESSAGE_STORE_INPUT_SCHEMA, path="$input")
    with pytest.raises(PluginSchemaError, match="UTF-8 byte limit"):
        validate_message_store_input(document)
    assert len(canonical_json(document)) < MESSAGE_STORE_MAX_DOCUMENT_BYTES


def test_message_store_operation_rules_are_closed() -> None:
    allowed, required = message_store_operation_rule("put")
    assert required == allowed
    assert "principal" not in allowed
    with pytest.raises(ValueError, match="unsupported"):
        message_store_operation_rule("execute")
    with pytest.raises(ValueError, match="unsupported"):
        validate_message_store_identifier("message-1", field="principal")
    for operation in ("consume", "delete"):
        allowed, required = message_store_operation_rule(operation)
        assert required == allowed
        assert {"expected_message_sha256", "expected_sequence"} <= required


def test_message_store_destructive_operations_require_cas_fields() -> None:
    for operation in ("consume", "delete"):
        with pytest.raises(PluginSchemaError, match="requires fields"):
            validate_message_store_input(
                {
                    "operation": operation,
                    "namespace": "group:alpha/channel:general",
                    "message_id": "message-1",
                }
            )


@pytest.mark.parametrize(
    "document",
    [
        _base_output("probe"),
        _record_output("put"),
        _record_output("get", content=True),
        _record_output("consume", content=True),
        {**_base_output("delete"), "found": True, "deleted": True},
        {
            **_base_output("list"),
            "found": True,
            "items": [
                {
                    key: value
                    for key, value in _record_output("put").items()
                    if key
                    in {
                        "created_at_ms",
                        "delivery_mode",
                        "expires_at_ms",
                        "message_id",
                        "message_sha256",
                        "retention_mode",
                        "sequence",
                    }
                }
            ],
            "next_sequence": 1,
        },
    ],
)
def test_message_store_valid_outputs(document: dict) -> None:
    validate_message_store_output(document)


def test_message_store_rejects_output_state_contradictions() -> None:
    bad_get = _record_output("get", content=True)
    bad_get["delivery_mode"] = "consume-on-read"
    with pytest.raises(PluginSchemaError, match="repeatable"):
        validate_message_store_output(bad_get)

    bad_consume = _record_output("consume", content=True)
    bad_consume["deleted"] = False
    with pytest.raises(PluginSchemaError, match="atomically delete"):
        validate_message_store_output(bad_consume)

    bad_list = _base_output("list")
    bad_list["found"] = True
    with pytest.raises(PluginSchemaError, match="flags"):
        validate_message_store_output(bad_list)

    skipped_cursor = {
        **_base_output("list"),
        "found": True,
        "items": [
            {
                key: value
                for key, value in _record_output("put").items()
                if key
                in {
                    "created_at_ms",
                    "delivery_mode",
                    "expires_at_ms",
                    "message_id",
                    "message_sha256",
                    "retention_mode",
                    "sequence",
                }
            }
        ],
        "next_sequence": 2,
    }
    with pytest.raises(PluginSchemaError, match="equal the final item"):
        validate_message_store_output(skipped_cursor)

    bad_put = _record_output("put")
    bad_put["message_sha256"] = "A" * 64
    with pytest.raises(PluginSchemaError, match="message_sha256"):
        validate_message_store_output(bad_put)

    missing_put = _base_output("put")
    with pytest.raises(PluginSchemaError, match="identify the stored record"):
        validate_message_store_output(missing_put)

    false_probe = _base_output("probe")
    false_probe["found"] = True
    with pytest.raises(PluginSchemaError, match="record or listing"):
        validate_message_store_output(false_probe)

    unsupported_mode = _record_output("put")
    unsupported_mode["supported_delivery_modes"] = ["consume-on-read"]
    with pytest.raises(PluginSchemaError, match="not advertised"):
        validate_message_store_output(unsupported_mode)

    unsupported_list_mode = {**skipped_cursor, "next_sequence": 1}
    unsupported_list_mode["supported_delivery_modes"] = ["consume-on-read"]
    with pytest.raises(PluginSchemaError, match="list delivery mode"):
        validate_message_store_output(unsupported_list_mode)


def test_message_store_checked_in_wire_examples_validate() -> None:
    vector = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    cases = json.loads((VECTOR_DIR / vector["operation_vectors"]).read_text("utf-8"))
    for document in cases["valid_inputs"]:
        validate_message_store_input(document)
    for document in cases["valid_outputs"]:
        validate_message_store_output(document)
    for case in cases["invalid_semantic_inputs"]:
        validate_instance(case["document"], MESSAGE_STORE_INPUT_SCHEMA, path="$input")
        with pytest.raises(PluginSchemaError):
            validate_message_store_input(case["document"])
    for case in cases["invalid_operation_inputs"]:
        validate_instance(case["document"], MESSAGE_STORE_INPUT_SCHEMA, path="$input")
        with pytest.raises(PluginSchemaError):
            validate_message_store_input(case["document"])
    for case in cases["invalid_semantic_outputs"]:
        validate_instance(case["document"], MESSAGE_STORE_OUTPUT_SCHEMA, path="$output")
        with pytest.raises(PluginSchemaError):
            validate_message_store_output(case["document"])
    for case in cases["invalid_message_documents"]:
        with pytest.raises(ValueError):
            canonical_message_document(case["canonical_utf8"])
    for case in cases["canonical_examples"]:
        encoded = canonical_json(case["document"])
        assert encoded.decode("utf-8") == case["canonical_utf8"]
        assert hashlib.sha256(encoded).hexdigest() == case["sha256"]


def test_node_consumer_matches_message_store_conformance_vectors() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is unavailable for cross-language conformance")
    script = r"""
const crypto = require("crypto");
const fs = require("fs");
function canonical(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("non-integer number");
    return String(value);
  }
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (typeof value === "object") {
    return "{" + Object.keys(value).sort().map(
      key => JSON.stringify(key) + ":" + canonical(value[key])
    ).join(",") + "}";
  }
  throw new Error("unsupported JSON value");
}
function assertPortableKeys(value) {
  if (Array.isArray(value)) {
    for (const item of value) assertPortableKeys(item);
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const key of Object.keys(value)) {
    if (!/^[\x20-\x7E]{1,256}$/.test(key)) throw new Error("non-portable key");
    assertPortableKeys(value[key]);
  }
}
function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}
function assertOperationShape(input, operationRules) {
  const rule = operationRules[input.operation];
  if (!rule) throw new Error("unsupported operation");
  const keys = Object.keys(input);
  for (const required of rule.required) {
    if (!keys.includes(required)) throw new Error("missing operation field");
  }
  for (const key of keys) {
    if (!rule.allowed.includes(key)) throw new Error("unexpected operation field");
  }
}
function executeScenario(scenario, errorModel) {
  const records = new Map();
  const tombstones = new Map();
  let sequence = 0;
  const nowMs = 1750000000000;
  function invoke(input) {
    const key = input.namespace + "\u0000" + input.message_id;
    if (input.operation === "put") {
      if (input.retention_mode === "ttl" && input.expires_at_ms <= nowMs) {
        fail("expired");
      }
      const digest = crypto.createHash("sha256")
        .update(input.message_json, "utf8").digest("hex");
      if (digest !== input.message_sha256) fail("conflict");
      const current = records.get(key);
      if (current) fail("conflict");
      sequence += 1;
      const record = {...input, sequence};
      records.set(key, record);
      return {found: true, replayed: false, sequence};
    }
    const current = records.get(key);
    if (input.operation === "get") {
      if (!current) return {found: false};
      if (current.delivery_mode !== "read-many") {
        fail("unsupported-delivery-mode");
      }
      return {
        found: true,
        message_json: current.message_json,
        message_sha256: current.message_sha256,
        sequence: current.sequence,
      };
    }
    if (input.operation === "consume" || input.operation === "delete") {
      if (!current) {
        const tombstone = tombstones.get(key);
        if (tombstone
            && tombstone.sequence === input.expected_sequence
            && tombstone.message_sha256 === input.expected_message_sha256) {
          fail("already-applied");
        }
        fail("generation-not-found");
      }
      if (current.sequence !== input.expected_sequence
          || current.message_sha256 !== input.expected_message_sha256) {
        fail("stale-generation");
      }
      if (input.operation === "consume"
          && current.delivery_mode !== "consume-on-read") {
        fail("unsupported-delivery-mode");
      }
      tombstones.set(key, {
        message_sha256: current.message_sha256,
        operation: input.operation,
        sequence: current.sequence,
      });
      records.delete(key);
      const response = {deleted: true, found: true};
      if (input.operation === "consume") {
        response.message_json = current.message_json;
        response.message_sha256 = current.message_sha256;
        response.sequence = current.sequence;
      }
      return response;
    }
    fail("unsupported-operation");
  }
  for (const step of scenario.steps) {
    if (step.expected_error) {
      if (!(step.expected_error in errorModel)) {
        throw new Error("scenario uses an undeclared error code");
      }
      let actual = "";
      try { invoke(step.input); }
      catch (error) { actual = error.code || ""; }
      if (actual !== step.expected_error) {
        throw new Error("state transition error mismatch");
      }
      continue;
    }
    const response = invoke(step.input);
    for (const [key, expected] of Object.entries(step.expected_fields)) {
      if (response[key] !== expected) {
        throw new Error("state transition output mismatch");
      }
    }
  }
}
const vectors = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
for (const input of vectors.valid_inputs) {
  assertOperationShape(input, vectors.operation_rules);
}
for (const item of vectors.invalid_operation_inputs) {
  let rejected = false;
  try { assertOperationShape(item.document, vectors.operation_rules); }
  catch (error) { rejected = true; }
  if (!rejected) throw new Error("invalid operation input was accepted");
}
for (const item of vectors.canonical_examples) {
  assertPortableKeys(item.document);
  const encoded = canonical(item.document);
  if (encoded !== item.canonical_utf8) throw new Error("canonical bytes mismatch");
  const digest = crypto.createHash("sha256").update(encoded, "utf8").digest("hex");
  if (digest !== item.sha256) throw new Error("canonical digest mismatch");
}
for (const item of vectors.invalid_message_documents) {
  let rejected = false;
  try { assertPortableKeys(JSON.parse(item.canonical_utf8)); }
  catch (error) { rejected = true; }
  if (!rejected) throw new Error("invalid message document was accepted");
}
for (const scenario of vectors.state_transition_vectors) {
  executeScenario(scenario, vectors.error_model);
}
"""
    vector = VECTOR_DIR / "message-store-wire-cases-v1.json"
    result = subprocess.run(
        [node, "-e", script, str(vector)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout
