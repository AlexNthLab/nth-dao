"""Conformance checks for the language-neutral agent provider contract."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import typing

import pytest

from nth_dao.canonical_json import canonical_json
from nth_dao.plugins.agent_provider import (
    AGENT_SESSION_CAPABILITY_ID,
    AGENT_SESSION_CONTRACT,
    AGENT_SESSION_INPUT_SCHEMA,
    AGENT_SESSION_MAX_DOCUMENT_BYTES,
    AGENT_SESSION_OUTPUT_SCHEMA,
    AGENT_SESSION_LEGACY_CAPABILITY_VERSION,
    AGENT_SESSION_V1_CONTRACT,
    AGENT_SESSION_V1_OUTPUT_SCHEMA,
    agent_session_operation_rule,
    agent_session_protocol_digest,
    agent_session_protocol_document,
    capability_document,
    validate_agent_session_identifier,
    validate_agent_session_input,
    validate_agent_session_output,
)
from nth_dao.plugins.host import CapabilitySchemas
from nth_dao.plugins.schema import PluginSchemaError, validate_instance


VECTOR_PATH = (
    Path(__file__).parents[1]
    / "nth_dao"
    / "plugins"
    / "vectors"
    / "agent-session-capability-v2.json"
)
VECTOR_DIR = VECTOR_PATH.parent
LEGACY_VECTOR_PATH = VECTOR_DIR / "agent-session-capability-v1.json"


def test_agent_session_contract_matches_checked_in_vector() -> None:
    vector = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    assert vector["format"] == "nth-dao-plugin-capability-conformance-v1"
    assert vector["schema_version"] == 2
    assert vector["capability"] == AGENT_SESSION_CONTRACT.to_dict()
    assert vector["expected_digest"] == AGENT_SESSION_CONTRACT.digest
    input_schema = json.loads(
        (VECTOR_DIR / vector["input_schema"]).read_text(encoding="utf-8")
    )
    output_schema = json.loads(
        (VECTOR_DIR / vector["output_schema"]).read_text(encoding="utf-8")
    )
    cases = json.loads(
        (VECTOR_DIR / vector["operation_vectors"]).read_text(encoding="utf-8")
    )
    protocol = agent_session_protocol_document()
    assert input_schema == protocol["input_schema"] == AGENT_SESSION_INPUT_SCHEMA
    assert output_schema == protocol["output_schema"] == AGENT_SESSION_OUTPUT_SCHEMA
    assert cases["operation_rules"] == protocol["operation_rules"]
    assert cases["identifier_rules"] == protocol["identifier_rules"]
    assert cases["output_rules"] == protocol["output_rules"]
    assert cases["wire_limits"] == protocol["wire_limits"]
    assert cases["wire_limits"]["max_document_bytes"] == (
        AGENT_SESSION_MAX_DOCUMENT_BYTES
    )
    assert vector["expected_protocol_digest"] == agent_session_protocol_digest()
    CapabilitySchemas(AGENT_SESSION_INPUT_SCHEMA, AGENT_SESSION_OUTPUT_SCHEMA)


def test_legacy_agent_session_contract_and_vectors_remain_verifiable() -> None:
    vector = json.loads(LEGACY_VECTOR_PATH.read_text(encoding="utf-8"))
    assert vector["schema_version"] == 1
    assert vector["capability"] == AGENT_SESSION_V1_CONTRACT.to_dict()
    assert vector["expected_digest"] == AGENT_SESSION_V1_CONTRACT.digest
    assert vector["expected_protocol_digest"] == agent_session_protocol_digest(
        AGENT_SESSION_LEGACY_CAPABILITY_VERSION
    )
    output_schema = json.loads(
        (VECTOR_DIR / vector["output_schema"]).read_text(encoding="utf-8")
    )
    assert output_schema == AGENT_SESSION_V1_OUTPUT_SCHEMA
    cases = json.loads(
        (VECTOR_DIR / vector["operation_vectors"]).read_text(encoding="utf-8")
    )
    for document in cases["valid_outputs"]:
        validate_agent_session_output(
            document,
            version=AGENT_SESSION_LEGACY_CAPABILITY_VERSION,
        )
        with pytest.raises(PluginSchemaError):
            validate_agent_session_output(document)


def test_agent_session_cross_implementation_wire_cases() -> None:
    vector = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    cases = json.loads(
        (VECTOR_DIR / vector["operation_vectors"]).read_text(encoding="utf-8")
    )
    for document in cases["valid_inputs"]:
        validate_agent_session_input(document)
    for case in cases["invalid_inputs"]:
        document = case["document"]
        validate_instance(document, AGENT_SESSION_INPUT_SCHEMA, path="$input")
        allowed, required = agent_session_operation_rule(document["operation"])
        operation_valid = set(document) <= allowed and required <= set(document)
        identifiers_valid = True
        for field in ("session_id", "turn_id"):
            if field not in document:
                continue
            try:
                validate_agent_session_identifier(document[field], field=field)
            except ValueError:
                identifiers_valid = False
        assert not (operation_valid and identifiers_valid), case["reason"]
    for document in cases["valid_outputs"]:
        validate_agent_session_output(document)
    for case in cases["invalid_outputs"]:
        with pytest.raises(PluginSchemaError):
            validate_instance(
                case["document"],
                AGENT_SESSION_OUTPUT_SCHEMA,
                path="$output",
            )
    for case in cases["invalid_semantic_outputs"]:
        validate_instance(
            case["document"],
            AGENT_SESSION_OUTPUT_SCHEMA,
            path="$output",
        )
        with pytest.raises(PluginSchemaError):
            validate_agent_session_output(case["document"])
    for case in cases["canonical_examples"]:
        encoded = canonical_json(case["document"])
        assert encoded.decode("utf-8") == case["canonical_utf8"]
        assert f"sha256:{hashlib.sha256(encoded).hexdigest()}" == case["sha256"]


def test_node_consumer_matches_agent_session_canonical_vectors() -> None:
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
const vectors = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
for (const item of vectors.canonical_examples) {
  const encoded = canonical(item.document);
  if (encoded !== item.canonical_utf8) throw new Error("canonical bytes mismatch");
  const digest = "sha256:" + crypto.createHash("sha256").update(encoded, "utf8").digest("hex");
  if (digest !== item.sha256) throw new Error("canonical digest mismatch");
}
"""
    result = subprocess.run(
        [node, "-e", script, str(VECTOR_DIR / "agent-session-wire-cases-v2.json")],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout


def test_agent_session_input_is_closed_and_bounded() -> None:
    validate_instance(
        {
            "operation": "turn",
            "session_id": "session-1",
            "prompt": "hello",
            "system_prompt": "be concise",
            "timeout_ms": 10_000,
            "turn_id": "turn-1",
        },
        AGENT_SESSION_INPUT_SCHEMA,
        path="$input",
    )
    with pytest.raises(PluginSchemaError, match="unknown fields"):
        validate_instance(
            {"operation": "probe", "command": "arbitrary"},
            AGENT_SESSION_INPUT_SCHEMA,
        )


def test_agent_session_wire_byte_limit_is_normative() -> None:
    document = {
        "operation": "turn",
        "session_id": "session-1",
        "turn_id": "turn-1",
        "prompt": "\U0001f600" * 262_144,
    }
    validate_instance(document, AGENT_SESSION_INPUT_SCHEMA, path="$input")
    with pytest.raises(PluginSchemaError, match="canonical UTF-8 bytes"):
        validate_agent_session_input(document)
    with pytest.raises(PluginSchemaError, match="too long"):
        validate_instance(
            {
                "operation": "turn",
                "session_id": "session-1",
                "prompt": "x" * 262_145,
            },
            AGENT_SESSION_INPUT_SCHEMA,
        )


def test_agent_session_contract_declares_confidential_at_most_once_calls() -> None:
    assert AGENT_SESSION_CONTRACT.capability_id == AGENT_SESSION_CAPABILITY_ID
    assert AGENT_SESSION_CONTRACT.privacy == "confidential"
    assert AGENT_SESSION_CONTRACT.failure_semantics == "at-most-once"
    assert AGENT_SESSION_CONTRACT.retention == "ephemeral"
    assert AGENT_SESSION_CONTRACT.effects == ("none",)


def test_capability_projection_rejects_invalid_metadata_instead_of_coercing() -> None:
    class Capabilities:
        max_context_tokens = 1
        notes = "ok"
        supports_multi_turn = True
        supports_streaming = False
        supports_system_prompt = True
        supports_temperature = False
        supports_tools = False

    assert capability_document(Capabilities())["supports_streaming"] is False
    Capabilities.supports_streaming = "false"
    with pytest.raises(ValueError, match="booleans"):
        capability_document(Capabilities())
    Capabilities.supports_streaming = False
    Capabilities.max_context_tokens = -1
    with pytest.raises(ValueError, match="non-negative"):
        capability_document(Capabilities())


def test_agent_session_wire_module_does_not_import_legacy_backend_package() -> None:
    source_path = (
        Path(__file__).parents[1] / "nth_dao" / "plugins" / "agent_provider.py"
    )
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
    assert all(not name.startswith("team_layer") for name in imported)


def test_agent_session_wire_import_does_not_execute_legacy_backend_package() -> None:
    root = Path(__file__).parents[1]
    script = (
        "import sys; import nth_dao.plugins.agent_provider; "
        "loaded=sorted(n for n in sys.modules if n.startswith('team_layer')); "
        "assert not loaded, loaded"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout


def test_facade_attach_remains_callable_after_submodule_import() -> None:
    """Import machinery must not replace the public attach function."""
    import importlib

    import nth_dao

    importlib.import_module("nth_dao.attach")
    assert callable(nth_dao.attach)


def test_facade_runtime_annotations_do_not_require_legacy_backend_import() -> None:
    import importlib

    import nth_dao

    attach_module = importlib.import_module("nth_dao.attach")
    hints = typing.get_type_hints(nth_dao.attach)
    session_hints = typing.get_type_hints(nth_dao.TeamSession)
    assert "Any" not in str(hints["backend"])
    assert session_hints["backend"] == (
        attach_module._RuntimeAgentBackend | None
    )
