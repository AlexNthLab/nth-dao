"""Conformance and negative tests for the market.index wire contract."""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from pathlib import Path
import shutil
import subprocess

import pytest

from nth_dao.canonical_json import canonical_json
from nth_dao.plugins.market_index import (
    MARKET_INDEX_CAPABILITY_ID,
    MARKET_INDEX_CONTRACT,
    MARKET_INDEX_ERROR_MODEL,
    MARKET_INDEX_MAX_CURSOR_CHARS,
    MARKET_INDEX_MAX_CURSOR_AGE_MS,
    MARKET_INDEX_MAX_ENTRY_BYTES,
    MARKET_INDEX_STALE_RETENTION_MS,
    MarketIndexOperationError,
    canonical_market_index_entry,
    is_market_index_protocol_contract,
    is_market_index_wire_compatible_contract,
    market_index_entry_digest,
    market_index_protocol_digest,
    market_index_protocol_document,
    market_index_provider_allowed,
    market_index_provider_contract,
    market_index_vector_documents,
    market_index_wire_vectors,
    validate_market_index_exchange,
    validate_market_index_input,
    validate_market_index_output,
)
from nth_dao.plugins.schema import PluginSchemaError


PUBLISHER_DID = "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd"
VECTOR_DIR = Path(__file__).parents[1] / "nth_dao" / "plugins" / "vectors"


def _entry(
    entry_id: str = "task:alpha",
    *,
    title: str = "Review alpha",
    origin: str = "local",
    source_peer: str = "",
) -> dict:
    return {
        "capabilities": ["code.review"],
        "categories": ["tasks"],
        "entry_id": entry_id,
        "intents": ["request"],
        "last_verified_at_ms": 1_750_000_000_100,
        "not_after_ms": 1_750_086_400_000,
        "origin": origin,
        "projection_only": True,
        "published_at_ms": 1_750_000_000_000,
        "publisher_did": PUBLISHER_DID,
        "source_digest": "sha256:" + "a" * 64,
        "source_locator": "nth://market/task/alpha",
        "source_object_id": "announcement-alpha",
        "source_peer": source_peer,
        "source_protocol": "org.nth-dao.market.task-announcement.v3",
        "stale": False,
        "summary": "Inspect the signed source before claiming.",
        "title": title,
        "version": "1",
    }


def _entry_json(**kwargs) -> str:
    return canonical_json(_entry(**kwargs)).decode("utf-8")


def _base_output(operation: str) -> dict:
    return {
        "changed": False,
        "detail": "",
        "entry_id": "",
        "entry_json": "",
        "entry_sha256": "",
        "found": False,
        "index_id": "org.nth-dao.market.memory-index",
        "items": [],
        "max_entries_per_principal": 2_048,
        "max_entry_bytes": MARKET_INDEX_MAX_ENTRY_BYTES,
        "next_cursor": "",
        "operation": operation,
        "ready": True,
        "removed": False,
        "replayed": False,
        "revision": 0,
    }


def test_market_index_contract_is_non_authoritative_and_retry_safe() -> None:
    assert MARKET_INDEX_CAPABILITY_ID == "org.nth-dao.market.index"
    assert MARKET_INDEX_CONTRACT.effects == ("none",)
    assert MARKET_INDEX_CONTRACT.security == "verified-input"
    assert MARKET_INDEX_CONTRACT.privacy == "public"
    assert MARKET_INDEX_CONTRACT.retention == "ephemeral"
    assert MARKET_INDEX_CONTRACT.failure_semantics == "retry-safe"
    assert (
        market_index_protocol_document()["semantics"]["authority"]
        == "search-projection-only-resolve-and-reverify-source-before-action"
    )


def test_market_index_provider_profiles_separate_wire_shape_from_host_policy() -> None:
    network = market_index_provider_contract(
        effects=("network-read", "network-write"),
        consistency="C1",
        retention="durable",
    )

    assert network.digest != MARKET_INDEX_CONTRACT.digest
    assert network.input_schema_digest == MARKET_INDEX_CONTRACT.input_schema_digest
    assert network.output_schema_digest == MARKET_INDEX_CONTRACT.output_schema_digest
    assert is_market_index_wire_compatible_contract(network) is True
    assert is_market_index_protocol_contract(network) is True
    assert market_index_provider_allowed(network, allowed_effects=()) is False
    assert (
        market_index_provider_allowed(network, allowed_effects=("network-read",))
        is False
    )
    assert market_index_provider_allowed(
        network,
        allowed_effects=("network-read", "network-write"),
    ) is True
    assert market_index_provider_allowed(
        MARKET_INDEX_CONTRACT,
        allowed_effects=(),
    ) is True


def test_market_index_wire_compatibility_does_not_accept_unsafe_semantics() -> None:
    network = market_index_provider_contract(effects=("network-read",))
    authoritative = replace(network, security="authoritative")
    wrong_schema = replace(network, output_schema_digest="sha256:" + "0" * 64)

    assert is_market_index_wire_compatible_contract(authoritative) is True
    assert is_market_index_protocol_contract(authoritative) is False
    assert market_index_provider_allowed(
        authoritative,
        allowed_effects=("network-read",),
    ) is False
    assert is_market_index_wire_compatible_contract(wrong_schema) is False
    with pytest.raises(TypeError):
        market_index_provider_allowed(network, allowed_effects="network-read")
    with pytest.raises(ValueError):
        market_index_provider_allowed(network, allowed_effects=("none",))


def test_market_index_protocol_digest_and_error_model_are_stable() -> None:
    before = market_index_protocol_digest()
    assert before.startswith("sha256:")
    assert set(MARKET_INDEX_ERROR_MODEL) >= {
        "conflict",
        "invalid-cursor",
        "quota-exceeded",
        "stale-cursor",
    }
    with pytest.raises(TypeError):
        MARKET_INDEX_ERROR_MODEL["conflict"]["retryable"] = True  # type: ignore[index]
    assert market_index_protocol_digest() == before
    error = MarketIndexOperationError("stale-cursor", "index changed")
    assert error.retryable is True


def test_market_index_checked_in_vectors_match_reference_implementation() -> None:
    generated = market_index_vector_documents()
    assert generated
    for filename, expected in generated.items():
        stored = json.loads((VECTOR_DIR / filename).read_text(encoding="utf-8"))
        assert stored == expected
    for request in generated["market-index-wire-cases-v1.json"]["positive_inputs"]:
        validate_market_index_input(request)
    wire = generated["market-index-wire-cases-v1.json"]
    for output in wire["positive_outputs"]:
        validate_market_index_output(output)
    for exchange in wire["positive_exchanges"]:
        validate_market_index_exchange(exchange["request"], exchange["response"])
    assert wire["entry_rules"] == market_index_protocol_document()["entry_rules"]
    for case in wire["negative_entries"]:
        with pytest.raises(ValueError):
            canonical_market_index_entry(case["entry_json"])
    for case in wire["negative_inputs"]:
        with pytest.raises(PluginSchemaError):
            validate_market_index_input(case["input"])
    for case in wire["negative_outputs"]:
        with pytest.raises(
            PluginSchemaError,
            match=case["expected_error_contains"],
        ):
            validate_market_index_output(case["output"])
    for case in wire["negative_exchanges"]:
        validate_market_index_input(case["request"])
        validate_market_index_output(case["response"])
        with pytest.raises(
            PluginSchemaError,
            match=case["expected_error_contains"],
        ):
            validate_market_index_exchange(case["request"], case["response"])


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_market_index_vector_canonicalizes_identically_in_node() -> None:
    vector = json.loads(
        (VECTOR_DIR / "market-index-wire-cases-v1.json").read_text(encoding="utf-8")
    )
    script = r"""
const crypto = require("crypto");
const value = JSON.parse(process.argv[1]);
function canonical(item) {
  if (Array.isArray(item)) return item.map(canonical);
  if (item !== null && typeof item === "object") {
    const out = {};
    for (const key of Object.keys(item).sort()) out[key] = canonical(item[key]);
    return out;
  }
  return item;
}
const encoded = JSON.stringify(canonical(value));
const digest = crypto.createHash("sha256").update(encoded, "utf8").digest("hex");
process.stdout.write(JSON.stringify({encoded, digest}));
"""
    completed = subprocess.run(
        [shutil.which("node") or "node", "-e", script, json.dumps(vector["valid_entry"])],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    result = json.loads(completed.stdout)
    assert result["encoded"] == vector["valid_entry_json"]
    assert result["digest"] == vector["valid_entry_sha256"]


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_market_index_output_and_exchange_vectors_reject_identically_in_node() -> None:
    script = r"""
const crypto = require("crypto");
const fs = require("fs");
const vector = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
function fail(message) { throw new Error(message); }
function digest(text) {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}
function validateEntry(item) {
  if (digest(item.entry_json) !== item.entry_sha256) {
    fail("entry_sha256 does not bind entry_json");
  }
  return JSON.parse(item.entry_json);
}
function compareRank(left, right) {
  if (left[0] !== right[0]) return left[0] - right[0];
  if (left[1] !== right[1]) return left[1] - right[1];
  return left[2].localeCompare(right[2]);
}
function validateOutput(value) {
  if (value.operation === "search") {
    if (value.found !== (value.items.length > 0)) {
      fail("found flag does not match items");
    }
    const seen = new Set();
    const rank = value.items.map((item) => {
      const entry = validateEntry(item);
      if (seen.has(item.entry_id)) fail("search entry ids must be unique");
      seen.add(item.entry_id);
      return [-item.score, -entry.published_at_ms, item.entry_id];
    });
    const sorted = [...rank].sort(compareRank);
    if (JSON.stringify(rank) !== JSON.stringify(sorted)) {
      fail("search items are not in stable rank order");
    }
    return;
  }
  if (value.operation === "get" && value.found) validateEntry(value);
  if (value.operation === "upsert") {
    if (!value.found || !value.entry_id || !value.entry_sha256
        || value.removed || value.changed === value.replayed) {
      fail("upsert flags are inconsistent");
    }
  }
  if (value.operation === "remove") {
    if (value.found || !value.removed || !value.entry_id
        || value.changed === value.replayed) {
      fail("remove flags are inconsistent");
    }
  }
}
function validateExchange(request, response) {
  if (response.operation !== request.operation) {
    fail("operation does not match");
  }
  if (request.operation === "search") {
    if (response.items.length > request.limit) fail("items exceed");
    for (const item of response.items) {
      const entry = validateEntry(item);
      if (request.categories.length > 0
          && !entry.categories.some((value) => request.categories.includes(value))) {
        fail("categories");
      }
      if (request.intents.length > 0
          && !entry.intents.some((value) => request.intents.includes(value))) {
        fail("intents");
      }
      if (request.source_protocols.length > 0
          && !request.source_protocols.includes(entry.source_protocol)) {
        fail("source_protocols");
      }
      if (entry.stale && !request.include_stale) fail("include_stale");
    }
    return;
  }
  if (request.operation === "probe") return;
  if (request.operation === "get") {
    if (response.found && response.entry_id !== request.entry_id) {
      fail("entry_id does not match");
    }
    return;
  }
  const expected = request.operation === "upsert"
    ? request.entry_sha256 : request.expected_entry_sha256;
  if (response.entry_id !== request.entry_id) fail("entry_id does not match");
  if (response.entry_sha256 !== expected) fail("content digest does not match");
}
for (const output of vector.positive_outputs) validateOutput(output);
for (const item of vector.positive_exchanges) {
  validateOutput(item.response);
  validateExchange(item.request, item.response);
}
for (const item of vector.negative_outputs) {
  let rejected = false;
  try { validateOutput(item.output); }
  catch (error) {
    rejected = String(error.message).includes(item.expected_error_contains);
  }
  if (!rejected) fail(`negative output accepted: ${item.name}`);
}
for (const item of vector.negative_exchanges) {
  let rejected = false;
  validateOutput(item.response);
  try { validateExchange(item.request, item.response); }
  catch (error) {
    rejected = String(error.message).includes(item.expected_error_contains);
  }
  if (!rejected) fail(`negative exchange accepted: ${item.name}`);
}
process.stdout.write("ok");
"""
    completed = subprocess.run(
        [
            shutil.which("node") or "node",
            "-e",
            script,
            str(VECTOR_DIR / "market-index-wire-cases-v1.json"),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.stdout == "ok"


def test_market_index_entry_round_trip_is_content_addressed() -> None:
    text = _entry_json()
    parsed, encoded = canonical_market_index_entry(text)
    assert parsed == _entry()
    assert encoded == text.encode("utf-8")
    assert market_index_entry_digest(text) == __import__("hashlib").sha256(encoded).hexdigest()
    assert (
        market_index_protocol_document()["entry_rules"]["projection_only"]
        == "must-be-true-and-never-grants-authority"
    )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"projection_only": False}, "projection_only"),
        ({"source_digest": "a" * 64}, "source_digest"),
        ({"publisher_did": "did:web:example.test"}, "publisher_did"),
        ({"categories": ["tasks", "tasks"]}, "sorted and unique"),
        ({"capabilities": ["z", "a"]}, "sorted and unique"),
        ({"origin": "local", "source_peer": "https://peer.test"}, "source_peer"),
        ({"origin": "federated", "source_peer": ""}, "source_peer"),
        ({"not_after_ms": 1_749_999_999_999}, "not_after_ms"),
        ({"last_verified_at_ms": 1_749_999_999_999}, "last_verified_at_ms"),
        ({"source_locator": "nth://bad\nlocator"}, "source_locator"),
        ({"source_locator": "nth://demo-user:demo-pass@peer/item"}, "userinfo"),
        ({"title": "unsafe\u001btitle"}, "title"),
        ({"summary": "unsafe\u0000summary"}, "summary"),
    ],
)
def test_market_index_entry_rejects_semantic_drift(mutation: dict, message: str) -> None:
    value = _entry()
    value.update(mutation)
    with pytest.raises(ValueError, match=message):
        canonical_market_index_entry(canonical_json(value).decode("utf-8"))


def test_market_index_entry_rejects_noncanonical_or_unbounded_content() -> None:
    with pytest.raises(ValueError, match="canonical"):
        canonical_market_index_entry(json.dumps(_entry(), indent=2))
    oversized = _entry()
    oversized["summary"] = "x" * (MARKET_INDEX_MAX_ENTRY_BYTES + 1)
    with pytest.raises(ValueError, match="byte limit"):
        canonical_market_index_entry(canonical_json(oversized).decode("utf-8"))


def test_market_index_upsert_binds_outer_id_and_digest() -> None:
    text = _entry_json()
    request = {
        "operation": "upsert",
        "entry_id": "task:alpha",
        "entry_json": text,
        "entry_sha256": market_index_entry_digest(text),
        "expected_entry_sha256": "",
    }
    validate_market_index_input(request)
    with pytest.raises(PluginSchemaError, match="entry_id does not bind"):
        validate_market_index_input({**request, "entry_id": "task:other"})
    with pytest.raises(PluginSchemaError, match="entry_sha256 does not bind"):
        validate_market_index_input({**request, "entry_sha256": "0" * 64})


def test_market_index_search_requires_closed_sorted_filters() -> None:
    request = {
        "operation": "search",
        "q": "review",
        "categories": ["services", "tasks"],
        "intents": ["exchange", "request"],
        "source_protocols": ["org.nth-dao.market.task-announcement.v3"],
        "include_stale": False,
        "cursor": "",
        "limit": 20,
    }
    validate_market_index_input(request)
    with pytest.raises(PluginSchemaError, match="sorted and unique"):
        validate_market_index_input({**request, "categories": ["tasks", "services"]})
    with pytest.raises(PluginSchemaError, match="does not accept"):
        validate_market_index_input({"operation": "probe", "q": "hidden"})


def test_market_index_remove_requires_a_content_cas_digest() -> None:
    with pytest.raises(PluginSchemaError, match="non-empty expected digest"):
        validate_market_index_input(
            {
                "operation": "remove",
                "entry_id": "task:alpha",
                "expected_entry_sha256": "",
            }
        )
    assert MARKET_INDEX_MAX_CURSOR_CHARS >= 1_024
    assert MARKET_INDEX_MAX_CURSOR_AGE_MS == 300_000
    assert MARKET_INDEX_STALE_RETENTION_MS == 300_000


def test_market_index_output_revalidates_embedded_projection() -> None:
    text = _entry_json()
    result = _base_output("get")
    result.update(
        {
            "entry_id": "task:alpha",
            "entry_json": text,
            "entry_sha256": market_index_entry_digest(text),
            "found": True,
        }
    )
    validate_market_index_output(result)
    tampered = dict(result)
    tampered["entry_sha256"] = "0" * 64
    with pytest.raises(PluginSchemaError, match="does not bind"):
        validate_market_index_output(tampered)


def test_market_index_output_rejects_false_authority_shapes() -> None:
    probe = _base_output("probe")
    probe["found"] = True
    with pytest.raises(PluginSchemaError, match="probe"):
        validate_market_index_output(probe)
    upsert = _base_output("upsert")
    upsert.update(
        {
            "entry_id": "task:alpha",
            "entry_sha256": "a" * 64,
            "found": True,
            "changed": True,
            "replayed": True,
            "revision": 1,
        }
    )
    with pytest.raises(PluginSchemaError, match="flags"):
        validate_market_index_output(upsert)


def test_market_index_exchange_binds_resource_and_content_to_request() -> None:
    requested = _entry_json()
    other = _entry_json(entry_id="task:other")
    get_response = _base_output("get")
    get_response.update(
        {
            "entry_id": "task:other",
            "entry_json": other,
            "entry_sha256": market_index_entry_digest(other),
            "found": True,
        }
    )
    validate_market_index_output(get_response)
    with pytest.raises(PluginSchemaError, match="entry_id does not match"):
        validate_market_index_exchange(
            {"operation": "get", "entry_id": "task:alpha"},
            get_response,
        )

    upsert_response = _base_output("upsert")
    upsert_response.update(
        {
            "entry_id": "task:alpha",
            "entry_sha256": "b" * 64,
            "found": True,
            "changed": True,
            "revision": 1,
        }
    )
    validate_market_index_output(upsert_response)
    with pytest.raises(PluginSchemaError, match="requested content digest"):
        validate_market_index_exchange(
            {
                "operation": "upsert",
                "entry_id": "task:alpha",
                "entry_json": requested,
                "entry_sha256": market_index_entry_digest(requested),
                "expected_entry_sha256": "",
            },
            upsert_response,
        )


def test_market_index_exchange_enforces_requested_page_limit() -> None:
    response = _base_output("search")
    response["items"] = [
        {
            "entry_id": entry_id,
            "entry_json": text,
            "entry_sha256": market_index_entry_digest(text),
            "score": score,
        }
        for entry_id, text, score in (
            ("task:alpha", _entry_json(), 20),
            ("task:other", _entry_json(entry_id="task:other"), 10),
        )
    ]
    response["found"] = True
    validate_market_index_output(response)
    with pytest.raises(PluginSchemaError, match="exceed"):
        validate_market_index_exchange(
            {
                "operation": "search",
                "q": "",
                "categories": [],
                "intents": [],
                "source_protocols": [],
                "include_stale": False,
                "cursor": "",
                "limit": 1,
            },
            response,
        )


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("categories", ["services"], "categories"),
        ("intents", ["provide"], "intents"),
        (
            "source_protocols",
            ["org.nth-dao.market.trade-offer.v3"],
            "source_protocols",
        ),
    ],
)
def test_market_index_search_exchange_rejects_hard_filter_mismatch(
    field: str,
    value: list[str],
    expected: str,
) -> None:
    exchange = copy.deepcopy(market_index_wire_vectors()["positive_exchanges"][3])
    exchange["request"][field] = value
    validate_market_index_input(exchange["request"])
    validate_market_index_output(exchange["response"])

    with pytest.raises(PluginSchemaError, match=expected):
        validate_market_index_exchange(exchange["request"], exchange["response"])


def test_market_index_search_exchange_rejects_explicit_stale_result() -> None:
    exchange = copy.deepcopy(market_index_wire_vectors()["positive_exchanges"][3])
    item = exchange["response"]["items"][0]
    entry = json.loads(item["entry_json"])
    entry["stale"] = True
    item["entry_json"] = canonical_json(entry).decode("utf-8")
    item["entry_sha256"] = market_index_entry_digest(item["entry_json"])
    validate_market_index_input(exchange["request"])
    validate_market_index_output(exchange["response"])

    with pytest.raises(PluginSchemaError, match="include_stale"):
        validate_market_index_exchange(exchange["request"], exchange["response"])
