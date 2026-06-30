"""v0.10 T-7: A2A Agent Card generator + validator.

build_agent_card() turns a (name, description, url, capabilities, skills)
tuple into the JSON manifest A2A consumers fetch at
/.well-known/agent.json. The roadmap's v0.11 goal is for an external
A2A agent to read this manifest and call us; this T-7 ticket is just
the manifest generation.

15 tests covering minimal shape, capabilities-list shortcut, detailed
skills, merge semantics, defaults, provider block, NTH DAO extras,
TeamSession bridge, well-known path constant, schema validation,
file round-trip, and the wire-format rule that unknown skill fields
must be x- prefixed vendor extensions.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nth_dao.a2a.agent_card import (
    A2A_PROTOCOL_VERSION,
    A2A_WELL_KNOWN_PATH,
    build_agent_card,
    build_agent_card_from_session,
    validate_agent_card,
    write_agent_card,
)


# ===== T7-#1: minimal card has required A2A fields =====


def test_T7_01_minimal_card_has_required_fields():
    card = build_agent_card(
        name="Test Agent", description="Reviews PRs",
        url="https://example.com/a2a",
    )
    # All A2A v1.0.1 required top-level fields present
    for field in (
        "name", "description", "supportedInterfaces", "version",
        "capabilities", "defaultInputModes", "defaultOutputModes", "skills",
        "securitySchemes", "securityRequirements",
    ):
        assert field in card, f"missing {field!r}"
    # Spec-conforming values
    assert card["name"] == "Test Agent"
    assert card["supportedInterfaces"][0]["url"] == "https://example.com/a2a"
    assert card["supportedInterfaces"][0]["protocolVersion"] == A2A_PROTOCOL_VERSION
    assert card["supportedInterfaces"][0]["protocolBinding"] == "HTTP+JSON"
    assert card["defaultInputModes"] == ["application/json"]
    # Skills array exists but is empty by default
    assert card["skills"] == []

# ===== T7-#2: capabilities-list -> minimal skill stubs =====


def test_T7_02_capabilities_become_minimal_skill_stubs():
    card = build_agent_card(
        name="Bot", description="", url="https://x/a2a",
        capabilities=["code_review", "deploy", "build-and-test"],
    )
    skills_by_id = {s["id"]: s for s in card["skills"]}
    assert set(skills_by_id) == {"code_review", "deploy", "build-and-test"}
    # Title-cased display name auto-derived
    assert skills_by_id["code_review"]["name"] == "Code Review"
    assert skills_by_id["build-and-test"]["name"] == "Build And Test"
    # IO defaults
    for skill in card["skills"]:
        assert skill["inputModes"] == ["application/json"]
        assert skill["outputModes"] == ["application/json"]
        assert skill["tags"] == []


# ===== T7-#3: detailed skills wins on id collision =====


def test_T7_03_detailed_skill_wins_on_id_collision():
    """If the caller passes both a capability stub AND a detailed skill
    with the same id, the detailed one wins and no duplicate is emitted."""
    card = build_agent_card(
        name="X", description="", url="https://x/a2a",
        capabilities=["code_review"],   # would yield a stub
        skills=[{
            "id": "code_review",
            "name": "Senior Code Review",
            "description": "Detailed PR critique",
            "tags": ["python", "review"],
            "inputModes": ["application/json", "text/plain"],
            "outputModes": ["application/json", "text/markdown"],
        }],
    )
    by_id = {s["id"]: s for s in card["skills"]}
    assert len(card["skills"]) == 1   # not duplicated
    assert by_id["code_review"]["name"] == "Senior Code Review"
    assert by_id["code_review"]["tags"] == ["python", "review"]


# ===== T7-#4: capability flag overrides =====


def test_T7_04_capability_flags_default_and_override():
    """capabilities.streaming / pushNotifications are bool flags that an A2A consumer reads to decide how to call us."""
    default = build_agent_card(name="X", description="", url="https://x/a2a")
    assert default["capabilities"]["streaming"] is False
    assert default["capabilities"]["pushNotifications"] is False
    assert default["capabilities"]["extendedAgentCard"] is False

    overridden = build_agent_card(
        name="X", description="", url="https://x/a2a",
        streaming=True, push_notifications=True, state_transition_history=False,
    )
    assert overridden["capabilities"]["streaming"] is True
    assert overridden["capabilities"]["pushNotifications"] is True
    assert overridden["capabilities"]["extendedAgentCard"] is False

# ===== T7-#5: provider block optional =====


def test_T7_05_provider_block_added_only_when_supplied():
    no_provider = build_agent_card(name="X", description="", url="https://x/a2a")
    assert "provider" not in no_provider

    with_org = build_agent_card(
        name="X", description="", url="https://x/a2a",
        provider_org="NTH DAO", provider_url="https://nth-dao.org",
    )
    assert with_org["provider"] == {
        "organization": "NTH DAO",
        "url": "https://nth-dao.org",
    }

    org_only = build_agent_card(
        name="X", description="", url="https://x/a2a",
        provider_org="Solo Operator",
    )
    assert org_only["provider"] == {"organization": "Solo Operator"}


# ===== T7-#6: NTH DAO extras under x-prefixed namespace =====


def test_T7_06_nth_dao_extras_under_x_namespace():
    """Vendor extension fields MUST be x- prefixed per the standard A2A
    convention. Consumers that don't understand them must ignore them
    rather than reject the whole card."""
    card = build_agent_card(
        name="X", description="", url="https://x/a2a",
        nth_dao_extras={"agent_did": "did:key:zABC", "groups": ["bots"]},
    )
    assert card["x-nth-dao"] == {"agent_did": "did:key:zABC", "groups": ["bots"]}
    # No non-x extras at the top level
    for k in card:
        if k != "x-nth-dao":
            assert not k.startswith("x-")


# ===== T7-#7: skill validation rejects bad shape =====


def test_T7_07_skill_validation_rejects_bad_shape():
    base = dict(name="X", description="", url="https://x/a2a")

    # Missing id
    with pytest.raises(ValueError, match="skill.id"):
        build_agent_card(**base, skills=[{"name": "X"}])

    # Bad id (URL-unsafe)
    with pytest.raises(ValueError, match="URL-safe"):
        build_agent_card(**base, skills=[{"id": "has space", "name": "X"}])

    # Missing name
    with pytest.raises(ValueError, match=".name"):
        build_agent_card(**base, skills=[{"id": "ok_id"}])

    # Bad tags (must be list of strings)
    with pytest.raises(ValueError, match=".tags"):
        build_agent_card(**base, skills=[{
            "id": "ok", "name": "ok", "tags": "not-a-list",
        }])

    # Bad inputModes (must be non-empty list of strings)
    with pytest.raises(ValueError, match="inputModes"):
        build_agent_card(**base, skills=[{
            "id": "ok", "name": "ok", "inputModes": [],
        }])

    # Unknown non-x field -> error pointing at vendor-extension fix
    with pytest.raises(ValueError, match="vendor extensions"):
        build_agent_card(**base, skills=[{
            "id": "ok", "name": "ok", "weirdField": "v",
        }])

    # x-prefixed unknown field is ACCEPTED (vendor extension)
    out = build_agent_card(**base, skills=[{
        "id": "ok", "name": "ok", "x-rate-limit": 100,
    }])
    assert out["skills"][0]["x-rate-limit"] == 100


def test_T7_07b_duplicate_skill_id_rejected():
    """Two skills with the same id is ambiguous - reject."""
    with pytest.raises(ValueError, match="duplicate skill id"):
        build_agent_card(
            name="X", description="", url="https://x/a2a",
            skills=[
                {"id": "a", "name": "A"},
                {"id": "a", "name": "Another A"},
            ],
        )


# ===== T7-#8: top-level shape validation =====


def test_T7_08_top_level_validation():
    with pytest.raises(ValueError, match="non-empty"):
        build_agent_card(name="", description="", url="https://x/a2a")
    # V-35 wording changed: "scheme must be http(s)" - match the
    # canonical name "http(s)" used by the hardened urlparse path.
    with pytest.raises(ValueError, match="http"):
        build_agent_card(name="X", description="", url="ftp://x/a2a")
    with pytest.raises(ValueError, match="url"):
        build_agent_card(name="X", description="", url="")
    with pytest.raises(ValueError, match="capability"):
        build_agent_card(
            name="X", description="", url="https://x/a2a",
            capabilities=["has space"],   # not URL-safe
        )


def test_T7_08b_voss_V35_hardened_url_validation():
    """V-35 tightening: urlparse-based check rejects empty-host URLs,
    URLs containing CR/LF, and 2KB+ payloads."""
    # bare scheme, no host -> reject
    with pytest.raises(ValueError, match="host"):
        build_agent_card(name="X", description="", url="http://")
    # CR/LF injection
    with pytest.raises(ValueError, match="CR/LF"):
        build_agent_card(name="X", description="", url="https://x/a2a\nHeader: evil")
    # length cap
    with pytest.raises(ValueError, match="too long"):
        build_agent_card(
            name="X", description="",
            url="https://x.com/" + ("a" * 3000),
        )


# ===== T7-#9: validate_agent_card flags structural problems =====


def test_T7_09_validate_catches_missing_fields():
    good = build_agent_card(name="X", description="", url="https://x/a2a")
    ok, reason = validate_agent_card(good)
    assert ok, reason

    # Strip a required field; must fail
    broken = dict(good)
    del broken["supportedInterfaces"]
    ok, reason = validate_agent_card(broken)
    assert not ok
    assert "supportedInterfaces" in reason

def test_T7_09b_validate_catches_invalid_capability_types():
    bad = build_agent_card(name="X", description="", url="https://x/a2a")
    bad["capabilities"]["streaming"] = "yes"   # str, not bool
    ok, reason = validate_agent_card(bad)
    assert not ok
    assert "bool" in reason


# ===== T7-#10: write+read round trip =====


def test_T7_10_write_and_read_round_trip(tmp_path: Path):
    card = build_agent_card(
        name="X", description="", url="https://x/a2a",
        capabilities=["a", "b"],
    )
    out_path = tmp_path / "well-known" / "agent.json"
    write_agent_card(out_path, card)
    assert out_path.exists()
    loaded = json.loads(out_path.read_text(encoding="utf-8"))
    # Round trip preserves the card byte-for-byte (sorted keys)
    assert loaded == card
    # And the loaded card still passes validation
    ok, _ = validate_agent_card(loaded)
    assert ok


def test_T7_10b_write_refuses_invalid_card(tmp_path: Path):
    """We never ship malformed cards to the well-known URL."""
    broken = {"this": "is not a card"}
    with pytest.raises(ValueError, match="invalid card"):
        write_agent_card(tmp_path / "agent.json", broken)   # type: ignore[arg-type]
    assert not (tmp_path / "agent.json").exists()


# ===== T7-#11: well-known path constant =====


def test_T7_11_well_known_path_constant():
    """The exact path A2A consumers fetch. Stable across the v0.10
    minor; bumping it is a breaking protocol change."""
    assert A2A_WELL_KNOWN_PATH == "/.well-known/agent.json"


# ===== T7-#12: TeamSession bridge =====


def test_T7_12_from_session_bridge_pulls_capabilities():
    """build_agent_card_from_session should pull the agent_id +
    capabilities + groups from the attached TeamSession."""
    class FakeSession:
        agent_id = "alice"
        capabilities = ["code_review", "deploy"]
        groups = ["bots", "reviewers"]
        workspace = "/tmp/foo"
        identity = None

    card = build_agent_card_from_session(
        FakeSession(),   # type: ignore[arg-type]
        url="https://nth-dao.example/a2a",
        description="The Alice agent",
    )
    assert card["name"] == "alice"
    assert card["description"] == "The Alice agent"
    skill_ids = {s["id"] for s in card["skills"]}
    assert skill_ids == {"code_review", "deploy"}
    assert card["x-nth-dao"]["agent_id"] == "alice"
    assert card["x-nth-dao"]["groups"] == ["bots", "reviewers"]


def test_T7_12b_from_session_includes_did_when_signing_identity_present():
    from nth_dao.identity import AgentIdentity, crypto_available
    if not crypto_available():
        pytest.skip("PyNaCl required")
    alice = AgentIdentity.generate(label="alice")
    class FakeSession:
        agent_id = "alice"
        capabilities = ["x"]
        groups: list = []
        workspace = "/tmp"
        identity = alice
    card = build_agent_card_from_session(
        FakeSession(), url="https://x/a2a",   # type: ignore[arg-type]
    )
    assert card["x-nth-dao"]["agent_did"] == alice.as_did()


# ===== T7-#13: facade re-export =====


def test_T7_13_facade_reexport():
    import nth_dao
    assert nth_dao.build_agent_card is build_agent_card
    assert nth_dao.build_agent_card_from_session is build_agent_card_from_session
    assert nth_dao.validate_agent_card is validate_agent_card
    assert nth_dao.write_agent_card is write_agent_card
    assert nth_dao.A2A_WELL_KNOWN_PATH == A2A_WELL_KNOWN_PATH
    assert nth_dao.A2A_PROTOCOL_VERSION == A2A_PROTOCOL_VERSION
