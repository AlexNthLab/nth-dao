"""Regression coverage for visible Agent codes and code lookup."""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nth_dao.agent_code import (
    CODE_LEN,
    code_for_agent_id,
    code_for_pubkey,
    parse_code,
)
from nth_dao.group_registry import GroupRecord
from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.web import create_app


def test_code_for_pubkey_is_stable_and_formatted():
    pk = "a3" * 32
    code = code_for_pubkey(pk)
    assert len(code) == CODE_LEN + 1
    assert code[4] == "-"
    assert code_for_pubkey(pk) == code


def test_code_for_pubkey_empty_returns_empty():
    assert code_for_pubkey("") == ""


def test_code_for_agent_id_stable():
    code = code_for_agent_id("alice")
    assert "-" in code
    assert code_for_agent_id("alice") == code
    assert code_for_agent_id("bob") != code


def test_parse_code_accepts_with_and_without_dash():
    assert parse_code("a3f7-b2e8") == "a3f7b2e8"
    assert parse_code("a3f7b2e8") == "a3f7b2e8"
    assert parse_code("A3F7-B2E8") == "a3f7b2e8"
    assert parse_code("  a3f7-b2e8  ") == "a3f7b2e8"


def test_parse_code_rejects_bad_inputs():
    for bad in ("", "xyz", "abc", "12345678901234567", "a3f7-b2", "g3f7-b2e8"):
        with pytest.raises(ValueError):
            parse_code(bad)


def test_parse_code_rejects_non_string():
    with pytest.raises(ValueError):
        parse_code(12345)  # type: ignore[arg-type]


def test_code_round_trip():
    pk = "b1" * 32
    code = code_for_pubkey(pk)
    assert parse_code(code) == code.replace("-", "")


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(workspace=tmp_path))


def test_summary_exposes_actor_code(client):
    res = client.get("/api/summary", params={"actor_id": "alice"})
    assert res.status_code == 200
    assert res.json()["actor_code"] == code_for_agent_id("alice")


def test_state_actor_carries_code(client):
    body = client.get("/api/state", params={"agent_id": "admin"}).json()
    identity = client.get("/api/identity", params={"actor_id": "admin"}).json()
    assert body["actor"]["code"] == identity["code"]
    assert body["actor"]["code"] != code_for_agent_id("admin")


def test_state_members_carry_code(client):
    body = client.get("/api/state", params={"agent_id": "admin"}).json()
    identity = client.get("/api/identity", params={"actor_id": "admin"}).json()
    for member in body["members"]:
        assert "code" in member
        if member["agent_id"] == "admin":
            assert member["code"] == identity["code"]
        else:
            assert member["code"] == code_for_agent_id(member["agent_id"])


def test_lookup_by_code_finds_home_member(client):
    code = client.get("/api/identity", params={"actor_id": "admin"}).json()["code"]
    res = client.get(f"/api/agents/by_code/{code}", params={"actor_id": "admin"})
    assert res.status_code == 200
    assert res.json()["agent_id"] == "admin"
    assert res.json()["source"] == "home"


def test_lookup_by_code_accepts_dashless(client):
    code = client.get(
        "/api/identity", params={"actor_id": "admin"},
    ).json()["code"].replace("-", "")
    res = client.get(f"/api/agents/by_code/{code}", params={"actor_id": "admin"})
    assert res.status_code == 200


def test_lookup_by_code_404_on_unknown(client):
    res = client.get(
        "/api/agents/by_code/aaaa-bbbb", params={"actor_id": "admin"},
    )
    assert res.status_code == 404


def test_lookup_by_code_rejects_bad_format(client):
    res = client.get(
        "/api/agents/by_code/not-a-code", params={"actor_id": "admin"},
    )
    assert res.status_code == 400


def test_lookup_by_code_finds_group_member(client):
    if not crypto_available():
        pytest.skip("PyNaCl required for group fixture")
    founder = AgentIdentity.generate(label="founder")
    prep = client.post("/api/groups/registry", json={
        "actor_id": "admin",
        "actor_pubkey_hex": founder.pubkey_hex,
        "display_name": "MumoLawOS",
        "description": "Legal-tech group",
        "policy": "open",
    })
    assert prep.status_code == 200, prep.text
    skeleton = prep.json()["unsigned_record"]
    skeleton["group_id"] = secrets.token_hex(6)
    rec = GroupRecord.from_dict(skeleton)
    rec.sig = founder.sign_json(rec.signable_dict())
    pub = client.post("/api/groups/registry/publish", json={"record": rec.to_dict()})
    assert pub.status_code == 200, pub.text

    code = code_for_pubkey(founder.pubkey_hex)
    res = client.get(f"/api/agents/by_code/{code}", params={"actor_id": "admin"})
    assert res.status_code == 200, res.text
    assert res.json()["source"] == "group"
    assert res.json()["pubkey_hex"] == founder.pubkey_hex
