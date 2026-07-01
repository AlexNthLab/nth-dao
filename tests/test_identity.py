import json

import nth_dao as nth


def test_plain_identity_round_trip(tmp_path):
    identity_path = tmp_path / ".nth" / "identity.json"
    identity = nth.AgentIdentity.from_string(
        "alice",
        label="Alice",
        metadata={"role": "reviewer"},
    )

    identity.save(identity_path)
    loaded = nth.AgentIdentity.load(identity_path)

    assert str(loaded.agent_id) == "alice"
    assert loaded.label == "Alice"
    assert loaded.metadata["role"] == "reviewer"
    assert loaded.public_dict()["is_cryptographic"] is False


def test_load_or_generate_creates_stable_identity_file(tmp_path):
    first = nth.load_or_generate(tmp_path, label="worker")
    second = nth.load_or_generate(tmp_path, label="ignored")

    assert str(first.agent_id) == str(second.agent_id)
    assert nth.default_identity_path(tmp_path).exists()


def test_attach_exports_identity_metadata_without_bypassing_membership(tmp_path):
    identity = nth.AgentIdentity.from_string("alice", label="Alice")
    session = nth.attach(
        "alice",
        backend=None,
        workspace=tmp_path,
        start_heartbeat=False,
        identity=identity,
    )
    try:
        record_path = tmp_path / "team_agents" / "alice.json"
        record = json.loads(record_path.read_text(encoding="utf-8"))

        assert session.identity is identity
        assert record["metadata"]["identity"]["agent_id"] == "alice"
        assert record["metadata"]["identity"]["label"] == "Alice"
        assert "alice" in session.membership.load_config().member_ids
    finally:
        session.detach()


def test_identity_does_not_bypass_approval_policy(tmp_path):
    membership = nth.MembershipManager(tmp_path)
    membership.init_team(policy="approval", admin_ids=["admin"])

    identity = nth.AgentIdentity.from_string("guest", label="Guest")

    try:
        nth.attach(
            "guest",
            backend=None,
            workspace=tmp_path,
            start_heartbeat=False,
            identity=identity,
        )
    except PermissionError as exc:
        assert "approval_required" in str(exc)
    else:
        raise AssertionError("unapproved identity attach should be blocked")

def test_windows_acl_warning_reports_safe_reason_without_local_path(
    tmp_path, monkeypatch, caplog,
):
    import logging
    import nth_dao.identity as identity_mod

    identity_path = tmp_path / "private-dir" / "identity.json"
    identity_path.parent.mkdir()
    identity_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(identity_mod.sys, "platform", "win32")
    monkeypatch.setattr(
        identity_mod,
        "_restrict_windows_acl",
        lambda _path: (False, "icacls-grant-exit-5"),
    )

    with caplog.at_level(logging.WARNING, logger="nth_dao.identity"):
        identity_mod._restrict_to_owner(identity_path)

    messages = [r.getMessage() for r in caplog.records]
    assert any("identity.json" in m for m in messages)
    assert any("reason=icacls-grant-exit-5" in m for m in messages)
    assert all(str(tmp_path) not in m for m in messages)
    assert all("private-dir" not in m for m in messages)


def test_windows_acl_uses_binary_icacls_and_reports_stage(
    tmp_path, monkeypatch,
):
    import subprocess
    import nth_dao.identity as identity_mod

    identity_path = tmp_path / "identity.json"
    identity_path.write_text("{}", encoding="utf-8")
    calls = []

    class Result:
        def __init__(self, returncode=7, stdout=b""):
            self.returncode = returncode
            self.stdout = stdout

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        if argv[0] == "whoami":
            return Result(0, b'"PC\\Alice","S-1-5-21-1"\r\n')
        return Result(7)

    monkeypatch.setenv("USERNAME", "Alice")
    monkeypatch.setattr(subprocess, "run", fake_run)

    ok, reason = identity_mod._restrict_windows_acl(identity_path)

    assert ok is False
    assert reason.startswith("icacls-grant-exit-")
    assert "7" in reason
    assert calls
    for _argv, kwargs in calls:
        assert kwargs["stderr"] is subprocess.DEVNULL
        assert "text" not in kwargs
        assert "capture_output" not in kwargs


def test_windows_acl_prefers_current_user_sid(tmp_path, monkeypatch):
    import subprocess
    import nth_dao.identity as identity_mod

    identity_path = tmp_path / "identity.json"
    identity_path.write_text("{}", encoding="utf-8")
    calls = []

    class Result:
        def __init__(self, returncode=0, stdout=b""):
            self.returncode = returncode
            self.stdout = stdout

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        if argv[0] == "whoami":
            return Result(0, b'"PC\\Alice","S-1-5-21-999"\r\n')
        return Result(0)

    monkeypatch.setenv("USERNAME", "Alice")
    monkeypatch.setenv("USERDOMAIN", "PC")
    monkeypatch.setattr(subprocess, "run", fake_run)

    ok, reason = identity_mod._restrict_windows_acl(identity_path)

    assert ok is True
    assert reason == "ok"
    icacls_calls = [c for c in calls if c[0][0] == "icacls"]
    assert icacls_calls[0][0][2] == "/grant:r"
    assert icacls_calls[0][0][3] == "*S-1-5-21-999:(F)"
