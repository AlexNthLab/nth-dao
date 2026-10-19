from __future__ import annotations

import importlib.util
import json
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "nth_release_gate", ROOT / "tools" / "release_gate.py"
)
assert SPEC is not None and SPEC.loader is not None
release_gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release_gate
SPEC.loader.exec_module(release_gate)


def _reasons(findings):
    return {finding.reason for finding in findings}


def test_content_scan_detects_private_material_and_local_paths():
    private_marker = "-----BEGIN " + "PRIVATE KEY-----"
    findings = release_gate.scan_text(
        "sample.txt",
        private_marker
        + "\nC:\\Users\\LocalOperator\\workspace\\repo\n"
        + "ghp_" + "A" * 30,
    )

    assert _reasons(findings) == {
        "private-key marker",
        "Windows user path",
        "GitHub token",
    }


def test_content_scan_detects_source_escaped_windows_user_path():
    findings = release_gate.scan_text(
        "sample.py",
        'WORKDIR = "C:\\\\Users\\\\LocalOperator\\\\workspace"',
    )

    assert _reasons(findings) == {"Windows user path"}


def test_content_scan_ignores_documented_names_and_short_test_keys():
    findings = release_gate.scan_text(
        "test.py",
        'os.environ["ANTHROPIC_API_KEY"] = "sk-ant-test"',
    )

    assert findings == []


def test_release_gate_scans_its_own_source_cleanly():
    source = (ROOT / "tools" / "release_gate.py").read_text(encoding="utf-8")

    assert release_gate.scan_text("tools/release_gate.py", source) == []


def test_name_scan_blocks_runtime_and_credential_files_but_allows_placeholders():
    assert release_gate.scan_name("team_agents/.gitkeep") == []
    assert "runtime data under repository root" in _reasons(
        release_gate.scan_name("team_agents/alice/status.json")
    )
    assert "sensitive credential/runtime filename" in _reasons(
        release_gate.scan_name("workspace/identity.json")
    )


def test_only_sdist_generated_egg_info_is_allowed():
    assert release_gate.scan_name(
        "nth_dao.egg-info/PKG-INFO",
        archive=True,
        allow_sdist_metadata=True,
    ) == []
    assert "egg-info build residue" in _reasons(
        release_gate.scan_name("nth_dao.egg-info/PKG-INFO", archive=True)
    )
    assert "egg-info build residue" in _reasons(
        release_gate.scan_name(
            "other.egg-info/PKG-INFO",
            archive=True,
            allow_sdist_metadata=True,
        )
    )


def test_distribution_scan_rejects_nested_metadata_and_runtime_data(tmp_path):
    wheel = tmp_path / "nth_dao-0.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("nth_dao/__init__.py", "")
        archive.writestr("nth_dao/pyproject.toml", "[project]")
        archive.writestr("team_agents/alice/status.json", "{}")

    findings = release_gate.scan_distribution(wheel, tmp_path)
    reasons = _reasons(findings)

    assert "stale nested packaging metadata" in reasons
    assert "runtime data under repository root" in reasons


def test_distribution_scan_preserves_and_rejects_traversal_paths(tmp_path):
    wheel = tmp_path / "nth_dao-0.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("nth_dao/__init__.py", "")
        archive.writestr("../../outside.txt", "unsafe")

    findings = release_gate.scan_distribution(wheel, tmp_path)

    assert "unsafe archive member path" in _reasons(findings)


def test_dirty_entries_reports_untracked_files(tmp_path):
    import subprocess

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "new.txt").write_text("local", encoding="utf-8")

    assert any("new.txt" in entry for entry in release_gate.dirty_entries(tmp_path))


def test_allow_dirty_scan_still_checks_untracked_sensitive_files(tmp_path):
    import subprocess

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "identity.json").write_text(
        "-----BEGIN " + "PRIVATE KEY-----\nsecret",
        encoding="utf-8",
    )

    findings = release_gate.scan_untracked_tree(tmp_path)

    assert "sensitive credential/runtime filename" in _reasons(findings)
    assert "private-key marker" in _reasons(findings)


def test_tracked_scan_checks_staged_bytes_not_only_worktree(tmp_path):
    import subprocess

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    path = tmp_path / "config.txt"
    path.write_text("-----BEGIN " + "PRIVATE KEY-----\nsecret", encoding="utf-8")
    subprocess.run(["git", "add", "config.txt"], cwd=tmp_path, check=True)
    path.write_text("safe worktree content", encoding="utf-8")

    findings = release_gate.scan_tracked_tree(tmp_path)

    assert any(
        finding.location == "index:config.txt"
        and finding.reason == "private-key marker"
        for finding in findings
    )


@pytest.mark.parametrize("key", ["private_key", "signing_key", "privateKey", "private-key"])
def test_json_private_key_is_detected_with_arbitrary_filename_and_nested_object(key):
    secret = "a" * 64
    findings = release_gate.scan_text("extensionless", json.dumps({"items": [{key: secret}]}))
    assert _reasons(findings) == {"JSON private signing key"}
    assert secret not in repr(findings)


def test_duplicate_json_field_cannot_hide_private_material():
    text = '{"private_key":' + json.dumps("a" * 64) + ',"private_key":null}'
    assert _reasons(release_gate.scan_text("unknown", text)) == {"JSON private signing key"}


@pytest.mark.parametrize("value", [list(range(32)), {"seed": [1, 2, 3]}, 17, 0, False, [], {}])
@pytest.mark.parametrize("key", ["private_key", "signing_key"])
def test_non_string_private_key_representation_is_not_treated_as_public(key, value):
    text = json.dumps({key: value})
    assert _reasons(release_gate.scan_text("extensionless", text)) == {"JSON private signing key"}


def test_duplicate_json_field_cannot_hide_structured_private_material():
    text = '{"private_key":[1,2,3],"private_key":null}'
    assert _reasons(release_gate.scan_text("unknown", text)) == {"JSON private signing key"}


@pytest.mark.parametrize("kty", ["OKP", "EC", "RSA"])
def test_jwk_private_parameter_is_detected(kty):
    assert _reasons(release_gate.scan_text("unknown", json.dumps({"kty": kty, "d": "secret"}))) == {
        "JSON private signing key",
    }


@pytest.mark.parametrize("value", [[1, 2, 3], {"bytes": [1, 2, 3]}, 0, False])
def test_jwk_private_parameter_with_invalid_non_string_type_is_blocked(value):
    text = json.dumps({"kty": "OKP", "d": value})
    assert _reasons(release_gate.scan_text("unknown", text)) == {"JSON private signing key"}


def test_public_identity_jwk_and_source_literals_are_not_private_material():
    assert release_gate.scan_text("public", json.dumps({"pubkey": "a" * 64, "private_key": ""})) == []
    assert release_gate.scan_text("public", json.dumps({"pubkey": "a" * 64, "private_key": None})) == []
    assert release_gate.scan_text("jwk", json.dumps({"kty": "OKP", "x": "public"})) == []
    assert release_gate.scan_text("source.py", 'data["private_key"] = signing_key.hex()') == []


def test_untracked_and_staged_extensionless_identity_are_blocked(tmp_path):
    import subprocess

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    path = tmp_path / "extensionless"
    path.write_text(json.dumps({"private_key": "a" * 64}), encoding="utf-8")
    assert "JSON private signing key" in _reasons(release_gate.scan_untracked_tree(tmp_path))
    subprocess.run(["git", "add", "extensionless"], cwd=tmp_path, check=True)
    path.write_text("safe worktree bytes", encoding="utf-8")
    findings = release_gate.scan_tracked_tree(tmp_path)
    assert any(item.location == "index:extensionless" and item.reason == "JSON private signing key"
               for item in findings)


def test_distribution_with_extensionless_private_identity_is_blocked(tmp_path):
    wheel = tmp_path / "nth_dao-0.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("nth_dao/__init__.py", "")
        archive.writestr("nth_dao/unknown", json.dumps({"private_key": "a" * 64}))
    assert "JSON private signing key" in _reasons(release_gate.scan_distribution(wheel, tmp_path))


def _private_input(case):
    private = json.dumps({"private_key": "a" * 64})
    if case == "array-key":
        return json.dumps({"private_key": list(range(32))}).encode()
    if case == "object-key":
        return json.dumps({"private_key": {"seed": [1, 2, 3]}}).encode()
    if case == "jsonl":
        return (json.dumps({"event": "export"}) + "\n" + private + "\n").encode()
    if case == "truncated":
        return private[:-1].encode()
    if case == "oversize":
        return json.dumps({"private_key": "a" * 64, "padding": "x" * release_gate.MAX_TEXT_BYTES}).encode()
    return private.encode(case)


@pytest.mark.parametrize("case", ["jsonl", "truncated", "utf-8-sig", "utf-16", "utf-32", "oversize", "array-key", "object-key"])
@pytest.mark.parametrize("entry", ["untracked", "staged", "wheel", "sdist"])
def test_private_material_or_incomplete_scan_blocks_all_entry_points(tmp_path, case, entry):
    import io
    import subprocess
    import tarfile

    data = _private_input(case)
    if entry in {"untracked", "staged"}:
        subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
        path = tmp_path / "extensionless"
        path.write_bytes(data)
        if entry == "staged":
            subprocess.run(["git", "add", "extensionless"], cwd=tmp_path, check=True)
            path.write_text("clean worktree bytes", encoding="utf-8")
            findings = release_gate.scan_tracked_tree(tmp_path)
            assert any(item.location == "index:extensionless" for item in findings)
        else:
            findings = release_gate.scan_untracked_tree(tmp_path)
    elif entry == "wheel":
        archive = tmp_path / "sample.whl"
        with zipfile.ZipFile(archive, "w") as stream:
            stream.writestr("nth_dao/extensionless", data)
        findings = release_gate.scan_distribution(archive, tmp_path)
    else:
        archive = tmp_path / "sample.tar.gz"
        with tarfile.open(archive, "w:gz") as stream:
            info = tarfile.TarInfo("nth_dao-0.0.0/nth_dao/extensionless")
            info.size = len(data)
            stream.addfile(info, io.BytesIO(data))
        findings = release_gate.scan_distribution(archive, tmp_path)
    assert any(item.reason == "JSON private signing key" or "content scan incomplete" in item.reason
               for item in findings)
    assert "a" * 64 not in repr(findings)


def test_json_document_budget_and_deep_parse_failure_are_not_clean(monkeypatch):
    monkeypatch.setattr(release_gate, "MAX_JSON_DOCUMENTS", 2)
    assert release_gate.scan_text("stream.jsonl", "{}\n{}\n{}\n")
    import sys

    depth = sys.getrecursionlimit() + 10
    # Decoder depth thresholds vary across Python versions. Whether parsed
    # successfully or rejected as too deep, private input must never be clean.
    private = json.dumps({"private_key": "a" * 64})
    assert release_gate.scan_text("deep.json", "[" * depth + private + "]" * depth)


def test_json_scan_rejects_incomplete_array_without_flagging_ini_or_source():
    assert release_gate.scan_text("extensionless", '[true,{"private_key":"secret"}')
    assert release_gate.scan_text("config.ini", "[run]\nbranch = true\n") == []
    assert release_gate.scan_text("source.py", '"""Source documentation."""\nvalue = {}\n') == []


def test_unknown_encoding_or_binary_is_not_silently_skipped():
    for raw in (b"\xffnot-utf8", b"header\0content", b"\xff\xfetruncated\0x"):
        findings = release_gate.scan_bytes("extensionless", raw, logical_name="extensionless")
        assert any("content scan incomplete" in item.reason for item in findings)


def test_only_exact_reviewed_binary_content_and_path_are_allowed():
    name = "frontend/public/nth-dao-logo.jpg"
    raw = (ROOT / name).read_bytes()
    assert release_gate.scan_bytes(name, raw, logical_name=name) == []
    assert release_gate.scan_bytes(name, raw + b"extra", logical_name=name)
    assert release_gate.scan_bytes("other.jpg", raw, logical_name="other.jpg")


def test_oversize_index_blob_is_rejected_before_reading_blob_contents(tmp_path, monkeypatch):
    import subprocess

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "large").write_bytes(b"x" * (release_gate.MAX_TEXT_BYTES + 1))
    subprocess.run(["git", "add", "large"], cwd=tmp_path, check=True)
    git = release_gate._git

    def bounded(root, *args):
        assert args[:2] != ("cat-file", "blob"), "oversize blob was read"
        return git(root, *args)

    monkeypatch.setattr(release_gate, "_git", bounded)
    findings = release_gate.scan_tracked_tree(tmp_path)
    assert any("byte limit" in item.reason for item in findings)


def test_index_scan_reads_the_size_checked_immutable_blob(tmp_path, monkeypatch):
    import subprocess

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    path = tmp_path / "changing"
    path.write_text("original public content", encoding="utf-8")
    subprocess.run(["git", "add", "changing"], cwd=tmp_path, check=True)
    git = release_gate._git

    def replace_index(root, *args):
        result = git(root, *args)
        if args[:2] == ("cat-file", "-s"):
            path.write_bytes(b"x" * (release_gate.MAX_TEXT_BYTES + 1))
            subprocess.run(["git", "add", "changing"], cwd=tmp_path, check=True)
        return result

    monkeypatch.setattr(release_gate, "_git", replace_index)
    assert release_gate._read_index(tmp_path, "changing") == b"original public content"
