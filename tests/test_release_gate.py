from __future__ import annotations

import importlib.util
import sys
import zipfile
from pathlib import Path


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
