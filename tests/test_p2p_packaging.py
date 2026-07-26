"""Packaging contract tests for the optional P2P transport."""

from pathlib import Path
import re
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def _project_metadata() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_p2p_extra_matches_the_websockets_asyncio_api_range() -> None:
    extras = _project_metadata()["project"]["optional-dependencies"]

    assert extras["p2p"] == ["websockets>=13.0,<17.0"]


def test_p2p_lock_pins_a_version_inside_the_declared_range() -> None:
    lock = (ROOT / "requirements" / "p2p.lock.txt").read_text(encoding="utf-8")
    match = re.search(r"^websockets==(\d+)\.(\d+)\.(\d+)", lock, re.MULTILINE)

    assert match is not None
    assert 13 <= int(match.group(1)) < 17
    assert lock.count("--hash=sha256:") > 1
    assert "Users\\" not in lock
    assert "Users/" not in lock


def test_publish_workflow_installs_and_smoke_tests_p2p_transport() -> None:
    workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(
        encoding="utf-8"
    )

    assert workflow.count("requirements/p2p.lock.txt") >= 3
    assert '"nth-dao[p2p] @ file://$WHEEL --hash=sha256:$WHEEL_HASH"' in workflow
    assert "--require-hashes" in workflow
    assert '"nth_dao.gossip"' in workflow
    assert "assert gossip._WEBSOCKETS_AVAILABLE" in workflow
    assert 'metadata.get_all("Provides-Extra")' in workflow
    assert 'extra == "p2p"' in workflow


def test_runtime_install_hint_matches_the_published_extra() -> None:
    source = (ROOT / "nth_dao" / "gossip.py").read_text(encoding="utf-8")

    assert "pip install nth-dao[p2p]" in source
    assert "websockets>=13.0,<17.0" in source
