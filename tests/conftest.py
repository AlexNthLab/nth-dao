import hashlib
import subprocess
import sys
from pathlib import Path
from typing import Optional, Tuple

import pytest


ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
_ROOT_TEAM_SNAPSHOT: Optional[Tuple[bool, str]] = None
_UNTRACKED_PATHS: Tuple[Path, ...] = ()
_UNTRACKED_SNAPSHOT: Optional[str] = None

for path in (ROOT, EXAMPLES):
    path_str = str(path)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)


@pytest.fixture(autouse=True)
def _disable_real_mdns_by_default(monkeypatch):
    """Unit tests must opt in before publishing on the host LAN."""
    monkeypatch.setenv("NTH_LAN_PUBLISH", "0")


@pytest.fixture(autouse=True)
def _protect_repository_state(request):
    """Name the exact test that mutates user-owned repository state."""
    team_before = _root_team_fingerprint()
    untracked_before = _untracked_fingerprint()
    yield
    team_after = _root_team_fingerprint()
    untracked_after = _untracked_fingerprint()
    changes = []
    if team_after != team_before:
        changes.append("repository-root team.json")
    if untracked_after != untracked_before:
        changes.append("pre-existing untracked user files")
    if changes:
        pytest.fail(
            f"{request.node.nodeid} changed {' and '.join(changes)}; "
            "files were left untouched",
            pytrace=False,
        )


def _root_team_fingerprint() -> Tuple[bool, str]:
    """Describe root runtime state without modifying or decoding user data."""
    path = ROOT / "team.json"
    try:
        payload = path.read_bytes()
    except FileNotFoundError:
        return False, ""
    return True, hashlib.sha256(payload).hexdigest()


def _discover_untracked_files() -> Tuple[Path, ...]:
    """Return non-ignored untracked files present before the test session."""
    try:
        completed = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard", "-z"],
            cwd=ROOT,
            capture_output=True,
            check=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return ()
    paths = []
    for raw_path in completed.stdout.split(b"\0"):
        if not raw_path:
            continue
        path = ROOT / raw_path.decode("utf-8", errors="surrogateescape")
        if path.is_file() and not path.is_symlink():
            paths.append(path)
    return tuple(sorted(paths))


def _untracked_fingerprint() -> str:
    """Fingerprint user files from metadata without reading their contents."""
    digest = hashlib.sha256()
    for path in _UNTRACKED_PATHS:
        relative = path.relative_to(ROOT).as_posix().encode("utf-8")
        digest.update(relative)
        digest.update(b"\0")
        try:
            stat = path.stat()
        except (FileNotFoundError, OSError):
            digest.update(b"MISSING")
            continue
        metadata = (
            stat.st_size,
            stat.st_mtime_ns,
            getattr(stat, "st_ino", 0),
        )
        digest.update(repr(metadata).encode("ascii"))
    return digest.hexdigest()


def pytest_sessionstart(session):
    """Remember user-owned root state so tests cannot mutate it silently."""
    global _ROOT_TEAM_SNAPSHOT, _UNTRACKED_PATHS, _UNTRACKED_SNAPSHOT
    _ROOT_TEAM_SNAPSHOT = _root_team_fingerprint()
    _UNTRACKED_PATHS = _discover_untracked_files()
    _UNTRACKED_SNAPSHOT = _untracked_fingerprint()


def pytest_sessionfinish(session, exitstatus):
    """Fail closed on root pollution; never delete or restore user files."""
    changed = []
    if _ROOT_TEAM_SNAPSHOT != _root_team_fingerprint():
        changed.append("repository-root team.json")
    if _UNTRACKED_SNAPSHOT != _untracked_fingerprint():
        changed.append("pre-existing untracked user files")
    if not changed:
        return
    session.exitstatus = pytest.ExitCode.TESTS_FAILED
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        reporter.write_sep(
            "=",
            "TEST SAFETY FAILURE: tests changed "
            f"{' and '.join(changed)}; files were left untouched",
            red=True,
        )
