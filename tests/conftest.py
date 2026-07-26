import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"

for path in (ROOT, EXAMPLES):
    path_str = str(path)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)


@pytest.fixture(autouse=True)
def _disable_real_mdns_by_default(monkeypatch):
    """Unit tests must opt in before publishing on the host LAN."""
    monkeypatch.setenv("NTH_LAN_PUBLISH", "0")


def pytest_sessionfinish(session, exitstatus):
    generated_config = ROOT / "team.json"
    if generated_config.exists():
        generated_config.unlink()
