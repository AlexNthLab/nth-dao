"""P5: protocol-layer source must stay ASCII-only.

Project history has multiple Windows / GBK / mojibake incidents
(see PR #7, the original event_bus.py linter corruption, the
lan_mdns.py garbling). Stick to ASCII in protocol-layer files so a
mis-configured environment can't silently corrupt them.

Display literals belong in frontend assets or escaped runtime strings,
not raw protocol-layer source.
"""

from __future__ import annotations

import pathlib

import pytest


PROTOCOL_LAYER_FILES = [
    "nth_dao/action_routing.py",
    "nth_dao/event_bus.py",
    "nth_dao/event_subscriptions.py",
    "nth_dao/fault_isolation.py",
    "nth_dao/agent_profile.py",
    "nth_dao/achievement.py",
    "nth_dao/discovery/lan_mdns.py",
    "nth_dao/orchestration/template.py",
]


@pytest.mark.parametrize("path", PROTOCOL_LAYER_FILES)
def test_P5_protocol_layer_is_ASCII(path: str):
    """Every byte in these files must be ASCII."""
    text = pathlib.Path(path).read_text(encoding="utf-8")
    offenders = sorted({
        c for c in text
        if ord(c) > 127
    })
    assert not offenders, (
        f"{path}: non-ASCII chars found: "
        + ", ".join(f"U+{ord(c):04X}" for c in offenders)
        + "\nASCII-ify protocol-layer source before merging."
    )
