"""Regression tests for optional Nostr native-binding failures."""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path


def test_native_loader_oserror_keeps_nostr_optional() -> None:
    script = textwrap.dedent(
        """
        import builtins

        original_import = builtins.__import__

        def blocked_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "nostr_sdk" or name.startswith("nostr_sdk."):
                raise OSError("simulated native loader failure")
            return original_import(name, globals, locals, fromlist, level)

        builtins.__import__ = blocked_import

        import nth_dao.nostr as nostr

        assert nostr._NOSTR_AVAILABLE is False
        try:
            nostr.NostrKeys.generate()
        except nostr.NostrAdapterUnavailable:
            pass
        else:
            raise AssertionError("NostrKeys did not fail closed")

        try:
            nostr.NostrRelayClient(None, relay_urls=["wss://relay.example"])
        except nostr.NostrAdapterUnavailable:
            pass
        else:
            raise AssertionError("NostrRelayClient did not fail closed")
        """
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        timeout=15.0,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
