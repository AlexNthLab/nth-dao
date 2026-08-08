from __future__ import annotations

from pathlib import Path

import pytest


PUBLIC_MARKET_SURFACES = (
    "docs/architecture/MARKET_INFORMATION_ARCHITECTURE.md",
    "frontend/src/v2/components/MarketPublishForm.tsx",
    "nth_dao/market/conformance.py",
    "nth_dao/market/publication_policy.py",
    "nth_dao/market/resource_descriptor.py",
    "tests/test_market_public_language.py",
)


@pytest.mark.parametrize("path", PUBLIC_MARKET_SURFACES)
def test_new_market_public_surfaces_are_ascii_english(path: str):
    text = Path(path).read_text(encoding="utf-8")
    offenders = sorted({character for character in text if ord(character) > 127})
    assert not offenders, (
        f"{path} contains non-ASCII public text: "
        + ", ".join(f"U+{ord(character):04X}" for character in offenders)
    )
