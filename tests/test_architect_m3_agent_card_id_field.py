"""Architect audit M-3 (2026-06-07): agent_card_from removes non-spec
top-level ``id`` field.

The A2A v1.0.1 Agent Card schema identifies reachable endpoints through
``supportedInterfaces[].url``. There is no canonical top-level ``id`` field. The sibling
``build_agent_card`` builder (which is the test-covered canonical
path) agrees - it never adds ``id``.

A previous revision added ``"id": agent_did`` to ``agent_card_from``.
Spec-strict A2A clients would flag the card as carrying an undefined
property; some validators (depending on JSON-schema mode) would
reject the whole document.

This pins:
  * agent_card_from does NOT emit a top-level ``id`` key
  * The DID is still discoverable inside ``x-nth-dao.agent_did``
    (vendor extensions are explicitly allowed by the spec)
  * Field set matches the canonical build_agent_card output (with the
    expected ``x-nth-dao`` / ``metadata`` additions only)
"""

from __future__ import annotations

import pytest

from nth_dao.a2a.translate import agent_card_from


_VALID_DID = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"


def _build():
    return agent_card_from(
        agent_did=_VALID_DID,
        name="Test Agent",
        description="M-3 test",
        templates=[],
        capabilities=["code-review"],
        endpoint_url="https://example.com/a2a",
    )


# ===== M-3 core: no top-level id =====


def test_M3_card_has_no_top_level_id_field():
    """The A2A Agent Card spec has no top-level ``id`` identity.
    Adding one pollutes the document."""
    card = _build()
    assert "id" not in card, (
        f"agent_card_from emitted spec-undefined top-level 'id': "
        f"{card.get('id')!r}"
    )


def test_M3_card_uses_supported_interface_url_as_canonical_endpoint():
    """A2A v1.0.1 carries endpoint identity in supportedInterfaces.
    Make this explicit so top-level url/id regressions are caught."""
    card = _build()
    assert "url" not in card
    assert card["supportedInterfaces"][0]["url"] == "https://example.com/a2a"
    assert card["supportedInterfaces"][0]["protocolBinding"] == "HTTP+JSON"


# ===== M-3 corollary: DID still discoverable =====


def test_M3_agent_did_still_discoverable_under_x_nth_dao():
    """Removing top-level ``id`` must not lose the DID - it lives in
    the vendor extension namespace per spec convention."""
    card = _build()
    assert "x-nth-dao" in card
    assert card["x-nth-dao"]["agent_did"] == _VALID_DID


# ===== Field set sanity =====


def test_M3_card_field_set_matches_canonical_schema():
    """The card emits exactly the A2A-recognised top-level fields
    plus our two vendor-prefixed extensions (``metadata`` and
    ``x-nth-dao``). Catching ``id`` regression is the main goal,
    but this also detects any other accidental top-level pollution."""
    card = _build()
    expected_keys = {
        # A2A v1.0.1 canonical fields
        "name",
        "description",
        "supportedInterfaces",
        "version",
        "capabilities",
        "defaultInputModes",
        "defaultOutputModes",
        "skills",
        "securitySchemes",
        "securityRequirements",
        # Vendor extensions (allowed by spec)
        "metadata",
        "x-nth-dao",
    }
    actual_keys = set(card.keys())
    assert actual_keys == expected_keys, (
        f"unexpected field-set drift:\n"
        f"  missing: {expected_keys - actual_keys}\n"
        f"  extra:   {actual_keys - expected_keys}"
    )


# ===== Behavioural alignment with build_agent_card =====


def test_M3_aligned_with_canonical_build_agent_card_on_no_id():
    """The other builder (test-covered canonical path) doesn't emit
    ``id`` either. If they diverge, downstream consumers see
    inconsistent cards depending on which builder was used."""
    from nth_dao.a2a.agent_card import build_agent_card

    canonical = build_agent_card(
        name="Test",
        description="x",
        url="https://example.com/a2a",
        capabilities=["code-review"],
    )
    assert "id" not in canonical
