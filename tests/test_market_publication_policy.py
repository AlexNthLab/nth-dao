from __future__ import annotations

import pytest

from nth_dao.market.publication_policy import reject_private_publication_data


@pytest.mark.parametrize(
    "value",
    [
        r"C:\Users\Operator\Desktop\offer.txt",
        "/Users/operator/Documents/offer.txt",
        "/home/operator/offer.txt",
        "file:///tmp/offer.txt",
        "-----BEGIN OPENSSH " + "PRIVATE KEY-----",
        "ghp_" + ("A" * 24),
        "sk-ant-" + ("A" * 40),
        "https://user:" + "password@example.test/item",
        "https://example.test/item?access_token=secret",
    ],
)
def test_publication_policy_rejects_private_or_secret_material(value):
    with pytest.raises(ValueError, match="signed and may be federated"):
        reject_private_publication_data(
            {"attributes": {"display_reference": value}},
            label="market_offer",
        )


def test_publication_policy_accepts_public_protocol_references():
    reject_private_publication_data(
        {
            "title": "Code review service",
            "resource_id": "urn:nthdao:service:review",
            "reference": "https://example.test/public/catalog/review",
            "digest": "sha256:" + ("a" * 64),
        },
        label="market_offer",
    )
