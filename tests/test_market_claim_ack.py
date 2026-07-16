from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("nacl")

from nth_dao.cap_token import CAP_NTH_RECEIPT_SIGN, sign_cap_token
from nth_dao.identity import AgentIdentity
from nth_dao.market.announcement import sign_announcement
from nth_dao.market.claim import sign_claim_receipt
from nth_dao.market.claim_ack import (
    AuthorityClaimAckStore,
    sign_authority_claim_ack,
    verify_authority_claim_ack,
)


def _fixture():
    authority = AgentIdentity.generate(label="authority")
    claimant = AgentIdentity.generate(label="claimant")
    announcement = sign_announcement(
        publisher=authority,
        authority_did=authority.as_did(),
        title="claim ack fixture",
    )
    token = sign_cap_token(
        issuer=claimant,
        subject_did=claimant.as_did(),
        capabilities=[CAP_NTH_RECEIPT_SIGN],
    )
    receipt = sign_claim_receipt(announcement, claimant, token)
    claimed_at = receipt["timeline"][0]["timestamp"]
    record = {
        "announcement_id": announcement.announcement_id,
        "status": "claimed",
        "claimant_did": claimant.as_did(),
        "publisher_did": announcement.publisher_did,
        "cap_token_id": token["token_id"],
        "claimed_at_ms": claimed_at,
        "receipt_id": receipt["receipt_id"],
        "receipt": receipt,
        "foreign": True,
    }
    return authority, claimant, announcement, receipt, record


def test_authority_claim_ack_roundtrip_and_store(tmp_path: Path) -> None:
    authority, claimant, announcement, receipt, record = _fixture()
    ack = sign_authority_claim_ack(
        authority=authority,
        announcement=announcement,
        claim_record=record,
    )

    assert verify_authority_claim_ack(
        ack,
        expected_authority_did=authority.as_did(),
        expected_claimant_did=claimant.as_did(),
        expected_claim_receipt=receipt,
    ) == (True, "ok")
    store = AuthorityClaimAckStore(tmp_path)
    path = store.save(ack)
    assert path.is_file()
    assert store.load(ack["ack_id"]) == ack
    assert store.save(ack) == path


@pytest.mark.parametrize(
    "field,value",
    [
        ("claimant_did", "did:key:zWrong"),
        ("claim_receipt_hash", "0" * 64),
        ("claim_record_hash", "1" * 64),
        ("outcome", "rejected"),
    ],
)
def test_authority_claim_ack_rejects_tampering(field: str, value: str) -> None:
    authority, _claimant, announcement, _receipt, record = _fixture()
    ack = sign_authority_claim_ack(
        authority=authority,
        announcement=announcement,
        claim_record=record,
    )
    ack[field] = value

    assert verify_authority_claim_ack(ack)[0] is False


def test_authority_claim_ack_is_idempotent_for_same_cas_record() -> None:
    authority, _claimant, announcement, _receipt, record = _fixture()

    first = sign_authority_claim_ack(
        authority=authority, announcement=announcement, claim_record=record,
    )
    second = sign_authority_claim_ack(
        authority=authority, announcement=announcement, claim_record=record,
    )

    assert first == second
