from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest

pytest.importorskip("nacl")

from nth_dao.cap_token import CAP_NTH_RECEIPT_SIGN, sign_cap_token
from nth_dao.identity import AgentIdentity
from nth_dao.market.announcement import announcement_federation_key, sign_announcement
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


def test_claim_ack_lookup_requires_exact_signed_receipt_and_source(
    tmp_path: Path,
) -> None:
    authority, claimant, announcement, receipt, record = _fixture()
    ack = sign_authority_claim_ack(
        authority=authority, announcement=announcement, claim_record=record,
    )
    store = AuthorityClaimAckStore(tmp_path)
    assert store.find_for_receipt(
        receipt,
        expected_authority_did=authority.as_did(),
        expected_federation_key=announcement_federation_key(announcement),
        expected_claimant_did=claimant.as_did(),
    ) is None
    store.save(ack)
    assert store.find_for_receipt(
        receipt,
        expected_authority_did=authority.as_did(),
        expected_federation_key=announcement_federation_key(announcement),
        expected_claimant_did=claimant.as_did(),
    ) == ack
    with pytest.raises(ValueError, match="matching claim ACK"):
        store.find_for_receipt(
            receipt,
            expected_authority_did=authority.as_did(),
            expected_federation_key="nth-ann-sha256:wrong",
            expected_claimant_did=claimant.as_did(),
        )
    with pytest.raises(ValueError, match="envelope does not bind"):
        store.find_for_receipt(
            {**receipt, "goal_id": "market:claim:tampered"},
            expected_authority_did=authority.as_did(),
            expected_federation_key=announcement_federation_key(announcement),
            expected_claimant_did=claimant.as_did(),
        )


def test_claim_ack_lookup_rejects_conflicting_valid_acknowledgements(
    tmp_path: Path,
) -> None:
    authority, claimant, announcement, receipt, record = _fixture()
    store = AuthorityClaimAckStore(tmp_path)
    first = sign_authority_claim_ack(
        authority=authority, announcement=announcement, claim_record=record,
    )
    second = sign_authority_claim_ack(
        authority=authority, announcement=announcement,
        claim_record={**record, "foreign": False},
    )
    assert first["ack_id"] != second["ack_id"]
    store.save(first)
    store.save(second)
    with pytest.raises(ValueError, match="more than one source ACK"):
        store.find_for_receipt(
            receipt,
            expected_authority_did=authority.as_did(),
            expected_federation_key=announcement_federation_key(announcement),
            expected_claimant_did=claimant.as_did(),
        )


def test_claim_ack_lookup_rejects_signed_ack_for_another_announcement(
    tmp_path: Path,
) -> None:
    authority, claimant, _announcement, receipt, record = _fixture()
    other = sign_announcement(
        publisher=authority,
        authority_did=authority.as_did(),
        title="different task",
    )
    mismatched_ack = sign_authority_claim_ack(
        authority=authority, announcement=other, claim_record=record,
    )
    store = AuthorityClaimAckStore(tmp_path)
    store.save(mismatched_ack)
    with pytest.raises(ValueError, match="does not bind the signed claim event"):
        store.find_for_receipt(
            receipt,
            expected_authority_did=authority.as_did(),
            expected_federation_key=announcement_federation_key(other),
            expected_claimant_did=claimant.as_did(),
        )


def test_claim_ack_lookup_fails_closed_on_unbound_corruption(tmp_path: Path) -> None:
    authority, claimant, announcement, receipt, _record = _fixture()
    store = AuthorityClaimAckStore(tmp_path)
    store.root.mkdir(parents=True)
    (store.root / f"{'0' * 64}.json").write_text("{broken", encoding="utf-8")
    (store.root / f"{'1' * 64}.json").write_text(
        '{"ack_id":"' + '1' * 64 + '"}', encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unreadable record"):
        store.find_for_receipt(
            receipt,
            expected_authority_did=authority.as_did(),
            expected_federation_key=announcement_federation_key(announcement),
            expected_claimant_did=claimant.as_did(),
        )
    with pytest.raises(ValueError):
        store.audit()


def test_claim_ack_lookup_handles_more_than_legacy_scan_cap(tmp_path: Path) -> None:
    authority, claimant, announcement, receipt, record = _fixture()
    store = AuthorityClaimAckStore(tmp_path)
    ack = sign_authority_claim_ack(
        authority=authority, announcement=announcement, claim_record=record,
    )
    store.save(ack)
    for index in range(4_097):
        (store.root / f"unrelated-{index}.json").write_text("{}", encoding="utf-8")
    assert store.find_for_receipt(
        receipt,
        expected_authority_did=authority.as_did(),
        expected_federation_key=announcement_federation_key(announcement),
        expected_claimant_did=claimant.as_did(),
    ) == ack


def test_claim_ack_lookup_fails_closed_when_directory_exceeds_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority, claimant, announcement, receipt, record = _fixture()
    store = AuthorityClaimAckStore(tmp_path)
    ack = sign_authority_claim_ack(
        authority=authority, announcement=announcement, claim_record=record,
    )
    store.save(ack)
    monkeypatch.setattr(
        store, "_MAX_DIRECTORY_ENTRIES", sum(1 for _ in store.root.iterdir())
    )
    lookup = {
        "expected_authority_did": authority.as_did(),
        "expected_federation_key": announcement_federation_key(announcement),
        "expected_claimant_did": claimant.as_did(),
    }
    assert store.find_for_receipt(receipt, **lookup) == ack
    (store.root / "unrelated.txt").write_text("unrelated", encoding="utf-8")
    with pytest.raises(ValueError, match="exceeds lookup limit"):
        store.find_for_receipt(receipt, **lookup)


def test_claim_ack_lookup_rejects_parseable_forgery_after_cold_start(
    tmp_path: Path,
) -> None:
    authority, claimant, announcement, receipt, record = _fixture()
    store = AuthorityClaimAckStore(tmp_path)
    ack = sign_authority_claim_ack(
        authority=authority, announcement=announcement, claim_record=record,
    )
    path = store.save(ack)
    path.write_text(
        json.dumps({**ack, "claim_receipt_hash": "0" * 64}), encoding="utf-8",
    )
    AuthorityClaimAckStore._directory_cache.clear()
    with pytest.raises(ValueError, match="invalid evidence"):
        store.find_for_receipt(
            receipt,
            expected_authority_did=authority.as_did(),
            expected_federation_key=announcement_federation_key(announcement),
            expected_claimant_did=claimant.as_did(),
        )


def test_dangling_ack_root_is_not_reported_as_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority, claimant, announcement, receipt, _record = _fixture()
    store = AuthorityClaimAckStore(tmp_path)
    original_is_symlink = Path.is_symlink
    monkeypatch.setattr(
        Path, "is_symlink",
        lambda path: path == store.root or original_is_symlink(path),
    )
    lookup = {
        "expected_authority_did": authority.as_did(),
        "expected_federation_key": announcement_federation_key(announcement),
        "expected_claimant_did": claimant.as_did(),
    }
    with pytest.raises(ValueError, match="must not be a symlink"):
        store.find_for_receipt(receipt, **lookup)
    with pytest.raises(ValueError, match="must not be a symlink"):
        store.audit()


def test_claim_ack_lookup_uses_bounded_descriptor_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority, claimant, announcement, receipt, record = _fixture()
    store = AuthorityClaimAckStore(tmp_path)
    ack = sign_authority_claim_ack(
        authority=authority, announcement=announcement, claim_record=record,
    )
    path = store.save(ack)
    with monkeypatch.context() as patcher:
        patcher.setattr(Path, "read_text", lambda *_args, **_kwargs: (
            pytest.fail("unbounded path read")
        ))
        assert store.find_for_receipt(
            receipt,
            expected_authority_did=authority.as_did(),
            expected_federation_key=announcement_federation_key(announcement),
            expected_claimant_did=claimant.as_did(),
        ) == ack
    path.write_bytes(b" " * (64 * 1024 + 1))
    with pytest.raises(ValueError, match="oversized"):
        store.find_for_receipt(
            receipt,
            expected_authority_did=authority.as_did(),
            expected_federation_key=announcement_federation_key(announcement),
            expected_claimant_did=claimant.as_did(),
        )


def test_corrupt_derived_index_does_not_block_durable_ack(tmp_path: Path) -> None:
    authority, claimant, announcement, receipt, record = _fixture()
    store = AuthorityClaimAckStore(tmp_path)
    index = store.root / "_index" / "ack-index.sqlite3"
    index.parent.mkdir(parents=True)
    index.write_bytes(b"not a sqlite database")
    ack = sign_authority_claim_ack(
        authority=authority, announcement=announcement, claim_record=record,
    )
    path = store.save(ack)
    assert path.is_file()
    assert store.find_for_receipt(
        receipt,
        expected_authority_did=authority.as_did(),
        expected_federation_key=announcement_federation_key(announcement),
        expected_claimant_did=claimant.as_did(),
    ) == ack


def test_imported_ack_is_found_even_if_directory_mtime_is_restored(
    tmp_path: Path,
) -> None:
    authority, claimant, announcement, receipt, record = _fixture()
    store = AuthorityClaimAckStore(tmp_path)
    lookup = {
        "expected_authority_did": authority.as_did(),
        "expected_federation_key": announcement_federation_key(announcement),
        "expected_claimant_did": claimant.as_did(),
    }
    store.root.mkdir(parents=True)
    assert store.find_for_receipt(receipt, **lookup) is None
    before = store.root.stat()
    ack = sign_authority_claim_ack(
        authority=authority, announcement=announcement, claim_record=record,
    )
    (store.root / f"{ack['ack_id']}.json").write_text(
        json.dumps(ack), encoding="utf-8",
    )
    os.utime(store.root, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert store.find_for_receipt(receipt, **lookup) == ack


def test_saving_ack_does_not_scan_historical_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority, claimant, announcement, receipt, record = _fixture()
    store = AuthorityClaimAckStore(tmp_path)
    ack = sign_authority_claim_ack(
        authority=authority, announcement=announcement, claim_record=record,
    )
    with monkeypatch.context() as patcher:
        patcher.setattr(Path, "glob", lambda *_args, **_kwargs: (
            pytest.fail("save scanned historical ACK files")
        ))
        assert store.save(ack).is_file()
    assert store.find_for_receipt(
        receipt,
        expected_authority_did=authority.as_did(),
        expected_federation_key=announcement_federation_key(announcement),
        expected_claimant_did=claimant.as_did(),
    ) == ack


def test_unavailable_index_directory_does_not_change_save_result(
    tmp_path: Path,
) -> None:
    authority, claimant, announcement, receipt, record = _fixture()
    store = AuthorityClaimAckStore(tmp_path)
    store.root.mkdir(parents=True)
    (store.root / "_index").write_bytes(b"not a directory")
    ack = sign_authority_claim_ack(
        authority=authority, announcement=announcement, claim_record=record,
    )
    assert store.save(ack).is_file()
    assert store.find_for_receipt(
        receipt,
        expected_authority_did=authority.as_did(),
        expected_federation_key=announcement_federation_key(announcement),
        expected_claimant_did=claimant.as_did(),
    ) == ack


def test_tampered_obsolete_index_cannot_hide_conflicting_signed_ack(
    tmp_path: Path,
) -> None:
    authority, claimant, announcement, receipt, record = _fixture()
    store = AuthorityClaimAckStore(tmp_path)
    first = sign_authority_claim_ack(
        authority=authority, announcement=announcement, claim_record=record,
    )
    second = sign_authority_claim_ack(
        authority=authority, announcement=announcement,
        claim_record={**record, "foreign": False},
    )
    store.save(first)
    store.save(second)
    index_dir = store.root / "_index"
    index_dir.mkdir()
    with sqlite3.connect(index_dir / "ack-index.sqlite3") as db:
        db.execute("CREATE TABLE files (ack_id TEXT, receipt_hash TEXT)")
        db.execute(
            "INSERT INTO files (ack_id, receipt_hash) VALUES (?, ?)",
            (first["ack_id"], first["claim_receipt_hash"]),
        )
        db.execute(
            "INSERT INTO files (ack_id, receipt_hash) VALUES (?, ?)",
            (second["ack_id"], "0" * 64),
        )
    with pytest.raises(ValueError, match="more than one source ACK"):
        store.find_for_receipt(
            receipt,
            expected_authority_did=authority.as_did(),
            expected_federation_key=announcement_federation_key(announcement),
            expected_claimant_did=claimant.as_did(),
        )


def test_claim_ack_lookup_reuses_unrelated_file_bindings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority, claimant, announcement, receipt, record = _fixture()
    store = AuthorityClaimAckStore(tmp_path)
    ack = sign_authority_claim_ack(
        authority=authority, announcement=announcement, claim_record=record,
    )
    store.save(ack)
    (
        other_authority, _other_claimant, other_announcement,
        _other_receipt, other_record,
    ) = _fixture()
    store.save(sign_authority_claim_ack(
        authority=other_authority,
        announcement=other_announcement,
        claim_record=other_record,
    ))
    assert store.find_for_receipt(
        receipt,
        expected_authority_did=authority.as_did(),
        expected_federation_key=announcement_federation_key(announcement),
        expected_claimant_did=claimant.as_did(),
    ) == ack
    original = store._read_ack
    opened: list[Path] = []

    def record_read(path: Path) -> dict:
        opened.append(path)
        return original(path)

    monkeypatch.setattr(store, "_read_ack", record_read)
    assert store.find_for_receipt(
        receipt,
        expected_authority_did=authority.as_did(),
        expected_federation_key=announcement_federation_key(announcement),
        expected_claimant_did=claimant.as_did(),
    ) == ack
    assert opened == [store.root / f"{ack['ack_id']}.json"]


def test_save_does_not_overwrite_corrupt_existing_ack(tmp_path: Path) -> None:
    authority, _claimant, announcement, _receipt, record = _fixture()
    store = AuthorityClaimAckStore(tmp_path)
    ack = sign_authority_claim_ack(
        authority=authority, announcement=announcement, claim_record=record,
    )
    store.root.mkdir(parents=True)
    path = store.root / f"{ack['ack_id']}.json"
    path.write_bytes(b"{broken")
    with pytest.raises(ValueError):
        store.save(ack)
    assert path.read_bytes() == b"{broken"


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
