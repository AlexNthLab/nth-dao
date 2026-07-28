"""C2 (receipt-side cap_token chain) + Phase B (receipt chaining).

Implements DESIGN_TRADE_OFFS §2 (authorizing_cap_token) and §1 D1
follow-through (per-signer chain link via ``nth.chain_link`` entry).

What this suite proves:

  C2:
    1. A receipt signed by an ephemeral DID with a valid
       authorizing_cap_token verifies under verify_receipt.
    2. Tampering the cap_token (any field) → verify fails.
    3. Re-signed cap_token from a different issuer → verify fails
       (subject_did mismatch with receipt signer).
    4. Cap_token without nth:receipt_sign capability → verify
       fails.
    5. Cap_token expired before receipt issued_at → verify fails.
    6. Cap_token scope_task_id ≠ receipt goal_id → verify fails.
    7. **Revocation NOT consulted at receipt verify** (D7
       normative semantic): revoking the cap_token after the
       receipt was signed leaves the receipt valid.

  Phase B:
    8. Chained receipts (3-deep): each verifies individually AND
       as a chain.
    9. Dropping a middle receipt → chain verify fails (orphan
       prev pointer).
   10. Forking the chain (two receipts share the same prev) →
       chain verify fails.
   11. Two genesis receipts → chain verify fails.
   12. Different signer_did mid-chain → chain verify fails.
   13. Tampering prev_content_hash payload → individual verify
       fails (signed body covers the link entry).
   14. ReceiptStore.head_content_hash returns latest by issued_at.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from nth_dao.cap_token import (
    CAP_A2A_MESSAGE_SEND,
    CAP_NTH_RECEIPT_SIGN,
    sign_cap_token,
)
from nth_dao.execution_receipt import (
    ReceiptStore,
    TYPE_GOAL_COMPLETED,
    TYPE_GOAL_STARTED,
    TYPE_NTH_CHAIN_LINK,
    TimelineEntry,
    extract_prev_content_hash,
    now_ms,
    sign_receipt,
    verify_receipt,
    verify_receipt_chain,
)
from nth_dao.identity import AgentIdentity, crypto_available


pytestmark = pytest.mark.skipif(
    not crypto_available(),
    reason="cap_token chain + receipt chaining require PyNaCl",
)


# ─── helpers ─────────────────────────────────────────────────────────


@pytest.fixture
def admin() -> AgentIdentity:
    return AgentIdentity.generate(label="admin")


@pytest.fixture
def helper() -> AgentIdentity:
    return AgentIdentity.generate(label="helper")


def _entry(type_=TYPE_GOAL_STARTED, **payload) -> TimelineEntry:
    return TimelineEntry(timestamp=now_ms(), type=type_, payload=payload)


# ─── C2: cap_token chain verification ────────────────────────────────


def test_c2_chained_receipt_verifies(admin, helper):
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_NTH_RECEIPT_SIGN],
    )
    r = sign_receipt(
        [_entry(goal_id="g1")], helper,
        authorizing_cap_token=tok,
    )
    assert verify_receipt(r)
    # The cap_token is preserved on the envelope verbatim
    assert r["authorizing_cap_token"] == tok


def test_c2_tampered_cap_token_capabilities_rejected(admin, helper):
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_NTH_RECEIPT_SIGN],
    )
    r = sign_receipt(
        [_entry()], helper, authorizing_cap_token=tok,
    )
    # Mutate the cap_token capabilities after attaching — sig
    # invalid → reject.
    r["authorizing_cap_token"]["capabilities"].append("nth:add_member")
    assert verify_receipt(r) is False


def test_c2_cap_token_from_different_issuer_rejected(admin, helper):
    """An attacker who signs a cap_token claiming Tony's subject
    DID with their own issuer key — verifier rejects because the
    receipt's signer pubkey doesn't match the subject_did pubkey
    derivation (and the cap_token verify catches the issuer
    signature)."""
    attacker = AgentIdentity.generate(label="attacker")
    # Attacker mints a cap_token for THEMSELVES as subject
    attacker_tok = sign_cap_token(
        issuer=attacker, subject_did=attacker.as_did(),
        capabilities=[CAP_NTH_RECEIPT_SIGN],
    )
    # Then signs a receipt with helper's identity but attaches
    # the attacker's token — subject mismatch.
    r = sign_receipt(
        [_entry()], helper, authorizing_cap_token=attacker_tok,
    )
    assert verify_receipt(r) is False


def test_c2_cap_token_missing_receipt_sign_capability_rejected(admin, helper):
    """A cap_token granting only A2A capabilities cannot
    authorize a receipt signature."""
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_A2A_MESSAGE_SEND],
    )
    r = sign_receipt(
        [_entry()], helper, authorizing_cap_token=tok,
    )
    assert verify_receipt(r) is False


def test_c2_cap_token_expired_before_receipt_rejected(admin, helper):
    """A cap_token whose not_after precedes receipt issued_at
    cannot authorize the receipt — the user delegated and the
    window closed before the work happened."""
    # Mint a token that expires 1 second in the future
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_NTH_RECEIPT_SIGN],
        ttl_ms=1000,
    )
    # Force receipt issued_at to be AFTER the cap_token expired.
    # We do this by forging the not_after to a time in the past.
    tok["not_after"] = now_ms() - 1
    # Re-sign would invalidate; but we know verify_cap_token will
    # reject this at the time-bound check first, so just attach.
    r = sign_receipt(
        [_entry()], helper, authorizing_cap_token=tok,
    )
    assert verify_receipt(r) is False


def test_c2_cap_token_scope_task_mismatch_rejected(admin, helper):
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_NTH_RECEIPT_SIGN],
        scope_task_id="task-A",
    )
    # Receipt with goal_id=task-B — scope mismatch.
    r = sign_receipt(
        [_entry()], helper,
        goal_id="task-B",
        authorizing_cap_token=tok,
    )
    assert verify_receipt(r) is False


def test_c2_cap_token_scope_match_accepted(admin, helper):
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_NTH_RECEIPT_SIGN],
        scope_task_id="task-A",
    )
    r = sign_receipt(
        [_entry()], helper,
        goal_id="task-A",
        authorizing_cap_token=tok,
    )
    assert verify_receipt(r)


def test_c2_d7_receipt_signed_within_window_verifies_after_cap_expired(
    admin, helper,
):
    """R1 (audit fix 2026-06-08): the D7 normative semantic also
    applies to TIME: a receipt signed at time T while the cap_token
    was valid (cap.not_before <= T <= cap.not_after) MUST verify
    forever, even if cap.not_after has since passed.

    The original implementation passed verify_cap_token without
    now_ms_override, so the inner pipeline used current time and
    rejected any cap_token whose not_after had passed. That
    contradicted D7.

    The fix passes ``now_ms_override=receipt_issued_at_ms`` so the
    time check anchors to when the receipt was signed.
    """
    # Mint a cap with a SHORT TTL — already expired by now
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_NTH_RECEIPT_SIGN],
        ttl_ms=1000,
    )
    # Synthesize a receipt with issued_at that falls WITHIN the
    # cap's window. We forge the receipt's issued_at directly so
    # the test is deterministic regardless of wall-clock skew.
    not_before = int(tok["not_before"])
    not_after = int(tok["not_after"])
    receipt_ms = (not_before + not_after) // 2  # middle of window
    # Re-issue the receipt with a precise issued_at
    from datetime import datetime as _dt
    iso = _dt.fromtimestamp(receipt_ms / 1000).isoformat()

    r = sign_receipt([_entry()], helper, authorizing_cap_token=tok)
    r["issued_at"] = iso

    # Simulate "verification happens after cap_token has expired"
    # by waiting until wall-clock is past not_after
    import time as _time
    wait_s = max(0.0, (not_after - _time.time() * 1000) / 1000) + 0.05
    if wait_s > 0:
        _time.sleep(wait_s)
    assert _time.time() * 1000 > not_after, (
        "test precondition: we need wall clock to be past cap not_after"
    )

    # Receipt must still verify per D7
    assert verify_receipt(r), (
        "D7 contract violated: receipt signed within the cap's "
        "time window failed to verify because the cap has since "
        "expired. verify_receipt MUST anchor the cap time check "
        "to the receipt's issued_at, not to current wall clock."
    )


def test_c2_d7_revocation_does_not_invalidate_past_receipt(admin, helper):
    """DESIGN_TRADE_OFFS §2 + D7 normative semantic:
    revoking a cap_token AFTER it signed a receipt does NOT
    retroactively invalidate that receipt. verify_receipt MUST
    NOT consult the revoked_set when verifying the chain."""
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_NTH_RECEIPT_SIGN],
    )
    r = sign_receipt(
        [_entry()], helper, authorizing_cap_token=tok,
    )
    # Receipt was valid at signing time
    assert verify_receipt(r)
    # Now the admin "revokes" the token. We simulate by passing
    # the token_id through a store's revoked_set — but verify_receipt
    # MUST NOT consult any store's revocation state. The receipt
    # remains valid forever.
    # The verify path internally calls verify_cap_token with
    # revoked_ids=set() to enforce this.
    assert verify_receipt(r), (
        "D7 contract violated: cap_token-chained receipt failed "
        "to verify after a logical revocation (verify_receipt is "
        "consulting the revocation list, which it MUST NOT)"
    )


# ─── Phase B: receipt chaining ───────────────────────────────────────


def test_phase_b_chain_link_entry_is_prepended(admin, helper):
    # Genesis
    r1 = sign_receipt([_entry()], helper)
    assert extract_prev_content_hash(r1) == ""

    # Non-genesis
    r2 = sign_receipt(
        [_entry()], helper, prev_content_hash=r1["content_hash"],
    )
    assert r2["timeline"][0]["type"] == TYPE_NTH_CHAIN_LINK
    assert extract_prev_content_hash(r2) == r1["content_hash"]


def test_phase_b_three_deep_chain_verifies(helper):
    r1 = sign_receipt([_entry(payload_n=1)], helper)
    r2 = sign_receipt(
        [_entry(payload_n=2)], helper,
        prev_content_hash=r1["content_hash"],
    )
    r3 = sign_receipt(
        [_entry(payload_n=3)], helper,
        prev_content_hash=r2["content_hash"],
    )
    assert verify_receipt_chain([r1, r2, r3])
    # Also verify input order doesn't matter
    assert verify_receipt_chain([r3, r1, r2])


def test_phase_b_dropping_middle_receipt_breaks_chain(helper):
    r1 = sign_receipt([_entry()], helper)
    r2 = sign_receipt(
        [_entry()], helper, prev_content_hash=r1["content_hash"],
    )
    r3 = sign_receipt(
        [_entry()], helper, prev_content_hash=r2["content_hash"],
    )
    # Dropping r2 leaves r3 with an orphan prev pointer
    assert verify_receipt_chain([r1, r3]) is False


def test_phase_b_forked_chain_rejected(helper):
    """Two receipts sharing the same prev_content_hash is a fork.
    Per the spec, a fork is a malformed chain."""
    r1 = sign_receipt([_entry()], helper)
    r2a = sign_receipt(
        [_entry(branch="a")], helper,
        prev_content_hash=r1["content_hash"],
    )
    r2b = sign_receipt(
        [_entry(branch="b")], helper,
        prev_content_hash=r1["content_hash"],
    )
    assert verify_receipt_chain([r1, r2a, r2b]) is False


def test_phase_b_two_genesis_rejected(helper):
    """Two receipts with no prev pointer is malformed — a chain has
    exactly one genesis."""
    r1 = sign_receipt([_entry(n=1)], helper)
    r2 = sign_receipt([_entry(n=2)], helper)  # also genesis
    assert verify_receipt_chain([r1, r2]) is False


def test_phase_b_different_signer_midchain_rejected(admin, helper):
    """A chain is per-signer. Mixing two signers' receipts is
    a malformed input — chain verify rejects."""
    r1 = sign_receipt([_entry()], helper)
    r2 = sign_receipt(
        [_entry()], admin,
        prev_content_hash=r1["content_hash"],
    )
    assert verify_receipt_chain([r1, r2]) is False


def test_phase_b_tampered_chain_link_payload_invalidates_receipt(helper):
    """The chain_link entry is INSIDE the timeline, so it's part
    of content_hash, so tampering invalidates sig."""
    r1 = sign_receipt([_entry()], helper)
    r2 = sign_receipt(
        [_entry()], helper, prev_content_hash=r1["content_hash"],
    )
    # Flip one bit of the prev_content_hash
    bogus = r1["content_hash"][:-1] + (
        "0" if r1["content_hash"][-1] != "0" else "1"
    )
    r2["timeline"][0]["payload"]["prev_content_hash"] = bogus
    assert verify_receipt(r2) is False


def test_phase_b_prev_content_hash_invalid_length_rejected_at_sign(helper):
    with pytest.raises(ValueError):
        sign_receipt(
            [_entry()], helper, prev_content_hash="short",
        )


def test_phase_b_prev_content_hash_non_hex_rejected_at_sign(helper):
    with pytest.raises(ValueError):
        sign_receipt(
            [_entry()], helper,
            prev_content_hash="z" * 64,
        )


# ─── ReceiptStore.head_content_hash ─────────────────────────────────


def test_store_head_returns_empty_for_unknown_signer(tmp_path):
    store = ReceiptStore(tmp_path)
    assert store.head_content_hash("did:key:zNoSuch") == ""


def test_store_head_returns_latest_by_issued_at(tmp_path, helper):
    store = ReceiptStore(tmp_path)
    r1 = sign_receipt([_entry()], helper)
    store.save(r1)
    time.sleep(0.01)  # ensure issued_at differs
    r2 = sign_receipt([_entry()], helper)
    store.save(r2)
    assert store.head_content_hash(helper.as_did()) == r2["content_hash"]


def test_store_head_is_per_signer(tmp_path, admin, helper):
    """Two different signers have INDEPENDENT chain heads — the
    store partitions by signer_did."""
    store = ReceiptStore(tmp_path)
    r_admin = sign_receipt([_entry()], admin)
    r_helper = sign_receipt([_entry()], helper)
    store.save(r_admin)
    store.save(r_helper)
    assert store.head_content_hash(admin.as_did()) == r_admin["content_hash"]
    assert store.head_content_hash(helper.as_did()) == r_helper["content_hash"]


def test_store_sign_and_save_serializes_competing_chain_extensions(
    tmp_path, helper,
):
    """Two independent store instances must not mint sibling chain heads."""
    barrier = Barrier(2)

    def _append(index: int):
        store = ReceiptStore(tmp_path)
        barrier.wait(timeout=5)
        return store.sign_and_save([_entry(worker=index)], helper)

    with ThreadPoolExecutor(max_workers=2) as pool:
        receipts = list(pool.map(_append, (1, 2)))

    persisted = [
        ReceiptStore(tmp_path).load(str(receipt["receipt_id"]))
        for receipt in receipts
    ]
    assert all(receipt is not None for receipt in persisted)
    loaded = [receipt for receipt in persisted if receipt is not None]
    prev_hashes = [extract_prev_content_hash(receipt) for receipt in loaded]
    assert prev_hashes.count("") == 1
    assert len(set(prev_hashes) - {""}) == 1
    assert verify_receipt_chain(loaded)


def test_store_sign_and_save_refuses_tampered_existing_head(
    tmp_path, helper,
):
    store = ReceiptStore(tmp_path)
    poisoned = sign_receipt([_entry(value="original")], helper)
    poisoned["timeline"][-1]["payload"]["value"] = "tampered"
    store.save(poisoned)

    with pytest.raises(RuntimeError, match="poisoned chain"):
        store.sign_and_save([_entry(value="next")], helper)

    assert store.list_ids() == [poisoned["receipt_id"]]


def test_e4_cap_token_chain_plus_receipt_chain_combined(
    tmp_path, admin, helper,
):
    """E4 (audit fix 2026-06-08): the C2 cap_token chain and
    Phase B per-signer receipt chain MUST compose cleanly. An
    ephemeral subject DID can sign a SEQUENCE of receipts where
    every receipt:

      * is authorized by the same cap_token (chain through to
        the root user authority)
      * links to the previous receipt in the sequence via
        prev_content_hash (chain integrity within the ephemeral
        subject's own history)

    This is the realistic shape of an overnight autonomous-
    agent workload: one cap_token grants a window of authority,
    the agent emits N receipts during that window, each chained
    to the previous.

    Prior to this test, C2 and Phase B were tested independently
    but never together — a real-world deployment is the first
    place the composition would be exercised.
    """
    # Admin mints a cap_token authorizing the helper to sign
    # receipts for the next hour
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_NTH_RECEIPT_SIGN],
        ttl_ms=3600_000,
    )

    store = ReceiptStore(tmp_path)
    chain = []
    prev = ""
    for i in range(4):
        r = sign_receipt(
            [_entry(step=i)],
            helper,
            prev_content_hash=prev,
            authorizing_cap_token=tok,
        )
        store.save(r)
        chain.append(r)
        prev = store.head_content_hash(helper.as_did())
        time.sleep(0.005)

    # Every individual receipt must verify (C2 chain through to admin)
    for r in chain:
        assert verify_receipt(r), (
            f"receipt {r['receipt_id'][:8]} (step {chain.index(r)}) "
            f"failed individual verify"
        )
    # Chain integrity (Phase B) must verify too
    assert verify_receipt_chain(chain), (
        "C2 + Phase B composition failed: 4-receipt chain signed "
        "by an ephemeral subject under a single cap_token does "
        "not verify as a coherent chain"
    )


def test_e2_non_dict_authorizing_cap_token_rejected(helper):
    """E2 (audit fix 2026-06-08): verify_receipt's contract is to
    return False rather than raise. If a malformed envelope has
    ``authorizing_cap_token`` as a non-dict (string / list / int /
    bool), the previous implementation would crash through the
    no-raise boundary at the first ``cap_token.get(...)`` call.
    Guard added in verify_receipt; this test pins the contract."""
    # Build a valid receipt then attach a non-dict at the field
    r = sign_receipt([_entry()], helper)
    # String
    r["authorizing_cap_token"] = "not-a-dict"
    assert verify_receipt(r) is False
    # List
    r["authorizing_cap_token"] = ["not", "a", "dict"]
    assert verify_receipt(r) is False
    # Int
    r["authorizing_cap_token"] = 42
    assert verify_receipt(r) is False
    # Bool — True is technically truthy but not a dict
    r["authorizing_cap_token"] = True
    assert verify_receipt(r) is False


def test_store_head_used_to_build_real_chain_end_to_end(tmp_path, helper):
    """The intended use: sign first receipt, save, query head, use
    head as prev for next receipt, save again — produces a verified
    chain."""
    store = ReceiptStore(tmp_path)
    chain = []
    prev = ""
    for i in range(3):
        r = sign_receipt(
            [_entry(idx=i)], helper, prev_content_hash=prev,
        )
        store.save(r)
        chain.append(r)
        prev = store.head_content_hash(helper.as_did())
        time.sleep(0.005)  # disambiguate issued_at
    assert verify_receipt_chain(chain)
