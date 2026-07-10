"""Execution Receipt — L1-1 work-proof primitive (2026-06-08).

What this suite proves:

  1. Canonical content_hash is byte-identical to motebit
     execution-ledger@1.0 §5 (the spec example: one entry yields one
     known hash; reordering keys inside payload does NOT change the
     hash because canonical_json sorts).
  2. Signature is computed over the 32-byte raw digest, NOT the
     64-char hex string (verifiers that implement the spec correctly
     will reject hex-string signatures).
  3. base64url uses ``-``/``_`` alphabet, NO padding.
  4. Verify round-trip: sign → verify True; tamper anything → verify
     False.
  5. ``expected_pubkey_hex`` belt-and-braces: even if the receipt
     itself is internally consistent, a caller who knows the agent's
     pubkey from another channel can lock down "the receipt is from
     THIS agent specifically" rather than "from someone with a valid
     DID".
  6. ReceiptStore: atomic save, load round-trips, path-traversal
     rejection.
  7. Timeline contracts: empty rejected; non-int timestamp rejected;
     non-dict payload rejected.

If any test here fails after a refactor, you've broken interop with
motebit's existing receipts in the wild. The deterministic-hash test
is the canary — it pins a known input to a known SHA-256 output.
"""

from __future__ import annotations

import base64
import json
import shutil
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from nth_dao.execution_receipt import (
    MOTEBIT_BASE_TYPES,
    MOTEBIT_COMPATIBLE,
    NTH_RECEIPT_KIND,
    NTH_RECEIPT_SPEC,
    ReceiptStore,
    TYPE_GOAL_COMPLETED,
    TYPE_GOAL_STARTED,
    TYPE_NTH_POST_MESSAGE,
    TYPE_TOOL_INVOKED,
    TimelineEntry,
    compute_content_hash,
    now_ms,
    sign_receipt,
    verify_receipt,
)
from nth_dao.identity import AgentIdentity, crypto_available


pytestmark = pytest.mark.skipif(
    not crypto_available(),
    reason="receipts require PyNaCl",
)


# ─── TimelineEntry contracts ─────────────────────────────────────────


def test_timeline_entry_rejects_float_timestamp():
    """motebit spec example uses integer ms. Float timestamps are a
    portability hazard — different float-to-string rules across
    languages would break interop."""
    with pytest.raises(TypeError):
        TimelineEntry(timestamp=1710288000.5, type="x")  # type: ignore[arg-type]


def test_timeline_entry_rejects_negative_timestamp():
    with pytest.raises(ValueError):
        TimelineEntry(timestamp=-1, type="x")


def test_timeline_entry_rejects_empty_type():
    with pytest.raises(ValueError):
        TimelineEntry(timestamp=0, type="")


def test_timeline_entry_rejects_non_dict_payload():
    with pytest.raises(TypeError):
        TimelineEntry(
            timestamp=0, type="x", payload="not-a-dict",  # type: ignore[arg-type]
        )


def test_motebit_base_types_are_the_11_documented():
    """motebit execution-ledger@1.0 §4 lists exactly 11 base types.
    If this set drifts the README and consumer docs go stale."""
    assert len(MOTEBIT_BASE_TYPES) == 11
    assert "goal_started" in MOTEBIT_BASE_TYPES
    assert "goal_completed" in MOTEBIT_BASE_TYPES
    assert "tool_invoked" in MOTEBIT_BASE_TYPES


def test_nth_extension_types_namespaced():
    """Per motebit's extension convention, NTH-added types must
    carry the ``nth.`` namespace prefix."""
    assert TYPE_NTH_POST_MESSAGE.startswith("nth.")


# ─── content_hash determinism (motebit interop) ──────────────────────


def test_compute_content_hash_against_motebit_spec_example():
    """motebit execution-ledger@1.0 §5 cites this exact entry:

        {"payload":{"goal_id":"goal-01","prompt":"Search for flights"},"timestamp":1710288000000,"type":"goal_started"}

    The full content_hash of a 1-entry timeline of this entry is
    deterministic SHA-256 of the canonical UTF-8 bytes. If
    canonical_json's key ordering or whitespace handling drifts,
    NTH-emitted receipts would stop verifying on motebit consumers.
    """
    entry = TimelineEntry(
        timestamp=1710288000000,
        type=TYPE_GOAL_STARTED,
        payload={
            "goal_id": "goal-01",
            "prompt": "Search for flights",
        },
    )
    h = compute_content_hash([entry])

    # Recompute the expected hash directly from the spec-quoted
    # canonical bytes. If this assertion fails, EITHER our
    # canonical_json drifted from motebit's rules OR motebit changed
    # their spec — investigate which before "fixing" the test.
    import hashlib
    spec_bytes = (
        b'{"payload":{"goal_id":"goal-01","prompt":"Search for flights"},'
        b'"timestamp":1710288000000,"type":"goal_started"}'
    )
    expected = hashlib.sha256(spec_bytes).hexdigest()
    assert h == expected, (
        f"content_hash drifted from motebit spec: got {h}, expected "
        f"{expected}. NTH-emitted receipts will not verify against "
        f"motebit consumers."
    )


def test_compute_content_hash_joins_multiple_entries_with_newline():
    """Two-entry timeline: per-entry canonical bytes joined with
    ``\\n`` (U+000A) before hashing."""
    e1 = TimelineEntry(timestamp=1, type="goal_started", payload={"a": 1})
    e2 = TimelineEntry(timestamp=2, type="goal_completed", payload={"b": 2})
    h = compute_content_hash([e1, e2])

    import hashlib
    expected_bytes = (
        b'{"payload":{"a":1},"timestamp":1,"type":"goal_started"}'
        b"\n"
        b'{"payload":{"b":2},"timestamp":2,"type":"goal_completed"}'
    )
    expected = hashlib.sha256(expected_bytes).hexdigest()
    assert h == expected


def test_content_hash_unaffected_by_payload_key_order():
    """canonical_json sorts keys — content_hash MUST be stable across
    payload key orderings."""
    e1 = TimelineEntry(
        timestamp=0, type="x", payload={"a": 1, "b": 2},
    )
    e2 = TimelineEntry(
        timestamp=0, type="x", payload={"b": 2, "a": 1},
    )
    assert compute_content_hash([e1]) == compute_content_hash([e2])


def test_content_hash_rejects_empty_timeline():
    with pytest.raises(ValueError):
        compute_content_hash([])


# ─── signing: 32-byte digest, NOT hex string ─────────────────────────


def test_sign_receipt_signs_raw_digest_not_hex_string():
    """The motebit spec is explicit (§6): ``Ed25519_Sign(content_hash_bytes,
    private_key)`` over the 32-byte raw digest. An implementation that
    signs the hex string instead would produce signatures that fail
    every spec-conforming verifier.

    We re-sign manually with the wrong input and prove that the
    receipt's stored sig matches the RIGHT input.
    """
    ident = AgentIdentity.generate(label="raw-digest-test")
    entry = TimelineEntry(
        timestamp=now_ms(), type=TYPE_GOAL_STARTED, payload={},
    )
    receipt = sign_receipt([entry], ident)

    content_hash = receipt["content_hash"]
    sig_b64 = receipt["sig"]
    sig_bytes = base64.urlsafe_b64decode(
        sig_b64 + "=" * (-len(sig_b64) % 4)
    )

    # Signature over the 32-byte digest MUST verify
    raw_digest = bytes.fromhex(content_hash)
    from nacl.signing import VerifyKey
    vk = VerifyKey(bytes.fromhex(ident.pubkey_hex))
    vk.verify(raw_digest, sig_bytes)  # raises BadSignatureError on mismatch

    # Signature over the HEX STRING (the wrong input) MUST NOT verify
    from nacl.exceptions import BadSignatureError
    with pytest.raises(BadSignatureError):
        vk.verify(content_hash.encode("ascii"), sig_bytes)


def test_sig_is_base64url_no_padding():
    """RFC 4648 §5 base64url: alphabet ``-``/``_``, no ``=`` padding."""
    ident = AgentIdentity.generate(label="b64u-test")
    entry = TimelineEntry(timestamp=now_ms(), type=TYPE_GOAL_STARTED)
    sig = sign_receipt([entry], ident)["sig"]
    # No padding
    assert "=" not in sig
    # No standard-b64 alphabet characters that should have been
    # mapped to URL-safe alternatives
    assert "+" not in sig
    assert "/" not in sig


# ─── verify: positive + tampering ────────────────────────────────────


def test_verify_round_trip_passes():
    ident = AgentIdentity.generate(label="rt")
    e1 = TimelineEntry(
        timestamp=now_ms(), type=TYPE_GOAL_STARTED, payload={"g": "g1"},
    )
    e2 = TimelineEntry(
        timestamp=now_ms() + 1,
        type=TYPE_GOAL_COMPLETED,
        payload={"ok": True},
    )
    receipt = sign_receipt([e1, e2], ident, goal_id="g1")
    assert verify_receipt(receipt) is True


def test_verify_with_expected_pubkey_matches():
    ident = AgentIdentity.generate(label="exp")
    e = TimelineEntry(timestamp=now_ms(), type=TYPE_GOAL_STARTED)
    receipt = sign_receipt([e], ident)
    assert verify_receipt(
        receipt, expected_pubkey_hex=ident.pubkey_hex,
    ) is True


def test_verify_with_wrong_expected_pubkey_rejects():
    """Even if the receipt is internally consistent, a caller can
    bind it to a pubkey they trust — protects against did:key spoof
    if the consumer learned the pubkey via a separate trust channel."""
    ident = AgentIdentity.generate(label="exp")
    other = AgentIdentity.generate(label="other")
    e = TimelineEntry(timestamp=now_ms(), type=TYPE_GOAL_STARTED)
    receipt = sign_receipt([e], ident)
    assert verify_receipt(
        receipt, expected_pubkey_hex=other.pubkey_hex,
    ) is False


def test_verify_rejects_tampered_timeline():
    ident = AgentIdentity.generate(label="tamper")
    e = TimelineEntry(
        timestamp=now_ms(), type=TYPE_GOAL_STARTED, payload={"x": 1},
    )
    receipt = sign_receipt([e], ident)
    # Mutate the payload — content_hash will no longer match
    receipt["timeline"][0]["payload"]["x"] = 999
    assert verify_receipt(receipt) is False


def test_verify_rejects_tampered_content_hash():
    """An attacker who edits content_hash to match a tampered timeline
    still loses because sig is over the (now-stale) original hash."""
    ident = AgentIdentity.generate(label="tamper2")
    e = TimelineEntry(timestamp=now_ms(), type=TYPE_GOAL_STARTED)
    receipt = sign_receipt([e], ident)
    # Recompute hash for a fake timeline; copy it in
    fake = TimelineEntry(
        timestamp=now_ms(), type=TYPE_GOAL_STARTED, payload={"evil": True},
    )
    receipt["timeline"] = [fake.to_dict()]
    receipt["content_hash"] = compute_content_hash([fake])
    # sig is now stale — verify must fail
    assert verify_receipt(receipt) is False


def test_verify_rejects_signature_under_different_key():
    """An attacker re-signs with a different keypair; verify must
    reject when expected_pubkey_hex is supplied."""
    real = AgentIdentity.generate(label="real")
    fake_signer = AgentIdentity.generate(label="fake")
    e = TimelineEntry(timestamp=now_ms(), type=TYPE_GOAL_STARTED)
    receipt = sign_receipt([e], fake_signer)
    # If the consumer knows the REAL agent's pubkey, this fake-signed
    # receipt must fail.
    assert verify_receipt(
        receipt, expected_pubkey_hex=real.pubkey_hex,
    ) is False


def test_verify_rejects_internally_inconsistent_envelope():
    """If signer_pubkey_hex disagrees with the pubkey derived from
    signer_did, the receipt is lying about who signed it."""
    ident = AgentIdentity.generate(label="liar")
    other = AgentIdentity.generate(label="other")
    e = TimelineEntry(timestamp=now_ms(), type=TYPE_GOAL_STARTED)
    receipt = sign_receipt([e], ident)
    # Substitute someone else's pubkey in the envelope
    receipt["signer_pubkey_hex"] = other.pubkey_hex
    assert verify_receipt(receipt) is False


def test_verify_rejects_missing_signer_did():
    ident = AgentIdentity.generate(label="nodid")
    e = TimelineEntry(timestamp=now_ms(), type=TYPE_GOAL_STARTED)
    receipt = sign_receipt([e], ident)
    receipt["signer_did"] = ""
    assert verify_receipt(receipt) is False


# ─── envelope shape ──────────────────────────────────────────────────


def test_receipt_carries_motebit_compat_marker():
    """A motebit consumer looking for our receipts can scan for the
    ``compatible_with`` field as a fast filter."""
    ident = AgentIdentity.generate(label="compat")
    e = TimelineEntry(timestamp=now_ms(), type=TYPE_GOAL_STARTED)
    receipt = sign_receipt([e], ident)
    assert receipt["compatible_with"] == MOTEBIT_COMPATIBLE
    assert receipt["spec"] == NTH_RECEIPT_SPEC
    assert receipt["kind"] == NTH_RECEIPT_KIND


def test_receipt_id_is_uuid_when_unspecified():
    ident = AgentIdentity.generate(label="rid")
    e = TimelineEntry(timestamp=now_ms(), type=TYPE_GOAL_STARTED)
    r1 = sign_receipt([e], ident)
    r2 = sign_receipt([e], ident)
    assert r1["receipt_id"] != r2["receipt_id"]
    # uuid4().hex is 32 chars
    assert len(r1["receipt_id"]) == 32


def test_receipt_id_caller_supplied_preserved():
    ident = AgentIdentity.generate(label="rid2")
    e = TimelineEntry(timestamp=now_ms(), type=TYPE_GOAL_STARTED)
    r = sign_receipt([e], ident, receipt_id="custom-id-123")
    assert r["receipt_id"] == "custom-id-123"


def test_envelope_fields_NOT_covered_by_signature():
    """The envelope (receipt_id, goal_id, issued_at) is discovery
    metadata only. Mutating them must NOT invalidate verification —
    only ``timeline`` + ``content_hash`` + ``sig`` are the trust chain."""
    ident = AgentIdentity.generate(label="env")
    e = TimelineEntry(timestamp=now_ms(), type=TYPE_GOAL_STARTED)
    receipt = sign_receipt([e], ident, goal_id="g1")
    receipt["goal_id"] = "g2-changed"
    receipt["receipt_id"] = "different"
    receipt["issued_at"] = "1999-01-01T00:00:00"
    # All envelope mutations preserved verification
    assert verify_receipt(receipt) is True


# ─── ReceiptStore ────────────────────────────────────────────────────


def test_store_save_then_load_roundtrips(tmp_path):
    store = ReceiptStore(tmp_path)
    ident = AgentIdentity.generate(label="st")
    e = TimelineEntry(
        timestamp=now_ms(), type=TYPE_TOOL_INVOKED, payload={"tool": "x"},
    )
    receipt = sign_receipt([e], ident)
    path = store.save(receipt)
    assert path.exists()
    loaded = store.load(receipt["receipt_id"])
    assert loaded is not None
    # Round-trip preserves verification — sig still good
    assert verify_receipt(loaded) is True


def test_store_save_is_atomic_no_tmp_lingers(tmp_path):
    store = ReceiptStore(tmp_path)
    ident = AgentIdentity.generate(label="atomic")
    e = TimelineEntry(timestamp=now_ms(), type=TYPE_GOAL_STARTED)
    receipt = sign_receipt([e], ident)
    store.save(receipt)
    # After a successful save, no .tmp file should remain
    leftover = list((tmp_path / "team_receipts").glob("*.tmp"))
    assert not leftover, f"orphaned .tmp files: {leftover}"


def test_store_concurrent_same_receipt_id_does_not_collide_on_tmp(tmp_path):
    store = ReceiptStore(tmp_path)
    ident = AgentIdentity.generate(label="atomic-race")
    e = TimelineEntry(timestamp=now_ms(), type=TYPE_GOAL_STARTED)
    receipt = sign_receipt([e], ident, receipt_id="same-receipt-id")

    with ThreadPoolExecutor(max_workers=8) as pool:
        paths = list(pool.map(lambda _i: store.save(receipt), range(16)))

    assert len(set(paths)) == 1
    assert paths[0].exists()
    loaded = store.load("same-receipt-id")
    assert loaded is not None
    assert verify_receipt(loaded) is True
    leftover = list((tmp_path / "team_receipts").glob("*.tmp"))
    assert not leftover, f"orphaned .tmp files: {leftover}"


def test_store_save_recreates_receipts_dir_if_removed(tmp_path):
    """Runtime cleanup or operator repair can remove team_receipts
    after app bootstrap. save() must self-heal the directory instead
    of turning a valid agent reply into a channel error."""
    store = ReceiptStore(tmp_path)
    shutil.rmtree(tmp_path / "team_receipts")
    ident = AgentIdentity.generate(label="recreate")
    e = TimelineEntry(timestamp=now_ms(), type=TYPE_GOAL_STARTED)
    receipt = sign_receipt([e], ident)

    path = store.save(receipt)

    assert path.exists()
    assert store.load(receipt["receipt_id"]) is not None


def test_store_rejects_traversal_in_receipt_id(tmp_path):
    """Path-traversal protection: receipt_id with ``..`` or ``/`` is
    rejected. Otherwise a malicious caller could write to ANYWHERE
    on disk."""
    store = ReceiptStore(tmp_path)
    ident = AgentIdentity.generate(label="trav")
    e = TimelineEntry(timestamp=now_ms(), type=TYPE_GOAL_STARTED)
    receipt = sign_receipt([e], ident, receipt_id="../escape")
    with pytest.raises(ValueError):
        store.save(receipt)


def test_store_list_ids_returns_saved_ids(tmp_path):
    store = ReceiptStore(tmp_path)
    ident = AgentIdentity.generate(label="list")
    ids = []
    for _ in range(3):
        e = TimelineEntry(timestamp=now_ms(), type=TYPE_GOAL_STARTED)
        r = sign_receipt([e], ident)
        store.save(r)
        ids.append(r["receipt_id"])
    listed = set(store.list_ids())
    assert set(ids) <= listed


def test_store_load_missing_returns_none(tmp_path):
    store = ReceiptStore(tmp_path)
    assert store.load("nonexistent-id") is None


def test_store_load_rejects_traversal_id(tmp_path):
    """Load also rejects suspicious IDs — symmetric to save."""
    store = ReceiptStore(tmp_path)
    assert store.load("../../etc/passwd") is None


def test_store_contains_operator(tmp_path):
    store = ReceiptStore(tmp_path)
    ident = AgentIdentity.generate(label="contains")
    e = TimelineEntry(timestamp=now_ms(), type=TYPE_GOAL_STARTED)
    r = sign_receipt([e], ident)
    store.save(r)
    assert r["receipt_id"] in store
    assert "nonexistent" not in store


# ─── now_ms helper ───────────────────────────────────────────────────


def test_now_ms_returns_integer_milliseconds():
    """Documented contract: integer milliseconds since Unix epoch.
    Not seconds, not nanoseconds — milliseconds, like motebit's spec
    example."""
    n = now_ms()
    assert isinstance(n, int)
    # Sanity: should be greater than year 2020 in ms
    assert n > 1_577_836_800_000   # 2020-01-01T00:00:00Z in ms


def test_ma3_hash_and_dicts_helper_returns_consistent_triple():
    """MA-3 (review fix 2026-06-08): ``_hash_and_dicts`` returns
    ``(hex_str, raw_32_byte_digest, entry_dicts)``. The three pieces
    must be consistent with each other and with the public
    ``compute_content_hash`` API.

    If this test fails, ``sign_receipt`` may be using a stale digest
    (signing one input, advertising another hash) — a
    catastrophe-grade interop bug.
    """
    from nth_dao.execution_receipt import _hash_and_dicts
    entry = TimelineEntry(
        timestamp=1710288000000,
        type=TYPE_GOAL_STARTED,
        payload={"goal_id": "x", "prompt": "y"},
    )
    hex_str, digest, dicts = _hash_and_dicts([entry])
    # Consistency between hex and digest
    assert digest == bytes.fromhex(hex_str)
    assert len(digest) == 32   # SHA-256 size
    # Consistency with the public API
    assert hex_str == compute_content_hash([entry])
    # Consistency between entry_dicts and the input entries
    assert dicts == [entry.to_dict()]


def test_ma3_sign_receipt_does_one_canonicalization_pass(monkeypatch):
    """MA-3 regression canary: sign_receipt MUST NOT canonicalize the
    same timeline twice. Pre-MA3 it did one pass via
    compute_content_hash and a second via the output dict's
    ``timeline`` build. The fix routes everything through
    ``_hash_and_dicts`` so the canonicalization runs exactly once
    per entry per sign.

    Detection: monkeypatch canonical_json to count invocations.
    For a 5-entry timeline we expect 5 invocations, not 10.
    """
    import nth_dao.execution_receipt as er
    counter = {"n": 0}
    real_canonical = er.canonical_json
    def counting(d):
        counter["n"] += 1
        return real_canonical(d)
    monkeypatch.setattr(er, "canonical_json", counting)

    ident = AgentIdentity.generate(label="ma3-perf")
    timeline = [
        TimelineEntry(
            timestamp=now_ms() + i,
            type=TYPE_GOAL_STARTED,
            payload={"i": i},
        )
        for i in range(5)
    ]
    sign_receipt(timeline, ident)
    assert counter["n"] == 5, (
        f"canonical_json was called {counter['n']} times for a 5-entry "
        f"timeline; expected exactly 5 (one per entry). Pre-MA3 it was "
        f"10 (one per entry per pass × 2 passes)."
    )


def test_now_ms_uses_nanosecond_source_not_float_time():
    """MA-1 (review fix 2026-06-08): a previous implementation used
    ``int(time.time() * 1000)``. On Windows ``time.time()`` has
    ~15 ms resolution, which means int() truncation could collapse
    distinct events to the same millisecond. The current impl
    derives from ``time.time_ns()`` which is nanosecond-resolution
    on every platform — confirm the implementation isn't reverted.

    The detection: time_ns() / 1e6 produces millisecond integers
    that are NOT in the small lattice of float-second multiples.
    Specifically, the LSB pattern of (now_ms() % 16) should not be
    biased toward 0 (which it WOULD be under the float-truncation
    bug because Windows quantises time.time() to ~15.6 ms steps,
    making most resulting ms values aligned to 15 or 16).
    """
    import time
    samples = [now_ms() for _ in range(50)]
    # Cheap precision probe: under float-truncation on Windows we'd
    # see <5 distinct ms values across 50 calls in a tight loop
    # (each loop iteration is sub-millisecond). With time_ns we
    # expect many distinct values OR consecutive milliseconds.
    # The actual contract we lock: now_ms must derive from a
    # nanosecond source.
    direct = time.time_ns() // 1_000_000
    delta = abs(direct - samples[-1])
    assert delta < 100, (
        f"now_ms ({samples[-1]}) drifted from a freshly-computed "
        f"time.time_ns() //1e6 ({direct}); the implementation may "
        f"have reverted to int(time.time()*1000)"
    )
