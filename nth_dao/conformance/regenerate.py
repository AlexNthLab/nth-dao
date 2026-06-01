"""Regenerate conformance vectors.json from the reference implementation.

Run with:

    python -m nth_dao.conformance.regenerate

This OVERWRITES vectors.json. The file is part of the wire-format
contract — only regenerate when you've explicitly changed the spec.
A PR that touches vectors.json without rationale should be rejected.

Vectors use FIXED keys (not random) so other-language implementations
can reproduce the exact same outputs from the same inputs.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path

from ..identity import canonical_json
from .runner import VECTORS_PATH


# ─────────────────── fixed test keys ───────────────────
# These are NOT real keys for any production agent. They are deterministic
# test fixtures so any implementation can reproduce.

ALICE_SEED_HEX = "00" * 31 + "01"  # 32 bytes
BOB_SEED_HEX   = "00" * 31 + "02"
CAROL_SEED_HEX = "00" * 31 + "03"


def _seed_keypair(seed_hex: str) -> dict:
    """Derive Ed25519 keypair from a deterministic seed."""
    try:
        from nacl.signing import SigningKey
    except ImportError:
        return {"private_hex": seed_hex, "pubkey_hex": "00" * 32}
    sk = SigningKey(bytes.fromhex(seed_hex))
    pk = sk.verify_key
    return {
        "private_hex": seed_hex,
        "pubkey_hex": pk.encode().hex(),
    }


# ─────────────────── individual generators ───────────────────


def gen_canonical_json() -> list:
    """Verify the canonical JSON encoder is byte-identical across implementations."""
    cases = [
        {
            "id": "canon-001",
            "description": "Empty object",
            "input": {},
        },
        {
            "id": "canon-002",
            "description": "Single ASCII field",
            "input": {"name": "alice"},
        },
        {
            "id": "canon-003",
            "description": "Field order MUST be sorted alphabetically",
            "input": {"z": 1, "a": 2, "m": 3},
        },
        {
            "id": "canon-004",
            "description": "Nested objects also sort keys",
            "input": {"outer": {"z": 1, "a": 2}, "another": True},
        },
        {
            "id": "canon-005",
            "description": "Arrays preserve order",
            "input": {"items": [3, 1, 2]},
        },
        {
            "id": "canon-006",
            "description": "Unicode preserved as UTF-8 (no \\u escapes)",
            "input": {"name": "Alice 王"},
        },
        {
            "id": "canon-007",
            "description": "No whitespace between tokens",
            "input": {"a": 1, "b": [2, 3]},
        },
        {
            "id": "canon-008",
            "description": "Booleans and null encoded as JSON literals",
            "input": {"yes": True, "no": False, "absent": None},
        },
    ]
    for c in cases:
        c["expected_bytes_hex"] = canonical_json(c["input"]).hex()
    return cases


def gen_fingerprint() -> list:
    """SHA-256(pubkey_hex)[:16] is the fingerprint of cryptographic agent_ids."""
    alice = _seed_keypair(ALICE_SEED_HEX)
    bob   = _seed_keypair(BOB_SEED_HEX)
    cases = [
        {
            "id": "fp-001",
            "description": "Fingerprint of a known Ed25519 pubkey",
            "input": {"pubkey_hex": alice["pubkey_hex"], "agent_id": ""},
        },
        {
            "id": "fp-002",
            "description": "Different pubkey → different fingerprint",
            "input": {"pubkey_hex": bob["pubkey_hex"], "agent_id": ""},
        },
        {
            "id": "fp-003",
            "description": "Plain agent_id fingerprint (no pubkey)",
            "input": {"pubkey_hex": "", "agent_id": "alice"},
        },
    ]
    for c in cases:
        payload = c["input"]["pubkey_hex"] or c["input"]["agent_id"]
        c["expected_fingerprint"] = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return cases


def gen_signature_verify() -> list:
    """Ed25519 verify with a known message produces a stable signature."""
    try:
        from nacl.signing import SigningKey
    except ImportError:
        return []
    alice_sk = SigningKey(bytes.fromhex(ALICE_SEED_HEX))
    alice_pk = alice_sk.verify_key.encode().hex()
    msg = b"NTH DAO conformance test message"
    sig = alice_sk.sign(msg).signature.hex()
    bob = _seed_keypair(BOB_SEED_HEX)
    return [
        {
            "id": "sig-001",
            "description": "Valid signature under matching pubkey",
            "pubkey_hex": alice_pk,
            "message_hex": msg.hex(),
            "signature_hex": sig,
            "expected_valid": True,
        },
        {
            "id": "sig-002",
            "description": "Same signature under different pubkey → invalid",
            "pubkey_hex": bob["pubkey_hex"],
            "message_hex": msg.hex(),
            "signature_hex": sig,
            "expected_valid": False,
        },
        {
            "id": "sig-003",
            "description": "Tampered signature byte → invalid",
            "pubkey_hex": alice_pk,
            "message_hex": msg.hex(),
            "signature_hex": "00" + sig[2:],   # flip first byte
            "expected_valid": False,
        },
    ]


def gen_endorsement_canonical_payload() -> list:
    """Endorsement.signable_dict() canonical bytes are stable."""
    alice = _seed_keypair(ALICE_SEED_HEX)
    bob = _seed_keypair(BOB_SEED_HEX)
    cases = [
        {
            "id": "endorse-001",
            "description": "Minimal endorsement",
            "input": {
                "endorser_pubkey":  alice["pubkey_hex"],
                "subject_pubkey":   bob["pubkey_hex"],
                "subject_agent_id": "bob",
                "depth_allowed":    1,
                "context":          "general",
                "issued_at":        "2026-01-01T00:00:00",
                "expires_at":       "2026-12-31T00:00:00",
                "sig":              "",   # signable_dict drops this
            },
        },
        {
            "id": "endorse-002",
            "description": "Endorsement with context=code_review and depth=2",
            "input": {
                "endorser_pubkey":  alice["pubkey_hex"],
                "subject_pubkey":   bob["pubkey_hex"],
                "subject_agent_id": "bob",
                "depth_allowed":    2,
                "context":          "code_review",
                "issued_at":        "2026-02-15T10:30:00",
                "expires_at":       "2026-08-15T10:30:00",
                "sig":              "",
            },
        },
    ]
    from ..web_of_trust import Endorsement
    for c in cases:
        e = Endorsement.from_dict(c["input"])
        c["expected_canonical_hex"] = canonical_json(e.signable_dict()).hex()
    return cases


def gen_template_canonical_payload() -> list:
    """MissionTemplate.signable_dict() canonical bytes are stable."""
    alice = _seed_keypair(ALICE_SEED_HEX)
    from ..did_key import encode_ed25519_did_key_hex
    case = {
        "id": "template-001",
        "description": "Minimal v1.0.0 template",
        "input": {
            "template_id":        "code-review",
            "version":            "1.0.0",
            "publisher_pubkey":   alice["pubkey_hex"],
            "publisher_did":      encode_ed25519_did_key_hex(alice["pubkey_hex"]),
            "name":               "Code Review",
            "description":        "Review a diff.",
            "template_type":      "agent_task",
            "category":           "code_review",
            "tags":               ["python"],
            "required_capabilities": ["code_review"],
            "inputs": {},
            "outputs": {},
            "steps": [],
            "suggested_reward":   5.0,
            "suggested_deadline_hours": 0.0,
            "created_at":         "2026-01-01T00:00:00",
            "deprecated":         False,
            "deprecated_reason":  "",
            "supersedes":         [],
            "delegations":        [],
            "credentials_required": [],
            "legal_jurisdiction": "",
            "publisher_sig":      "",
        },
    }
    from ..orchestration.template import MissionTemplate
    t = MissionTemplate.from_dict(case["input"])
    case["expected_canonical_hex"] = canonical_json(t.signable_dict()).hex()
    return [case]


def gen_channel_message_canonical() -> list:
    """ChannelMessage canonical payload bytes for the sign-over-payload step."""
    alice = _seed_keypair(ALICE_SEED_HEX)
    # We re-create the payload exactly as TeamChannel.send() does:
    # {msg_id, channel, from_agent, content, content_type, reply_to,
    #  mentions, timestamp, metadata}
    case = {
        "id": "chmsg-001",
        "description": "Plain text ChannelMessage signable payload (no mentions / no reply)",
        "input": {
            "msg_id":       "abcd1234567890ef",
            "channel":      "team",
            "from_agent":   "alice",
            "content":      "Hello DAO",
            "content_type": "text",
            "reply_to":     "",
            "mentions":     [],
            "timestamp":    "2026-04-01T12:00:00",
            "metadata":     {},
        },
    }
    from ..identity import canonical_json
    case["expected_canonical_hex"] = canonical_json(case["input"]).hex()
    case2 = {
        "id": "chmsg-002",
        "description": "ChannelMessage with reply_to and mentions",
        "input": {
            "msg_id":       "1234567890abcdef",
            "channel":      "group:backend",
            "from_agent":   "bob",
            "content":      "ack @alice",
            "content_type": "text",
            "reply_to":     "abcd1234567890ef",
            "mentions":     ["alice"],
            "timestamp":    "2026-04-01T12:00:30",
            "metadata":     {"thread": "code-review"},
        },
    }
    case2["expected_canonical_hex"] = canonical_json(case2["input"]).hex()
    return [case, case2]


def gen_invitation_canonical() -> list:
    """Invitation.signable_dict() canonical bytes."""
    alice = _seed_keypair(ALICE_SEED_HEX)
    case = {
        "id": "invite-001",
        "description": "Invitation minimal example",
        "input": {
            "team_id":      "t1",
            "team_name":    "Test Team",
            "owner_pubkey": alice["pubkey_hex"],
            "issuer":       "alice",
            "issued_at":    "2026-01-01T00:00:00",
            "expires_at":   "2026-01-08T00:00:00",
            "join_token":   "secret",
            "ws_url":       "ws://192.168.1.5:9876",
            "psk":          "lan-secret",
            "sig":          "",
        },
    }
    from ..invitation import Invitation
    inv = Invitation.from_dict(case["input"])
    case["expected_canonical_hex"] = canonical_json(inv.signable_dict()).hex()
    return [case]


def gen_team_config_canonical() -> list:
    """TeamConfig.signable_dict() canonical bytes for owner-signed configs."""
    alice = _seed_keypair(ALICE_SEED_HEX)
    case = {
        "id": "team-001",
        "description": "Signed TeamConfig minimal example",
        "input": {
            "team_id":        "abc12345",
            "team_name":      "Test Team",
            "join_policy":    "approval",
            "join_token":     "",
            "admin_ids":      ["alice"],
            "member_ids":     ["alice"],
            "roles":          {"alice": "owner"},
            "created_at":     "2026-01-01T00:00:00",
            "metadata":       {},
            "owner_pubkey":   alice["pubkey_hex"],
            "owner_sig":      "",
            "sig_updated_at": "2026-01-01T00:00:00",
        },
    }
    from ..membership import TeamConfig
    cfg = TeamConfig.from_dict(case["input"])
    case["expected_canonical_hex"] = canonical_json(cfg.signable_dict()).hex()
    return [case]


def gen_did_key_encoding() -> list:
    """did:key encoding/decoding of Ed25519 pubkeys.

    Lets a non-Python implementation verify their base58btc + multicodec
    handling against deterministic test pubkeys.
    """
    from ..did_key import encode_ed25519_did_key_hex
    cases = []
    for label, hex_pk in (
        ("did-001", "00" * 32),
        ("did-002", "01" * 32),
        ("did-003", "".join(f"{i:02x}" for i in range(32))),
    ):
        cases.append({
            "id": label,
            "description": f"Encode pubkey {hex_pk[:8]}... as did:key",
            "input": {"pubkey_hex": hex_pk},
            "expected_did": encode_ed25519_did_key_hex(hex_pk),
        })
    return cases


def gen_lan_psk_tag() -> list:
    """LAN discovery psk_tag = HMAC-SHA256(psk, canonical_json(message - psk_tag)).

    Lock the construction so a Go/Rust port produces byte-identical tags.
    """
    import hashlib
    import hmac as _hmac
    import json as _json
    cases = []
    for cid, psk, msg in (
        ("psk-001", "team-secret", {"type": "nth-dao-query", "v": 1,
                                     "from": "alice", "wants": [],
                                     "nonce": "deadbeef"}),
        ("psk-002", "team-secret", {"type": "nth-dao-hello", "v": 1,
                                     "agent_id": "alice",
                                     "nonce": "feedface"}),
    ):
        canon = _json.dumps(
            {k: v for k, v in msg.items() if k != "psk_tag"},
            sort_keys=True, separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        tag = _hmac.new(psk.encode("utf-8"), canon, hashlib.sha256).hexdigest()
        cases.append({
            "id": cid,
            "description": f"HMAC-SHA256 psk_tag over canonical {msg.get('type')}",
            "input": {"psk": psk, "message": msg},
            "expected_psk_tag": tag,
        })
    return cases


def gen_replay_window() -> list:
    """Replay window boundaries.

    Offsets are relative to "now" at runtime — vectors stay valid regardless
    of when the conformance suite runs.
    """
    return [
        {
            "id": "replay-001",
            "description": "Message timestamp = now → accepted",
            "offset_seconds": 0,
            "expected_within_window": True,
        },
        {
            "id": "replay-002",
            "description": "Message timestamp = 30 seconds ago → accepted",
            "offset_seconds": -30,
            "expected_within_window": True,
        },
        {
            "id": "replay-003",
            "description": "Message timestamp = 30 seconds in future (allowed clock skew) → accepted",
            "offset_seconds": 30,
            "expected_within_window": True,
        },
        {
            "id": "replay-004",
            "description": "Message timestamp = 120 seconds in future → REJECTED (drift cap)",
            "offset_seconds": 120,
            "expected_within_window": False,
        },
        {
            "id": "replay-005",
            "description": "Message timestamp = 700 seconds ago → REJECTED (replay window)",
            "offset_seconds": -700,
            "expected_within_window": False,
        },
    ]


# ─────────────────── top-level ───────────────────


def regenerate(path: Path = VECTORS_PATH) -> None:
    vectors = {
        "format": "nth-dao-conformance-v1",
        "schema_version": 1,
        "generated_at": datetime.now().isoformat(),
        "reference_impl": "nth-dao Python (pyproject version)",
        "vectors": {
            "canonical_json":              gen_canonical_json(),
            "fingerprint":                 gen_fingerprint(),
            "signature_verify":            gen_signature_verify(),
            "endorsement_canonical_payload": gen_endorsement_canonical_payload(),
            "template_canonical_payload":  gen_template_canonical_payload(),
            "channel_message_canonical":   gen_channel_message_canonical(),
            "invitation_canonical":        gen_invitation_canonical(),
            "team_config_canonical":       gen_team_config_canonical(),
            "did_key_encoding":            gen_did_key_encoding(),
            "lan_psk_tag":                 gen_lan_psk_tag(),
            "replay_window":               gen_replay_window(),
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(vectors, f, indent=2, ensure_ascii=False)
    counts = {k: len(v) for k, v in vectors["vectors"].items()}
    print(f"wrote {path}")
    print(f"  categories: {len(counts)}")
    for k, n in counts.items():
        print(f"    {k:35s} {n} vectors")


if __name__ == "__main__":
    regenerate()
