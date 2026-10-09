"""Transport-independent ACK packaging never grants domain authority."""

from __future__ import annotations

import json
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from nth_dao.delivery.acknowledgement import (
    ACK_KIND,
    DeliveryAckRejected,
    ack_from_envelope,
    sign_ack,
    sign_ack_envelope,
)
from nth_dao.delivery.envelope import (
    TransportEnvelope,
    envelope_digest,
    sign_envelope,
    validate_envelope,
)
from nth_dao.did_key import decode_ed25519_did_key_hex
from nth_dao.identity import AgentIdentity

pytest.importorskip("nacl")
NOW = 1_750_000_000_000


def _pair():
    source, claimant = AgentIdentity.generate(), AgentIdentity.generate()
    ack = sign_ack(claimant, message_id="sha256:" + "1" * 64,
                   envelope_sha256="sha256:" + "2" * 64, received_at_ms=NOW)
    envelope = sign_ack_envelope(claimant, ack, recipient=source.as_did(),
                                 created_at_ms=NOW, expires_at_ms=NOW + 60_000)
    return source, claimant, ack, envelope


def test_ack_roundtrip_and_legacy_import_share_the_same_verifier():
    from nth_dao.delivery import ack_from_envelope as facade
    from nth_dao.delivery.transports.federation import ack_from_envelope as legacy

    _, _, ack, envelope = _pair()
    assert legacy is facade is ack_from_envelope
    assert ack_from_envelope(envelope, now_ms=NOW).to_dict() == ack.to_dict()
    ack.envelope_sha256 = "sha256:" + "3" * 64
    assert ack_from_envelope(envelope).envelope_sha256 == "sha256:" + "2" * 64


@pytest.mark.parametrize("tamper", ["outer_signature", "inner_signature", "author", "extra", "kind"])
def test_ack_unpack_rejects_forgery_and_substitution(tamper):
    source, claimant, _, envelope = _pair()
    if tamper == "outer_signature":
        envelope.signature = "forged"
    else:
        payload = deepcopy(envelope.payload)
        if tamper == "inner_signature":
            payload["ack"]["signature"] = "forged"
        elif tamper == "extra":
            payload["unknown"] = True
        envelope = sign_envelope(
            source if tamper == "author" else claimant,
            kind="chat.message" if tamper == "kind" else ACK_KIND,
            recipient=source.as_did(), payload=payload, created_at_ms=NOW, expires_at_ms=NOW + 60_000,
        )
    with pytest.raises(DeliveryAckRejected):
        ack_from_envelope(envelope, now_ms=NOW)


def test_ack_intake_expiry_and_packing_signer_are_checked():
    source, _, ack, envelope = _pair()
    with pytest.raises(DeliveryAckRejected, match="expired"):
        ack_from_envelope(envelope, now_ms=NOW + 60_000)
    with pytest.raises(DeliveryAckRejected, match="signer differs"):
        sign_ack_envelope(source, ack, recipient=source.as_did(),
                          created_at_ms=NOW, expires_at_ms=NOW + 60_000)
    assert ack_from_envelope(envelope, now_ms=NOW).to_dict() == ack.to_dict()


def test_public_ack_return_vector_covers_binding_and_intake_time():
    fixture = json.loads((
        Path(__file__).parents[1] / "nth_dao/market/vectors/ack-return-envelope-v1.json"
    ).read_text(encoding="utf-8"))
    assert fixture["format"] == "nth-delivery-ack-envelope-v1" and fixture["synthetic"]
    assert fixture["verification_scope"] == "wire_binding_only_not_local_source_authorization"
    original = TransportEnvelope.from_dict(fixture["original_envelope"])
    returned = TransportEnvelope.from_dict(fixture["return_envelope"])
    assert validate_envelope(original, now_ms=fixture["now_ms"]) == (True, "ok")
    ack = ack_from_envelope(returned, now_ms=fixture["now_ms"])
    assert returned.recipient == original.sender_did
    assert ack.receiver_did == original.recipient == returned.sender_did
    assert decode_ed25519_did_key_hex(original.sender_did) == fixture["source_pubkey_hex"]
    assert decode_ed25519_did_key_hex(ack.receiver_did) == fixture["receiver_pubkey_hex"]
    assert ack.message_id == original.message_id and ack.envelope_sha256 == envelope_digest(original)
    assert returned.routing == {"hop_limit": 0, "hop_count": 0}
    for case in fixture["time_cases"]:
        if case["expected_valid"]:
            assert ack_from_envelope(returned, now_ms=case["now_ms"]).to_dict() == ack.to_dict()
        else:
            with pytest.raises(DeliveryAckRejected):
                ack_from_envelope(returned, now_ms=case["now_ms"])


def test_independent_node_negatives_kill_missing_inner_signature_verifier():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node runtime is required for independent verifier mutation test")
    root = Path(__file__).parents[1]
    script = (root / "tools/check_source_receipt_delivery.cjs").read_text(encoding="utf-8")
    arguments = [str(root / "nth_dao/market/vectors/source-receipt-delivery-v1.json"),
                 str(root / "nth_dao/market/vectors/ack-return-envelope-v1.json")]
    good = subprocess.run([node, "-e", script, "-", *arguments], capture_output=True, timeout=30, check=False)
    assert good.returncode == 0, good.stderr.decode("utf-8", errors="replace")
    candidates = ["verify(sig, canonical(ack), publicKey(vector.receiver_pubkey_hex));",
                  "verify(sig, canonical(ack), publicKey(vector.receiver_pubkey_hex), 'inner-signature');"]
    targets = [line for line in candidates if line in script]
    assert len(targets) == 1 and script.count(targets[0]) == 1
    mutant = script.replace(targets[0], "// injected missing inner verification")
    killed = subprocess.run([node, "-e", mutant, "-", *arguments], capture_output=True, timeout=30, check=False)
    assert killed.returncode != 0, "independent negatives failed to detect a missing inner verifier"
