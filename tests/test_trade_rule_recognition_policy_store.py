from __future__ import annotations

import json
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from datetime import datetime, timezone

import pytest

from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.trade_rules.recognition import RuleRecognitionTrustPolicy
from nth_dao.trade_rules.recognition_policy import (
    TradeRuleRecognitionPolicy,
    create_rule_recognition_policy,
)
from nth_dao.trade_rules.recognition_policy_store import (
    RuleRecognitionPolicyStore,
    RuleRecognitionPolicyStoreCapacity,
    RuleRecognitionPolicyStoreCorruption,
)

pytestmark = pytest.mark.skipif(
    not crypto_available(),
    reason="Recognition policy requires PyNaCl",
)


def _trust(issuer_did: str) -> RuleRecognitionTrustPolicy:
    return RuleRecognitionTrustPolicy(
        trusted_issuers={issuer_did},
        threshold=1,
        max_statement_ttl_seconds=86_400,
        issuer_rule_scopes={issuer_did: ("*",)},
    )


def _chain():
    node = AgentIdentity.generate(label="node")
    issuer = AgentIdentity.generate(label="issuer")
    first = create_rule_recognition_policy(
        node,
        node_did=node.as_did(),
        trust_policy=_trust(issuer.as_did()),
        issued_at="2026-08-01T00:00:00Z",
        now=datetime(2026, 8, 1, tzinfo=timezone.utc),
    )
    second = create_rule_recognition_policy(
        node,
        node_did=node.as_did(),
        trust_policy=_trust(issuer.as_did()),
        issued_at="2026-08-01T00:00:01Z",
        previous=first,
        now=datetime(2026, 8, 1, 0, 0, 1, tzinfo=timezone.utc),
    )
    return node, issuer, first, second


def _append_worker(args):
    root, node_did, raw_hex = args
    store = RuleRecognitionPolicyStore(root, node_did=node_did)
    policy = TradeRuleRecognitionPolicy.from_json(bytes.fromhex(raw_hex))
    result = store.append(policy)
    return result.created, result.policy.digest


def test_store_appends_chain_and_is_idempotent(tmp_path):
    node, _issuer, first, second = _chain()
    store = RuleRecognitionPolicyStore(tmp_path, node_did=node.as_did())

    one = store.append(first)
    duplicate = store.append(first)
    two = store.append(second)

    assert one.created
    assert not duplicate.created
    assert two.created
    assert store.list_all() == (first, second)
    assert store.head() == second
    head = json.loads(store.head_path.read_text(encoding="ascii"))
    assert head["sequence"] == 2
    assert head["policy_digest"] == second.digest


def test_store_reopens_stable_namespace_after_authorized_key_rotation(tmp_path):
    node, issuer, first, _second = _chain()
    replacement = AgentIdentity.generate(label="replacement-node-key")
    rotatable_first = create_rule_recognition_policy(
        node,
        node_did=node.as_did(),
        controllers=[node.as_did(), replacement.as_did()],
        trust_policy=_trust(issuer.as_did()),
        issued_at="2026-08-01T00:00:00Z",
        now=datetime(2026, 8, 1, tzinfo=timezone.utc),
    )
    RuleRecognitionPolicyStore(
        tmp_path,
        node_did=node.as_did(),
    ).append(rotatable_first)

    reopened = RuleRecognitionPolicyStore.open_or_create_for_identity(
        tmp_path,
        identity_did=replacement.as_did(),
    )
    successor = create_rule_recognition_policy(
        replacement,
        node_did=node.as_did(),
        controllers=[replacement.as_did()],
        trust_policy=_trust(issuer.as_did()),
        issued_at="2026-08-01T00:00:01Z",
        previous=rotatable_first,
        now=datetime(2026, 8, 1, 0, 0, 1, tzinfo=timezone.utc),
    )

    assert reopened.node_did == node.as_did()
    assert reopened.append(successor).created
    assert reopened.head() == successor


def test_store_rejects_foreign_did_in_unsigned_empty_namespace(tmp_path):
    node = AgentIdentity.generate(label="node")
    replacement = AgentIdentity.generate(label="replacement")
    store = RuleRecognitionPolicyStore(tmp_path, node_did=node.as_did())
    store._write_head(sequence=0, digest="sha256:" + ("0" * 64))

    with pytest.raises(
        RuleRecognitionPolicyStoreCorruption,
        match="empty Recognition policy namespace",
    ):
        RuleRecognitionPolicyStore.open_or_create_for_identity(
            tmp_path,
            identity_did=replacement.as_did(),
        )


def test_store_recovers_fsynced_cas_tail_after_head_write_crash(tmp_path):
    node, _issuer, first, second = _chain()
    store = RuleRecognitionPolicyStore(tmp_path, node_did=node.as_did())
    store.append(first)
    store._atomic_write(
        store._statement_path(second.digest),
        second.canonical_bytes,
    )
    stale = json.loads(store.head_path.read_text(encoding="ascii"))
    assert stale["sequence"] == 1

    assert store.head() == second
    repaired = json.loads(store.head_path.read_text(encoding="ascii"))
    assert repaired["sequence"] == 2
    assert repaired["policy_digest"] == second.digest


def test_store_detects_truncation_behind_checkpoint(tmp_path):
    node, _issuer, first, second = _chain()
    store = RuleRecognitionPolicyStore(tmp_path, node_did=node.as_did())
    store.append(first)
    store.append(second)
    store._statement_path(second.digest).unlink()

    with pytest.raises(
        RuleRecognitionPolicyStoreCorruption,
        match="truncated behind its head",
    ):
        store.head()


def test_store_rejects_noncanonical_head_bytes(tmp_path):
    node, _issuer, first, _second = _chain()
    store = RuleRecognitionPolicyStore(tmp_path, node_did=node.as_did())
    store.append(first)
    document = json.loads(store.head_path.read_text(encoding="ascii"))
    store.head_path.write_text(
        json.dumps(document, indent=2),
        encoding="ascii",
    )

    with pytest.raises(
        RuleRecognitionPolicyStoreCorruption,
        match="not canonical JSON",
    ):
        store.head()


def test_store_detects_external_fork_without_rewriting_head(tmp_path):
    node, issuer, first, second = _chain()
    store = RuleRecognitionPolicyStore(tmp_path, node_did=node.as_did())
    store.append(first)
    fork = create_rule_recognition_policy(
        node,
        node_did=node.as_did(),
        trust_policy=_trust(issuer.as_did()),
        issued_at="2026-08-01T00:00:02Z",
        previous=first,
        now=datetime(2026, 8, 1, 0, 0, 2, tzinfo=timezone.utc),
    )
    store._atomic_write(
        store._statement_path(second.digest),
        second.canonical_bytes,
    )
    store._atomic_write(
        store._statement_path(fork.digest),
        fork.canonical_bytes,
    )

    with pytest.raises(
        RuleRecognitionPolicyStoreCorruption,
        match="fork",
    ):
        store.head()


def test_store_rejects_foreign_node_and_non_successor(tmp_path):
    node, issuer, first, second = _chain()
    other = AgentIdentity.generate(label="other")
    store = RuleRecognitionPolicyStore(tmp_path, node_did=other.as_did())

    with pytest.raises(ValueError, match="another node"):
        store.append(first)

    correct = RuleRecognitionPolicyStore(tmp_path / "correct", node_did=node.as_did())
    with pytest.raises(ValueError, match="sequence 1"):
        correct.append(second)
    assert correct.list_all() == ()
    assert issuer.as_did() in first.trust_policy.trusted_issuers


def test_store_enforces_capacity_before_new_cas_write(tmp_path):
    node, _issuer, first, second = _chain()
    store = RuleRecognitionPolicyStore(
        tmp_path,
        node_did=node.as_did(),
        max_revisions=1,
    )
    store.append(first)

    with pytest.raises(RuleRecognitionPolicyStoreCapacity):
        store.append(second)
    assert not store._statement_path(second.digest).exists()


def test_thread_concurrency_creates_one_revision(tmp_path):
    node, _issuer, first, _second = _chain()
    store = RuleRecognitionPolicyStore(tmp_path, node_did=node.as_did())

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _index: store.append(first), range(16)))

    assert sum(result.created for result in results) == 1
    assert store.list_all() == (first,)


def test_process_concurrency_creates_one_revision(tmp_path):
    node, _issuer, first, _second = _chain()
    args = (
        str(tmp_path),
        node.as_did(),
        first.canonical_bytes.hex(),
    )
    context = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=4, mp_context=context) as pool:
        results = list(pool.map(_append_worker, [args] * 8))

    assert sum(created for created, _digest in results) == 1
    assert {digest for _created, digest in results} == {first.digest}
    assert RuleRecognitionPolicyStore(
        tmp_path,
        node_did=node.as_did(),
    ).head() == first
