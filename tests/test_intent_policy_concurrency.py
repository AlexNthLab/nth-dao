"""Cross-process invariants for the local Intent policy head."""

from __future__ import annotations

import hashlib
import json
import multiprocessing as mp
from pathlib import Path
import sys

import pytest

from nth_dao.plugins.intent_policy import (
    IntentAcceptancePolicySnapshot,
    IntentPolicyMember,
)
from tools.generate_intent_envelope_vectors import _test_identity


def _hash(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def _member(signer_did: str) -> IntentPolicyMember:
    return IntentPolicyMember(
        signer_did=signer_did,
        role="member",
        status="active",
        allowed_solver_classes=("org.nth-dao.solver.review",),
        automation_ceiling="A1",
    )


def _policy(signer_did: str, audience_did: str, draft_digest: str, **changes):
    values = {
        "audience_did": audience_did,
        "scope_id": "workspace:conformance-intent",
        "reviewed_draft_digest": draft_digest,
        "membership_digest": _hash("membership-v1"),
        "revocation_digest": _hash("revocations-v1"),
        "policy_revision": 1,
        "previous_policy_digest": "",
        "issued_at_ms": 900,
        "expires_at_ms": 2_000,
        "allowed_acceptance_roles": ("admin", "member", "owner"),
        "members": (_member(signer_did),),
    }
    return IntentAcceptancePolicySnapshot.create(**(values | changes))


@pytest.fixture
def policy_inputs():
    signer = _test_identity("intent-envelope-signer-v1")
    audience = _test_identity("intent-envelope-audience-v1")
    vectors = json.loads(
        (
            Path(__file__).parents[1]
            / "nth_dao/plugins/vectors/intent-envelope-wire-cases-v1.json"
        ).read_text(encoding="utf-8")
    )
    return signer, audience, vectors["positive_cases"][0]


def _publish_worker(workspace: str, document: dict, start, results) -> None:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from nth_dao.plugins.intent_policy import IntentAcceptancePolicySnapshot
    from nth_dao.plugins.intent_policy_store import (
        IntentPolicyStore,
        IntentPolicyStoreConflict,
    )

    try:
        policy = IntentAcceptancePolicySnapshot.from_dict(document)
        store = IntentPolicyStore(Path(workspace), timeout=5, clock=lambda: 1_001)
        start.wait(timeout=10)
        try:
            result = store.publish(policy)
            results.put(("created" if result.created else "existing", policy.digest))
        except IntentPolicyStoreConflict:
            results.put(("conflict", policy.digest))
    except Exception as exc:
        results.put(("error", type(exc).__name__, str(exc)))


def _hold_policy_lock(workspace: str, ready, release, results) -> None:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from nth_dao.plugins.intent_policy_store import IntentPolicyStore

    try:
        store = IntentPolicyStore(Path(workspace), timeout=5, clock=lambda: 1_000)
        with store.coordination_lock():
            ready.set()
            release.wait(timeout=10)
        results.put(("released",))
    except Exception as exc:
        results.put(("error", type(exc).__name__, str(exc)))


def test_only_one_competing_successor_becomes_current(tmp_path, policy_inputs):
    from nth_dao.plugins.intent_policy_store import IntentPolicyStore

    signer, audience, case = policy_inputs
    first = _policy(signer.as_did(), audience.as_did(), case["envelope"]["draft_digest"])
    store = IntentPolicyStore(tmp_path, clock=lambda: 1_000)
    store.publish(first)
    candidates = [
        _policy(
            signer.as_did(),
            audience.as_did(),
            case["envelope"]["draft_digest"],
            policy_revision=2,
            previous_policy_digest=first.digest,
            membership_digest=_hash(f"membership-{index}"),
            issued_at_ms=1_000,
            expires_at_ms=3_000,
        )
        for index in range(2)
    ]
    context = mp.get_context("spawn")
    start = context.Event()
    results = context.Queue()
    workers = [
        context.Process(
            target=_publish_worker,
            args=(str(tmp_path), candidate.to_dict(), start, results),
        )
        for candidate in candidates
    ]
    for worker in workers:
        worker.start()
    start.set()
    for worker in workers:
        worker.join(timeout=20)
        assert not worker.is_alive()
    outcomes = [results.get(timeout=2) for _worker in workers]

    assert sum(outcome[0] == "created" for outcome in outcomes) == 1, outcomes
    assert sum(outcome[0] == "conflict" for outcome in outcomes) == 1, outcomes
    assert all(outcome[0] != "error" for outcome in outcomes), outcomes
    assert store.verify_history()[0] == 2
    assert store.current(audience.as_did(), case["envelope"]["scope_id"]).digest in {
        candidate.digest for candidate in candidates
    }


def test_governed_acceptance_fails_while_policy_head_is_locked(
    tmp_path, policy_inputs,
):
    from nth_dao.plugins.intent_acceptance import IntentAcceptanceStore
    from nth_dao.plugins.intent_policy_store import IntentPolicyStore, IntentPolicyStoreBusy

    signer, audience, case = policy_inputs
    policy = _policy(signer.as_did(), audience.as_did(), case["envelope"]["draft_digest"])
    published = IntentPolicyStore(tmp_path, clock=lambda: 1_000).publish(policy)
    policies = IntentPolicyStore(tmp_path, timeout=0.05, clock=lambda: 1_000)
    acceptances = IntentAcceptanceStore(tmp_path, clock=lambda: 1_000)
    context = mp.get_context("spawn")
    ready, release, results = context.Event(), context.Event(), context.Queue()
    worker = context.Process(
        target=_hold_policy_lock,
        args=(str(tmp_path), ready, release, results),
    )
    worker.start()
    assert ready.wait(timeout=10)
    try:
        try:
            acceptances.accept_governed(
                case["envelope"],
                policy_store=policies,
                signer_did=signer.as_did(),
                expected_policy_tail_digest=published.record.audit_digest,
            )
        except IntentPolicyStoreBusy:
            pass
        else:
            raise AssertionError("acceptance bypassed the held policy-head lock")
    finally:
        release.set()
        worker.join(timeout=20)
    assert results.get(timeout=2) == ("released",)
    assert acceptances.history() == ()
