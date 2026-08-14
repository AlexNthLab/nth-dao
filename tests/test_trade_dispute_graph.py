from __future__ import annotations

import hashlib
import itertools
import re
from datetime import datetime, timedelta, timezone

import pytest

from nth_dao.identity import AgentID, AgentIdentity
from nth_dao.trade_rules.agreement_conformance import generate_vectors
from nth_dao.trade_rules.agreement_order import TradeOrder
from nth_dao.trade_rules.canonical import trade_canonical_json
from nth_dao.trade_rules.dispute_graph import (
    TradeDisputeGraphCapacity,
    TradeDisputeGraphError,
    TradeDisputeGraphNode,
    TradeDisputeGraphProjection,
    project_trade_dispute_graph,
)
from nth_dao.trade_rules.dispute_statement import (
    TradeDisputeStatement,
    TradeDisputeStatementResolverRequired,
    create_trade_dispute_statement,
    trade_dispute_id,
)
from nth_dao.trade_rules.dispute_statement_store import (
    TradeDisputeStatementDependencyError,
    TradeDisputeStatementParentError,
    TradeDisputeStatementStore,
    TradeDisputeStatementStoreCapacity,
    TradeDisputeStatementStoreError,
)
from nth_dao.trade_rules.execution_receipt import TradeExecutionReceipt
from nth_dao.trade_rules.package_store import build_rule_package
from nth_dao.trade_rules.receipt_review import TradeReceiptReview


class _Resolver:
    def __init__(self, package):
        self.package = package

    def load(self, digest):
        return self.package if digest == self.package.digest else None


class _ResolverUnavailable(Exception):
    pass


class _FailingResolver:
    def load(self, _digest):
        raise _ResolverUnavailable("resolver intentionally unavailable")


@pytest.fixture(scope="module")
def graph_context():
    vectors = generate_vectors()
    order = TradeOrder.from_dict(vectors["order"])
    receipt = TradeExecutionReceipt.from_dict(
        vectors["execution_receipt"],
        order=order,
    )
    review = TradeReceiptReview.from_dict(
        vectors["disputed_receipt_review"],
        receipt=receipt,
        order=order,
    )
    raw_package = vectors["rule_package"]
    resources = {
        item["digest"]: bytes.fromhex(item["bytes_hex"])
        for item in raw_package["resources"]
    }
    resolver = _Resolver(build_rule_package(raw_package["manifest"], resources))
    root = TradeDisputeStatement.from_dict(
        vectors["trade_dispute_statement"],
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
    )
    return order, receipt, review, root


def _maker_identity() -> AgentIdentity:
    from nacl.signing import SigningKey

    signing_key = SigningKey(
        hashlib.sha256(b"NTH Trade Agreement v1 maker public seed").digest()
    )
    verify_key = signing_key.verify_key.encode()
    return AgentIdentity(
        agent_id=AgentID.from_pubkey(verify_key.hex()),
        label="public-conformance-only",
        _signing_key=signing_key.encode(),
        _verify_key=verify_key,
    )


def _digest(statement: TradeDisputeStatement) -> str:
    return "sha256:" + hashlib.sha256(statement.canonical_bytes).hexdigest()


def _later(value: str, seconds: int) -> str:
    moment = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    shifted = moment + timedelta(seconds=seconds)
    timespec = "microseconds" if shifted.microsecond else "seconds"
    return shifted.astimezone(timezone.utc).isoformat(timespec=timespec).replace(
        "+00:00", "Z"
    )


def _later_microseconds(value: str, microseconds: int) -> str:
    moment = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    shifted = moment + timedelta(microseconds=microseconds)
    return shifted.astimezone(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _child(graph_context, *, parent_digest: str, created_at: str):
    order, receipt, review, _root = graph_context
    return create_trade_dispute_statement(
        _maker_identity(),
        review=review,
        receipt=receipt,
        order=order,
        statement_type="remedy-proposal",
        parent_statement_digests=[parent_digest],
        reason_codes=["follow-up"],
        claim={
            "claim_type": "remedy-proposal",
            "media_type": "application/json",
            "digest": "sha256:" + ("c" * 64),
            "size": 1,
            "schema_digest": None,
        },
        created_at=created_at,
    )


def test_dispute_graph_projects_complete_parent_chain(graph_context):
    _order, _receipt, _review, root = graph_context
    root_digest = _digest(root)
    child = _child(
        graph_context,
        parent_digest=root_digest,
        created_at=_later(root.to_dict()["created_at"], 1),
    )
    child_digest = _digest(child)

    projection = project_trade_dispute_graph(
        [(child_digest, child), (root_digest, root)]
    )

    assert projection.graph_status == "complete"
    assert projection.complete is True
    assert projection.root_digests == (root_digest,)
    assert projection.tip_digests == (child_digest,)
    assert projection.topological_digests == (root_digest, child_digest)
    assert [node.ancestry_status for node in projection.nodes] == [
        "complete",
        "complete",
    ]
    assert [node.depth for node in projection.nodes] == [0, 1]
    assert projection.adjudicated_or_proven_true is False
    assert re.fullmatch(r"v2:[0-9a-f]{64}", projection.snapshot_token)
    assert projection.to_dict()["adjudicated_or_proven_true"] is False
    bounded = projection.to_dict(max_items=1)
    assert bounded["node_count"] == 2
    assert len(bounded["nodes"]) == 1
    assert bounded["items_truncated"] is True


def test_bounded_projection_keeps_every_visible_membership_digest_in_nodes():
    digests = tuple(f"sha256:{index:064x}" for index in range(501))
    nodes = tuple(
        TradeDisputeGraphNode(
            statement_digest=digest,
            parent_statement_digests=(),
            ancestry_status="complete",
            depth=0,
        )
        for digest in digests
    )
    projection = TradeDisputeGraphProjection(
        snapshot_token="v2:" + ("1" * 64),
        graph_status="complete",
        review_digest="sha256:" + ("2" * 64),
        dispute_id="nth-trade-dispute-sha256:" + ("3" * 64),
        statement_count=len(digests),
        root_digests=(digests[-1],),
        tip_digests=(digests[-1],),
        topological_digests=digests,
        unresolved_parent_digests=(),
        non_dag_digests=(),
        issues=(),
        nodes=nodes,
    )

    bounded = projection.to_dict(max_items=500)
    visible = {node["statement_digest"] for node in bounded["nodes"]}

    assert bounded["items_truncated"] is True
    assert len(visible) == 500
    assert bounded["root_digests"] == []
    assert bounded["tip_digests"] == []
    assert set(bounded["topological_digests"]) == visible
    assert all(
        digest in visible
        for key in (
            "root_digests",
            "tip_digests",
            "topological_digests",
            "non_dag_digests",
        )
        for digest in bounded[key]
    )


def test_bounded_projection_uses_parent_closed_topological_prefix():
    parent = "sha256:" + ("a" * 64)
    child = "sha256:" + ("b" * 64)
    projection = TradeDisputeGraphProjection(
        snapshot_token="v2:" + ("1" * 64),
        graph_status="complete",
        review_digest="sha256:" + ("2" * 64),
        dispute_id="nth-trade-dispute-sha256:" + ("3" * 64),
        statement_count=2,
        root_digests=(parent,),
        tip_digests=(child,),
        topological_digests=(parent, child),
        unresolved_parent_digests=(),
        non_dag_digests=(),
        issues=(),
        # Deliberately place the child first to prove serializer selection is
        # based on graph order rather than presentation/timestamp order.
        nodes=(
            TradeDisputeGraphNode(child, (parent,), "complete", 1),
            TradeDisputeGraphNode(parent, (), "complete", 0),
        ),
    )

    bounded = projection.to_dict(max_items=1)

    assert bounded["items_truncated"] is True
    assert [node["statement_digest"] for node in bounded["nodes"]] == [parent]
    assert bounded["nodes"][0]["parent_statement_digests"] == []


def test_dispute_graph_orders_fractional_timestamp_after_whole_second(
    graph_context,
):
    order, receipt, review, root = graph_context
    later = create_trade_dispute_statement(
        _maker_identity(),
        review=review,
        receipt=receipt,
        order=order,
        statement_type="remedy-proposal",
        reason_codes=["fractional-later"],
        claim={
            "claim_type": "remedy-proposal",
            "media_type": "application/json",
            "digest": "sha256:" + ("a" * 64),
            "size": 1,
            "schema_digest": None,
        },
        created_at=_later_microseconds(root.to_dict()["created_at"], 1),
    )

    projection = project_trade_dispute_graph(
        [(_digest(later), later), (_digest(root), root)]
    )

    assert projection.topological_digests == (_digest(root), _digest(later))


def test_dispute_graph_reports_missing_parent_without_rejecting_claim(graph_context):
    _order, _receipt, _review, root = graph_context
    missing = "sha256:" + ("f" * 64)
    child = _child(
        graph_context,
        parent_digest=missing,
        created_at=_later(root.to_dict()["created_at"], 1),
    )
    projection = project_trade_dispute_graph([(_digest(child), child)])

    assert projection.graph_status == "incomplete"
    assert projection.unresolved_parent_digests == (missing,)
    assert projection.nodes[0].ancestry_status == "incomplete"
    assert projection.issues[0].reason == "missing-parent"


def test_dispute_graph_distinguishes_cross_review_parent(graph_context):
    _order, _receipt, _review, root = graph_context
    foreign = "sha256:" + ("e" * 64)
    child = _child(
        graph_context,
        parent_digest=foreign,
        created_at=_later(root.to_dict()["created_at"], 1),
    )
    missing_projection = project_trade_dispute_graph(
        [(_digest(child), child)],
    )
    projection = project_trade_dispute_graph(
        [(_digest(child), child)],
        known_review_digests={foreign: "sha256:" + ("d" * 64)},
    )

    assert missing_projection.graph_status == "incomplete"
    assert projection.graph_status == "invalid"
    assert projection.snapshot_token != missing_projection.snapshot_token
    assert projection.unresolved_parent_digests == ()
    assert projection.issues[0].reason == "parent-context-mismatch"


def test_dispute_graph_tolerates_parent_within_clock_skew(graph_context):
    order, receipt, review, root = graph_context
    root_time = root.to_dict()["created_at"]
    parent = create_trade_dispute_statement(
        _maker_identity(),
        review=review,
        receipt=receipt,
        order=order,
        statement_type="remedy-proposal",
        reason_codes=["later-parent"],
        claim={
            "claim_type": "remedy-proposal",
            "media_type": "application/json",
            "digest": "sha256:" + ("d" * 64),
            "size": 1,
            "schema_digest": None,
        },
        created_at=_later(root_time, 2),
    )
    child = _child(
        graph_context,
        parent_digest=_digest(parent),
        created_at=_later(root_time, 1),
    )
    projection = project_trade_dispute_graph(
        [(_digest(parent), parent), (_digest(child), child)]
    )
    strict_projection = project_trade_dispute_graph(
        [(_digest(parent), parent), (_digest(child), child)],
        clock_skew_seconds=0,
    )

    assert projection.graph_status == "complete"
    assert projection.issues == ()
    assert strict_projection.graph_status == "invalid"
    assert strict_projection.snapshot_token != projection.snapshot_token
    child_node = next(
        node for node in projection.nodes if node.statement_digest == _digest(child)
    )
    assert child_node.ancestry_status == "complete"


def test_dispute_graph_rejects_parent_beyond_clock_skew(graph_context):
    order, receipt, review, root = graph_context
    root_time = root.to_dict()["created_at"]
    parent = create_trade_dispute_statement(
        _maker_identity(),
        review=review,
        receipt=receipt,
        order=order,
        statement_type="remedy-proposal",
        reason_codes=["far-future-parent"],
        claim={
            "claim_type": "remedy-proposal",
            "media_type": "application/json",
            "digest": "sha256:" + ("e" * 64),
            "size": 1,
            "schema_digest": None,
        },
        created_at=_later(root_time, 302),
    )
    child = _child(
        graph_context,
        parent_digest=_digest(parent),
        created_at=_later(root_time, 1),
    )
    projection = project_trade_dispute_graph(
        [(_digest(parent), parent), (_digest(child), child)]
    )

    assert projection.graph_status == "invalid"
    assert projection.issues[0].reason == "parent-beyond-clock-skew"


def test_dispute_graph_rejects_digest_mismatch_and_duplicates(graph_context):
    _order, _receipt, _review, root = graph_context
    digest = _digest(root)
    with pytest.raises(TradeDisputeGraphError, match="content digest mismatch"):
        project_trade_dispute_graph([("sha256:" + ("0" * 64), root)])
    with pytest.raises(TradeDisputeGraphError, match="duplicate"):
        project_trade_dispute_graph([(digest, root), (digest, root)])


def test_dispute_graph_rejects_edge_budget_before_projection(graph_context):
    _order, _receipt, _review, root = graph_context
    root_digest = _digest(root)
    child = _child(
        graph_context,
        parent_digest=root_digest,
        created_at=_later(root.to_dict()["created_at"], 1),
    )
    child_digest = _digest(child)
    grandchild = _child(
        graph_context,
        parent_digest=child_digest,
        created_at=_later(root.to_dict()["created_at"], 2),
    )

    with pytest.raises(TradeDisputeGraphCapacity, match="max_edges"):
        project_trade_dispute_graph(
            [
                (root_digest, root),
                (child_digest, child),
                (_digest(grandchild), grandchild),
            ],
            max_edges=1,
        )


def test_store_rejects_edge_budget_before_statement_verification(
    tmp_path,
    graph_context,
    monkeypatch,
):
    order, receipt, review, root = graph_context
    root_digest = _digest(root)
    child = _child(
        graph_context,
        parent_digest=root_digest,
        created_at=_later(root.to_dict()["created_at"], 1),
    )
    child_digest = _digest(child)
    grandchild = _child(
        graph_context,
        parent_digest=child_digest,
        created_at=_later(root.to_dict()["created_at"], 2),
    )
    raw_package = generate_vectors()["rule_package"]
    resources = {
        item["digest"]: bytes.fromhex(item["bytes_hex"])
        for item in raw_package["resources"]
    }
    resolver = _Resolver(build_rule_package(raw_package["manifest"], resources))
    store = TradeDisputeStatementStore(tmp_path, max_graph_edges=1)
    store.put(
        root,
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
    )
    store.put(child, review=review, receipt=receipt, order=order)
    store.put(grandchild, review=review, receipt=receipt, order=order)

    def must_not_verify(*_args, **_kwargs):
        raise AssertionError("edge budget must run before signature verification")

    monkeypatch.setattr(store, "_verified_statement", must_not_verify)
    with pytest.raises(TradeDisputeStatementStoreCapacity, match="max_edges"):
        store.graph_for_review(
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
        )


def test_store_bounds_externally_overfilled_inventory_before_verification(
    tmp_path,
    graph_context,
    monkeypatch,
):
    order, receipt, review, root = graph_context
    child = _child(
        graph_context,
        parent_digest=_digest(root),
        created_at=_later(root.to_dict()["created_at"], 1),
    )
    raw_package = generate_vectors()["rule_package"]
    resources = {
        item["digest"]: bytes.fromhex(item["bytes_hex"])
        for item in raw_package["resources"]
    }
    resolver = _Resolver(build_rule_package(raw_package["manifest"], resources))
    writer = TradeDisputeStatementStore(tmp_path)
    writer.put(
        root,
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
    )
    writer.put(child, review=review, receipt=receipt, order=order)

    bounded_reader = TradeDisputeStatementStore(tmp_path, max_statements=1)

    def must_not_verify(*_args, **_kwargs):
        raise AssertionError("inventory budget must run before verification")

    monkeypatch.setattr(
        bounded_reader,
        "_verified_statement",
        must_not_verify,
    )
    with pytest.raises(
        TradeDisputeStatementStoreCapacity,
        match="max_statements",
    ):
        bounded_reader.graph_for_review(
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
        )


def test_dispute_graph_bounds_iterable_before_materializing_it(graph_context):
    _order, _receipt, _review, root = graph_context

    with pytest.raises(TradeDisputeGraphCapacity, match="max_nodes"):
        project_trade_dispute_graph(
            itertools.repeat((_digest(root), root)),
            max_nodes=2,
        )


def test_dispute_graph_bounds_known_review_mapping(graph_context):
    _order, _receipt, _review, root = graph_context
    known = {
        "sha256:" + (character * 64): "sha256:" + (character * 64)
        for character in ("1", "2")
    }

    with pytest.raises(TradeDisputeGraphCapacity, match="known review mapping"):
        project_trade_dispute_graph(
            [(_digest(root), root)],
            known_review_digests=known,
            max_nodes=1,
        )


def test_empty_dispute_graph_is_complete_but_not_adjudicated():
    review_digest = "sha256:" + ("1" * 64)
    dispute_id = trade_dispute_id("nth-trade-review-sha256:" + ("2" * 64))
    projection = project_trade_dispute_graph(
        [],
        expected_review_digest=review_digest,
        expected_dispute_id=dispute_id,
    )
    assert projection.graph_status == "complete"
    assert projection.statement_count == 0
    assert projection.review_digest == review_digest
    assert projection.dispute_id == dispute_id
    assert projection.adjudicated_or_proven_true is False
    other = project_trade_dispute_graph(
        [],
        expected_review_digest="sha256:" + ("3" * 64),
        expected_dispute_id=dispute_id,
    )
    assert other.snapshot_token != projection.snapshot_token


def test_empty_dispute_graph_requires_exact_context():
    with pytest.raises(TradeDisputeGraphError, match="requires expected"):
        project_trade_dispute_graph([])


def test_store_projection_completes_when_federated_parent_arrives(
    tmp_path,
    graph_context,
):
    order, receipt, review, root = graph_context
    child = _child(
        graph_context,
        parent_digest=_digest(root),
        created_at=_later(root.to_dict()["created_at"], 1),
    )
    store = TradeDisputeStatementStore(tmp_path)

    # Federation may deliver a signed child before its parent. Retain the
    # claim, but keep its ancestry visibly incomplete.
    store.put(child, review=review, receipt=receipt, order=order)
    incomplete = store.graph_for_review(
        review=review,
        receipt=receipt,
        order=order,
    )
    assert incomplete.graph_status == "incomplete"
    assert incomplete.unresolved_parent_digests == (_digest(root),)
    with pytest.raises(TradeDisputeStatementParentError, match="incomplete"):
        store.assert_complete_parent_chain(
            child,
            review=review,
            receipt=receipt,
            order=order,
        )

    raw_package = generate_vectors()["rule_package"]
    resources = {
        item["digest"]: bytes.fromhex(item["bytes_hex"])
        for item in raw_package["resources"]
    }
    resolver = _Resolver(build_rule_package(raw_package["manifest"], resources))
    store.put(
        root,
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
    )
    complete = store.graph_for_review(
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
    )
    assert complete.graph_status == "complete"
    assert complete.statement_count == 2
    assert (
        store.assert_complete_parent_chain(
            child,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
        ).graph_status
        == "complete"
    )


def test_local_parent_gate_preserves_ancestor_resolver_requirement(
    tmp_path,
    graph_context,
):
    order, receipt, review, root = graph_context
    child = _child(
        graph_context,
        parent_digest=_digest(root),
        created_at=_later(root.to_dict()["created_at"], 1),
    )
    raw_package = generate_vectors()["rule_package"]
    resources = {
        item["digest"]: bytes.fromhex(item["bytes_hex"])
        for item in raw_package["resources"]
    }
    resolver = _Resolver(build_rule_package(raw_package["manifest"], resources))
    store = TradeDisputeStatementStore(tmp_path)
    store.put(
        root,
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
    )

    with pytest.raises(
        TradeDisputeStatementResolverRequired,
        match="requires an exact-digest package_resolver",
    ):
        store.assert_complete_parent_chain(
            child,
            review=review,
            receipt=receipt,
            order=order,
        )


def test_store_accepts_local_extension_within_clock_skew(tmp_path, graph_context):
    order, receipt, review, root = graph_context
    parent = create_trade_dispute_statement(
        _maker_identity(),
        review=review,
        receipt=receipt,
        order=order,
        statement_type="remedy-proposal",
        reason_codes=["later-parent"],
        claim={
            "claim_type": "remedy-proposal",
            "media_type": "application/json",
            "digest": "sha256:" + ("d" * 64),
            "size": 1,
            "schema_digest": None,
        },
        created_at=_later(root.to_dict()["created_at"], 2),
    )
    child = _child(
        graph_context,
        parent_digest=_digest(parent),
        created_at=_later(root.to_dict()["created_at"], 1),
    )
    store = TradeDisputeStatementStore(tmp_path)
    store.put(parent, review=review, receipt=receipt, order=order)

    projection = store.assert_complete_parent_chain(
        child,
        review=review,
        receipt=receipt,
        order=order,
    )
    assert projection.graph_status == "complete"


def test_local_parent_gate_reads_only_candidate_ancestry(tmp_path, graph_context):
    order, receipt, review, root = graph_context
    root_digest = _digest(root)
    child = _child(
        graph_context,
        parent_digest=root_digest,
        created_at=_later(root.to_dict()["created_at"], 1),
    )
    raw_package = generate_vectors()["rule_package"]
    resources = {
        item["digest"]: bytes.fromhex(item["bytes_hex"])
        for item in raw_package["resources"]
    }
    resolver = _Resolver(build_rule_package(raw_package["manifest"], resources))
    store = TradeDisputeStatementStore(tmp_path)
    store.put(
        root,
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
    )

    unrelated = root.to_dict()
    unrelated["reason_codes"] = ["unrelated-corrupt-signature"]
    unrelated_payload = trade_canonical_json(unrelated)
    unrelated_digest = "sha256:" + hashlib.sha256(unrelated_payload).hexdigest()
    store._path(unrelated_digest).write_bytes(unrelated_payload)

    projection = store.assert_complete_parent_chain(
        child,
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
    )

    assert projection.graph_status == "complete"
    assert projection.statement_count == 2
    assert unrelated_digest not in projection.topological_digests


def test_local_parent_gate_enforces_ancestry_budget(tmp_path, graph_context):
    order, receipt, review, root = graph_context
    child = _child(
        graph_context,
        parent_digest=_digest(root),
        created_at=_later(root.to_dict()["created_at"], 1),
    )
    raw_package = generate_vectors()["rule_package"]
    resources = {
        item["digest"]: bytes.fromhex(item["bytes_hex"])
        for item in raw_package["resources"]
    }
    resolver = _Resolver(build_rule_package(raw_package["manifest"], resources))
    store = TradeDisputeStatementStore(tmp_path)
    store.put(
        root,
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
    )

    with pytest.raises(TradeDisputeStatementStoreCapacity, match="ancestry"):
        store.assert_complete_parent_chain(
            child,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
            max_ancestry_nodes=1,
        )


def test_store_graph_wraps_corrupt_signature_as_integrity_error(
    tmp_path,
    graph_context,
):
    order, receipt, review, root = graph_context
    tampered = root.to_dict()
    tampered["reason_codes"] = ["tampered-claim"]
    payload = trade_canonical_json(tampered)
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    store = TradeDisputeStatementStore(tmp_path)
    store.root.mkdir(parents=True)
    store._path(digest).write_bytes(payload)
    raw_package = generate_vectors()["rule_package"]
    resources = {
        item["digest"]: bytes.fromhex(item["bytes_hex"])
        for item in raw_package["resources"]
    }
    resolver = _Resolver(build_rule_package(raw_package["manifest"], resources))

    with pytest.raises(
        TradeDisputeStatementStoreError,
        match="failed protocol verification",
    ):
        store.get(
            digest,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
        )
    with pytest.raises(
        TradeDisputeStatementStoreError,
        match="failed protocol verification",
    ):
        store.list_for_review(
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
        )
    with pytest.raises(
        TradeDisputeStatementStoreError,
        match="failed protocol verification",
    ):
        store.graph_for_review(
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
        )


def test_store_graph_preserves_operational_resolver_failure(
    tmp_path,
    graph_context,
):
    order, receipt, review, root = graph_context
    raw_package = generate_vectors()["rule_package"]
    resources = {
        item["digest"]: bytes.fromhex(item["bytes_hex"])
        for item in raw_package["resources"]
    }
    resolver = _Resolver(build_rule_package(raw_package["manifest"], resources))
    store = TradeDisputeStatementStore(tmp_path)
    store.put(
        root,
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
    )

    with pytest.raises(
        TradeDisputeStatementDependencyError,
        match="dependency is unavailable",
    ):
        store.graph_for_review(
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=_FailingResolver(),
        )
