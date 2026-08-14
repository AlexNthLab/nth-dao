"""Deterministic structural projection for signed dispute statements.

The projection proves only that retained statements form a locally complete,
context-consistent parent graph.  It does not decide whether any claim is true
or settle the dispute.
"""

from __future__ import annotations

import hashlib
import heapq
import itertools
import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Mapping

from nth_dao.trade_rules.agreement import DEFAULT_CLOCK_SKEW_SECONDS
from nth_dao.trade_rules.dispute_statement import (
    MAX_TRADE_DISPUTE_CLOCK_SKEW_SECONDS,
    TRADE_DISPUTE_ID_PREFIX,
    TradeDisputeStatement,
)

MAX_TRADE_DISPUTE_GRAPH_NODES = 20_000
MAX_TRADE_DISPUTE_GRAPH_EDGES = 100_000

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_DISPUTE_ID = re.compile(
    rf"^{re.escape(TRADE_DISPUTE_ID_PREFIX)}[0-9a-f]{{64}}$"
)


class TradeDisputeGraphError(ValueError):
    """The supplied statement set cannot form a trustworthy projection."""


class TradeDisputeGraphCapacity(TradeDisputeGraphError):
    """The supplied statement set exceeds a projection resource budget."""


@dataclass(frozen=True)
class TradeDisputeGraphIssue:
    """One structural problem on a child-to-parent edge."""

    statement_digest: str
    parent_digest: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {
            "statement_digest": self.statement_digest,
            "parent_digest": self.parent_digest,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class TradeDisputeGraphNode:
    """Derived ancestry state for one signed statement."""

    statement_digest: str
    parent_statement_digests: tuple[str, ...]
    ancestry_status: str
    depth: int | None

    def to_dict(self) -> dict[str, object]:
        return {
            "statement_digest": self.statement_digest,
            "parent_statement_digests": list(self.parent_statement_digests),
            "ancestry_status": self.ancestry_status,
            "depth": self.depth,
        }


@dataclass(frozen=True)
class TradeDisputeGraphProjection:
    """Read-only view over a single exact disputed Review."""

    snapshot_token: str
    graph_status: str
    review_digest: str
    dispute_id: str
    statement_count: int
    root_digests: tuple[str, ...]
    tip_digests: tuple[str, ...]
    topological_digests: tuple[str, ...]
    unresolved_parent_digests: tuple[str, ...]
    non_dag_digests: tuple[str, ...]
    issues: tuple[TradeDisputeGraphIssue, ...]
    nodes: tuple[TradeDisputeGraphNode, ...]

    @property
    def complete(self) -> bool:
        return self.graph_status == "complete"

    @property
    def adjudicated_or_proven_true(self) -> bool:
        return False

    def to_dict(self, *, max_items: int | None = None) -> dict[str, object]:
        if max_items is not None and (
            isinstance(max_items, bool)
            or not isinstance(max_items, int)
            or max_items < 1
        ):
            raise ValueError("max_items must be a positive integer or None")

        if max_items is None:
            visible_nodes = self.nodes
        else:
            details_fit = all(
                len(values) <= max_items
                for values in (
                    self.root_digests,
                    self.tip_digests,
                    self.topological_digests,
                    self.unresolved_parent_digests,
                    self.non_dag_digests,
                    self.issues,
                    self.nodes,
                )
            )
            if details_fit:
                visible_nodes = self.nodes
            else:
                nodes_by_digest = {
                    node.statement_digest: node for node in self.nodes
                }
                issue_counts: dict[str, int] = {}
                for issue in self.issues:
                    issue_counts[issue.statement_digest] = (
                        issue_counts.get(issue.statement_digest, 0) + 1
                    )
                selected: list[TradeDisputeGraphNode] = []
                selected_issue_count = 0
                # A topological prefix is closed over every locally retained
                # parent. Cyclic components are omitted unless the complete
                # detail set fits, because a bounded strict subset of a cycle
                # cannot be referentially closed.
                for digest in self.topological_digests:
                    next_issue_count = (
                        selected_issue_count + issue_counts.get(digest, 0)
                    )
                    if len(selected) >= max_items or next_issue_count > max_items:
                        break
                    selected.append(nodes_by_digest[digest])
                    selected_issue_count = next_issue_count
                visible_nodes = tuple(selected)
        visible_digests = {node.statement_digest for node in visible_nodes}

        def _bounded_digests(values: tuple[str, ...]) -> list[str]:
            if max_items is None:
                return list(values)
            return [value for value in values if value in visible_digests][:max_items]

        visible_issues = (
            self.issues
            if max_items is None
            else tuple(
                issue
                for issue in self.issues
                if issue.statement_digest in visible_digests
            )
        )
        visible_unresolved = (
            list(self.unresolved_parent_digests)
            if max_items is None
            else sorted(
                {
                    issue.parent_digest
                    for issue in visible_issues
                    if issue.reason == "missing-parent"
                }
            )[:max_items]
        )

        collections = (
            self.root_digests,
            self.tip_digests,
            self.topological_digests,
            self.unresolved_parent_digests,
            self.non_dag_digests,
            self.issues,
            self.nodes,
        )
        return {
            "snapshot_token": self.snapshot_token,
            "graph_status": self.graph_status,
            "review_digest": self.review_digest,
            "dispute_id": self.dispute_id,
            "statement_count": self.statement_count,
            "root_digests": _bounded_digests(self.root_digests),
            "root_count": len(self.root_digests),
            "tip_digests": _bounded_digests(self.tip_digests),
            "tip_count": len(self.tip_digests),
            "topological_digests": _bounded_digests(self.topological_digests),
            "topological_count": len(self.topological_digests),
            "unresolved_parent_digests": visible_unresolved,
            "unresolved_parent_count": len(self.unresolved_parent_digests),
            "non_dag_digests": _bounded_digests(self.non_dag_digests),
            "non_dag_count": len(self.non_dag_digests),
            "issues": [
                issue.to_dict()
                for issue in visible_issues
            ],
            "issue_count": len(self.issues),
            "nodes": [
                node.to_dict()
                for node in visible_nodes
            ],
            "node_count": len(self.nodes),
            "items_truncated": max_items is not None
            and (
                len(visible_nodes) != len(self.nodes)
                or len(visible_issues) != len(self.issues)
                or any(len(values) > max_items for values in collections)
            ),
            "adjudicated_or_proven_true": False,
        }


def _statement_digest(statement: TradeDisputeStatement) -> str:
    return "sha256:" + hashlib.sha256(statement.canonical_bytes).hexdigest()


def _timestamp(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except (TypeError, ValueError) as exc:
        raise TradeDisputeGraphError(
            "verified statement contains an invalid created_at"
        ) from exc


def _clock_skew_policy(
    value: float,
) -> tuple[timedelta, int]:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
        or value > MAX_TRADE_DISPUTE_CLOCK_SKEW_SECONDS
    ):
        raise ValueError(
            "clock_skew_seconds must be finite and between 0 and "
            f"{MAX_TRADE_DISPUTE_CLOCK_SKEW_SECONDS}"
        )
    delta = timedelta(seconds=float(value))
    microseconds = (
        (delta.days * 86_400 + delta.seconds) * 1_000_000
        + delta.microseconds
    )
    return delta, microseconds


def trade_dispute_graph_snapshot_token(
    digests: Iterable[str],
    *,
    review_digest: str,
    dispute_id: str,
    known_parent_review_digests: Mapping[str, str] | None = None,
    clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
) -> str:
    """Bind every retained input that can change one graph projection."""

    if _DIGEST.fullmatch(review_digest) is None:
        raise TradeDisputeGraphError("review_digest is invalid")
    if _DISPUTE_ID.fullmatch(dispute_id) is None:
        raise TradeDisputeGraphError("dispute_id is invalid")
    values = list(digests)
    if any(not isinstance(value, str) or _DIGEST.fullmatch(value) is None for value in values):
        raise TradeDisputeGraphError("statement digest set is invalid")
    if len(set(values)) != len(values):
        raise TradeDisputeGraphError("statement digest set contains duplicates")
    known_parents = dict(known_parent_review_digests or {})
    _clock_skew, clock_skew_microseconds = _clock_skew_policy(
        clock_skew_seconds
    )
    if any(
        not isinstance(digest, str)
        or _DIGEST.fullmatch(digest) is None
        or not isinstance(parent_review, str)
        or _DIGEST.fullmatch(parent_review) is None
        for digest, parent_review in known_parents.items()
    ):
        raise TradeDisputeGraphError("known parent review mapping is invalid")
    payload = b"\x00".join(
        [
            b"nth-dao/trade-dispute-graph-snapshot/v2",
            review_digest.encode("ascii"),
            dispute_id.encode("ascii"),
            b"clock-skew-microseconds",
            str(clock_skew_microseconds).encode("ascii"),
            b"statements",
        ]
        + [value.encode("ascii") for value in sorted(values)]
        + [b"known-parent-reviews"]
        + [
            f"{digest}={parent_review}".encode("ascii")
            for digest, parent_review in sorted(known_parents.items())
        ]
    )
    return "v2:" + hashlib.sha256(payload).hexdigest()


def project_trade_dispute_graph(
    records: Iterable[tuple[str, TradeDisputeStatement]],
    *,
    known_review_digests: Mapping[str, str] | None = None,
    expected_review_digest: str | None = None,
    expected_dispute_id: str | None = None,
    max_nodes: int = MAX_TRADE_DISPUTE_GRAPH_NODES,
    max_edges: int = MAX_TRADE_DISPUTE_GRAPH_EDGES,
    clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
) -> TradeDisputeGraphProjection:
    """Project structural ancestry without treating signed claims as facts.

    ``records`` must contain every locally retained statement for one exact
    Review.  ``known_review_digests`` may additionally identify parent digests
    retained for other Reviews so cross-context references are distinguishable
    from unavailable parents.
    """

    if isinstance(max_nodes, bool) or not isinstance(max_nodes, int) or max_nodes < 1:
        raise ValueError("max_nodes must be a positive integer")
    if isinstance(max_edges, bool) or not isinstance(max_edges, int) or max_edges < 1:
        raise ValueError("max_edges must be a positive integer")
    clock_skew_delta, _clock_skew_microseconds = _clock_skew_policy(
        clock_skew_seconds
    )
    if expected_review_digest is not None and (
        not isinstance(expected_review_digest, str)
        or _DIGEST.fullmatch(expected_review_digest) is None
    ):
        raise TradeDisputeGraphError("expected_review_digest is invalid")
    if expected_dispute_id is not None and (
        not isinstance(expected_dispute_id, str)
        or _DISPUTE_ID.fullmatch(expected_dispute_id) is None
    ):
        raise TradeDisputeGraphError("expected_dispute_id is invalid")
    supplied = list(itertools.islice(iter(records), max_nodes + 1))
    if len(supplied) > max_nodes:
        raise TradeDisputeGraphCapacity("dispute graph exceeds max_nodes")

    statements: dict[str, TradeDisputeStatement] = {}
    documents: dict[str, dict[str, object]] = {}
    edge_count = 0
    for digest, statement in supplied:
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            raise TradeDisputeGraphError("statement digest is invalid")
        if not isinstance(statement, TradeDisputeStatement):
            raise TypeError("records must contain TradeDisputeStatement values")
        if _statement_digest(statement) != digest:
            raise TradeDisputeGraphError("statement content digest mismatch")
        if digest in statements:
            raise TradeDisputeGraphError("duplicate statement digest")
        statements[digest] = statement
        document = statement.to_dict()
        edge_count += len(document["parent_statement_digests"])
        if edge_count > max_edges:
            raise TradeDisputeGraphCapacity("dispute graph exceeds max_edges")
        documents[digest] = document

    known: dict[str, str] = {}
    for index, (digest, review_digest) in enumerate(
        (known_review_digests or {}).items()
    ):
        if index >= max_nodes:
            raise TradeDisputeGraphCapacity(
                "known review mapping exceeds max_nodes"
            )
        if (
            not isinstance(digest, str)
            or _DIGEST.fullmatch(digest) is None
            or not isinstance(review_digest, str)
            or _DIGEST.fullmatch(review_digest) is None
        ):
            raise TradeDisputeGraphError("known review digest mapping is invalid")
        known[digest] = review_digest

    if not statements:
        if expected_review_digest is None or expected_dispute_id is None:
            raise TradeDisputeGraphError(
                "empty dispute graph requires expected Review and dispute context"
            )
        return TradeDisputeGraphProjection(
            snapshot_token=trade_dispute_graph_snapshot_token(
                (),
                review_digest=expected_review_digest or "",
                dispute_id=expected_dispute_id or "",
                clock_skew_seconds=clock_skew_seconds,
            ),
            graph_status="complete",
            review_digest=expected_review_digest or "",
            dispute_id=expected_dispute_id or "",
            statement_count=0,
            root_digests=(),
            tip_digests=(),
            topological_digests=(),
            unresolved_parent_digests=(),
            non_dag_digests=(),
            issues=(),
            nodes=(),
        )

    first = next(iter(documents.values()))
    review_digest = str(first["review_digest"])
    dispute_id = str(first["dispute_id"])
    if expected_review_digest is not None and review_digest != expected_review_digest:
        raise TradeDisputeGraphError("statement set does not match expected Review")
    if expected_dispute_id is not None and dispute_id != expected_dispute_id:
        raise TradeDisputeGraphError("statement set does not match expected dispute")
    order_digest = str(first["order_digest"])
    receipt_digest = str(first["receipt_digest"])
    for digest, document in documents.items():
        if (
            document["review_digest"] != review_digest
            or document["dispute_id"] != dispute_id
            or document["order_digest"] != order_digest
            or document["receipt_digest"] != receipt_digest
        ):
            raise TradeDisputeGraphError(
                f"statement {digest} belongs to a different dispute context"
            )
        mapped_review = known.get(digest)
        if mapped_review is not None and mapped_review != review_digest:
            raise TradeDisputeGraphError(
                "known review mapping contradicts supplied statement"
            )
        known[digest] = review_digest

    issues: list[TradeDisputeGraphIssue] = []
    unresolved: set[str] = set()
    parents: dict[str, tuple[str, ...]] = {}
    children: dict[str, set[str]] = {digest: set() for digest in statements}
    indegree: dict[str, int] = {digest: 0 for digest in statements}
    direct_status: dict[str, str] = {digest: "complete" for digest in statements}

    def _issue(child: str, parent: str, reason: str, status: str) -> None:
        issues.append(TradeDisputeGraphIssue(child, parent, reason))
        if status == "invalid" or direct_status[child] == "complete":
            direct_status[child] = status

    for child_digest, document in documents.items():
        child_parents = tuple(document["parent_statement_digests"])
        parents[child_digest] = child_parents
        child_time = _timestamp(str(document["created_at"]))
        for parent_digest in child_parents:
            if parent_digest == child_digest:
                _issue(child_digest, parent_digest, "self-parent", "invalid")
                continue
            parent = documents.get(parent_digest)
            if parent is None:
                known_review = known.get(parent_digest)
                if known_review is not None and known_review != review_digest:
                    _issue(
                        child_digest,
                        parent_digest,
                        "parent-context-mismatch",
                        "invalid",
                    )
                else:
                    unresolved.add(parent_digest)
                    _issue(child_digest, parent_digest, "missing-parent", "incomplete")
                continue
            children[parent_digest].add(child_digest)
            indegree[child_digest] += 1
            if _timestamp(str(parent["created_at"])) > child_time + clock_skew_delta:
                _issue(
                    child_digest,
                    parent_digest,
                    "parent-beyond-clock-skew",
                    "invalid",
                )

    def _sort_key(digest: str) -> tuple[datetime, str, str]:
        document = documents[digest]
        return (
            _timestamp(str(document["created_at"])),
            str(document["statement_id"]),
            digest,
        )

    ready = [(_sort_key(digest), digest) for digest, degree in indegree.items() if degree == 0]
    heapq.heapify(ready)
    topological: list[str] = []
    remaining_indegree = dict(indegree)
    while ready:
        _key, digest = heapq.heappop(ready)
        topological.append(digest)
        for child in sorted(children[digest], key=_sort_key):
            remaining_indegree[child] -= 1
            if remaining_indegree[child] == 0:
                heapq.heappush(ready, (_sort_key(child), child))
    non_dag = set(statements).difference(topological)

    node_status: dict[str, str] = {}
    node_depth: dict[str, int | None] = {}
    for digest in topological:
        status = direct_status[digest]
        depth = 0
        for parent in parents[digest]:
            if parent not in statements:
                continue
            parent_status = node_status[parent]
            if parent_status == "invalid":
                status = "invalid"
            elif parent_status == "incomplete" and status == "complete":
                status = "incomplete"
            parent_depth = node_depth[parent]
            if parent_depth is not None:
                depth = max(depth, parent_depth + 1)
        node_status[digest] = status
        node_depth[digest] = depth if status == "complete" else None
    for digest in non_dag:
        node_status[digest] = "invalid"
        node_depth[digest] = None

    nodes = tuple(
        TradeDisputeGraphNode(
            statement_digest=digest,
            parent_statement_digests=parents[digest],
            ancestry_status=node_status[digest],
            depth=node_depth[digest],
        )
        for digest in sorted(statements, key=_sort_key)
    )
    statuses = {node.ancestry_status for node in nodes}
    graph_status = (
        "invalid"
        if "invalid" in statuses
        else "incomplete" if "incomplete" in statuses else "complete"
    )
    roots = tuple(
        sorted((digest for digest, value in parents.items() if not value), key=_sort_key)
    )
    tips = tuple(
        sorted((digest for digest, value in children.items() if not value), key=_sort_key)
    )
    issues.sort(key=lambda item: (item.statement_digest, item.parent_digest, item.reason))
    graph_input_parent_reviews = {
        parent_digest: known[parent_digest]
        for document in documents.values()
        for parent_digest in document["parent_statement_digests"]
        if parent_digest not in statements and parent_digest in known
    }
    return TradeDisputeGraphProjection(
        snapshot_token=trade_dispute_graph_snapshot_token(
            statements,
            review_digest=review_digest,
            dispute_id=dispute_id,
            known_parent_review_digests=graph_input_parent_reviews,
            clock_skew_seconds=clock_skew_seconds,
        ),
        graph_status=graph_status,
        review_digest=review_digest,
        dispute_id=dispute_id,
        statement_count=len(statements),
        root_digests=roots,
        tip_digests=tips,
        topological_digests=tuple(topological),
        unresolved_parent_digests=tuple(sorted(unresolved)),
        non_dag_digests=tuple(sorted(non_dag)),
        issues=tuple(issues),
        nodes=nodes,
    )


__all__ = [
    "MAX_TRADE_DISPUTE_GRAPH_EDGES",
    "MAX_TRADE_DISPUTE_GRAPH_NODES",
    "TradeDisputeGraphCapacity",
    "TradeDisputeGraphError",
    "TradeDisputeGraphIssue",
    "TradeDisputeGraphNode",
    "TradeDisputeGraphProjection",
    "project_trade_dispute_graph",
    "trade_dispute_graph_snapshot_token",
]
