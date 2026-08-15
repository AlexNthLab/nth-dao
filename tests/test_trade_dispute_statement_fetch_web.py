import time
from types import SimpleNamespace

from fastapi.testclient import TestClient

import nth_dao.web.v2_api as web_v2_api
from nth_dao.web import create_app


def _fetch_path(*, federated: bool) -> str:
    prefix = "/api/v2/trade/federation" if federated else "/api/v2/trade"
    return (
        f"{prefix}/orders/sha256:{'1' * 64}"
        f"/execution-receipts/nth-trade-execution-sha256:{'2' * 64}"
        f"/reviews/nth-trade-review-sha256:{'3' * 64}"
        "/dispute-statements/fetch"
    )


def test_fetch_route_auth_boundaries_and_preparse_limit(tmp_path):
    app = create_app(tmp_path / "node", require_console_auth=True)
    client = TestClient(app)

    federated = client.post(_fetch_path(federated=True), json={})
    local = client.post(_fetch_path(federated=False), json={})
    oversized = client.post(
        _fetch_path(federated=True),
        content=b"{" + (b" " * (16 * 1024)),
        headers={"Content-Type": "application/json"},
    )
    oversized_local = client.post(
        _fetch_path(federated=False),
        content=b"{" + (b" " * (16 * 1024)),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {app.state.nth_console_token}",
        },
    )

    # The signed federation route reaches protocol routing without the
    # operator's secret. It is not a console action.
    assert federated.status_code == 400
    # The local fetch command remains an authenticated operator action.
    assert local.status_code == 401
    # Oversized anonymous bodies are rejected before JSON or runtime lookup.
    assert oversized.status_code == 413
    assert oversized_local.status_code == 413


def test_fetch_runtime_state_is_initialized(tmp_path):
    app = create_app(tmp_path / "node")

    assert app.state.nth.trade_dispute_statement_fetch_journal is not None
    assert app.state.nth.trade_dispute_statement_fetch_outbox is not None
    assert app.state.nth.trade_dispute_statement_fetch_limiter is not None
    assert app.state.nth.trade_dispute_statement_fetch_global_limiter is not None


def test_fetch_web_coordinator_cache_evicts_by_count_and_ttl(tmp_path):
    app = create_app(tmp_path / "node")
    state = app.state.nth
    state.trade_dispute_statement_fetch_max_coordinators = 2
    request = SimpleNamespace(app=app)

    for marker in ("1", "2", "3"):
        web_v2_api._trade_dispute_statement_fetch_coordinator(
            request,
            order_digest="sha256:" + (marker * 64),
            journal=state.trade_dispute_statement_fetch_journal,
            statement_store=state.trade_dispute_statements,
            identity=state.node_identity,
            spine=state.spine,
            package_resolver=None,
        )
    assert tuple(state.trade_dispute_statement_fetch_coordinators) == (
        "sha256:" + ("2" * 64),
        "sha256:" + ("3" * 64),
    )

    stale = next(iter(state.trade_dispute_statement_fetch_coordinators.values()))
    stale.web_cache_last_used = time.monotonic() - 2.0
    state.trade_dispute_statement_fetch_coordinator_ttl_seconds = 1.0
    web_v2_api._trade_dispute_statement_fetch_coordinator(
        request,
        order_digest="sha256:" + ("4" * 64),
        journal=state.trade_dispute_statement_fetch_journal,
        statement_store=state.trade_dispute_statements,
        identity=state.node_identity,
        spine=state.spine,
        package_resolver=None,
    )
    assert "sha256:" + ("2" * 64) not in (
        state.trade_dispute_statement_fetch_coordinators
    )
