"""v0.9.4 — nth status CLI + Prometheus metrics endpoint."""

import json
import urllib.request

import pytest

from nth_dao.cli.metrics import collect_metrics, render_prometheus
from nth_dao.cli.status import collect_status, render_text


# ─────────────────── status ───────────────────


def test_status_empty_workspace_does_not_raise(tmp_path):
    snap = collect_status(tmp_path)
    assert "version" in snap
    assert "team" in snap
    assert "agents" in snap
    assert "missions" in snap
    assert "templates" in snap
    assert "trust" in snap


def test_status_reports_populated_team(tmp_path):
    import nth_dao as nth
    mm = nth.MembershipManager(tmp_path)
    mm.init_team(team_name="alpha", admin_ids=["alice"])
    snap = collect_status(tmp_path)
    assert snap["team"]["team_name"] == "alpha"
    assert snap["team"]["admins"] == 1
    assert snap["team"]["members"] == 1


def test_status_reports_active_missions(tmp_path):
    from nth_dao.orchestration import Mission, MissionStore
    store = MissionStore(str(tmp_path / "missions"))
    m = Mission.new(title="t", goal="g", owner="alice",
                    steps=[{"id": "s", "description": "x"}])
    store.create(m)
    snap = collect_status(tmp_path)
    assert snap["missions"]["by_status"]["planning"] == 1


def test_status_text_renders_all_sections(tmp_path):
    snap = collect_status(tmp_path)
    text = render_text(snap)
    assert "NTH DAO workspace status" in text
    assert "Team" in text
    assert "Agents" in text
    assert "Missions" in text
    assert "Templates" in text
    assert "Trust" in text


def test_status_json_mode_is_valid_json(tmp_path):
    snap = collect_status(tmp_path)
    blob = json.dumps(snap)
    re_parsed = json.loads(blob)
    assert re_parsed["workspace"] == str(tmp_path.resolve())


# ─────────────────── metrics ───────────────────


def test_metrics_collect_returns_list_of_tuples(tmp_path):
    rows = collect_metrics(tmp_path)
    assert isinstance(rows, list)
    assert all(isinstance(r, tuple) and len(r) == 3 for r in rows)


def test_metrics_includes_info_and_workspace(tmp_path):
    rows = collect_metrics(tmp_path)
    names = {n for n, _, _ in rows}
    assert "nth_dao_info" in names
    assert "nth_dao_workspace_path_info" in names


def test_metrics_includes_mission_status_breakdown(tmp_path):
    rows = collect_metrics(tmp_path)
    mission_rows = [r for r in rows if r[0] == "nth_dao_missions_total"]
    statuses = {labels.get("status") for _, labels, _ in mission_rows}
    assert "planning" in statuses
    assert "active" in statuses
    assert "completed" in statuses
    assert "failed" in statuses
    assert "archived" in statuses


def test_metrics_prometheus_format_has_help_and_type(tmp_path):
    rows = collect_metrics(tmp_path)
    body = render_prometheus(rows)
    assert "# HELP nth_dao_info" in body
    assert "# TYPE nth_dao_info gauge" in body


def test_metrics_prometheus_format_escapes_label_values(tmp_path):
    rows = [("nth_dao_test", {"path": 'C:\\path\\with"quotes'}, 1.0)]
    body = render_prometheus(rows)
    # double quote -> \"   ; backslash -> \\
    assert r'\\path\\with\"quotes' in body


def test_metrics_reflects_active_missions(tmp_path):
    from nth_dao.orchestration import Mission, MissionStore
    store = MissionStore(str(tmp_path / "missions"))
    m = Mission.new(title="t", goal="g", owner="alice",
                    steps=[{"id": "s", "description": "x"}])
    store.create(m)
    rows = collect_metrics(tmp_path)
    planning_rows = [
        r for r in rows
        if r[0] == "nth_dao_missions_total" and r[1].get("status") == "planning"
    ]
    assert any(r[2] == 1.0 for r in planning_rows)


# ─────────────────── server smoke test ───────────────────


def test_metrics_server_serves_text_endpoint(tmp_path):
    """Start a brief metrics server, scrape it once, then shut it down."""
    import socket
    import threading
    import time

    from nth_dao.cli.metrics import _Handler
    from http.server import ThreadingHTTPServer

    # Pick a free TCP port (different from the LAN UDP discovery port path)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    _Handler.workspace = tmp_path
    server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        time.sleep(0.1)
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=3) as resp:
            assert resp.status == 200
            body = resp.read().decode("utf-8")
            assert "nth_dao_info" in body
        # healthz
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=3) as resp:
            assert resp.status == 200
            assert resp.read().startswith(b"ok")
    finally:
        server.shutdown()
