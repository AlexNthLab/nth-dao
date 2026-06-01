"""Prometheus exposition-format metrics from a NTH DAO workspace.

Pure stdlib: emits Prometheus text format without depending on the
prometheus_client library.

Usage:

    python -m nth_dao.cli.metrics --workspace . --port 9090

Then scrape http://host:9090/metrics from your Prometheus server.

Metrics emitted:

    nth_dao_info{version="0.9.4"}                          1
    nth_dao_agents_total{status="alive"}                   N
    nth_dao_agents_total{status="all"}                     N
    nth_dao_missions_total{status="planning"}              N
    nth_dao_missions_total{status="active"}                N
    nth_dao_missions_total{status="completed"}             N
    nth_dao_missions_total{status="failed"}                N
    nth_dao_missions_total{status="archived"}              N
    nth_dao_templates_total                                N
    nth_dao_templates_deprecated_total                     N
    nth_dao_reviews_total                                  N
    nth_dao_trust_endorsements_active                      N
    nth_dao_trust_revocations_total                        N
    nth_dao_join_requests_pending                          N
    nth_dao_workspace_path_info{path="..."}                1
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Tuple

from ..util import safe_load_json

logger = logging.getLogger("nth_dao.cli.metrics")


def _esc(label_value: str) -> str:
    """Prometheus exposition escape for label values."""
    return label_value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def collect_metrics(workspace: Path) -> List[Tuple[str, Dict[str, str], float]]:
    """Walk the workspace and return [(metric_name, labels, value), ...].

    Tolerant: any individual subsystem failure just yields zero/no data
    for that metric. The whole metrics endpoint should never raise.
    """
    metrics: List[Tuple[str, Dict[str, str], float]] = []

    try:
        from .. import __version__
    except Exception:
        __version__ = "unknown"

    metrics.append(("nth_dao_info", {"version": __version__}, 1.0))
    metrics.append(("nth_dao_workspace_path_info",
                    {"path": str(workspace.resolve())}, 1.0))

    # ── Agents (discovery/agent_registry) ──
    try:
        from ..discovery import AgentRegistry
        reg = AgentRegistry(agents_dir=str(workspace / "team_agents"))
        all_agents = reg.list_all()
        alive_agents = reg.list_alive()
        metrics.append(("nth_dao_agents_total", {"status": "all"}, len(all_agents)))
        metrics.append(("nth_dao_agents_total", {"status": "alive"}, len(alive_agents)))
    except Exception as e:
        logger.debug("agent metrics failed: %s", e)

    # ── Missions ──
    mission_counts = {
        "planning": 0, "active": 0, "completed": 0,
        "failed": 0, "cancelled": 0, "paused": 0,
    }
    archive_count = 0
    template_count = 0
    deprecated_count = 0
    review_count = 0
    try:
        from ..orchestration import MissionStore
        store = MissionStore(str(workspace / "missions"))
        for m in store.list_all():
            mission_counts[m.status] = mission_counts.get(m.status, 0) + 1
        archive_count = len(store.list_archive())

        # Templates
        for t in store.templates.list_all(include_deprecated=True):
            template_count += 1
            if t.deprecated:
                deprecated_count += 1

        # Reviews — count lines in every reviews/*.jsonl
        reviews_dir = workspace / "missions" / "reviews"
        if reviews_dir.exists():
            for path in reviews_dir.glob("*.jsonl"):
                try:
                    review_count += sum(
                        1 for line in path.read_text(encoding="utf-8").splitlines()
                        if line.strip()
                    )
                except OSError:
                    continue
    except Exception as e:
        logger.debug("mission metrics failed: %s", e)

    for status, n in mission_counts.items():
        metrics.append(("nth_dao_missions_total", {"status": status}, float(n)))
    metrics.append(("nth_dao_missions_total", {"status": "archived"}, float(archive_count)))
    metrics.append(("nth_dao_templates_total", {}, float(template_count)))
    metrics.append(("nth_dao_templates_deprecated_total", {}, float(deprecated_count)))
    metrics.append(("nth_dao_reviews_total", {}, float(review_count)))

    # ── Trust (endorsements + revocations) ──
    try:
        from ..web_of_trust import TrustGraph
        tg = TrustGraph(workspace)
        active = len(tg.list_endorsements(include_expired=False))
        revs = len(tg._load_revocations())
        metrics.append(("nth_dao_trust_endorsements_active", {}, float(active)))
        metrics.append(("nth_dao_trust_revocations_total", {}, float(revs)))
    except Exception as e:
        logger.debug("trust metrics failed: %s", e)

    # ── Membership: pending join requests ──
    try:
        from ..membership import MembershipManager
        mm = MembershipManager(workspace)
        pending = len(mm.list_pending())
        metrics.append(("nth_dao_join_requests_pending", {}, float(pending)))
    except Exception as e:
        logger.debug("membership metrics failed: %s", e)

    return metrics


def render_prometheus(metrics: List[Tuple[str, Dict[str, str], float]]) -> str:
    """Render in Prometheus text exposition format v0.0.4."""
    out: List[str] = []
    # Group lines per metric name for HELP+TYPE comments
    by_name: Dict[str, List[Tuple[Dict[str, str], float]]] = {}
    for name, labels, value in metrics:
        by_name.setdefault(name, []).append((labels, value))
    for name, entries in by_name.items():
        out.append(f"# HELP {name} NTH DAO derived metric.")
        out.append(f"# TYPE {name} gauge")
        for labels, value in entries:
            if labels:
                label_pairs = ",".join(
                    f'{k}="{_esc(v)}"' for k, v in sorted(labels.items())
                )
                out.append(f"{name}{{{label_pairs}}} {value}")
            else:
                out.append(f"{name} {value}")
    out.append("")  # trailing newline
    return "\n".join(out)


class _Handler(BaseHTTPRequestHandler):
    workspace: Path = Path(".")

    def log_message(self, format, *args):
        # Quieter access log; route to our logger
        logger.debug("%s - %s", self.address_string(), format % args)

    def do_GET(self):
        if self.path in ("/metrics", "/metrics/"):
            try:
                body = render_prometheus(collect_metrics(self.workspace))
            except Exception as e:
                logger.exception("metrics collection raised: %s", e)
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"error: {e}".encode("utf-8"))
                return
            data = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif self.path in ("/healthz", "/healthz/"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok\n")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"try /metrics or /healthz\n")


def serve(workspace: Path, host: str, port: int) -> None:
    _Handler.workspace = workspace
    server = ThreadingHTTPServer((host, port), _Handler)
    print(f"nth_dao.cli.metrics  workspace={workspace.resolve()}  "
          f"endpoint=http://{host}:{port}/metrics")
    print("Press Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("shutting down")
        server.shutdown()


def main(argv: list = None) -> None:
    parser = argparse.ArgumentParser(
        description="Serve Prometheus metrics from a NTH DAO workspace.",
    )
    parser.add_argument("--workspace", default=".", type=Path,
                        help="NTH DAO workspace directory (default: cwd)")
    parser.add_argument("--host", default="127.0.0.1",
                        help="bind address (default: 127.0.0.1)")
    parser.add_argument("--port", default=9090, type=int,
                        help="bind port (default: 9090)")
    parser.add_argument("--once", action="store_true",
                        help="print metrics once to stdout and exit (no server)")
    args = parser.parse_args(argv)

    if args.once:
        body = render_prometheus(collect_metrics(args.workspace))
        sys.stdout.write(body)
        return

    serve(args.workspace, args.host, args.port)


if __name__ == "__main__":
    main()
