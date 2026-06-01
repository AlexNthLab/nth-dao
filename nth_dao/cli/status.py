"""Human-friendly status snapshot of a NTH DAO workspace.

Usage:
    python -m nth_dao.cli.status [--workspace .] [--json]

Plain text output:

    NTH DAO workspace status
    ========================
      version:      0.9.4
      workspace:    /path/to/workspace
      generated:    2026-05-31T10:00:00

    Team
    ----
      team:         "alpha" (signed)
      members:      3
      admins:       1
      pending:      0

    Agents
    ------
      alive:        2 / 3 registered
      idle:         1
      busy:         1

    Missions
    --------
      planning:     0
      active:       1
      completed:    5
      failed:       0
      archived:     12

    Templates
    ---------
      total:        2  (deprecated: 0)
      reviews:      7

    Trust
    -----
      anchors:      3
      endorsements: 4 active
      revocations:  0

JSON mode (--json) emits the same info as a single object suitable for
piping to jq or alerting tools.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict


def collect_status(workspace: Path) -> Dict[str, Any]:
    """Build a structured dict describing the workspace's current state.

    Each subsystem is wrapped in try/except so a broken subsystem doesn't
    blank the whole snapshot.
    """
    snapshot: Dict[str, Any] = {
        "generated_at": datetime.now().isoformat(),
        "workspace":    str(workspace.resolve()),
    }
    try:
        from .. import __version__
        snapshot["version"] = __version__
    except Exception:
        snapshot["version"] = "unknown"

    # Team config
    team: Dict[str, Any] = {}
    try:
        from ..membership import MembershipManager
        mm = MembershipManager(workspace)
        cfg = mm.load_config()
        team["team_id"] = cfg.team_id
        team["team_name"] = cfg.team_name
        team["join_policy"] = cfg.join_policy.value
        team["members"] = len(cfg.member_ids)
        team["admins"] = len(cfg.admin_ids)
        team["signed"] = bool(cfg.owner_pubkey)
        team["pending"] = len(mm.list_pending())
    except Exception as e:
        team["error"] = str(e)
    snapshot["team"] = team

    # Agents
    agents: Dict[str, Any] = {"alive": 0, "all": 0, "by_status": {}}
    try:
        from ..discovery import AgentRegistry
        reg = AgentRegistry(agents_dir=str(workspace / "team_agents"))
        all_a = reg.list_all()
        alive = reg.list_alive()
        agents["all"] = len(all_a)
        agents["alive"] = len(alive)
        by_status: Dict[str, int] = {}
        for r in alive:
            by_status[r.status] = by_status.get(r.status, 0) + 1
        agents["by_status"] = by_status
    except Exception as e:
        agents["error"] = str(e)
    snapshot["agents"] = agents

    # Missions + templates + reviews
    missions: Dict[str, Any] = {}
    templates: Dict[str, Any] = {}
    try:
        from ..orchestration import MissionStore
        store = MissionStore(str(workspace / "missions"))
        by_status: Dict[str, int] = {}
        for m in store.list_all():
            by_status[m.status] = by_status.get(m.status, 0) + 1
        missions["by_status"] = by_status
        missions["archived"] = len(store.list_archive())
        # Templates
        all_t = store.templates.list_all(include_deprecated=True)
        templates["total"] = len(all_t)
        templates["deprecated"] = sum(1 for t in all_t if t.deprecated)
        # Reviews count
        reviews_count = 0
        reviews_dir = workspace / "missions" / "reviews"
        if reviews_dir.exists():
            for path in reviews_dir.glob("*.jsonl"):
                try:
                    reviews_count += sum(
                        1 for line in path.read_text(encoding="utf-8").splitlines()
                        if line.strip()
                    )
                except OSError:
                    continue
        templates["reviews"] = reviews_count
    except Exception as e:
        missions["error"] = str(e)
        templates["error"] = str(e)
    snapshot["missions"] = missions
    snapshot["templates"] = templates

    # Trust
    trust: Dict[str, Any] = {}
    try:
        from ..web_of_trust import TrustGraph
        tg = TrustGraph(workspace)
        trust["roots"] = len(tg.roots())
        trust["endorsements_active"] = len(
            tg.list_endorsements(include_expired=False)
        )
        trust["endorsements_all"] = len(
            tg.list_endorsements(include_expired=True)
        )
        trust["revocations"] = len(tg._load_revocations())
    except Exception as e:
        trust["error"] = str(e)
    snapshot["trust"] = trust

    return snapshot


def render_text(snapshot: Dict[str, Any]) -> str:
    """Compact human-readable rendering of the snapshot."""
    out = []
    out.append("NTH DAO workspace status")
    out.append("=" * 60)
    out.append(f"  version:    {snapshot.get('version', '?')}")
    out.append(f"  workspace:  {snapshot.get('workspace', '?')}")
    out.append(f"  generated:  {snapshot.get('generated_at', '?')}")
    out.append("")

    team = snapshot.get("team", {})
    out.append("Team")
    out.append("-" * 60)
    if "error" in team:
        out.append(f"  (error: {team['error']})")
    else:
        signed = " (signed)" if team.get("signed") else ""
        out.append(f"  team:       {team.get('team_name', '?')}{signed}")
        out.append(f"  policy:     {team.get('join_policy', '?')}")
        out.append(f"  members:    {team.get('members', 0)}")
        out.append(f"  admins:     {team.get('admins', 0)}")
        out.append(f"  pending:    {team.get('pending', 0)}")
    out.append("")

    agents = snapshot.get("agents", {})
    out.append("Agents")
    out.append("-" * 60)
    if "error" in agents:
        out.append(f"  (error: {agents['error']})")
    else:
        out.append(f"  alive:      {agents.get('alive', 0)} / {agents.get('all', 0)} registered")
        for status, n in (agents.get("by_status") or {}).items():
            out.append(f"  {status:10s}  {n}")
    out.append("")

    missions = snapshot.get("missions", {})
    out.append("Missions")
    out.append("-" * 60)
    if "error" in missions:
        out.append(f"  (error: {missions['error']})")
    else:
        for status in ("planning", "active", "completed", "failed", "cancelled", "paused"):
            n = (missions.get("by_status") or {}).get(status, 0)
            out.append(f"  {status:10s}  {n}")
        out.append(f"  archived    {missions.get('archived', 0)}")
    out.append("")

    templates = snapshot.get("templates", {})
    out.append("Templates")
    out.append("-" * 60)
    if "error" in templates:
        out.append(f"  (error: {templates['error']})")
    else:
        out.append(f"  total:      {templates.get('total', 0)} "
                   f"(deprecated: {templates.get('deprecated', 0)})")
        out.append(f"  reviews:    {templates.get('reviews', 0)}")
    out.append("")

    trust = snapshot.get("trust", {})
    out.append("Trust")
    out.append("-" * 60)
    if "error" in trust:
        out.append(f"  (error: {trust['error']})")
    else:
        out.append(f"  anchors:        {trust.get('roots', 0)}")
        out.append(f"  endorsements:   {trust.get('endorsements_active', 0)} active "
                   f"({trust.get('endorsements_all', 0)} total)")
        out.append(f"  revocations:    {trust.get('revocations', 0)}")
    out.append("")
    return "\n".join(out)


def main(argv: list = None) -> None:
    parser = argparse.ArgumentParser(
        description="Print a status snapshot of a NTH DAO workspace.",
    )
    parser.add_argument("--workspace", default=".", type=Path,
                        help="NTH DAO workspace directory (default: cwd)")
    parser.add_argument("--json", action="store_true",
                        help="emit JSON instead of text")
    args = parser.parse_args(argv)

    snapshot = collect_status(args.workspace)
    if args.json:
        sys.stdout.write(json.dumps(snapshot, indent=2, ensure_ascii=False))
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_text(snapshot))


if __name__ == "__main__":
    main()
