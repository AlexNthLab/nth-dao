"""
PR 5


  - alice-laptop / bob-desktop TeamAgent
  -  4  timeout_database  ledger
  -  LogCollector  logs/ push
  -  CentralAggregator.run()    EvoLoop
  -
       logs/  2
       sidechain/aggregated_ledger.jsonl  8
       EvoLoop   fix_timeout_database AUTO_MERGE
       sidechain/aggregate_report.md  PR
       sync_audit.jsonl
"""

import sys
from pathlib import Path

# Windows UTF-8
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # examples/ -> repo root

from examples.demo_workspace import new_demo_workspace, prepare_demo_workspace
from nth_dao import (
    CentralAggregator,
    LedgerProvider,
    LogCollector,
    SkillLoader,
    SyncConfig,
)


REPO_ROOT = new_demo_workspace("sync")


def simulate_terminal(hostname: str, username: str, agent_id: str, error_count: int):
    """ + collect"""
    print(f"\n--- : {hostname}/{username} (agent: {agent_id}) ---")

    #  hostname/username  config
    cfg = SyncConfig(
        repo_root=REPO_ROOT,
        hostname=hostname,
        username=username,
        sidechain_dir=f"sidechain/{hostname}",
        ledger_path=f"sidechain/{hostname}/ledger.jsonl",
        sync_audit_path=f"sidechain/{hostname}/sync_audit.jsonl",
        reload_signal_path=f"sidechain/{hostname}/reload.signal",
        auto_push=False,  # demo
    )

    # 1.  ledger
    ledger = LedgerProvider(str(cfg.ledger_full_path()))
    ledger.initialize({})
    for i in range(error_count):
        ledger.record(
            agent_id=agent_id,
            action_type="db_query",
            result=f"Connection timeout from {hostname} (attempt {i+1})",
            error_sig="timeout_database",
            token_cost=6000,
        )
    ledger.on_session_end()
    print(f"  Wrote {error_count} ledger entries")

    # 2. Collect
    collector = LogCollector(cfg)
    result = collector.collect(auto_push=False)
    print(f"  {result}")

def show_logs_dir():
    """ logs/ """
    logs_dir = REPO_ROOT / "logs"
    if not logs_dir.exists():
        print("   logs/ ")
        return
    files = sorted(logs_dir.glob("*.jsonl"))
    print(f"\n logs/  {len(files)} :")
    for f in files:
        size = f.stat().st_size
        lines = sum(1 for _ in f.open(encoding="utf-8")) if size > 0 else 0
        print(f"  - {f.name} ({size} bytes, {lines} entries)")


def show_aggregate_outputs():
    """"""
    print()
    print("=" * 70)
    print("[Step 4] ")
    print("=" * 70)

    artifacts = [
        ("Aggregated ledger", REPO_ROOT / "sidechain" / "aggregated_ledger.jsonl"),
        ("PR Report (Markdown)", REPO_ROOT / "sidechain" / "aggregate_report.md"),
        ("Auto-merged skill", REPO_ROOT / "skills" / "registry" / "fix_timeout_database.md"),
        ("Evolution audit", REPO_ROOT / "sidechain" / "evolution_audit.jsonl"),
        ("Sync audit", REPO_ROOT / "sidechain" / "sync_audit.jsonl"),
    ]
    for label, path in artifacts:
        if path.exists():
            print(f"   {label}: {path.relative_to(REPO_ROOT)} ({path.stat().st_size} bytes)")
        else:
            print(f"   {label}: MISSING")


def show_report_preview():
    """ PR  30 """
    report = REPO_ROOT / "sidechain" / "aggregate_report.md"
    if not report.exists():
        return
    print()
    print("=" * 70)
    print("[Step 5] PR  (sidechain/aggregate_report.md)")
    print("=" * 70)
    content = report.read_text(encoding="utf-8")
    for line in content.split("\n")[:30]:
        print(f"  {line}")


def main():
    prepare_demo_workspace(REPO_ROOT)
    print("=" * 70)
    print("PR 5   ")
    print("=" * 70)

    print(f"\n[Step 0] isolated workspace: {REPO_ROOT}")

    print("\n[Step 1]  + collect")
    simulate_terminal("alice-laptop", "alice", "worker-alice", error_count=4)
    simulate_terminal("bob-desktop", "bob", "worker-bob", error_count=4)

    print("\n[Step 2] ")
    show_logs_dir()

    print("\n[Step 3]    +  EvoLoop")
    cfg = SyncConfig(repo_root=REPO_ROOT)
    aggregator = CentralAggregator(cfg, noise_min_count=2)
    report = aggregator.run(trigger_evolution=True)

    print("\n  Report summary:")
    print(f"    total_entries     = {report.total_entries}")
    print(f"    unique_hosts      = {report.unique_hosts}")
    print(f"    error_sigs        = {report.error_sigs}")
    print(f"    evolved_sigs      = {report.evolved_sigs}")
    print(f"    auto_merged       = {report.auto_merged}")
    print(f"    pending_review    = {report.pending_review}")

    show_aggregate_outputs()
    show_report_preview()

    print("\n[Step 6] SkillLoader ")
    loader = SkillLoader(cfg)
    print(f"  Loader reload paths: {loader.reload_paths}")
    print(f"  Signal mechanism: {'pkill -HUP' if sys.platform != 'win32' else 'signal-file'}")
    print("  (Skipped actual reload to avoid touching working tree)")

    print()
    print("=" * 70)
    print(" PR 5 sync demo complete")
    print("=" * 70)
    print()
    print("In production:")
    print("  - LogCollector runs hourly on each terminal (cron/systemd)")
    print("  - CentralAggregator runs daily via GitHub Action")
    print("     .github/workflows/team-evolve-daily.yml")
    print("  - SkillLoader runs after team merges Evolution PR")
    print("     atomic checkout + reload signal")


if __name__ == "__main__":
    main()
