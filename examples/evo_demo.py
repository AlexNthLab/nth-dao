"""
EvoLoop


1.  4  timeout_database  cost 6000t 24000t > 15000 * 1.5
2.  2  lint_violation count>=3
3.  4  destructive_drop_table PENDING_REVIEW
4.  EvoLoop.run_once()
   - timeout_database   AUTO_MERGE (low risk)
   - lint_violation     count
   - destructive_drop   PENDING_REVIEW (high risk)
"""

import os
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
from nth_dao import EvoLoop, EvoTrigger, LedgerProvider


DEMO_ROOT = new_demo_workspace("evolution")


def seed_ledger(ledger: LedgerProvider):
    """"""
    # 1. timeout_database  4   6000t = 24000t > 22500 (15000*1.5)
    for i in range(4):
        ledger.record(
            agent_id="worker-1",
            action_type="db_query",
            result=f"Connection timeout after 30s (attempt {i+1})",
            error_sig="timeout_database",
            token_cost=6000,
        )

    # 2. lint_violation   2  count>=3
    for i in range(2):
        ledger.record(
            agent_id="worker-2",
            action_type="lint_check",
            result=f"E501 line too long (file{i}.py)",
            error_sig="lint_violation",
            token_cost=200,
        )

    # 3. destructive_drop_table  4   6000t
    for i in range(4):
        ledger.record(
            agent_id="worker-3",
            action_type="db_admin",
            result=f"DROP TABLE attempted on prod.users (request {i+1})",
            error_sig="destructive_drop_table",
            token_cost=6000,
        )

    #
    ledger.on_session_end()


def main():
    prepare_demo_workspace(DEMO_ROOT)
    os.chdir(DEMO_ROOT)
    print("=" * 70)
    print("EvoLoop   PR 4")
    print("=" * 70)

    print(f"\n[Step 0] isolated workspace: {DEMO_ROOT}")

    print("\n[Step 1]  Ledger ...")
    ledger = LedgerProvider("sidechain/ledger.jsonl")
    ledger.initialize({})
    seed_ledger(ledger)
    print("  Total entries written: 4 + 2 + 4 = 10")

    print("\n[Step 2]  Trigger ...")
    trigger = EvoTrigger(ledger, evolution_budget=15000)
    print(f"  Budget = {trigger.evolution_budget}, Threshold = {int(trigger.waste_threshold)}t")
    for sig in ("timeout_database", "lint_violation", "destructive_drop_table"):
        d = trigger.check(sig)
        marker = "" if d.should_evolve else ""
        print(f"  {marker} {d}")

    print("\n[Step 3]  EvoLoop.run_once()...")
    loop = EvoLoop(ledger=ledger, trigger=trigger)
    results = loop.run_once()

    print(f"\n[Step 4] {len(results)} \n")
    for i, result in enumerate(results, 1):
        print(f"--- Cycle {i} ---")
        print(result.summary())
        print()

    print("=" * 70)
    print("[Step 5] ")
    print("=" * 70)

    auto_merged = Path("skills/registry/fix_timeout_database.md")
    pending = Path("sidechain/pending_patches/fix_destructive_drop_table.patch.json")
    audit = Path("sidechain/evolution_audit.jsonl")

    print(f"\n[AUTO_MERGE] {auto_merged}")
    if auto_merged.exists():
        print(f"   Exists ({auto_merged.stat().st_size} bytes)")
        print("  Preview (first 5 lines):")
        for line in auto_merged.read_text(encoding="utf-8").split("\n")[:5]:
            print(f"    {line}")
    else:
        print("   NOT FOUND")

    print(f"\n[PENDING_REVIEW] {pending}")
    if pending.exists():
        print(f"   Exists ({pending.stat().st_size} bytes)")
    else:
        print("   NOT FOUND")

    print(f"\n[AUDIT LOG] {audit}")
    if audit.exists():
        lines = audit.read_text(encoding="utf-8").strip().split("\n")
        print(f"   {len(lines)} audit entries")
        for line in lines:
            import json
            entry = json.loads(line)
            print(f"    - {entry['action'].upper()}: {entry['skill_id']} ({entry['reason']})")
    else:
        print("   NOT FOUND")

    print("\n" + "=" * 70)
    print(" EvoLoop demo complete")
    print("=" * 70)


if __name__ == "__main__":
    main()
