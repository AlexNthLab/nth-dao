"""
PR 7  Backend

 Agent Team  NTH DAO runtime

  alice-frontend    MockBackend (,  Hermes)
  bob-backend       MockBackend (,  Claude Code)
  carol-codegen     MockBackend ( fail_rate,  Codex)


  1. Backend Registry
  2.  Agent  backend  NTH DAO runtime:
       -  TEAM-SOUL.md ()
       -  Blackboard ()
       -  Ledger ( backend )
  3. carol  Blackboard   alice/bob
  4.  backend carol  N   EvoLoop   fix skill  registry
      alice/bob  VectorProvider
"""

import os
import sys
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # examples/ -> repo root

from examples.demo_workspace import new_demo_workspace, prepare_demo_workspace
from nth_dao import (
    Blackboard,
    BlackboardProvider,
    EvoLoop,
    LedgerProvider,
    SoulProvider,
    TeamAgent,
    TeamMemoryManager,
    UserModelProvider,
    VectorProvider,
    default_registry,
    render_kanban,
)

SOURCE_ROOT = Path(__file__).resolve().parent.parent
REPO = new_demo_workspace("multi-backend")


def section(t):
    print()
    print("=" * 76)
    print(t)
    print("=" * 76)


def make_agent(agent_id: str, groups: list = None) -> TeamAgent:
    """ TeamAgent Provider"""
    providers = [
        SoulProvider(str(SOURCE_ROOT / "skills" / "TEAM-SOUL.md")),
        UserModelProvider(str(REPO / "memory" / "user-model.json")),
        VectorProvider(str(REPO / "skills" / "registry")),
        LedgerProvider(str(REPO / "sidechain" / "ledger.jsonl")),
        BlackboardProvider(
            agent_id=agent_id,
            blackboard_root=str(REPO / "blackboard"),
            groups=groups or [],
        ),
    ]
    mem = TeamMemoryManager(providers, session_id=f"{agent_id}_session")
    mem.initialize({"agent_id": agent_id})
    return TeamAgent(agent_id=agent_id, team_memory_manager=mem, compression_threshold=0.75)


def main():
    prepare_demo_workspace(REPO)
    os.chdir(REPO)
    section("PR 7  Backend ")
    print("3  Agent  backend NTH DAO runtime")

    section(f"[Step 0] isolated workspace: {REPO}")
    bb = Blackboard(REPO / "blackboard")

    section("[Step 1] Backend ")
    desc = default_registry.describe(refresh=True)
    avail = []
    unavail = []
    for bid, info in desc.items():
        if info["available"]:
            avail.append(bid)
            print(f"   {bid:15s} ready")
        else:
            unavail.append(bid)
            print(f"   {bid:15s} unavailable")
    print(f"\n  ({len(avail)} available, {len(unavail)} unavailable in current env)")
    print("   demo  MockBackend ( backend)")

    section("[Step 2] PM (carol)  shared ")
    t1 = bb.post(
        topic="",
        author="carol",
        scope="shared",
        content="React  + Express OAuth2",
        metadata={"assignee": "alice"},
    )
    t2 = bb.post(
        topic=" OAuth callback handler",
        author="carol",
        scope="shared",
        metadata={"assignee": "bob"},
    )
    t3 = bb.post(
        topic="",
        author="carol",
        scope="shared",
        metadata={"assignee": "carol"},  # carol
    )
    print(f"   Posted: {t1.id}  assignee=alice")
    print(f"   Posted: {t2.id}  assignee=bob")
    print(f"   Posted: {t3.id}  assignee=carol")

    section("[Step 3] alice  MockBackend ( Hermes) ")
    alice = make_agent("alice", groups=["dev"])
    alice_backend = default_registry.create("mock", latency_ms=5)
    bb.update(t1.id, author="alice", status="doing")
    result = alice.run_with_backend(
        alice_backend,
        goal="implement login page",
        max_turns=2,
    )
    bb.update(t1.id, author="alice", status="done",
              content=f"completed in {result['session_summary'].total_turns} turns")

    section("[Step 4] bob  MockBackend ( Claude Code) ")
    bob = make_agent("bob", groups=["dev"])
    bob_backend = default_registry.create("mock", latency_ms=10)
    bb.update(t2.id, author="bob", status="doing")
    bob.run_with_backend(
        bob_backend,
        goal="design oauth callback handler",
        max_turns=2,
    )
    bb.update(t2.id, author="bob", status="done")

    section("[Step 5] carol  fail-prone MockBackend ( Codex )")
    print("   carol  4  session   ROI  EvoLoop")
    carol = make_agent("carol")
    carol_backend = default_registry.create("mock", latency_ms=2)
    bb.update(t3.id, author="carol", status="doing")

    #  4  session 'fail'
    for attempt in range(4):
        result = carol.run_with_backend(
            carol_backend,
            goal=f"please fail this codegen (attempt {attempt+1})",
            max_turns=1,
            per_turn_prompt=lambda i, a: "please fail this codegen task (large token waste)",
            error_sig_fn=lambda r: "carol_mock_error",
        )
        #  token cost  EvoLoop  6000t
        carol.team_mem.providers["LedgerProvider"].record(
            agent_id="carol",
            action_type="backend:mock",
            result="failed codegen",
            error_sig="carol_mock_error",
            token_cost=6000,
        )
    # buffer  ledger.jsonl
    carol.team_mem.providers["LedgerProvider"].on_session_end()

    bb.update(t3.id, author="carol", status="blocked", content="error rate too high, retry needed")

    section("[Step 6]  Ledger ")
    ledger_path = REPO / "sidechain" / "ledger.jsonl"
    ledger = LedgerProvider(str(ledger_path))
    ledger.initialize({})
    if ledger_path.exists():
        entries = sum(1 for line in ledger_path.open(encoding="utf-8") if line.strip())
        print(f"  Total ledger entries:    {entries}")
    print(f"  carol_mock_error count:  {ledger.count_error_occurrences('carol_mock_error')}")
    print(f"  carol_mock_error wasted: {ledger.sum_token_cost_by_sig('carol_mock_error')} tokens")
    print("  EVOLUTION_BUDGET:        15000  (threshold = 22500t)")

    section("[Step 7] EvoLoop  backend ")
    print("  Trigger: count >= 3 AND wasted > budget * 1.5")
    loop = EvoLoop(ledger=ledger)
    results = loop.run_once()
    for r in results:
        print(f"   {r.summary()}")
    if not results:
        print("   no signatures crossed threshold this round")

    section("[Step 8] Kanban    scope")
    all_entries = bb.list()
    print(render_kanban(all_entries, width=30))

    section("[Step 9] alice  carol  skill")
    new_alice_vp = VectorProvider(str(REPO / "skills" / "registry"))
    new_alice_vp.initialize({})
    fix_skills = [s for s in new_alice_vp.skill_index if "carol" in s["name"].lower()]
    if fix_skills:
        print(f"   {len(fix_skills)} new fix skill(s) available to ALL future agents:")
        for s in fix_skills:
            print(f"    - {s['name']}: {s['desc'][:70]}")
    else:
        print("  (no auto-merged fix skill yet  EvoLoop may have routed to pending_review)")
        pending_dir = REPO / "sidechain" / "pending_patches"
        if pending_dir.exists():
            for p in pending_dir.glob("*.json"):
                print(f"    PENDING: {p.name}")

    section("[Step 10] ")
    for label, path in [
        ("Ledger (cross-backend)",  REPO / "sidechain" / "ledger.jsonl"),
        ("Blackboard (shared)",     REPO / "blackboard" / "shared.jsonl"),
        ("Evolution audit",         REPO / "sidechain" / "evolution_audit.jsonl"),
    ]:
        if path.exists():
            lines = sum(1 for _ in path.open(encoding="utf-8"))
            print(f"   {label:30s} {path.relative_to(REPO)}  ({lines} lines)")

    section(" PR 7 multi-backend demo ")
    print()
    print("")
    print("  1. 6  backend  Registry ")
    print("  2. 3  Agent  backend Soul / Blackboard / Ledger")
    print("  3.  backend   EvoLoop    backend ")
    print()
    print("")
    print("  python team_entrypoint.py --backend hermes --goal '...' --auto-evolve")
    print("  python team_entrypoint.py --backend claude_code --goal '...' --auto-evolve")
    print("  python team_entrypoint.py --backend openhands --goal '...' --auto-evolve")
    print("    backend ")


if __name__ == "__main__":
    main()
