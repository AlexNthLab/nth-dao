"""
PR 6 Blackboard

3  Agent  sprint

  alice (frontend )    + group:frontend + shared
  bob   (backend )     + group:backend + shared
  carol (PM / shared)    shared


  1.  scope shared/group/private
  2. update
  3. list/get
  4. alice  private:bob
  5. Kanban  (TODO / DOING / DONE / BLOCKED)
  6. BlackboardProvider  system prompt
"""

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
    Scope,
    render_kanban,
    render_table,
)

DEMO_ROOT = new_demo_workspace("blackboard")
BB_ROOT = DEMO_ROOT / "blackboard"


def section(title: str):
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def main():
    prepare_demo_workspace(DEMO_ROOT)
    section("PR 6 Blackboard   Agent ")

    print(f"\n[Setup] isolated workspace: {DEMO_ROOT}")
    bb = Blackboard(BB_ROOT)
    print(f"  Blackboard root: {BB_ROOT}")

    #
    section("[Step 1] 3  Agent ")
    #

    # Carol (PM)  shared
    t1 = bb.post(
        topic="Q2 ship: ",
        author="carol",
        scope="shared",
        content=" sub-task owner ",
        metadata={"priority": "P0", "deadline": "2026-06-15"},
    )
    print(f"  carol  shared: {t1.id} '{t1.topic}'")

    t2 = bb.post(
        topic=" N=50",
        author="carol",
        scope="shared",
        status="doing",
    )
    print(f"  carol  shared: {t2.id} '{t2.topic}' [doing]")

    # Alice (frontend)  group:frontend
    t3 = bb.post(
        topic="Refactor checkout flow",
        author="alice",
        scope="group:frontend",
        status="doing",
        metadata={"branch": "feat/checkout-v2"},
    )
    print(f"  alice  group:frontend: {t3.id} '{t3.topic}' [doing]")

    t4 = bb.post(
        topic="Add Stripe payment elements",
        author="alice",
        scope="group:frontend",
    )
    print(f"  alice  group:frontend: {t4.id} '{t4.topic}'")

    # Bob (backend)  group:backend
    t5 = bb.post(
        topic=" webhook handler",
        author="bob",
        scope="group:backend",
        status="doing",
    )
    print(f"  bob  group:backend: {t5.id} '{t5.topic}' [doing]")

    # Alice  private
    t6 = bb.post(
        topic="CheckoutContext  useReducer  zustand",
        author="alice",
        scope="private:alice",
        content=" zustand",
        status="todo",
    )
    print(f"  alice  private:alice: {t6.id} '{t6.topic}' ()")

    #
    section("[Step 2] update append ")
    #

    bb.update(t2.id, author="carol", status="done", content="N=53,  Pro  17 ")
    print(f"  carol UPDATE {t2.id}  done")

    bb.update(t3.id, author="alice", status="blocked",
              content=" bob  webhook contract", metadata_patch={"blocker": t5.id})
    print(f"  alice UPDATE {t3.id}  blocked (waiting bob)")

    bb.update(t5.id, author="bob", status="done",
              content="webhook schema  #api-design")
    print(f"  bob UPDATE {t5.id}  done")

    bb.update(t3.id, author="alice", status="doing", content="unblocked")
    print(f"  alice UPDATE {t3.id}  doing (now version 3)")

    #
    section("[Step 3] ")
    #

    try:
        bb.post(
            topic=" bob ",
            author="alice",  #  scope  private:bob
            scope="private:bob",
        )
        print("   alice  private:bob")
    except PermissionError as e:
        print(f"   : {e}")

    #
    section("[Step 4] ")
    #

    history = bb.history(t3.id)
    print(f"  {t3.id} 'Refactor checkout flow'  {len(history)} ")
    for v in history:
        print(f"    v{v.version}  [{v.status:7s}]  by {v.author}  @ {v.updated_at[:19]}")
        if v.content:
            print(f"             {v.content[:60]}")

    #
    section("[Step 5] Kanban  ( scope )")
    #

    all_entries = bb.list()
    print(render_kanban(all_entries, width=28))

    #
    section("[Step 6] Kanban  ( shared )")
    #

    shared_only = bb.list(scope=Scope.shared())
    print(render_kanban(shared_only, width=32))

    #
    section("[Step 7]  ( author=alice )")
    #

    alices_tasks = bb.list(author="alice")
    print(render_table(alices_tasks))

    #
    section("[Step 8] BlackboardProvider ")
    #

    print("   alice  Agent  system prompt \n")
    provider = BlackboardProvider(
        agent_id="alice",
        blackboard_root=str(BB_ROOT),
        groups=["frontend"],  # alice  frontend
    )
    provider.initialize({})
    block = provider.prefetch("alice-session-1")
    print(block)

    print()
    print("   bob  group \n")
    provider_bob = BlackboardProvider(
        agent_id="bob",
        blackboard_root=str(BB_ROOT),
        groups=["backend"],
    )
    provider_bob.initialize({})
    print(provider_bob.prefetch("bob-session-1"))

    #
    section("[Step 9] ")
    #

    for f in sorted(BB_ROOT.glob("*.jsonl")):
        lines = sum(1 for _ in f.open(encoding="utf-8"))
        in_git = " Git tracked" if not f.name.startswith("private_") else " Local only"
        print(f"  {f.name:35s}  {lines:3d} entries  {in_git}")

    section(" Blackboard demo ")
    print()
    print("Public API")
    print("  from nth_dao import Blackboard, Scope")
    print("  board = Blackboard('/path/to/workspace/blackboard')")
    print("  rows = board.list(scope=Scope.SHARED)")


if __name__ == "__main__":
    main()
