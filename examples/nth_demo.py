"""
PR 8 NTH DAO

3  Agent  nth.attach()  Mission

  alice-frontend    capabilities=["python", "frontend", "react"]
  bob-backend       capabilities=["python", "backend", "api"]
  carol-qa          capabilities=["python", "testing"]

Mission v23  step
  step 1: design API             backend
  step 2: implement frontend     frontend step 1
  step 3: e2e tests              testing step 1 + 2


  1.  Agent attach()
  2. PeerFinder  capability
  3. MissionRunner.find_work()  capability  +
  4. alice  step 1  bob  step 2   claim
  5. carol    step 3  done
  6. Mission planning  active  completed
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

import nth_dao as nth
from examples.demo_workspace import new_demo_workspace, prepare_demo_workspace

REPO = new_demo_workspace("orchestration")


def section(t):
    print()
    print("=" * 76)
    print(t)
    print("=" * 76)


def main():
    prepare_demo_workspace(REPO)
    section("PR 8 NTH DAO  Discovery + Mission Orchestration")
    print("3  Agent  attach()      Mission")

    section(f"[Setup] isolated workspace: {REPO}")

    #
    section("[Step 1] alice attach()   + ")
    #
    alice = nth.attach(
        agent_id="alice-frontend",
        backend="mock",
        capabilities=["python", "frontend", "react"],
        groups=["payments"],
        workspace=REPO,
        start_heartbeat=False,  # demo  detach
    )
    print(f"   alice registered: {alice.agent_id}")
    print(f"    backend={alice.backend_id}, caps={alice.capabilities}, groups={alice.groups}")

    #
    section("[Step 2] alice  Mission")
    #
    mission = alice.start_mission(
        title=" v2",
        goal="API    ",
        scope="shared",
        priority="high",
        steps=[
            {
                "id": "design-api",
                "description": " webhook + REST API contract",
                "required_capabilities": ["backend", "api"],
            },
            {
                "id": "impl-frontend",
                "description": " React Checkout ",
                "required_capabilities": ["frontend", "react"],
                "depends_on": ["design-api"],
            },
            {
                "id": "e2e-tests",
                "description": "Playwright E2E ",
                "required_capabilities": ["testing"],
                "depends_on": ["design-api", "impl-frontend"],
            },
        ],
    )
    print(f"   Mission created: {mission.id} '{mission.title}'")
    print(f"    Steps: {[s.id for s in mission.steps]}")
    print()
    print(f"    {mission.short()}")

    #
    section("[Step 3] bob attach()   team")
    #
    bob = nth.attach(
        agent_id="bob-backend",
        backend="mock",
        capabilities=["python", "backend", "api"],
        groups=["payments"],
        workspace=REPO,
        start_heartbeat=False,
    )
    print(f"   bob registered: {bob.agent_id}")
    print()
    print("  bob.discover() ():")
    for r in bob.discover():
        print(f"    {r.short()}")

    #
    section("[Step 4] bob  backend    alice alice  frontend")
    #
    teammate = bob.find_teammate(needed_capabilities=["backend"], )
    if teammate and teammate.record.agent_id != bob.agent_id:
        print(f"   matched: {teammate.record.agent_id} (score={teammate.score})")
    else:
        print("   no other 'backend' agent  bob is the only one (himself excluded)")

    # bob  step
    bob_work = bob.runner.find_work()
    if bob_work:
        m, s = bob_work
        print(f"   bob.find_work()  Mission '{m.title}' step '{s.id}': {s.description}")
        print(f"    required={s.required_capabilities}, bob has {bob.capabilities} ")

    #
    section("[Step 5] bob claim +  step 'design-api'")
    #
    bob.runner.claim(mission.id, "design-api")
    print("   bob claimed 'design-api'  status=active")

    #  backend
    response = bob.backend.send_turn(
        "Design payment webhook & REST API",
        system_prompt=bob.memory.build_memory_context_block(),
    ) if bob.backend else None
    if response:
        print(f"    [mock backend response] {response.content[:80]}")

    bob.runner.complete(
        mission.id, "design-api",
        output={"api_spec": "POST /webhooks/payment, GET /api/orders/:id"},
        note="API contract draft posted to blackboard",
    )
    print("   bob completed 'design-api'")

    #
    section("[Step 6] alice    step 2 ")
    #
    alice_work = alice.runner.find_work()
    if alice_work:
        m, s = alice_work
        print(f"   alice.find_work()  '{s.id}': {s.description}")
        print(f"    required={s.required_capabilities}, alice has {alice.capabilities} ")

        alice.runner.claim(mission.id, s.id)
        print(f"   alice claimed '{s.id}'")
        alice.runner.complete(
            mission.id, s.id,
            output={"component": "CheckoutForm.tsx"},
            note="React component shipped to feat/checkout-v2",
        )
        print(f"   alice completed '{s.id}'")

    #
    section("[Step 7] carol attach()  e2e-tests ")
    #
    carol = nth.attach(
        agent_id="carol-qa",
        backend="mock",
        capabilities=["python", "testing"],
        groups=["payments"],
        workspace=REPO,
        start_heartbeat=False,
    )
    print(f"   carol registered: {carol.agent_id}")

    print("\n  discover:")
    for r in carol.discover():
        print(f"    {r.short()}")

    carol_work = carol.runner.find_work()
    if carol_work:
        m, s = carol_work
        print(f"\n   carol.find_work()  '{s.id}': {s.description}")
        carol.runner.claim(mission.id, s.id)
        carol.runner.complete(
            mission.id, s.id,
            output={"test_count": 12, "coverage": "94%"},
            note="all green on playwright",
        )
        print(f"   carol completed '{s.id}'")

    #
    section("[Step 8] Mission  completed  ")
    #
    final = alice.mission_store.get(mission.id)
    p = final.progress()
    print(f"  Mission: {final.short()}")
    print(f"  Status:  {final.status}")
    print(f"  Done:    {p['done']}/{p['total']} ({p['percent']}%)")
    print()
    print("  ")
    for s in final.steps:
        assignees = "  ".join(s.previous_assignees + [s.assignee or "?"])
        print(f"    {s.id:18s} [{s.status:9s}]  by  {assignees}")
        for note in s.notes[-2:]:
            print(f"       {note}")

    #
    section("[Step 9]   missions/*.json ")
    #
    mfile = REPO / "missions" / f"{mission.id}.json"
    if mfile.exists():
        size = mfile.stat().st_size
        print(f"   {mfile.relative_to(REPO)}  ({size} bytes, will be git-synced)")

    afiles = list((REPO / "team_agents").glob("*.json"))
    print(f"\n  team_agents/  ({len(afiles)} )")
    for f in sorted(afiles):
        print(f"    - {f.name}")

    #
    section("[Step 10]  detach")
    #
    for s in (alice, bob, carol):
        s.detach()
        print(f"   {s.agent_id} detached")

    section(" PR 8 nth-dao demo ")
    print()
    print("")
    print("  import nth_dao as nth")
    print("  team = nth.attach(agent_id='...', backend='hermes', capabilities=[...])")
    print("  #  Agent ")
    print("  team.detach()")
    print()
    print(" workspace/  Git  +  PR 5 git_sync")
    print("  attach() ")


if __name__ == "__main__":
    main()
