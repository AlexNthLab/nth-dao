"""
 demo  Hermes Team  + LLM

 DeepSeek (via Hermes backend)
       (team_layer/backends/hermes.py)  3


  attach()                        Hermes Team

  team.start_mission(...)        3-step Mission  missions/

  team.runner.find_work()        MissionRunner  step

  team.runner.claim(step)         active +

  team.agent.run_with_backend(   Backend-driven
      backend=team.backend,
      goal=...                    prompt  DeepSeek
  )

  HermesBackend.send_turn        subprocess hermes chat

  hermes  ~/.hermes/.env        OPENROUTER_API_KEY

  openai SDK  DeepSeek API

  TurnResponse + Ledger

  team.runner.complete/fail()    Mission

  team.detach()                   +


  - team_agents/alice-coder.json
  - missions/<id>.json             Mission
  - sidechain/ledger.jsonl          turn
  - sidechain/evolution_audit.jsonl
"""

import json
import sys
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import nth_dao as nth
from examples.demo_workspace import new_demo_workspace, prepare_demo_workspace

SOURCE_ROOT = Path(__file__).resolve().parent.parent
REPO = new_demo_workspace("real-world")


def section(t):
    print()
    print("=" * 76)
    print(t)
    print("=" * 76)


def main():
    prepare_demo_workspace(REPO)
    section("Hermes Team   demo")
    print(" LLM  team_layer/backends/hermes.py 3 ")
    print("Backend: hermes + DeepSeek")
    print()

    #
    section("[Step 1] attach()   Hermes Team agent")
    #
    team = nth.attach(
        agent_id="alice-coder",
        backend="hermes",
        backend_kwargs={
            "model": "deepseek-chat",
            # hermes_args  ["--max-turns", "1"]  tool iters
        },
        capabilities=["python", "code-review", "refactor"],
        groups=["dev"],
        workspace=REPO,
        start_heartbeat=False,  # demo
    )
    print(f"   Agent attached: {team.agent_id}")
    print(f"    backend_id:   {team.backend_id}")
    print(f"    backend cls:  {type(team.backend).__name__ if team.backend else 'none'}")
    print(f"    capabilities: {team.capabilities}")
    print(f"    workspace:    {team.workspace}")
    print(f"    :     team_agents/{team.agent_id}.json")

    #
    section("[Step 2] discover()  ")
    #
    online = team.discover()
    print(f"   ({len(online)} ):")
    for r in online:
        print(f"    {r.short()}")

    #
    section("[Step 3] start_mission()   step ")
    #
    mission = team.start_mission(
        title=" hermes.py ",
        goal=" team_layer/backends/hermes.py 3 ",
        scope="shared",
        priority="normal",
        steps=[
            {
                "id": "read-file",
                "description": " team_layer/backends/hermes.py send_turn",
                "required_capabilities": ["python"],
            },
            {
                "id": "review",
                "description": " +  3 ' N: ...'",
                "required_capabilities": ["code-review"],
                "depends_on": ["read-file"],
            },
        ],
    )
    print(f"   Mission created: {mission.id}")
    print(f"    title:  {mission.title}")
    print(f"    steps:  {[s.id for s in mission.steps]}")

    #
    section("[Step 4]  step LLM")
    #
    work = team.runner.find_work()
    if not work:
        print("  [WARN] no actionable step")
        return
    m, s = work
    print(f"   find_work()  step '{s.id}': {s.description}")
    team.runner.claim(mission.id, s.id)

    #
    code_path = SOURCE_ROOT / "team_layer" / "backends" / "hermes.py"
    code = code_path.read_text(encoding="utf-8")
    snippet = code[code.find("def send_turn"):][:2200]  #  2.2KB
    print(f"   Read {code_path.name} ({len(code)} bytes total, snippet {len(snippet)} chars)")
    team.runner.complete(
        mission.id, s.id,
        output={"snippet_len": len(snippet)},
        note=f"loaded {code_path.relative_to(SOURCE_ROOT)}",
    )

    #
    section("[Step 5]  LLM  DeepSeek ")
    #
    work = team.runner.find_work()
    if not work:
        print("  [WARN] no review step")
        return
    m, review_step = work
    print(f"   find_work()  step '{review_step.id}'")
    team.runner.claim(mission.id, review_step.id)

    prompt = f"""You are a senior Python reviewer. Read this code from
team_layer/backends/hermes.py and give exactly 3 concrete improvement
suggestions, numbered "Suggestion 1: ...", "Suggestion 2: ...", "Suggestion 3: ...".

Focus on: robustness, error handling, Windows compatibility, security.
Be specific (line of code or pattern). Don't generic-praise.

```python
{snippet}
```"""

    print(f"   Prompt length: {len(prompt)} chars")
    print("   Calling DeepSeek via Hermes backend...")
    print()

    #  turn   team.agent.run_with_backend
    result = team.agent.run_with_backend(
        backend=team.backend,
        goal=prompt,
        max_turns=1,
    )

    #
    section("[Step 6] LLM ")
    #
    summary = result["session_summary"]
    turn = result["turns"][0] if result["turns"] else None

    print("  Backend session summary:")
    print(f"    total_turns:    {summary.total_turns}")
    print(f"    total_tokens:   {summary.total_usage.total}")
    print(f"    duration:       {summary.duration_seconds:.2f}s")
    print(f"    final_status:   {summary.final_status}")

    if turn:
        print("\n  Turn 1:")
        print(f"    finish_reason: {turn['finish_reason']}")
        print(f"    tokens:        {turn['tokens']}")
        print(f"    latency:       {turn['latency']:.2f}s")
        if turn['error']:
            print(f"    error:         {turn['error'][:120]}")
        if turn['response_content']:
            print("\n   LLM response (first 800 chars) ")
            for line in turn['response_content'][:800].split("\n"):
                print(f"   {line}")
            print("  ")

    #  step
    if turn and turn['finish_reason'] == 'stop' and turn['response_content']:
        team.runner.complete(
            mission.id, review_step.id,
            output={"response_excerpt": turn['response_content'][:200]},
            note="LLM ",
        )
    else:
        team.runner.fail(
            mission.id, review_step.id,
            reason=turn['error'] if turn else "no response",
        )

    #
    section("[Step 7] Mission + Ledger + ")
    #
    final = team.mission_store.get(mission.id)
    p = final.progress()
    print(f"  Mission status: {final.status}  ({p['done']}/{p['total']} done, {p['failed']} failed)")
    print("\n  Step trail:")
    for s in final.steps:
        print(f"    [{s.status:9s}] {s.id:12s} assignee={s.assignee}")
        for n in s.notes[-2:]:
            print(f"       {n[:120]}")

    print()
    print("  Ledger entries (in-memory + buffer):")
    #  flush buffer LedgerProvider  batch
    ledger_provider = team.memory.providers["LedgerProvider"]
    #  buffer  on_session_end
    if hasattr(ledger_provider, 'buffer') and ledger_provider.buffer:
        for entry in ledger_provider.buffer:
            sig = entry.get('error_sig') or 'success'
            print(f"    [{sig:25s}] cost={entry.get('token_cost', 0):5d}t  "
                  f"action={entry.get('action_type', '?')[:30]}")
    else:
        #  flush
        ledger_path = REPO / "sidechain" / "ledger.jsonl"
        if ledger_path.exists():
            for line in ledger_path.read_text(encoding="utf-8").strip().split("\n"):
                if not line.strip():
                    continue
                entry = json.loads(line)
                sig = entry.get('error_sig') or 'success'
                print(f"    [{sig:25s}] cost={entry.get('token_cost', 0):5d}t  "
                      f"action={entry.get('action_type', '?')[:30]}")
        else:
            print("    (still in buffer  will flush on detach)")

    #
    section("[Step 8] EvoLoop   ")
    #
    from nth_dao import EvoLoop
    evo = EvoLoop(ledger=team.memory.providers["LedgerProvider"])
    results = evo.run_once()
    if results:
        print(f"   Triggered! {len(results)} evolution(s):")
        for r in results:
            print(f"    {r.summary()}")
    else:
        print("   Not triggered yet (need count3 AND wasted>budget*1.5)")
        print("      EvoLoop ")

    #
    section("[Step 9] detach()  ")
    #
    team.detach()
    print(f"   {team.agent_id} detached")
    print("   heartbeat file  offline")
    print("   memory/user-model.json ")

    section(" Real-world demo complete")
    print()
    print("")
    print("  1. attach()  hermes team ")
    print("  2. Discovery + Mission +  ")
    print("  3. Hermes backend  DeepSeek API")
    print("  4. LedgerProvider  turn  cost/error")
    print("  5. EvoLoop  ROI ")
    print()
    print(" key :")
    print("  - turn[0]['finish_reason'] == 'stop'")
    print("  - turn[0]['response_content'] == LLM  3 ")
    print("  - Mission status == 'completed'")


if __name__ == "__main__":
    main()
