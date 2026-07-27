"""
PR 1-5


    1. []  reload.signal   + reload SoulProvider
    2. [Agent ] 4  Provider  fence  system prompt
    3. []  12   context > 60%  Snip
    4. []  4  timeout  ledger   EvoLoop
    5. [] auto-collect  team_logs/ + auto-evolve  AUTO_MERGE skill

 push--no-push
"""

import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

SOURCE_ROOT = Path(__file__).resolve().parent.parent
# Make sibling team_layer/nth_dao packages importable when run directly
# (`python examples/integration_demo.py` from the repo root).
sys.path.insert(0, str(SOURCE_ROOT))

from examples.demo_workspace import (  # noqa: E402
    new_demo_workspace,
    prepare_demo_workspace,
)


REPO = new_demo_workspace("integration")


def section(title: str):
    print()
    print("=" * 70)
    print(title)
    print("=" * 70)


def plant_reload_signal():
    """ reload PR 5  PR 1+2 """
    signal_path = REPO / "sidechain" / "reload.signal"
    payload = {
        "requested_at": datetime.now().isoformat(),
        "hostname": "demo-host",
        "username": "demo-user",
        "reload_paths": ["skills/", "memory/auto-memory.md"],
    }
    signal_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    print(f"  Planted reload.signal: {payload['hostname']}/{payload['username']}")


def seed_failure_logs():
    """ 4  timeout_database PR 4 EvoLoop """
    from nth_dao import LedgerProvider
    ledger = LedgerProvider(str(REPO / "sidechain" / "ledger.jsonl"))
    ledger.initialize({})
    for i in range(4):
        ledger.record(
            agent_id="integration-test",
            action_type="db_query",
            result=f"Connection timeout (#{i+1})",
            error_sig="timeout_database",
            token_cost=6000,  # 4*6000=24000 > 15000*1.5=22500
        )
    ledger.on_session_end()
    print("  Seeded 4 timeout_database entries (24000t total, threshold 22500t)")


def run_entrypoint(args: list) -> int:
    """ team_entrypoint.py """
    print(f"  Command: python team_entrypoint.py {' '.join(args)}\n")
    proc = subprocess.run(
        [sys.executable, str(SOURCE_ROOT / "team_entrypoint.py"), *args],
        cwd=str(REPO),
        env={
            **__import__("os").environ,
            "PYTHONIOENCODING": "utf-8",
            "PYTHONPATH": str(SOURCE_ROOT),
        },
        capture_output=True,
        text=True,
        encoding="utf-8",       # Windows  GBK UTF-8
        errors="replace",       #
        timeout=120,
    )
    #
    for line in (proc.stdout or "").split("\n"):
        if line.strip():
            print(f"   {line}")
    if proc.returncode != 0:
        print("  STDERR:")
        for line in (proc.stderr or "").split("\n")[:20]:
            if line.strip():
                print(f"   {line}")
    return proc.returncode


def verify_artifacts():
    """ PR """
    checks = [
        ("PR 2: user model persisted",       REPO / "memory" / "user-model.json"),
        ("PR 5: signal consumed (no longer exists)", REPO / "sidechain" / "reload.signal", "absent"),
        ("PR 5: collected log in team_logs/", REPO / "team_logs", "has_jsonl"),
        ("PR 5: sync_audit logged",          REPO / "sidechain" / "sync_audit.jsonl"),
        ("PR 4: EvoLoop produced skill",     REPO / "skills" / "registry" / "fix_timeout_database.md"),
        ("PR 4: evolution_audit logged",     REPO / "sidechain" / "evolution_audit.jsonl"),
    ]
    for entry in checks:
        if len(entry) == 3 and entry[2] == "absent":
            label, path, _ = entry
            ok = not path.exists()
            print(f"  {'' if ok else ''} {label}")
        elif len(entry) == 3 and entry[2] == "has_jsonl":
            label, path, _ = entry
            files = list(path.glob("*.jsonl")) if path.exists() else []
            ok = len(files) > 0
            print(f"  {'' if ok else ''} {label}  ({len(files)} files)")
            for f in files[:2]:
                print(f"       - {f.name}")
        else:
            label, path = entry
            ok = path.exists()
            size = path.stat().st_size if ok else 0
            print(f"  {'' if ok else ''} {label}  ({size} bytes)")


def show_audit_excerpt():
    """ sync_audit + evolution_audit """
    print()
    print("[sync_audit.jsonl ]")
    sync = REPO / "sidechain" / "sync_audit.jsonl"
    if sync.exists():
        for line in sync.read_text(encoding="utf-8").strip().split("\n"):
            if line.strip():
                entry = json.loads(line)
                print(f"  {entry['action']:20s} entries={entry.get('entries', '-')}  "
                      f"committed={entry.get('committed', '-')}  "
                      f"pushed={entry.get('pushed', '-')}")

    print()
    print("[evolution_audit.jsonl ]")
    evo = REPO / "sidechain" / "evolution_audit.jsonl"
    if evo.exists():
        for line in evo.read_text(encoding="utf-8").strip().split("\n"):
            if line.strip():
                entry = json.loads(line)
                print(f"  {entry['action']:15s} {entry['skill_id']:32s} "
                      f"risk={entry['risk_level']}  verify={entry['verify_passed']}")


def main():
    prepare_demo_workspace(REPO)
    (REPO / "team_logs").mkdir()
    (REPO / "sidechain").mkdir()
    (REPO / "memory").mkdir()
    section("PR 1-5 ")
    print(" TeamAgent  5  PR")

    section(f"[Setup] isolated workspace: {REPO}")
    plant_reload_signal()
    seed_failure_logs()

    section("[Run] team_entrypoint.py  4  flag")
    rc = run_entrypoint([
        "--goal", "integration-demo-task",
        "--agent", "integration-1",
        "--iterations", "5",
        "--reload-skills",       # PR 5:
        "--auto-collect",        # PR 5:  collect
        "--auto-evolve",         # PR 4:  EvoLoop
        "--no-push",             #  GitHub
    ])
    print(f"\n  exit code = {rc}")

    section("[Verify] PR 1-5 ")
    verify_artifacts()

    section("[Audit] ")
    show_audit_excerpt()

    section("  demo ")
    print()
    print("      ")
    print()
    print("")
    print("  python team_entrypoint.py --goal '...' --auto-collect --auto-evolve --reload-skills")
    print()
    print(" --no-push  GitHub")


if __name__ == "__main__":
    main()
