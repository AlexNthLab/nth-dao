"""
Phase 1.5: seed workspace JSON files for v2 disk readers.

The Phase 1 hub (``v2_api.py``) tries to read live data from
``<workspace>/team_{agents,cap_tokens,receipts}/`` on every request,
falling back to in-memory seed when those dirs are empty. This
script pours the canonical seed values onto disk so:

  - ``/api/v2/agents``      stops falling through to ``_seed_agents``
  - ``/api/v2/cap_tokens``  stops falling through to ``_seed_cap_tokens``
  - ``/api/v2/receipts``    augments whatever real receipts are
                            already on disk with the seed ones

After running this script, the v2 console shows real disk-backed
data even before any agent has actually written anything — useful
for demo and for verifying the disk-reader path end-to-end.

Single source of truth: the seed data comes from ``v2_api._seed_*``
so there's no second copy to drift. This script just translates
"list of dicts in memory" → "one file per entity on disk".

Usage::

  python -m nth_dao.web.seed_workspace                   # write into ~/.nth-dao/workspaces/default
  python -m nth_dao.web.seed_workspace --workspace PATH  # custom path
  python -m nth_dao.web.seed_workspace --reset           # wipe team_* dirs first
  python -m nth_dao.web.seed_workspace --dry-run         # report only

Idempotent without ``--reset``: existing files are kept, only
missing entries are written. The receipt that's already on disk
(``d228da186f8b4937b493a0344d6d79d4.json``) stays — the script
only adds the seed receipts alongside.

Phase 2 will deprecate this script once real agents start
emitting their own identity / cap_token / receipt records.
"""
from __future__ import annotations

import argparse
import copy
import json
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, NamedTuple, Optional

# Import the seed functions directly — single source of truth.
from . import v2_api


def _default_workspace() -> Path:
    """Match WebState's default: ``~/.nth-dao/workspaces/default``.

    Resolved locally to keep this script importable as a standalone
    module without going through the WebState bootstrap path. Note
    (review fix #4 2026-06-10): the earlier docstring claimed this
    avoided "importing the FastAPI graph" — that was wrong, since
    v2_api itself imports FastAPI at module level. The honest
    reason is just simplicity. """
    return Path.home() / ".nth-dao" / "workspaces" / "default"


def _now_ms() -> int:
    """Epoch milliseconds — kept as a thin helper so the call site
    reads better than a raw ``int(time.time() * 1000)``. """
    return int(time.time() * 1000)


class SeedCount(NamedTuple):
    """Per-entity result counts. Q5 fix 2026-06-10: previously a
    bare Tuple[int, int, int] whose position semantics depended on
    a docstring. Adding a 4th counter no longer silently breaks
    callers that do ``w, s, a = result``. """
    wrote: int
    skipped: int
    already: int


def _write_json_atomic(path: Path, payload: Dict[str, Any]) -> None:
    """Write JSON atomically — temp file + rename. Prevents the
    disk reader from observing a half-written file if the script
    is interrupted mid-write.

    Review fix #2 (2026-06-10): on Windows ``tmp.replace(path)``
    can raise PermissionError when the target is locked (e.g. the
    hub process is reading it, antivirus has it open). Without
    cleanup the ``.tmp`` file leaks. ``except OSError`` covers
    PermissionError on both platforms while still letting
    programmer bugs (TypeError from a bad payload, etc) propagate. """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        tmp.replace(path)
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _seed_one(
    *,
    label: str,
    target_dir: Path,
    entries: List[Dict[str, Any]],
    filename_of: Callable[[Dict[str, Any]], str],
    payload_of: Callable[[Dict[str, Any]], Dict[str, Any]],
    reset: bool,
    dry_run: bool,
) -> SeedCount:
    """Seed one entity type. Returns a :class:`SeedCount` with
    ``wrote`` / ``skipped`` / ``already`` named fields. """
    if reset and target_dir.exists():
        if dry_run:
            print(f"  [{label}] --reset: would remove {target_dir}")
        else:
            shutil.rmtree(target_dir)
            print(f"  [{label}] --reset: removed {target_dir}")

    wrote = skipped = already = 0
    for entry in entries:
        rel = filename_of(entry)
        path = target_dir / rel
        if path.exists():
            already += 1
            if dry_run:
                print(f"  [{label}] keep   {rel}")
            continue
        if dry_run:
            print(f"  [{label}] write  {rel}  (dry-run)")
            wrote += 1
            continue
        try:
            _write_json_atomic(path, payload_of(entry))
            wrote += 1
            print(f"  [{label}] write  {rel}")
        except Exception as exc:  # noqa: BLE001
            # R1 fix (2026-06-10): per-entry safety net — one broken
            # mapper / unserialisable payload should NOT kill the
            # whole batch (the script seeds 9 entities; losing 1 to
            # a programmer bug shouldn't abort the other 8). The
            # inner _write_json_atomic narrows to OSError for the
            # rename-cleanup case; this outer catch is deliberately
            # wider as the run-to-completion guarantee.
            # KeyboardInterrupt / SystemExit still propagate (they
            # inherit from BaseException, not Exception) so Ctrl+C
            # mid-batch ends the script as expected.
            print(f"  [{label}] skip   {rel}: {exc}", file=sys.stderr)
            skipped += 1
    return SeedCount(wrote=wrote, skipped=skipped, already=already)


def seed_workspace(
    workspace: Optional[Path] = None,
    *,
    reset: bool = False,
    dry_run: bool = False,
) -> Dict[str, SeedCount]:
    """Seed all three disk-reader directories.

    Returns ``{label: (wrote, skipped, already)}`` so callers can
    integration-test the outcome without parsing stdout. """
    ws = workspace or _default_workspace()
    print(f"workspace: {ws}")
    print(f"reset:     {reset}")
    print(f"dry-run:   {dry_run}")
    print()

    results: Dict[str, SeedCount] = {}

    # ── receipts ──────────────────────────────────────────────
    # Filename mirrors what the reader will use as the id fallback,
    # so "id" field in the JSON wins regardless. Keep the existing
    # real receipt (d228...) alongside.
    results["receipts"] = _seed_one(
        label="receipt",
        target_dir=ws / "team_receipts",
        entries=v2_api._seed_receipts(),
        filename_of=lambda r: f"{r['id']}.json",
        payload_of=lambda r: r,
        reset=reset,
        dry_run=dry_run,
    )

    # ── cap_tokens ────────────────────────────────────────────
    # Review fix #3 (2026-06-10): v2_api._seed_cap_tokens() stamps
    # not_before / not_after at call time (e.g. now + 2h). Once
    # frozen on disk, those values decay — within 2 hours the
    # frontend's `caps_expiring_soon` filter starts hiding tokens
    # that were just seeded, and after the window passes they
    # appear expired even though the script never wrote a real
    # expiry. For SEED data we want "looks healthy by default":
    # extend not_after to a far-future point (≈ 1 year out) so
    # the demo UI keeps both tokens visible across operator
    # sessions without re-running the script. Real cap_tokens
    # written by the running app are untouched — those carry
    # actual expiries from the issuer.
    # v2_api._seed_cap_tokens() currently returns a freshly-built
    # list of fresh dicts on each call, so the in-place mutation
    # below is local to this script's view. Caveat (review #2
    # follow-up 2026-06-10): if that helper is ever memoised /
    # cached at the module level, this mutation would corrupt the
    # cache and silently extend cap_token expiry on the API too.
    # Defensive deep-copy keeps us safe from that future change.
    cap_seed = copy.deepcopy(v2_api._seed_cap_tokens())
    # Q3 + Q4 fix (2026-06-10): compute the far-future expiry ONCE
    # outside the loop, and assign DIRECTLY rather than max(...).
    # The previous max() form read as "preserve longer if the seed
    # already stamped one" but for demo/seed data the intent is
    # always "set to far-future" — make that intent literal.
    future_not_after = _now_ms() + 365 * 24 * 3600 * 1000  # ~1 year
    for c in cap_seed:
        c["not_after"] = future_not_after
    results["cap_tokens"] = _seed_one(
        label="cap_token",
        target_dir=ws / "team_cap_tokens",
        entries=cap_seed,
        filename_of=lambda c: f"{c['token_id']}.json",
        payload_of=lambda c: c,
        reset=reset,
        dry_run=dry_run,
    )

    # ── agents ────────────────────────────────────────────────
    # Agents are nested: team_agents/{code}/identity.json. The
    # disk reader (_map_agent_dir) descends one level looking for
    # identity.json. The directory NAME is whatever uniquely
    # identifies the agent on disk — we use the agent_code since
    # it's already short, human-readable, and unique. The full DID
    # lives inside identity.json.
    results["agents"] = _seed_one(
        label="agent",
        target_dir=ws / "team_agents",
        entries=v2_api._seed_agents(),
        filename_of=lambda a: f"{a['code']}/identity.json",
        payload_of=lambda a: a,
        reset=reset,
        dry_run=dry_run,
    )

    print()
    print("summary:")
    for label, (w, s, a) in results.items():
        print(f"  {label:12s}  wrote={w}  skipped={s}  already-present={a}")
    return results


def _cli() -> int:
    # Q6 fix (2026-06-10): hardcoded description. The previous
    # ``__doc__.split("\\n\\n")[0]`` was fragile — any reformatting
    # of the module docstring's leading paragraph (extra blank
    # line, single-paragraph mode) silently emptied --help.
    parser = argparse.ArgumentParser(
        prog="python -m nth_dao.web.seed_workspace",
        description=(
            "Seed v2 console workspace directories "
            "(team_agents/, team_cap_tokens/, team_receipts/) "
            "with canonical demo data so the disk readers in "
            "nth_dao.web.v2_api find live entries instead of "
            "falling back to in-memory seed."
        ),
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help="Workspace root (default: ~/.nth-dao/workspaces/default)",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Wipe team_agents/, team_cap_tokens/, team_receipts/ "
             "before writing. WARNING: deletes any real on-disk data.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would happen without touching disk.",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip the interactive confirmation for --reset. "
             "Required when running non-interactively (CI, hooks).",
    )
    args = parser.parse_args()

    # Review fix #1 (2026-06-10): --reset rm-rf's three directories
    # that may contain real receipts written by the running app
    # (we already had a real d228...json on disk when this script
    # was first written). A copy-pasted --reset flag without a
    # runtime gate silently wipes that data. Confirm-or-abort here
    # unless --dry-run (read-only) or --yes (explicit consent) is
    # already set.
    if args.reset and not args.dry_run and not args.yes:
        ws = args.workspace or _default_workspace()
        # Q7 fix (2026-06-10): consistent ``print(file=sys.stderr)``
        # everywhere in this block — previously alternated between
        # sys.stderr.write + flush and print(file=sys.stderr).
        print(
            f"\nWARNING: --reset will rm -rf the following under {ws}:\n"
            "  team_agents/\n"
            "  team_cap_tokens/\n"
            "  team_receipts/\n"
            "This deletes ANY real receipts / cap_tokens / agent identities\n"
            "the running hub may have written. Type YES to confirm: ",
            end="",
            file=sys.stderr,
            flush=True,
        )
        try:
            answer = input().strip()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer != "YES":
            # Match the warning stream so a CI step that captures
            # stdout for the summary doesn't get "aborted." poisoning
            # its output. Review #1 follow-up 2026-06-10.
            print("aborted.", file=sys.stderr)
            return 1

    seed_workspace(
        workspace=args.workspace,
        reset=args.reset,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    sys.exit(_cli())
