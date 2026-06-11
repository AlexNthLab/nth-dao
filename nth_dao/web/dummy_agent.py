"""
Dummy agent process — Phase 3a stand-in for a real backend.

Spawned by the hub's :class:`SubprocessRunner` so the supervisor
has a real PID + real stdout to observe. Prints a single heartbeat
JSON line per second; exits cleanly on SIGTERM (or SIGINT on
Windows where SIGTERM doesn't work the usual way).

Future work (Phase 3b/3c):
  - Issue an Ed25519 keypair + DID at start, print the DID on the
    first stdout line so the hub registers the agent under its
    real identity.
  - Read a cap_token from a file passed via --cap-token-file and
    refuse to act outside its scope.
  - Open a tiny HTTP server on localhost:<port> for A2A messages
    from peers; report the port on the first stdout line.

For Phase 3a the dummy just stays alive long enough to be observed
and killable.

Usage (the supervisor invokes this; not meant to be human-run):

  python -m nth_dao.web.dummy_agent --id <id> --kind <kind>

CLI:
  --id           required, the agent_id assigned by the supervisor
  --kind         required, free-form label (e.g. "mock", "claude-code")
  --heartbeat    optional, seconds between heartbeats (default 1.0)
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time


_STOP = False


def _request_stop(_signum: int, _frame: object) -> None:
    global _STOP
    _STOP = True


def _print_event(**fields: object) -> None:
    """Emit one NDJSON event line to stdout. Flushes so the
    supervisor's reader thread sees the line promptly. """
    print(json.dumps(fields, ensure_ascii=False), flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m nth_dao.web.dummy_agent",
        description="Phase 3a placeholder agent process.",
    )
    parser.add_argument("--id", required=True, help="Agent id assigned by supervisor.")
    parser.add_argument("--kind", required=True, help="Backend kind label.")
    parser.add_argument(
        "--heartbeat",
        type=float,
        default=1.0,
        help="Seconds between heartbeats (default: 1.0).",
    )
    args = parser.parse_args(argv)
    # L-2 fix (2026-06-11): reject non-positive heartbeat — the
    # downstream max(0.1, heartbeat) would silently clamp to 100ms
    # and produce 10 events/sec, swamping the hub's log.
    if args.heartbeat <= 0:
        parser.error(
            f"--heartbeat must be > 0 seconds; got {args.heartbeat}"
        )

    # SIGTERM is the conventional shutdown signal on POSIX; on
    # Windows the supervisor falls back to terminate() which fires
    # SIGINT-shaped behaviour via Win32 GenerateConsoleCtrlEvent.
    try:
        signal.signal(signal.SIGTERM, _request_stop)
    except (AttributeError, ValueError):
        pass  # platform without SIGTERM in Python
    try:
        signal.signal(signal.SIGINT, _request_stop)
    except (AttributeError, ValueError):
        pass

    _print_event(
        event="agent_started",
        agent_id=args.id,
        kind=args.kind,
        # L-1 fix (2026-06-11): plain os.getpid() instead of
        # __import__ runtime trick.
        pid=os.getpid(),
        started_at=int(time.time() * 1000),
    )

    while not _STOP:
        _print_event(
            event="heartbeat",
            agent_id=args.id,
            ts=int(time.time() * 1000),
        )
        # Sleep in small slices so SIGTERM is responsive — a long
        # sleep would leave the process alive for the whole window.
        deadline = time.time() + max(0.1, args.heartbeat)
        while not _STOP and time.time() < deadline:
            time.sleep(0.1)

    _print_event(
        event="agent_stopping",
        agent_id=args.id,
        ts=int(time.time() * 1000),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
