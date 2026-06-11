"""
Dummy agent process — Phase 3b stand-in for a real backend.

Spawned by the hub's :class:`SubprocessRunner` so the supervisor
has a real PID + real stdout to observe. Prints a single heartbeat
JSON line per second; exits cleanly on SIGTERM (or SIGINT on
Windows where SIGTERM doesn't work the usual way).

Phase 3b (2026-06-11):
  - Child generates its own Ed25519 keypair via AgentIdentity.generate()
    on startup and emits its W3C did:key on the first stdout line.
    The hub blocks inside SubprocessRunner.start() waiting for that
    first event, then registers the AgentRecord under the real DID
    and issues a cap_token bound to it. Without PyNaCl available the
    child writes an error event to stderr and exits with code 2.
  - Identity is ephemeral — held in-process only, not persisted.
    Phase 3c will save it under sandbox/agents/<agent_id>/identity.json
    so the child can be restarted under the same DID.

Future work (Phase 3c+):
  - Read a cap_token from a file passed via --cap-token-file and
    refuse to act outside its scope; sign receipts using the
    identity from this process.
  - Open a tiny HTTP server on localhost:<port> for A2A messages
    from peers; report the port on the first stdout line.

For Phase 3b the dummy generates a real identity, advertises its DID,
and stays alive long enough to be observed and killable.

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


def _print_error(**fields: object) -> None:
    """Emit one NDJSON line to stderr (operator log). Stdout is
    reserved for the protocol stream so a startup failure must
    not pollute the event stream the hub is parsing. """
    sys.stderr.write(json.dumps(fields, ensure_ascii=False) + "\n")
    sys.stderr.flush()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m nth_dao.web.dummy_agent",
        description="Phase 3b placeholder agent process.",
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

    # Phase 3b: generate an Ed25519 keypair so the hub can register
    # this agent under its W3C did:key. The supervisor blocks on
    # the first agent_started event waiting for the `did` field —
    # if we can't produce one we must exit cleanly so the hub's
    # 10s handshake timeout fires fast instead of hanging.
    #
    # The import lives INSIDE main() — not at module top — for two
    # reasons:
    #   1. ``args.id`` is already known by this point, so the
    #      stderr error event we emit on failure carries the
    #      supervisor's agent_id (the operator can grep for it).
    #      A top-level import that exits before argparse runs
    #      would emit a generic ImportError with no routing key.
    #   2. argparse failures (bad --heartbeat, missing --id) should
    #      stop us BEFORE we import nth_dao.identity — otherwise a
    #      caller probing the CLI with --help would pay the cost
    #      of importing the whole identity stack for nothing.
    try:
        from nth_dao.identity import AgentIdentity, crypto_available
    except ImportError as exc:
        _print_error(
            event="agent_error",
            agent_id=args.id,
            error="identity-import-failed",
            detail=str(exc),
        )
        return 2
    if not crypto_available():
        _print_error(
            event="agent_error",
            agent_id=args.id,
            error="crypto-unavailable",
            detail="PyNaCl not installed; cannot generate Ed25519 keypair.",
        )
        return 2
    try:
        identity = AgentIdentity.generate(label=args.id)
        did = identity.as_did()
        pubkey_hex = identity.pubkey_hex
    except Exception as exc:  # noqa: BLE001
        _print_error(
            event="agent_error",
            agent_id=args.id,
            error="identity-generate-failed",
            detail=f"{type(exc).__name__}: {exc}",
        )
        return 2

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
        # Phase 3b: include the child's real DID + pubkey on the
        # first event. The hub uses `did` as the lookup key for
        # cap_token issuance; pubkey is for the audit log + future
        # offline verification.
        did=did,
        pubkey_hex=pubkey_hex,
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
