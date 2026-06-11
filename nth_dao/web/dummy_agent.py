"""
Dummy agent process — Phase 3c stand-in for a real backend.

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

Phase 3c (2026-06-11):
  - The child opens a stdlib HTTP server on 127.0.0.1:<random port>
    in a daemon thread (Phase 3c A2A surface). The port is advertised
    on ``agent_started.a2a_port`` and served by ``/ping`` returning
    the agent's identity card. Failures to bind don't kill the agent
    — the port field is just omitted from agent_started so the hub
    knows to skip A2A routing for this agent.
  - The child accepts ``--cap-token-file <path>``. The path doesn't
    have to exist yet — the supervisor signs the cap_token after the
    handshake and atomic-writes it to that path while the child is
    already heart-beating. Each heartbeat tick the child polls the
    path; on first appearance it loads + parses + signs ONE
    ``nth.agent_attestation`` receipt asserting "I hold this token"
    and emits ``receipt_signed`` with the receipt JSON.

Future work (Phase 3d+):
  - Enforce the cap_token's scope against incoming A2A requests.
  - Sign more than the single attestation — task-result receipts.
  - Persist identity under sandbox/agents/<agent_id>/identity.json
    so the child can be restarted under the same DID.

For Phase 3c the dummy generates a real identity, advertises its DID
+ port, signs one attestation, and stays alive long enough to be
observed and killable.

Usage (the supervisor invokes this; not meant to be human-run):

  python -m nth_dao.web.dummy_agent --id <id> --kind <kind> \\
      [--cap-token-file <path>] [--heartbeat <secs>]

CLI:
  --id              required, the agent_id assigned by the supervisor
  --kind            required, free-form label (e.g. "mock", "claude-code")
  --heartbeat       optional, seconds between heartbeats (default 1.0)
  --cap-token-file  optional, where to poll for the issued cap_token.
                    If absent, the child runs in Phase 3a/3b mode (no
                    attestation receipt).
"""
from __future__ import annotations

import argparse
import http.server
import json
import os
import signal
import socketserver
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


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
    not pollute the event stream the hub is parsing.

    L-1 fix (review round Phase 3c R1): symmetrical with
    ``_print_event`` (same ``print(..., flush=True)`` shape; just
    ``file=sys.stderr``) so a maintainer reading both side-by-side
    doesn't have to wonder why the stderr variant uses a different
    API. """
    print(
        json.dumps(fields, ensure_ascii=False),
        file=sys.stderr, flush=True,
    )


# ─── Phase 3c: A2A localhost HTTP server ─────────────────────────


def _start_a2a_server(
    identity_card: Dict[str, Any],
) -> Tuple[Optional[int], Optional[socketserver.BaseServer]]:
    """Bind a stdlib HTTP server on 127.0.0.1:<random port> and
    serve ``identity_card`` from GET /ping.

    Returns ``(port, server)`` on success, ``(None, None)`` if
    the bind fails. Bind failure is non-fatal — the agent runs
    without an A2A surface (Phase 3c logs the gap; Phase 3d would
    surface it as a degraded-state indicator).

    The server runs on a daemon thread so process exit takes it
    down even if we forget to call shutdown(). """
    state_snapshot: Dict[str, Any] = dict(identity_card)
    state_lock = threading.Lock()

    # L-3 pushback (review round Phase 3c R1): PingHandler is
    # defined inline because it CLOSES OVER state_snapshot +
    # state_lock. Hoisting it to module level would force per-agent
    # state through class attributes (mutable global state shared
    # across agents) or a factory pattern — both worse than a
    # closure for state encapsulation. ``_start_a2a_server`` is
    # called once per agent lifetime, so the class-rebuild cost
    # is irrelevant.
    class PingHandler(http.server.BaseHTTPRequestHandler):
        # Quiet the per-request stderr line — the parent already
        # forwards meaningful events via the supervisor's
        # _read_stderr_loop, and access logs from a localhost
        # pingable server are pure noise.
        def log_message(self, _fmt: str, *_args: Any) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802 — stdlib API
            if self.path.rstrip("/") != "/ping":
                self.send_error(404, "only /ping is implemented")
                return
            with state_lock:
                payload = json.dumps(
                    {**state_snapshot, "uptime_ms":
                     int(time.time() * 1000) - state_snapshot["started_at"]},
                    ensure_ascii=False,
                ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    try:
        # Port 0 → kernel picks a free ephemeral port; we then read
        # back via .server_address.
        # Phase 3d: ThreadingHTTPServer (one thread per request)
        # replaces the single-threaded TCPServer so concurrent
        # /ping or future A2A method calls don't serialise. The
        # daemon-thread classmethod marks worker threads as daemons
        # so process exit takes them down.
        server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), PingHandler,
        )
        server.daemon_threads = True
    except OSError as exc:
        _print_error(
            event="a2a_bind_failed",
            agent_id=str(identity_card.get("agent_id", "")),
            detail=f"{type(exc).__name__}: {exc}",
        )
        return None, None

    port = int(server.server_address[1])
    t = threading.Thread(
        target=server.serve_forever,
        name=f"a2a-{port}",
        daemon=True,
    )
    t.start()
    return port, server


# ─── Phase 3c: cap_token polling + attestation signing ───────────


def _try_load_cap_token(path: str) -> Optional[Dict[str, Any]]:
    """Return the parsed cap_token if ``path`` is a complete JSON
    file, else None. Tolerant of:
      - file not yet written (FileNotFoundError)
      - partial write caught mid-flight (json.JSONDecodeError) —
        but the supervisor uses atomic tmp+os.replace so this
        should only happen if a different writer touches the path.
      - empty file (json.JSONDecodeError) """
    # M-1 fix (review round Phase 3c R1): proper context manager so
    # the file descriptor closes deterministically even if a future
    # edit inserts work between open() and read().
    try:
        with open(path, encoding="utf-8") as f:
            raw = f.read()
    except FileNotFoundError:
        return None
    except OSError:
        return None
    if not raw.strip():
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    return data


def _sign_attestation_receipt(
    *,
    identity: Any,  # AgentIdentity — typed Any to avoid early import
    agent_id: str,
    kind: str,
    did: str,
    cap_token: Dict[str, Any],
    a2a_port: Optional[int],
) -> Optional[Dict[str, Any]]:
    """Mint an ``nth.agent_attestation`` receipt signed by the
    child's own identity. Returns None on signing failure (caller
    logs + continues — the agent stays alive without the receipt). """
    try:
        from nth_dao.execution_receipt import TimelineEntry, sign_receipt
    except ImportError as exc:
        _print_error(
            event="agent_error",
            agent_id=agent_id,
            error="receipt-import-failed",
            detail=str(exc),
        )
        return None

    timeline = [
        TimelineEntry(
            timestamp=int(time.time() * 1000),
            type="nth.agent_attestation",
            payload={
                "agent_id": agent_id,
                "kind": kind,
                "did": did,
                "cap_token_id": cap_token.get("token_id", ""),
                "cap_token_caps": cap_token.get("capabilities", []),
                "a2a_port": a2a_port,
                "claim": "I, this agent, hold the cap_token "
                         "identified above and am alive at the "
                         "timestamp on this entry.",
            },
        ),
    ]
    try:
        receipt = sign_receipt(
            timeline, identity,
            goal_id=f"agent:{agent_id}",
            prev_content_hash="",
        )
    except Exception as exc:  # noqa: BLE001
        _print_error(
            event="agent_error",
            agent_id=agent_id,
            error="receipt-sign-failed",
            detail=f"{type(exc).__name__}: {exc}",
        )
        return None
    return receipt


# ─── main loop ────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m nth_dao.web.dummy_agent",
        description="Phase 3c placeholder agent process.",
    )
    parser.add_argument("--id", required=True, help="Agent id assigned by supervisor.")
    parser.add_argument("--kind", required=True, help="Backend kind label.")
    parser.add_argument(
        "--heartbeat",
        type=float,
        default=1.0,
        help="Seconds between heartbeats (default: 1.0).",
    )
    parser.add_argument(
        "--cap-token-file",
        type=str,
        default="",
        help=(
            "Path where the supervisor will write the issued "
            "cap_token JSON. The child polls this path each tick; "
            "on first appearance signs an nth.agent_attestation "
            "receipt and emits receipt_signed. Empty disables the "
            "polling loop entirely (Phase 3a/3b mode)."
        ),
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

    started_at = int(time.time() * 1000)

    # Phase 3c: open the A2A surface BEFORE emitting agent_started
    # so the advertised port is the one we'll actually serve on.
    a2a_port, _server = _start_a2a_server({
        "agent_id": args.id,
        "kind": args.kind,
        "did": did,
        "pubkey_hex": pubkey_hex,
        "started_at": started_at,
    })

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

    agent_started: Dict[str, Any] = {
        "event": "agent_started",
        "agent_id": args.id,
        "kind": args.kind,
        # Phase 3b: include the child's real DID + pubkey on the
        # first event. The hub uses `did` as the lookup key for
        # cap_token issuance; pubkey is for the audit log + future
        # offline verification.
        "did": did,
        "pubkey_hex": pubkey_hex,
        # L-1 fix (2026-06-11): plain os.getpid() instead of
        # __import__ runtime trick.
        "pid": os.getpid(),
        "started_at": started_at,
    }
    if a2a_port is not None:
        # Phase 3c: only advertise when the bind actually
        # succeeded. Omitting the field signals "no A2A surface"
        # to the hub — Phase 3d will treat that as a degraded state.
        agent_started["a2a_port"] = a2a_port
    _print_event(**agent_started)

    cap_token_loaded = False
    cap_token_path: str = (args.cap_token_file or "").strip()
    while not _STOP:
        _print_event(
            event="heartbeat",
            agent_id=args.id,
            ts=int(time.time() * 1000),
        )
        # Phase 3c: poll for the cap_token file. Once loaded we
        # never re-load — re-issuance is a future-phase concern
        # (cap_tokens are revocable, not mutable: a new token gets
        # a new token_id).
        if cap_token_path and not cap_token_loaded:
            token = _try_load_cap_token(cap_token_path)
            if token is None:
                pass  # not yet — try next tick
            elif token.get("subject_did") != did:
                # M-1 fix (review round Phase 3c R2): defense in
                # depth. The supervisor controls the file path so
                # under normal operation subject_did MATCHES, but
                # a misconfigured path or future bug routing the
                # wrong token to this child would otherwise have
                # us sign a false "I hold this token" attestation.
                # Refuse, emit a structured stderr event so the
                # operator can grep for it, and mark the slot
                # loaded so we don't spin re-reading the same
                # mismatched file.
                cap_token_loaded = True
                _print_error(
                    event="cap_token_subject_mismatch",
                    agent_id=args.id,
                    expected_did=did,
                    actual_subject_did=str(token.get("subject_did", "")),
                    token_id=str(token.get("token_id", "")),
                )
            else:
                cap_token_loaded = True
                receipt = _sign_attestation_receipt(
                    identity=identity,
                    agent_id=args.id,
                    kind=args.kind,
                    did=did,
                    cap_token=token,
                    a2a_port=a2a_port,
                )
                if receipt is not None:
                    # M-3 fix (review round Phase 3c R2): persist
                    # the receipt to disk BEFORE emitting it on
                    # stdout so a crash between sign and parent
                    # pipe-read leaves a recovery artifact. Phase
                    # 3e will sweep these on hub startup; for now
                    # the file is removed alongside cap_token.json
                    # when the supervisor stops the agent.
                    recovery_path = (
                        Path(cap_token_path).parent / "last_receipt.json"
                    )
                    try:
                        with open(recovery_path, "w", encoding="utf-8") as f:
                            json.dump(
                                receipt, f, ensure_ascii=False, indent=2,
                            )
                    except OSError as exc:
                        _print_error(
                            event="recovery_write_failed",
                            agent_id=args.id,
                            path=str(recovery_path),
                            detail=f"{type(exc).__name__}: {exc}",
                        )
                    _print_event(
                        event="receipt_signed",
                        agent_id=args.id,
                        receipt=receipt,
                    )
                    # Phase 3d: also raise a decision asking the
                    # operator to acknowledge the agent is live.
                    # Hub assigns id + source — child only proposes.
                    _print_event(
                        event="decision_raised",
                        agent_id=args.id,
                        decision={
                            "title": (
                                f"Acknowledge agent {args.id[:8]} is live "
                                f"(kind={args.kind})"
                            ),
                            "impact": "low",
                            "preview_receipt": {
                                "kind": "nth.agent_attestation",
                                "agent_id": args.id,
                                "did": did,
                            },
                            "mission_id": "",
                        },
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
