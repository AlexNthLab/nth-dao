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


def _atomic_write_json(path: Path, payload: Dict[str, Any]) -> None:
    """Write ``payload`` to ``path`` atomically via tmp + replace.

    M-1 fix (review round Phase 3d R1): the Phase 3c recovery
    file (``last_receipt.json``) and any future hub-readable
    child file MUST be atomic so a recovery sweep doesn't pick
    up a half-written JSON. Same wire-format as the supervisor's
    ``_atomic_write_json``; deliberately reimplemented here to
    keep the child a single-file CLI with no nth_dao.web import
    coupling (Phase 4 may package the child separately). """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        os.replace(str(tmp), str(path))
    except OSError:
        # M-2 echo: clean up tmp on replace failure so the agent
        # dir doesn't accumulate orphan tmp files across runs.
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


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


# ─── Phase 3e: cap_token holder + method → required-cap map ─────


class _CapTokenHolder:
    """Thread-safe slot holding the child's own cap_token after it
    loads from disk. The A2A server reads ``issuer_did`` from this
    to validate incoming tokens are signed by the SAME hub.

    Before the child loads its own token, ``token`` is None and
    every A2A POST returns 401 ("not-yet-authorized") — defense in
    depth so a fast peer can't slip in before the handshake. """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._token: Optional[Dict[str, Any]] = None

    def set(self, token: Dict[str, Any]) -> None:
        with self._lock:
            self._token = dict(token)

    def get_issuer_did(self) -> Optional[str]:
        with self._lock:
            if self._token is None:
                return None
            return str(self._token.get("issuer_did") or "") or None


# Phase 3e: which method requires which cap. Method "echo" is the
# MVP demonstration; later methods would map to richer caps.
_A2A_METHOD_CAPABILITIES: Dict[str, str] = {
    "echo": "a2a:message_send",
}


def _verify_a2a_auth(
    auth_header: str,
    holder: _CapTokenHolder,
    method: str,
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Verify an incoming A2A request's Authorization header.

    Returns ``(ok, reason, token)``. On success ``reason`` is "" and
    ``token`` is the parsed cap_token dict. On failure ``reason`` is
    a machine-readable string mirroring cap_token.REJECT_* values
    plus a few A2A-specific ones (``no-auth``, ``bad-scheme``,
    ``issuer-mismatch``, ``not-yet-authorized``, ``method-unknown``).

    Checks performed:
      1. Header must be ``CapToken <encoded>``.
      2. Token must parse + verify against its claimed issuer.
      3. Token's issuer_did must match the CHILD's OWN cap_token's
         issuer_did — a peer presenting a token signed by some
         other hub is rejected outright.
      4. Token must carry the capability required by ``method``. """
    if not auth_header:
        return False, "no-auth", None
    parts = auth_header.split(None, 1)
    if len(parts) != 2 or parts[0] != "CapToken":
        return False, "bad-scheme", None
    encoded = parts[1].strip()

    # Lazy import — cap_token pulls in nacl + canonical_json, which
    # the child shouldn't pay for if no A2A request ever arrives.
    try:
        from nth_dao.cap_token import (
            decode_authorization_value, verify_cap_token,
        )
    except ImportError:
        return False, "crypto-unavailable", None

    token = decode_authorization_value(encoded)
    if token is None or not isinstance(token, dict):
        return False, "sig-decode-failed", None

    own_issuer = holder.get_issuer_did()
    if own_issuer is None:
        return False, "not-yet-authorized", None
    if token.get("issuer_did") != own_issuer:
        return False, "issuer-mismatch", token

    required_cap = _A2A_METHOD_CAPABILITIES.get(method)
    if required_cap is None:
        return False, "method-unknown", token

    ok, reason = verify_cap_token(
        token, required_capabilities=[required_cap],
    )
    if not ok:
        return False, reason or "verify-failed", token
    return True, "", token


# ─── Phase 3c: A2A localhost HTTP server ─────────────────────────


def _start_a2a_server(
    identity_card: Dict[str, Any],
    cap_token_holder: "_CapTokenHolder",
) -> Tuple[Optional[int], Optional[socketserver.BaseServer]]:
    """Bind a stdlib HTTP server on 127.0.0.1:<random port> and
    serve ``identity_card`` from GET /ping plus a JSON-RPC-style
    POST /a2a/<method> surface (Phase 3e).

    Returns ``(port, server)`` on success, ``(None, None)`` if
    the bind fails. Bind failure is non-fatal — the agent runs
    without an A2A surface (Phase 3c logs the gap; Phase 3d would
    surface it as a degraded-state indicator).

    The server runs on a daemon thread so process exit takes it
    down even if we forget to call shutdown(). """
    state_snapshot: Dict[str, Any] = dict(identity_card)
    state_lock = threading.Lock()

    # L-3 pushback (review round Phase 3c R1): A2AHandler is
    # defined inline because it CLOSES OVER state_snapshot +
    # state_lock + cap_token_holder. Hoisting it to module level
    # would force per-agent state through class attributes
    # (mutable global state shared across agents) or a factory
    # pattern — both worse than a closure for state encapsulation.
    # ``_start_a2a_server`` is called once per agent lifetime, so
    # the class-rebuild cost is irrelevant.
    class A2AHandler(http.server.BaseHTTPRequestHandler):
        # Quiet the per-request stderr line — the parent already
        # forwards meaningful events via the supervisor's
        # _read_stderr_loop, and access logs from a localhost
        # pingable server are pure noise.
        def log_message(self, _fmt: str, *_args: Any) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802 — stdlib API
            if self.path.rstrip("/") != "/ping":
                self.send_error(404, "only /ping is implemented for GET")
                return
            with state_lock:
                payload = json.dumps(
                    {**state_snapshot, "uptime_ms":
                     int(time.time() * 1000) - state_snapshot["started_at"]},
                    ensure_ascii=False,
                ).encode("utf-8")
            self._respond(200, payload)

        def do_POST(self) -> None:  # noqa: N802 — stdlib API
            """Phase 3e: JSON-RPC-style POST /a2a/<method>.

            Body is the raw params dict; response is
            ``{"result": ...}`` on success or ``{"error": {...}}``
            on failure. Auth required via ``Authorization: CapToken
            <base64url-canonical-token>`` header. """
            if not self.path.startswith("/a2a/"):
                self.send_error(404, "only /a2a/<method> is implemented for POST")
                return
            method = self.path[len("/a2a/"):].strip("/")
            if not method:
                self._json_error(400, "bad-request", "missing method in path")
                return
            # Body: bounded read so a misbehaving peer can't OOM
            # the child by claiming Content-Length: 1GB.
            # H-1 fix (review round Phase 3e R1): parse defensively —
            # a malformed Content-Length (e.g. "abc") used to raise
            # ValueError out of the int() call → 500 from
            # BaseHTTPRequestHandler. Bad client input belongs on
            # the 400 path, not 500.
            cl_header = self.headers.get("Content-Length") or "0"
            try:
                content_length = int(cl_header)
            except ValueError:
                self._json_error(
                    400, "bad-request",
                    f"Content-Length is not an integer: {cl_header!r}",
                )
                return
            if content_length < 0 or content_length > 1024 * 1024:
                self._json_error(
                    413, "payload-too-large",
                    f"Content-Length {content_length} exceeds 1MB cap",
                )
                return
            body_bytes = self.rfile.read(content_length) if content_length else b""
            try:
                params = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                self._json_error(
                    400, "bad-request",
                    f"body is not valid JSON: {exc}",
                )
                return
            # Auth: parse "Authorization: CapToken <encoded>"
            auth_header = self.headers.get("Authorization", "")
            ok, reason, token = _verify_a2a_auth(
                auth_header, cap_token_holder, method,
            )
            if not ok:
                self._json_error(
                    401 if reason != "cap-insufficient" else 403,
                    reason, f"A2A auth failed for /a2a/{method}: {reason}",
                )
                return
            # Method dispatch — Phase 3e supports only "echo".
            if method == "echo":
                response = {"result": {
                    "method": method,
                    "received_params": params,
                    "caller_did": (token or {}).get("subject_did", ""),
                    "agent_did": state_snapshot["did"],
                }}
            else:
                self._json_error(
                    404, "method-not-found",
                    f"method {method!r} not supported (Phase 3e: echo only)",
                )
                return
            self._respond(
                200,
                json.dumps(response, ensure_ascii=False).encode("utf-8"),
            )

        def _respond(self, status: int, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json_error(self, status: int, code: str, message: str) -> None:
            body = json.dumps(
                {"error": {"code": code, "message": message}},
                ensure_ascii=False,
            ).encode("utf-8")
            self._respond(status, body)

    try:
        # Port 0 → kernel picks a free ephemeral port; we then read
        # back via .server_address.
        # Phase 3d: ThreadingHTTPServer (one thread per request)
        # replaces the single-threaded TCPServer so concurrent
        # /ping or future A2A method calls don't serialise. The
        # daemon-thread classmethod marks worker threads as daemons
        # so process exit takes them down.
        server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), A2AHandler,
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

    # Phase 3e: holder is shared between the main polling loop
    # (which sets the token after cap_token_file loads) and the
    # A2A HTTP server's auth check.
    cap_token_holder = _CapTokenHolder()

    # Phase 3c: open the A2A surface BEFORE emitting agent_started
    # so the advertised port is the one we'll actually serve on.
    a2a_port, _server = _start_a2a_server(
        {
            "agent_id": args.id,
            "kind": args.kind,
            "did": did,
            "pubkey_hex": pubkey_hex,
            "started_at": started_at,
        },
        cap_token_holder,
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
                # Phase 3e: hand the token to the A2A auth slot so
                # incoming requests with peer cap_tokens issued by
                # the same hub start being honored.
                cap_token_holder.set(token)
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
                    # pipe-read leaves a recovery artifact. The
                    # Phase 3e recovery sweep on hub startup picks
                    # up any such files; the supervisor's stop()
                    # cleanup removes them alongside cap_token.json
                    # when the agent shuts down cleanly.
                    # M-1 fix (review round Phase 3d R1): atomic
                    # write so the sweep can't see a partial file.
                    recovery_path = (
                        Path(cap_token_path).parent / "last_receipt.json"
                    )
                    try:
                        _atomic_write_json(recovery_path, receipt)
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
