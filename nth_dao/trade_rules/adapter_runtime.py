"""Adapter runtime — executes an approved Rule Hook artifact (Slice B).

The Trade Rule Protocol v1 intentionally "executes nothing": manifests
declare Hook contracts (name, version, input/output schema digests,
side effects, permissions) and `TradeExecutionCoordinator.issue` notarizes a
result against a bilaterally signed Order. The missing piece — the code that
actually RUNS an approved adapter artifact against an operation input — is
this module.

MCP alignment (borrowed shape, zero dependencies): the wire is the
initialize → call pattern from Model Context Protocol, expressed as
JSON-lines over stdio between the runtime and one subprocess:

    runtime → adapter : {"protocol": "nth-trade-adapter-rpc", "version": 1,
                         "artifact_digest": "sha256:..."}       (handshake)
    adapter → runtime : {"ok": true}                              (ack)
    runtime → adapter : {"id": N, "hook": {...}, "input": {...}}  (request)
    adapter → runtime : {"id": N, "ok": true, "result": {...}}    (response)
                      | {"id": N, "ok": false, "error": "..."}

Authority boundary (design doc §Trade Rule Protocol): the runner is a pure
hook executor. It does NOT decide who may execute — bilateral consent,
readiness, permission scoping, and schema validation live in
`TradeExecutionCoordinator.issue`, which re-validates the input and (for
successful outcomes) the result against the manifest schemas. The runner
adds process isolation and hard resource bounds around one approved,
digest-pinned artifact.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Any, Optional

from nth_dao.canonical_json import canonical_json
from nth_dao.trade_rules.execution_adapter import (
    MAX_ADAPTER_ARTIFACT_BYTES,
    TradeExecutionAdapter,
)

logger = logging.getLogger("nth_dao.trade_rules")

ADAPTER_RPC_PROTOCOL = "nth-trade-adapter-rpc"
ADAPTER_RPC_VERSION = 1
MAX_RESULT_BYTES = 1024 * 1024
MAX_INPUT_BYTES = 1024 * 1024
DEFAULT_TIMEOUT_S = 10.0
MAX_TIMEOUT_S = 60.0
_LINE_CAP = MAX_RESULT_BYTES + 65_536  # ack + response share one bounded read

OUTCOME_SUCCEEDED = "succeeded"
OUTCOME_FAILED = "failed"


class AdapterHookRejected(ValueError):
    """Raised when an adapter artifact cannot be executed honestly.

    ``retryable`` separates transient infrastructure failures (execution
    budget exceeded, process crash, spawn failure — the same operation may
    succeed on a retry) from permanent rejections (digest mismatch, bounds,
    protocol violations — the same inputs will fail identically forever).
    Callers driving outbox-style retries must consult it.
    """

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


@dataclass(frozen=True)
class AdapterHookOutcome:
    """One completed hook invocation, ready for `coordinator.issue`."""

    outcome: str
    result_payload: bytes
    request_id: int
    duration_ms: int


def encode_handshake(*, artifact_digest: str) -> bytes:
    """First line sent to the adapter: pins the digest it must assert."""

    line = canonical_json({
        "protocol": ADAPTER_RPC_PROTOCOL,
        "version": ADAPTER_RPC_VERSION,
        "artifact_digest": artifact_digest,
    })
    return line + b"\n"


def encode_request(
    request_id: int,
    *,
    hook_name: str,
    hook_version: str,
    input_payload: bytes,
) -> bytes:
    """Second line: the hook invocation. ``input_payload`` must be JSON."""

    try:
        parsed = json.loads(input_payload.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AdapterHookRejected(f"input payload is not JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise AdapterHookRejected("input payload must be a JSON object")
    try:
        # NaN/Infinity inputs pass json.loads but are non-portable: refuse
        # them here with the contract type, not a raw TypeError
        line = canonical_json({
            "id": request_id,
            "hook": {"name": hook_name, "version": hook_version},
            "input": parsed,
        })
    except (TypeError, ValueError, RecursionError) as exc:
        raise AdapterHookRejected(
            f"input payload is not canonical JSON: {exc}"
        ) from exc
    return line + b"\n"


def _parse_json_line(line: bytes, *, what: str) -> dict:
    try:
        parsed = json.loads(line.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AdapterHookRejected(f"adapter {what} is not JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise AdapterHookRejected(f"adapter {what} must be a JSON object")
    return parsed


def parse_handshake_ack(line: bytes) -> None:
    """Validate the adapter's handshake acknowledgement."""

    ack = _parse_json_line(line, what="handshake ack")
    if ack != {"ok": True}:
        raise AdapterHookRejected(
            f"adapter handshake rejected: {json.dumps(ack)[:200]}"
        )


def parse_response(line: bytes, *, expected_id: int) -> dict:
    """Validate one hook response line and return the ``result`` object."""

    parsed = _parse_json_line(line, what="response")
    if parsed.get("id") != expected_id:
        raise AdapterHookRejected(
            "adapter response id does not match the request"
        )
    if parsed.get("ok") is True:
        result = parsed.get("result")
        if not isinstance(result, dict):
            raise AdapterHookRejected("adapter response result must be an object")
        return result
    if parsed.get("ok") is False:
        error = parsed.get("error")
        if not isinstance(error, str) or not error:
            raise AdapterHookRejected("adapter error response needs text")
        raise AdapterHookFailed(error)
    raise AdapterHookRejected("adapter response ok field must be true or false")


class AdapterHookFailed(AdapterHookRejected):
    """The adapter ran but the hook itself reported failure (outcome=failed)."""


def content_descriptor(
    payload: bytes, *, media_type: str = "application/json"
) -> dict[str, Any]:
    """The wire shape every execution input/result uses (digest-addressed)."""

    return {
        "media_type": media_type,
        "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
        "size_bytes": len(payload),
    }


class SubprocessAdapterRunner:
    """Executes one approved adapter artifact in a bounded subprocess."""

    def __init__(
        self,
        *,
        python: str = sys.executable,
        default_timeout_s: float = DEFAULT_TIMEOUT_S,
        max_timeout_s: float = MAX_TIMEOUT_S,
        max_result_bytes: int = MAX_RESULT_BYTES,
        max_input_bytes: int = MAX_INPUT_BYTES,
    ) -> None:
        if not 0.1 <= float(default_timeout_s) <= float(max_timeout_s):
            raise ValueError("default_timeout_s must be within [0.1, max_timeout_s]")
        if not 0.1 <= float(max_timeout_s) <= 300.0:
            raise ValueError("max_timeout_s must be within [0.1, 300]")
        for name, value in (
            ("max_result_bytes", max_result_bytes),
            ("max_input_bytes", max_input_bytes),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        self._python = python
        self._default_timeout_s = float(default_timeout_s)
        self._max_timeout_s = float(max_timeout_s)
        self._max_result_bytes = max_result_bytes
        self._max_input_bytes = max_input_bytes

    # ─────────────────────── public API ───────────────────────

    def run(
        self,
        *,
        adapter: TradeExecutionAdapter,
        artifact_bytes: bytes,
        hook_name: str,
        hook_version: str,
        rule_id: str,
        input_payload: bytes,
        timeout_s: Optional[float] = None,
    ) -> AdapterHookOutcome:
        """Execute one hook and return the content-addressed outcome.

        Raises :class:`AdapterHookRejected` for every refusal that means
        "this invocation never ran honestly" (digest mismatch, bounds,
        protocol violations). A hook that RAN and reported failure returns
        ``outcome="failed"`` with a ``{"error": ...}`` payload instead.
        """

        timeout = self._default_timeout_s if timeout_s is None else float(timeout_s)
        if not 0.1 <= timeout <= self._max_timeout_s:
            raise AdapterHookRejected(
                f"timeout_s must be within [0.1, {self._max_timeout_s}]"
            )
        self._verify_adapter_support(adapter, hook_name, hook_version, rule_id)
        self._verify_artifact(adapter, artifact_bytes)
        if len(input_payload) > self._max_input_bytes:
            raise AdapterHookRejected(
                f"input payload exceeds {self._max_input_bytes} bytes"
            )

        started_ms = time.monotonic_ns() // 1_000_000
        request_id = int.from_bytes(os.urandom(8), "big") % (2**31)
        stdin_payload = encode_handshake(
            artifact_digest=adapter.to_dict()["artifact_digest"],
        ) + encode_request(
            request_id,
            hook_name=hook_name,
            hook_version=hook_version,
            input_payload=input_payload,
        )

        scratch = tempfile.mkdtemp(prefix="nth-adapter-")
        try:
            artifact_path = os.path.join(scratch, "adapter.py")
            artifact_fd = os.open(
                artifact_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
            )
            with os.fdopen(artifact_fd, "wb") as handle:
                handle.write(artifact_bytes)
            stdout, stderr, returncode = self._communicate(
                [self._python, "-I", artifact_path],
                stdin_payload,
                timeout=timeout,
                cap=_LINE_CAP + self._max_result_bytes,
                scratch=scratch,
            )
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
        duration_ms = time.monotonic_ns() // 1_000_000 - started_ms

        lines = [line for line in stdout.split(b"\n") if line.strip()]
        if len(lines) != 2:
            raise AdapterHookRejected(
                f"adapter stdout must hold exactly the ack and response lines, "
                f"got {len(lines)} line(s)"
            )
        parse_handshake_ack(lines[0])
        try:
            result = parse_response(lines[1], expected_id=request_id)
        except AdapterHookFailed as failed:
            return AdapterHookOutcome(
                outcome=OUTCOME_FAILED,
                result_payload=canonical_json(
                    {"error": failed.args[0][:512]}
                ),
                request_id=request_id,
                duration_ms=duration_ms,
            )
        try:
            result_payload = canonical_json(result)
        except (TypeError, ValueError, RecursionError) as exc:
            raise AdapterHookRejected(
                f"adapter result is not canonical JSON: {exc}"
            ) from exc
        if len(result_payload) > self._max_result_bytes:
            raise AdapterHookRejected(
                f"adapter result exceeds {self._max_result_bytes} bytes"
            )
        return AdapterHookOutcome(
            outcome=OUTCOME_SUCCEEDED,
            result_payload=result_payload,
            request_id=request_id,
            duration_ms=duration_ms,
        )

    # ─────────────────────── internals ───────────────────────

    def _verify_adapter_support(
        self,
        adapter: TradeExecutionAdapter,
        hook_name: str,
        hook_version: str,
        rule_id: str,
    ) -> None:
        supported = {
            (hook.get("rule_id"), hook.get("hook_name"), hook.get("hook_version"))
            for hook in adapter.to_dict()["hooks"]
        }
        if (rule_id, hook_name, hook_version) not in supported:
            raise AdapterHookRejected(
                "adapter does not support hook "
                f"{rule_id}/{hook_name}@{hook_version}"
            )

    def _verify_artifact(
        self, adapter: TradeExecutionAdapter, artifact_bytes: bytes
    ) -> None:
        if len(artifact_bytes) > MAX_ADAPTER_ARTIFACT_BYTES:
            raise AdapterHookRejected(
                f"artifact exceeds {MAX_ADAPTER_ARTIFACT_BYTES} bytes"
            )
        actual = "sha256:" + hashlib.sha256(artifact_bytes).hexdigest()
        declared = adapter.to_dict()["artifact_digest"]
        if actual != declared:
            raise AdapterHookRejected(
                "artifact bytes do not match the adapter descriptor digest"
            )

    def _communicate(
        self,
        argv: list[str],
        stdin_payload: bytes,
        *,
        timeout: float,
        cap: int,
        scratch: str,
    ) -> tuple[bytes, bytes, int]:
        """Run the adapter; return (stdout, stderr, returncode).

        Three bounded pumps (stdin/stdout/stderr) so a hostile artifact that
        never reads stdin or never closes stdout cannot deadlock the runtime,
        and stdout can never buffer beyond ``cap`` — the process is killed
        the moment the bound is crossed.
        """

        minimal_env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        }
        try:
            process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=scratch,
                env=minimal_env,
            )
        except OSError as exc:
            # spawn failures (missing interpreter, fd/memory exhaustion) are
            # transient infrastructure conditions, not permanent rejections
            raise AdapterHookRejected(
                f"adapter process could not be started: {exc}", retryable=True
            ) from exc
        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []
        exceeded = False
        killed = False

        def _kill() -> None:
            nonlocal killed
            if not killed:
                killed = True
                process.kill()

        def _pump(pipe, sink: list[bytes], cap_bytes: int) -> None:
            nonlocal exceeded
            total = 0
            while True:
                chunk = pipe.read(65_536)
                if not chunk:
                    return
                sink.append(chunk)
                total += len(chunk)
                if total > cap_bytes:
                    exceeded = True
                    _kill()
                    return

        def _write_stdin() -> None:
            try:
                process.stdin.write(stdin_payload)  # type: ignore[union-attr]
                process.stdin.close()  # type: ignore[union-attr]
            except (BrokenPipeError, OSError):
                pass  # a dying adapter must not kill the runtime

        pumps = [
            threading.Thread(target=_pump, args=(process.stdout, stdout_chunks, cap),
                             daemon=True),
            threading.Thread(target=_pump, args=(process.stderr, stderr_chunks, 65_536),
                             daemon=True),
            threading.Thread(target=_write_stdin, daemon=True),
        ]
        for pump in pumps:
            pump.start()
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill()
            process.wait(timeout=5.0)
            raise AdapterHookRejected(
                f"adapter exceeded the {timeout}s execution budget",
                retryable=True,
            ) from None
        for pump in pumps:
            pump.join(timeout=5.0)
        if exceeded:
            # the pump killed the process; report the bound, not the signal
            raise AdapterHookRejected(
                f"adapter output exceeded the {cap}-byte bound"
            )
        if process.returncode != 0:
            tail = b"".join(stderr_chunks)[-512:]
            raise AdapterHookRejected(
                f"adapter exited with code {process.returncode}: "
                f"{tail.decode('utf-8', 'replace')}",
                retryable=True,
            )
        return b"".join(stdout_chunks), b"".join(stderr_chunks), process.returncode


__all__ = [
    "ADAPTER_RPC_PROTOCOL",
    "ADAPTER_RPC_VERSION",
    "AdapterHookFailed",
    "AdapterHookOutcome",
    "AdapterHookRejected",
    "MAX_INPUT_BYTES",
    "MAX_RESULT_BYTES",
    "OUTCOME_FAILED",
    "OUTCOME_SUCCEEDED",
    "SubprocessAdapterRunner",
    "content_descriptor",
    "encode_handshake",
    "encode_request",
    "parse_handshake_ack",
    "parse_response",
]
