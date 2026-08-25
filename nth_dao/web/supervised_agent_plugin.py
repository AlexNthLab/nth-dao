"""Web runtime bridge for fixed-target supervised Agent plugins.

This module adapts the existing localhost A2A + CapToken + signed Receipt path
to the language-neutral Agent Provider contract. The plugin receives neither
the child port nor its bearer token; both remain owned by the Web runtime.
"""

from __future__ import annotations

import asyncio
from contextlib import nullcontext
import hashlib
import json
import math
from pathlib import Path
import queue
import threading
import time
from typing import Any, Callable, Coroutine
import urllib.error
import urllib.request

from starlette.requests import Request

from nth_dao.canonical_json import canonical_json
from nth_dao.plugins.builtin.supervised_agent_provider import (
    SupervisedAgentCapabilities,
    SupervisedAgentOutcomeUnknown,
    SupervisedAgentProbe,
    SupervisedAgentTarget,
    SupervisedAgentTurnRequest,
    SupervisedAgentTurnResult,
    register_supervised_agent_provider,
    supervised_agent_plugin_id,
)
from nth_dao.util.io import InterProcessLock, atomic_write_json, safe_load_json


_PROBE_RESPONSE_LIMIT = 65_536
_BACKEND_ID = "supervised-a2a"
_MAX_BRIDGE_WORKERS = 8
_BRIDGE_WORKER_SLOTS = threading.BoundedSemaphore(_MAX_BRIDGE_WORKERS)
_TURN_RESULT_RETENTION_SECONDS = 7 * 24 * 60 * 60
_MAX_DURABLE_TURN_STATES = 4_096
_PUBLIC_AGENT_ERROR_CODES = frozenset(
    {
        "backend-failed",
        "backend-timeout",
        "not-yet-authorized",
        "rate-limited",
        "usage-limit",
    }
)
_WEB_REVIEWED_ARTIFACT_PATHS = (
    "nth_dao/cap_token.py",
    "nth_dao/execution_receipt.py",
    "nth_dao/util/io.py",
    "nth_dao/web/agent_link.py",
    "nth_dao/web/agent_supervisor.py",
    "nth_dao/web/dummy_agent.py",
    "nth_dao/web/supervised_agent_plugin.py",
    "nth_dao/web/v2_api.py",
)


def _request_for_app(app: Any) -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/_internal/plugin-agent-provider",
            "raw_path": b"/_internal/plugin-agent-provider",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 0),
            "server": ("127.0.0.1", 0),
            "app": app,
        }
    )


def _require_sync_bridge_thread() -> None:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return
    raise RuntimeError(
        "synchronous supervised Agent bridge cannot run on an event-loop "
        "thread; invoke it through a worker thread"
    )


def _run_coroutine(
    coroutine: Coroutine[Any, Any, Any],
    *,
    timeout_s: float,
) -> Any:
    """Run a Web coroutine from the synchronous PluginHost boundary.

    The child protocol has its own timeout, but this bridge also needs a hard
    upper bound. Otherwise an event-loop bug or a coroutine which mishandles
    cancellation can block a synchronous plugin invocation forever.
    """

    if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)):
        coroutine.close()
        raise TypeError("timeout_s must be a number")
    timeout = float(timeout_s)
    if not math.isfinite(timeout) or timeout <= 0.0 or timeout > 3_600.0:
        coroutine.close()
        raise ValueError("timeout_s must be in (0, 3600]")

    try:
        _require_sync_bridge_thread()
    except RuntimeError:
        coroutine.close()
        raise

    if not _BRIDGE_WORKER_SLOTS.acquire(blocking=False):
        coroutine.close()
        raise RuntimeError("supervised Agent bridge worker capacity is exhausted")

    async def bounded() -> Any:
        return await asyncio.wait_for(coroutine, timeout=timeout)

    results: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

    def runner() -> None:
        try:
            results.put((True, asyncio.run(bounded())))
        except BaseException as exc:  # noqa: BLE001 - re-raised in caller
            results.put((False, exc))
        finally:
            _BRIDGE_WORKER_SLOTS.release()

    thread = threading.Thread(
        target=runner,
        name="nth-supervised-agent-plugin",
        daemon=True,
    )
    try:
        thread.start()
    except BaseException:
        _BRIDGE_WORKER_SLOTS.release()
        coroutine.close()
        raise
    try:
        # Give the worker a small scheduling margin beyond the coroutine's
        # own timeout. The caller returns at this hard boundary even if an
        # invalid coroutine suppresses cancellation. Such a daemon worker
        # retains one bounded slot until it actually exits.
        ok, value = results.get(timeout=timeout + 0.25)
    except queue.Empty as exc:
        raise TimeoutError("supervised Agent coroutine exceeded bridge timeout") from exc
    thread.join(timeout=0.25)
    if not ok:
        raise value
    return value


def _turn_binding_id(target: SupervisedAgentTarget, request: SupervisedAgentTurnRequest) -> str:
    # Deliberately exclude the execution-target revision. A target revision
    # change must collide with the same logical turn state and fail closed,
    # rather than create a fresh key which could execute the turn twice.
    document = {
        "agent_did": target.agent_did,
        "principal": request.principal,
        "session_id": request.session_id,
        "turn_id": request.turn_id,
    }
    return "plugin-" + hashlib.sha256(canonical_json(document)).hexdigest()


def _execution_request_sha256(
    target: SupervisedAgentTarget,
    request: SupervisedAgentTurnRequest,
) -> str:
    """Bind every Host-owned execution control into one Receipt digest."""

    document = {
        "agent_did": target.agent_did,
        "execution_target_revision": target.execution_target_revision,
        "format": "nth-dao-agent-execution-request-v2",
        "goal": request.goal,
        "max_output_tokens": request.max_output_tokens,
        "model": request.model,
        "principal": request.principal,
        "prompt": request.prompt,
        "session_id": request.session_id,
        "system_prompt": request.system_prompt,
        "temperature_milli": request.temperature_milli,
        "timeout_ms": request.timeout_ms,
        "turn_id": request.turn_id,
    }
    return hashlib.sha256(canonical_json(document)).hexdigest()


class WebSupervisedAgentInvoker:
    """Host-owned invoker over a single FastAPI application's supervisor."""

    def __init__(
        self,
        app: Any,
        supervisor: Any,
        *,
        expected_agent_id: str | None = None,
        expected_a2a_port: int | None = None,
    ) -> None:
        if app is None:
            raise TypeError("app is required")
        if not callable(getattr(supervisor, "list_agents", None)):
            raise TypeError("supervisor must provide list_agents()")
        self._app = app
        self._supervisor = supervisor
        self._expected_agent_id = expected_agent_id
        self._expected_a2a_port = expected_a2a_port

    def _record(self, target: SupervisedAgentTarget) -> Any:
        matches = [
            record
            for record in self._supervisor.list_agents()
            if (
                str(getattr(record, "did", "") or "") == target.agent_did
                and str(getattr(record, "agent_id", "") or "")
                == target.agent_id
                and (
                    self._expected_agent_id is None
                    or str(getattr(record, "agent_id", "") or "")
                    == self._expected_agent_id
                )
                and (
                    self._expected_a2a_port is None
                    or getattr(record, "a2a_port", None)
                    == self._expected_a2a_port
                )
                and bool(getattr(record, "alive", False))
                and getattr(record, "a2a_port", None) is not None
            )
        ]
        if not matches:
            raise RuntimeError("fixed target has no live supervised A2A endpoint")
        if len(matches) != 1:
            raise RuntimeError("fixed target DID resolves to multiple live Agents")
        return matches[0]

    @staticmethod
    def _capabilities(record: Any) -> SupervisedAgentCapabilities:
        kind = str(getattr(record, "kind", "supervised") or "supervised")
        return SupervisedAgentCapabilities(
            supports_streaming=False,
            supports_tools=False,
            supports_system_prompt=False,
            supports_multi_turn=False,
            supports_temperature=False,
            max_context_tokens=0,
            notes=f"{kind} through localhost A2A; signed Receipt required.",
        )

    def probe(
        self,
        target: SupervisedAgentTarget,
        *,
        timeout_ms: int,
    ) -> SupervisedAgentProbe:
        _require_sync_bridge_thread()
        try:
            record = self._record(target)
        except RuntimeError as exc:
            return SupervisedAgentProbe(
                ready=False,
                capabilities=SupervisedAgentCapabilities(),
                detail=str(exc),
            )
        capabilities = self._capabilities(record)
        if not bool(getattr(record, "a2a_ready", False)):
            return SupervisedAgentProbe(
                ready=False,
                capabilities=capabilities,
                detail="supervised Agent has not acknowledged its current CapToken",
            )
        url = f"http://127.0.0.1:{record.a2a_port}/ping"
        timeout_s = max(0.1, min(float(timeout_ms) / 1_000.0, 5.0))
        try:
            with urllib.request.urlopen(url, timeout=timeout_s) as response:  # noqa: S310
                raw = response.read(_PROBE_RESPONSE_LIMIT + 1)
            if len(raw) > _PROBE_RESPONSE_LIMIT:
                raise ValueError("A2A ping response exceeds 64KiB")
            document = json.loads(raw.decode("utf-8"))
        except (
            OSError,
            TimeoutError,
            UnicodeDecodeError,
            ValueError,
            json.JSONDecodeError,
            urllib.error.URLError,
        ) as exc:
            return SupervisedAgentProbe(
                ready=False,
                capabilities=capabilities,
                detail=f"A2A ping failed: {type(exc).__name__}",
            )
        if not isinstance(document, dict) or document.get("did") != target.agent_did:
            return SupervisedAgentProbe(
                ready=False,
                capabilities=capabilities,
                detail="A2A ping identity does not match the fixed target DID",
            )
        return SupervisedAgentProbe(
            ready=True,
            capabilities=capabilities,
            detail="verified localhost A2A identity",
        )

    def _turn_state_path(self, binding_id: str) -> Path | None:
        state = getattr(getattr(self._app, "state", None), "nth", None)
        workspace = getattr(state, "workspace", None)
        if workspace is None:
            return None
        key = hashlib.sha256(binding_id.encode("utf-8")).hexdigest()
        return (
            Path(workspace)
            / ".nth"
            / "plugin-host"
            / "supervised-turns"
            / f"{key}.json"
        )

    @staticmethod
    def _turn_tombstone_path(state_path: Path) -> Path:
        key = state_path.stem
        return state_path.parent / "tombstones" / key[:2] / state_path.name

    @classmethod
    def _archive_turn_tombstone(
        cls,
        path: Path,
        document: dict[str, Any],
    ) -> None:
        tombstone_path = cls._turn_tombstone_path(path)
        atomic_write_json(
            tombstone_path,
            document,
            ensure_ascii=True,
            indent=2,
        )
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    @classmethod
    def _compact_expired_turn_state(
        cls,
        path: Path,
        document: Any,
        now: int,
        *,
        force: bool = False,
    ) -> bool:
        if isinstance(document, dict) and document.get("state") in {
            "evicted",
            "expired",
            "receipt-reconciled",
            "rejected",
        }:
            cls._archive_turn_tombstone(path, document)
            return True
        if (
            not isinstance(document, dict)
            or document.get("state") != "completed"
            or not isinstance(document.get("result"), dict)
        ):
            return False
        completed_at = document.get("completed_at_epoch")
        expires_at = document.get("result_expires_at_epoch")
        if document.get("format") in {
            "nth-dao-supervised-turn-state-v2",
            "nth-dao-supervised-turn-state-v3",
        }:
            metadata_valid = (
                type(completed_at) is int
                and type(expires_at) is int
                and expires_at == completed_at + _TURN_RESULT_RETENTION_SECONDS
            )
            if not metadata_valid:
                expires_at = now
        else:
            try:
                observed_at = min(int(path.stat().st_mtime), now)
            except OSError:
                observed_at = now
            if type(completed_at) is not int:
                completed_at = observed_at
            expected_expiry = completed_at + _TURN_RESULT_RETENTION_SECONDS
            if type(expires_at) is not int or expires_at != expected_expiry:
                expires_at = expected_expiry
                document = {
                    **document,
                    "completed_at_epoch": completed_at,
                    "result_expires_at_epoch": expires_at,
                }
                if expires_at > now:
                    atomic_write_json(path, document, ensure_ascii=True, indent=2)
                    return False
        if expires_at > now and not force:
            return False
        result = document["result"]
        tombstone = {
            key: value
            for key, value in document.items()
            if key not in {"result", "state"}
        }
        tombstone.update(
            {
                "receipt_content_hash": result.get("receipt_content_hash", ""),
                "receipt_id": result.get("receipt_id", ""),
                "result_sha256": hashlib.sha256(canonical_json(result)).hexdigest(),
                "state": "expired" if expires_at <= now else "evicted",
            }
        )
        if expires_at > now:
            tombstone["result_evicted_at_epoch"] = now
        cls._archive_turn_tombstone(path, tombstone)
        return True

    def _maintain_turn_state_store(self, state_path: Path, *, now: int) -> None:
        directory = state_path.parent
        directory.mkdir(parents=True, exist_ok=True)
        for path in directory.glob("*.json"):
            document = safe_load_json(path, fallback=None)
            self._compact_expired_turn_state(path, document, now)
        hot_paths = list(directory.glob("*.json"))
        state_count = len(hot_paths)
        known_turn = state_path.exists() or self._turn_tombstone_path(
            state_path
        ).exists()
        if not known_turn and state_count >= _MAX_DURABLE_TURN_STATES:
            for path in sorted(
                hot_paths,
                key=lambda candidate: candidate.stat().st_mtime,
            ):
                document = safe_load_json(path, fallback=None)
                if self._compact_expired_turn_state(
                    path,
                    document,
                    now,
                    force=True,
                ):
                    state_count -= 1
                    if state_count < _MAX_DURABLE_TURN_STATES:
                        break
        if not known_turn and state_count >= _MAX_DURABLE_TURN_STATES:
            raise RuntimeError(
                "durable supervised unresolved-turn store is at capacity; "
                "operator review is required"
            )

    @staticmethod
    def _turn_result_document(result: SupervisedAgentTurnResult) -> dict[str, Any]:
        return {
            "content": result.content,
            "error": result.error,
            "finish_reason": result.finish_reason,
            "input_tokens": result.input_tokens,
            "latency_ms": result.latency_ms,
            "output_tokens": result.output_tokens,
            "receipt_content_hash": result.receipt_content_hash,
            "receipt_id": result.receipt_id,
            "tool_calls": [dict(item) for item in result.tool_calls],
        }

    def _restore_turn_result(
        self,
        target: SupervisedAgentTarget,
        request: SupervisedAgentTurnRequest,
        binding_id: str,
        execution_request_sha256: str,
        document: Any,
    ) -> SupervisedAgentTurnResult:
        if not isinstance(document, dict):
            raise RuntimeError("durable supervised turn state is malformed")
        self._restore_turn_result_bindings(
            target,
            binding_id,
            execution_request_sha256,
            document,
        )
        state = document.get("state")
        if state == "expired":
            raise RuntimeError(
                "supervised turn result retention expired; at-most-once policy "
                "prevents re-execution"
            )
        if state == "evicted":
            raise RuntimeError(
                "supervised turn result body was evicted by the bounded cache; "
                "at-most-once policy prevents re-execution"
            )
        if state == "started":
            raise RuntimeError(
                "supervised turn outcome is unknown after an interrupted execution"
            )
        if state == "receipt-reconciled":
            raise RuntimeError(
                "supervised turn completed according to a verified Receipt, but "
                "its response body is unavailable; re-execution is prohibited"
            )
        if state == "rejected":
            raise RuntimeError(
                "supervised turn response was rejected after dispatch; "
                "re-execution is prohibited"
            )
        if state != "completed" or not isinstance(document.get("result"), dict):
            raise RuntimeError("durable supervised turn state is invalid")
        raw = document["result"]
        tool_calls = raw.get("tool_calls")
        if not isinstance(tool_calls, list) or any(
            not isinstance(item, dict) for item in tool_calls
        ):
            raise RuntimeError("durable supervised turn tool calls are invalid")
        try:
            result = SupervisedAgentTurnResult(
                content=raw["content"],
                error=raw["error"],
                finish_reason=raw["finish_reason"],
                input_tokens=raw["input_tokens"],
                latency_ms=raw["latency_ms"],
                output_tokens=raw["output_tokens"],
                receipt_content_hash=raw.get("receipt_content_hash", ""),
                receipt_id=raw.get("receipt_id", ""),
                tool_calls=tuple(dict(item) for item in tool_calls),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("durable supervised turn result is malformed") from exc
        if result.finish_reason in {"stop", "length", "tool_call"}:
            self._verify_recovered_receipt(
                target,
                request,
                binding_id,
                execution_request_sha256,
                result,
            )
        return result

    @staticmethod
    def _restore_turn_result_bindings(
        target: SupervisedAgentTarget,
        binding_id: str,
        execution_request_sha256: str,
        document: Any,
    ) -> None:
        if not isinstance(document, dict):
            raise RuntimeError("durable supervised turn state is malformed")
        expected = {
            "agent_did": target.agent_did,
            "binding_id": binding_id,
            "execution_request_sha256": execution_request_sha256,
        }
        for field, value in expected.items():
            if document.get(field) != value:
                raise RuntimeError(
                    f"durable supervised turn {field} binding mismatch"
                )
        state_format = document.get("format")
        if state_format not in {
            "nth-dao-supervised-turn-state-v1",
            "nth-dao-supervised-turn-state-v2",
            "nth-dao-supervised-turn-state-v3",
        }:
            raise RuntimeError("durable supervised turn format binding mismatch")
        if (
            state_format == "nth-dao-supervised-turn-state-v3"
            and document.get("execution_target_revision")
            != target.execution_target_revision
        ):
            raise RuntimeError(
                "durable supervised turn execution target revision binding mismatch"
            )

    def _reconcile_dispatched_receipt(
        self,
        target: SupervisedAgentTarget,
        request: SupervisedAgentTurnRequest,
        binding_id: str,
        execution_request_sha256: str,
    ) -> dict[str, Any] | None:
        from nth_dao.web import v2_api

        state = getattr(getattr(self._app, "state", None), "nth", None)
        receipts = getattr(state, "receipts", None)
        if receipts is None:
            return None
        matches: list[dict[str, Any]] = []
        for receipt_id in receipts.list_ids():
            receipt = receipts.load(receipt_id)
            if not isinstance(receipt, dict):
                continue
            try:
                payload = v2_api._agent_link_receipt_payload(receipt)
            except ValueError:
                continue
            if (
                payload.get("agent_link_job_id") != binding_id
                or payload.get("execution_request_sha256")
                != execution_request_sha256
            ):
                continue
            self._validate_turn_receipt(
                target,
                request,
                binding_id,
                execution_request_sha256,
                receipt,
                response=None,
            )
            matches.append(receipt)
        if len(matches) > 1:
            raise RuntimeError(
                "multiple verified Receipts claim the same supervised turn binding"
            )
        return matches[0] if matches else None

    def _verify_recovered_receipt(
        self,
        target: SupervisedAgentTarget,
        request: SupervisedAgentTurnRequest,
        binding_id: str,
        execution_request_sha256: str,
        result: SupervisedAgentTurnResult,
    ) -> None:
        state = getattr(getattr(self._app, "state", None), "nth", None)
        receipts = getattr(state, "receipts", None)
        if receipts is None or not result.receipt_id:
            raise RuntimeError("durable supervised turn Receipt is unavailable")
        receipt = receipts.load(result.receipt_id)
        if not isinstance(receipt, dict):
            raise RuntimeError("durable supervised turn Receipt is missing")
        if receipt.get("content_hash") != result.receipt_content_hash:
            raise RuntimeError("durable supervised turn Receipt hash mismatch")
        verified = self._validate_turn_receipt(
            target,
            request,
            binding_id,
            execution_request_sha256,
            receipt,
            response=result.content,
            expected_receipt_id=result.receipt_id,
            expected_receipt_hash=result.receipt_content_hash,
        )
        expected_result = {
            "finish_reason": result.finish_reason,
            "input_tokens": result.input_tokens,
            "latency_ms": result.latency_ms,
            "output_tokens": result.output_tokens,
        }
        for field, value in expected_result.items():
            if verified[field] != value:
                raise RuntimeError(
                    f"durable supervised turn Receipt {field} mismatch"
                )

    @staticmethod
    def _validate_turn_receipt(
        target: SupervisedAgentTarget,
        request: SupervisedAgentTurnRequest,
        binding_id: str,
        execution_request_sha256: str,
        receipt: Any,
        *,
        response: str | None,
        expected_receipt_id: str = "",
        expected_receipt_hash: str = "",
    ) -> dict[str, Any]:
        from nth_dao.web import v2_api

        if not isinstance(receipt, dict):
            raise RuntimeError("A2A success Receipt is malformed")
        receipt_id = receipt.get("receipt_id")
        receipt_hash = receipt.get("content_hash")
        if not isinstance(receipt_id, str) or not receipt_id:
            raise RuntimeError("A2A success Receipt id is invalid")
        if (
            not isinstance(receipt_hash, str)
            or len(receipt_hash) != 64
            or any(char not in "0123456789abcdef" for char in receipt_hash)
        ):
            raise RuntimeError("A2A success Receipt content hash is invalid")
        if expected_receipt_id and receipt_id != expected_receipt_id:
            raise RuntimeError("A2A success Receipt id metadata mismatch")
        if expected_receipt_hash and receipt_hash != expected_receipt_hash:
            raise RuntimeError("A2A success Receipt hash metadata mismatch")
        v2_api._verify_agent_receipt(
            agent_id=target.agent_id,
            expected_did=target.agent_did,
            receipt=receipt,
        )
        payload = v2_api._agent_link_receipt_payload(receipt)
        response_hash = payload.get("response_sha256")
        if response is not None:
            try:
                response_bytes = response.strip().encode("utf-8")
            except UnicodeEncodeError as exc:
                raise RuntimeError("A2A response is not valid UTF-8 text") from exc
            if not response_bytes:
                raise RuntimeError("A2A response is empty")
            if len(response_bytes) > request.max_output_tokens:
                raise RuntimeError(
                    "A2A response exceeds the conservative output budget"
                )
            response_hash = hashlib.sha256(response_bytes).hexdigest()
        elif (
            not isinstance(response_hash, str)
            or len(response_hash) != 64
            or any(char not in "0123456789abcdef" for char in response_hash)
        ):
            raise RuntimeError("persisted Receipt response_sha256 is invalid")
        expected_bindings = {
            "agent_did": target.agent_did,
            "agent_link_job_id": binding_id,
            "execution_request_sha256": execution_request_sha256,
            "method": "ask",
            "request_sha256": hashlib.sha256(
                request.prompt.encode("utf-8")
            ).hexdigest(),
            "requested_model": request.model,
            "response_sha256": response_hash,
        }
        for field, expected in expected_bindings.items():
            if payload.get(field) != expected:
                raise RuntimeError(
                    f"persisted Receipt {field} does not match the plugin turn"
                )
        values = {
            "input_tokens": payload.get("input_tokens", 0),
            "output_tokens": payload.get("output_tokens", 0),
            "latency_ms": payload.get("elapsed_ms", 0),
        }
        for label, value in values.items():
            if type(value) is not int or not 0 <= value <= 1_000_000_000:
                raise RuntimeError(f"persisted Receipt {label} is invalid")
        if values["output_tokens"] > request.max_output_tokens:
            raise RuntimeError("persisted Receipt output_tokens exceeds turn budget")
        stop_reason = payload.get("stop_reason", "")
        if not isinstance(stop_reason, str) or len(stop_reason) > 64:
            raise RuntimeError("persisted Receipt stop_reason is invalid")
        values.update(
            {
                "finish_reason": (
                    "length"
                    if stop_reason.lower()
                    in {"length", "max_tokens", "max_output_tokens"}
                    else "stop"
                ),
                "receipt_content_hash": receipt_hash,
                "receipt_id": receipt_id,
            }
        )
        return values

    def turn(
        self,
        target: SupervisedAgentTarget,
        request: SupervisedAgentTurnRequest,
    ) -> SupervisedAgentTurnResult:
        # Reject a sync-on-event-loop integration error before creating even a
        # prepared idempotency record. No A2A dispatch can have occurred yet.
        _require_sync_bridge_thread()
        binding_id = _turn_binding_id(target, request)
        execution_request_sha256 = _execution_request_sha256(target, request)
        state_path = self._turn_state_path(binding_id)
        if state_path is None:
            raise RuntimeError(
                "durable supervised turn store is unavailable; refusing dispatch"
            )
        lock_timeout = max(10.0, min(request.timeout_ms / 1_000.0 + 5.0, 310.0))
        with InterProcessLock(state_path, timeout=lock_timeout):
            now = int(time.time())
            with InterProcessLock(
                state_path.parent / ".store-maintenance",
                timeout=min(lock_timeout, 10.0),
            ):
                self._maintain_turn_state_store(state_path, now=now)
            tombstone_path = self._turn_tombstone_path(state_path)
            state_exists = state_path.exists()
            tombstone_exists = tombstone_path.exists()
            document = (
                safe_load_json(state_path, fallback=None)
                if state_exists
                else (
                    safe_load_json(tombstone_path, fallback=None)
                    if tombstone_exists
                    else None
                )
            )
            if (state_exists or tombstone_exists) and document is None:
                raise RuntimeError("durable supervised turn state is malformed")
            if document is not None:
                state = document.get("state") if isinstance(document, dict) else None
                if state in {"started", "dispatched"}:
                    receipt = self._reconcile_dispatched_receipt(
                        target,
                        request,
                        binding_id,
                        execution_request_sha256,
                    )
                    if receipt is None:
                        raise SupervisedAgentOutcomeUnknown(
                            "supervised turn outcome is unknown after dispatch"
                        )
                    reconciled = {
                        key: value
                        for key, value in document.items()
                        if key != "state"
                    }
                    reconciled.update(
                        {
                            "receipt_content_hash": receipt.get("content_hash", ""),
                            "receipt_id": receipt.get("receipt_id", ""),
                            "reconciled_at_epoch": int(time.time()),
                            "state": "receipt-reconciled",
                        }
                    )
                    atomic_write_json(
                        state_path,
                        reconciled,
                        ensure_ascii=True,
                        indent=2,
                    )
                    return self._restore_turn_result(
                        target,
                        request,
                        binding_id,
                        execution_request_sha256,
                        reconciled,
                    )
                if state != "prepared":
                    return self._restore_turn_result(
                        target,
                        request,
                        binding_id,
                        execution_request_sha256,
                        document,
                    )
                self._restore_turn_result_bindings(
                    target,
                    binding_id,
                    execution_request_sha256,
                    document,
                )
            expected_record = self._record(target)
            base = {
                "agent_did": target.agent_did,
                "agent_id": str(getattr(expected_record, "agent_id", "") or ""),
                "a2a_port": getattr(expected_record, "a2a_port", None),
                "binding_id": binding_id,
                "created_at_epoch": (
                    document.get("created_at_epoch", now)
                    if isinstance(document, dict)
                    else now
                ),
                "execution_request_sha256": execution_request_sha256,
                "execution_target_revision": target.execution_target_revision,
                "format": "nth-dao-supervised-turn-state-v3",
            }
            atomic_write_json(
                state_path,
                {**base, "state": "prepared"},
                ensure_ascii=True,
                indent=2,
            )

            def mark_dispatched() -> None:
                atomic_write_json(
                    state_path,
                    {
                        **base,
                        "dispatched_at_epoch": int(time.time()),
                        "state": "dispatched",
                    },
                    ensure_ascii=True,
                    indent=2,
                )

            try:
                result = self._turn_once(
                    target,
                    request,
                    expected_record=expected_record,
                    on_dispatch=mark_dispatched,
                )
            except SupervisedAgentOutcomeUnknown:
                raise
            except Exception:
                current = safe_load_json(state_path, fallback=None)
                if isinstance(current, dict) and current.get("state") == "dispatched":
                    self._archive_turn_tombstone(
                        state_path,
                        {
                            **base,
                            "rejected_at_epoch": int(time.time()),
                            "state": "rejected",
                        },
                    )
                raise
            atomic_write_json(
                state_path,
                {
                    **base,
                    "completed_at_epoch": int(time.time()),
                    "result": self._turn_result_document(result),
                    "result_expires_at_epoch": int(time.time())
                    + _TURN_RESULT_RETENTION_SECONDS,
                    "state": "completed",
                },
                ensure_ascii=True,
                indent=2,
            )
            return result

    def _turn_once(
        self,
        target: SupervisedAgentTarget,
        request: SupervisedAgentTurnRequest,
        *,
        expected_record: Any | None = None,
        on_dispatch: Callable[[], None] | None = None,
    ) -> SupervisedAgentTurnResult:
        from nth_dao.web import v2_api

        if expected_record is None:
            expected_record = self._record(target)
        binding_id = _turn_binding_id(target, request)
        execution_request_sha256 = _execution_request_sha256(target, request)
        payload = {
            "agent_link_job_id": binding_id,
            "execution_request_sha256": execution_request_sha256,
            "max_tokens": request.max_output_tokens,
            "prompt": request.prompt,
            "timeout_s": request.timeout_ms / 1_000.0,
        }
        if request.model:
            payload["model"] = request.model
        operation = v2_api._drive_supervised_agent_ask(
            _request_for_app(self._app),
            target.agent_did,
            payload,
            expected_agent_id=str(
                getattr(expected_record, "agent_id", "") or ""
            ),
            expected_a2a_port=getattr(expected_record, "a2a_port", None),
            on_dispatch=on_dispatch,
        )
        started = time.monotonic()
        try:
            status, content, record, receipt_meta = _run_coroutine(
                operation,
                timeout_s=request.timeout_ms / 1_000.0 + 1.0,
            )
        except Exception as exc:
            raise SupervisedAgentOutcomeUnknown(
                "supervised turn crossed the dispatch boundary without "
                "a trusted terminal result"
            ) from exc
        elapsed_ms = int((time.monotonic() - started) * 1_000)
        if (
            str(getattr(record, "did", "") or "") != target.agent_did
            or str(getattr(record, "agent_id", "") or "")
            != str(getattr(expected_record, "agent_id", "") or "")
            or getattr(record, "a2a_port", None)
            != getattr(expected_record, "a2a_port", None)
        ):
            raise RuntimeError("A2A response record escaped the fixed target binding")
        if status != 200:
            error = content.get("error") if isinstance(content, dict) else None
            code = str(error.get("code") or "") if isinstance(error, dict) else ""
            if code not in _PUBLIC_AGENT_ERROR_CODES:
                code = "upstream-error"
            detail = (
                f"supervised Agent request timed out ({code})"
                if status == 504
                else f"supervised Agent request failed ({code})"
            )
            return SupervisedAgentTurnResult(
                content="",
                finish_reason="timeout" if status == 504 else "error",
                latency_ms=elapsed_ms,
                error=detail,
            )
        if not isinstance(content, dict):
            raise RuntimeError("A2A ask returned a non-object success envelope")
        result = content.get("result")
        if not isinstance(result, dict):
            raise RuntimeError("A2A ask returned no result object")
        response = result.get("response")
        receipt = result.get("receipt")
        if not isinstance(response, str):
            raise RuntimeError("A2A ask response must be text")
        if not isinstance(receipt, dict) or not isinstance(receipt_meta, dict):
            raise RuntimeError("A2A success is missing a verified persisted Receipt")
        receipt_id = receipt.get("receipt_id")
        receipt_hash = receipt.get("content_hash")
        if (
            not isinstance(receipt_id, str)
            or not receipt_id
            or receipt_meta.get("nth_receipt_id") != receipt_id
            or not isinstance(receipt_hash, str)
            or not receipt_hash
            or receipt_meta.get("nth_receipt_content_hash") != receipt_hash
        ):
            raise RuntimeError(
                "A2A success Receipt does not match the persisted Receipt metadata"
            )
        verified = self._validate_turn_receipt(
            target,
            request,
            binding_id,
            execution_request_sha256,
            receipt,
            response=response,
            expected_receipt_id=str(receipt_meta["nth_receipt_id"]),
            expected_receipt_hash=str(receipt_meta["nth_receipt_content_hash"]),
        )
        return SupervisedAgentTurnResult(
            content=response,
            finish_reason=verified["finish_reason"],
            input_tokens=verified["input_tokens"],
            output_tokens=verified["output_tokens"],
            latency_ms=verified["latency_ms"],
            receipt_id=verified["receipt_id"],
            receipt_content_hash=verified["receipt_content_hash"],
        )

    def cancel(
        self,
        target: SupervisedAgentTarget,
        *,
        session_id: str,
        turn_id: str,
    ) -> bool:
        del target, session_id, turn_id
        # Current SDK/CLI-backed children cannot interrupt an in-flight call.
        # Returning False preserves truth; killing the whole child is not a
        # session-scoped cancellation acknowledgement.
        return False


def _execution_target_revision(record: Any) -> str:
    """Hash the stable execution boundary while excluding transport churn."""

    agent_id = str(getattr(record, "agent_id", "") or "")
    did = str(getattr(record, "did", "") or "")
    kind = str(getattr(record, "kind", "supervised") or "supervised")
    if not agent_id or len(agent_id) > 128:
        raise ValueError("record must expose a bounded Agent ID")
    if len(did) > 512:
        raise ValueError("record DID is too long")
    if not kind or len(kind) > 128:
        raise ValueError("record kind must be bounded text")
    raw_capabilities = getattr(record, "capabilities", ())
    if not isinstance(raw_capabilities, (list, tuple, set, frozenset)):
        raise ValueError("record capabilities must be a bounded collection")
    if (
        len(raw_capabilities) > 256
        or any(
            not isinstance(capability, str)
            or not capability
            or len(capability) > 256
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in capability)
            for capability in raw_capabilities
        )
    ):
        raise ValueError("record capabilities are invalid")
    capabilities = tuple(sorted(set(raw_capabilities)))
    work_scope = getattr(record, "work_scope", None)
    root = str(getattr(work_scope, "root", "") or "")
    access = str(getattr(work_scope, "access", "workspace-write") or "")
    revision = str(getattr(work_scope, "revision", "") or "")
    if len(root) > 32_768:
        raise ValueError("record work-scope root is too long")
    if access not in {"read-only", "workspace-write"}:
        raise ValueError("record work-scope access is invalid")
    if len(revision) > 128:
        raise ValueError("record work-scope revision is too long")
    document = {
        "agent_did": did,
        "agent_id": agent_id,
        "agent_kind": kind,
        "backend_id": _BACKEND_ID,
        "capabilities": list(capabilities),
        "format": "nth-dao-supervised-execution-target-v1",
        "work_scope": {
            "access": access,
            # Never persist an operator's local absolute path. The full digest
            # still binds it more strongly than WorkScope.scope_id's UI prefix.
            "root_sha256": (
                hashlib.sha256(root.encode("utf-8")).hexdigest() if root else ""
            ),
            "revision": revision,
        },
    }
    return hashlib.sha256(canonical_json(document)).hexdigest()


def ensure_supervised_agent_plugin(app: Any, supervisor: Any, record: Any) -> str:
    """Register one live Agent as a disabled fixed-DID provider plugin."""

    did = str(getattr(record, "did", "") or "")
    raw_port = getattr(record, "a2a_port", None)
    if (
        not did
        or isinstance(raw_port, bool)
        or not isinstance(raw_port, int)
        or not 1 <= raw_port <= 65_535
    ):
        raise ValueError("record must expose a DID and localhost A2A port")
    agent_id = str(getattr(record, "agent_id", "") or "")
    if not agent_id:
        raise ValueError("record must expose a non-empty Agent ID")
    state = getattr(getattr(app, "state", None), "nth", None)
    host = getattr(state, "plugin_host", None)
    if host is None:
        raise RuntimeError("application plugin host is unavailable")
    execution_target_revision = _execution_target_revision(record)
    plugin_id = supervised_agent_plugin_id(did)
    fingerprint = (
        agent_id,
        raw_port,
        execution_target_revision,
    )
    binding_fingerprints = getattr(state, "supervised_plugin_bindings", None)
    if binding_fingerprints is None:
        binding_fingerprints = {}
        setattr(state, "supervised_plugin_bindings", binding_fingerprints)
    lifecycle_lock = getattr(state, "plugin_lifecycle_lock", None)
    guard = lifecycle_lock if lifecycle_lock is not None else nullcontext()
    with guard:
        try:
            status = host.status(plugin_id)
        except KeyError:
            status = None
        if status is not None:
            if (
                status.declared_permissions != ("network.client",)
                or status.provided_capabilities
                != ("org.nth-dao.agent.session",)
            ):
                raise RuntimeError(
                    "existing fixed-DID plugin has an incompatible contract"
                )
            if binding_fingerprints.get(plugin_id) == fingerprint:
                return plugin_id
            authorized = set(status.authorized_permissions)
            restore_enabled = status.state == "enabled" or status.desired_enabled
            if status.state in {"enabled", "cleanup-failed"}:
                host.disable(plugin_id)
            host.uninstall(plugin_id)
        target = SupervisedAgentTarget(
            agent_id=agent_id,
            agent_did=did,
            backend_id=_BACKEND_ID,
            execution_target_revision=execution_target_revision,
        )
        register_supervised_agent_provider(
            host,
            target,
            WebSupervisedAgentInvoker(
                app,
                supervisor,
                expected_agent_id=agent_id,
                expected_a2a_port=raw_port,
            ),
            reviewed_artifact_paths=_WEB_REVIEWED_ARTIFACT_PATHS,
        )
        if status is not None:
            host.authorize(plugin_id, authorized)
            if restore_enabled:
                host.enable(plugin_id)
        binding_fingerprints[plugin_id] = fingerprint
        return plugin_id


def disable_supervised_agent_plugins(app: Any) -> dict[str, str]:
    """Revoke all active fixed-DID providers before Supervisor shutdown."""

    state = getattr(getattr(app, "state", None), "nth", None)
    host = getattr(state, "plugin_host", None)
    if host is None:
        return {}
    outcomes: dict[str, str] = {}
    lifecycle_lock = getattr(state, "plugin_lifecycle_lock", None)
    guard = lifecycle_lock if lifecycle_lock is not None else nullcontext()
    with guard:
        statuses = tuple(host.list_status())
        for status in statuses:
            plugin_id = status.plugin_id
            suffix = plugin_id.removeprefix("org.nth-dao.agent.s")
            if (
                suffix == plugin_id
                or len(suffix) != 24
                or any(char not in "0123456789abcdef" for char in suffix)
            ):
                continue
            if status.state not in {"enabled", "cleanup-failed"}:
                outcomes[plugin_id] = status.state
                continue
            try:
                host.disable(plugin_id)
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                outcomes[plugin_id] = f"cleanup-failed:{type(exc).__name__}"
            else:
                outcomes[plugin_id] = "disabled"
    return outcomes


def retire_supervised_agent_plugin(
    app: Any,
    agent_did: str,
    *,
    keep_installed: bool,
) -> tuple[str, str]:
    """Disable one fixed-DID provider and optionally uninstall its record."""

    plugin_id = supervised_agent_plugin_id(agent_did)
    state = getattr(getattr(app, "state", None), "nth", None)
    host = getattr(state, "plugin_host", None)
    if host is None:
        raise RuntimeError("application plugin host is unavailable")
    lifecycle_lock = getattr(state, "plugin_lifecycle_lock", None)
    guard = lifecycle_lock if lifecycle_lock is not None else nullcontext()
    with guard:
        try:
            status = host.status(plugin_id)
        except KeyError:
            return plugin_id, "not-installed"
        if status.state in {"enabled", "cleanup-failed"}:
            host.disable(plugin_id)
            status = host.status(plugin_id)
        if keep_installed:
            return plugin_id, status.state
        host.uninstall(plugin_id)
        binding_fingerprints = getattr(state, "supervised_plugin_bindings", None)
        if isinstance(binding_fingerprints, dict):
            binding_fingerprints.pop(plugin_id, None)
        return plugin_id, "uninstalled"


__all__ = [
    "WebSupervisedAgentInvoker",
    "_execution_request_sha256",
    "_execution_target_revision",
    "disable_supervised_agent_plugins",
    "ensure_supervised_agent_plugin",
    "retire_supervised_agent_plugin",
]
