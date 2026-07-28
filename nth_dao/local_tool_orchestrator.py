"""Local tool orchestrator — the user's own subprocess dispatcher
for CLI-based AI assistants (Claude Code, Codex CLI, OpenClaw, etc).

═══════════════════════════════════════════════════════════════════
Identity model (CRITICAL — read before extending)
═══════════════════════════════════════════════════════════════════

Per the NTH DAO reframe (2026-06-08): identity belongs to the
**user**, not to the AI model. Models evolve (Claude 3.7 → 4.7 →
4.8 → …), tools rotate (claude-cli today, codex tomorrow,
hermes-agent next week), but the user's DID is stable across all
of them. This module does NOT mint a DID for the subprocess —
that would be cosplay; the subprocess has no keypair and cannot
sign anything.

Instead, every invocation through this module:

  1. Runs under the **workspace node identity** (the user's DID)
  2. Is recorded as a ``tool_invoked`` + ``tool_result`` entry on
     the receipt timeline, with the tool's name, version, and the
     invocation role (``planner`` / ``reviewer`` / ``executor``)
  3. Is signed by the workspace identity — so the audit chain reads
     "user X (via tool: claude-cli v1.2.3, role: planner) produced
     output digest Y at time T"
  4. Includes ``via_subscription: true`` in the timeline payload —
     **deliberate honesty**: if Anthropic / OpenAI later audits the
     workspace, the receipts truthfully say "this output came from
     the user's subscription account", not "from an autonomous
     paid-API agent".

This positioning preserves NTH DAO's "useful trace" promise: a
1000-year archive of NTH receipts shows that user X used Claude 3.7
on date D to do step S — a piece of human-AI collaboration history
that doesn't get erased when Claude 4.7 ships.

═══════════════════════════════════════════════════════════════════
TOS-risk policy (read this too)
═══════════════════════════════════════════════════════════════════

Anthropic / OpenAI consumer subscriptions forbid 24/7 automated
polling. This module enforces three rules at the type-system level
so the policy can't drift by accident:

  * **No polling loop in this module.** ``invoke()`` is a pure
    one-shot API. If the caller wants to drive a worker loop, they
    have to write it themselves, AND the module's hard rate-limit
    will throttle them.

  * **Hard per-tool per-hour rate cap.** Configurable, default 10
    calls/hour for ``claude``, 5/hour for ``codex``. Burst above the
    cap raises ``ToolRateLimitExceeded``; the caller must either
    wait, drop the request, or switch to a different tool.

  * **Default invocation-mode is interactive-confirmation.** The CLI
    entry point asks the operator to confirm each invocation (with
    a default ``yes`` so it doesn't get in the way for trusted
    workflows). Programmatic use requires ``--unattended`` AND a
    ``NTH_TOOL_UNATTENDED=1`` env var — making accidental daemon
    deployment harder.

═══════════════════════════════════════════════════════════════════
What this module is NOT
═══════════════════════════════════════════════════════════════════

  * NOT a "worker agent" — it doesn't claim Mission steps on its
    own; the operator (or a separate orchestrator) decides which
    work the local tool gets.
  * NOT a third-party A2A participant — it doesn't appear on
    /.well-known/agent.json as a separate Agent.
  * NOT a cap-token holder — subscription CLIs don't have a DID;
    the cap-token model has nowhere to bind.
  * NOT a way to monetize subscription seats — see the deliberate
    honesty rule above; receipts mark via_subscription=true.

For programmatic-agent integration (an autonomous agent with its
OWN DID and a cap_token bound to a task), use the Anthropic /
OpenAI APIs, NOT subscription CLIs. See README.md §"API vs CLI
agent integration" for the trade-off.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from nth_dao.execution_receipt import (
    ReceiptStore,
    TYPE_TOOL_INVOKED,
    TYPE_TOOL_RESULT,
    TimelineEntry,
    now_ms,
)

if TYPE_CHECKING:
    from nth_dao.identity import AgentIdentity

logger = logging.getLogger("nth_dao.local_tool_orchestrator")


# ─── tool roles ──────────────────────────────────────────────────────

ROLE_PLANNER = "planner"
ROLE_REVIEWER = "reviewer"
ROLE_EXECUTOR = "executor"
ROLE_OTHER = "other"

KNOWN_ROLES = frozenset({
    ROLE_PLANNER, ROLE_REVIEWER, ROLE_EXECUTOR, ROLE_OTHER,
})


# ─── known tool registry ─────────────────────────────────────────────

# Default rate caps per hour. Tuned to be **comfortably below** the
# threshold at which a single human user starts to look like a bot:
# 10 Claude calls/hour ≈ one every 6 minutes during active work,
# which is well within "human in the loop" pacing.
DEFAULT_RATE_LIMITS: Dict[str, int] = {
    "claude":   10,   # Claude Code CLI
    "codex":     5,   # OpenAI Codex CLI
    "openclaw": 20,   # OpenClaw (no subscription TOS risk)
    "hermes":   60,   # Hermes (local; no external rate concerns)
}


@dataclass(frozen=True)
class ToolSpec:
    """Discovered CLI tool. Constructed by ``detect_tools``."""
    name: str               # ``claude`` / ``codex`` / …
    path: str               # absolute path to the executable
    version: str            # best-effort version string (or "")
    via_subscription: bool  # True for Claude/Codex consumer CLIs

    def __repr__(self) -> str:
        return (
            f"ToolSpec(name={self.name!r}, path={self.path!r}, "
            f"version={self.version!r}, "
            f"via_subscription={self.via_subscription})"
        )


# ─── exceptions ──────────────────────────────────────────────────────


class ToolNotFound(LookupError):
    """The requested CLI tool isn't on PATH or wasn't registered."""


class ToolRateLimitExceeded(RuntimeError):
    """Caller exceeded the hard per-tool rate cap. Wait or switch."""


class ToolInvocationFailed(RuntimeError):
    """The subprocess returned a non-zero exit code. The receipt
    is still emitted (with ok=False) so the failed attempt is part
    of the audit trail."""


# ─── tool discovery ──────────────────────────────────────────────────


def _probe_version(executable: str) -> str:
    """Best-effort: run ``<exe> --version`` and capture the output.

    Returns empty string on any failure — version is metadata, not a
    correctness gate. Subprocess timeout is short (2s) so a hung
    binary doesn't block startup.
    """
    try:
        proc = subprocess.run(
            [executable, "--version"],
            capture_output=True, text=True,
            timeout=2.0,
            check=False,
        )
        out = (proc.stdout or proc.stderr or "").strip()
        return out.splitlines()[0][:80] if out else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


# Subscription-CLI fingerprint: tools that authenticate via a
# personal OAuth subscription rather than a programmatic API key.
# Listing here is what triggers the ``via_subscription=true`` honest
# marker on the receipt timeline.
_SUBSCRIPTION_CLI_NAMES = frozenset({"claude", "codex"})


def detect_tools(
    *,
    extra_paths: Optional[List[str]] = None,
) -> Dict[str, ToolSpec]:
    """Find all known CLI tools on PATH.

    Args:
        extra_paths: optional list of directories prepended to PATH
            during the search. Useful for Windows where Claude Code
            installs to ``%APPDATA%/npm-global`` which is on PATH for
            interactive shells but not always for child processes.

    Returns:
        ``{tool_name: ToolSpec}`` — only tools actually present.
    """
    found: Dict[str, ToolSpec] = {}

    # Build an effective PATH for shutil.which probing
    effective_path = os.environ.get("PATH", "")
    if extra_paths:
        effective_path = os.pathsep.join(
            [*extra_paths, effective_path]
        )

    for name in DEFAULT_RATE_LIMITS:
        # On Windows the executable may have a ``.cmd`` or ``.exe``
        # suffix. ``shutil.which`` handles PATHEXT for us.
        located = shutil.which(name, path=effective_path)
        if not located:
            continue
        found[name] = ToolSpec(
            name=name,
            path=located,
            version=_probe_version(located),
            via_subscription=(name in _SUBSCRIPTION_CLI_NAMES),
        )
    return found


# ─── rate limiter ────────────────────────────────────────────────────


class _RateLimiter:
    """Simple sliding-window rate limiter per tool name.

    Trade-off: in-memory only. A process restart resets the
    counters, which means a malicious operator could escape the cap
    by restarting frequently. For v1 the rate cap is a SAFETY GUARD
    against accidental polling-induced bans, not a security feature
    against a deliberately-bad operator. (The operator already has
    the workspace identity and can sign anything they want.)
    """

    def __init__(self, limits: Dict[str, int]) -> None:
        self.limits = dict(limits)
        self._hits: Dict[str, List[float]] = {}
        self._lock = RLock()

    def check_and_record(self, tool_name: str) -> None:
        """Raise ``ToolRateLimitExceeded`` if the call would exceed
        the cap. Otherwise record the invocation."""
        limit = self.limits.get(tool_name, 0)
        if limit <= 0:
            # No cap configured for this tool — pass through
            return
        now = time.time()
        window_start = now - 3600.0
        with self._lock:
            recent = [
                t for t in self._hits.get(tool_name, [])
                if t > window_start
            ]
            if len(recent) >= limit:
                # Compute wait suggestion
                next_slot = recent[0] + 3600.0
                wait_s = max(0.0, next_slot - now)
                raise ToolRateLimitExceeded(
                    f"{tool_name}: {len(recent)}/{limit} calls in "
                    f"the last hour. Wait {wait_s:.0f}s, switch "
                    f"tool, or raise the cap via rate_limits."
                )
            recent.append(now)
            self._hits[tool_name] = recent


# ─── result + main orchestrator ──────────────────────────────────────


@dataclass
class ToolResult:
    """One invocation's outcome — signed and persisted via the
    receipt store before returning."""
    tool: str
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int
    args_hash: str
    receipt_id: str = ""
    via_subscription: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


# Each tool gets a different argv shape. Centralised here so the
# subprocess call sites stay symmetric.
_ARGV_BUILDERS = {
    # Claude Code: ``claude -p "<prompt>" --output-format json``
    "claude": lambda exe, prompt, _opts: [
        exe, "-p", prompt, "--output-format", "json",
    ],
    # OpenAI Codex CLI: ``codex exec "<prompt>" --json``
    "codex": lambda exe, prompt, _opts: [
        exe, "exec", prompt, "--json",
    ],
    # OpenClaw: ``openclaw run "<prompt>"`` (placeholder — adjust to
    # real CLI when integrating)
    "openclaw": lambda exe, prompt, _opts: [exe, "run", prompt],
    # Hermes: ``hermes ask "<prompt>"``  (placeholder)
    "hermes": lambda exe, prompt, _opts: [exe, "ask", prompt],
}


class LocalToolOrchestrator:
    """The user's local tool dispatcher.

    Construct ONCE per workspace; reuse across invocations so the
    rate limiter accumulates correctly.
    """

    def __init__(
        self,
        *,
        identity: "AgentIdentity",
        receipt_store: ReceiptStore,
        rate_limits: Optional[Dict[str, int]] = None,
        tool_overrides: Optional[Dict[str, ToolSpec]] = None,
        timeout_s: float = 120.0,
    ) -> None:
        """
        Args:
            identity: the workspace's ``AgentIdentity``. ALL receipts
                are signed by this identity — there is no
                "sub-identity" for the subprocess.
            receipt_store: where signed receipts get persisted.
            rate_limits: optional override for per-tool per-hour
                caps. Falls back to ``DEFAULT_RATE_LIMITS``.
            tool_overrides: optional dict of pre-discovered tools
                (skip the PATH probe — useful for tests).
            timeout_s: subprocess timeout per invocation. A
                misbehaving tool that hangs would otherwise prevent
                the orchestrator from emitting a tool_result entry.
        """
        self.identity = identity
        self.receipts = receipt_store
        self._tools = tool_overrides or detect_tools()
        self._rate = _RateLimiter(rate_limits or DEFAULT_RATE_LIMITS)
        self.timeout_s = timeout_s

    @property
    def available_tools(self) -> List[str]:
        return sorted(self._tools.keys())

    def invoke(
        self,
        tool_name: str,
        prompt: str,
        *,
        role: str = ROLE_OTHER,
        goal_id: str = "",
        extra_options: Optional[Dict[str, Any]] = None,
    ) -> ToolResult:
        """Invoke a tool subprocess, sign a receipt, return the result.

        Args:
            tool_name: must be in ``available_tools``.
            prompt: the user-facing prompt forwarded to the CLI.
            role: one of ``KNOWN_ROLES`` — surfaces in the receipt
                timeline so a reviewer can tell whether this
                invocation was a plan, a review, or actual execution.
            goal_id: optional opaque ID (e.g. a Mission ID) for
                grouping receipts. Empty is fine for ad-hoc calls.
            extra_options: free-form dict passed to the argv builder.
                Currently unused for the four bundled tools but
                makes the API future-proof.

        Raises:
            ToolNotFound, ToolRateLimitExceeded, ToolInvocationFailed.
        """
        if tool_name not in self._tools:
            raise ToolNotFound(
                f"tool {tool_name!r} not detected. Available: "
                f"{self.available_tools}"
            )
        if role not in KNOWN_ROLES:
            raise ValueError(
                f"role must be one of {sorted(KNOWN_ROLES)}; "
                f"got {role!r}"
            )

        self._rate.check_and_record(tool_name)

        spec = self._tools[tool_name]
        builder = _ARGV_BUILDERS.get(tool_name)
        if builder is None:
            raise ToolNotFound(
                f"no argv builder registered for {tool_name!r}; "
                f"extend _ARGV_BUILDERS"
            )
        argv = builder(spec.path, prompt, extra_options or {})

        # Hash the args ONCE — used in both timeline entries so they
        # can be correlated even if the prompt contains secrets we'd
        # rather not bake into the receipt.
        args_hash = hashlib.sha256(
            ("\n".join(str(a) for a in argv)).encode("utf-8")
        ).hexdigest()

        # Build invocation entry FIRST so we can sign a receipt
        # even if the subprocess crashes mid-run.
        invocation_entry = TimelineEntry(
            timestamp=now_ms(),
            type=TYPE_TOOL_INVOKED,
            payload={
                "tool": tool_name,
                "tool_version": spec.version,
                "invocation_role": role,
                "args_hash": args_hash,
                "via_subscription": spec.via_subscription,
            },
        )

        start = time.monotonic()
        stdout = ""
        stderr = ""
        exit_code = -1
        timed_out = False
        try:
            proc = subprocess.run(
                argv,
                capture_output=True, text=True,
                timeout=self.timeout_s,
                check=False,
            )
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            exit_code = proc.returncode
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout = (exc.stdout or b"")
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", errors="replace")
            stderr = (
                f"[orchestrator] tool {tool_name!r} timed out after "
                f"{self.timeout_s}s"
            )
        duration_ms = int((time.monotonic() - start) * 1000)

        result_entry = TimelineEntry(
            timestamp=now_ms(),
            type=TYPE_TOOL_RESULT,
            payload={
                "tool": tool_name,
                "ok": (exit_code == 0 and not timed_out),
                "exit_code": exit_code,
                "duration_ms": duration_ms,
                "timed_out": timed_out,
                "stdout_digest": hashlib.sha256(
                    stdout.encode("utf-8")
                ).hexdigest(),
                "stderr_digest": hashlib.sha256(
                    stderr.encode("utf-8")
                ).hexdigest(),
                "args_hash": args_hash,
            },
        )

        receipt_id = ""
        try:
            receipt = self.receipts.sign_and_save(
                [invocation_entry, result_entry],
                self.identity,
                goal_id=goal_id,
            )
            receipt_id = receipt["receipt_id"]
        except (OSError, ValueError, RuntimeError) as exc:
            # The work-proof chain breaks for this invocation;
            # logging at ERROR per the MA-2 convention so the
            # operator sees it.
            logger.error(
                "tool receipt emission failed for %s (%s): %s",
                tool_name, type(exc).__name__, exc,
            )

        result = ToolResult(
            tool=tool_name,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            duration_ms=duration_ms,
            args_hash=args_hash,
            receipt_id=receipt_id,
            via_subscription=spec.via_subscription,
        )
        if not result.ok and not timed_out:
            # Non-zero exit code is something the caller needs to
            # see explicitly. The receipt is already persisted so
            # the audit trail is intact whether the caller handles
            # the exception or not.
            raise ToolInvocationFailed(
                f"{tool_name} exited with code {exit_code}: "
                f"{stderr[:200]}"
            )
        if timed_out:
            raise ToolInvocationFailed(
                f"{tool_name} timed out after {self.timeout_s}s"
            )
        return result


# ─── CLI entry (one-shot, opt-in unattended) ─────────────────────────


def _build_arg_parser():
    import argparse
    parser = argparse.ArgumentParser(
        description=(
            "Local tool orchestrator — invoke a CLI AI assistant "
            "(Claude / Codex / OpenClaw / Hermes) and produce a "
            "signed NTH DAO receipt."
        ),
    )
    parser.add_argument(
        "--tool",
        required=True,
        help="Tool name (claude, codex, openclaw, hermes).",
    )
    parser.add_argument(
        "--prompt",
        required=True,
        help="Prompt to forward to the tool.",
    )
    parser.add_argument(
        "--role",
        choices=sorted(KNOWN_ROLES),
        default=ROLE_OTHER,
        help="Invocation role recorded on the receipt timeline.",
    )
    parser.add_argument(
        "--goal-id",
        default="",
        help="Optional Mission/Goal ID to group receipts by.",
    )
    parser.add_argument(
        "--unattended",
        action="store_true",
        help=(
            "Skip the interactive confirmation. Requires the "
            "``NTH_TOOL_UNATTENDED=1`` env var to be set — guards "
            "against accidental daemon deployment."
        ),
    )
    parser.add_argument(
        "--workspace",
        default="",
        help=(
            "Workspace path (defaults to ``~/.nth-dao``). The "
            "node identity is loaded from "
            "``<workspace>/.nth/identity.json``."
        ),
    )
    return parser


def _resolve_workspace(arg_value: str) -> Path:
    if arg_value:
        return Path(arg_value).expanduser().resolve()
    return Path.home() / ".nth-dao"


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point.

    Default mode requires interactive confirmation per invocation.
    Use ``--unattended`` plus ``NTH_TOOL_UNATTENDED=1`` to bypass —
    the env var is intentional friction to prevent accidental
    polling-loop deployment.
    """
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    if args.unattended and os.environ.get("NTH_TOOL_UNATTENDED") != "1":
        print(
            "[orchestrator] --unattended requires "
            "NTH_TOOL_UNATTENDED=1 in the environment. Refusing.",
        )
        return 2

    workspace = _resolve_workspace(args.workspace)
    # Late imports — keep module-load fast for ``--help``.
    from nth_dao.identity import AgentIdentity, default_identity_path
    ident_path = default_identity_path(workspace)
    if not ident_path.exists():
        print(
            f"[orchestrator] no identity at {ident_path}; "
            f"run ``nth-web`` once to bootstrap.",
        )
        return 3
    identity = AgentIdentity.load(ident_path)
    receipts = ReceiptStore(workspace)

    orch = LocalToolOrchestrator(
        identity=identity, receipt_store=receipts,
    )

    if args.tool not in orch.available_tools:
        print(
            f"[orchestrator] tool {args.tool!r} not detected. "
            f"Available: {orch.available_tools}",
        )
        return 4

    if not args.unattended:
        spec = orch._tools[args.tool]   # pylint: disable=protected-access
        print(
            f"About to invoke: {spec.name} (v{spec.version or '?'}) "
            f"as role={args.role}",
        )
        if spec.via_subscription:
            print(
                "  ⚠ via_subscription=True — this call counts "
                "against your OAuth quota; the receipt will mark it.",
            )
        try:
            ans = input("Continue? [Y/n] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "n"
        if ans and ans not in ("y", "yes"):
            print("[orchestrator] cancelled by operator.")
            return 0

    try:
        result = orch.invoke(
            args.tool, args.prompt,
            role=args.role, goal_id=args.goal_id,
        )
    except ToolRateLimitExceeded as exc:
        print(f"[orchestrator] {exc}")
        return 5
    except ToolInvocationFailed as exc:
        print(f"[orchestrator] {exc}")
        return 6
    print(result.stdout)
    if result.receipt_id:
        print(
            f"[orchestrator] receipt_id={result.receipt_id} "
            f"role={args.role} via_subscription={result.via_subscription}",
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
