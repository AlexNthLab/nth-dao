"""
team_layer.backends  Agent

"Agent " backend NTH DAO runtime//EvoLoop/git_sync/Blackboard
 Agent

    HermesBackend         hermes-agent (NousResearch)
    ClaudeCodeBackend     Anthropic Claude Code CLI
    OpenClawBackend       OpenClaw (ACP protocol)
    CodexBackend          OpenAI Codex CLI
    OpenHandsBackend      All-Hands-AI/OpenHands (REST API)
    MockBackend            / demo


1.    backend  ABC
2.    backend  is_available()
3.   base/mock  backend
4.   capabilities()  backend streaming/tools/cost
"""

from .base import (
    AgentBackend,
    BackendCapabilities,
    BackendUnavailableError,
    SessionConfig,
    SessionSummary,
    TokenUsage,
    ToolCall,
    TurnResponse,
)
from .registry import BackendRegistry, default_registry

#  backendlazy import
def _register_builtins():
    from .mock import MockBackend
    default_registry.register("mock", MockBackend)

    try:
        from .hermes import HermesBackend
        default_registry.register("hermes", HermesBackend)
    except ImportError:
        pass

    try:
        from .claude_code import ClaudeCodeBackend
        default_registry.register("claude_code", ClaudeCodeBackend)
    except ImportError:
        pass

    try:
        from .openclaw import OpenClawBackend
        default_registry.register("openclaw", OpenClawBackend)
    except ImportError:
        pass

    try:
        from .codex import CodexBackend
        default_registry.register("codex", CodexBackend)
    except ImportError:
        pass

    try:
        from .openhands import OpenHandsBackend
        default_registry.register("openhands", OpenHandsBackend)
    except ImportError:
        pass


_register_builtins()

__all__ = [
    "AgentBackend",
    "BackendCapabilities",
    "BackendRegistry",
    "BackendUnavailableError",
    "SessionConfig",
    "SessionSummary",
    "TokenUsage",
    "ToolCall",
    "TurnResponse",
    "default_registry",
]
