"""
PR 1: Team Agent   Hermes  + Team  +


- TeamMemoryManager 4  Provider
- TeamAgent HermesAgent Team
- <memory-context> fence
-  on_pre_compress
"""

from typing import Any, Callable, Dict, List, Optional
import os
import json
from pathlib import Path
from datetime import datetime


class MemoryProviderABC:
    """Memory Provider  Hermes"""

    def initialize(self, context: dict) -> None:
        """  """
        pass

    def prefetch(self, session_id: str) -> str:
        """   system prompt"""
        return ""

    def on_pre_compress(self, compaction_hint: str) -> None:
        """  """
        pass

    def sync_turn(self, action: dict, result: Any) -> None:
        """  """
        pass

    def on_session_end(self) -> None:
        """  """
        pass


class TeamMemoryManager:
    """Team    4  Provider"""

    def __init__(self, providers: List[MemoryProviderABC], session_id: str = None):
        self.providers = {p.__class__.__name__: p for p in providers}
        self.session_id = session_id or self._gen_session_id()
        self.memory_context_fence = "<memory-context>\n{}\n</memory-context>"

    @staticmethod
    def _gen_session_id() -> str:
        return f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    def initialize(self, context: dict) -> None:
        """ Provider"""
        for name, provider in self.providers.items():
            try:
                provider.initialize(context)
            except Exception as e:
                print(f"[WARN] Provider {name} initialize failed: {e}")

    def prefetch_memory(self) -> Dict[str, str]:
        """  """
        memory_blocks = {}
        for name, provider in self.providers.items():
            try:
                block = provider.prefetch(self.session_id)
                if block:
                    memory_blocks[name] = block
            except Exception as e:
                print(f"[WARN] Provider {name} prefetch failed: {e}")
                memory_blocks[name] = f"[{name} unavailable]"
        return memory_blocks

    def build_memory_context_block(self) -> str:
        """ fence   """
        blocks = self.prefetch_memory()
        if not blocks:
            return ""

        content = "\n\n".join([
            f"## {name}\n{text}"
            for name, text in blocks.items()
        ])

        #  fence
        return self.memory_context_fence.format(content)

    def on_pre_compress(self, compaction_hint: str) -> None:
        """   Provider """
        for name, provider in self.providers.items():
            try:
                provider.on_pre_compress(compaction_hint)
            except Exception as e:
                print(f"[WARN] Provider {name} on_pre_compress failed: {e}")

    def sync_turn(self, action: dict, result: Any) -> None:
        """   Provider """
        for provider in self.providers.values():
            try:
                provider.sync_turn(action, result)
            except Exception as e:
                pass  #

    def on_session_end(self) -> None:
        """   Provider"""
        for provider in self.providers.values():
            try:
                provider.on_session_end()
            except Exception as e:
                pass


class TeamAgent:
    """
    Team Agent  Hermes Agent

     Hermes Agent  hermes.agent
     Hermes  install
    """

    def __init__(
        self,
        agent_id: str,
        team_memory_manager: Optional[TeamMemoryManager] = None,
        compression_threshold: float = 0.75,
        **kwargs
    ):
        """
        Args:
            agent_id: ID
            team_memory_manager: Team
            compression_threshold: 0.75 = 75%
            **kwargs:  Agent
        """
        self.agent_id = agent_id
        self.team_mem = team_memory_manager or TeamMemoryManager([])
        self.compression_threshold = compression_threshold
        self.context_usage = 0.0
        self.history = []
        self.session_id = self.team_mem.session_id

        #  Hermes Agent
        # from hermes.agent import Agent as HermesAgent
        # self._agent = HermesAgent(**kwargs)

    def should_compact(self) -> bool:
        """"""
        return self.context_usage >= self.compression_threshold

    def trigger_compression(self, stage: int = 5) -> None:
        """"""
        #  Provider
        hint = f"compression_stage_{stage}_at_{self.context_usage:.1%}_context"
        self.team_mem.on_pre_compress(hint)

        # team_layer/compression/
        print(f"[INFO] Triggering compression stage {stage} (context: {self.context_usage:.1%})")

    def append_history(self, action: dict, result: Any) -> None:
        """ Provider"""
        self.history.append((action, result))
        self.team_mem.sync_turn(action, result)

        #  context_usage ~500 tokens
        self.context_usage = min(1.0, len(self.history) * 0.05)

    def get_system_prompt_with_memory(self, base_prompt: str = "") -> str:
        """"""
        memory_block = self.team_mem.build_memory_context_block()
        if memory_block:
            return f"{base_prompt}\n\n{memory_block}"
        return base_prompt

    def finalize(self) -> None:
        """  """
        self.team_mem.on_session_end()
        print(f"[INFO] Session {self.session_id} finalized")

    #
    # PR 7: Backend-driven
    #

    def run_with_backend(
        self,
        backend,                       # AgentBackend ( import )
        goal: str,
        max_turns: int = 5,
        per_turn_prompt: Optional[Callable[[int, "TeamAgent"], str]] = None,
        error_sig_fn: Optional[Callable[[Any], Optional[str]]] = None,
    ) -> Dict[str, Any]:
        """
         AgentBackend  mock

        Args:
            backend:  AgentBackend mock / hermes / claude_code / ...
            goal:  SessionConfig +  prompt
            max_turns:
            per_turn_prompt:  prompt  fn(turn_idx, agent) -> str
                              goal "continue"
            error_sig_fn:  TurnResponse  error_sig  EvoLoop
                          finish_reason=='error'  backend.backend_id

        Returns:
            {
                "session_summary": SessionSummary ,
                "turns": [{"prompt": ..., "response": ...}, ...],
                "agent_id": ...,
                "backend_id": ...,
            }
        """
        # 1.  backend
        from .backends import SessionConfig

        # 2.  backend session
        config = SessionConfig(
            session_id=self.session_id,
            goal=goal,
        )
        backend.start_session(config)
        print(f"[BACKEND] {backend.backend_id} session started: {self.session_id}")

        # 3.  prompt
        if per_turn_prompt is None:
            def per_turn_prompt(turn_idx: int, agent: "TeamAgent") -> str:
                return goal if turn_idx == 0 else "continue"

        # 4.
        turns_log = []
        system_prompt = self.get_system_prompt_with_memory(
            base_prompt="You are a team-aware AI agent."
        )

        for turn_idx in range(max_turns):
            prompt = per_turn_prompt(turn_idx, self)
            response = backend.send_turn(prompt, system_prompt)

            #  history mock
            action = {"type": "backend_turn", "backend": backend.backend_id, "prompt": prompt}
            self.append_history(action, response.content)

            #  Ledger EvoLoop  backend
            ledger = self.team_mem.providers.get("LedgerProvider")
            if ledger:
                error_sig = None
                if response.is_error:
                    error_sig = (
                        error_sig_fn(response) if error_sig_fn
                        else f"{backend.backend_id}_{response.finish_reason}"
                    )
                ledger.record(
                    agent_id=self.agent_id,
                    action_type=f"backend:{backend.backend_id}",
                    result=response.content[:200] if response.content else (response.error or ""),
                    error_sig=error_sig,
                    token_cost=response.usage.total,
                )

            turns_log.append({
                "turn": turn_idx + 1,
                "prompt": prompt,
                "response_content": response.content,
                "finish_reason": response.finish_reason,
                "tokens": response.usage.total,
                "latency": response.latency_seconds,
                "error": response.error,
            })

            print(
                f"[TURN {turn_idx+1}/{max_turns}] {backend.backend_id} "
                f"finish={response.finish_reason} tokens={response.usage.total} "
                f"latency={response.latency_seconds:.2f}s"
            )

            #
            if response.is_error:
                print(f"[BACKEND] error: {response.error}")
                break

            #
            if self.should_compact():
                self.trigger_compression()

        # 5.  session
        summary = backend.end_session()
        print(
            f"[BACKEND] session ended: {summary.total_turns} turns, "
            f"{summary.total_usage.total} tokens, {summary.duration_seconds:.1f}s"
        )

        return {
            "session_summary": summary,
            "turns": turns_log,
            "agent_id": self.agent_id,
            "backend_id": backend.backend_id,
        }


#  Team Agent
def create_team_agent(
    agent_id: str,
    memory_providers: List[MemoryProviderABC] = None,
    **kwargs
) -> TeamAgent:
    """
       Team Agent

    Example:
        agent = create_team_agent(
            "nlp-worker-1",
            memory_providers=[SoulProvider(), UserModelProvider()],
            compression_threshold=0.75
        )
    """
    mem_mgr = TeamMemoryManager(memory_providers or [])
    return TeamAgent(agent_id, team_memory_manager=mem_mgr, **kwargs)
