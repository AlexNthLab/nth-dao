"""nth_dao.a2a — boundary adapter for Google's Agent2Agent (A2A) protocol.

This is the v0.9.5 starter: translation primitives only, no JSON-RPC server,
no HTTP transport. Those land in v0.10.0 as a separate package
(`nth-dao-a2a-adapter`).

See docs/research/A2A_ALIGNMENT.md for the comparison rationale and the
strategic decision to keep this at the boundary rather than rewire our
protocol core.

What this module provides:

    - `template_to_a2a_skill(template)` — render a MissionTemplate as the
      Skill schema embedded in an A2A AgentCard.
    - `agent_card_from(team_config, identity, templates, …)` — assemble an
      A2A AgentCard JSON dict that an external A2A server would serve at
      `/.well-known/agent.json`.
    - `a2a_task_from_mission(mission)` — render one of our Missions as
      an A2A Task object (for outbound responses).
    - `mission_inputs_from_a2a_message(message, template)` — extract
      structured inputs from an A2A SendMessage payload, validating against
      the template's input schema.

What this module does NOT do (yet):

    - Serve HTTP / JSON-RPC.
    - Authenticate A2A bearer tokens (out of scope for the core; the
      adapter package will handle OAuth/OIDC).
    - Subscribe to streaming task updates (SSE).
    - Implement the 11 JSON-RPC methods of A2A.

Doing those things would force HTTP/OAuth deps into the core package and
break the stdlib-only philosophy. They live in `nth-dao-a2a-adapter`.
"""

from .translate import (
    a2a_task_from_mission,
    agent_card_from,
    mission_inputs_from_a2a_message,
    template_to_a2a_skill,
)

__all__ = [
    "template_to_a2a_skill",
    "agent_card_from",
    "a2a_task_from_mission",
    "mission_inputs_from_a2a_message",
]
