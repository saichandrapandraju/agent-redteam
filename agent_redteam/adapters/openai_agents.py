"""OpenAIAgentsAdapter — instrument OpenAI Agents SDK agents for security testing.

Wraps an ``openai-agents`` ``Agent`` object and uses RunHooks to intercept all
tool calls, LLM requests, and agent handoffs for full telemetry capture.

    from agents import Agent
    from agent_redteam.adapters.openai_agents import OpenAIAgentsAdapter

    agent = Agent(name="my_agent", instructions="...", tools=[...])
    adapter = OpenAIAgentsAdapter(agent)
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from agent_redteam.core.enums import EventType, TrustBoundary
from agent_redteam.core.models import (
    AgentTask,
    AgentTrace,
    Environment,
    Event,
)

if TYPE_CHECKING:
    pass

try:
    from agents import Runner
    from agents.lifecycle import RunHooks

    _HAS_AGENTS_SDK = True
except ImportError:
    _HAS_AGENTS_SDK = False
    Runner = None  # type: ignore[assignment, misc]
    RunHooks = object  # type: ignore[assignment, misc]


class _TraceRunHooks(RunHooks):  # type: ignore[misc]
    """RunHooks implementation that captures events into an AgentTrace."""

    def __init__(self, trace: AgentTrace) -> None:
        self._trace = trace
        self._turn = 0

    async def on_agent_start(self, context: Any, agent: Any) -> None:
        self._trace.events.append(
            Event(
                event_type=EventType.LLM_PROMPT,
                trust_boundary=TrustBoundary.B1_USER_TO_AGENT,
                content=f"Agent started: {getattr(agent, 'name', 'unknown')}",
                turn_number=self._turn,
            )
        )

    async def on_agent_end(self, context: Any, agent: Any, output: Any) -> None:
        output_str = str(getattr(output, "final_output", output))
        self._trace.events.append(
            Event(
                event_type=EventType.LLM_RESPONSE,
                trust_boundary=TrustBoundary.B1_USER_TO_AGENT,
                content=output_str[:2000],
                turn_number=self._turn,
            )
        )

    async def on_tool_start(self, context: Any, agent: Any, tool: Any) -> None:
        self._turn += 1
        tool_name = getattr(tool, "name", str(tool))
        tool_args = self._extract_tool_args(tool)
        self._trace.events.append(
            Event(
                event_type=EventType.TOOL_CALL,
                trust_boundary=TrustBoundary.B4_AGENT_TO_TOOL,
                tool_name=tool_name,
                tool_args=tool_args,
                turn_number=self._turn,
            )
        )

    @staticmethod
    def _extract_tool_args(tool: Any) -> dict[str, Any] | None:
        """Best-effort extraction of tool arguments from the SDK tool object."""
        for attr in ("model_input", "input", "args", "arguments", "kwargs"):
            val = getattr(tool, attr, None)
            if val is not None:
                if isinstance(val, dict):
                    return val
                if isinstance(val, str):
                    import json

                    try:
                        parsed = json.loads(val)
                        if isinstance(parsed, dict):
                            return parsed
                    except (json.JSONDecodeError, ValueError):
                        return {"input": val}
                    return {"input": val}
        return None

    async def on_tool_end(self, context: Any, agent: Any, tool: Any, result: Any) -> None:
        tool_name = getattr(tool, "name", str(tool))
        self._trace.events.append(
            Event(
                event_type=EventType.TOOL_RESULT,
                trust_boundary=TrustBoundary.B3_TOOL_OUTPUT_TO_AGENT,
                tool_name=tool_name,
                tool_result=str(result)[:2000],
                turn_number=self._turn,
            )
        )

    async def on_handoff(self, context: Any, from_agent: Any, to_agent: Any) -> None:
        from_name = getattr(from_agent, "name", "unknown")
        to_name = getattr(to_agent, "name", "unknown")
        self._trace.events.append(
            Event(
                event_type=EventType.AGENT_MESSAGE_SENT,
                trust_boundary=TrustBoundary.B5_AGENT_TO_AGENT,
                content=f"Handoff: {from_name} -> {to_name}",
                turn_number=self._turn,
            )
        )


class OpenAIAgentsAdapter:
    """Wraps an OpenAI Agents SDK Agent for security testing.

    Parameters
    ----------
    agent : Any
        An ``agents.Agent`` instance.
    name : str
        Human-readable adapter name.
    max_turns : int
        Maximum number of agent turns (default 10).
    """

    def __init__(
        self,
        agent: Any,
        *,
        name: str = "openai_agents",
        max_turns: int = 10,
    ) -> None:
        if not _HAS_AGENTS_SDK:
            raise ImportError(
                "OpenAIAgentsAdapter requires the openai-agents package. "
                "Install it with: pip install openai-agents"
            )
        self._agent = agent
        self._name = name
        self._max_turns = max_turns

    @property
    def adapter_name(self) -> str:
        return self._name

    async def health_check(self) -> bool:
        return _HAS_AGENTS_SDK and self._agent is not None

    async def run(self, task: AgentTask, environment: Environment) -> AgentTrace:
        trace = AgentTrace(task=task, environment=environment)
        hooks = _TraceRunHooks(trace)

        try:
            result = await asyncio.wait_for(
                Runner.run(
                    self._agent,
                    input=task.instruction,
                    hooks=hooks,
                    max_turns=self._max_turns,
                ),
                timeout=task.timeout_seconds,
            )
            trace.final_output = str(getattr(result, "final_output", result))
        except TimeoutError:
            trace.error = "timeout"
        except Exception as e:
            trace.error = str(e)
        finally:
            trace.ended_at = datetime.now(UTC)

        return trace

    async def run_streaming(self, task: AgentTask, environment: Environment) -> AsyncIterator[Event]:
        trace = await self.run(task, environment)
        for event in trace.events:
            yield event
