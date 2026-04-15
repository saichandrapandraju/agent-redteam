"""CallableAdapter — wraps any async callable for security testing."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from typing import Any

from agent_redteam.core.enums import EventType, TrustBoundary
from agent_redteam.core.models import (
    AgentTask,
    AgentTrace,
    Environment,
    Event,
)
from agent_redteam.environments.runtime import EnvironmentRuntime


class CallableAdapter:
    """Wraps an async callable agent function for security testing.

    The callable receives (instruction: str, tools: dict) where tools maps
    tool names to instrumented async callables backed by an
    :class:`EnvironmentRuntime` that maintains shared mutable state.

    Example::

        async def my_agent(instruction: str, tools: dict) -> str:
            content = await tools["file_read"](path="/some/file.txt")
            return f"File says: {content}"

        adapter = CallableAdapter(my_agent)
    """

    def __init__(
        self,
        agent_fn: Callable[..., Any],
        name: str = "callable_agent",
    ) -> None:
        self._agent_fn = agent_fn
        self._name = name

    @property
    def adapter_name(self) -> str:
        return self._name

    async def health_check(self) -> bool:
        return True

    async def run(self, task: AgentTask, environment: Environment) -> AgentTrace:
        trace = AgentTrace(task=task, environment=environment)
        runtime = EnvironmentRuntime(environment)
        tools = _build_instrumented_tools(runtime, trace)

        try:
            result = await asyncio.wait_for(
                self._agent_fn(task.instruction, tools),
                timeout=task.timeout_seconds,
            )
            trace.final_output = str(result) if result is not None else None
        except TimeoutError:
            trace.error = "timeout"
            raise TimeoutError("Agent timed out") from None
        except Exception as e:
            trace.error = str(e)
        finally:
            trace.ended_at = datetime.now(UTC)

        return trace

    async def run_streaming(self, task: AgentTask, environment: Environment) -> AsyncIterator[Event]:
        trace = await self.run(task, environment)
        for event in trace.events:
            yield event


_FILE_READ_TOOLS = frozenset({"file_read", "read_file"})
_HTTP_TOOLS = frozenset({"http_request", "curl", "fetch", "requests", "http_get"})


def _build_instrumented_tools(
    runtime: EnvironmentRuntime, trace: AgentTrace
) -> dict[str, Callable]:
    """Build tool_name -> instrumented_callable backed by EnvironmentRuntime."""
    tools: dict[str, Callable] = {}
    turn_counter = {"n": 0}

    for tool_def in runtime.env.tools:
        name = tool_def.name
        tools[name] = _make_instrumented_tool(name, runtime, trace, turn_counter)

    if runtime.inbox and "read_emails" not in tools:
        tools["read_emails"] = _make_instrumented_tool("read_emails", runtime, trace, turn_counter)

    return tools


def _make_instrumented_tool(
    name: str,
    runtime: EnvironmentRuntime,
    trace: AgentTrace,
    turn_counter: dict[str, int],
) -> Callable:
    async def instrumented_tool(**kwargs: Any) -> Any:
        turn_counter["n"] += 1
        turn = turn_counter["n"]

        call_event = Event(
            event_type=EventType.TOOL_CALL,
            trust_boundary=TrustBoundary.B4_AGENT_TO_TOOL,
            tool_name=name,
            tool_args=kwargs,
            turn_number=turn,
        )
        if name == "read_emails":
            call_event.trust_boundary = TrustBoundary.B2_EXTERNAL_DATA_TO_AGENT
        trace.events.append(call_event)

        result = runtime.execute(name, kwargs)

        if name in _FILE_READ_TOOLS and "path" in kwargs:
            trace.events.append(
                Event(
                    event_type=EventType.FILE_READ,
                    trust_boundary=TrustBoundary.B4_AGENT_TO_TOOL,
                    file_path=kwargs["path"],
                    content=str(result)[:500],
                    turn_number=turn,
                )
            )

        if name in _HTTP_TOOLS and "url" in kwargs:
            trace.events.append(
                Event(
                    event_type=EventType.NETWORK_REQUEST,
                    trust_boundary=TrustBoundary.B4_AGENT_TO_TOOL,
                    url=kwargs["url"],
                    turn_number=turn,
                )
            )

        result_event = Event(
            event_type=EventType.TOOL_RESULT,
            trust_boundary=TrustBoundary.B3_TOOL_OUTPUT_TO_AGENT,
            tool_name=name,
            tool_result=result,
            turn_number=turn,
        )
        if name == "read_emails":
            result_event.trust_boundary = TrustBoundary.B2_EXTERNAL_DATA_TO_AGENT
        trace.events.append(result_event)

        return result

    return instrumented_tool
