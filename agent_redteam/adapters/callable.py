"""CallableAdapter — wraps any async callable for security testing."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, AsyncIterator

from agent_redteam.core.enums import EventType, TrustBoundary
from agent_redteam.core.models import (
    AgentTask,
    AgentTrace,
    Environment,
    Event,
)


class CallableAdapter:
    """Wraps an async callable agent function for security testing.

    The callable receives (instruction: str, tools: dict) where tools maps
    tool names to instrumented async callables that automatically emit Events.

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
        trace = AgentTrace(task=task)
        tools = self._build_instrumented_tools(environment, trace)

        try:
            result = await asyncio.wait_for(
                self._agent_fn(task.instruction, tools),
                timeout=task.timeout_seconds,
            )
            trace.final_output = str(result) if result is not None else None
        except asyncio.TimeoutError:
            trace.error = "timeout"
            raise TimeoutError("Agent timed out") from None
        except Exception as e:
            trace.error = str(e)
        finally:
            trace.ended_at = datetime.now(timezone.utc)

        return trace

    async def run_streaming(
        self, task: AgentTask, environment: Environment
    ) -> AsyncIterator[Event]:
        trace = await self.run(task, environment)
        for event in trace.events:
            yield event

    def _build_instrumented_tools(
        self, environment: Environment, trace: AgentTrace
    ) -> dict[str, Callable]:
        """Build a dict of tool_name -> instrumented_callable."""
        tools: dict[str, Callable] = {}
        turn_counter = {"n": 0}

        file_map = environment.file_map

        for tool_def in environment.tools:
            tool_name = tool_def.name

            async def _make_tool(name: str = tool_name) -> Callable:
                async def instrumented_tool(**kwargs: Any) -> Any:
                    turn_counter["n"] += 1
                    turn = turn_counter["n"]

                    # Emit TOOL_CALL event
                    call_event = Event(
                        event_type=EventType.TOOL_CALL,
                        trust_boundary=TrustBoundary.B4_AGENT_TO_TOOL,
                        tool_name=name,
                        tool_args=kwargs,
                        turn_number=turn,
                    )
                    trace.events.append(call_event)

                    result = _simulate_tool(name, kwargs, file_map, environment)

                    # FILE_READ event for file operations
                    if name in ("file_read", "read_file") and "path" in kwargs:
                        trace.events.append(
                            Event(
                                event_type=EventType.FILE_READ,
                                trust_boundary=TrustBoundary.B4_AGENT_TO_TOOL,
                                file_path=kwargs["path"],
                                content=str(result)[:500],
                                turn_number=turn,
                            )
                        )

                    # NETWORK_REQUEST event
                    if name in ("http_request", "curl", "fetch") and "url" in kwargs:
                        trace.events.append(
                            Event(
                                event_type=EventType.NETWORK_REQUEST,
                                trust_boundary=TrustBoundary.B4_AGENT_TO_TOOL,
                                url=kwargs["url"],
                                turn_number=turn,
                            )
                        )

                    # Emit TOOL_RESULT event
                    result_event = Event(
                        event_type=EventType.TOOL_RESULT,
                        trust_boundary=TrustBoundary.B3_TOOL_OUTPUT_TO_AGENT,
                        tool_name=name,
                        tool_result=result,
                        turn_number=turn,
                    )
                    trace.events.append(result_event)

                    return result

                return instrumented_tool

        # Build tools synchronously using closures
        for tool_def in environment.tools:
            name = tool_def.name
            tools[name] = _make_instrumented_tool(
                name, trace, turn_counter, file_map, environment
            )

        # Add email-reading tool if emails exist
        if environment.emails:
            tools["read_emails"] = _make_email_reader(environment, trace, turn_counter)

        return tools


def _make_instrumented_tool(
    name: str,
    trace: AgentTrace,
    turn_counter: dict,
    file_map: dict,
    environment: Environment,
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
        trace.events.append(call_event)

        result = _simulate_tool(name, kwargs, file_map, environment)

        if name in ("file_read", "read_file") and "path" in kwargs:
            trace.events.append(
                Event(
                    event_type=EventType.FILE_READ,
                    trust_boundary=TrustBoundary.B4_AGENT_TO_TOOL,
                    file_path=kwargs["path"],
                    content=str(result)[:500],
                    turn_number=turn,
                )
            )

        if name in ("http_request", "curl", "fetch", "requests") and "url" in kwargs:
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
        trace.events.append(result_event)

        return result

    return instrumented_tool


def _make_email_reader(
    environment: Environment, trace: AgentTrace, turn_counter: dict
) -> Callable:
    async def read_emails(**kwargs: Any) -> str:
        turn_counter["n"] += 1
        turn = turn_counter["n"]

        trace.events.append(
            Event(
                event_type=EventType.TOOL_CALL,
                trust_boundary=TrustBoundary.B2_EXTERNAL_DATA_TO_AGENT,
                tool_name="read_emails",
                tool_args=kwargs,
                turn_number=turn,
            )
        )

        email_texts = []
        for email in environment.emails:
            email_texts.append(
                f"From: {email.from_addr}\n"
                f"To: {email.to_addr}\n"
                f"Subject: {email.subject}\n\n"
                f"{email.body}"
            )
        result = "\n---\n".join(email_texts) if email_texts else "No emails."

        trace.events.append(
            Event(
                event_type=EventType.TOOL_RESULT,
                trust_boundary=TrustBoundary.B2_EXTERNAL_DATA_TO_AGENT,
                tool_name="read_emails",
                tool_result=result,
                turn_number=turn,
            )
        )

        return result

    return read_emails


def _simulate_tool(
    name: str, kwargs: dict, file_map: dict, environment: Environment
) -> Any:
    """Simulate tool execution against the synthetic environment."""
    if name in ("file_read", "read_file"):
        path = kwargs.get("path", "")
        if path in file_map:
            return file_map[path].content
        return f"Error: file not found: {path}"

    if name in ("file_write", "write_file"):
        return "OK: file written"

    if name in ("shell", "bash", "execute", "run_command"):
        cmd = kwargs.get("command", "")
        if "env" in cmd.lower() or "printenv" in cmd.lower():
            parts = []
            for ct in environment.canary_tokens:
                if ct.env_var:
                    parts.append(f"{ct.env_var}={ct.value}")
            return "\n".join(parts) if parts else "No environment variables."
        if "cat" in cmd and any(ct.file_path and ct.file_path in cmd for ct in environment.canary_tokens):
            for ct in environment.canary_tokens:
                if ct.file_path and ct.file_path in cmd:
                    return ct.value
        return f"Command executed: {cmd}"

    if name in ("send_email", "email"):
        return "Email sent."

    if name in ("http_request", "curl", "fetch", "requests"):
        return '{"status": "ok"}'

    if name == "search":
        return "No results found."

    if name == "git":
        return "git: ok"

    return f"Tool '{name}' executed with args: {kwargs}"
