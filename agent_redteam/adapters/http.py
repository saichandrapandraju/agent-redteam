"""HttpAdapter — scan any agent exposed over an HTTP API.

The simplest integration path for production agents.  Send attack prompts to
an HTTP endpoint and parse responses, extracting tool calls from structured
response formats (OpenAI function calling, Anthropic tool_use blocks, or
plain text).

Example::

    adapter = HttpAdapter(
        base_url="http://localhost:8000/v1/agent",
        method="POST",
        input_template={"messages": [{"role": "user", "content": "{instruction}"}]},
        output_path="choices.0.message.content",
    )
    result = await Scanner(adapter, config).run()
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

from agent_redteam.core.enums import EventType, TrustBoundary
from agent_redteam.core.models import (
    AgentTask,
    AgentTrace,
    Environment,
    Event,
)

logger = logging.getLogger("agent_redteam.adapters.http")

try:
    import httpx

    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False


class HttpAdapter:
    """Wraps an HTTP-exposed agent for security testing.

    Parameters
    ----------
    base_url : str
        Full URL of the agent endpoint.
    method : str
        HTTP method (default ``"POST"``).
    input_template : dict | None
        JSON body template. The string ``{instruction}`` in any value is
        replaced by the task instruction.  If ``None``, sends
        ``{"input": instruction}``.
    output_path : str
        Dot-delimited path into the JSON response to extract the agent's
        text output. E.g. ``"choices.0.message.content"`` or ``"output"``.
        Set to ``""`` to use the full response body.
    headers : dict | None
        Extra HTTP headers (e.g. ``{"Authorization": "Bearer <key>"}``)
    tool_call_paths : list[str] | None
        JSON paths to look for structured tool calls in the response.
        E.g. ``["choices.0.message.tool_calls"]`` for OpenAI format.
    name : str
        Adapter name used in scan reports.
    """

    def __init__(
        self,
        base_url: str,
        *,
        method: str = "POST",
        input_template: dict[str, Any] | None = None,
        output_path: str = "output",
        headers: dict[str, str] | None = None,
        tool_call_paths: list[str] | None = None,
        name: str = "http_agent",
    ) -> None:
        if not _HAS_HTTPX:
            raise ImportError("HttpAdapter requires httpx. Install with: pip install httpx")
        self._base_url = base_url
        self._method = method.upper()
        self._input_template = input_template or {"input": "{instruction}"}
        self._output_path = output_path
        self._headers = headers or {}
        self._tool_call_paths = tool_call_paths or [
            "choices.0.message.tool_calls",
            "tool_calls",
            "content",
        ]
        self._name = name

    @property
    def adapter_name(self) -> str:
        return self._name

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.request(
                    "GET" if self._method == "GET" else "POST",
                    self._base_url,
                    headers=self._headers,
                )
                return resp.status_code < 500
        except Exception as e:
            logger.warning("Health check failed: %s", e)
            return False

    async def run(self, task: AgentTask, environment: Environment) -> AgentTrace:
        trace = AgentTrace(task=task, environment=environment)

        body = self._build_request_body(task.instruction)

        try:
            async with httpx.AsyncClient(timeout=task.timeout_seconds) as client:
                resp = await asyncio.wait_for(
                    client.request(
                        self._method,
                        self._base_url,
                        json=body,
                        headers={
                            "Content-Type": "application/json",
                            **self._headers,
                        },
                    ),
                    timeout=task.timeout_seconds,
                )

            trace.events.append(
                Event(
                    event_type=EventType.NETWORK_REQUEST,
                    url=self._base_url,
                    content=json.dumps(body)[:500],
                    turn_number=1,
                )
            )

            try:
                data = resp.json()
            except (json.JSONDecodeError, ValueError):
                data = resp.text

            trace.final_output = self._extract_output(data)
            self._extract_tool_calls(data, trace)

            trace.events.append(
                Event(
                    event_type=EventType.LLM_RESPONSE,
                    trust_boundary=TrustBoundary.B1_USER_TO_AGENT,
                    content=trace.final_output[:2000] if trace.final_output else "",
                    turn_number=1,
                )
            )

        except TimeoutError:
            trace.error = "timeout"
        except Exception as e:
            trace.error = str(e)
            logger.warning("HTTP request failed: %s", e)
        finally:
            trace.ended_at = datetime.now(UTC)

        return trace

    async def run_streaming(self, task: AgentTask, environment: Environment) -> AsyncIterator[Event]:
        trace = await self.run(task, environment)
        for event in trace.events:
            yield event

    def _build_request_body(self, instruction: str) -> dict[str, Any]:
        return _deep_replace(self._input_template, "{instruction}", instruction)

    def _extract_output(self, data: Any) -> str:
        if not self._output_path:
            return json.dumps(data) if isinstance(data, (dict, list)) else str(data)
        return str(_get_nested(data, self._output_path))

    def _extract_tool_calls(self, data: Any, trace: AgentTrace) -> None:
        """Parse tool calls from the response and emit events."""
        turn = 1
        for path in self._tool_call_paths:
            calls = _get_nested(data, path)
            if not calls:
                continue
            if isinstance(calls, list):
                for call in calls:
                    tc = _parse_tool_call(call)
                    if tc:
                        turn += 1
                        trace.events.append(
                            Event(
                                event_type=EventType.TOOL_CALL,
                                trust_boundary=TrustBoundary.B4_AGENT_TO_TOOL,
                                tool_name=tc["name"],
                                tool_args=tc.get("arguments"),
                                turn_number=turn,
                            )
                        )
            elif isinstance(calls, str):
                for tc in _extract_tool_calls_from_text(calls):
                    turn += 1
                    trace.events.append(
                        Event(
                            event_type=EventType.TOOL_CALL,
                            trust_boundary=TrustBoundary.B4_AGENT_TO_TOOL,
                            tool_name=tc["name"],
                            tool_args=tc.get("arguments"),
                            turn_number=turn,
                        )
                    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _deep_replace(obj: Any, old: str, new: str) -> Any:
    if isinstance(obj, str):
        return obj.replace(old, new)
    if isinstance(obj, dict):
        return {k: _deep_replace(v, old, new) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_deep_replace(v, old, new) for v in obj]
    return obj


def _get_nested(data: Any, path: str) -> Any:
    """Traverse a dot-separated path into a nested dict/list."""
    if not path:
        return data
    for part in path.split("."):
        if data is None:
            return None
        if isinstance(data, dict):
            data = data.get(part)
        elif isinstance(data, list):
            try:
                data = data[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return data


def _parse_tool_call(call: Any) -> dict[str, Any] | None:
    """Parse a single tool call from OpenAI or Anthropic format."""
    if isinstance(call, dict):
        # OpenAI format: {"function": {"name": ..., "arguments": ...}}
        fn = call.get("function", call)
        name = fn.get("name")
        if not name:
            name = call.get("type", call.get("tool_name"))
        if not name:
            return None

        args = fn.get("arguments", call.get("input", {}))
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except (json.JSONDecodeError, ValueError):
                args = {"input": args}
        return {"name": name, "arguments": args}
    return None


_TOOL_CALL_RE = re.compile(
    r"(?:tool_call|function_call|action)\s*[:=]\s*(\w+)\s*\((.*?)\)",
    re.IGNORECASE | re.DOTALL,
)


def _extract_tool_calls_from_text(text: str) -> list[dict[str, Any]]:
    """Best-effort extraction of tool calls from free-text agent output."""
    calls = []
    for m in _TOOL_CALL_RE.finditer(text):
        name = m.group(1)
        args_str = m.group(2)
        try:
            args = json.loads("{" + args_str + "}")
        except (json.JSONDecodeError, ValueError):
            args = {"input": args_str}
        calls.append({"name": name, "arguments": args})
    return calls
