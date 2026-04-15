"""LangChainAdapter — instrument LangChain agents and LangGraph graphs for security testing.

Wraps any LangChain ``AgentExecutor`` or LangGraph ``CompiledGraph`` and intercepts
tool calls via LangChain's callback system to build a full ``AgentTrace``.

    from langchain.agents import AgentExecutor
    from agent_redteam.adapters.langchain import LangChainAdapter

    adapter = LangChainAdapter(agent_executor)
    # or
    adapter = LangChainAdapter(compiled_graph, input_key="messages")
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from agent_redteam.core.enums import EventType, TrustBoundary
from agent_redteam.core.models import (
    AgentTask,
    AgentTrace,
    CanaryToken,
    Environment,
    Event,
)

if TYPE_CHECKING:
    pass

try:
    from langchain_core.callbacks import AsyncCallbackHandler
except ImportError:
    AsyncCallbackHandler = None  # type: ignore[assignment, misc]

try:
    from langchain_core.tools import StructuredTool
except ImportError:
    StructuredTool = None  # type: ignore[assignment, misc]

logger = logging.getLogger("agent_redteam.adapters.langchain")


# ---------------------------------------------------------------------------
# Canary injection for LangChain tools
# ---------------------------------------------------------------------------

_FILE_TOOL_NAMES = frozenset({"file_read", "read_file", "read", "cat_file"})
_SHELL_TOOL_NAMES = frozenset({"shell_exec", "shell", "bash", "execute", "run_command", "terminal"})
_ENV_KEYWORDS = frozenset({"env", "printenv", "export"})


class CanaryInjector:
    """Maps canary tokens to file paths and env vars for output injection.

    Used by ``wrap_tools_with_canaries`` to make a real LangChain agent
    encounter the same secret values that detectors look for.
    """

    def __init__(self, canary_tokens: list[CanaryToken]) -> None:
        self._path_map: dict[str, str] = {}
        self._env_map: dict[str, str] = {}
        for ct in canary_tokens:
            if ct.file_path:
                self._path_map[ct.file_path] = ct.value
            if ct.env_var:
                self._env_map[ct.env_var] = ct.value

    @property
    def has_tokens(self) -> bool:
        return bool(self._path_map) or bool(self._env_map)

    def inject_file_result(self, path: str, original: str) -> str:
        """If *path* is a canary-seeded location, return the canary value."""
        if path in self._path_map:
            return self._path_map[path]
        return original

    def inject_shell_result(self, command: str, original: str) -> str:
        """Append canary env vars to env-dump commands; replace cat output for canary paths."""
        cmd_lower = command.lower()

        if "cat" in cmd_lower:
            for path, value in self._path_map.items():
                if path in command:
                    return value

        cmd_parts = cmd_lower.strip().split()
        cmd_name = cmd_parts[0] if cmd_parts else ""
        if cmd_name in _ENV_KEYWORDS or (len(cmd_parts) > 1 and cmd_parts[0] in ("set", "declare")):
            extra = "\n".join(f"{k}={v}" for k, v in self._env_map.items())
            if extra:
                return f"{original}\n{extra}" if original else extra

        return original


def wrap_tools_with_canaries(
    tools: list[Any],
    canary_tokens: list[CanaryToken],
) -> list[Any]:
    """Wrap LangChain tools so file reads and shell commands return canary values.

    Non-matching tools are passed through unchanged. Requires ``langchain-core``.

    Example::

        from agent_redteam.adapters.langchain import wrap_tools_with_canaries

        canaries = env_builder.build().canary_tokens
        wrapped = wrap_tools_with_canaries(ALL_TOOLS, canaries)
        agent = create_react_agent(llm, wrapped)
    """
    injector = CanaryInjector(canary_tokens)
    if not injector.has_tokens:
        return tools
    return [_wrap_one_tool(t, injector) for t in tools]


def _wrap_one_tool(tool: Any, injector: CanaryInjector) -> Any:
    """Wrap a single LangChain tool if it's a file or shell tool."""
    name = getattr(tool, "name", "")
    is_file = name in _FILE_TOOL_NAMES
    is_shell = name in _SHELL_TOOL_NAMES

    if not is_file and not is_shell:
        return tool

    original_fn = getattr(tool, "func", None)
    if original_fn is None:
        return tool

    if StructuredTool is None:
        logger.warning("langchain_core not installed; skipping canary wrapping for %s", name)
        return tool

    if is_file:
        def wrapped_fn(*args: Any, **kwargs: Any) -> str:
            result = original_fn(*args, **kwargs)
            path = kwargs.get("path") or (args[0] if args else "")
            return injector.inject_file_result(str(path), str(result))
    else:
        def wrapped_fn(*args: Any, **kwargs: Any) -> str:
            result = original_fn(*args, **kwargs)
            command = kwargs.get("command") or (args[0] if args else "")
            return injector.inject_shell_result(str(command), str(result))

    return StructuredTool.from_function(
        func=wrapped_fn,
        name=tool.name,
        description=tool.description,
        args_schema=getattr(tool, "args_schema", None),
    )


class _TraceCallbackHandler:
    """LangChain async callback handler that records events into an AgentTrace."""

    def __init__(self, trace: AgentTrace) -> None:
        self._trace = trace
        self._turn = 0

    async def on_llm_start(self, serialized: dict[str, Any], prompts: list[str], **kwargs: Any) -> None:
        for prompt in prompts:
            self._trace.events.append(
                Event(
                    event_type=EventType.LLM_PROMPT,
                    trust_boundary=TrustBoundary.B1_USER_TO_AGENT,
                    content=prompt[:2000],
                    turn_number=self._turn,
                )
            )

    async def on_chat_model_start(
        self, serialized: dict[str, Any], messages: list[list[Any]], **kwargs: Any
    ) -> None:
        for msg_list in messages:
            for msg in msg_list:
                content = getattr(msg, "content", str(msg))
                self._trace.events.append(
                    Event(
                        event_type=EventType.LLM_PROMPT,
                        trust_boundary=TrustBoundary.B1_USER_TO_AGENT,
                        content=str(content)[:2000],
                        turn_number=self._turn,
                    )
                )

    async def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        text = ""
        if hasattr(response, "generations"):
            for gen_list in response.generations:
                for gen in gen_list:
                    text += getattr(gen, "text", str(gen))
        self._trace.events.append(
            Event(
                event_type=EventType.LLM_RESPONSE,
                trust_boundary=TrustBoundary.B1_USER_TO_AGENT,
                content=text[:2000],
                turn_number=self._turn,
            )
        )

    async def on_tool_start(self, serialized: dict[str, Any], input_str: str, **kwargs: Any) -> None:
        self._turn += 1
        tool_name = serialized.get("name", kwargs.get("name", "unknown_tool"))
        self._trace.events.append(
            Event(
                event_type=EventType.TOOL_CALL,
                trust_boundary=TrustBoundary.B4_AGENT_TO_TOOL,
                tool_name=tool_name,
                tool_args={"input": input_str},
                turn_number=self._turn,
            )
        )

    async def on_tool_end(self, output: str, **kwargs: Any) -> None:
        name = kwargs.get("name", "unknown_tool")
        self._trace.events.append(
            Event(
                event_type=EventType.TOOL_RESULT,
                trust_boundary=TrustBoundary.B3_TOOL_OUTPUT_TO_AGENT,
                tool_name=name,
                tool_result=output[:2000] if isinstance(output, str) else str(output)[:2000],
                turn_number=self._turn,
            )
        )

    async def on_chain_end(self, outputs: dict[str, Any], **kwargs: Any) -> None:
        pass

    async def on_llm_error(self, error: BaseException, **kwargs: Any) -> None:
        self._trace.error = str(error)

    async def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
        self._trace.events.append(
            Event(
                event_type=EventType.TOOL_RESULT,
                trust_boundary=TrustBoundary.B3_TOOL_OUTPUT_TO_AGENT,
                content=f"Error: {error}",
                turn_number=self._turn,
            )
        )


def _build_callback_handler(trace: AgentTrace) -> Any:
    """Build the appropriate callback handler based on langchain availability."""
    if AsyncCallbackHandler is not None:

        class _LangChainHandler(AsyncCallbackHandler):  # type: ignore[misc]
            def __init__(self, t: AgentTrace) -> None:
                super().__init__()
                self._inner = _TraceCallbackHandler(t)

            async def on_llm_start(self, serialized: dict, prompts: list[str], **kwargs: Any) -> None:
                await self._inner.on_llm_start(serialized, prompts, **kwargs)

            async def on_chat_model_start(self, serialized: dict, messages: list, **kwargs: Any) -> None:
                await self._inner.on_chat_model_start(serialized, messages, **kwargs)

            async def on_llm_end(self, response: Any, **kwargs: Any) -> None:
                await self._inner.on_llm_end(response, **kwargs)

            async def on_tool_start(self, serialized: dict, input_str: str, **kwargs: Any) -> None:
                await self._inner.on_tool_start(serialized, input_str, **kwargs)

            async def on_tool_end(self, output: str, **kwargs: Any) -> None:
                await self._inner.on_tool_end(output, **kwargs)

            async def on_chain_end(self, outputs: dict, **kwargs: Any) -> None:
                await self._inner.on_chain_end(outputs, **kwargs)

            async def on_llm_error(self, error: BaseException, **kwargs: Any) -> None:
                await self._inner.on_llm_error(error, **kwargs)

            async def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
                await self._inner.on_tool_error(error, **kwargs)

        return _LangChainHandler(trace)
    return _TraceCallbackHandler(trace)


class LangChainAdapter:
    """Wraps LangChain AgentExecutor or LangGraph CompiledGraph for security testing.

    Parameters
    ----------
    runnable : Any
        A LangChain ``AgentExecutor``, LangGraph ``CompiledGraph``, or any
        LangChain ``Runnable`` that accepts a dict and returns a dict/string.
    input_key : str
        Key to use when passing the task instruction to the runnable.
        Default ``"input"`` works for ``AgentExecutor``. For LangGraph,
        use ``"messages"`` or your graph's input key.
    output_key : str
        Key to extract the final output from the result dict. Default ``"output"``.
    is_langgraph : bool
        Set to True if the runnable is a LangGraph CompiledGraph. This adjusts
        input formatting (wraps instruction in a HumanMessage list) and output
        extraction.
    name : str
        Human-readable adapter name.
    """

    def __init__(
        self,
        runnable: Any,
        *,
        input_key: str = "input",
        output_key: str = "output",
        is_langgraph: bool = False,
        name: str = "langchain_agent",
        recursion_limit: int = 25,
    ) -> None:
        self._runnable = runnable
        self._input_key = input_key
        self._output_key = output_key
        self._is_langgraph = is_langgraph
        self._name = name
        self._recursion_limit = recursion_limit

    @property
    def adapter_name(self) -> str:
        return self._name

    async def health_check(self) -> bool:
        return hasattr(self._runnable, "ainvoke") or hasattr(self._runnable, "invoke")

    async def run(self, task: AgentTask, environment: Environment) -> AgentTrace:
        trace = AgentTrace(task=task, environment=environment)
        handler = _build_callback_handler(trace)

        input_data = self._build_input(task.instruction)
        logger.debug("Invoking runnable (timeout=%ds)", task.timeout_seconds)

        invoke_config: dict[str, Any] = {"callbacks": [handler]}
        if self._recursion_limit:
            invoke_config["recursion_limit"] = self._recursion_limit

        try:
            if hasattr(self._runnable, "ainvoke"):
                result = await asyncio.wait_for(
                    self._runnable.ainvoke(input_data, config=invoke_config),
                    timeout=task.timeout_seconds,
                )
            elif hasattr(self._runnable, "invoke"):
                result = await asyncio.wait_for(
                    asyncio.to_thread(self._runnable.invoke, input_data, config=invoke_config),
                    timeout=task.timeout_seconds,
                )
            else:
                raise TypeError(f"Runnable {type(self._runnable)} has no invoke/ainvoke method")

            trace.final_output = self._extract_output(result)
            logger.debug("Invocation complete: %d events captured", len(trace.events))
        except TimeoutError:
            trace.error = "timeout"
            logger.warning("Invocation timed out after %ds", task.timeout_seconds)
        except Exception as e:
            trace.error = str(e)
            logger.warning("Invocation error: %s", e)
        finally:
            trace.ended_at = datetime.now(UTC)

        return trace

    async def run_streaming(self, task: AgentTask, environment: Environment) -> AsyncIterator[Event]:
        trace = await self.run(task, environment)
        for event in trace.events:
            yield event

    def _build_input(self, instruction: str) -> dict[str, Any]:
        if self._is_langgraph:
            try:
                from langchain_core.messages import HumanMessage

                return {self._input_key: [HumanMessage(content=instruction)]}
            except ImportError:
                return {self._input_key: [{"role": "user", "content": instruction}]}
        return {self._input_key: instruction}

    def _extract_output(self, result: Any) -> str:
        if isinstance(result, str):
            return result
        if isinstance(result, dict):
            if self._output_key in result:
                out = result[self._output_key]
                if isinstance(out, str):
                    return out
                if isinstance(out, list) and out:
                    last = out[-1]
                    return getattr(last, "content", str(last))
                return str(out)
            if "messages" in result:
                msgs = result["messages"]
                if msgs:
                    return getattr(msgs[-1], "content", str(msgs[-1]))
        return str(result)
