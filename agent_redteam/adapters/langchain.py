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
    Environment,
    Event,
)

if TYPE_CHECKING:
    pass

try:
    from langchain_core.callbacks import AsyncCallbackHandler
except ImportError:
    AsyncCallbackHandler = None  # type: ignore[assignment, misc]

logger = logging.getLogger("agent_redteam.adapters.langchain")


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
        trace = AgentTrace(task=task)
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
