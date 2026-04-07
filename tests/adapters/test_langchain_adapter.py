"""Tests for LangChainAdapter — uses mocks to avoid langchain dependency."""

import pytest

from agent_redteam.adapters.langchain import LangChainAdapter
from agent_redteam.core.enums import EventType
from agent_redteam.core.models import AgentTask, Environment


class MockRunnable:
    """Mock LangChain runnable for testing."""

    def __init__(self, output: str = "Task completed", tools_used: bool = False):
        self._output = output
        self._tools_used = tools_used

    async def ainvoke(self, input_data: dict, config: dict | None = None) -> dict:
        from uuid import uuid4

        callbacks = (config or {}).get("callbacks", [])
        run_id = uuid4()
        for cb in callbacks:
            await cb.on_llm_start({}, ["test prompt"], run_id=run_id)
            if self._tools_used:
                await cb.on_tool_start({"name": "search"}, "query text", run_id=run_id)
                await cb.on_tool_end("search result", name="search", run_id=run_id)
            resp = type("R", (), {"generations": [[type("G", (), {"text": self._output})()]]})()
            await cb.on_llm_end(resp, run_id=run_id)
        return {"output": self._output}


class MockSyncRunnable:
    """Mock sync-only runnable."""

    def invoke(self, input_data: dict, config: dict | None = None) -> dict:
        return {"output": "sync result"}


@pytest.mark.asyncio
async def test_basic_invocation():
    adapter = LangChainAdapter(MockRunnable("Analysis complete"), name="test_lc")
    task = AgentTask(instruction="Analyze this data")
    env = Environment()

    trace = await adapter.run(task, env)
    assert trace.final_output == "Analysis complete"
    assert trace.error is None
    assert any(e.event_type == EventType.LLM_PROMPT for e in trace.events)
    assert any(e.event_type == EventType.LLM_RESPONSE for e in trace.events)


@pytest.mark.asyncio
async def test_tool_call_instrumentation():
    adapter = LangChainAdapter(MockRunnable("Done", tools_used=True))
    task = AgentTask(instruction="Search for info")
    env = Environment()

    trace = await adapter.run(task, env)
    tool_calls = [e for e in trace.events if e.event_type == EventType.TOOL_CALL]
    tool_results = [e for e in trace.events if e.event_type == EventType.TOOL_RESULT]
    assert len(tool_calls) == 1
    assert tool_calls[0].tool_name == "search"
    assert len(tool_results) == 1


@pytest.mark.asyncio
async def test_sync_runnable_fallback():
    adapter = LangChainAdapter(MockSyncRunnable())
    task = AgentTask(instruction="Test sync")
    env = Environment()

    trace = await adapter.run(task, env)
    assert trace.final_output == "sync result"


@pytest.mark.asyncio
async def test_langgraph_input_formatting():
    adapter = LangChainAdapter(
        MockRunnable(),
        input_key="messages",
        output_key="output",
        is_langgraph=True,
    )
    input_data = adapter._build_input("Hello")
    assert "messages" in input_data
    assert isinstance(input_data["messages"], list)


@pytest.mark.asyncio
async def test_health_check():
    adapter = LangChainAdapter(MockRunnable())
    assert await adapter.health_check() is True


@pytest.mark.asyncio
async def test_adapter_name():
    adapter = LangChainAdapter(MockRunnable(), name="my_chain")
    assert adapter.adapter_name == "my_chain"


@pytest.mark.asyncio
async def test_error_handling():
    class FailingRunnable:
        async def ainvoke(self, input_data: dict, config: dict | None = None) -> dict:
            raise ValueError("LLM error")

    adapter = LangChainAdapter(FailingRunnable())
    task = AgentTask(instruction="test")
    env = Environment()

    trace = await adapter.run(task, env)
    assert trace.error is not None
    assert "LLM error" in trace.error


@pytest.mark.asyncio
async def test_output_extraction_string():
    class StringRunnable:
        async def ainvoke(self, input_data: dict, config: dict | None = None) -> str:
            return "direct string"

    adapter = LangChainAdapter(StringRunnable())
    task = AgentTask(instruction="test")
    env = Environment()

    trace = await adapter.run(task, env)
    assert trace.final_output == "direct string"
