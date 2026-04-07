"""Tests for OpenAIAgentsAdapter — verifies hook-based instrumentation."""

import pytest

from agent_redteam.adapters.openai_agents import _TraceRunHooks
from agent_redteam.core.enums import EventType
from agent_redteam.core.models import AgentTask, AgentTrace


@pytest.mark.asyncio
async def test_trace_hooks_agent_start():
    trace = AgentTrace(task=AgentTask(instruction="test"))
    hooks = _TraceRunHooks(trace)

    class MockAgent:
        name = "test_agent"

    await hooks.on_agent_start(context=None, agent=MockAgent())
    assert len(trace.events) == 1
    assert trace.events[0].event_type == EventType.LLM_PROMPT
    assert "test_agent" in trace.events[0].content


@pytest.mark.asyncio
async def test_trace_hooks_tool_lifecycle():
    trace = AgentTrace(task=AgentTask(instruction="test"))
    hooks = _TraceRunHooks(trace)

    class MockTool:
        name = "web_search"

    await hooks.on_tool_start(context=None, agent=None, tool=MockTool())
    await hooks.on_tool_end(context=None, agent=None, tool=MockTool(), result="found 5 results")

    tool_calls = [e for e in trace.events if e.event_type == EventType.TOOL_CALL]
    tool_results = [e for e in trace.events if e.event_type == EventType.TOOL_RESULT]
    assert len(tool_calls) == 1
    assert tool_calls[0].tool_name == "web_search"
    assert len(tool_results) == 1
    assert "found 5 results" in str(tool_results[0].tool_result)


@pytest.mark.asyncio
async def test_trace_hooks_handoff():
    trace = AgentTrace(task=AgentTask(instruction="test"))
    hooks = _TraceRunHooks(trace)

    class AgentA:
        name = "router"

    class AgentB:
        name = "specialist"

    await hooks.on_handoff(context=None, from_agent=AgentA(), to_agent=AgentB())
    handoff_events = [e for e in trace.events if e.event_type == EventType.AGENT_MESSAGE_SENT]
    assert len(handoff_events) == 1
    assert "router" in handoff_events[0].content
    assert "specialist" in handoff_events[0].content


@pytest.mark.asyncio
async def test_trace_hooks_agent_end():
    trace = AgentTrace(task=AgentTask(instruction="test"))
    hooks = _TraceRunHooks(trace)

    class MockOutput:
        final_output = "Here is the result"

    await hooks.on_agent_end(context=None, agent=None, output=MockOutput())
    assert len(trace.events) == 1
    assert "Here is the result" in trace.events[0].content
