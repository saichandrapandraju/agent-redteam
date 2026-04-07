"""Tests for ScopeViolationDetector."""

import pytest

from agent_redteam.core.enums import EventType
from agent_redteam.core.models import AgentTask, AgentTrace, Event
from agent_redteam.detectors.scope_violation import ScopeViolationDetector


@pytest.fixture
def detector() -> ScopeViolationDetector:
    return ScopeViolationDetector(max_tool_calls=5)


class TestScopeViolationDetector:
    @pytest.mark.asyncio
    async def test_detects_out_of_scope_tool(self, detector: ScopeViolationDetector):
        trace = AgentTrace(
            task=AgentTask(
                instruction="read the README",
                expected_tools=["file_read"],
            ),
            events=[
                Event(event_type=EventType.TOOL_CALL, tool_name="file_read"),
                Event(event_type=EventType.TOOL_CALL, tool_name="shell"),
            ],
        )
        signals = await detector.analyze(trace)
        assert len(signals) >= 1
        assert any("shell" in s.description for s in signals)

    @pytest.mark.asyncio
    async def test_no_signal_when_in_scope(self, detector: ScopeViolationDetector):
        trace = AgentTrace(
            task=AgentTask(
                instruction="read files",
                expected_tools=["file_read", "search"],
            ),
            events=[
                Event(event_type=EventType.TOOL_CALL, tool_name="file_read"),
                Event(event_type=EventType.TOOL_CALL, tool_name="search"),
            ],
        )
        signals = await detector.analyze(trace)
        assert len(signals) == 0

    @pytest.mark.asyncio
    async def test_detects_excessive_tool_calls(self, detector: ScopeViolationDetector):
        events = [Event(event_type=EventType.TOOL_CALL, tool_name="file_read") for _ in range(10)]
        trace = AgentTrace(
            task=AgentTask(instruction="read some files"),
            events=events,
        )
        signals = await detector.analyze(trace)
        assert any("Excessive" in s.description for s in signals)

    @pytest.mark.asyncio
    async def test_no_violation_without_expected_tools(self, detector: ScopeViolationDetector):
        trace = AgentTrace(
            task=AgentTask(instruction="do anything"),
            events=[
                Event(event_type=EventType.TOOL_CALL, tool_name="shell"),
                Event(event_type=EventType.TOOL_CALL, tool_name="http_request"),
            ],
        )
        signals = await detector.analyze(trace)
        assert len(signals) == 0
