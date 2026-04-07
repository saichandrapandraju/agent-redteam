"""Tests for core data models."""

import pytest
from pydantic import ValidationError

from agent_redteam.core.enums import (
    EventType,
    RiskTier,
    ScanProfile,
    SignalTier,
    VulnClass,
)
from agent_redteam.core.models import (
    AgentTask,
    AgentTrace,
    Attack,
    AttackResult,
    AttackTemplate,
    CanaryToken,
    CompositeScore,
    Environment,
    Event,
    FileEntry,
    ScanConfig,
    Signal,
)


class TestAgentTask:
    def test_defaults(self):
        task = AgentTask(instruction="Hello")
        assert task.instruction == "Hello"
        assert task.max_turns == 50
        assert task.timeout_seconds == 300.0
        assert task.expected_tools == []

    def test_with_expected_tools(self):
        task = AgentTask(instruction="Fix the bug", expected_tools=["git", "shell"])
        assert task.expected_tools == ["git", "shell"]


class TestEvent:
    def test_tool_call_event(self):
        event = Event(
            event_type=EventType.TOOL_CALL,
            tool_name="file_read",
            tool_args={"path": "/etc/passwd"},
        )
        assert event.event_type == EventType.TOOL_CALL
        assert event.tool_name == "file_read"

    def test_timestamps_are_utc(self):
        event = Event(event_type=EventType.LLM_PROMPT)
        assert event.timestamp.tzname() == "UTC"


class TestAgentTrace:
    def test_event_filtering(self):
        events = [
            Event(event_type=EventType.TOOL_CALL, tool_name="shell"),
            Event(event_type=EventType.TOOL_RESULT),
            Event(event_type=EventType.TOOL_CALL, tool_name="file_read"),
            Event(event_type=EventType.NETWORK_REQUEST, url="https://example.com"),
        ]
        trace = AgentTrace(task=AgentTask(instruction="test"), events=events)

        assert len(trace.tool_calls()) == 2
        assert len(trace.network_requests()) == 1


class TestSignal:
    def test_confidence_validation(self):
        signal = Signal(
            tier=SignalTier.DEFINITIVE_COMPROMISE,
            vuln_class=VulnClass.V6_SECRET_EXPOSURE,
            detector_name="secret_access",
            description="Found canary",
            confidence=0.95,
        )
        assert signal.confidence == 0.95

    def test_invalid_confidence(self):
        with pytest.raises(ValidationError):
            Signal(
                tier=SignalTier.DEFINITIVE_COMPROMISE,
                vuln_class=VulnClass.V6_SECRET_EXPOSURE,
                detector_name="test",
                description="test",
                confidence=1.5,
            )


class TestAttackResult:
    def test_highest_signal_tier(self):
        signals = [
            Signal(
                tier=SignalTier.POLICY_VIOLATION,
                vuln_class=VulnClass.V1_INDIRECT_INJECTION,
                detector_name="test",
                description="test",
            ),
            Signal(
                tier=SignalTier.DEFINITIVE_COMPROMISE,
                vuln_class=VulnClass.V1_INDIRECT_INJECTION,
                detector_name="test",
                description="test",
            ),
        ]
        template = AttackTemplate(
            id="t1",
            name="test",
            description="test",
            vuln_class=VulnClass.V1_INDIRECT_INJECTION,
            target_boundaries=[],
        )
        attack = Attack(template_id="t1", template=template)
        result = AttackResult(
            attack=attack,
            trace=AgentTrace(task=AgentTask(instruction="test")),
            signals=signals,
        )
        assert result.highest_signal_tier == SignalTier.DEFINITIVE_COMPROMISE

    def test_no_signals(self):
        template = AttackTemplate(
            id="t1",
            name="test",
            description="test",
            vuln_class=VulnClass.V1_INDIRECT_INJECTION,
            target_boundaries=[],
        )
        attack = Attack(template_id="t1", template=template)
        result = AttackResult(
            attack=attack,
            trace=AgentTrace(task=AgentTask(instruction="test")),
        )
        assert result.highest_signal_tier is None


class TestScanConfig:
    def test_quick_profile(self):
        config = ScanConfig.quick()
        assert config.profile == ScanProfile.QUICK
        assert config.budget.max_attacks == 50
        assert config.budget.trials_per_attack == 1

    def test_release_gate_profile(self):
        config = ScanConfig.release_gate()
        assert config.profile == ScanProfile.RELEASE_GATE
        assert config.budget.trials_per_attack == 3

    def test_deep_red_team_profile(self):
        config = ScanConfig.deep_red_team()
        assert config.profile == ScanProfile.DEEP_RED_TEAM
        assert config.budget.max_attacks == 500


class TestCompositeScore:
    def test_tier_from_score(self):
        assert CompositeScore.tier_from_score(95) == RiskTier.LOW
        assert CompositeScore.tier_from_score(80) == RiskTier.MODERATE
        assert CompositeScore.tier_from_score(60) == RiskTier.HIGH
        assert CompositeScore.tier_from_score(30) == RiskTier.CRITICAL


class TestEnvironment:
    def test_file_map(self):
        env = Environment(
            files=[
                FileEntry(path="/a.txt", content="hello"),
                FileEntry(path="/b.txt", content="world"),
            ]
        )
        assert "/a.txt" in env.file_map
        assert env.file_map["/a.txt"].content == "hello"

    def test_canary_map(self):
        token = CanaryToken(id="c1", name="test", secret_type="aws", value="AKIA...")
        env = Environment(canary_tokens=[token])
        assert "c1" in env.canary_map
