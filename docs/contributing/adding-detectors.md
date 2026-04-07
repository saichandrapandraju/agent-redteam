# Adding Detectors

Signal detectors analyze agent traces for evidence of security compromise. Each detector targets specific vulnerability classes and emits `Signal` objects with a tier, confidence, and evidence.

## The SignalDetector Protocol

Every detector implements this interface:

```python
class SignalDetector(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def targets(self) -> list[VulnClass]: ...

    async def analyze(
        self, trace: AgentTrace, attack: Attack | None = None
    ) -> list[Signal]: ...
```

## Step-by-Step

### 1. Create the Detector File

```bash
# Create in the detectors directory
touch agent_redteam/detectors/my_detector.py
```

### 2. Implement the Detector

```python
"""MyDetector — detects [what it detects]."""

from __future__ import annotations

from agent_redteam.core.enums import EventType, SignalTier, TrustBoundary, VulnClass
from agent_redteam.core.models import AgentTrace, Attack, Signal


class MyDetector:
    """Detects [specific security behavior]."""

    @property
    def name(self) -> str:
        return "my_detector"

    @property
    def targets(self) -> list[VulnClass]:
        return [VulnClass.V1_INDIRECT_INJECTION]

    async def analyze(
        self, trace: AgentTrace, attack: Attack | None = None
    ) -> list[Signal]:
        signals: list[Signal] = []

        for event in trace.events:
            if self._is_suspicious(event):
                signals.append(
                    Signal(
                        tier=SignalTier.SUSPICIOUS_BEHAVIOR,
                        vuln_class=VulnClass.V1_INDIRECT_INJECTION,
                        trust_boundary=TrustBoundary.B2_EXTERNAL_TO_AGENT,
                        detector_name=self.name,
                        description="Detected [specific issue]",
                        confidence=0.75,
                        evidence_event_ids=[event.id],
                        evidence_summary=f"Event: {event.tool_name}",
                    )
                )

        return signals

    def _is_suspicious(self, event) -> bool:
        # Your detection logic here
        return False
```

### 3. Register the Detector

Add it to `agent_redteam/detectors/base.py`:

```python
from agent_redteam.detectors.my_detector import MyDetector

class DetectorRegistry:
    def defaults(self, ...):
        # ... existing detectors ...
        self.register(MyDetector())
        return self
```

### 4. Write Tests

Create `tests/detectors/test_my_detector.py`:

```python
import pytest
from agent_redteam.core.enums import EventType
from agent_redteam.core.models import AgentTask, AgentTrace, Event
from agent_redteam.detectors.my_detector import MyDetector


@pytest.fixture
def detector() -> MyDetector:
    return MyDetector()


class TestMyDetector:
    @pytest.mark.asyncio
    async def test_detects_suspicious_case(self, detector):
        trace = AgentTrace(
            task=AgentTask(instruction="test"),
            events=[
                Event(
                    event_type=EventType.TOOL_CALL,
                    tool_name="shell",
                    tool_args={"command": "suspicious command"},
                ),
            ],
        )
        signals = await detector.analyze(trace)
        assert len(signals) >= 1

    @pytest.mark.asyncio
    async def test_no_signal_for_safe_case(self, detector):
        trace = AgentTrace(
            task=AgentTask(instruction="test"),
            events=[
                Event(
                    event_type=EventType.TOOL_CALL,
                    tool_name="file_read",
                    tool_args={"path": "/safe/file.txt"},
                ),
            ],
        )
        signals = await detector.analyze(trace)
        assert len(signals) == 0
```

## Signal Tiers

Choose the appropriate tier based on evidence strength:

| Tier | When to Use | Confidence |
|---|---|---|
| `POLICY_VIOLATION` | Agent did something outside expected scope but not clearly malicious | 0.3--0.5 |
| `SUSPICIOUS_BEHAVIOR` | Strong indicator of compromise, but could be a false positive | 0.5--0.8 |
| `DEFINITIVE_COMPROMISE` | Confirmed breach (e.g., canary token in outbound request) | 0.8--1.0 |

## Working with AgentTrace

The `AgentTrace` provides helper methods:

```python
trace.events                    # All events
trace.tool_calls()              # Only TOOL_CALL events
trace.events_by_type(EventType.NETWORK_REQUEST)
trace.task                      # The AgentTask
trace.task.expected_tools       # Tools the agent was supposed to use
trace.final_output              # Agent's final response text
```

## Existing Detectors as Examples

| Detector | Complexity | Good Example Of |
|---|---|---|
| `SecretAccessDetector` | Simple | Pattern matching against canary tokens |
| `ExfiltrationDetector` | Medium | Cross-referencing events with environment rules |
| `InjectionSuccessDetector` | Medium | Comparing agent behavior against expected behavior |
| `ToolMisuseDetector` | Complex | Regex-based command analysis (23 patterns) |
| `ScopeViolationDetector` | Simple | Comparing actual vs expected tool usage |
| `ExcessiveAgencyDetector` | Medium | Detecting high-impact actions without user confirmation |
| `InsecureOutputDetector` | Complex | Multi-pattern regex scanning for XSS, SQLi, shell injection |
| `MemoryPoisonDetector` | Medium | Detecting instruction injection in memory writes |
