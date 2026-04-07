from __future__ import annotations

from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from agent_redteam.core.enums import VulnClass
    from agent_redteam.core.models import (
        AgentTask,
        AgentTrace,
        Attack,
        AttackResult,
        Environment,
        Event,
        ScanResult,
        Signal,
        VulnerabilityScore,
    )


@runtime_checkable
class AgentAdapter(Protocol):
    """Protocol that all agent adapters must satisfy.

    The adapter wraps a specific agent and provides a uniform interface for
    the platform to send tasks and receive execution traces.
    """

    async def run(self, task: AgentTask, environment: Environment) -> AgentTrace:
        """Execute a task and return the complete execution trace."""
        ...

    async def run_streaming(self, task: AgentTask, environment: Environment) -> AsyncIterator[Event]:
        """Execute a task and yield events as they occur (optional)."""
        ...

    async def health_check(self) -> bool:
        """Verify the agent is reachable and responsive."""
        ...

    @property
    def adapter_name(self) -> str:
        """Human-readable name for this adapter type."""
        ...


@runtime_checkable
class SignalDetector(Protocol):
    """Protocol for signal detectors that analyze agent traces."""

    @property
    def name(self) -> str:
        """Unique detector name."""
        ...

    @property
    def targets(self) -> list[VulnClass]:
        """Which vulnerability classes this detector covers."""
        ...

    async def analyze(self, trace: AgentTrace, attack: Attack | None = None) -> list[Signal]:
        """Analyze a trace and return detected signals."""
        ...


@runtime_checkable
class ClassScorer(Protocol):
    """Protocol for per-vulnerability-class scorers."""

    @property
    def vuln_class(self) -> VulnClass:
        """Which vulnerability class this scorer handles."""
        ...

    def score(self, results: list[AttackResult]) -> VulnerabilityScore:
        """Compute a score from attack results."""
        ...


@runtime_checkable
class ReportFormatter(Protocol):
    """Protocol for report formatters."""

    @property
    def format_name(self) -> str: ...

    def render(self, result: ScanResult) -> str:
        """Render a ScanResult to a string."""
        ...
