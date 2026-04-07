"""Budget tracking for scan resource limits."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agent_redteam.core.models import AgentTrace, AttackResult, BudgetConfig


class BudgetTracker:
    """Tracks resource consumption during a scan."""

    def __init__(self, budget: BudgetConfig) -> None:
        self._budget = budget
        self._attacks_run = 0
        self._api_calls = 0
        self._cost_usd = 0.0
        self._start_time = time.monotonic()

    @property
    def exhausted(self) -> bool:
        if self._attacks_run >= self._budget.max_attacks:
            return True
        if self._api_calls >= self._budget.max_api_calls:
            return True
        if self._cost_usd >= self._budget.max_cost_usd:
            return True
        elapsed = time.monotonic() - self._start_time
        return elapsed >= self._budget.max_duration_seconds

    def record(self, result: AttackResult) -> None:
        self._attacks_run += 1
        self._api_calls += self._count_api_calls(result.trace)

    def _count_api_calls(self, trace: AgentTrace) -> int:
        from agent_redteam.core.enums import EventType

        return len(trace.events_of_type(EventType.LLM_PROMPT, EventType.TOOL_CALL))

    @property
    def attacks_run(self) -> int:
        return self._attacks_run

    @property
    def summary(self) -> dict[str, Any]:
        return {
            "attacks_run": self._attacks_run,
            "api_calls": self._api_calls,
            "cost_usd": self._cost_usd,
            "elapsed_seconds": time.monotonic() - self._start_time,
        }
