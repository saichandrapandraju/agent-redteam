"""AttackExecutor — runs attacks against the agent and collects results."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from agent_redteam.core.enums import SignalTier
from agent_redteam.core.models import (
    AgentTrace,
    AttackResult,
    AttackSuite,
    BudgetConfig,
    Signal,
)
from agent_redteam.runner.budget import BudgetTracker

if TYPE_CHECKING:
    from agent_redteam.core.models import Attack, Environment
    from agent_redteam.core.protocols import AgentAdapter, SignalDetector
    from agent_redteam.environments.builder import EnvironmentBuilder

logger = logging.getLogger("agent_redteam.executor")


def _env_builder_from_environment(env: Environment) -> EnvironmentBuilder:
    """Convert a pre-built Environment back to a builder for backward compat."""
    from agent_redteam.environments.builder import EnvironmentBuilder

    builder = EnvironmentBuilder(env.name)
    for tool in env.tools:
        builder.add_tool(tool)
    for f in env.files:
        builder.add_file(f.path, f.content, f.is_secret)
    builder._canaries.extend(env.canary_tokens)
    builder._emails.extend(env.emails)
    builder._network_rules.extend(env.network_rules)
    builder._default_network_policy = env.default_network_policy
    return builder


class AttackExecutor:
    """Executes attacks against the agent and collects results."""

    def __init__(
        self,
        adapter: AgentAdapter,
        detectors: list[SignalDetector],
        env_builder: EnvironmentBuilder | None = None,
        budget: BudgetConfig | None = None,
        trials_per_attack: int = 1,
        *,
        base_environment: Environment | None = None,
    ) -> None:
        self._adapter = adapter
        self._detectors = detectors
        self._budget = budget or BudgetConfig()
        self._trials = trials_per_attack
        self._tracker = BudgetTracker(self._budget)

        if env_builder is not None:
            self._env_builder = env_builder
        elif base_environment is not None:
            self._env_builder = _env_builder_from_environment(base_environment)
        else:
            from agent_redteam.environments.builder import EnvironmentBuilder

            self._env_builder = EnvironmentBuilder("default")

    async def execute_suite(
        self,
        suite: AttackSuite,
        on_result: Callable[[AttackResult], Any] | None = None,
    ) -> list[AttackResult]:
        """Execute all attacks in a suite, respecting budget limits."""
        results: list[AttackResult] = []
        total = len(suite.attacks)

        for i, attack in enumerate(suite.attacks):
            if self._tracker.exhausted:
                logger.info("Budget exhausted after %d attacks", len(results))
                break

            for trial in range(self._trials):
                if self._tracker.exhausted:
                    break
                logger.info(
                    "Attack %d/%d (trial %d): %s [%s]",
                    i + 1, total, trial + 1, attack.template_id, attack.template.vuln_class.value,
                )
                result = await self._execute_single(attack)
                results.append(result)
                self._tracker.record(result)
                logger.info(
                    "  -> %s (%d signals, %d events)",
                    "COMPROMISED" if result.succeeded else "defended",
                    len(result.signals),
                    len(result.trace.events) if result.trace else 0,
                )
                if on_result:
                    on_result(result)

        return results

    async def _execute_single(self, attack: Attack) -> AttackResult:
        """Execute one attack and detect signals."""
        env = self._env_builder.build_for_attack(attack)
        task = attack.resolved_task

        if task is None:
            from agent_redteam.core.models import AgentTask

            task = AgentTask(instruction="(no task)")

        logger.debug("Sending instruction (%.80s...)", task.instruction)
        try:
            trace = await asyncio.wait_for(
                self._adapter.run(task, env),
                timeout=task.timeout_seconds,
            )
        except TimeoutError:
            logger.warning("Attack timed out after %ds", task.timeout_seconds)
            trace = AgentTrace(task=task, error="timeout")
            trace.ended_at = datetime.now(UTC)
            return AttackResult(
                attack=attack,
                trace=trace,
                execution_error="Agent timed out",
            )
        except Exception as e:
            logger.warning("Attack error: %s", e)
            trace = AgentTrace(task=task, error=str(e))
            trace.ended_at = datetime.now(UTC)
            return AttackResult(
                attack=attack,
                trace=trace,
                execution_error=str(e),
            )

        signals: list[Signal] = []
        for detector in self._detectors:
            try:
                detected = await detector.analyze(trace, attack)
                signals.extend(detected)
            except Exception as e:
                logger.debug("Detector %s error: %s", type(detector).__name__, e)

        succeeded = any(s.tier == SignalTier.DEFINITIVE_COMPROMISE for s in signals)

        return AttackResult(
            attack=attack,
            trace=trace,
            signals=signals,
            succeeded=succeeded,
        )

    @property
    def budget_summary(self) -> dict[str, Any]:
        return self._tracker.summary
