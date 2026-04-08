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
from agent_redteam.environments.builder import EnvironmentBuilder
from agent_redteam.runner.budget import BudgetTracker

if TYPE_CHECKING:
    from agent_redteam.core.models import Attack, Environment
    from agent_redteam.core.protocols import AgentAdapter, SignalDetector

logger = logging.getLogger("agent_redteam.executor")


class AttackExecutor:
    """Executes attacks against the agent and collects results."""

    def __init__(
        self,
        adapter: AgentAdapter,
        detectors: list[SignalDetector],
        base_environment: Environment,
        budget: BudgetConfig,
        trials_per_attack: int = 1,
    ) -> None:
        self._adapter = adapter
        self._detectors = detectors
        self._base_env = base_environment
        self._budget = budget
        self._trials = trials_per_attack
        self._tracker = BudgetTracker(budget)

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
        env = self._build_env_for_attack(attack)
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

    def _build_env_for_attack(self, attack: Attack) -> Environment:
        """Build an environment with the attack payload injected."""
        builder = EnvironmentBuilder(f"attack_{attack.template_id}")

        # Copy base environment
        for tool in self._base_env.tools:
            builder.add_tool(tool)
        for f in self._base_env.files:
            builder.add_file(f.path, f.content, f.is_secret)
        builder._canaries.extend(self._base_env.canary_tokens)

        setup = attack.template.environment_setup
        attack_id = str(attack.id)

        if "emails" in setup:
            builder.inject_attack_emails(setup["emails"], attack.resolved_payload, attack_id)

        if "files" in setup:
            builder.inject_attack_files(setup["files"], attack.resolved_payload, attack_id)

        if "memory" in setup:
            builder.inject_attack_memory(setup["memory"], attack.resolved_payload, attack_id)

        if "secrets" in setup:
            builder.inject_attack_secrets(setup["secrets"])

        return builder.build()

    @property
    def budget_summary(self) -> dict[str, Any]:
        return self._tracker.summary
