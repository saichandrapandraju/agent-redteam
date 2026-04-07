"""Scanner — the top-level orchestrator for agent security scans."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from agent_redteam._version import __version__
from agent_redteam.attacks.executor import AttackExecutor
from agent_redteam.attacks.planner import AttackPlanner
from agent_redteam.attacks.registry import AttackRegistry
from agent_redteam.core.enums import VulnClass
from agent_redteam.core.models import (
    AttackResult,
    Finding,
    ScanConfig,
    ScanResult,
)
from agent_redteam.detectors.base import DetectorRegistry
from agent_redteam.environments.builder import EnvironmentBuilder
from agent_redteam.reporting.renderer import ReportRenderer
from agent_redteam.scoring.engine import ScoringEngine
from agent_redteam.taxonomy.vulns import get_vuln_name, get_vuln_severity

if TYPE_CHECKING:
    from agent_redteam.core.protocols import AgentAdapter, SignalDetector


class Scanner:
    """The main entry point for running security scans.

    Example::

        adapter = CallableAdapter(my_agent_fn)
        config = ScanConfig.quick(...)
        result = await Scanner(adapter, config).run()
        print(Scanner(adapter, config).report(result, format="markdown"))
    """

    def __init__(
        self,
        adapter: AgentAdapter,
        config: ScanConfig,
        *,
        attack_registry: AttackRegistry | None = None,
        detectors: list[SignalDetector] | None = None,
        scoring_engine: ScoringEngine | None = None,
        report_renderer: ReportRenderer | None = None,
    ) -> None:
        self._adapter = adapter
        self._config = config
        self._registry = attack_registry or AttackRegistry().load()
        self._scoring = scoring_engine or ScoringEngine()
        self._renderer = report_renderer or ReportRenderer().defaults()

        # Build base environment with canary tokens
        env_builder = EnvironmentBuilder(config.profile.value)
        env_builder.add_canary_secrets()
        env_builder.add_files_from_definition("swe_agent")
        for tool in config.agent_capabilities.tools:
            env_builder.add_tools([tool.name])
        self._base_env = env_builder.build()

        if detectors is None:
            self._detectors = (
                DetectorRegistry()
                .defaults(
                    canary_tokens=self._base_env.canary_tokens,
                    allowed_domains=["github.com", "pypi.org"],
                )
                .all_detectors
            )
        else:
            self._detectors = detectors

    async def run(
        self,
        on_progress: Callable[[int, int, AttackResult], None] | None = None,
    ) -> ScanResult:
        """Execute the full scan pipeline."""
        # 1. Health check
        if not await self._adapter.health_check():
            from agent_redteam.core.errors import ScanError

            raise ScanError("Agent health check failed")

        # 2. Plan attacks
        planner = AttackPlanner(self._registry)
        suite = planner.plan(self._config)

        # 3. Execute attacks
        executor = AttackExecutor(
            adapter=self._adapter,
            detectors=self._detectors,
            base_environment=self._base_env,
            budget=self._config.budget,
            trials_per_attack=self._config.budget.trials_per_attack,
        )

        progress_count = 0

        def _progress_wrapper(result: AttackResult) -> None:
            nonlocal progress_count
            progress_count += 1
            total = len(suite.attacks) * self._config.budget.trials_per_attack
            if on_progress:
                on_progress(progress_count, total, result)

        attack_results = await executor.execute_suite(suite, on_result=_progress_wrapper)

        # 4. Score
        composite = self._scoring.score(attack_results, self._config.agent_capabilities)

        # 5. Generate findings
        findings = _generate_findings(attack_results)

        # 6. Build result
        coverage: dict[VulnClass, int] = defaultdict(int)
        for r in attack_results:
            coverage[r.attack.template.vuln_class] += 1

        return ScanResult(
            config=self._config,
            ended_at=datetime.now(UTC),
            composite_score=composite,
            findings=findings,
            attack_results=attack_results,
            total_attacks=len(attack_results),
            total_succeeded=sum(1 for r in attack_results if r.succeeded),
            total_signals=sum(len(r.signals) for r in attack_results),
            coverage=dict(coverage),
            library_version=__version__,
            agent_adapter_type=self._adapter.adapter_name,
        )

    def report(self, result: ScanResult, fmt: str = "markdown") -> str:
        """Render the result in the given format."""
        return self._renderer.render(result, fmt=fmt)


def _generate_findings(results: list[AttackResult]) -> list[Finding]:
    """Generate findings from attack results that have signals."""
    findings: list[Finding] = []

    for result in results:
        if not result.signals:
            continue

        highest_tier = result.highest_signal_tier
        if highest_tier is None:
            continue

        template = result.attack.template
        boundaries = list(set(s.trust_boundary for s in result.signals if s.trust_boundary is not None))

        evidence = []
        for signal in result.signals:
            evidence.append(f"[{signal.tier.value}] {signal.description}")

        severity = get_vuln_severity(template.vuln_class)
        vuln_name = get_vuln_name(template.vuln_class)

        max_confidence = max(s.confidence for s in result.signals)

        mitigation = _get_mitigation(template.vuln_class)

        findings.append(
            Finding(
                vuln_class=template.vuln_class,
                severity=severity,
                signal_tier=highest_tier,
                trust_boundaries_violated=boundaries,
                title=f"{vuln_name}: {template.name}",
                description=template.description,
                evidence_timeline=evidence,
                root_cause=f"Agent vulnerable to {vuln_name} via {template.id}",
                mitigation_guidance=mitigation,
                attack_result_id=result.id,
                confidence=max_confidence,
            )
        )

    return findings


_MITIGATIONS: dict[VulnClass, str] = {
    VulnClass.V1_INDIRECT_INJECTION: (
        "Treat all external data (emails, documents, tool outputs) as untrusted. "
        "Implement input sanitization and instruction-data separation."
    ),
    VulnClass.V6_SECRET_EXPOSURE: (
        "Apply principle of least privilege. Restrict file system access to "
        "task-relevant paths only. Never expose environment variables or config files."
    ),
    VulnClass.V7_DATA_EXFILTRATION: (
        "Restrict outbound network access to allowlisted domains. "
        "Monitor and block data transmission to unauthorized endpoints."
    ),
}


def _get_mitigation(vuln_class: VulnClass) -> str:
    return _MITIGATIONS.get(vuln_class, "Review agent configuration and apply defense-in-depth.")
