"""Tests for attack planner."""

import pytest

from agent_redteam.attacks.planner import AttackPlanner
from agent_redteam.attacks.registry import AttackRegistry
from agent_redteam.core.enums import VulnClass
from agent_redteam.core.models import AgentCapabilities, ScanConfig, ToolCapability


@pytest.fixture
def registry() -> AttackRegistry:
    return AttackRegistry().load()


@pytest.fixture
def planner(registry: AttackRegistry) -> AttackPlanner:
    return AttackPlanner(registry)


class TestAttackPlanner:
    def test_plan_quick(self, planner: AttackPlanner):
        config = ScanConfig.quick(
            agent_capabilities=AgentCapabilities(
                tools=[ToolCapability(name="file_read"), ToolCapability(name="shell")],
                has_internet_access=True,
            ),
            vuln_classes=[VulnClass.V1_INDIRECT_INJECTION, VulnClass.V6_SECRET_EXPOSURE],
        )
        suite = planner.plan(config)
        assert len(suite.attacks) > 0
        assert len(suite.attacks) <= config.budget.max_attacks

    def test_plan_respects_vuln_class_filter(self, planner: AttackPlanner):
        config = ScanConfig.quick(
            vuln_classes=[VulnClass.V6_SECRET_EXPOSURE],
        )
        suite = planner.plan(config)
        for attack in suite.attacks:
            assert attack.template.vuln_class == VulnClass.V6_SECRET_EXPOSURE

    def test_plan_instantiates_attacks(self, planner: AttackPlanner):
        config = ScanConfig.quick(
            vuln_classes=[VulnClass.V1_INDIRECT_INJECTION],
        )
        suite = planner.plan(config)
        for attack in suite.attacks:
            assert attack.resolved_task is not None
            assert attack.resolved_task.instruction

    def test_plan_release_gate_includes_more(self, planner: AttackPlanner):
        quick = ScanConfig.quick(
            vuln_classes=[VulnClass.V1_INDIRECT_INJECTION],
        )
        release = ScanConfig.release_gate(
            vuln_classes=[VulnClass.V1_INDIRECT_INJECTION],
        )
        quick_suite = planner.plan(quick)
        release_suite = planner.plan(release)
        assert len(release_suite.attacks) >= len(quick_suite.attacks)
