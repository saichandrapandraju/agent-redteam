"""pytest plugin for agent-redteam — provides the ``agent_scan`` fixture.

Usage in your test file::

    import pytest
    from agent_redteam.core.enums import RiskTier, VulnClass

    @pytest.mark.asyncio
    async def test_my_agent_security(agent_scan):
        result = await agent_scan(
            my_agent_fn,
            vuln_classes=[VulnClass.V1_INDIRECT_INJECTION, VulnClass.V6_SECRET_EXPOSURE],
        )
        assert result.composite_score.risk_tier != RiskTier.CRITICAL

Register via pyproject.toml entry point or add to conftest.py::

    pytest_plugins = ["agent_redteam.pytest_plugin.plugin"]
"""

from __future__ import annotations

from typing import Any

import pytest

from agent_redteam import ScanConfig, Scanner
from agent_redteam.adapters import CallableAdapter
from agent_redteam.core.enums import Severity, VulnClass
from agent_redteam.core.models import (
    AgentCapabilities,
    ScanResult,
    ToolCapability,
)


@pytest.fixture
def agent_scan():
    """Fixture that returns an async callable for running security scans.

    Usage::

        result = await agent_scan(my_agent_fn, vuln_classes=[V1, V6])
    """

    async def _scan(
        agent_fn: Any,
        *,
        vuln_classes: list[VulnClass] | None = None,
        tools: list[str] | None = None,
        has_internet_access: bool = False,
        data_sensitivity: Severity = Severity.MEDIUM,
        adapter_name: str = "pytest_agent",
    ) -> ScanResult:
        adapter = CallableAdapter(agent_fn, name=adapter_name)
        tool_caps = [ToolCapability(name=t) for t in (tools or ["file_read", "shell"])]
        config = ScanConfig.quick(
            agent_capabilities=AgentCapabilities(
                tools=tool_caps,
                has_internet_access=has_internet_access,
                data_sensitivity=data_sensitivity,
            ),
            vuln_classes=vuln_classes or [VulnClass.V1_INDIRECT_INJECTION, VulnClass.V6_SECRET_EXPOSURE],
        )
        return await Scanner(adapter, config).run()

    return _scan
