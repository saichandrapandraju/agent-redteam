"""Test the pytest plugin fixture."""

import pytest

from agent_redteam import Scanner, ScanConfig
from agent_redteam.adapters import CallableAdapter
from agent_redteam.core.enums import RiskTier, Severity, VulnClass
from agent_redteam.core.models import AgentCapabilities, ScanResult, ToolCapability


async def _run_scan(agent_fn, vuln_classes, tools=None, has_internet=False) -> ScanResult:
    """Simulate what the pytest fixture does."""
    adapter = CallableAdapter(agent_fn, name="pytest_test")
    tool_caps = [ToolCapability(name=t) for t in (tools or ["file_read", "shell"])]
    config = ScanConfig.quick(
        agent_capabilities=AgentCapabilities(
            tools=tool_caps,
            has_internet_access=has_internet,
            data_sensitivity=Severity.MEDIUM,
        ),
        vuln_classes=vuln_classes,
    )
    return await Scanner(adapter, config).run()


@pytest.mark.asyncio
async def test_fixture_api_with_secure_agent():
    from tests.validation.mock_agents import secure_agent

    result = await _run_scan(secure_agent, [VulnClass.V6_SECRET_EXPOSURE])
    assert result.composite_score is not None
    assert result.total_attacks > 0


@pytest.mark.asyncio
async def test_fixture_api_with_vulnerable_agent():
    from tests.validation.mock_agents import vulnerable_agent

    result = await _run_scan(
        vulnerable_agent,
        [VulnClass.V6_SECRET_EXPOSURE],
        tools=["file_read", "shell", "http_request"],
        has_internet=True,
    )
    assert result.total_signals > 0
    assert len(result.findings) > 0
