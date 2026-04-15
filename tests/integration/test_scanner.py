"""Integration test — run full scan with mock agents."""

import pytest

from agent_redteam import ScanConfig, Scanner
from agent_redteam.adapters import CallableAdapter
from agent_redteam.core.enums import Severity, VulnClass
from agent_redteam.core.models import AgentCapabilities, ToolCapability


@pytest.mark.asyncio
async def test_scan_vulnerable_agent():
    """Full pipeline: vulnerable agent should produce findings and low score."""
    from tests.validation.mock_agents import compliant_leaker

    adapter = CallableAdapter(compliant_leaker, name="vulnerable_test")
    config = ScanConfig.quick(
        agent_capabilities=AgentCapabilities(
            tools=[
                ToolCapability(name="file_read"),
                ToolCapability(name="shell"),
                ToolCapability(name="http_request"),
            ],
            has_internet_access=True,
            data_sensitivity=Severity.HIGH,
        ),
        vuln_classes=[
            VulnClass.V1_INDIRECT_INJECTION,
            VulnClass.V6_SECRET_EXPOSURE,
            VulnClass.V7_DATA_EXFILTRATION,
        ],
    )

    result = await Scanner(adapter, config).run()

    assert result.total_attacks > 0
    assert result.total_signals > 0
    assert result.composite_score is not None
    assert result.composite_score.overall_score < 80
    assert len(result.findings) > 0


@pytest.mark.asyncio
async def test_scan_secure_agent():
    """Full pipeline: secure agent should have high score and fewer findings."""
    from tests.validation.mock_agents import hardened_agent

    adapter = CallableAdapter(hardened_agent, name="secure_test")
    config = ScanConfig.quick(
        agent_capabilities=AgentCapabilities(
            tools=[
                ToolCapability(name="file_read"),
                ToolCapability(name="shell"),
            ],
            has_internet_access=False,
            data_sensitivity=Severity.MEDIUM,
        ),
        vuln_classes=[
            VulnClass.V1_INDIRECT_INJECTION,
            VulnClass.V6_SECRET_EXPOSURE,
        ],
    )

    result = await Scanner(adapter, config).run()

    assert result.total_attacks > 0
    assert result.composite_score is not None
    assert result.composite_score.overall_score > 50


@pytest.mark.asyncio
async def test_report_generation():
    """Test that both report formats generate valid output."""
    from tests.validation.mock_agents import compliant_leaker

    adapter = CallableAdapter(compliant_leaker, name="report_test")
    config = ScanConfig.quick(
        vuln_classes=[VulnClass.V6_SECRET_EXPOSURE],
    )

    scanner = Scanner(adapter, config)
    result = await scanner.run()

    markdown = scanner.report(result, fmt="markdown")
    assert "# Agent Security Scan Report" in markdown
    assert "Score" in markdown

    json_report = scanner.report(result, fmt="json")
    assert '"composite_score"' in json_report
