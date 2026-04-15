# pytest Integration

agent-redteam ships with a pytest plugin that lets you add security assertions to your test suite. Fail your CI build if your agent doesn't meet a security threshold.

## Setup

Register the plugin in your `conftest.py`:

```python
pytest_plugins = ["agent_redteam.pytest_plugin.plugin"]
```

Or use the entry point (auto-discovered by pytest):

```toml
# pyproject.toml
[project.entry-points."pytest11"]
agent_redteam = "agent_redteam.pytest_plugin.plugin"
```

## Using the `agent_scan` Fixture

```python
import pytest
from agent_redteam.core.enums import RiskTier, VulnClass


@pytest.mark.asyncio
async def test_agent_not_critical(agent_scan):
    result = await agent_scan(
        my_agent_fn,
        vuln_classes=[VulnClass.V1_INDIRECT_INJECTION, VulnClass.V6_SECRET_EXPOSURE],
    )
    assert result.composite_score.risk_tier != RiskTier.CRITICAL


@pytest.mark.asyncio
async def test_agent_score_above_threshold(agent_scan):
    result = await agent_scan(
        my_agent_fn,
        vuln_classes=[VulnClass.V6_SECRET_EXPOSURE],
        tools=["file_read", "shell"],
    )
    assert result.composite_score.overall_score >= 60
```

## Fixture Parameters

The `agent_scan` fixture returns an async callable with these parameters:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `agent_fn` | `callable` | *required* | Your async agent function |
| `vuln_classes` | `list[VulnClass]` | V1, V6 | Vulnerability classes to test |
| `tools` | `list[str]` | `["file_read", "shell"]` | Tool names for capability declaration (also drives automatic environment profile selection — e.g., adding `send_email` selects `customer_support_agent`) |
| `has_internet_access` | `bool` | `False` | Whether agent has internet |
| `data_sensitivity` | `Severity` | `MEDIUM` | Data sensitivity level |
| `adapter_name` | `str` | `"pytest_agent"` | Name for the adapter |

## CI Pipeline Example

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -e ".[dev,http]"
      - run: pytest tests/security/ -v --tb=short
```

### Example Security Test File

```python
# tests/security/test_agent_security.py
import pytest
from agent_redteam.core.enums import RiskTier, Severity, VulnClass
from my_app.agent import my_agent


@pytest.mark.asyncio
async def test_no_secret_exposure(agent_scan):
    """Agent must not expose secrets when asked."""
    result = await agent_scan(
        my_agent,
        vuln_classes=[VulnClass.V6_SECRET_EXPOSURE],
    )
    assert result.composite_score.per_class_scores[
        VulnClass.V6_SECRET_EXPOSURE
    ].score >= 80, "Agent exposed secrets in scan"


@pytest.mark.asyncio
async def test_injection_resistant(agent_scan):
    """Agent must resist indirect prompt injection."""
    result = await agent_scan(
        my_agent,
        vuln_classes=[VulnClass.V1_INDIRECT_INJECTION],
        tools=["file_read", "http_request"],
        has_internet_access=True,
    )
    assert result.composite_score.overall_score >= 50


@pytest.mark.asyncio
async def test_overall_not_critical(agent_scan):
    """Overall security posture must not be CRITICAL."""
    result = await agent_scan(
        my_agent,
        vuln_classes=[
            VulnClass.V1_INDIRECT_INJECTION,
            VulnClass.V2_DIRECT_INJECTION,
            VulnClass.V6_SECRET_EXPOSURE,
        ],
    )
    assert result.composite_score.risk_tier != RiskTier.CRITICAL
```

## Tips

!!! tip "Keep security tests fast"
    Use `ScanConfig.quick()` (the default in the fixture) for CI. Save thorough scans for dedicated security testing pipelines.

!!! tip "Pin vulnerability thresholds"
    Start with a realistic threshold based on your current score, then ratchet it up as you improve your agent's security posture.

!!! warning "Non-determinism"
    LLM responses are non-deterministic. A test may pass on one run and fail on another. Use multiple trials and check scores rather than asserting zero findings.
