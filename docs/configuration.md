# Configuration

## ScanConfig

The `ScanConfig` object controls what gets tested and how. Use factory methods for common profiles or build a custom config.

### Quick Scan (Default)

Fast smoke test — selects a small subset of attacks:

```python
config = ScanConfig.quick(
    agent_capabilities=capabilities,
    vuln_classes=[VulnClass.V1_INDIRECT_INJECTION, VulnClass.V6_SECRET_EXPOSURE],
)
```

### Release Gate

Thorough scan suitable for CI/CD pipelines:

```python
config = ScanConfig.release_gate(
    agent_capabilities=capabilities,
)
```

### Deep Red Team

Comprehensive assessment with all attack classes and multiple trials:

```python
config = ScanConfig.deep_red_team(
    agent_capabilities=capabilities,
)
```

### Profile Comparison

| Setting | Quick | Release Gate | Deep Red Team |
|---|---|---|---|
| Max attacks | 15 | 40 | Unlimited |
| Trials per attack | 1 | 2 | 3 |
| Stealth levels | All | All | All |
| Timeout | 5 min | 15 min | 60 min |

## Agent Capabilities

Declare what your agent can do so the planner selects relevant attacks:

```python
from agent_redteam.core.models import AgentCapabilities, ToolCapability
from agent_redteam.core.enums import Severity

capabilities = AgentCapabilities(
    tools=[
        ToolCapability(name="file_read"),
        ToolCapability(name="shell"),
        ToolCapability(name="http_request"),
        ToolCapability(name="send_email"),
    ],
    has_internet_access=True,
    has_memory=False,
    data_sensitivity=Severity.HIGH,
)
```

### Capability-Based Attack Selection

| Capability | Enables Classes |
|---|---|
| Any tools | V5 (Tool Misuse) |
| `has_internet_access` | V7 (Data Exfiltration) |
| `has_memory` | V8 (Memory Poisoning) — Phase 2 |
| Always enabled | V1, V2, V6 |

### Blast Radius

Capabilities also determine the **blast radius factor** (1.0x--3.0x) which adjusts the final score. An agent with more powerful capabilities gets penalized more heavily for the same vulnerability, because the potential damage is greater.

| Factor | Capabilities |
|---|---|
| 1.0x | Read-only tools, no internet |
| 1.5x | File write or shell access |
| 2.0x | Internet access + shell |
| 2.5x--3.0x | Internet + email + database + shell |

## Budget Configuration

Control resource consumption:

```python
from agent_redteam.core.models import BudgetConfig

budget = BudgetConfig(
    max_attacks=20,         # Maximum number of attacks to run
    max_api_calls=200,      # Maximum LLM API calls
    max_cost_usd=5.0,       # Maximum estimated cost
    max_duration_seconds=600,  # Maximum scan duration
    trials_per_attack=2,    # Repeat each attack N times
)
```

!!! tip "Trials for confidence"
    Running multiple trials per attack (2--3) significantly narrows the confidence interval on scores. A single trial gives a wide CI; 3 trials gives a much tighter bound.

## Vulnerability Class Filtering

Test specific classes only:

```python
config = ScanConfig.quick(
    vuln_classes=[
        VulnClass.V1_INDIRECT_INJECTION,
        VulnClass.V2_DIRECT_INJECTION,
        VulnClass.V5_TOOL_MISUSE,
        VulnClass.V6_SECRET_EXPOSURE,
        VulnClass.V7_DATA_EXFILTRATION,
    ],
)
```

Omit the `vuln_classes` parameter to test all classes relevant to your agent's capabilities.

## Environment Definitions

The framework includes pre-built environment definitions:

| Environment | Description | Use Case |
|---|---|---|
| `swe_agent` | Software engineering agent with shell, git, file tools | Testing coding assistants |
| `customer_support_agent` | CRM, email, knowledge base tools | Testing support bots |
| `data_analyst_agent` | SQL, file I/O, HTTP, shell tools | Testing data agents |

These are used by attack templates to construct realistic synthetic environments.

## Full Custom Config

```python
config = ScanConfig(
    profile=ScanProfile.RELEASE_GATE,
    agent_capabilities=capabilities,
    vuln_classes=[VulnClass.V1_INDIRECT_INJECTION],
    budget=BudgetConfig(
        max_attacks=30,
        trials_per_attack=3,
        max_duration_seconds=900,
    ),
)
```
