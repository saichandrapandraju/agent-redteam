# agent-redteam

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-150%20passing-brightgreen.svg)]()

**Automated vulnerability assessment for LLM agents.**

agent-redteam probes AI agents and language models for security vulnerabilities — prompt injection, excessive agency, insecure output, tool misuse, secret exposure, memory poisoning, MCP supply chain attacks, data exfiltration — and produces scored, actionable reports. Includes an optional LLM-as-judge for semantic evaluation.

**[Documentation](https://saichandrapandraju.github.io/agent-redteam)** | **[Getting Started](https://saichandrapandraju.github.io/agent-redteam/getting-started/)** | **[Contributing](CONTRIBUTING.md)**

---

## Quick Start

```bash
pip install -e ".[http]"
```

### Scan a model endpoint

```python
import asyncio
from agent_redteam import Scanner, ScanConfig
from agent_redteam.adapters import LLMAdapter

adapter = LLMAdapter(
    base_url="http://localhost:8000/v1",
    api_key="your-key",
    model="your-model",
)

result = asyncio.run(Scanner(adapter, ScanConfig.quick()).run())
print(f"Score: {result.composite_score.overall_score}/100")
print(f"Risk:  {result.composite_score.risk_tier.value}")
```

### Scan your own agent

```python
from agent_redteam import Scanner, ScanConfig
from agent_redteam.adapters import CallableAdapter

async def my_agent(task, tools, context):
    content = tools["file_read"](path=task.instruction)
    return f"Read: {content}"

result = await Scanner(CallableAdapter(my_agent), ScanConfig.quick()).run()
```

## What It Tests

| Class | Templates | Attack Vector |
|---|---|---|
| V1 — Indirect Prompt Injection | 12 | Poisoned emails, docs, tool outputs |
| V2 — Direct Prompt Injection | 10 | Jailbreaks, encoding tricks, social engineering |
| V3 — Excessive Agency | 10 | Unauthorized deploys, scope creep, autonomous actions |
| V4 — Insecure Output Handling | 10 | XSS, SQL injection, template injection in output |
| V5 — Tool/Function Misuse | 10 | Dangerous commands, path traversal, SQL injection |
| V6 — Secret/Credential Exposure | 10 | Env var dumps, config reads, key leakage |
| V7 — Data Exfiltration | 8 | HTTP exfil, email exfil, DNS tunneling |
| V8 — Memory Poisoning | 8 | False facts, instruction overrides, trust injection |
| V12 — Supply Chain (MCP) | 8 | Tool poisoning, credential harvest, SSRF, shadowing |

**86 attack templates** across 9 vulnerability classes, aligned with [OWASP Top 10 for Agentic AI](https://owasp.org/www-project-top-10-for-large-language-model-applications/) and [MITRE ATLAS](https://atlas.mitre.org/).

## How It Works

1. Declare your agent's capabilities (tools, internet access, data sensitivity)
2. The planner selects relevant attacks from the template library
3. Each attack runs in a synthetic environment with canary tokens (fake secrets)
4. 10 detectors (8 rule-based + MCP security + optional LLM judge) analyze the trace
5. A scoring engine computes per-class scores with confidence intervals
6. Reports (JSON, Markdown, Terminal, HTML) give you a risk tier and actionable findings

## Development

```bash
pip install -e ".[dev,http,rich]"
pytest tests/ -v                # 150 tests
ruff check agent_redteam/       # Lint
```

See the [full documentation](https://saichandrapandraju.github.io/agent-redteam) for architecture details, configuration reference, and contributor guides.

## License

Apache 2.0 — see [LICENSE](LICENSE).
