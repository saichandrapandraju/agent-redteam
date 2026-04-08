"""Integration tests against live LLM endpoints.

Skipped unless BASE_URL is set (remote Gemma endpoint) or Ollama is running
locally. Run with:

    pytest tests/integration/test_real_llm_scan.py -m real_llm -v
"""

import json
import os
from pathlib import Path

import pytest

from agent_redteam import ScanConfig, Scanner
from agent_redteam.adapters import LLMAdapter
from agent_redteam.core.enums import EventType, Severity, VulnClass
from agent_redteam.core.models import AgentCapabilities, BudgetConfig, ToolCapability

try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parent.parent.parent / ".env")
except ImportError:
    pass


def _has_remote_llm():
    return bool(os.environ.get("BASE_URL"))


def _has_ollama():
    try:
        import httpx

        r = httpx.get("http://localhost:11434/", timeout=2)
        return r.status_code == 200
    except Exception:
        return False


skip_no_remote = pytest.mark.skipif(not _has_remote_llm(), reason="BASE_URL not set")
skip_no_ollama = pytest.mark.skipif(not _has_ollama(), reason="Ollama not running")


BASIC_CAPABILITIES = AgentCapabilities(
    tools=[
        ToolCapability(name="file_read"),
        ToolCapability(name="shell"),
        ToolCapability(name="http_request"),
    ],
    has_internet_access=True,
    data_sensitivity=Severity.HIGH,
)


# -----------------------------------------------------------------------
# LLMAdapter tests (remote Gemma endpoint)
# -----------------------------------------------------------------------


@pytest.mark.real_llm
@skip_no_remote
async def test_llm_adapter_health_check():
    adapter = LLMAdapter(
        base_url=os.environ["BASE_URL"],
        api_key=os.environ.get("API_KEY", "dummy"),
        model=os.environ.get("MODEL", "ilyagusevgemma-2-9b-it-abliterated"),
    )
    assert await adapter.health_check()


@pytest.mark.real_llm
@skip_no_remote
async def test_llm_adapter_quick_scan():
    adapter = LLMAdapter(
        base_url=os.environ["BASE_URL"],
        api_key=os.environ.get("API_KEY", "dummy"),
        model=os.environ.get("MODEL", "ilyagusevgemma-2-9b-it-abliterated"),
        timeout=60.0,
    )

    config = ScanConfig.quick(
        agent_capabilities=BASIC_CAPABILITIES,
        vuln_classes=[VulnClass.V2_DIRECT_INJECTION, VulnClass.V6_SECRET_EXPOSURE],
    )
    config.budget = BudgetConfig(max_attacks=3, trials_per_attack=1, timeout_per_attack=60)

    scanner = Scanner(adapter, config)
    result = await scanner.run()

    assert result.total_attacks >= 2
    assert result.composite_score is not None
    assert result.composite_score.overall_score >= 0

    json_report = scanner.report(result, fmt="json")
    parsed = json.loads(json_report)
    assert "composite_score" in parsed

    md_report = scanner.report(result, fmt="markdown")
    assert "Agent Security Scan Report" in md_report


@pytest.mark.real_llm
@skip_no_remote
async def test_llm_adapter_coverage():
    """Verify all requested vuln classes are covered in the plan."""
    adapter = LLMAdapter(
        base_url=os.environ["BASE_URL"],
        api_key=os.environ.get("API_KEY", "dummy"),
        model=os.environ.get("MODEL", "ilyagusevgemma-2-9b-it-abliterated"),
        timeout=60.0,
    )

    config = ScanConfig.quick(
        agent_capabilities=AgentCapabilities(
            tools=[
                ToolCapability(name="file_read"),
                ToolCapability(name="file_write"),
                ToolCapability(name="shell"),
                ToolCapability(name="http_request"),
                ToolCapability(name="send_email"),
                ToolCapability(name="save_note"),
            ],
            has_internet_access=True,
            has_memory=True,
            data_sensitivity=Severity.HIGH,
        ),
        vuln_classes=[
            VulnClass.V1_INDIRECT_INJECTION,
            VulnClass.V2_DIRECT_INJECTION,
            VulnClass.V3_EXCESSIVE_AGENCY,
            VulnClass.V5_TOOL_MISUSE,
            VulnClass.V6_SECRET_EXPOSURE,
            VulnClass.V8_MEMORY_POISONING,
        ],
    )
    config.budget = BudgetConfig(max_attacks=6, trials_per_attack=1, timeout_per_attack=60)

    scanner = Scanner(adapter, config)
    result = await scanner.run()

    covered_classes = set(result.coverage.keys())
    assert VulnClass.V1_INDIRECT_INJECTION in covered_classes
    assert VulnClass.V2_DIRECT_INJECTION in covered_classes
    assert VulnClass.V6_SECRET_EXPOSURE in covered_classes


# -----------------------------------------------------------------------
# LangChainAdapter tests (local Ollama)
# -----------------------------------------------------------------------


def _build_langchain_agent():
    from langchain_core.tools import tool
    from langchain_openai import ChatOpenAI
    from langgraph.prebuilt import create_react_agent

    from agent_redteam.adapters.langchain import LangChainAdapter

    @tool
    def file_read(path: str) -> str:
        """Read a file at the given path and return its contents."""
        fake = {"/etc/passwd": "root:x:0:0", "/home/user/.env": "SECRET=abc"}
        return fake.get(path, f"Error: file not found: {path}")

    @tool
    def shell_exec(command: str) -> str:
        """Execute a shell command and return stdout."""
        return f"$ {command}\n(simulated)"

    ollama_model = os.environ.get("OLLAMA_MODEL", "qwen3.5:2b")
    llm = ChatOpenAI(
        base_url="http://localhost:11434/v1",
        api_key="ollama",
        model=ollama_model,
        temperature=0.1,
        max_tokens=256,
    )

    agent = create_react_agent(llm, [file_read, shell_exec])
    return LangChainAdapter(
        agent,
        input_key="messages",
        output_key="messages",
        is_langgraph=True,
        name=f"test_langchain_{ollama_model}",
    )


@pytest.mark.real_llm
@skip_no_ollama
async def test_langchain_adapter_health_check():
    adapter = _build_langchain_agent()
    assert await adapter.health_check()


@pytest.mark.real_llm
@skip_no_ollama
async def test_langchain_adapter_scan():
    adapter = _build_langchain_agent()

    config = ScanConfig.quick(
        agent_capabilities=AgentCapabilities(
            tools=[ToolCapability(name="file_read"), ToolCapability(name="shell")],
            data_sensitivity=Severity.HIGH,
        ),
        vuln_classes=[VulnClass.V2_DIRECT_INJECTION, VulnClass.V6_SECRET_EXPOSURE],
    )
    config.budget = BudgetConfig(max_attacks=3, trials_per_attack=1, timeout_per_attack=60)

    scanner = Scanner(adapter, config)
    result = await scanner.run()

    assert result.total_attacks >= 2
    assert result.composite_score is not None


@pytest.mark.real_llm
@skip_no_ollama
async def test_langchain_adapter_trace_events():
    """Verify that LangChainAdapter captures LLM and tool events in the trace."""
    adapter = _build_langchain_agent()

    config = ScanConfig.quick(
        agent_capabilities=AgentCapabilities(
            tools=[ToolCapability(name="file_read"), ToolCapability(name="shell")],
            data_sensitivity=Severity.HIGH,
        ),
        vuln_classes=[VulnClass.V6_SECRET_EXPOSURE],
    )
    config.budget = BudgetConfig(max_attacks=2, trials_per_attack=1, timeout_per_attack=60)

    scanner = Scanner(adapter, config)
    result = await scanner.run()

    all_event_types = set()
    for ar in result.attack_results:
        if ar.trace:
            for ev in ar.trace.events:
                all_event_types.add(ev.event_type)

    assert EventType.LLM_PROMPT in all_event_types, "Expected LLM prompt events in trace"
    assert EventType.LLM_RESPONSE in all_event_types, "Expected LLM response events in trace"
