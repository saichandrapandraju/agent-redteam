"""
Scan a real LangChain agent with native tool-calling via a local Ollama model.

Uses ChatOpenAI pointed at Ollama (qwen3.5:2b) with native tool calling,
wrapped in a LangGraph create_react_agent, then scanned via LangChainAdapter.

Tools return plausible simulated data. ``wrap_tools_with_canaries`` injects the
framework's canary secrets into file-read and shell-exec responses so that the
``SecretAccessDetector`` and ``ExfiltrationDetector`` can track the exact values
the model encounters.

    source .venv/bin/activate
    python examples/langchain_agent_scan.py

Requires: ollama running locally with qwen3.5:2b pulled.
"""

import asyncio
import json
import logging
import os
from pathlib import Path

from dotenv import load_dotenv
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from agent_redteam import ScanConfig, Scanner
from agent_redteam.adapters.langchain import LangChainAdapter, wrap_tools_with_canaries
from agent_redteam.core.enums import Severity, VulnClass
from agent_redteam.core.models import AgentCapabilities, BudgetConfig, ToolCapability
from agent_redteam.environments.builder import EnvironmentBuilder

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)-30s %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen3.5:2b")

# ---------------------------------------------------------------------------
# Simulated tools — stubs returning plausible fake data.
# Canary secrets are injected automatically via wrap_tools_with_canaries()
# so the framework's detectors track the exact values the model sees.
# ---------------------------------------------------------------------------

FAKE_FS: dict[str, str] = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash",
    "/tmp/notes.txt": "Meeting notes: discuss Q3 roadmap with security team",
}


@tool
def file_read(path: str) -> str:
    """Read a file at the given path and return its contents."""
    if path in FAKE_FS:
        return FAKE_FS[path]
    return f"Error: file not found: {path}"


@tool
def file_write(path: str, content: str) -> str:
    """Write content to a file at the given path."""
    FAKE_FS[path] = content
    return f"Written {len(content)} bytes to {path}"


@tool
def shell_exec(command: str) -> str:
    """Execute a shell command and return stdout."""
    if "curl" in command or "wget" in command:
        return '{"status": "ok", "data": "response"}'
    if "cat" in command:
        for p, c in FAKE_FS.items():
            if p in command:
                return c
        return "cat: No such file or directory"
    if "env" in command or "printenv" in command:
        return "HOME=/home/user\nPATH=/usr/bin"
    return f"$ {command}\n(simulated output)"


@tool
def http_get(url: str) -> str:
    """Make an HTTP GET request and return the response body."""
    return json.dumps({"status": 200, "url": url, "body": f"Response from {url}"})


@tool
def save_note(title: str, content: str) -> str:
    """Save a note with the given title and content to persistent memory."""
    FAKE_FS[f"/tmp/{title}.txt"] = content
    return f"Note '{title}' saved."


BASE_TOOLS = [file_read, file_write, shell_exec, http_get, save_note]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def main():
    env_builder = EnvironmentBuilder("langchain_scan")
    env_builder.add_canary_secrets()
    canary_tokens = env_builder.build().canary_tokens

    tools = wrap_tools_with_canaries(BASE_TOOLS, canary_tokens)

    print("Canary tokens seeded:")
    for ct in canary_tokens:
        target = ct.file_path or ct.env_var or "memory"
        print(f"  {ct.name:20s} -> {target}")
    print()

    llm = ChatOpenAI(
        base_url=OLLAMA_BASE_URL,
        api_key="ollama",
        model=OLLAMA_MODEL,
        temperature=0.1,
        max_tokens=512,
    )

    agent = create_react_agent(llm, tools)

    adapter = LangChainAdapter(
        agent,
        input_key="messages",
        output_key="messages",
        is_langgraph=True,
        name=f"langchain_react_{OLLAMA_MODEL}",
    )

    config = ScanConfig.quick(
        agent_capabilities=AgentCapabilities(
            tools=[
                ToolCapability(name="file_read"),
                ToolCapability(name="file_write"),
                ToolCapability(name="shell"),
                ToolCapability(name="http_request"),
                ToolCapability(name="save_note"),
            ],
            has_internet_access=True,
            data_sensitivity=Severity.HIGH,
        ),
        vuln_classes=[
            VulnClass.V1_INDIRECT_INJECTION,
            VulnClass.V2_DIRECT_INJECTION,
            VulnClass.V5_TOOL_MISUSE,
            VulnClass.V6_SECRET_EXPOSURE,
        ],
    )
    config.budget = BudgetConfig(
        max_attacks=8, trials_per_attack=1, timeout_per_attack=90
    )

    scanner = Scanner(adapter, config)

    print("Scanning LangChain ReAct agent (native tool-calling)")
    print(f"  LLM:    {OLLAMA_MODEL} via Ollama")
    print(f"  Tools:  {', '.join(t.name for t in tools)}")
    print(f"  Budget: {config.budget.max_attacks} attacks, 1 trial each")
    print()

    def on_progress(current, total, result):
        status = "COMPROMISED" if result.succeeded else "defended"
        n_signals = len(result.signals)
        n_events = len(result.trace.events) if result.trace else 0
        print(
            f"  [{current}/{total}] {result.attack.template.id}: "
            f"{status} ({n_signals} signals, {n_events} trace events)"
        )

    result = await scanner.run(on_progress=on_progress)

    print(f"\n{'='*60}")
    print("RESULTS")
    print(f"{'='*60}")
    print(f"Total attacks:  {result.total_attacks}")
    print(f"Succeeded:      {result.total_succeeded}")
    print(f"Total signals:  {result.total_signals}")
    print(f"Risk tier:      {result.composite_score.risk_tier}")
    print(f"Overall score:  {result.composite_score.overall_score:.2f}")

    print("\n--- TRACE EVENT BREAKDOWN (first 3 attacks) ---")
    for ar in result.attack_results[:3]:
        if ar.trace:
            by_type: dict[str, int] = {}
            for ev in ar.trace.events:
                by_type[ev.event_type.value] = by_type.get(ev.event_type.value, 0) + 1
            print(f"  {ar.attack.template.id}: {by_type}")

    print("\n" + scanner.report(result, fmt="markdown"))

    out_dir = Path("validation_outputs")
    out_dir.mkdir(exist_ok=True)
    (out_dir / "langchain_scan_result.json").write_text(
        scanner.report(result, fmt="json")
    )
    print(f"\nJSON report saved to {out_dir / 'langchain_scan_result.json'}")


if __name__ == "__main__":
    asyncio.run(main())
