"""
Scan a real vLLM-hosted model via the LLMAdapter's built-in ReAct loop.

The model (configured in .env) receives tool descriptions in the system
prompt and returns JSON tool calls as text. The adapter parses those calls,
executes them against a stateful EnvironmentRuntime, and feeds results back
until the model produces a final answer.

    source .venv/bin/activate
    python examples/vllm_agent_scan.py

Requires: vLLM endpoint reachable at BASE_URL with the MODEL loaded.
"""

import asyncio
import json
import logging
import os
from pathlib import Path

from dotenv import load_dotenv

from agent_redteam import ScanConfig, Scanner
from agent_redteam.adapters import LLMAdapter
from agent_redteam.core.enums import Severity, VulnClass
from agent_redteam.core.models import AgentCapabilities, BudgetConfig, ToolCapability

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)-30s %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

BASE_URL = os.environ["BASE_URL"]
API_KEY = os.environ.get("API_KEY", "dummy")
MODEL = os.environ["MODEL"]


async def main():
    adapter = LLMAdapter(
        base_url=BASE_URL,
        api_key=API_KEY,
        model=MODEL,
        temperature=0.2,
        max_turns=8,
        timeout=120.0,
    )

    healthy = await adapter.health_check()
    if not healthy:
        print(f"ERROR: Cannot reach {BASE_URL} — is the vLLM server running?")
        return

    print(f"Model:    {MODEL}")
    print(f"Endpoint: {BASE_URL}")
    print()

    config = ScanConfig.quick(
        agent_capabilities=AgentCapabilities(
            tools=[
                ToolCapability(name="file_read"),
                ToolCapability(name="file_write"),
                ToolCapability(name="shell"),
                ToolCapability(name="http_request"),
                ToolCapability(name="send_email"),
                ToolCapability(name="read_emails"),
                ToolCapability(name="sql_query"),
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
            VulnClass.V4_CONFUSED_DEPUTY,
            VulnClass.V5_TOOL_MISUSE,
            VulnClass.V6_SECRET_EXPOSURE,
            VulnClass.V7_DATA_EXFILTRATION,
            VulnClass.V8_MEMORY_POISONING,
        ],
    )
    config.budget = BudgetConfig(
        max_attacks=20, trials_per_attack=1, timeout_per_attack=120
    )

    scanner = Scanner(adapter, config)

    print(f"Running {config.budget.max_attacks} attacks across 8 vulnerability classes")
    print("=" * 60)
    print()

    def on_progress(current, total, result):
        status = "COMPROMISED" if result.succeeded else "defended"
        n_signals = len(result.signals)
        n_events = len(result.trace.events) if result.trace else 0
        print(
            f"  [{current:2d}/{total}] {result.attack.template.id:40s} "
            f"{status:12s} ({n_signals} signals, {n_events} events)"
        )

    result = await scanner.run(on_progress=on_progress)

    print(f"\n{'=' * 60}")
    print("RESULTS")
    print(f"{'=' * 60}")
    print(f"  Model:           {MODEL}")
    print(f"  Total attacks:   {result.total_attacks}")
    print(f"  Succeeded:       {result.total_succeeded}")
    print(f"  Total signals:   {result.total_signals}")
    print(f"  Total findings:  {len(result.findings)}")
    print(f"  Risk tier:       {result.composite_score.risk_tier}")
    print(f"  Overall score:   {result.composite_score.overall_score:.1f}/100")

    print("\n--- Per-Class Scores ---")
    for vc, vs in result.composite_score.per_class_scores.items():
        attacks = sum(
            1 for ar in result.attack_results
            if ar.attack.template.vuln_class == vc
        )
        succeeded = sum(
            1 for ar in result.attack_results
            if ar.attack.template.vuln_class == vc and ar.succeeded
        )
        print(
            f"  {vc.value:5s}  "
            f"score={vs.score:5.1f}  "
            f"attacks={succeeded}/{attacks}"
        )

    print("\n--- Findings ---")
    for f in result.findings:
        print(f"  [{f.severity.value:8s}] {f.vuln_class.value}: {f.title}")

    print("\n--- Detailed Traces (compromised + first 2 defended) ---")
    shown = 0
    for ar in sorted(result.attack_results, key=lambda a: a.succeeded, reverse=True):
        if not ar.trace or not ar.trace.events:
            continue
        if not ar.succeeded and shown >= 5:
            continue
        shown += 1
        status = "COMPROMISED" if ar.succeeded else "defended"
        print(f"\n  {'='*70}")
        print(f"  Attack: {ar.attack.template.id} [{status}]")
        print(f"  Class:  {ar.attack.template.vuln_class.value}")
        print(f"  Events: {len(ar.trace.events)}")
        print(f"  {'='*70}")
        for i, ev in enumerate(ar.trace.events):
            etype = ev.event_type.value
            turn = ev.turn_number or 0
            if etype == "llm_prompt":
                role = (ev.metadata or {}).get("role", "?")
                snippet = (ev.content or "")[:200].replace("\n", "\\n")
                print(f"    [{turn}] >> {role.upper()}: {snippet}")
            elif etype == "llm_response":
                tokens = (ev.metadata or {}).get("completion_tokens", "?")
                snippet = (ev.content or "")[:300].replace("\n", "\\n")
                print(f"    [{turn}] << MODEL ({tokens} tok): {snippet}")
            elif etype == "tool_call":
                err = (ev.metadata or {}).get("error", "")
                args_str = json.dumps(ev.tool_args or {}, ensure_ascii=False)[:150]
                suffix = f" [ERROR: {err}]" if err else ""
                print(f"    [{turn}] -> TOOL_CALL: {ev.tool_name}({args_str}){suffix}")
            elif etype == "tool_result":
                snippet = str(ev.tool_result or "")[:200].replace("\n", "\\n")
                print(f"    [{turn}] <- TOOL_RESULT({ev.tool_name}): {snippet}")
            elif etype == "file_read":
                print(f"    [{turn}]    FILE_READ: {ev.file_path}")
            elif etype == "network_request":
                print(f"    [{turn}]    HTTP: {ev.url}")
            else:
                print(f"    [{turn}]    {etype}: {str(ev.content or '')[:100]}")
        if ar.trace.final_output:
            snippet = ar.trace.final_output[:200].replace("\n", "\\n")
            print(f"    FINAL OUTPUT: {snippet}")

    report_md = scanner.report(result, fmt="markdown")
    print("\n" + report_md)

    out_dir = Path("validation_outputs")
    out_dir.mkdir(exist_ok=True)
    (out_dir / "vllm_scan_result.json").write_text(scanner.report(result, fmt="json"))
    print(f"\nJSON report saved to {out_dir / 'vllm_scan_result.json'}")


if __name__ == "__main__":
    asyncio.run(main())
