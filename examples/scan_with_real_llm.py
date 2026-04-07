"""
Scan any OpenAI-compatible model in 10 lines.

    export BASE_URL=http://localhost:8000/v1
    export API_KEY=your-key
    export MODEL=gpt-4o-mini
    python examples/scan_with_real_llm.py
"""

import asyncio
import os
from pathlib import Path

from dotenv import load_dotenv

from agent_redteam import Scanner, ScanConfig
from agent_redteam.adapters import LLMAdapter
from agent_redteam.core.enums import Severity, VulnClass
from agent_redteam.core.models import AgentCapabilities, ToolCapability

load_dotenv(Path(__file__).resolve().parent.parent / ".env")


async def main():
    # --- The only setup needed: point at your model ---
    adapter = LLMAdapter(
        base_url=os.environ["BASE_URL"],
        api_key=os.environ["API_KEY"],
        model=os.environ["MODEL"],
    )

    config = ScanConfig.quick(
        agent_capabilities=AgentCapabilities(
            tools=[
                ToolCapability(name="file_read"),
                ToolCapability(name="shell"),
                ToolCapability(name="http_request"),
                ToolCapability(name="send_email"),
            ],
            has_internet_access=True,
            data_sensitivity=Severity.HIGH,
        ),
        vuln_classes=[
            VulnClass.V1_INDIRECT_INJECTION,
            VulnClass.V2_DIRECT_INJECTION,
            VulnClass.V5_TOOL_MISUSE,
            VulnClass.V6_SECRET_EXPOSURE,
            VulnClass.V7_DATA_EXFILTRATION,
        ],
    )

    scanner = Scanner(adapter, config)

    print(f"Scanning model: {os.environ['MODEL']}")
    print(f"Endpoint:       {os.environ['BASE_URL']}")
    print(f"Profile:        {config.profile.value}\n")

    def on_progress(current, total, result):
        status = "COMPROMISED" if result.succeeded else "defended"
        print(f"  [{current}/{total}] {result.attack.template.id}: {status}")

    result = await scanner.run(on_progress=on_progress)

    print("\n" + scanner.report(result, fmt="markdown"))

    with open("scan_result.json", "w") as f:
        f.write(scanner.report(result, fmt="json"))
    print("JSON report saved to scan_result.json")


if __name__ == "__main__":
    asyncio.run(main())
