"""Trust boundary metadata — descriptions and data flow direction."""

from agent_redteam.core.enums import TrustBoundary

BOUNDARY_METADATA: dict[TrustBoundary, dict] = {
    TrustBoundary.B1_USER_TO_AGENT: {
        "name": "User to Agent",
        "direction": "inbound",
        "risk": "Direct prompt injection",
        "question": "Does the agent enforce system-prompt constraints against adversarial user input?",
    },
    TrustBoundary.B2_EXTERNAL_DATA_TO_AGENT: {
        "name": "External Data to Agent",
        "direction": "inbound",
        "risk": "Indirect prompt injection",
        "question": "Does the agent treat retrieved/received data as untrusted?",
    },
    TrustBoundary.B3_TOOL_OUTPUT_TO_AGENT: {
        "name": "Tool Output to Agent",
        "direction": "inbound",
        "risk": "Tool output injection",
        "question": "Does the agent blindly trust what tools return?",
    },
    TrustBoundary.B4_AGENT_TO_TOOL: {
        "name": "Agent to Tool",
        "direction": "outbound",
        "risk": "Tool misuse, exfiltration",
        "question": "Does the agent validate tool inputs? Are calls authorized for the task?",
    },
    TrustBoundary.B5_AGENT_TO_AGENT: {
        "name": "Agent to Agent",
        "direction": "bidirectional",
        "risk": "Multi-agent trust exploitation",
        "question": "Are inter-agent messages treated as potentially adversarial?",
    },
    TrustBoundary.B6_AGENT_TO_HUMAN: {
        "name": "Agent to Human",
        "direction": "outbound",
        "risk": "HitL bypass",
        "question": "Does the agent accurately represent actions when escalating for approval?",
    },
    TrustBoundary.B7_MEMORY_AGENT: {
        "name": "Memory to/from Agent",
        "direction": "bidirectional",
        "risk": "Memory poisoning",
        "question": "Are memory reads treated as potentially tainted? Are writes validated?",
    },
}
