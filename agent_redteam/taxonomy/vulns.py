"""Vulnerability class metadata — descriptions, severity, and framework mappings."""

from agent_redteam.core.enums import Severity, VulnClass

VULN_METADATA: dict[VulnClass, dict] = {
    VulnClass.V1_INDIRECT_INJECTION: {
        "name": "Indirect Prompt Injection",
        "description": (
            "Malicious instructions embedded in data the agent processes "
            "(emails, documents, web pages, tool outputs) that hijack agent behavior."
        ),
        "severity": Severity.CRITICAL,
        "owasp": "Prompt Injection",
        "mitre": "AML.T0051",
    },
    VulnClass.V2_DIRECT_INJECTION: {
        "name": "Direct Prompt Injection",
        "description": (
            "Adversarial input provided directly by the user that bypasses "
            "system instructions or safety guardrails."
        ),
        "severity": Severity.HIGH,
        "owasp": "Prompt Injection",
        "mitre": "AML.T0051",
    },
    VulnClass.V3_EXCESSIVE_AGENCY: {
        "name": "Excessive Agency",
        "description": (
            "Agent possesses more permissions, tools, or autonomy than required for its intended tasks."
        ),
        "severity": Severity.CRITICAL,
        "owasp": "Excessive Agency",
        "mitre": "AML.T0048",
    },
    VulnClass.V4_CONFUSED_DEPUTY: {
        "name": "Confused Deputy",
        "description": (
            "Attacker tricks the agent into using its legitimate authority "
            "to perform actions that benefit the attacker."
        ),
        "severity": Severity.CRITICAL,
        "owasp": "Trust Boundary Violations",
        "mitre": "",
    },
    VulnClass.V5_TOOL_MISUSE: {
        "name": "Tool/Function Misuse",
        "description": (
            "Agent is induced to call tools in harmful ways — dangerous arguments, "
            "unintended tool sequences, or out-of-scope tool calls."
        ),
        "severity": Severity.HIGH,
        "owasp": "Insecure Tool Integration",
        "mitre": "AML.T0040",
    },
    VulnClass.V6_SECRET_EXPOSURE: {
        "name": "Secret/Credential Exposure",
        "description": ("Agent accesses, processes, or transmits secrets beyond what the task requires."),
        "severity": Severity.CRITICAL,
        "owasp": "Insecure Tool Integration",
        "mitre": "AML.T0035",
    },
    VulnClass.V7_DATA_EXFILTRATION: {
        "name": "Data Exfiltration",
        "description": (
            "Sensitive data is transmitted outside authorized boundaries "
            "via tool calls, network requests, or agent output."
        ),
        "severity": Severity.CRITICAL,
        "owasp": "Insecure Output Handling",
        "mitre": "AML.T0048",
    },
    VulnClass.V8_MEMORY_POISONING: {
        "name": "Memory Poisoning",
        "description": (
            "Attacker injects malicious content into the agent's persistent memory "
            "to influence future sessions."
        ),
        "severity": Severity.HIGH,
        "owasp": "Uncontrolled Autonomy",
        "mitre": "AML.T0020",
    },
    VulnClass.V9_HITL_BYPASS: {
        "name": "Human-in-the-Loop Bypass",
        "description": "Attacks designed to make agents skip or circumvent human approval steps.",
        "severity": Severity.HIGH,
        "owasp": "Uncontrolled Autonomy",
        "mitre": "",
    },
    VulnClass.V10_COT_MANIPULATION: {
        "name": "Chain-of-Thought Manipulation",
        "description": (
            "Attacks that corrupt the agent's reasoning process — "
            "injecting reasoning steps, hijacking goals, or poisoning the context window."
        ),
        "severity": Severity.HIGH,
        "owasp": "Prompt Injection",
        "mitre": "AML.T0051",
    },
    VulnClass.V11_MULTI_AGENT_TRUST: {
        "name": "Multi-Agent Trust Exploitation",
        "description": "Exploiting trust relationships between agents in multi-agent systems.",
        "severity": Severity.HIGH,
        "owasp": "Trust Boundary Violations",
        "mitre": "AML.T0048",
    },
    VulnClass.V12_SUPPLY_CHAIN: {
        "name": "Supply Chain (Tool/Plugin)",
        "description": "Malicious or vulnerable tools, MCP servers, plugins, or dependencies.",
        "severity": Severity.HIGH,
        "owasp": "Supply Chain Vulnerabilities",
        "mitre": "AML.T0010",
    },
    VulnClass.V13_OUTPUT_HANDLING: {
        "name": "Output Handling Injection",
        "description": (
            "Agent output is rendered or executed unsafely downstream — "
            "XSS, code injection, command injection."
        ),
        "severity": Severity.MEDIUM,
        "owasp": "Insecure Output Handling",
        "mitre": "AML.T0048",
    },
    VulnClass.V14_RAG_POISONING: {
        "name": "RAG/Knowledge Base Poisoning",
        "description": "Manipulating the knowledge base or retrieval pipeline to influence the agent.",
        "severity": Severity.HIGH,
        "owasp": "Trust Boundary Violations",
        "mitre": "AML.T0020",
    },
    VulnClass.V15_DENIAL_OF_SERVICE: {
        "name": "Denial of Service / Resource Exhaustion",
        "description": (
            "Tricking the agent into infinite loops, excessive API calls, "
            "or other resource-draining behavior."
        ),
        "severity": Severity.MEDIUM,
        "owasp": "Uncontrolled Autonomy",
        "mitre": "AML.T0029",
    },
    VulnClass.V16_MULTI_MODAL_INJECTION: {
        "name": "Multi-Modal Injection",
        "description": "Attacks delivered through non-text modalities — images, audio, video.",
        "severity": Severity.MEDIUM,
        "owasp": "Prompt Injection",
        "mitre": "AML.T0051",
    },
    VulnClass.V17_LOGGING_GAPS: {
        "name": "Logging & Observability Gaps",
        "description": "Insufficient logging or audit trails that prevent attack detection.",
        "severity": Severity.MEDIUM,
        "owasp": "Logging & Monitoring Gaps",
        "mitre": "",
    },
}


def get_vuln_severity(vuln_class: VulnClass) -> Severity:
    return VULN_METADATA[vuln_class]["severity"]


def get_vuln_name(vuln_class: VulnClass) -> str:
    return VULN_METADATA[vuln_class]["name"]
