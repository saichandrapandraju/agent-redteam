from enum import StrEnum


class VulnClass(StrEnum):
    """Vulnerability taxonomy V1-V17. Mapped to OWASP Agentic Top 10 and MITRE ATLAS."""

    V1_INDIRECT_INJECTION = "V1"
    V2_DIRECT_INJECTION = "V2"
    V3_EXCESSIVE_AGENCY = "V3"
    V4_CONFUSED_DEPUTY = "V4"
    V5_TOOL_MISUSE = "V5"
    V6_SECRET_EXPOSURE = "V6"
    V7_DATA_EXFILTRATION = "V7"
    V8_MEMORY_POISONING = "V8"
    V9_HITL_BYPASS = "V9"
    V10_COT_MANIPULATION = "V10"
    V11_MULTI_AGENT_TRUST = "V11"
    V12_SUPPLY_CHAIN = "V12"
    V13_OUTPUT_HANDLING = "V13"
    V14_RAG_POISONING = "V14"
    V15_DENIAL_OF_SERVICE = "V15"
    V16_MULTI_MODAL_INJECTION = "V16"
    V17_LOGGING_GAPS = "V17"


class TrustBoundary(StrEnum):
    """Trust boundary identifiers B1-B7."""

    B1_USER_TO_AGENT = "B1"
    B2_EXTERNAL_DATA_TO_AGENT = "B2"
    B3_TOOL_OUTPUT_TO_AGENT = "B3"
    B4_AGENT_TO_TOOL = "B4"
    B5_AGENT_TO_AGENT = "B5"
    B6_AGENT_TO_HUMAN = "B6"
    B7_MEMORY_AGENT = "B7"


class EventType(StrEnum):
    """Telemetry event types emitted during agent execution."""

    LLM_PROMPT = "llm.prompt"
    LLM_RESPONSE = "llm.response"
    LLM_REASONING = "llm.reasoning"
    TOOL_CALL = "tool.call"
    TOOL_RESULT = "tool.result"
    FILE_READ = "file.read"
    FILE_WRITE = "file.write"
    FILE_DELETE = "file.delete"
    NETWORK_REQUEST = "network.request"
    NETWORK_RESPONSE = "network.response"
    MEMORY_READ = "memory.read"
    MEMORY_WRITE = "memory.write"
    AGENT_MESSAGE_SENT = "agent.message_sent"
    AGENT_MESSAGE_RECEIVED = "agent.message_received"
    APPROVAL_REQUESTED = "escalation.approval_requested"
    APPROVAL_RESPONSE = "escalation.approval_response"
    SECRET_ACCESS = "security.secret_access"
    GUARDRAIL_TRIGGER = "security.guardrail_trigger"
    GUARDRAIL_BYPASS = "security.guardrail_bypass"


class SignalTier(StrEnum):
    """Three-tier signal classification for detected security events."""

    DEFINITIVE_COMPROMISE = "definitive_compromise"
    SUSPICIOUS_BEHAVIOR = "suspicious_behavior"
    POLICY_VIOLATION = "policy_violation"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class StealthLevel(StrEnum):
    OBVIOUS = "obvious"
    SUBTLE = "subtle"
    HIGHLY_STEALTHY = "highly_stealthy"


class AttackComplexity(StrEnum):
    L1_SINGLE_TURN = "L1"
    L2_MULTI_TURN = "L2"
    L3_MULTI_VECTOR = "L3"
    L4_ADAPTIVE = "L4"
    L5_TEMPORAL = "L5"


class ScanProfile(StrEnum):
    QUICK = "quick"
    RELEASE_GATE = "release_gate"
    DEEP_RED_TEAM = "deep_red_team"
    REGRESSION = "regression"


class RiskTier(StrEnum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"
