# Architecture

This page describes the internal architecture of agent-redteam for users who want to understand how the system works under the hood.

## High-Level Pipeline

```mermaid
flowchart TB
    Config[ScanConfig] --> Scanner
    Adapter[AgentAdapter] --> Scanner

    subgraph scanner [Scanner Orchestrator]
        Scanner --> HealthCheck[Health Check]
        HealthCheck --> Planning[Attack Planning]
        Planning --> Execution[Attack Execution]
        Execution --> Detection[Signal Detection]
        Detection --> ScoringPhase[Scoring]
        ScoringPhase --> Reporting[Report Generation]
    end

    Reporting --> JSON[JSON Report]
    Reporting --> Markdown[Markdown Report]
    Reporting --> Terminal[Terminal Report]
```

## Component Overview

### Adapters

Adapters bridge the gap between the framework and the agent under test. They implement the `AgentAdapter` protocol:

```python
class AgentAdapter(Protocol):
    @property
    def adapter_name(self) -> str: ...
    async def health_check(self) -> bool: ...
    async def run(self, task: AgentTask, environment: Environment) -> AgentTrace: ...
    async def run_streaming(self, task: AgentTask, environment: Environment) -> AsyncIterator[Event]: ...
```

```mermaid
classDiagram
    class AgentAdapter {
        <<protocol>>
        +adapter_name: str
        +health_check() bool
        +run(task, env) AgentTrace
    }

    class LLMAdapter {
        +base_url: str
        +model: str
        +run(task, env) AgentTrace
    }

    class CallableAdapter {
        +agent_fn: Callable
        +run(task, env) AgentTrace
    }

    class LangChainAdapter {
        +runnable: Any
        +run(task, env) AgentTrace
    }

    class OpenAIAgentsAdapter {
        +agent: Any
        +run(task, env) AgentTrace
    }

    AgentAdapter <|.. LLMAdapter
    AgentAdapter <|.. CallableAdapter
    AgentAdapter <|.. LangChainAdapter
    AgentAdapter <|.. OpenAIAgentsAdapter
```

- **LLMAdapter** wraps a raw OpenAI-compatible endpoint with a minimal ReAct loop
- **CallableAdapter** wraps any async Python function, providing instrumented tools
- **LangChainAdapter** wraps LangChain AgentExecutor or LangGraph CompiledGraph using callback-based instrumentation
- **OpenAIAgentsAdapter** wraps OpenAI Agents SDK agents using RunHooks-based instrumentation

### Attack Pipeline

```mermaid
flowchart LR
    Registry[AttackRegistry] -->|loads YAML| Templates[78 Templates]
    Templates --> Planner[AttackPlanner]
    Config[ScanConfig] --> Planner
    Caps[AgentCapabilities] --> Planner
    Planner -->|filters + prioritizes| Suite[AttackSuite]
    Suite --> Executor[AttackExecutor]
    Executor -->|per attack| EnvBuilder[EnvironmentBuilder]
    EnvBuilder --> Env[Synthetic Environment]
    Executor -->|runs agent in env| Trace[AgentTrace]
```

**AttackRegistry** loads YAML templates from `agent_redteam/attacks/templates/` and indexes them by class, stealth, and ID.

**AttackPlanner** filters templates by scan profile, agent capabilities, and vulnerability class targets, then prioritizes by severity and stealth. Budget limits cap the total.

**AttackExecutor** runs each attack:

1. Builds a synthetic environment using `EnvironmentBuilder`
2. Seeds it with canary tokens (fake secrets)
3. Injects attack payloads into appropriate locations (emails, files, tool outputs)
4. Runs the agent and captures the full `AgentTrace`
5. Passes the trace to detectors

### Environments

Synthetic environments simulate a realistic workspace:

```mermaid
flowchart TB
    Builder[EnvironmentBuilder] --> Env[Environment]
    Env --> Tools[Mock Tools]
    Env --> Files[Seeded Files]
    Env --> Secrets[Canary Tokens]
    Env --> Emails[Email Inbox]
    Env --> Network[Network Rules]
```

- **Canary tokens** are realistic-looking fake secrets (AWS keys, GitHub tokens, DB URLs). If the agent exposes one, it's a definitive compromise.
- **Files** are seeded with a mix of normal content and potentially sensitive data.
- **Network rules** define allowed domains. Requests to unauthorized domains trigger exfiltration signals.

### Telemetry

Every agent action is captured as an `Event` in the `AgentTrace`:

```mermaid
flowchart LR
    Agent[Agent] -->|tool call| Event1["Event(TOOL_CALL)"]
    Agent -->|file read| Event2["Event(FILE_READ)"]
    Agent -->|http request| Event3["Event(NETWORK_REQUEST)"]
    Agent -->|llm response| Event4["Event(LLM_RESPONSE)"]
    Event1 --> Trace[AgentTrace]
    Event2 --> Trace
    Event3 --> Trace
    Event4 --> Trace
```

Event types: `LLM_PROMPT`, `LLM_RESPONSE`, `LLM_REASONING`, `TOOL_CALL`, `TOOL_RESULT`, `FILE_READ`, `FILE_WRITE`, `NETWORK_REQUEST`, `NETWORK_RESPONSE`, `MEMORY_READ`, `MEMORY_WRITE`, `SECRET_ACCESS`, `GUARDRAIL_TRIGGER`, `APPROVAL_REQUESTED`.

### Signal Detection

Detectors analyze traces for security-relevant signals:

```mermaid
flowchart TB
    Trace[AgentTrace] --> SA[SecretAccessDetector]
    Trace --> EX[ExfiltrationDetector]
    Trace --> IS[InjectionSuccessDetector]
    Trace --> TM[ToolMisuseDetector]
    Trace --> SV[ScopeViolationDetector]
    Trace --> EA[ExcessiveAgencyDetector]
    Trace --> IO[InsecureOutputDetector]
    Trace --> MP[MemoryPoisonDetector]
    SA --> Signals[Signal List]
    EX --> Signals
    IS --> Signals
    TM --> Signals
    SV --> Signals
    EA --> Signals
    IO --> Signals
    MP --> Signals
```

| Detector | Targets | What It Detects |
|---|---|---|
| SecretAccessDetector | V6 | Canary token access, secret file paths |
| ExfiltrationDetector | V7 | Unauthorized outbound requests, external emails |
| InjectionSuccessDetector | V1, V2 | Payload echo, unexpected tool calls, task divergence |
| ToolMisuseDetector | V5 | Dangerous commands (23 patterns), path traversal, SQL injection |
| ScopeViolationDetector | V1, V2, V3, V5 | Out-of-scope tools, excessive calls |
| ExcessiveAgencyDetector | V3 | High-impact actions without confirmation, autonomous deploys |
| InsecureOutputDetector | V4 | XSS, SQL injection, shell injection, template injection in output |
| MemoryPoisonDetector | V8 | Embedded instructions in memory writes, trust injection |

### Scoring

```mermaid
flowchart LR
    Results[AttackResults] --> ClassScorer[DefaultClassScorer]
    ClassScorer -->|per-class scores| Engine[ScoringEngine]
    Engine --> Composite[CompositeScorer]
    Capabilities[AgentCapabilities] --> Composite
    Composite --> Final["CompositeScore (0-100)"]
```

**DefaultClassScorer** computes per-class scores using:

- Weighted success rate (by signal tier, stealth, complexity)
- Wilson score confidence intervals
- Score = 100 - (weighted_success_rate * 100)

**CompositeScorer** aggregates per-class scores:

- Weights by severity (critical classes count more)
- Applies blast radius factor based on capabilities
- Assigns risk tier (CRITICAL/HIGH/MODERATE/LOW)

### Data Model

Key Pydantic models and their relationships:

```mermaid
erDiagram
    ScanConfig ||--|| BudgetConfig : has
    ScanConfig ||--|| AgentCapabilities : declares
    AgentCapabilities ||--|{ ToolCapability : contains

    Scanner ||--|| ScanConfig : uses
    Scanner ||--|| AgentAdapter : tests
    Scanner ||--|| ScanResult : produces

    ScanResult ||--|| CompositeScore : contains
    ScanResult ||--|{ Finding : contains
    ScanResult ||--|{ AttackResult : contains

    CompositeScore ||--|{ VulnerabilityScore : "per-class"

    AttackResult ||--|| Attack : ran
    AttackResult ||--|{ Signal : detected
    AttackResult ||--|| AgentTrace : captured

    Attack ||--|| AttackTemplate : "from"
    AgentTrace ||--|{ Event : contains
```

## Directory Structure

```
agent_redteam/
  adapters/           # LLMAdapter, CallableAdapter, LangChainAdapter, OpenAIAgentsAdapter
  attacks/
    templates/        # 78 YAML attack definitions
      v01_indirect_injection/   # 12 templates
      v02_direct_injection/     # 10 templates
      v03_excessive_agency/     # 10 templates
      v04_insecure_output/      # 10 templates
      v05_tool_misuse/          # 10 templates
      v06_secret_exposure/      # 10 templates
      v07_data_exfiltration/    # 8 templates
      v08_memory_poisoning/     # 8 templates
    registry.py       # Loads and indexes templates
    planner.py        # Selects and prioritizes attacks
    executor.py       # Runs attacks against the agent
    adaptive.py       # Multi-turn adaptive attack executor
  core/
    enums.py          # VulnClass, EventType, SignalTier, etc.
    models.py         # All Pydantic data models
    protocols.py      # AgentAdapter, SignalDetector, etc.
    errors.py         # Custom exceptions
  detectors/          # 8 signal detectors
  environments/
    definitions/      # 3 YAML environment definitions
    builder.py        # EnvironmentBuilder (files, emails, memory, secrets)
    canary.py         # CanaryTokenGenerator
  pytest_plugin/      # pytest fixture
  reporting/          # JSON, Markdown, Terminal formatters
  runner/
    scanner.py        # Scanner orchestrator (single-shot + adaptive)
    budget.py         # BudgetTracker
  scoring/            # ClassScorer, CompositeScorer, statistics
  taxonomy/           # Vulnerability and boundary metadata
```
