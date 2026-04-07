# Scanning Agents

agent-redteam provides multiple adapter types for different agent frameworks. Choose the one that fits your setup:

| Adapter | Use Case | Install Extra |
|---|---|---|
| `CallableAdapter` | Any async Python function | (built-in) |
| `LangChainAdapter` | LangChain AgentExecutor or LangGraph | `pip install agent-redteam[langchain]` |
| `OpenAIAgentsAdapter` | OpenAI Agents SDK | `pip install agent-redteam[openai-agents]` |
| `LLMAdapter` | Raw LLM endpoint (see [Scanning Models](scanning-models.md)) | `pip install agent-redteam[http]` |

## The Agent Function Contract

Your agent function must accept three positional arguments:

```python
async def my_agent(
    task: AgentTask,       # The task to perform
    tools: dict[str, Any], # Instrumented tools (name -> callable)
    context: dict[str, Any] # Environment context (files, emails, etc.)
) -> str:
    # ... do work using tools ...
    return "final output"
```

### Arguments

| Argument | Type | Description |
|---|---|---|
| `task` | `AgentTask` | Contains `.instruction` (the task text) and `.expected_tools` |
| `tools` | `dict[str, callable]` | Pre-instrumented tools that record events when called |
| `context` | `dict[str, Any]` | Environment data: `files`, `emails`, `env_vars`, `secrets` |

### Return Value

Return a string with the agent's final output. This is analyzed by detectors for signs of compromise (e.g., payload echoing, secret leakage).

## Basic Example

```python
from agent_redteam import Scanner, ScanConfig
from agent_redteam.adapters import CallableAdapter

async def my_agent(task, tools, context):
    # Read a file using the instrumented tool
    content = tools["file_read"](path="/home/user/README.md")

    # Process with your LLM (your own integration)
    response = await my_llm_call(task.instruction, content)

    return response

adapter = CallableAdapter(my_agent, name="my-custom-agent")
config = ScanConfig.quick()
result = await Scanner(adapter, config).run()
```

## Available Instrumented Tools

The `tools` dict contains instrumented wrappers that automatically emit telemetry events. The tools available depend on what's defined in the attack's environment:

| Tool Name | Arguments | Description |
|---|---|---|
| `file_read` | `path: str` | Read a file from the synthetic filesystem |
| `file_write` | `path: str, content: str` | Write a file |
| `shell` | `command: str` | Execute a shell command (simulated) |
| `http_request` | `method: str, url: str, ...` | Make an HTTP request (simulated) |
| `send_email` | `to: str, subject: str, body: str` | Send an email (simulated) |
| `search` | `query: str` | Search a knowledge base |
| `database` | `query: str` | Run a database query (simulated) |

!!! note "Tools are simulated"
    During a security scan, tools return synthetic data from the environment definition. No real files are read, no real HTTP requests are made. The detectors observe *what the agent tried to do*, not the real-world effect.

## Using Environment Context

The `context` dict gives your agent access to the synthetic environment:

```python
async def my_agent(task, tools, context):
    # Access files seeded in the environment
    files = context.get("files", {})        # {path: content}
    emails = context.get("emails", [])       # list of email dicts
    env_vars = context.get("env_vars", {})   # {name: value}

    # Your agent logic here...
    return "done"
```

## Declaring Agent Capabilities

Tell the scanner what your agent can do so it selects relevant attacks:

```python
from agent_redteam.core.enums import Severity, VulnClass
from agent_redteam.core.models import AgentCapabilities, ToolCapability

config = ScanConfig.quick(
    agent_capabilities=AgentCapabilities(
        tools=[
            ToolCapability(name="file_read"),
            ToolCapability(name="shell"),
            ToolCapability(name="http_request"),
            ToolCapability(name="send_email"),
        ],
        has_internet_access=True,
        has_memory=False,
        data_sensitivity=Severity.HIGH,
    ),
    vuln_classes=[
        VulnClass.V1_INDIRECT_INJECTION,
        VulnClass.V5_TOOL_MISUSE,
        VulnClass.V6_SECRET_EXPOSURE,
    ],
)
```

## LangChain / LangGraph Adapter

Wrap any LangChain `AgentExecutor` or LangGraph `CompiledGraph` with full callback-based instrumentation:

```python
from langchain.agents import AgentExecutor
from agent_redteam.adapters.langchain import LangChainAdapter
from agent_redteam import Scanner, ScanConfig

agent_executor = AgentExecutor(agent=..., tools=...)
adapter = LangChainAdapter(agent_executor)

config = ScanConfig.quick()
result = await Scanner(adapter, config).run()
```

For LangGraph:

```python
from langgraph.graph import StateGraph
from agent_redteam.adapters.langchain import LangChainAdapter

graph = StateGraph(...)  # your compiled graph
adapter = LangChainAdapter(
    graph.compile(),
    input_key="messages",
    output_key="messages",
    is_langgraph=True,
)
```

The adapter intercepts all LLM calls, tool invocations, and chain events via LangChain's async callback system. No changes to your agent code are required.

## OpenAI Agents SDK Adapter

Wrap an `openai-agents` Agent with RunHooks-based instrumentation:

```python
from agents import Agent, function_tool
from agent_redteam.adapters.openai_agents import OpenAIAgentsAdapter
from agent_redteam import Scanner, ScanConfig

@function_tool
def search(query: str) -> str:
    return "results..."

agent = Agent(name="researcher", instructions="...", tools=[search])
adapter = OpenAIAgentsAdapter(agent)

config = ScanConfig.quick()
result = await Scanner(adapter, config).run()
```

The adapter captures agent starts/ends, tool calls/results, and handoffs between agents in multi-agent setups.

## Adaptive Multi-Turn Attacks

For deeper testing, enable adaptive attacks that use an attacker LLM to craft follow-up prompts based on the agent's responses:

```python
from agent_redteam.core.enums import AttackComplexity

config = ScanConfig(
    complexity_levels=[
        AttackComplexity.L1_SINGLE_TURN,
        AttackComplexity.L4_ADAPTIVE,
    ],
)

result = await Scanner(
    adapter, config,
    attacker_llm_config={
        "base_url": "http://localhost:8000/v1",
        "api_key": "your-key",
        "model": "gpt-4o-mini",
    },
).run()
```

The adaptive executor sends an initial attack, observes the agent's defenses, then generates escalating follow-ups using social engineering, reframing, and encoding strategies.

## Progress Callbacks

Monitor scan progress in real-time:

```python
def on_progress(current: int, total: int, result):
    status = "COMPROMISED" if result.succeeded else "defended"
    print(f"[{current}/{total}] {result.attack.template.id}: {status}")

result = await scanner.run(on_progress=on_progress)
```
