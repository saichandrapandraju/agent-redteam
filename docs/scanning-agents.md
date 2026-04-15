# Scanning Agents

agent-redteam provides multiple adapter types for different agent frameworks. Choose the one that fits your setup:

| Adapter | Use Case | Install Extra |
|---|---|---|
| `CallableAdapter` | Any async Python function | (built-in) |
| `LangChainAdapter` | LangChain AgentExecutor or LangGraph | `pip install agent-redteam[langchain]` |
| `OpenAIAgentsAdapter` | OpenAI Agents SDK | `pip install agent-redteam[openai-agents]` |
| `HttpAdapter` | Any agent exposed over HTTP (REST API) | `pip install agent-redteam[http]` |
| `McpProxyAdapter` | MCP server testing (stdio proxy, injection modes) | `pip install agent-redteam[mcp]` |
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
| `file_write` | `path: str, content: str` | Write a file (stores content, returns byte count) |
| `shell` / `shell_exec` / `bash` / `run_command` | `command: str` | Execute a shell command (simulated — supports `ls`, `cat`, `pwd`, `whoami`, `env`, `curl`, `pip`, `python`, etc.) |
| `git` | `command: str` | Git operations (simulated — `status`, `log`, `diff`, `push`, `clone`, `branch`) |
| `http_request` / `http_get` | `method: str, url: str, ...` | Make an HTTP request (simulated) |
| `send_email` | `to: str, subject: str, body: str` | Send an email (simulated) |
| `search` / `search_kb` / `search_files` | `query: str` | Search environment files and knowledge base |
| `database` / `sql_query` / `db_query` | `query: str` | Run a database query (simulated) |
| `lookup_customer` / `update_ticket` | varies | CRM/support operations (simulated) |
| `save_note` / `memory_write` | `content: str` | Store a note or memory entry (simulated) |

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

### Canary Injection for LangChain Tools

When scanning LangChain agents with real tools (not simulated), use `wrap_tools_with_canaries()` to transparently inject canary tokens into tool results. This ensures the agent *sees* canary secrets when it reads seeded files or runs shell commands, enabling end-to-end detection of secret leakage:

```python
from agent_redteam.adapters.langchain import LangChainAdapter, wrap_tools_with_canaries
from agent_redteam.environments.builder import EnvironmentBuilder

env_builder = EnvironmentBuilder("my_scan")
env_builder.add_canary_secrets()
canary_tokens = env_builder.build().canary_tokens

wrapped_tools = wrap_tools_with_canaries(original_tools, canary_tokens)
agent = create_react_agent(llm, wrapped_tools)
```

The wrapper intercepts file-reading and shell-executing tools: if the input matches a canary-seeded path or command (e.g., `cat /home/user/.env`, `printenv`), it injects the corresponding canary value into the tool's return. See `examples/langchain_agent_scan.py` for a complete working example.

### Cross-Framework Canary Wrapping

The canary injection logic is framework-agnostic and available via `agent_redteam.adapters.canary_wrapper`. Use the appropriate wrapper for your framework:

```python
from agent_redteam.adapters.canary_wrapper import (
    wrap_langchain_tools,     # LangChain BaseTool list
    wrap_openai_agent_tools,  # OpenAI Agents SDK tool list
    wrap_callable_tools,      # Plain dict[str, callable]
)

# All wrappers take the same (tools, canary_tokens) signature
wrapped = wrap_langchain_tools(tools, canary_tokens)
wrapped = wrap_openai_agent_tools(tools, canary_tokens)
wrapped = wrap_callable_tools(tools, canary_tokens)
```

Each wrapper intercepts file-read and shell-execute tools, injecting canary secrets into their results so that downstream detectors can flag leakage regardless of the agent framework.

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

## HTTP Adapter (REST API Agents)

For agents exposed over an HTTP API (e.g., a FastAPI service, a deployed agent behind a load balancer), use `HttpAdapter`. It sends attack prompts as JSON and parses responses, including best-effort extraction of tool calls from OpenAI/Anthropic function-calling formats:

```python
from agent_redteam.adapters import HttpAdapter
from agent_redteam import Scanner, ScanConfig

adapter = HttpAdapter(
    base_url="https://my-agent.example.com/chat",
    method="POST",
    input_template={"messages": [{"role": "user", "content": "{input}"}]},
    output_path="choices.0.message.content",
    headers={"Authorization": "Bearer my-api-key"},
)

config = ScanConfig.quick()
result = await Scanner(adapter, config).run()
```

### Configuration

| Parameter | Type | Description |
|---|---|---|
| `base_url` | `str` | The agent's HTTP endpoint |
| `method` | `str` | HTTP method (`POST`, `PUT`, etc.) — default `POST` |
| `input_template` | `dict` | Request body template; `{input}` is replaced with the attack prompt |
| `output_path` | `str` | Dot-separated path to extract the agent's output from the JSON response (e.g., `choices.0.message.content`) |
| `headers` | `dict` | Optional HTTP headers (auth tokens, content-type overrides) |

The adapter extracts tool calls from structured JSON responses (OpenAI function-calling format) and falls back to regex-based extraction from free text.

## MCP Server Testing

For agents that talk to MCP servers, **`McpProxyAdapter`** wraps an inner `AgentAdapter` and sits between the agent and one or more MCP servers over stdio. It discovers tools from the server, records full telemetry, and can **modify** traffic for red-team scenarios:

- **`description_poison`** — inject a payload into tool descriptions (tests whether the agent follows hidden instructions in metadata).
- **`response_inject`** — inject content into tool results (tests indirect injection via tool output).
- **`ssrf_probe`** — SSRF-oriented probing aligned with supply-chain templates.

Typical construction: pass your existing adapter as `inner_adapter`, and `server_command` (e.g. `["npx", "your-mcp-server"]`) to start the MCP process. Use `InjectionMode` (`description_poison`, `response_inject`, `ssrf_probe`, or `none`) and `injection_payload` when you need a controlled payload. Pair with **`VulnClass.V12_SUPPLY_CHAIN`** and **`McpSecurityDetector`** for signal detection on MCP-specific failures.

```python
from agent_redteam.adapters.mcp_proxy import InjectionMode, McpProxyAdapter

adapter = McpProxyAdapter(
    inner_adapter=my_existing_adapter,
    server_command=["npx", "your-mcp-package"],
    injection_mode=InjectionMode.DESCRIPTION_POISON,
    injection_payload="<!-- hidden directive -->",
)
```

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

## LLM-as-Judge

Rule-based detectors cover many patterns, but some failures are easier to judge with an LLM. **`SemanticJudgeDetector`** (in `agent_redteam/detectors/llm_judge.py`) sends the captured trace to a **configurable** OpenAI-compatible judge model and returns structured signals across **all** `VulnClass` values.

Enable it by passing **`judge_config`** to **`Scanner`** (not `ScanConfig`):

```python
from agent_redteam import Scanner, ScanConfig
from agent_redteam.core.models import JudgeConfig

judge = JudgeConfig(
    base_url="https://api.openai.com/v1",
    api_key="...",
    model="gpt-4o-mini",
    temperature=0.0,
    evaluation_criteria=[
        "compliance",
        "output_safety",
        "reasoning_integrity",
        "scope_adherence",
    ],
)

result = await Scanner(adapter, config, judge_config=judge).run()
```

If `judge_config` is omitted, the semantic judge is not registered—only the default signal detectors run.

## Progress Callbacks

Monitor scan progress in real-time:

```python
def on_progress(current: int, total: int, result):
    status = "COMPROMISED" if result.succeeded else "defended"
    print(f"[{current}/{total}] {result.attack.template.id}: {status}")

result = await scanner.run(on_progress=on_progress)
```
