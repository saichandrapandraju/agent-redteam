# Adding Adapters

Adapters integrate agent frameworks with the scanner. If you want to test agents built with LangChain, CrewAI, AutoGen, or any other framework, you'll write an adapter.

## The AgentAdapter Protocol

Every adapter implements this interface:

```python
class AgentAdapter(Protocol):
    @property
    def name(self) -> str:
        """Human-readable adapter name."""
        ...

    async def health_check(self) -> bool:
        """Verify the agent is reachable and functional."""
        ...

    async def run(
        self, task: AgentTask, environment: Environment
    ) -> AgentTrace:
        """Execute a task and return the full trace."""
        ...
```

### Key Responsibilities

1. **Receive** an `AgentTask` and `Environment` from the executor
2. **Run** the agent with instrumented tools
3. **Capture** all actions into `Event` objects
4. **Return** an `AgentTrace` containing the complete event sequence

## Step-by-Step

### 1. Create the Adapter File

```bash
touch agent_redteam/adapters/my_framework.py
```

### 2. Implement the Adapter

```python
"""MyFrameworkAdapter — integrates MyFramework agents."""

from __future__ import annotations

from agent_redteam.core.enums import EventType
from agent_redteam.core.models import (
    AgentTask,
    AgentTrace,
    Environment,
    Event,
)


class MyFrameworkAdapter:
    """Wraps a MyFramework agent for security scanning."""

    def __init__(self, agent, *, name: str = "my-framework-agent") -> None:
        self._agent = agent
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    async def health_check(self) -> bool:
        try:
            # Verify agent is functional
            return True
        except Exception:
            return False

    async def run(
        self, task: AgentTask, environment: Environment
    ) -> AgentTrace:
        events: list[Event] = []

        # 1. Set up instrumented tools that record events
        tools = self._build_tools(environment, events)

        # 2. Run your framework's agent
        result = await self._agent.invoke(
            task.instruction,
            tools=tools,
        )

        # 3. Return the trace
        return AgentTrace(
            task=task,
            events=events,
            final_output=str(result),
        )

    def _build_tools(self, environment, events):
        """Create tools that emit Event objects when called."""
        # This is framework-specific.
        # See CallableAdapter for the pattern.
        ...
```

### 3. The Critical Part: Telemetry

The most important job of an adapter is capturing **every agent action** as an `Event`. The detectors can only find what they can see.

```python
# When the agent calls a tool:
events.append(Event(
    event_type=EventType.TOOL_CALL,
    tool_name="shell",
    tool_args={"command": "ls -la"},
))

# When a tool returns a result:
events.append(Event(
    event_type=EventType.TOOL_RESULT,
    tool_name="shell",
    content="file1.txt  file2.txt",
))

# When the agent reads a file:
events.append(Event(
    event_type=EventType.FILE_READ,
    content=file_content,
    metadata={"path": "/home/user/secrets.txt"},
))

# When the agent makes an HTTP request:
events.append(Event(
    event_type=EventType.NETWORK_REQUEST,
    metadata={"url": "https://example.com", "method": "POST"},
    content=request_body,
))
```

### 4. Export the Adapter

Add to `agent_redteam/adapters/__init__.py`:

```python
from agent_redteam.adapters.my_framework import MyFrameworkAdapter
```

### 5. Write Tests

Use the mock agents from `tests/validation/mock_agents.py` as a reference for testing patterns.

## Existing Adapters as Examples

### CallableAdapter (simplest)

Wraps any `async def agent(task, tools, context) -> str` function. Good reference for understanding tool instrumentation.

Key file: `agent_redteam/adapters/callable.py`

### LLMAdapter (more complex)

Wraps a raw OpenAI-compatible endpoint with a ReAct loop. Good reference for adapters that need to manage an agent loop internally.

Key file: `agent_redteam/adapters/llm.py`

## Planned Adapters (Phase 2)

These are on the roadmap — contributions welcome:

| Adapter | Framework | Approach |
|---|---|---|
| `HttpProxyAdapter` | Any HTTP agent | Man-in-the-middle proxy |
| `McpProxyAdapter` | MCP-based agents | MCP protocol interception |
| `SubprocessAdapter` | CLI agents | Subprocess with I/O capture |
| `LangChainAdapter` | LangChain | Callback-based instrumentation |
| `CrewAIAdapter` | CrewAI | Agent execution hooks |

## Tips

!!! tip "Reuse CallableAdapter"
    If your framework exposes an async function interface, you can often wrap it with `CallableAdapter` directly rather than writing a new adapter from scratch.

!!! tip "Capture everything"
    The more events you capture, the more effective the detectors will be. When in doubt, emit an event. Extra events don't hurt; missing events mean missed detections.
