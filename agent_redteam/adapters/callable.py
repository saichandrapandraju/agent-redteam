"""CallableAdapter — wraps any async callable for security testing."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from typing import Any

from agent_redteam.core.enums import EventType, TrustBoundary
from agent_redteam.core.models import (
    AgentTask,
    AgentTrace,
    Environment,
    Event,
)


class CallableAdapter:
    """Wraps an async callable agent function for security testing.

    The callable receives (instruction: str, tools: dict) where tools maps
    tool names to instrumented async callables that automatically emit Events.

    Example::

        async def my_agent(instruction: str, tools: dict) -> str:
            content = await tools["file_read"](path="/some/file.txt")
            return f"File says: {content}"

        adapter = CallableAdapter(my_agent)
    """

    def __init__(
        self,
        agent_fn: Callable[..., Any],
        name: str = "callable_agent",
    ) -> None:
        self._agent_fn = agent_fn
        self._name = name

    @property
    def adapter_name(self) -> str:
        return self._name

    async def health_check(self) -> bool:
        return True

    async def run(self, task: AgentTask, environment: Environment) -> AgentTrace:
        trace = AgentTrace(task=task, environment=environment)
        tools = self._build_instrumented_tools(environment, trace)

        try:
            result = await asyncio.wait_for(
                self._agent_fn(task.instruction, tools),
                timeout=task.timeout_seconds,
            )
            trace.final_output = str(result) if result is not None else None
        except TimeoutError:
            trace.error = "timeout"
            raise TimeoutError("Agent timed out") from None
        except Exception as e:
            trace.error = str(e)
        finally:
            trace.ended_at = datetime.now(UTC)

        return trace

    async def run_streaming(self, task: AgentTask, environment: Environment) -> AsyncIterator[Event]:
        trace = await self.run(task, environment)
        for event in trace.events:
            yield event

    def _build_instrumented_tools(self, environment: Environment, trace: AgentTrace) -> dict[str, Callable]:
        """Build a dict of tool_name -> instrumented_callable."""
        tools: dict[str, Callable] = {}
        turn_counter = {"n": 0}

        file_map = environment.file_map

        for tool_def in environment.tools:
            tool_name = tool_def.name

            async def _make_tool(name: str = tool_name) -> Callable:
                async def instrumented_tool(**kwargs: Any) -> Any:
                    turn_counter["n"] += 1
                    turn = turn_counter["n"]

                    # Emit TOOL_CALL event
                    call_event = Event(
                        event_type=EventType.TOOL_CALL,
                        trust_boundary=TrustBoundary.B4_AGENT_TO_TOOL,
                        tool_name=name,
                        tool_args=kwargs,
                        turn_number=turn,
                    )
                    trace.events.append(call_event)

                    result = _simulate_tool(name, kwargs, file_map, environment)

                    # FILE_READ event for file operations
                    if name in ("file_read", "read_file") and "path" in kwargs:
                        trace.events.append(
                            Event(
                                event_type=EventType.FILE_READ,
                                trust_boundary=TrustBoundary.B4_AGENT_TO_TOOL,
                                file_path=kwargs["path"],
                                content=str(result)[:500],
                                turn_number=turn,
                            )
                        )

                    # NETWORK_REQUEST event
                    if name in ("http_request", "curl", "fetch") and "url" in kwargs:
                        trace.events.append(
                            Event(
                                event_type=EventType.NETWORK_REQUEST,
                                trust_boundary=TrustBoundary.B4_AGENT_TO_TOOL,
                                url=kwargs["url"],
                                turn_number=turn,
                            )
                        )

                    # Emit TOOL_RESULT event
                    result_event = Event(
                        event_type=EventType.TOOL_RESULT,
                        trust_boundary=TrustBoundary.B3_TOOL_OUTPUT_TO_AGENT,
                        tool_name=name,
                        tool_result=result,
                        turn_number=turn,
                    )
                    trace.events.append(result_event)

                    return result

                return instrumented_tool

        # Build tools synchronously using closures
        for tool_def in environment.tools:
            name = tool_def.name
            tools[name] = _make_instrumented_tool(name, trace, turn_counter, file_map, environment)

        # Add email-reading tool if emails exist
        if environment.emails:
            tools["read_emails"] = _make_email_reader(environment, trace, turn_counter)

        return tools


def _make_instrumented_tool(
    name: str,
    trace: AgentTrace,
    turn_counter: dict,
    file_map: dict,
    environment: Environment,
) -> Callable:
    async def instrumented_tool(**kwargs: Any) -> Any:
        turn_counter["n"] += 1
        turn = turn_counter["n"]

        call_event = Event(
            event_type=EventType.TOOL_CALL,
            trust_boundary=TrustBoundary.B4_AGENT_TO_TOOL,
            tool_name=name,
            tool_args=kwargs,
            turn_number=turn,
        )
        trace.events.append(call_event)

        result = _simulate_tool(name, kwargs, file_map, environment)

        if name in ("file_read", "read_file") and "path" in kwargs:
            trace.events.append(
                Event(
                    event_type=EventType.FILE_READ,
                    trust_boundary=TrustBoundary.B4_AGENT_TO_TOOL,
                    file_path=kwargs["path"],
                    content=str(result)[:500],
                    turn_number=turn,
                )
            )

        if name in ("http_request", "curl", "fetch", "requests") and "url" in kwargs:
            trace.events.append(
                Event(
                    event_type=EventType.NETWORK_REQUEST,
                    trust_boundary=TrustBoundary.B4_AGENT_TO_TOOL,
                    url=kwargs["url"],
                    turn_number=turn,
                )
            )

        result_event = Event(
            event_type=EventType.TOOL_RESULT,
            trust_boundary=TrustBoundary.B3_TOOL_OUTPUT_TO_AGENT,
            tool_name=name,
            tool_result=result,
            turn_number=turn,
        )
        trace.events.append(result_event)

        return result

    return instrumented_tool


def _make_email_reader(environment: Environment, trace: AgentTrace, turn_counter: dict) -> Callable:
    async def read_emails(**kwargs: Any) -> str:
        turn_counter["n"] += 1
        turn = turn_counter["n"]

        trace.events.append(
            Event(
                event_type=EventType.TOOL_CALL,
                trust_boundary=TrustBoundary.B2_EXTERNAL_DATA_TO_AGENT,
                tool_name="read_emails",
                tool_args=kwargs,
                turn_number=turn,
            )
        )

        email_texts = []
        for email in environment.emails:
            email_texts.append(
                f"From: {email.from_addr}\nTo: {email.to_addr}\nSubject: {email.subject}\n\n{email.body}"
            )
        result = "\n---\n".join(email_texts) if email_texts else "No emails."

        trace.events.append(
            Event(
                event_type=EventType.TOOL_RESULT,
                trust_boundary=TrustBoundary.B2_EXTERNAL_DATA_TO_AGENT,
                tool_name="read_emails",
                tool_result=result,
                turn_number=turn,
            )
        )

        return result

    return read_emails


def _simulate_tool(name: str, kwargs: dict, file_map: dict, environment: Environment) -> Any:
    """Simulate tool execution against the synthetic environment."""
    if name in ("file_read", "read_file"):
        path = kwargs.get("path", "")
        if path in file_map:
            return file_map[path].content
        return f"Error: file not found: {path}"

    if name in ("file_write", "write_file"):
        path = kwargs.get("path", "/tmp/output.txt")
        content = kwargs.get("content", "")
        file_map[path] = type("FE", (), {"content": content, "path": path})()
        return f"OK: wrote {len(content)} bytes to {path}"

    if name in ("shell", "bash", "execute", "run_command", "terminal"):
        return _simulate_shell(kwargs.get("command", ""), file_map, environment)

    if name in ("send_email", "email"):
        to = kwargs.get("to", "unknown")
        subject = kwargs.get("subject", "(no subject)")
        return f"Email sent to {to} with subject '{subject}'."

    if name in ("http_request", "curl", "fetch", "requests", "http_get"):
        url = kwargs.get("url", "")
        method = kwargs.get("method", "GET").upper()
        return (
            f'{{"status": 200, "method": "{method}", "url": "{url}", '
            f'"body": "Response from {url}"}}'
        )

    if name in ("search", "search_kb", "search_files"):
        query = kwargs.get("query", "")
        hits = [f.path for f in environment.files if query.lower() in f.content.lower()][:5]
        if hits:
            return f"Found {len(hits)} results:\n" + "\n".join(f"  - {p}" for p in hits)
        return f"No results found for '{query}'."

    if name == "git":
        return _simulate_git(kwargs.get("command", ""))

    if name in ("lookup_customer", "crm_lookup"):
        cid = kwargs.get("id", kwargs.get("email", "unknown"))
        return (
            f'{{"customer_id": "{cid}", "name": "Jane Doe", '
            f'"tier": "Gold", "email": "jane@example.com", "account_balance": 1250.00}}'
        )

    if name in ("update_ticket", "close_ticket"):
        ticket = kwargs.get("ticket_id", kwargs.get("id", "TKT-0000"))
        return f"Ticket {ticket} updated."

    if name in ("save_note", "remember", "store_memory"):
        key = kwargs.get("title", kwargs.get("key", "note"))
        return f"Stored memory entry '{key}'."

    if name in ("sql_query", "db_query", "sql"):
        query = kwargs.get("query", "")
        if "select" in query.lower():
            return (
                "id | name       | value\n"
                "---+------------+------\n"
                " 1 | Widget A   | 15000\n"
                " 2 | Widget B   | 22000\n"
                "(2 rows)"
            )
        return "Query OK, 0 rows affected."

    return f"Tool '{name}' returned: OK (args: {list(kwargs.keys())})"


def _simulate_shell(cmd: str, file_map: dict, environment: Environment) -> str:
    """Return realistic shell output for common commands."""
    cmd_lower = cmd.lower().strip()

    if "env" in cmd_lower or "printenv" in cmd_lower:
        parts = [
            "HOME=/home/user",
            "PATH=/usr/local/bin:/usr/bin:/bin",
            "SHELL=/bin/bash",
            "USER=user",
            "LANG=en_US.UTF-8",
        ]
        for ct in environment.canary_tokens:
            if ct.env_var:
                parts.append(f"{ct.env_var}={ct.value}")
        return "\n".join(parts)

    if cmd_lower.startswith("cat "):
        path = cmd.split("cat", 1)[1].strip().split()[0]
        if path in file_map:
            content = file_map[path]
            return content.content if hasattr(content, "content") else str(content)
        for ct in environment.canary_tokens:
            if ct.file_path and ct.file_path in cmd:
                return ct.value
        return f"cat: {path}: No such file or directory"

    if cmd_lower.startswith("ls"):
        target = cmd.split("ls", 1)[1].strip().split()[0] if len(cmd.split()) > 1 else "/home/user"
        entries = sorted({p.rsplit("/", 1)[0] if "/" in p else p for p in file_map if p.startswith(target)})
        if entries:
            return "\n".join(entries[:20])
        return f"ls: cannot access '{target}': No such file or directory"

    if cmd_lower.startswith("pwd"):
        return "/home/user/project"

    if cmd_lower.startswith("whoami"):
        return "user"

    if cmd_lower.startswith("id"):
        return "uid=1000(user) gid=1000(user) groups=1000(user)"

    if cmd_lower.startswith("uname"):
        return "Linux agent-sandbox 6.1.0-generic #1 SMP x86_64 GNU/Linux"

    if cmd_lower.startswith("echo "):
        return cmd.split("echo ", 1)[1]

    if "pip install" in cmd_lower:
        pkg = cmd.split("install", 1)[1].strip().split()[0] if "install" in cmd else "package"
        return f"Successfully installed {pkg}-1.0.0"

    if "curl" in cmd_lower or "wget" in cmd_lower:
        return '{"status": "ok", "data": "response"}'

    if "python" in cmd_lower:
        return "(python process exited with code 0)"

    return f"$ {cmd}\n(command completed)"


def _simulate_git(cmd: str) -> str:
    """Return realistic git output."""
    cmd_lower = cmd.lower().strip()

    if "status" in cmd_lower:
        return (
            "On branch main\n"
            "Your branch is up to date with 'origin/main'.\n\n"
            "nothing to commit, working tree clean"
        )

    if "log" in cmd_lower:
        return (
            "commit a1b2c3d (HEAD -> main, origin/main)\n"
            "Author: Dev User <dev@example.com>\n"
            "Date:   Mon Jan 1 12:00:00 2024 +0000\n\n"
            "    Initial commit"
        )

    if "diff" in cmd_lower:
        return "(no changes)"

    if "push" in cmd_lower:
        if "--force" in cmd_lower or "-f" in cmd_lower:
            return (
                "Total 0 (delta 0), reused 0 (delta 0)\n"
                "To origin\n + abc123...def456 main -> main (forced update)"
            )
        return "Everything up-to-date"

    if "clone" in cmd_lower:
        return "Cloning into 'repo'...\ndone."

    if "branch" in cmd_lower:
        return "* main\n  develop"

    return f"git: '{cmd}' executed"
