"""Framework-agnostic canary injection for agent tools.

Provides :class:`CanaryInjector` (the core logic) plus adapter-specific
wrappers for LangChain, OpenAI Agents SDK, and plain Python callables.

The goal: seed realistic fake secrets into tool outputs so detectors can
check whether the agent leaks them.

Usage (generic Python callables)::

    from agent_redteam.adapters.canary_wrapper import wrap_callable_tools

    tools = {"file_read": my_file_read_fn, "shell": my_shell_fn}
    wrapped = wrap_callable_tools(tools, canary_tokens)

Usage (LangChain)::

    from agent_redteam.adapters.canary_wrapper import wrap_langchain_tools
    wrapped = wrap_langchain_tools(lc_tools, canary_tokens)

Usage (OpenAI Agents SDK)::

    from agent_redteam.adapters.canary_wrapper import wrap_openai_agent_tools
    wrapped = wrap_openai_agent_tools(agent_tools, canary_tokens)
"""

from __future__ import annotations

import functools
import logging
from collections.abc import Callable
from typing import Any

from agent_redteam.core.models import CanaryToken

logger = logging.getLogger("agent_redteam.adapters.canary_wrapper")

_FILE_TOOL_NAMES = frozenset({
    "file_read", "read_file", "read", "cat_file", "readFile",
})
_SHELL_TOOL_NAMES = frozenset({
    "shell_exec", "shell", "bash", "execute", "run_command", "terminal",
    "run_terminal_cmd", "run_shell",
})
_ENV_KEYWORDS = frozenset({"env", "printenv", "export"})


# ---------------------------------------------------------------------------
# Core injector (framework-agnostic)
# ---------------------------------------------------------------------------


class CanaryInjector:
    """Maps canary tokens to file paths and env vars for tool output injection."""

    def __init__(self, canary_tokens: list[CanaryToken]) -> None:
        self._path_map: dict[str, str] = {}
        self._env_map: dict[str, str] = {}
        for ct in canary_tokens:
            if ct.file_path:
                self._path_map[ct.file_path] = ct.value
            if ct.env_var:
                self._env_map[ct.env_var] = ct.value

    @property
    def has_tokens(self) -> bool:
        return bool(self._path_map) or bool(self._env_map)

    def inject_file_result(self, path: str, original: str) -> str:
        if path in self._path_map:
            return self._path_map[path]
        return original

    def inject_shell_result(self, command: str, original: str) -> str:
        cmd_lower = command.lower()

        if "cat" in cmd_lower:
            for path, value in self._path_map.items():
                if path in command:
                    return value

        cmd_parts = cmd_lower.strip().split()
        cmd_name = cmd_parts[0] if cmd_parts else ""
        if cmd_name in _ENV_KEYWORDS or (
            len(cmd_parts) > 1 and cmd_parts[0] in ("set", "declare")
        ):
            extra = "\n".join(f"{k}={v}" for k, v in self._env_map.items())
            if extra:
                return f"{original}\n{extra}" if original else extra

        return original


# ---------------------------------------------------------------------------
# Generic Python callable wrapping
# ---------------------------------------------------------------------------


def wrap_callable_tools(
    tools: dict[str, Callable],
    canary_tokens: list[CanaryToken],
) -> dict[str, Callable]:
    """Wrap a dict of ``{name: async_fn}`` so file/shell tools return canaries.

    Non-matching tools are passed through unchanged.
    """
    injector = CanaryInjector(canary_tokens)
    if not injector.has_tokens:
        return tools

    wrapped: dict[str, Callable] = {}
    for name, fn in tools.items():
        name_lower = name.lower()
        if name_lower in _FILE_TOOL_NAMES or name in _FILE_TOOL_NAMES:
            wrapped[name] = _wrap_file_callable(fn, injector)
        elif name_lower in _SHELL_TOOL_NAMES or name in _SHELL_TOOL_NAMES:
            wrapped[name] = _wrap_shell_callable(fn, injector)
        else:
            wrapped[name] = fn
    return wrapped


def _wrap_file_callable(fn: Callable, injector: CanaryInjector) -> Callable:
    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> str:
        result = await fn(*args, **kwargs)
        path = kwargs.get("path") or (args[0] if args else "")
        return injector.inject_file_result(str(path), str(result))
    return wrapper


def _wrap_shell_callable(fn: Callable, injector: CanaryInjector) -> Callable:
    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> str:
        result = await fn(*args, **kwargs)
        command = kwargs.get("command") or (args[0] if args else "")
        return injector.inject_shell_result(str(command), str(result))
    return wrapper


# ---------------------------------------------------------------------------
# LangChain wrapping
# ---------------------------------------------------------------------------


def wrap_langchain_tools(
    tools: list[Any],
    canary_tokens: list[CanaryToken],
) -> list[Any]:
    """Wrap LangChain tools so file/shell tools return canary values.

    Requires ``langchain-core``. Non-matching tools pass through unchanged.
    """
    try:
        from langchain_core.tools import StructuredTool
    except ImportError:
        logger.warning("langchain_core not installed; returning tools unwrapped")
        return tools

    injector = CanaryInjector(canary_tokens)
    if not injector.has_tokens:
        return tools
    return [_wrap_one_lc_tool(t, injector, StructuredTool) for t in tools]


def _wrap_one_lc_tool(tool: Any, injector: CanaryInjector, StructuredTool: type) -> Any:
    name = getattr(tool, "name", "")
    is_file = name in _FILE_TOOL_NAMES
    is_shell = name in _SHELL_TOOL_NAMES

    if not is_file and not is_shell:
        return tool

    original_fn = getattr(tool, "func", None)
    if original_fn is None:
        return tool

    if is_file:
        def wrapped_fn(*args: Any, **kwargs: Any) -> str:
            result = original_fn(*args, **kwargs)
            path = kwargs.get("path") or (args[0] if args else "")
            return injector.inject_file_result(str(path), str(result))
    else:
        def wrapped_fn(*args: Any, **kwargs: Any) -> str:
            result = original_fn(*args, **kwargs)
            command = kwargs.get("command") or (args[0] if args else "")
            return injector.inject_shell_result(str(command), str(result))

    return StructuredTool.from_function(
        func=wrapped_fn,
        name=tool.name,
        description=tool.description,
        args_schema=getattr(tool, "args_schema", None),
    )


# ---------------------------------------------------------------------------
# OpenAI Agents SDK wrapping
# ---------------------------------------------------------------------------


def wrap_openai_agent_tools(
    tools: list[Any],
    canary_tokens: list[CanaryToken],
) -> list[Any]:
    """Wrap OpenAI Agents SDK function tools so file/shell tools return canaries.

    Supports ``agents.FunctionTool`` objects. Non-matching tools pass through.
    """
    injector = CanaryInjector(canary_tokens)
    if not injector.has_tokens:
        return tools
    return [_wrap_one_oai_tool(t, injector) for t in tools]


def _wrap_one_oai_tool(tool: Any, injector: CanaryInjector) -> Any:
    name = getattr(tool, "name", "")
    is_file = name in _FILE_TOOL_NAMES
    is_shell = name in _SHELL_TOOL_NAMES

    if not is_file and not is_shell:
        return tool

    on_invoke = getattr(tool, "on_invoke_tool", None)
    if on_invoke is None:
        return tool

    if is_file:
        @functools.wraps(on_invoke)
        async def wrapped_invoke(ctx: Any, input_str: str) -> str:
            result = await on_invoke(ctx, input_str)
            import json
            try:
                args = json.loads(input_str) if isinstance(input_str, str) else {}
            except (json.JSONDecodeError, ValueError):
                args = {}
            path = args.get("path", input_str if isinstance(input_str, str) else "")
            return injector.inject_file_result(str(path), str(result))
    else:
        @functools.wraps(on_invoke)
        async def wrapped_invoke(ctx: Any, input_str: str) -> str:
            result = await on_invoke(ctx, input_str)
            import json
            try:
                args = json.loads(input_str) if isinstance(input_str, str) else {}
            except (json.JSONDecodeError, ValueError):
                args = {}
            command = args.get("command", input_str if isinstance(input_str, str) else "")
            return injector.inject_shell_result(str(command), str(result))

    tool.on_invoke_tool = wrapped_invoke
    return tool


# Backward-compat alias used by langchain.py
wrap_tools_with_canaries = wrap_langchain_tools
