"""ReportRenderer — dispatches to format-specific renderers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_redteam.reporting.json_fmt import JsonFormatter
from agent_redteam.reporting.markdown import MarkdownFormatter
from agent_redteam.reporting.terminal import TerminalFormatter

if TYPE_CHECKING:
    from agent_redteam.core.models import ScanResult
    from agent_redteam.core.protocols import ReportFormatter


class ReportRenderer:
    """Dispatches report rendering to the appropriate formatter."""

    def __init__(self) -> None:
        self._formatters: dict[str, ReportFormatter] = {}

    def register(self, formatter: ReportFormatter) -> ReportRenderer:
        self._formatters[formatter.format_name] = formatter
        return self

    def defaults(self) -> ReportRenderer:
        self.register(JsonFormatter())
        self.register(MarkdownFormatter())
        self.register(TerminalFormatter())
        return self

    def render(self, result: ScanResult, fmt: str = "markdown") -> str:
        formatter = self._formatters.get(fmt)
        if not formatter:
            available = ", ".join(self._formatters.keys())
            raise ValueError(f"Unknown format '{fmt}'. Available: {available}")
        return formatter.render(result)

    @property
    def available_formats(self) -> list[str]:
        return list(self._formatters.keys())
