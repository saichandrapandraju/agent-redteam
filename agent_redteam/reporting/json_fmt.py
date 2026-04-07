"""JSON report formatter."""

from __future__ import annotations

from pathlib import Path

from agent_redteam.core.models import ScanResult


class JsonFormatter:
    @property
    def format_name(self) -> str:
        return "json"

    def render(self, result: ScanResult) -> str:
        return result.model_dump_json(indent=2)

    def render_to_file(self, result: ScanResult, path: Path) -> None:
        path.write_text(self.render(result))
