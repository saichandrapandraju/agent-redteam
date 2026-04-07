"""AttackRegistry — loads attack templates from YAML files and indexes them."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml
from jinja2 import Environment as JinjaEnvironment
from jinja2 import TemplateSyntaxError

from agent_redteam.core.enums import (
    AttackComplexity,
    StealthLevel,
    TrustBoundary,
    VulnClass,
)
from agent_redteam.core.errors import TemplateError
from agent_redteam.core.models import AttackTemplate, InjectionPoint


def _parse_template(data: dict[str, Any]) -> AttackTemplate:
    """Parse a raw YAML dict into an AttackTemplate."""
    injection_points = []
    for ip in data.get("injection_points", []):
        injection_points.append(
            InjectionPoint(
                location=ip.get("location", ""),
                description=ip.get("description", ""),
                trust_boundary=TrustBoundary(ip.get("trust_boundary", "B2")),
            )
        )

    return AttackTemplate(
        id=data["id"],
        name=data["name"],
        description=data.get("description", ""),
        vuln_class=VulnClass(data["vuln_class"]),
        target_boundaries=[TrustBoundary(b) for b in data.get("target_boundaries", [])],
        complexity=AttackComplexity(data.get("complexity", "L1")),
        stealth=StealthLevel(data.get("stealth", "obvious")),
        severity=data.get("severity", "high"),
        injection_points=injection_points,
        payload_template=data.get("payload_template", ""),
        payload_variants=data.get("payload_variants", []),
        setup_instructions=data.get("setup_instructions", ""),
        environment_setup=data.get("environment_setup", {}),
        agent_task_template=data.get("agent_task_template", ""),
        expected_signals=data.get("expected_signals", []),
        tags=data.get("tags", []),
    )


def _validate_template(template: AttackTemplate) -> list[str]:
    """Validate a template. Returns list of errors (empty = valid)."""
    errors: list[str] = []
    if not template.id:
        errors.append("Template must have an id")
    if not template.name:
        errors.append("Template must have a name")
    # V6 (secret exposure) and similar direct attacks use agent_task_template
    # as the attack vector, so payload_template may be empty
    # Direct attack classes use agent_task_template as the attack vector
    needs_payload = template.vuln_class not in (
        VulnClass.V2_DIRECT_INJECTION,
        VulnClass.V3_EXCESSIVE_AGENCY,
        VulnClass.V4_CONFUSED_DEPUTY,
        VulnClass.V5_TOOL_MISUSE,
        VulnClass.V6_SECRET_EXPOSURE,
        VulnClass.V8_MEMORY_POISONING,
    )
    if needs_payload and not template.payload_template and not template.payload_variants:
        errors.append(f"{template.id}: must have payload_template or payload_variants")
    if not template.agent_task_template:
        errors.append(f"{template.id}: must have agent_task_template")
    if not template.expected_signals:
        errors.append(f"{template.id}: must declare expected_signals")
    if template.payload_template:
        try:
            JinjaEnvironment().parse(template.payload_template)
        except TemplateSyntaxError as e:
            errors.append(f"{template.id}: invalid Jinja2 in payload_template: {e}")
    return errors


class AttackRegistry:
    """Loads, indexes, and serves attack templates."""

    def __init__(
        self,
        builtin_dir: Path | None = None,
        custom_dirs: list[Path] | None = None,
    ) -> None:
        self._builtin_dir = builtin_dir or (Path(__file__).parent / "templates")
        self._custom_dirs = custom_dirs or []
        self._templates: dict[str, AttackTemplate] = {}
        self._by_class: dict[VulnClass, list[AttackTemplate]] = defaultdict(list)
        self._by_boundary: dict[TrustBoundary, list[AttackTemplate]] = defaultdict(list)
        self._by_tag: dict[str, list[AttackTemplate]] = defaultdict(list)

    def load(self) -> AttackRegistry:
        """Load all templates from configured directories."""
        dirs = [self._builtin_dir, *self._custom_dirs]
        for d in dirs:
            if not d.exists():
                continue
            for yaml_file in sorted(d.rglob("*.yaml")):
                self._load_file(yaml_file)
        return self

    def _load_file(self, path: Path) -> None:
        with open(path) as f:
            data = yaml.safe_load(f)
        if not data or not isinstance(data, dict):
            return
        if "id" not in data:
            return

        try:
            template = _parse_template(data)
        except Exception as e:
            raise TemplateError(f"Failed to parse {path}: {e}") from e

        errors = _validate_template(template)
        if errors:
            raise TemplateError(f"Invalid template {path}: {'; '.join(errors)}")

        self._templates[template.id] = template
        self._by_class[template.vuln_class].append(template)
        for boundary in template.target_boundaries:
            self._by_boundary[boundary].append(template)
        for tag in template.tags:
            self._by_tag[tag].append(template)

    def get(self, template_id: str) -> AttackTemplate:
        """Get a template by ID. Raises KeyError if not found."""
        return self._templates[template_id]

    def query(
        self,
        vuln_classes: list[VulnClass] | None = None,
        boundaries: list[TrustBoundary] | None = None,
        max_complexity: AttackComplexity = AttackComplexity.L5_TEMPORAL,
        stealth_levels: list[StealthLevel] | None = None,
        tags: list[str] | None = None,
    ) -> list[AttackTemplate]:
        """Query templates by criteria. All filters are AND-combined."""
        candidates = list(self._templates.values())

        if vuln_classes:
            vc_set = set(vuln_classes)
            candidates = [t for t in candidates if t.vuln_class in vc_set]

        if boundaries:
            b_set = set(boundaries)
            candidates = [t for t in candidates if b_set.intersection(t.target_boundaries)]

        complexity_order = list(AttackComplexity)
        max_idx = complexity_order.index(max_complexity)
        allowed_complexity = set(complexity_order[: max_idx + 1])
        candidates = [t for t in candidates if t.complexity in allowed_complexity]

        if stealth_levels:
            sl_set = set(stealth_levels)
            candidates = [t for t in candidates if t.stealth in sl_set]

        if tags:
            tag_set = set(tags)
            candidates = [t for t in candidates if tag_set.intersection(t.tags)]

        return candidates

    @property
    def all_templates(self) -> list[AttackTemplate]:
        return list(self._templates.values())

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "total": len(self._templates),
            "by_class": {vc.value: len(ts) for vc, ts in self._by_class.items()},
            "by_boundary": {b.value: len(ts) for b, ts in self._by_boundary.items()},
        }
