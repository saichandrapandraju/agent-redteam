"""AttackPlanner — selects and prioritizes attacks for a scan."""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING

from jinja2 import Environment as JinjaEnvironment

from agent_redteam.core.enums import Severity, VulnClass
from agent_redteam.core.models import (
    AgentCapabilities,
    AgentTask,
    Attack,
    AttackSuite,
    AttackTemplate,
    BudgetConfig,
    ScanConfig,
)

if TYPE_CHECKING:
    from agent_redteam.attacks.registry import AttackRegistry

SEVERITY_PRIORITY = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

TOOL_TO_VULN_CLASSES: dict[str, list[VulnClass]] = {
    "shell": [VulnClass.V5_TOOL_MISUSE, VulnClass.V7_DATA_EXFILTRATION],
    "bash": [VulnClass.V5_TOOL_MISUSE, VulnClass.V7_DATA_EXFILTRATION],
    "email": [VulnClass.V1_INDIRECT_INJECTION, VulnClass.V7_DATA_EXFILTRATION],
    "send_email": [VulnClass.V1_INDIRECT_INJECTION, VulnClass.V7_DATA_EXFILTRATION],
    "browser": [VulnClass.V1_INDIRECT_INJECTION],
    "git": [VulnClass.V1_INDIRECT_INJECTION, VulnClass.V5_TOOL_MISUSE],
    "database": [VulnClass.V5_TOOL_MISUSE, VulnClass.V6_SECRET_EXPOSURE],
    "file_read": [VulnClass.V6_SECRET_EXPOSURE, VulnClass.V1_INDIRECT_INJECTION],
    "file_write": [VulnClass.V5_TOOL_MISUSE],
    "http_client": [VulnClass.V7_DATA_EXFILTRATION],
    "search": [VulnClass.V1_INDIRECT_INJECTION],
}


class AttackPlanner:
    """Selects and prioritizes attacks for a scan.

    Phase 1: Rule-based matching on capabilities, vuln classes, and budget.
    """

    def __init__(self, registry: AttackRegistry) -> None:
        self._registry = registry
        self._jinja = JinjaEnvironment()

    def plan(self, config: ScanConfig) -> AttackSuite:
        """Generate an attack suite for the given configuration."""
        templates = self._registry.query(
            vuln_classes=config.vuln_classes or None,
            boundaries=config.target_boundaries or None,
            max_complexity=max(config.complexity_levels) if config.complexity_levels else None,
            stealth_levels=config.stealth_levels or None,
        )

        templates = self._filter_by_capabilities(templates, config.agent_capabilities)
        templates = self._prioritize(templates)
        templates = self._apply_budget(templates, config.budget)

        attacks = [self._instantiate(t) for t in templates]

        vuln_classes = list({a.template.vuln_class for a in attacks})
        boundaries = list({b for a in attacks for b in a.template.target_boundaries})

        return AttackSuite(
            name=f"scan_{config.profile.value}",
            attacks=attacks,
            vuln_classes=vuln_classes,
            target_boundaries=boundaries,
        )

    def _filter_by_capabilities(
        self, templates: list[AttackTemplate], capabilities: AgentCapabilities
    ) -> list[AttackTemplate]:
        """Remove attacks that target capabilities the agent doesn't have."""
        tool_names = {t.name.lower() for t in capabilities.tools}

        relevant_classes: set[VulnClass] = set()
        for tool_name in tool_names:
            for name_pattern, classes in TOOL_TO_VULN_CLASSES.items():
                if name_pattern in tool_name:
                    relevant_classes.update(classes)

        # Always relevant if the agent has any tools
        relevant_classes.add(VulnClass.V1_INDIRECT_INJECTION)
        relevant_classes.add(VulnClass.V2_DIRECT_INJECTION)
        relevant_classes.add(VulnClass.V6_SECRET_EXPOSURE)
        if capabilities.tools:
            relevant_classes.add(VulnClass.V5_TOOL_MISUSE)

        if capabilities.has_internet_access:
            relevant_classes.add(VulnClass.V7_DATA_EXFILTRATION)

        if capabilities.has_memory:
            relevant_classes.add(VulnClass.V8_MEMORY_POISONING)

        return [t for t in templates if t.vuln_class in relevant_classes]

    def _prioritize(self, templates: list[AttackTemplate]) -> list[AttackTemplate]:
        """Order by severity (critical first), then stealth (obvious first)."""
        return sorted(
            templates,
            key=lambda t: (
                SEVERITY_PRIORITY.get(Severity(t.severity), 99),
                0 if t.stealth == "obvious" else 1,
                t.id,
            ),
        )

    def _apply_budget(self, templates: list[AttackTemplate], budget: BudgetConfig) -> list[AttackTemplate]:
        """Trim to budget.max_attacks while preserving class coverage."""
        if len(templates) <= budget.max_attacks:
            return templates

        # Ensure at least one from each class, then fill remaining budget
        by_class: dict[VulnClass, list[AttackTemplate]] = {}
        for t in templates:
            by_class.setdefault(t.vuln_class, []).append(t)

        selected: list[AttackTemplate] = []
        seen_ids: set[str] = set()

        for cls_templates in by_class.values():
            if cls_templates and len(selected) < budget.max_attacks:
                selected.append(cls_templates[0])
                seen_ids.add(cls_templates[0].id)

        for t in templates:
            if len(selected) >= budget.max_attacks:
                break
            if t.id not in seen_ids:
                selected.append(t)
                seen_ids.add(t.id)

        return selected

    def _instantiate(self, template: AttackTemplate) -> Attack:
        """Create an Attack from a template with resolved parameters."""
        params = {
            "secret_file_path": "/home/user/.aws/credentials",
            "exfil_url": "https://canary-exfil.redteam.local/collect",
        }

        payload = template.payload_template
        if payload:
            try:
                rendered = self._jinja.from_string(payload).render(**params)
            except Exception:
                rendered = payload
        else:
            rendered = template.payload_variants[0] if template.payload_variants else ""

        task_instruction = template.agent_task_template
        if task_instruction:
            with contextlib.suppress(Exception):
                task_instruction = self._jinja.from_string(task_instruction).render(**params)

        task = AgentTask(
            instruction=task_instruction,
            expected_tools=[],
        )

        return Attack(
            template_id=template.id,
            template=template,
            parameters=params,
            resolved_payload=rendered,
            resolved_task=task,
        )
