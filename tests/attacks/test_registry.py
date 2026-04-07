"""Tests for attack registry and template loading."""

import pytest

from agent_redteam.attacks.registry import AttackRegistry
from agent_redteam.core.enums import StealthLevel, VulnClass


class TestAttackRegistry:
    @pytest.fixture
    def registry(self) -> AttackRegistry:
        return AttackRegistry().load()

    def test_loads_all_templates(self, registry: AttackRegistry):
        assert len(registry.all_templates) == 86

    def test_stats_by_class(self, registry: AttackRegistry):
        stats = registry.stats
        assert stats["by_class"]["V1"] == 12
        assert stats["by_class"]["V2"] == 10
        assert stats["by_class"]["V3"] == 10
        assert stats["by_class"]["V4"] == 10
        assert stats["by_class"]["V5"] == 10
        assert stats["by_class"]["V6"] == 10
        assert stats["by_class"]["V7"] == 8
        assert stats["by_class"]["V8"] == 8
        assert stats["by_class"]["V12"] == 8

    def test_query_by_class(self, registry: AttackRegistry):
        v1_templates = registry.query(vuln_classes=[VulnClass.V1_INDIRECT_INJECTION])
        assert all(t.vuln_class == VulnClass.V1_INDIRECT_INJECTION for t in v1_templates)

    def test_query_by_stealth(self, registry: AttackRegistry):
        obvious = registry.query(stealth_levels=[StealthLevel.OBVIOUS])
        assert all(t.stealth == StealthLevel.OBVIOUS for t in obvious)

    def test_get_by_id(self, registry: AttackRegistry):
        templates = registry.all_templates
        first = templates[0]
        retrieved = registry.get(first.id)
        assert retrieved.id == first.id

    def test_get_missing_raises(self, registry: AttackRegistry):
        with pytest.raises(KeyError):
            registry.get("nonexistent_template_id")

    def test_template_fields_populated(self, registry: AttackRegistry):
        for template in registry.all_templates:
            assert template.id
            assert template.name
            assert template.vuln_class
            assert template.agent_task_template
            assert template.expected_signals
