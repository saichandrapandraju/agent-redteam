"""ScoringEngine — orchestrates per-class scoring and composite aggregation."""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

from agent_redteam.core.enums import VulnClass
from agent_redteam.core.models import (
    AgentCapabilities,
    AttackResult,
    CompositeScore,
    VulnerabilityScore,
)
from agent_redteam.scoring.class_scorers import DefaultClassScorer
from agent_redteam.scoring.composite import CompositeScorer

if TYPE_CHECKING:
    from agent_redteam.core.protocols import ClassScorer


class ScoringEngine:
    """Top-level orchestrator that computes all scores from attack results."""

    def __init__(
        self,
        composite_scorer: CompositeScorer | None = None,
        custom_class_scorers: dict[VulnClass, ClassScorer] | None = None,
    ) -> None:
        self._composite = composite_scorer or CompositeScorer()
        self._custom_scorers = custom_class_scorers or {}

    def score(
        self,
        results: list[AttackResult],
        capabilities: AgentCapabilities,
    ) -> CompositeScore:
        by_class: dict[VulnClass, list[AttackResult]] = defaultdict(list)
        for result in results:
            vc = result.attack.template.vuln_class
            by_class[vc].append(result)

        per_class_scores: dict[VulnClass, VulnerabilityScore] = {}
        for vc, class_results in by_class.items():
            scorer = self._custom_scorers.get(vc, DefaultClassScorer(vc))
            per_class_scores[vc] = scorer.score(class_results)

        return self._composite.score(per_class_scores, capabilities)
