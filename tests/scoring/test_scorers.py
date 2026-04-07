"""Tests for scoring engine."""

from agent_redteam.core.enums import (
    Severity,
    VulnClass,
)
from agent_redteam.core.models import (
    AgentCapabilities,
    AgentTask,
    AgentTrace,
    Attack,
    AttackResult,
    AttackTemplate,
    Signal,
    ToolCapability,
)
from agent_redteam.scoring.class_scorers import DefaultClassScorer
from agent_redteam.scoring.composite import CompositeScorer
from agent_redteam.scoring.engine import ScoringEngine
from agent_redteam.scoring.statistics import compute_confidence_interval


def _make_attack_result(
    vuln_class: VulnClass, succeeded: bool, signals: list[Signal] | None = None
) -> AttackResult:
    template = AttackTemplate(
        id=f"test_{vuln_class.value}",
        name="Test",
        description="test",
        vuln_class=vuln_class,
        target_boundaries=[],
    )
    attack = Attack(template_id=template.id, template=template)
    return AttackResult(
        attack=attack,
        trace=AgentTrace(task=AgentTask(instruction="test")),
        signals=signals or [],
        succeeded=succeeded,
    )


class TestConfidenceInterval:
    def test_zero_outcomes(self):
        stats = compute_confidence_interval([])
        assert stats.sample_size == 0
        assert stats.mean == 0.0

    def test_single_trial(self):
        stats = compute_confidence_interval([1.0])
        assert stats.sample_size == 1
        assert stats.ci_lower == 0.0
        assert stats.ci_upper == 1.0

    def test_all_success(self):
        stats = compute_confidence_interval([1.0] * 10)
        assert stats.mean == 1.0
        assert stats.ci_upper == 1.0

    def test_all_failure(self):
        stats = compute_confidence_interval([0.0] * 10)
        assert stats.mean == 0.0
        assert stats.ci_lower == 0.0

    def test_mixed(self):
        stats = compute_confidence_interval([1.0, 0.0, 1.0, 0.0, 0.0])
        assert 0.0 < stats.ci_lower < stats.mean < stats.ci_upper < 1.0


class TestDefaultClassScorer:
    def test_empty_results_perfect_score(self):
        scorer = DefaultClassScorer(VulnClass.V1_INDIRECT_INJECTION)
        score = scorer.score([])
        assert score.score == 100.0
        assert score.attack_success_rate == 0.0

    def test_all_attacks_succeed_low_score(self):
        results = [_make_attack_result(VulnClass.V1_INDIRECT_INJECTION, True) for _ in range(5)]
        scorer = DefaultClassScorer(VulnClass.V1_INDIRECT_INJECTION)
        score = scorer.score(results)
        assert score.score < 30
        assert score.attacks_succeeded == 5

    def test_no_attacks_succeed_high_score(self):
        results = [_make_attack_result(VulnClass.V1_INDIRECT_INJECTION, False) for _ in range(5)]
        scorer = DefaultClassScorer(VulnClass.V1_INDIRECT_INJECTION)
        score = scorer.score(results)
        assert score.score == 100.0
        assert score.attacks_succeeded == 0


class TestCompositeScorer:
    def test_blast_radius_increases_with_capabilities(self):
        scorer = CompositeScorer()
        basic = AgentCapabilities()
        advanced = AgentCapabilities(
            tools=[ToolCapability(name="shell"), ToolCapability(name="email")],
            has_internet_access=True,
            data_sensitivity=Severity.CRITICAL,
        )

        basic_factor = scorer._compute_blast_radius(basic)
        advanced_factor = scorer._compute_blast_radius(advanced)
        assert advanced_factor > basic_factor


class TestScoringEngine:
    def test_end_to_end_scoring(self):
        results = [
            _make_attack_result(VulnClass.V1_INDIRECT_INJECTION, True),
            _make_attack_result(VulnClass.V1_INDIRECT_INJECTION, False),
            _make_attack_result(VulnClass.V6_SECRET_EXPOSURE, True),
        ]
        engine = ScoringEngine()
        capabilities = AgentCapabilities(data_sensitivity=Severity.HIGH)
        composite = engine.score(results, capabilities)

        assert 0 < composite.overall_score < 100
        assert VulnClass.V1_INDIRECT_INJECTION in composite.per_class_scores
        assert VulnClass.V6_SECRET_EXPOSURE in composite.per_class_scores
