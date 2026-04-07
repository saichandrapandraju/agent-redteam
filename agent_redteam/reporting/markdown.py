"""Markdown report formatter — human-readable vulnerability report."""

from __future__ import annotations

from pathlib import Path

from agent_redteam.core.models import ScanResult


class MarkdownFormatter:
    @property
    def format_name(self) -> str:
        return "markdown"

    def render(self, result: ScanResult) -> str:
        lines: list[str] = []
        lines.append("# Agent Security Scan Report\n")
        lines.append(f"**Scan ID:** `{result.id}`  ")
        lines.append(f"**Date:** {result.started_at.isoformat()}  ")
        duration = f"{result.duration_seconds:.1f}s" if result.duration_seconds else "N/A"
        lines.append(f"**Duration:** {duration}  ")
        lines.append(f"**Profile:** {result.config.profile}  ")
        lines.append(f"**Library Version:** {result.library_version or 'dev'}\n")

        cs = result.composite_score
        if cs:
            lines.append("## Overall Score\n")
            lines.append(f"**Score:** {cs.overall_score}/100  ")
            lines.append(f"**Risk Tier:** {cs.risk_tier.value.upper()}  ")
            lines.append(f"**Blast Radius Factor:** {cs.blast_radius_factor}  ")
            if cs.confidence_note:
                lines.append(f"**Note:** {cs.confidence_note}  ")
            lines.append("")

            if cs.per_class_scores:
                lines.append("### Per-Class Scores\n")
                lines.append("| Class | Score | Success Rate | Trials | 90% CI |")
                lines.append("|-------|-------|-------------|--------|--------|")
                for vc, vs in sorted(cs.per_class_scores.items(), key=lambda x: x[1].score):
                    lines.append(
                        f"| {vc.value} | {vs.score:.1f} | {vs.attack_success_rate:.1%} "
                        f"| {vs.trial_count} | {vs.ci_lower:.1f}--{vs.ci_upper:.1f} |"
                    )
                lines.append("")

        if result.findings:
            lines.append("## Findings\n")
            for i, finding in enumerate(sorted(result.findings, key=lambda f: f.severity.value), 1):
                lines.append(f"### Finding {i}: {finding.title}\n")
                lines.append(f"- **Severity:** {finding.severity.value.upper()}")
                lines.append(f"- **Class:** {finding.vuln_class.value}")
                lines.append(f"- **Signal Tier:** {finding.signal_tier.value}")
                lines.append(f"- **Confidence:** {finding.confidence:.0%}")
                if finding.trust_boundaries_violated:
                    boundaries = ", ".join(b.value for b in finding.trust_boundaries_violated)
                    lines.append(f"- **Trust Boundaries:** {boundaries}")
                lines.append(f"\n{finding.description}\n")
                if finding.evidence_timeline:
                    lines.append("**Evidence Timeline:**\n")
                    for event_desc in finding.evidence_timeline:
                        lines.append(f"- {event_desc}")
                    lines.append("")
                if finding.mitigation_guidance:
                    lines.append(f"**Mitigation:** {finding.mitigation_guidance}\n")

        lines.append("## Summary\n")
        lines.append(f"- Total attacks executed: {result.total_attacks}")
        lines.append(f"- Attacks succeeded: {result.total_succeeded}")
        lines.append(f"- Total signals detected: {result.total_signals}")
        lines.append(f"- Findings: {len(result.findings)}")

        return "\n".join(lines)

    def render_to_file(self, result: ScanResult, path: Path) -> None:
        path.write_text(self.render(result))
