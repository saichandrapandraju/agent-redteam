"""Terminal report formatter using rich (optional dependency)."""

from __future__ import annotations

from agent_redteam.core.enums import RiskTier, Severity
from agent_redteam.core.models import ScanResult

TIER_COLORS = {
    RiskTier.CRITICAL: "bold red",
    RiskTier.HIGH: "red",
    RiskTier.MODERATE: "yellow",
    RiskTier.LOW: "green",
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


class TerminalFormatter:
    @property
    def format_name(self) -> str:
        return "terminal"

    def render(self, result: ScanResult) -> str:
        try:
            import io

            from rich.console import Console
            from rich.panel import Panel
            from rich.table import Table
            from rich.text import Text
        except ImportError:
            return _plain_fallback(result)

        buf = io.StringIO()
        console = Console(file=buf, force_terminal=True, width=100)

        cs = result.composite_score
        if cs:
            tier_color = TIER_COLORS.get(cs.risk_tier, "white")
            bg_color = tier_color.replace("bold ", "")
            score_text = Text(f" {cs.overall_score:.1f}/100 ", style=f"bold white on {bg_color}")
            console.print(
                Panel(
                    score_text,
                    title="[bold]Agent Security Score[/bold]",
                    subtitle=f"Risk: {cs.risk_tier.value.upper()} | Blast Radius: {cs.blast_radius_factor}x",
                )
            )

            if cs.per_class_scores:
                table = Table(title="Per-Class Scores", show_lines=True)
                table.add_column("Class", style="bold")
                table.add_column("Score", justify="right")
                table.add_column("Success Rate", justify="right")
                table.add_column("Trials", justify="right")
                table.add_column("90% CI", justify="right")

                for vc, vs in sorted(cs.per_class_scores.items(), key=lambda x: x[1].score):
                    score_style = "green" if vs.score >= 80 else "yellow" if vs.score >= 50 else "red"
                    table.add_row(
                        vc.value,
                        f"[{score_style}]{vs.score:.1f}[/{score_style}]",
                        f"{vs.attack_success_rate:.0%}",
                        str(vs.trial_count),
                        f"{vs.ci_lower:.1f}--{vs.ci_upper:.1f}",
                    )
                console.print(table)

        if result.findings:
            console.print(f"\n[bold]Findings ({len(result.findings)}):[/bold]\n")
            for _i, finding in enumerate(sorted(result.findings, key=lambda f: f.severity.value), 1):
                sev_color = SEVERITY_COLORS.get(finding.severity, "white")
                console.print(
                    f"  [{sev_color}]{finding.severity.value.upper()}[/{sev_color}] "
                    f"[bold]{finding.title}[/bold]"
                )
                console.print(
                    f"    Class: {finding.vuln_class.value} | "
                    f"Confidence: {finding.confidence:.0%} | "
                    f"Tier: {finding.signal_tier.value}"
                )
                if finding.mitigation_guidance:
                    console.print(f"    [dim]Mitigation: {finding.mitigation_guidance}[/dim]")
                console.print()

        console.print(
            f"[dim]Attacks: {result.total_attacks} | "
            f"Succeeded: {result.total_succeeded} | "
            f"Signals: {result.total_signals} | "
            f"Findings: {len(result.findings)}[/dim]"
        )

        return buf.getvalue()


def _plain_fallback(result: ScanResult) -> str:
    """Fallback for when rich is not installed."""
    lines = ["=== Agent Security Scan Report ==="]
    cs = result.composite_score
    if cs:
        lines.append(f"Score:     {cs.overall_score:.1f}/100")
        lines.append(f"Risk Tier: {cs.risk_tier.value.upper()}")
        lines.append(f"Blast Radius: {cs.blast_radius_factor}x")
        lines.append("")
        for vc, vs in sorted(cs.per_class_scores.items(), key=lambda x: x[1].score):
            lines.append(
                f"  {vc.value}: {vs.score:.1f} "
                f"(success rate: {vs.attack_success_rate:.0%}, n={vs.trial_count})"
            )
    lines.append(f"\nFindings: {len(result.findings)}")
    for finding in result.findings:
        lines.append(f"  [{finding.severity.value.upper()}] {finding.title}")
    lines.append(
        f"\nAttacks: {result.total_attacks} | Succeeded: {result.total_succeeded} "
        f"| Signals: {result.total_signals}"
    )
    return "\n".join(lines)
