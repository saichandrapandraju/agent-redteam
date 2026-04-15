"""Self-contained HTML report formatter.

Produces a single .html file with all CSS/JS inlined — open in any browser,
no server required.
"""

from __future__ import annotations

import html
from pathlib import Path

from agent_redteam.core.enums import EventType, Severity, SignalTier
from agent_redteam.core.models import AttackResult, Finding, ScanResult, VulnerabilityScore
from agent_redteam.reporting.behavioral import BehavioralAssessment, BehavioralRisk, analyze_behavioral_risks


class HtmlFormatter:
    @property
    def format_name(self) -> str:
        return "html"

    def render(self, result: ScanResult) -> str:
        cs = result.composite_score
        assessment = analyze_behavioral_risks(result)

        return _PAGE_TEMPLATE.format(
            scan_id=html.escape(str(result.id)),
            date=html.escape(result.started_at.isoformat(timespec="seconds")),
            duration=f"{result.duration_seconds:.1f}s" if result.duration_seconds else "N/A",
            profile=html.escape(result.config.profile.value),
            version=html.escape(result.library_version or "dev"),
            adapter=html.escape(result.agent_adapter_type or "unknown"),
            score_section=_render_score(cs) if cs else "",
            per_class_section=_render_per_class(cs) if cs and cs.per_class_scores else "",
            findings_section=_render_findings(result.findings),
            behavioral_section=_render_behavioral(assessment),
            attacks_section=_render_attacks(result.attack_results),
            total_attacks=result.total_attacks,
            total_succeeded=result.total_succeeded,
            total_signals=result.total_signals,
            total_findings=len(result.findings),
        )

    def render_to_file(self, result: ScanResult, path: Path) -> None:
        path.write_text(self.render(result))


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------

_SEV_COLOR = {
    "critical": "var(--c-critical)",
    "high": "var(--c-high)",
    "medium": "var(--c-medium)",
    "low": "var(--c-low)",
    "info": "var(--c-info)",
}

_TIER_LABEL = {
    SignalTier.DEFINITIVE_COMPROMISE: "Definitive Compromise",
    SignalTier.SUSPICIOUS_BEHAVIOR: "Suspicious Behavior",
    SignalTier.POLICY_VIOLATION: "Policy Violation",
}


def _risk_color(tier_value: str) -> str:
    return {
        "critical": "var(--c-critical)",
        "high": "var(--c-high)",
        "moderate": "var(--c-medium)",
        "low": "var(--c-low)",
    }.get(tier_value, "var(--c-info)")


def _score_color(score: float) -> str:
    if score >= 90:
        return "var(--c-low)"
    if score >= 75:
        return "var(--c-medium)"
    if score >= 50:
        return "var(--c-high)"
    return "var(--c-critical)"


def _esc(val: object) -> str:
    return html.escape(str(val))


# -- Score gauge -------------------------------------------------------------

def _render_score(cs) -> str:
    score = cs.overall_score
    tier = cs.risk_tier.value
    color = _score_color(score)
    pct = score / 100.0
    deg = int(pct * 360)
    note = f'<p class="note">{_esc(cs.confidence_note)}</p>' if cs.confidence_note else ""
    return f"""
    <section class="card score-card">
      <h2>Overall Score</h2>
      <div class="gauge-row">
        <div class="gauge" style="--deg:{deg}deg; --color:{color};">
          <div class="gauge-inner">
            <span class="gauge-value">{score:.0f}</span>
            <span class="gauge-label">/ 100</span>
          </div>
        </div>
        <div class="score-meta">
          <span class="badge" style="background:{_risk_color(tier)}">{tier.upper()}</span>
          <p>Blast radius factor: <strong>{cs.blast_radius_factor}</strong></p>
          {note}
        </div>
      </div>
    </section>"""


# -- Per-class bars ----------------------------------------------------------

def _render_per_class(cs) -> str:
    rows = []
    for vc, vs in sorted(cs.per_class_scores.items(), key=lambda x: x[1].score):
        color = _score_color(vs.score)
        pct = vs.score
        rows.append(f"""
        <div class="bar-row">
          <span class="bar-label">{_esc(vc.value)} &mdash; {_esc(vc.name.replace('_', ' ').title())}</span>
          <div class="bar-track">
            <div class="bar-fill" style="width:{pct}%;background:{color};"
                 title="Score {vs.score:.1f} | Success rate {vs.attack_success_rate:.0%} | {vs.trial_count} trials | CI [{vs.ci_lower:.0f}, {vs.ci_upper:.0f}]">
              <span class="bar-value">{vs.score:.0f}</span>
            </div>
          </div>
          <span class="bar-detail">{vs.attack_success_rate:.0%} ({vs.trial_count})</span>
        </div>""")
    return f"""
    <section class="card">
      <h2>Per-Class Breakdown</h2>
      <div class="bar-chart">{"".join(rows)}</div>
    </section>"""


# -- Findings ----------------------------------------------------------------

def _render_findings(findings: list[Finding]) -> str:
    if not findings:
        return '<section class="card"><h2>Findings</h2><p class="muted">No findings detected.</p></section>'

    sorted_findings = sorted(findings, key=lambda f: f.severity.value)
    rows = []
    for i, f in enumerate(sorted_findings, 1):
        sev_color = _SEV_COLOR.get(f.severity.value, "var(--c-info)")
        boundaries = ", ".join(b.value for b in f.trust_boundaries_violated) or "—"
        timeline_html = ""
        if f.evidence_timeline:
            items = "".join(f"<li>{_esc(e)}</li>" for e in f.evidence_timeline)
            timeline_html = f'<div class="timeline"><strong>Evidence Timeline</strong><ol>{items}</ol></div>'
        mitigation_html = ""
        if f.mitigation_guidance:
            mitigation_html = f'<div class="mitigation"><strong>Mitigation:</strong> {_esc(f.mitigation_guidance)}</div>'
        rows.append(f"""
        <tr class="finding-row" data-severity="{f.severity.value}" onclick="this.classList.toggle('expanded')">
          <td><span class="badge" style="background:{sev_color}">{f.severity.value.upper()}</span></td>
          <td>{_esc(f.vuln_class.value)}</td>
          <td>{_esc(f.title)}</td>
          <td>{_esc(f.signal_tier.value.replace('_', ' ').title())}</td>
          <td>{f.confidence:.0%}</td>
          <td>{_esc(boundaries)}</td>
        </tr>
        <tr class="finding-detail" data-severity="{f.severity.value}">
          <td colspan="6">
            <p>{_esc(f.description)}</p>
            {timeline_html}
            {mitigation_html}
          </td>
        </tr>""")

    sev_btns = "".join(
        f'<button class="filter-btn" data-filter="{s.value}" style="border-color:{_SEV_COLOR[s.value]}">{s.value.title()}</button>'
        for s in Severity
    )
    return f"""
    <section class="card">
      <h2>Findings <span class="count-badge">{len(findings)}</span></h2>
      <div class="filter-bar">
        <button class="filter-btn active" data-filter="all">All</button>
        {sev_btns}
      </div>
      <table class="findings-table">
        <thead><tr>
          <th>Severity</th><th>Class</th><th>Title</th><th>Signal</th><th>Confidence</th><th>Boundaries</th>
        </tr></thead>
        <tbody>{"".join(rows)}</tbody>
      </table>
    </section>"""


# -- Behavioral risks --------------------------------------------------------

def _render_behavioral(assessment: BehavioralAssessment) -> str:
    if not assessment.risks:
        return ""

    cards = []
    for risk in assessment.risks:
        sev_color = _SEV_COLOR.get(risk.severity, "var(--c-info)")
        details_html = ""
        if risk.details:
            items = "".join(f"<li><code>{_esc(d)}</code></li>" for d in risk.details)
            details_html = f"<ul>{items}</ul>"
        cards.append(f"""
        <div class="risk-card">
          <div class="risk-header">
            <span class="badge" style="background:{sev_color}">{risk.severity.upper()}</span>
            <strong>{_esc(risk.category)}</strong>
          </div>
          <p>{_esc(risk.summary)}</p>
          {details_html}
        </div>""")

    tool_rows = "".join(
        f"<tr><td><code>{_esc(t)}</code></td><td>{c}</td></tr>"
        for t, c in assessment.tool_call_summary.items()
    )
    tool_table = ""
    if tool_rows:
        tool_table = f"""
        <details class="tool-summary"><summary>Tool Usage Summary ({assessment.total_tool_calls} total calls)</summary>
          <table class="mini-table"><thead><tr><th>Tool</th><th>Calls</th></tr></thead>
          <tbody>{tool_rows}</tbody></table>
        </details>"""

    metrics = f"""
    <div class="metrics-grid">
      <div class="metric"><span class="metric-val">{assessment.attacks_with_out_of_scope_tools}</span><span class="metric-label">Out-of-scope tool attacks</span></div>
      <div class="metric"><span class="metric-val">{assessment.attacks_with_secret_access}</span><span class="metric-label">Secret access attempts</span></div>
      <div class="metric"><span class="metric-val">{assessment.attacks_with_network_requests}</span><span class="metric-label">Unauthorized network</span></div>
      <div class="metric"><span class="metric-val">{assessment.attacks_with_writes}</span><span class="metric-label">Unauthorized writes</span></div>
    </div>"""

    return f"""
    <section class="card">
      <h2>Behavioral Risk Assessment</h2>
      <p class="muted">Even when no canary token is definitively leaked, the model's attempted actions
      reveal whether it <em>would</em> compromise a real environment.</p>
      {metrics}
      <div class="risk-cards">{"".join(cards)}</div>
      {tool_table}
    </section>"""


# -- Attack drill-down -------------------------------------------------------

_EVENT_ICON = {
    EventType.LLM_PROMPT: ("prompt", "P"),
    EventType.LLM_RESPONSE: ("response", "R"),
    EventType.TOOL_CALL: ("toolcall", "T"),
    EventType.TOOL_RESULT: ("toolresult", "TR"),
    EventType.NETWORK_REQUEST: ("network", "N"),
    EventType.FILE_READ: ("fileop", "FR"),
    EventType.FILE_WRITE: ("fileop", "FW"),
    EventType.SECRET_ACCESS: ("secret", "S!"),
}


def _render_attacks(attack_results: list[AttackResult]) -> str:
    if not attack_results:
        return '<section class="card"><h2>Attack Results</h2><p class="muted">No attacks executed.</p></section>'

    items = []
    for ar in attack_results:
        tpl = ar.attack.template
        status_cls = "succeeded" if ar.succeeded else "defended"
        status_label = "COMPROMISED" if ar.succeeded else "DEFENDED"

        signals_html = ""
        if ar.signals:
            sig_items = "".join(
                f'<li><span class="badge badge-sm" style="background:{_SEV_COLOR.get("high", "var(--c-info)")}">'
                f'{_esc(s.tier.value.replace("_", " ").title())}</span> '
                f'{_esc(s.description[:120])}</li>'
                for s in ar.signals
            )
            signals_html = f"<ul class='signal-list'>{sig_items}</ul>"

        events_html = ""
        if ar.trace and ar.trace.events:
            evts = []
            for ev in ar.trace.events[:50]:
                cls_name, icon = _EVENT_ICON.get(ev.event_type, ("other", "?"))
                summary = ""
                if ev.tool_name:
                    summary = f"<strong>{_esc(ev.tool_name)}</strong>"
                    if ev.tool_args:
                        args_preview = str(ev.tool_args)[:100]
                        summary += f" <code>{_esc(args_preview)}</code>"
                elif ev.content:
                    summary = _esc(ev.content[:200])
                evts.append(
                    f'<div class="evt evt-{cls_name}">'
                    f'<span class="evt-icon">{icon}</span>'
                    f'<span class="evt-type">{_esc(ev.event_type.value)}</span>'
                    f'<span class="evt-body">{summary}</span></div>'
                )
            events_html = f'<div class="trace-timeline">{"".join(evts)}</div>'

        items.append(f"""
        <details class="attack-item">
          <summary>
            <span class="attack-status {status_cls}">{status_label}</span>
            <span class="attack-name">{_esc(tpl.name)}</span>
            <span class="badge badge-sm">{_esc(tpl.vuln_class.value)}</span>
            <span class="attack-meta">{_esc(tpl.stealth.value)} | {_esc(tpl.complexity.value)}</span>
          </summary>
          <div class="attack-body">
            <p>{_esc(tpl.description[:300])}</p>
            {signals_html}
            {events_html}
          </div>
        </details>""")

    return f"""
    <section class="card">
      <h2>Attack Results <span class="count-badge">{len(attack_results)}</span></h2>
      <div class="attack-filter-bar">
        <button class="atk-filter-btn active" data-filter="all">All</button>
        <button class="atk-filter-btn" data-filter="succeeded">Compromised</button>
        <button class="atk-filter-btn" data-filter="defended">Defended</button>
      </div>
      <div class="attacks-list">{"".join(items)}</div>
    </section>"""


# ---------------------------------------------------------------------------
# Full HTML template
# ---------------------------------------------------------------------------

_PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agent Security Scan Report</title>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--fg:#c9d1d9;--fg2:#8b949e;
  --border:#30363d;
  --c-critical:#f85149;--c-high:#db6d28;--c-medium:#d29922;--c-low:#3fb950;--c-info:#58a6ff;
  --radius:8px;--shadow:0 1px 3px rgba(0,0,0,.4);
  --font:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen,sans-serif;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
}}
[data-theme="light"]{{
  --bg:#f6f8fa;--bg2:#ffffff;--bg3:#eaeef2;--fg:#1f2328;--fg2:#656d76;
  --border:#d0d7de;--shadow:0 1px 3px rgba(0,0,0,.12);
}}
html{{font-family:var(--font);background:var(--bg);color:var(--fg);line-height:1.6}}
body{{max-width:1100px;margin:0 auto;padding:24px}}
a{{color:var(--c-info);text-decoration:none}}
code{{font-family:var(--mono);font-size:.88em;background:var(--bg3);padding:2px 5px;border-radius:4px}}

/* Header */
.header{{display:flex;justify-content:space-between;align-items:center;padding:16px 0;border-bottom:1px solid var(--border);margin-bottom:24px}}
.header h1{{font-size:1.4em;font-weight:600}}
.header-meta{{display:flex;gap:16px;font-size:.85em;color:var(--fg2);flex-wrap:wrap}}
.theme-toggle{{background:var(--bg3);border:1px solid var(--border);color:var(--fg);padding:6px 12px;border-radius:var(--radius);cursor:pointer;font-size:.85em}}

/* Cards */
.card{{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:20px;box-shadow:var(--shadow)}}
.card h2{{font-size:1.15em;margin-bottom:14px;display:flex;align-items:center;gap:8px}}

/* Badges */
.badge{{display:inline-block;padding:2px 10px;border-radius:12px;font-size:.75em;font-weight:600;color:#fff;text-transform:uppercase;letter-spacing:.03em}}
.badge-sm{{font-size:.7em;padding:1px 7px}}
.count-badge{{background:var(--bg3);color:var(--fg2);font-size:.75em;padding:2px 8px;border-radius:10px;font-weight:500}}

/* Score gauge */
.score-card .gauge-row{{display:flex;align-items:center;gap:32px;flex-wrap:wrap}}
.gauge{{width:140px;height:140px;border-radius:50%;background:conic-gradient(var(--color) var(--deg),var(--bg3) var(--deg));display:flex;align-items:center;justify-content:center;flex-shrink:0}}
.gauge-inner{{width:100px;height:100px;border-radius:50%;background:var(--bg2);display:flex;flex-direction:column;align-items:center;justify-content:center}}
.gauge-value{{font-size:2em;font-weight:700;line-height:1}}
.gauge-label{{font-size:.8em;color:var(--fg2)}}
.score-meta{{display:flex;flex-direction:column;gap:6px}}
.score-meta .note{{color:var(--fg2);font-size:.85em;font-style:italic}}

/* Bar chart */
.bar-chart{{display:flex;flex-direction:column;gap:8px}}
.bar-row{{display:grid;grid-template-columns:220px 1fr 80px;align-items:center;gap:10px;font-size:.85em}}
.bar-label{{text-align:right;color:var(--fg2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.bar-track{{height:22px;background:var(--bg3);border-radius:4px;overflow:hidden;position:relative}}
.bar-fill{{height:100%;border-radius:4px;display:flex;align-items:center;padding-left:6px;transition:width .3s;min-width:28px}}
.bar-value{{font-size:.75em;font-weight:600;color:#fff}}
.bar-detail{{font-size:.8em;color:var(--fg2)}}

/* Findings table */
.findings-table{{width:100%;border-collapse:collapse;font-size:.85em}}
.findings-table th{{text-align:left;padding:8px 10px;border-bottom:2px solid var(--border);color:var(--fg2);font-weight:600;cursor:pointer;user-select:none}}
.findings-table th:hover{{color:var(--fg)}}
.findings-table td{{padding:8px 10px;border-bottom:1px solid var(--border)}}
.finding-row{{cursor:pointer;transition:background .15s}}
.finding-row:hover{{background:var(--bg3)}}
.finding-detail{{display:none}}
.finding-row.expanded+.finding-detail{{display:table-row}}
.finding-detail td{{background:var(--bg3);padding:14px 16px}}
.finding-detail .timeline ol{{margin:8px 0 8px 18px}}
.finding-detail .mitigation{{margin-top:10px;padding:10px;background:var(--bg2);border-radius:var(--radius)}}

/* Filter bar */
.filter-bar,.attack-filter-bar{{display:flex;gap:6px;margin-bottom:14px;flex-wrap:wrap}}
.filter-btn,.atk-filter-btn{{background:transparent;border:1.5px solid var(--border);color:var(--fg2);padding:4px 12px;border-radius:16px;cursor:pointer;font-size:.8em;transition:all .15s}}
.filter-btn:hover,.atk-filter-btn:hover,.filter-btn.active,.atk-filter-btn.active{{background:var(--bg3);color:var(--fg);border-color:var(--fg2)}}

/* Behavioral risk cards */
.risk-cards{{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:12px;margin-bottom:14px}}
.risk-card{{background:var(--bg3);border-radius:var(--radius);padding:14px}}
.risk-card .risk-header{{display:flex;align-items:center;gap:8px;margin-bottom:6px}}
.risk-card p{{font-size:.85em;color:var(--fg2)}}
.risk-card ul{{margin:8px 0 0 16px;font-size:.82em}}
.risk-card li{{margin-bottom:2px}}

.metrics-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px;margin-bottom:16px}}
.metric{{background:var(--bg3);border-radius:var(--radius);padding:12px;text-align:center}}
.metric-val{{display:block;font-size:1.6em;font-weight:700}}
.metric-label{{font-size:.78em;color:var(--fg2)}}

.tool-summary{{margin-top:10px;font-size:.85em}}
.tool-summary summary{{cursor:pointer;color:var(--fg2);font-weight:500}}
.mini-table{{width:100%;border-collapse:collapse;margin-top:8px}}
.mini-table th,.mini-table td{{text-align:left;padding:4px 10px;border-bottom:1px solid var(--border)}}
.mini-table th{{color:var(--fg2);font-weight:600}}

/* Attack drill-down */
.attacks-list{{display:flex;flex-direction:column;gap:6px}}
.attack-item{{border:1px solid var(--border);border-radius:var(--radius);overflow:hidden}}
.attack-item summary{{display:flex;align-items:center;gap:10px;padding:10px 14px;cursor:pointer;font-size:.88em;list-style:none}}
.attack-item summary::-webkit-details-marker{{display:none}}
.attack-item summary::before{{content:"\\25B6";font-size:.7em;transition:transform .2s;color:var(--fg2)}}
.attack-item[open] summary::before{{transform:rotate(90deg)}}
.attack-status{{padding:2px 10px;border-radius:4px;font-size:.72em;font-weight:700;color:#fff;text-transform:uppercase;letter-spacing:.04em}}
.attack-status.succeeded{{background:var(--c-critical)}}
.attack-status.defended{{background:var(--c-low)}}
.attack-name{{flex:1;font-weight:500}}
.attack-meta{{color:var(--fg2);font-size:.8em}}
.attack-body{{padding:14px 16px;border-top:1px solid var(--border);background:var(--bg3)}}
.attack-body p{{font-size:.85em;color:var(--fg2);margin-bottom:8px}}
.signal-list{{margin:8px 0 10px 16px;font-size:.82em}}
.signal-list li{{margin-bottom:4px}}

/* Trace timeline */
.trace-timeline{{display:flex;flex-direction:column;gap:3px;max-height:350px;overflow-y:auto;font-size:.82em;border:1px solid var(--border);border-radius:var(--radius);padding:8px;background:var(--bg2)}}
.evt{{display:flex;align-items:baseline;gap:8px;padding:3px 0}}
.evt-icon{{width:24px;text-align:center;font-weight:700;font-size:.75em;color:#fff;background:var(--bg3);border-radius:4px;padding:1px 4px;flex-shrink:0}}
.evt-type{{width:110px;flex-shrink:0;color:var(--fg2);font-family:var(--mono);font-size:.9em}}
.evt-body{{word-break:break-word}}
.evt-prompt .evt-icon{{background:var(--c-info)}}
.evt-response .evt-icon{{background:#8b5cf6}}
.evt-toolcall .evt-icon{{background:var(--c-medium)}}
.evt-toolresult .evt-icon{{background:var(--c-low)}}
.evt-network .evt-icon{{background:var(--c-high)}}
.evt-fileop .evt-icon{{background:#64748b}}
.evt-secret .evt-icon{{background:var(--c-critical)}}

/* Summary footer */
.summary-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:12px}}
.summary-stat{{text-align:center;padding:16px;background:var(--bg3);border-radius:var(--radius)}}
.summary-stat .stat-val{{display:block;font-size:1.8em;font-weight:700}}
.summary-stat .stat-label{{font-size:.8em;color:var(--fg2)}}

.muted{{color:var(--fg2);font-size:.9em}}

@media(max-width:700px){{
  .bar-row{{grid-template-columns:1fr;gap:2px}}
  .bar-label{{text-align:left}}
  .header{{flex-direction:column;gap:10px}}
}}
</style>
</head>
<body>
<div class="header">
  <div>
    <h1>Agent Security Scan Report</h1>
    <div class="header-meta">
      <span>ID: <code>{scan_id}</code></span>
      <span>Date: {date}</span>
      <span>Duration: {duration}</span>
      <span>Profile: {profile}</span>
      <span>Version: {version}</span>
      <span>Adapter: {adapter}</span>
    </div>
  </div>
  <button class="theme-toggle" onclick="toggleTheme()">Toggle Theme</button>
</div>

{score_section}
{per_class_section}
{findings_section}
{behavioral_section}
{attacks_section}

<section class="card">
  <h2>Summary</h2>
  <div class="summary-grid">
    <div class="summary-stat"><span class="stat-val">{total_attacks}</span><span class="stat-label">Attacks</span></div>
    <div class="summary-stat"><span class="stat-val">{total_succeeded}</span><span class="stat-label">Succeeded</span></div>
    <div class="summary-stat"><span class="stat-val">{total_signals}</span><span class="stat-label">Signals</span></div>
    <div class="summary-stat"><span class="stat-val">{total_findings}</span><span class="stat-label">Findings</span></div>
  </div>
</section>

<footer style="text-align:center;padding:20px 0;color:var(--fg2);font-size:.8em">
  Generated by <strong>agent-redteam</strong>
</footer>

<script>
function toggleTheme(){{
  const html=document.documentElement;
  html.dataset.theme=html.dataset.theme==="dark"?"light":"dark";
}}

/* Findings severity filter */
document.querySelectorAll(".filter-btn").forEach(btn=>{{
  btn.addEventListener("click",()=>{{
    document.querySelectorAll(".filter-btn").forEach(b=>b.classList.remove("active"));
    btn.classList.add("active");
    const f=btn.dataset.filter;
    document.querySelectorAll(".finding-row").forEach(row=>{{
      const show=f==="all"||row.dataset.severity===f;
      row.style.display=show?"":"none";
      row.nextElementSibling.style.display="none";
      row.classList.remove("expanded");
    }});
  }});
}});

/* Attack status filter */
document.querySelectorAll(".atk-filter-btn").forEach(btn=>{{
  btn.addEventListener("click",()=>{{
    document.querySelectorAll(".atk-filter-btn").forEach(b=>b.classList.remove("active"));
    btn.classList.add("active");
    const f=btn.dataset.filter;
    document.querySelectorAll(".attack-item").forEach(item=>{{
      const status=item.querySelector(".attack-status");
      const show=f==="all"||status.classList.contains(f);
      item.style.display=show?"":"none";
    }});
  }});
}});

/* Column sort */
document.querySelectorAll(".findings-table th").forEach((th,colIdx)=>{{
  th.addEventListener("click",()=>{{
    const tbody=th.closest("table").querySelector("tbody");
    const rowPairs=[];
    const rows=[...tbody.querySelectorAll("tr")];
    for(let i=0;i<rows.length;i+=2)rowPairs.push([rows[i],rows[i+1]]);
    const dir=th.dataset.dir==="asc"?"desc":"asc";
    th.dataset.dir=dir;
    rowPairs.sort((a,b)=>{{
      const at=a[0].children[colIdx]?.textContent.trim()||"";
      const bt=b[0].children[colIdx]?.textContent.trim()||"";
      const cmp=at.localeCompare(bt,undefined,{{numeric:true}});
      return dir==="asc"?cmp:-cmp;
    }});
    rowPairs.forEach(([r,d])=>{{tbody.appendChild(r);tbody.appendChild(d);}});
  }});
}});
</script>
</body>
</html>"""
