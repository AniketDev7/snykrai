"""SnykrAI Code Analysis HTML Report — SAST Triage Evidence Report.

Generates a standalone HTML report with:
- Summary KPI cards (total, false positives, true positives, needs review)
- Donut chart showing verdict distribution
- Detailed findings table with file paths, CWE, verdict, confidence, reasoning
- Grouped by verdict: true positives first, then needs review, then false positives
- Evidence-grade detail for sharing with dev teams
"""
import html
from datetime import datetime, timezone


def _esc(text) -> str:
    return html.escape(str(text))


class CodeAnalysisHTMLReport:
    def generate(self, result: dict, trigger_user: str = "") -> str:
        now = datetime.now(timezone.utc)
        now_str = now.strftime("%B %d, %Y at %I:%M %p UTC")
        repo = result.get("repo", "unknown")
        total = result.get("total_findings", 0)
        unique_issues = result.get("unique_issue_count", total)
        fp = result.get("false_positives", [])
        tp = result.get("true_positives", [])
        nr = result.get("needs_review", [])
        ignored = result.get("ignored_count", 0)
        errors = result.get("errors", [])

        donut_svg = self._render_donut([
            ("True Positive", len(tp), "#ef4444"),
            ("Needs Review", len(nr), "#f59e0b"),
            ("False Positive", len(fp), "#22c55e"),
        ], total)

        tp_rows = self._render_findings_table(tp, "true_positive")
        nr_rows = self._render_findings_table(nr, "needs_review")
        fp_rows = self._render_findings_table(fp, "false_positive")

        errors_html = ""
        if errors:
            errors_html = '<div class="error-section"><h3>Errors</h3>'
            for err in errors:
                errors_html += f'<div class="error-item">{_esc(err)}</div>'
            errors_html += '</div>'

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SnykrAI Code Analysis — {_esc(repo)}</title>
<style>
{self._get_css()}
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <header class="header">
    <div class="header-left">
      <div class="logo">
        <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
          <rect width="32" height="32" rx="8" fill="url(#logo-grad)"/>
          <path d="M8 16L14 22L24 10" stroke="white" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
          <defs><linearGradient id="logo-grad" x1="0" y1="0" x2="32" y2="32"><stop stop-color="#f97316"/><stop offset="1" stop-color="#fbbf24"/></linearGradient></defs>
        </svg>
      </div>
      <div>
        <h1>Code Analysis Triage Report</h1>
        <p class="subtitle">{_esc(repo)} &middot; {_esc(now_str)}</p>
      </div>
    </div>
    <div class="header-right">
      <span class="badge badge-trigger">scan-code</span>
      {f'<span class="badge badge-user">by {_esc(trigger_user)}</span>' if trigger_user else ''}
    </div>
  </header>

  <!-- KPI Cards -->
  <section class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-value">{unique_issues}</div>
      <div class="kpi-label">Total Findings</div>
    </div>
    <div class="kpi-card kpi-danger">
      <div class="kpi-value">{len(tp)}</div>
      <div class="kpi-label">True Positives</div>
    </div>
    <div class="kpi-card kpi-warning">
      <div class="kpi-value">{len(nr)}</div>
      <div class="kpi-label">Needs Review</div>
    </div>
    <div class="kpi-card kpi-success">
      <div class="kpi-value">{len(fp)}</div>
      <div class="kpi-label">False Positives</div>
    </div>
    <div class="kpi-card kpi-info">
      <div class="kpi-value">{ignored}</div>
      <div class="kpi-label">Auto-Ignored</div>
    </div>
  </section>

  <!-- Chart -->
  <section class="charts-row">
    <div class="chart-card">
      <h3>Verdict Distribution</h3>
      {donut_svg}
    </div>
    <div class="chart-card">
      <h3>Summary</h3>
      <div class="summary-text">
        <p>SnykrAI analyzed <strong>{total}</strong> Snyk Code Analysis findings using AI-powered triage.</p>
        <ul>
          {'<li class="tp-highlight">' + str(len(tp)) + ' finding(s) confirmed as <strong>real vulnerabilities</strong> requiring action.</li>' if tp else ''}
          {'<li class="nr-highlight">' + str(len(nr)) + ' finding(s) need <strong>human review</strong> — AI confidence was insufficient.</li>' if nr else ''}
          {'<li class="fp-highlight">' + str(len(fp)) + ' finding(s) classified as <strong>false positives</strong>' + (f' ({ignored} auto-ignored in Snyk)' if ignored else '') + '.</li>' if fp else ''}
        </ul>
        {('<p class="all-fp-banner">All findings were false positives — no code changes needed.</p>' if not tp and not nr and fp else '')}
      </div>
    </div>
  </section>

  <!-- True Positives -->
  {self._render_section("True Positives — Action Required", tp_rows, "tp") if tp else ''}

  <!-- Needs Review -->
  {self._render_section("Needs Human Review", nr_rows, "nr") if nr else ''}

  <!-- False Positives -->
  {self._render_section("False Positives" + (f" ({ignored} auto-ignored)" if ignored else ""), fp_rows, "fp") if fp else ''}

  {errors_html}

  <footer class="footer">
    <p>Generated by <strong>SnykrAI scan-code</strong> &middot; {_esc(now_str)}</p>
    <p class="disclaimer">AI-generated analysis — always verify true positives before remediation and false positives before relying on auto-ignore.</p>
  </footer>
</div>
</body>
</html>"""

    def _render_findings_table(self, findings: list[dict], verdict_type: str) -> str:
        if not findings:
            return ""
        rows = []
        for f in findings:
            fid = _esc(f.get("id", "")[:12])
            title = _esc(f.get("title", ""))
            severity = f.get("severity", "low")
            sev_display = _esc(severity).upper()
            cwe_list = f.get("cwe", [])
            cwe_display = ", ".join(_esc(c) for c in cwe_list) if cwe_list else "—"
            confidence = f.get("confidence", 0)
            conf_pct = f"{confidence:.0%}"
            conf_cls = "conf-high" if confidence >= 0.9 else ("conf-med" if confidence >= 0.7 else "conf-low")
            reasoning = _esc(f.get("reasoning", ""))
            evidence = _esc(f.get("evidence", ""))
            ignore_reason = _esc(f.get("suggested_ignore_reason", ""))

            # File paths
            file_paths = f.get("file_paths", [])
            files_html = ""
            for fp in file_paths[:3]:
                path = _esc(fp.get("path", ""))
                line = fp.get("start_line", 0)
                files_html += f'<code class="file-path">{path}:{line}</code><br>'

            verdict_cls = {
                "true_positive": "verdict-tp",
                "false_positive": "verdict-fp",
                "needs_review": "verdict-nr",
            }.get(verdict_type, "")

            verdict_label = {
                "true_positive": "True Positive",
                "false_positive": "False Positive",
                "needs_review": "Needs Review",
            }.get(verdict_type, verdict_type)

            rows.append(f"""<tr>
  <td><span class="sev-badge sev-{severity}">{sev_display}</span></td>
  <td><strong>{title}</strong><br><span class="cwe-tag">{cwe_display}</span></td>
  <td>{files_html}</td>
  <td><span class="conf-badge {conf_cls}">{conf_pct}</span></td>
  <td class="reasoning-cell">
    <div class="reasoning-text">{reasoning}</div>
    {f'<div class="evidence-text"><strong>Evidence:</strong> {evidence}</div>' if evidence else ''}
    {f'<div class="ignore-reason"><strong>Ignore reason:</strong> {ignore_reason}</div>' if ignore_reason and verdict_type == "false_positive" else ''}
  </td>
</tr>""")

        return "\n".join(rows)

    def _render_section(self, title: str, table_rows: str, section_type: str) -> str:
        icon_map = {
            "tp": '<span class="section-icon section-icon-tp">&#9888;</span>',
            "nr": '<span class="section-icon section-icon-nr">&#128065;</span>',
            "fp": '<span class="section-icon section-icon-fp">&#10003;</span>',
        }
        icon = icon_map.get(section_type, "")
        return f"""<section class="section findings-section findings-{section_type}">
  <h2>{icon} {title}</h2>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Finding</th>
          <th>File</th>
          <th>Confidence</th>
          <th>AI Reasoning</th>
        </tr>
      </thead>
      <tbody>
        {table_rows}
      </tbody>
    </table>
  </div>
</section>"""

    def _render_donut(self, data: list[tuple], total: int) -> str:
        if not data or total == 0:
            return '<div class="empty-state">No findings</div>'
        circumference = 2 * 3.14159 * 40
        circles = []
        offset = 0
        for label, value, color in data:
            if value == 0:
                continue
            pct = value / total
            dash = pct * circumference
            gap = circumference - dash
            circles.append(
                f'<circle cx="50" cy="50" r="40" fill="none" stroke="{color}" stroke-width="12" '
                f'stroke-dasharray="{dash:.1f} {gap:.1f}" stroke-dashoffset="{-offset:.1f}" opacity="0.9"/>'
            )
            offset += dash
        legend = "".join(
            f'<div class="legend-item"><span class="legend-dot" style="background:{c}"></span>{l}: {v}</div>'
            for l, v, c in data if v > 0
        )
        return f"""<div class="donut-wrap">
<svg viewBox="0 0 100 100" class="donut-svg">
  <circle cx="50" cy="50" r="40" fill="none" stroke="#2a2a2a" stroke-width="12" opacity="0.4"/>
  {"".join(circles)}
  <text x="50" y="46" text-anchor="middle" class="donut-number">{total}</text>
  <text x="50" y="58" text-anchor="middle" class="donut-label">findings</text>
</svg>
<div class="legend">{legend}</div>
</div>"""

    def _get_css(self) -> str:
        return """:root {
  --bg: #0a0a0a; --surface: #141414; --surface-2: #1c1c1c; --border: #2a2a2a;
  --text: #f0ece4; --text-muted: #8a8580;
  --accent: #f97316; --accent-light: #fb923c; --accent-glow: rgba(249,115,22,0.15);
  --success: #22c55e; --warning: #f59e0b; --danger: #ef4444; --info: #f97316;
}
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; background:var(--bg); color:var(--text); line-height:1.6; }
.container { max-width:1200px; margin:0 auto; padding:2rem 1.5rem; }
.header { display:flex; justify-content:space-between; align-items:center; padding:1.5rem 2rem; background:linear-gradient(135deg,var(--surface),var(--surface-2)); border:1px solid var(--border); border-radius:16px; margin-bottom:1.5rem; flex-wrap:wrap; gap:1rem; }
.header-left { display:flex; align-items:center; gap:1rem; }
.header-left h1 { font-size:1.5rem; font-weight:700; background:linear-gradient(135deg,#f97316,#fbbf24); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }
.subtitle { font-size:0.85rem; color:var(--text-muted); }
.header-right { display:flex; gap:0.5rem; flex-wrap:wrap; }
.badge { padding:0.3rem 0.75rem; border-radius:20px; font-size:0.75rem; font-weight:600; }
.badge-trigger { background:rgba(249,115,22,0.12); color:#fb923c; border:1px solid rgba(249,115,22,0.3); }
.badge-user { background:rgba(251,191,36,0.12); color:#fbbf24; border:1px solid rgba(251,191,36,0.3); }
.kpi-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:1rem; margin-bottom:1.5rem; }
.kpi-card { background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:1.25rem; position:relative; overflow:hidden; transition:transform 0.2s,box-shadow 0.2s; }
.kpi-card:hover { transform:translateY(-2px); box-shadow:0 8px 30px rgba(0,0,0,0.3); }
.kpi-card::before { content:''; position:absolute; top:0; left:0; right:0; height:3px; background:var(--accent); border-radius:12px 12px 0 0; }
.kpi-success::before { background:var(--success); }
.kpi-warning::before { background:var(--warning); }
.kpi-danger::before { background:var(--danger); }
.kpi-info::before { background:var(--info); }
.kpi-value { font-size:2rem; font-weight:800; line-height:1; margin-bottom:0.25rem; }
.kpi-label { font-size:0.8rem; color:var(--text-muted); font-weight:500; }
.kpi-sublabel { font-size:0.7rem; color:var(--text-muted); opacity:0.7; }
.charts-row { display:grid; grid-template-columns:1fr 2fr; gap:1rem; margin-bottom:1.5rem; }
@media (max-width:900px) { .charts-row { grid-template-columns:1fr; } }
.chart-card { background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:1.5rem; }
.chart-card h3 { font-size:0.9rem; color:var(--text-muted); margin-bottom:1rem; font-weight:600; }
.summary-text { font-size:0.9rem; line-height:1.7; }
.summary-text ul { margin:0.75rem 0; padding-left:1.25rem; }
.summary-text li { margin-bottom:0.4rem; }
.tp-highlight { color:#fca5a5; }
.nr-highlight { color:#fde047; }
.fp-highlight { color:#86efac; }
.all-fp-banner { background:rgba(34,197,94,0.1); border:1px solid rgba(34,197,94,0.3); color:#86efac; padding:0.75rem 1rem; border-radius:8px; margin-top:0.75rem; font-weight:600; }
.donut-wrap { display:flex; align-items:center; gap:1.5rem; }
.donut-svg { width:120px; height:120px; transform:rotate(-90deg); }
.donut-number { font-size:18px; font-weight:800; fill:var(--text); transform:rotate(90deg); transform-origin:50% 46%; }
.donut-label { font-size:8px; fill:var(--text-muted); transform:rotate(90deg); transform-origin:50% 58%; }
.legend { display:flex; flex-direction:column; gap:0.5rem; }
.legend-item { display:flex; align-items:center; gap:0.5rem; font-size:0.8rem; color:var(--text-muted); }
.legend-dot { width:10px; height:10px; border-radius:50%; flex-shrink:0; }
.section { margin-bottom:1.5rem; }
.section h2 { font-size:1.1rem; font-weight:700; margin-bottom:1rem; padding-bottom:0.5rem; border-bottom:1px solid var(--border); }
.section-icon { margin-right:0.5rem; }
.section-icon-tp { color:var(--danger); }
.section-icon-nr { color:var(--warning); }
.section-icon-fp { color:var(--success); }
.findings-tp { border-left:3px solid var(--danger); padding-left:1rem; }
.findings-nr { border-left:3px solid var(--warning); padding-left:1rem; }
.findings-fp { border-left:3px solid var(--success); padding-left:1rem; }
.table-wrap { overflow-x:auto; margin-bottom:1rem; }
table { width:100%; border-collapse:collapse; font-size:0.85rem; }
th { text-align:left; padding:0.6rem 0.75rem; color:var(--text-muted); font-weight:600; font-size:0.75rem; text-transform:uppercase; letter-spacing:0.05em; border-bottom:1px solid var(--border); }
td { padding:0.6rem 0.75rem; border-bottom:1px solid rgba(45,45,45,0.5); vertical-align:top; }
td code { background:var(--surface-2); padding:0.15rem 0.4rem; border-radius:4px; font-size:0.8rem; color:#fbbf24; }
.file-path { font-size:0.78rem; color:#fbbf24; }
.cwe-tag { font-size:0.75rem; color:var(--text-muted); background:var(--surface-2); padding:0.1rem 0.4rem; border-radius:4px; }
.sev-badge { padding:0.15rem 0.5rem; border-radius:4px; font-size:0.7rem; font-weight:600; white-space:nowrap; }
.sev-critical { background:rgba(220,38,38,0.2); color:#fca5a5; }
.sev-high { background:rgba(249,115,22,0.2); color:#fdba74; }
.sev-medium { background:rgba(234,179,8,0.2); color:#fde047; }
.sev-low { background:rgba(163,230,53,0.2); color:#a3e635; }
.conf-badge { padding:0.15rem 0.5rem; border-radius:4px; font-size:0.75rem; font-weight:700; }
.conf-high { background:rgba(34,197,94,0.15); color:#86efac; }
.conf-med { background:rgba(245,158,11,0.15); color:#fde047; }
.conf-low { background:rgba(239,68,68,0.15); color:#fca5a5; }
.reasoning-cell { max-width:400px; }
.reasoning-text { font-size:0.83rem; color:var(--text); line-height:1.5; margin-bottom:0.4rem; }
.evidence-text { font-size:0.78rem; color:var(--text-muted); background:rgba(0,0,0,0.3); padding:0.4rem 0.6rem; border-radius:6px; margin-top:0.3rem; font-family:'Fira Code','Cascadia Code',monospace; }
.ignore-reason { font-size:0.78rem; color:#86efac; margin-top:0.3rem; padding:0.3rem 0.6rem; background:rgba(34,197,94,0.08); border-radius:6px; border-left:2px solid rgba(34,197,94,0.4); }
.error-section { background:rgba(239,68,68,0.05); border:1px solid rgba(239,68,68,0.2); border-radius:12px; padding:1rem 1.25rem; margin-bottom:1.5rem; }
.error-section h3 { color:#fca5a5; font-size:0.9rem; margin-bottom:0.5rem; }
.error-item { font-size:0.8rem; color:var(--text-muted); padding:0.3rem 0; }
.disclaimer { font-size:0.7rem; color:var(--text-muted); opacity:0.6; margin-top:0.3rem; }
.footer { text-align:center; padding:1.5rem; color:var(--text-muted); font-size:0.8rem; border-top:1px solid var(--border); margin-top:2rem; }
@media print { body { background:white; color:#1e293b; } .kpi-card,.chart-card,.section { break-inside:avoid; } }"""
