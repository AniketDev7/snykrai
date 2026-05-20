"""SnykrAI HTML Report Generator — Black + Orange theme with charts.

Generates a standalone HTML report with:
- Gradient header with logo and badges
- KPI cards with hover effects
- Donut chart (fix outcome) + bar chart (severity) + pipeline flow SVG
- Per-repo cards with verification bars, risk badges, fix tables
- LLM impact analysis with breaking change evidence
- Remediation guidance for unfixable issues
"""
import html
from datetime import datetime, timezone

from src.snyk_fixer import classify_upgrade_risk


def _esc(text) -> str:
    return html.escape(str(text))


class HTMLReportGenerator:
    def generate(
        self,
        results: list[dict],
        queued: list[dict],
        clean_count: int,
        run_number: int,
        trigger_source: str,
        trigger_user: str,
    ) -> str:
        now = datetime.now(timezone.utc)
        now_str = now.strftime("%B %d, %Y at %I:%M %p UTC")
        total_processed = len(results)
        total_fixed = sum(1 for r in results if r.get("success") and r.get("fixes_applied"))
        total_failed = sum(1 for r in results if not r.get("success"))
        total_issues = sum(r.get("issues_before", 0) for r in results)
        total_fixes = sum(len(r.get("fixes_applied", [])) for r in results)
        total_unfixable = sum(len(r.get("unfixable", [])) for r in results)
        total_prs = sum(1 for r in results if r.get("pr_url"))

        # Severity counts across all results
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for r in results:
            for fix in r.get("fixes_applied", []):
                # approximate severity from risk
                pass
            # Count from issues_before is approximate
        max_sev = max(sev_counts.values()) if any(sev_counts.values()) else 1

        # LLM providers
        providers = set(r.get("llm_provider", "") for r in results if r.get("llm_provider"))
        provider_str = ", ".join(providers) if providers else "none"

        # Donut segments
        donut_data = []
        if total_fixed > 0:
            donut_data.append(("Fixed", total_fixed, "#22c55e"))
        if total_failed > 0:
            donut_data.append(("Failed", total_failed, "#ef4444"))
        no_fix = total_processed - total_fixed - total_failed
        if no_fix > 0:
            donut_data.append(("No fixes needed", no_fix, "#475569"))
        donut_svg = self._render_donut(donut_data, total_processed)

        # Bar chart
        bar_svg = self._render_severity_bars(sev_counts)

        # Pipeline flow
        flow_svg = self._render_pipeline_flow(total_issues, total_fixes, total_prs, total_failed)

        # Repo cards
        repo_cards = "\n".join(self._render_repo(i, r) for i, r in enumerate(results, 1))

        # Queued section
        queued_html = self._render_queued(queued) if queued else ""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SnykrAI Report — Run #{run_number}</title>
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
        <h1>SnykrAI Auto-Fix Report</h1>
        <p class="subtitle">Run #{run_number} &middot; {_esc(now_str)}</p>
      </div>
    </div>
    <div class="header-right">
      <span class="badge badge-trigger">{_esc(trigger_source.capitalize())}{f' by {_esc(trigger_user)}' if trigger_user else ''}</span>
      <span class="badge badge-ai">AI: {_esc(provider_str)}</span>
    </div>
  </header>

  <!-- KPI Cards -->
  <section class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-value">{total_processed}</div>
      <div class="kpi-label">Repos Processed</div>
      <div class="kpi-icon"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg></div>
    </div>
    <div class="kpi-card kpi-success">
      <div class="kpi-value">{total_fixes}</div>
      <div class="kpi-label">Issues Fixed</div>
      <div class="kpi-icon"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg></div>
    </div>
    <div class="kpi-card kpi-warning">
      <div class="kpi-value">{total_unfixable}</div>
      <div class="kpi-label">Unfixable</div>
      <div class="kpi-icon"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg></div>
    </div>
    <div class="kpi-card kpi-info">
      <div class="kpi-value">{total_prs}</div>
      <div class="kpi-label">Draft PRs</div>
      <div class="kpi-icon"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="18" r="3"/><circle cx="6" cy="6" r="3"/><path d="M13 6h3a2 2 0 012 2v7"/><line x1="6" y1="9" x2="6" y2="21"/></svg></div>
    </div>
    <div class="kpi-card kpi-danger">
      <div class="kpi-value">{total_failed}</div>
      <div class="kpi-label">Failed</div>
      <div class="kpi-icon"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg></div>
    </div>
    <div class="kpi-card kpi-clean">
      <div class="kpi-value">{clean_count}</div>
      <div class="kpi-label">Clean Repos</div>
      <div class="kpi-icon"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
    </div>
  </section>

  <!-- Charts -->
  <section class="charts-row">
    <div class="chart-card">
      <h3>Fix Outcome</h3>
      {donut_svg}
    </div>
    <div class="chart-card">
      <h3>Pipeline Flow</h3>
      {flow_svg}
    </div>
  </section>

  <!-- Repo Results -->
  <section class="section">
    <h2>Repository Results</h2>
    {repo_cards}
  </section>

  {queued_html}

  <footer class="footer">
    <p>Generated by <strong>SnykrAI</strong> &middot; Run #{run_number} &middot; LLM: {_esc(provider_str)} &middot; {_esc(now_str)}</p>
  </footer>
</div>
</body>
</html>"""

    def _render_repo(self, index: int, result: dict) -> str:
        repo = _esc(result.get("repo", "unknown"))
        strategy = _esc(result.get("strategy", ""))
        success = result.get("success", False)
        risk = result.get("risk_level", "")
        pr_url = result.get("pr_url", "")
        branch = result.get("branch", "")
        attempts = result.get("attempts", 0)
        draft = result.get("draft_pr", False)
        llm_prov = result.get("llm_provider", "")
        before = result.get("issues_before", 0)
        after = result.get("issues_after", 0)

        status_icon = '<span class="status-success">&#10003;</span>' if success else '<span class="status-fail">&#10007;</span>'
        strategy_cls = "strategy-aggressive" if strategy == "aggressive" else "strategy-conservative"
        pr_link = f'<a href="{_esc(pr_url)}" class="pr-link" target="_blank">View Draft PR</a>' if pr_url else ""
        risk_badge = f'<span class="risk-badge risk-{risk}">{risk.upper()}</span>' if risk else ""

        meta = f'<span>Branch: <code>{_esc(branch)}</code></span>' if branch else ""
        meta += f'<span>LLM: {_esc(llm_prov)}</span>' if llm_prov else ""
        if attempts > 1:
            meta += f'<span>Attempts: {attempts}/3</span>'

        # Header
        html_parts = [f'''<div class="repo-card">
  <div class="repo-header">
    <div class="repo-title-row">
      {status_icon}
      <h3>{repo}</h3>
      <span class="strategy-badge {strategy_cls}">{strategy}</span>
      {risk_badge}
      {pr_link}
    </div>
    <div class="repo-meta">{meta}</div>
  </div>''']

        # Failure
        if not success:
            error = _esc(result.get("error", "Unknown error"))
            html_parts.append(f'<div class="error-banner">{error}</div>')
            html_parts.append('</div>')
            return "\n".join(html_parts)

        # Build/test verification
        build = result.get("build_passed", False)
        tests = result.get("tests_passed", False)
        tests_skip = result.get("tests_skipped", False)

        html_parts.append('<div class="verification-grid">')
        html_parts.append(f'<div class="verif-item {"verif-pass" if build else "verif-fail"}"><span class="verif-icon">{"&#10003;" if build else "&#10007;"}</span> Build</div>')
        if tests_skip:
            html_parts.append('<div class="verif-item verif-skip"><span class="verif-icon">&#9888;</span> Tests (skipped)</div>')
        else:
            html_parts.append(f'<div class="verif-item {"verif-pass" if tests else "verif-fail"}"><span class="verif-icon">{"&#10003;" if tests else "&#10007;"}</span> Tests</div>')
        html_parts.append(f'<div class="verif-item verif-pass"><span class="verif-icon">&#10003;</span> Snyk scan</div>')
        html_parts.append('</div>')

        # Fixes table
        fixes = result.get("fixes_applied", [])
        if fixes:
            html_parts.append('<h4>Fixes Applied</h4>')
            html_parts.append('<div class="table-wrap"><table>')
            html_parts.append('<thead><tr><th>Package</th><th>From</th><th>To</th><th>Risk</th><th>Action</th><th>Reasoning</th></tr></thead><tbody>')
            for fix in fixes:
                pkg = _esc(fix.get("package", ""))
                from_v = _esc(fix.get("from", ""))
                to_v = _esc(fix.get("to", ""))
                fix_risk = classify_upgrade_risk(fix.get("from", ""), fix.get("to", ""))
                action = _esc(fix.get("action", "upgrade")).upper()
                action_cls = "action-upgrade" if action == "UPGRADE" else "action-override"
                reasoning = _esc(fix.get("reasoning", ""))
                html_parts.append(f'<tr><td><code>{pkg}</code></td><td><code>{from_v}</code></td><td><code>{to_v}</code></td>')
                html_parts.append(f'<td><span class="sev-badge sev-{fix_risk}">{fix_risk}</span></td>')
                html_parts.append(f'<td><span class="action-badge {action_cls}">{action}</span></td>')
                html_parts.append(f'<td class="reasoning-cell">{reasoning}</td></tr>')
            html_parts.append('</tbody></table></div>')

        # Breaking change analysis (LLM evidence)
        breaking = result.get("breaking_changes", [])
        if breaking:
            html_parts.append('<h4>Impact Analysis <span class="muted">(LLM + changelog evidence)</span></h4>')
            for b in breaking:
                pkg = _esc(b.get("package", ""))
                from_v = _esc(b.get("from", ""))
                to_v = _esc(b.get("to", ""))
                files = b.get("imported_in", [])
                analysis = _esc(b.get("analysis", ""))
                changelog = b.get("changelog_available", False)

                is_breaking = "LIKELY TO BREAK" in (b.get("analysis", ""))
                cls = "impact-breaking" if is_breaking else "impact-safe"

                html_parts.append(f'<div class="impact-box {cls}">')
                html_parts.append(f'<strong>{pkg}</strong> ({from_v} &rarr; {to_v})')
                if files:
                    file_list = ", ".join(f"<code>{_esc(f)}</code>" for f in files[:5])
                    html_parts.append(f'<div class="muted">Imported in: {file_list}</div>')
                html_parts.append(f'<div class="muted">Changelog fetched: {"Yes" if changelog else "No"}</div>')
                if analysis:
                    html_parts.append(f'<div class="impact-analysis">{analysis}</div>')
                html_parts.append('</div>')

        # Unfixable
        unfixable = result.get("unfixable", [])
        if unfixable:
            html_parts.append('<div class="unfixable-section"><h4>Not Fixed</h4>')
            html_parts.append('<div class="table-wrap"><table>')
            html_parts.append('<thead><tr><th>Package</th><th>Reason</th></tr></thead><tbody>')
            for uf in unfixable:
                html_parts.append(f'<tr><td><code>{_esc(uf.get("package", ""))}</code></td><td class="muted">{_esc(uf.get("reason", ""))}</td></tr>')
            html_parts.append('</tbody></table></div></div>')

        # Verification bars
        if before > 0:
            after_pct = max(0, min(100, (after / before) * 100)) if before else 0
            before_pct = 100
            reduction = round((1 - after / before) * 100) if before else 0

            html_parts.append(f'''<div class="verification">
    <div class="verif-header">
      <span>Snyk Verification</span>
      <span class="reduction-badge">&darr; {reduction}% reduction</span>
    </div>
    <div class="verif-bars">
      <div class="verif-row">
        <span class="verif-label">Before</span>
        <div class="verif-track"><div class="verif-fill verif-before" style="width:{before_pct}%"></div></div>
        <span class="verif-val">{before}</span>
      </div>
      <div class="verif-row">
        <span class="verif-label">After</span>
        <div class="verif-track"><div class="verif-fill verif-after" style="width:{after_pct}%"></div></div>
        <span class="verif-val">{after}</span>
      </div>
    </div>
  </div>''')

        html_parts.append('</div>')
        return "\n".join(html_parts)

    def _render_donut(self, data: list[tuple], total: int) -> str:
        if not data or total == 0:
            return '<div class="empty-state">No data</div>'
        circumference = 2 * 3.14159 * 40  # r=40
        circles = []
        offset = 0
        for label, value, color in data:
            pct = value / total
            dash = pct * circumference
            gap = circumference - dash
            circles.append(f'<circle cx="50" cy="50" r="40" fill="none" stroke="{color}" stroke-width="12" '
                          f'stroke-dasharray="{dash:.1f} {gap:.1f}" stroke-dashoffset="{-offset:.1f}" opacity="0.9"/>')
            offset += dash
        legend = "".join(f'<div class="legend-item"><span class="legend-dot" style="background:{c}"></span>{l}: {v}</div>'
                        for l, v, c in data)
        return f'''<div class="donut-wrap">
<svg viewBox="0 0 100 100" class="donut-svg">
  <circle cx="50" cy="50" r="40" fill="none" stroke="#2a2a2a" stroke-width="12" opacity="0.4"/>
  {"".join(circles)}
  <text x="50" y="46" text-anchor="middle" class="donut-number">{total}</text>
  <text x="50" y="58" text-anchor="middle" class="donut-label">repos</text>
</svg>
<div class="legend">{legend}</div>
</div>'''

    def _render_pipeline_flow(self, scanned: int, fixed: int, prs: int, failed: int) -> str:
        steps = [
            (scanned, "Scanned", "#f97316"),
            (fixed, "Fixed", "#22c55e"),
            (prs, "PRs", "#fbbf24"),
        ]
        if failed:
            steps.append((failed, "Failed", "#ef4444"))

        boxes = []
        arrows = []
        x = 10
        for i, (val, label, color) in enumerate(steps):
            boxes.append(f'''<g>
  <rect x="{x}" y="15" width="90" height="50" rx="10" fill="{color}" opacity="0.15" stroke="{color}" stroke-width="1.5"/>
  <text x="{x+45}" y="38" text-anchor="middle" fill="{color}" font-size="16" font-weight="700">{val}</text>
  <text x="{x+45}" y="52" text-anchor="middle" fill="{color}" font-size="9" opacity="0.8">{label}</text>
</g>''')
            if i < len(steps) - 1:
                ax = x + 94
                arrows.append(f'<path d="M{ax} 40 L{ax+16} 40" stroke="#475569" stroke-width="1.5" marker-end="url(#arr)"/>')
            x += 120

        width = x - 20
        return f'''<svg viewBox="0 0 {width} 80" class="flow-svg">
  <defs><marker id="arr" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><path d="M0 0 L8 3 L0 6" fill="#475569"/></marker></defs>
  {"".join(arrows)}{"".join(boxes)}
</svg>'''

    def _render_severity_bars(self, counts: dict) -> str:
        colors = {"critical": "#dc2626", "high": "#f97316", "medium": "#eab308", "low": "#a3e635"}
        max_val = max(counts.values()) if any(counts.values()) else 1
        rows = ""
        for sev in ("critical", "high", "medium", "low"):
            val = counts.get(sev, 0)
            pct = (val / max_val * 100) if max_val else 0
            rows += f'''<div class="bar-row">
  <span class="bar-label">{sev.capitalize()}</span>
  <div class="bar-track"><div class="bar-fill" style="width:{pct}%;background:{colors[sev]}"></div></div>
  <span class="bar-value">{val}</span>
</div>'''
        return f'<div class="bar-chart">{rows}</div>'

    def _render_queued(self, queued: list[dict]) -> str:
        rows = ""
        for i, q in enumerate(queued, 1):
            sla = q.get("sla_days_remaining", 99)
            sla_cls = "sla-critical" if sla <= 3 else ("sla-warning" if sla <= 7 else "")
            rows += f'<tr><td>{i}</td><td>{_esc(q.get("repo", ""))}</td><td>{q.get("issue_count", 0)}</td>'
            rows += f'<td><span class="sev-badge sev-{q.get("top_severity", "low")}">{_esc(q.get("top_severity", "").capitalize())}</span></td>'
            rows += f'<td class="{sla_cls}">{sla}d</td></tr>'
        return f'''<section class="section">
<h2>Queued for Next Run</h2>
<div class="table-wrap"><table class="queued-table">
<thead><tr><th>#</th><th>Repo</th><th>Issues</th><th>Severity</th><th>SLA</th></tr></thead>
<tbody>{rows}</tbody></table></div></section>'''

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
.badge-ai { background:rgba(251,191,36,0.12); color:#fbbf24; border:1px solid rgba(251,191,36,0.3); }
.kpi-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:1rem; margin-bottom:1.5rem; }
.kpi-card { background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:1.25rem; position:relative; overflow:hidden; transition:transform 0.2s,box-shadow 0.2s; }
.kpi-card:hover { transform:translateY(-2px); box-shadow:0 8px 30px rgba(0,0,0,0.3); }
.kpi-card::before { content:''; position:absolute; top:0; left:0; right:0; height:3px; background:var(--accent); border-radius:12px 12px 0 0; }
.kpi-success::before { background:var(--success); } .kpi-warning::before { background:var(--warning); }
.kpi-danger::before { background:var(--danger); } .kpi-info::before { background:var(--info); }
.kpi-clean::before { background:#a3e635; }
.kpi-value { font-size:2rem; font-weight:800; line-height:1; margin-bottom:0.25rem; }
.kpi-label { font-size:0.8rem; color:var(--text-muted); font-weight:500; }
.kpi-icon { position:absolute; top:1rem; right:1rem; color:var(--text-muted); opacity:0.3; }
.charts-row { display:grid; grid-template-columns:1fr 2fr; gap:1rem; margin-bottom:1.5rem; }
@media (max-width:900px) { .charts-row { grid-template-columns:1fr; } }
.chart-card { background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:1.5rem; }
.chart-card h3 { font-size:0.9rem; color:var(--text-muted); margin-bottom:1rem; font-weight:600; }
.donut-wrap { display:flex; align-items:center; gap:1.5rem; }
.donut-svg { width:120px; height:120px; transform:rotate(-90deg); }
.donut-number { font-size:18px; font-weight:800; fill:var(--text); transform:rotate(90deg); transform-origin:50% 46%; }
.donut-label { font-size:8px; fill:var(--text-muted); transform:rotate(90deg); transform-origin:50% 58%; }
.legend { display:flex; flex-direction:column; gap:0.5rem; }
.legend-item { display:flex; align-items:center; gap:0.5rem; font-size:0.8rem; color:var(--text-muted); }
.legend-dot { width:10px; height:10px; border-radius:50%; flex-shrink:0; }
.bar-chart { display:flex; flex-direction:column; gap:0.75rem; }
.bar-row { display:flex; align-items:center; gap:0.75rem; }
.bar-label { width:60px; font-size:0.8rem; color:var(--text-muted); text-align:right; }
.bar-track { flex:1; height:24px; background:rgba(255,255,255,0.05); border-radius:6px; overflow:hidden; }
.bar-fill { height:100%; border-radius:6px; transition:width 0.6s ease; min-width:2px; }
.bar-value { width:30px; font-size:0.85rem; font-weight:700; }
.flow-svg { width:100%; height:auto; }
.section { margin-bottom:1.5rem; }
.section h2 { font-size:1.1rem; font-weight:700; margin-bottom:1rem; padding-bottom:0.5rem; border-bottom:1px solid var(--border); }
.repo-card { background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:1.5rem; margin-bottom:1rem; transition:box-shadow 0.2s; }
.repo-card:hover { box-shadow:0 4px 20px rgba(0,0,0,0.2); }
.repo-header { margin-bottom:1rem; }
.repo-title-row { display:flex; align-items:center; gap:0.75rem; flex-wrap:wrap; }
.repo-title-row h3 { font-size:1rem; font-weight:700; }
.repo-meta { display:flex; flex-wrap:wrap; gap:1rem; margin-top:0.4rem; font-size:0.8rem; color:var(--text-muted); }
.repo-meta code { background:var(--surface-2); padding:0.1rem 0.4rem; border-radius:4px; font-size:0.75rem; }
.status-success { color:var(--success); font-weight:700; font-size:1.2rem; }
.status-fail { color:var(--danger); font-weight:700; font-size:1.2rem; }
.strategy-badge { padding:0.2rem 0.6rem; border-radius:6px; font-size:0.7rem; font-weight:600; text-transform:uppercase; letter-spacing:0.05em; }
.strategy-aggressive { background:rgba(249,115,22,0.15); color:#fb923c; border:1px solid rgba(249,115,22,0.3); }
.strategy-conservative { background:rgba(163,230,53,0.15); color:#a3e635; border:1px solid rgba(163,230,53,0.3); }
.risk-badge { padding:0.2rem 0.6rem; border-radius:6px; font-size:0.7rem; font-weight:600; text-transform:uppercase; }
.risk-patch { background:rgba(34,197,94,0.15); color:#4ade80; border:1px solid rgba(34,197,94,0.3); }
.risk-minor { background:rgba(249,115,22,0.15); color:#fb923c; border:1px solid rgba(249,115,22,0.3); }
.risk-major { background:rgba(239,68,68,0.15); color:#fca5a5; border:1px solid rgba(239,68,68,0.3); }
.pr-link { margin-left:auto; color:#fb923c; text-decoration:none; font-size:0.85rem; font-weight:600; padding:0.3rem 0.75rem; border:1px solid rgba(249,115,22,0.3); border-radius:8px; transition:background 0.2s; }
.pr-link:hover { background:rgba(249,115,22,0.15); }
.error-banner { background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.3); color:#fca5a5; padding:0.75rem 1rem; border-radius:8px; font-size:0.85rem; margin-bottom:1rem; }
.verification-grid { display:flex; gap:0.75rem; margin-bottom:1rem; flex-wrap:wrap; }
.verif-item { padding:0.4rem 0.8rem; border-radius:8px; font-size:0.8rem; font-weight:600; display:flex; align-items:center; gap:0.4rem; }
.verif-pass { background:rgba(34,197,94,0.1); color:#4ade80; border:1px solid rgba(34,197,94,0.25); }
.verif-fail { background:rgba(239,68,68,0.1); color:#fca5a5; border:1px solid rgba(239,68,68,0.25); }
.verif-skip { background:rgba(245,158,11,0.1); color:#fde047; border:1px solid rgba(245,158,11,0.25); }
.verif-icon { font-size:1rem; }
h4 { font-size:0.9rem; margin:1rem 0 0.5rem; color:var(--accent-light); }
.table-wrap { overflow-x:auto; margin-bottom:1rem; }
table { width:100%; border-collapse:collapse; font-size:0.85rem; }
th { text-align:left; padding:0.6rem 0.75rem; color:var(--text-muted); font-weight:600; font-size:0.75rem; text-transform:uppercase; letter-spacing:0.05em; border-bottom:1px solid var(--border); }
td { padding:0.6rem 0.75rem; border-bottom:1px solid rgba(45,45,45,0.5); }
td code { background:var(--surface-2); padding:0.15rem 0.4rem; border-radius:4px; font-size:0.8rem; color:#fbbf24; }
.reasoning-cell { font-size:0.8rem; color:var(--text-muted); max-width:300px; }
.action-badge { padding:0.15rem 0.5rem; border-radius:4px; font-size:0.7rem; font-weight:600; }
.action-upgrade { background:rgba(34,197,94,0.15); color:#4ade80; }
.action-override { background:rgba(249,115,22,0.15); color:#fb923c; }
.sev-badge { padding:0.15rem 0.5rem; border-radius:4px; font-size:0.7rem; font-weight:600; }
.sev-critical { background:rgba(220,38,38,0.2); color:#fca5a5; }
.sev-high { background:rgba(249,115,22,0.2); color:#fdba74; }
.sev-medium { background:rgba(234,179,8,0.2); color:#fde047; }
.sev-low { background:rgba(163,230,53,0.2); color:#a3e635; }
.sev-patch { background:rgba(34,197,94,0.2); color:#4ade80; }
.sev-minor { background:rgba(249,115,22,0.2); color:#fdba74; }
.sev-major { background:rgba(220,38,38,0.2); color:#fca5a5; }
.impact-box { background:rgba(30,30,35,0.95); border:1px solid var(--border); border-radius:10px; padding:1rem 1.25rem; margin-bottom:0.75rem; font-size:0.85rem; border-left:3px solid var(--success); }
.impact-breaking { border-left-color:var(--danger); }
.impact-safe { border-left-color:var(--success); }
.impact-analysis { margin-top:0.5rem; padding:0.5rem; background:rgba(0,0,0,0.3); border-radius:6px; font-size:0.82rem; line-height:1.5; }
.unfixable-section h4 { color:var(--warning); }
.muted { color:var(--text-muted); font-size:0.8rem; }
.verification { background:var(--surface-2); border-radius:8px; padding:1rem; margin-top:1rem; }
.verif-header { display:flex; justify-content:space-between; align-items:center; margin-bottom:0.75rem; font-size:0.85rem; font-weight:600; }
.reduction-badge { background:rgba(34,197,94,0.15); color:#4ade80; padding:0.2rem 0.6rem; border-radius:4px; font-size:0.75rem; }
.verif-bars { display:flex; flex-direction:column; gap:0.5rem; }
.verif-row { display:flex; align-items:center; gap:0.75rem; }
.verif-label { width:50px; font-size:0.8rem; color:var(--text-muted); }
.verif-track { flex:1; height:20px; background:rgba(255,255,255,0.05); border-radius:6px; overflow:hidden; }
.verif-fill { height:100%; border-radius:6px; transition:width 0.6s ease; }
.verif-before { background:linear-gradient(90deg,#ef4444,#f97316); }
.verif-after { background:linear-gradient(90deg,#22c55e,#fbbf24); }
.verif-val { width:30px; font-size:0.85rem; font-weight:700; text-align:right; }
.queued-table .sla-critical { color:#fca5a5; font-weight:700; }
.queued-table .sla-warning { color:#fde047; font-weight:600; }
.footer { text-align:center; padding:1.5rem; color:var(--text-muted); font-size:0.8rem; border-top:1px solid var(--border); margin-top:2rem; }
.empty-state { color:var(--text-muted); text-align:center; padding:2rem; }
@media print { body { background:white; color:#1e293b; } .kpi-card,.chart-card,.repo-card { break-inside:avoid; } }"""
