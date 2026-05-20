from datetime import datetime, timezone

from src.snyk_fixer import classify_upgrade_risk


class ReportGenerator:
    def generate(
        self,
        results: list[dict],
        queued: list[dict],
        clean_count: int,
        run_number: int,
        trigger_source: str,
        trigger_user: str,
        org_analysis: "dict | None" = None,
    ) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %I:%M %p UTC")
        total_processed = len(results)
        total_fixed = sum(1 for r in results if r.get("success") and r.get("fixes_applied"))
        total_failed = sum(1 for r in results if not r.get("success"))
        total_issues = sum(r.get("issues_before", 0) for r in results)
        total_fixes = sum(len(r.get("fixes_applied", [])) for r in results)
        total_unfixable = sum(len(r.get("unfixable", [])) for r in results)
        total_prs = sum(1 for r in results if r.get("pr_url"))

        lines = [
            "# SnykrAI Fix Report",
            f"**Run:** #{run_number} | **Date:** {now}",
            f"**Trigger:** {trigger_source.capitalize()}"
            + (f" by {trigger_user}" if trigger_user else "")
            + f" | **Repos Processed:** {total_processed}",
            "",
            "---",
            "",
            "## Summary",
            "",
            "| Metric | Count |",
            "|--------|-------|",
            f"| Repos processed | {total_processed} |",
            f"| Repos with fixes | {total_fixed} |",
            f"| Repos failed | {total_failed} |",
            f"| Total issues analyzed | {total_issues} |",
            f"| Issues fixed | {total_fixes} |",
            f"| Issues unfixable | {total_unfixable} |",
            f"| Draft PRs created | {total_prs} |",
            "",
            "---",
            "",
        ]

        # ── Cascade Fix Plan ───────────────────────────────────────────────────
        if org_analysis:
            cascade_entries = org_analysis.get("cascade_entries", [])
            total_transitive = org_analysis.get("total_transitive_issues", 0)
            upstream_count = org_analysis.get("upstream_fix_count", 0)
            downstream_count = org_analysis.get("downstream_impact_count", 0)
            duration = org_analysis.get("analysis_duration_seconds", 0)
            fallback = org_analysis.get("fallback_used", False)

            lines.append("## Cascade Fix Plan (Phase 0 Analysis)")
            lines.append("")
            lines.append(
                f"**{total_transitive} transitive issues** across org | "
                f"**{upstream_count} upstream fix(es)** → "
                f"**{downstream_count} downstream repos** benefit | "
                f"Analysis: {duration}s"
                + (" _(partial — deadline reached)_" if fallback else "")
            )
            lines.append("")

            if cascade_entries:
                lines.append("| Upstream Package | Vuln Package | Fix Version | Severity | Downstream Repos |")
                lines.append("|-----------------|-------------|-------------|----------|-----------------|")
                for entry in cascade_entries:
                    org_pkg = entry.get("org_package_name", entry.get("cs_package_name", "?"))
                    upstream_repo = entry.get("upstream_repo_name") or "_(unmapped)_"
                    vuln_pkg = entry.get("vuln_package", "?")
                    fixed_in = entry.get("fixed_in_version", "?")
                    severity = entry.get("severity", "?").upper()
                    downstream = entry.get("downstream_repos", [])
                    n = len(downstream)
                    repo_preview = ", ".join(f"`{r}`" for r in downstream[:3])
                    if n > 3:
                        repo_preview += f" _(+{n - 3} more)_"
                    lines.append(
                        f"| `{org_pkg}` / `{upstream_repo}` | `{vuln_pkg}` | "
                        f"`{fixed_in}` | {severity} | {repo_preview} |"
                    )
                lines.append("")
            else:
                lines.append("_No org-owned packages found in transitive dep chains — all fixes are direct overrides._")
                lines.append("")

            lines.append("---")
            lines.append("")

        for i, result in enumerate(results, 1):
            repo = result.get("repo", "unknown")
            strategy = result.get("strategy", "unknown")
            branch = result.get("branch", "")
            pr_url = result.get("pr_url", "")
            success = result.get("success", False)
            risk = result.get("risk_level", "")
            attempts = result.get("attempts", 0)

            risk_label = {"patch": "LOW", "minor": "MED", "major": "HIGH"}.get(risk, "")

            lines.append(f"## {i}. {repo}")
            meta = f"**Strategy:** {strategy.capitalize()}"
            if risk_label:
                meta += f" | **Risk:** {risk_label}"
            if branch:
                meta += f" | **Branch:** `{branch}`"
            if pr_url:
                meta += f" | **PR:** {pr_url}"
            else:
                meta += " | **No PR created**"
            lines.append(meta)
            if attempts > 1:
                lines.append(f"*Fix succeeded on attempt {attempts}/{3}*")
            lines.append("")

            if not success:
                error = result.get("error", "Unknown error")
                lines.append(f"**FAILED:** {error}")
                lines.append("")
                lines.append("---")
                lines.append("")
                continue

            build = result.get("build_passed", False)
            tests = result.get("tests_passed", False)
            tests_skip = result.get("tests_skipped", False)

            if build and (tests or tests_skip):
                conf_label = "HIGH — build + tests passed"
            elif build:
                conf_label = "MEDIUM — build passed, tests failed"
            else:
                conf_label = "LOW — build failed"

            lines.append("### Verification")
            lines.append("")
            lines.append(f"**Verification confidence:** {conf_label}")
            lines.append("")
            lines.append(f"- [{'x' if build else ' '}] Build passes")
            if tests_skip:
                lines.append("- [ ] Tests _(no test suite found)_")
            else:
                lines.append(f"- [{'x' if tests else ' '}] Tests pass")

            before = result.get("issues_before", 0)
            after = result.get("issues_after", 0)
            reduced = before - after
            lines.append(f"- [x] Snyk re-scan: {before} → {after} issues ({reduced} fixed)")
            lines.append("")

            fixes = result.get("fixes_applied", [])
            breaking = result.get("breaking_changes", [])

            override_pkg_names = {
                b["package"] for b in breaking if b.get("fix_type") == "transitive_override"
            }
            direct_fixes = [f for f in fixes if f.get("package") not in override_pkg_names]
            override_fixes = [f for f in fixes if f.get("package") in override_pkg_names]

            if direct_fixes:
                lines.append("### Direct Dependency Upgrades")
                lines.append("")
                lines.append("| Package | From | To | Risk | CVE / Snyk ID | Reasoning |")
                lines.append("|---------|------|----|------|---------------|-----------|")
                direct_impact_map = {
                    b["package"]: b for b in breaking if b.get("fix_type") != "transitive_override"
                }
                for fix in direct_fixes:
                    pkg = fix.get("package", "")
                    from_v = fix.get("from", "")
                    to_v = fix.get("to", "")
                    fix_risk = classify_upgrade_risk(from_v, to_v)
                    reasoning = fix.get("reasoning", "").replace("|", "\\|").replace("\n", " ")
                    impact = direct_impact_map.get(pkg, {})
                    cve = impact.get("cve", "") or ""
                    snyk_id = impact.get("snyk_id", "") or ""
                    id_cell = cve if cve else (snyk_id if snyk_id else "—")
                    lines.append(f"| `{pkg}` | {from_v} | {to_v} | {fix_risk} | {id_cell} | {reasoning} |")
                lines.append("")

            if override_fixes:
                lines.append("### Transitive Dependency Overrides")
                lines.append("")
                lines.append(
                    "> **Scope note:** `overrides` pin the vulnerable version only in this "
                    "repo's install tree. They do not affect published packages or other consumers. "
                    "See upstream fix recommendations below for a permanent solution."
                )
                lines.append("")

                override_impact_map = {
                    b["package"]: b for b in breaking if b.get("fix_type") == "transitive_override"
                }
                for fix in override_fixes:
                    pkg = fix.get("package", "")
                    from_v = fix.get("from", "")
                    to_v = fix.get("to", "")
                    fix_risk = classify_upgrade_risk(from_v, to_v)
                    reasoning = fix.get("reasoning", "")
                    impact = override_impact_map.get(pkg, {})
                    cve = impact.get("cve", "") or ""
                    snyk_id = impact.get("snyk_id", "") or ""
                    severity = impact.get("severity", "") or ""
                    dep_chains = impact.get("dep_chains", [])
                    org_upstream = impact.get("org_upstream_pkgs", [])

                    id_str = f"CVE: {cve}" if cve else (f"Snyk: {snyk_id}" if snyk_id else "")
                    header = f"**`{pkg}`** {from_v} → {to_v} | {fix_risk.upper()} risk"
                    if severity:
                        header += f" | {severity.upper()}"
                    if id_str:
                        header += f" | {id_str}"
                    lines.append(header)
                    lines.append("")

                    if dep_chains:
                        lines.append(f"Dependency chain: `{'` → `'.join(dep_chains[0])}`")
                        if len(dep_chains) > 1:
                            lines.append(f"_(+{len(dep_chains) - 1} additional paths)_")
                    if org_upstream:
                        lines.append(
                            f"⚠️ **Upstream fix available:** `{org_upstream[0]}` is an org-owned "
                            f"package in this chain — upgrading `{pkg}` in `{org_upstream[0]}` and "
                            f"publishing a new version would cascade this fix to all dependent repos."
                        )
                    if reasoning:
                        lines.append(f"**LLM reasoning:** {reasoning}")
                    lines.append("")

            direct_impacts = [b for b in breaking if b.get("fix_type") != "transitive_override" and b.get("analysis")]
            if direct_impacts:
                lines.append("### Breaking Change Analysis")
                lines.append("")
                for b in direct_impacts:
                    pkg = b.get("package", "")
                    files = ", ".join(f"`{f}`" for f in b.get("imported_in", []))
                    analysis = b.get("analysis", "")
                    changelog = b.get("changelog_available", False)

                    lines.append(f"**{pkg}** ({b.get('from', '?')} → {b.get('to', '?')})")
                    if files:
                        lines.append(f"- Imported in: {files}")
                    lines.append(f"- Changelog fetched: {'Yes' if changelog else 'No'}")
                    if analysis:
                        lines.append(f"- **LLM Analysis:** {analysis}")
                    lines.append("")

            override_impacts = [b for b in breaking if b.get("fix_type") == "transitive_override" and b.get("analysis")]
            if override_impacts:
                lines.append("### Override Safety Analysis")
                lines.append("")
                for b in override_impacts:
                    pkg = b.get("package", "")
                    analysis = b.get("analysis", "")
                    version_jump = b.get("version_jump", "")
                    changelog = b.get("changelog_available", False)

                    lines.append(f"**{pkg}** ({b.get('from', '?')} → {b.get('to', '?')}) — {version_jump} jump")
                    lines.append(f"- Changelog fetched: {'Yes' if changelog else 'No'}")
                    if analysis:
                        lines.append(f"- **LLM Assessment:** {analysis}")
                    lines.append("")

            all_org_upstream = []
            for b in breaking:
                if b.get("fix_type") == "transitive_override":
                    for org_pkg in b.get("org_upstream_pkgs", [])[:1]:
                        all_org_upstream.append((org_pkg, b.get("package", "")))

            if all_org_upstream:
                lines.append("### Upstream Fix Recommendations")
                lines.append("")
                lines.append(
                    "The following org-owned packages appear in the transitive dep chains. "
                    "Fixing the vulnerability at source eliminates the need for overrides across all "
                    "repos that depend on these packages:"
                )
                lines.append("")
                seen_org: set[str] = set()
                for org_pkg, vuln_pkg in all_org_upstream:
                    if org_pkg not in seen_org:
                        lines.append(f"- **`{org_pkg}`** — upgrade `{vuln_pkg}` in this package and publish a new version")
                        seen_org.add(org_pkg)
                lines.append("")

            unfixable = result.get("unfixable", [])
            if unfixable:
                lines.append("### Not Fixed")
                lines.append("")
                for uf in unfixable:
                    lines.append(f"- **{uf.get('package', '?')}**: {uf.get('reason', '')}")
                lines.append("")

            lines.append("---")
            lines.append("")

        if queued:
            lines.append("## Queued for Next Run (by priority)")
            lines.append("")
            lines.append("| # | Repo | Issues | Top Severity | SLA Remaining |")
            lines.append("|---|------|--------|-------------|---------------|")
            for i, q in enumerate(queued, 1):
                lines.append(
                    f"| {i} | {q.get('name', q.get('repo', '?'))} | {q['issue_count']} | "
                    f"{q['top_severity'].capitalize()} | {q['sla_days_remaining']}d |"
                )
            lines.append("")

        if clean_count > 0:
            lines.append(f"## Clean Repos: {clean_count} repos with no open Snyk issues")
            lines.append("")

        llm_providers = set(r.get("llm_provider", "") for r in results if r.get("llm_provider"))
        provider_str = ", ".join(llm_providers) if llm_providers else "none"
        lines.append("---")
        lines.append(f"*Generated by SnykrAI | Run #{run_number} | LLM: {provider_str}*")

        return "\n".join(lines)
