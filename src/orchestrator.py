import argparse
import json
import logging
import os
import tempfile
from datetime import datetime, timezone

import yaml

from src.snyk_client import SnykClient
from src.llm_client import LLMClient
from src.git_ops import GitOps
from src.snyk_fixer import SnykFixer
from src.report_generator import ReportGenerator
from src.org_analyzer import OrgAnalyzer, OrgAnalysis

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


class Orchestrator:
    def __init__(self, config_path: str = "config.yaml"):
        with open(config_path) as f:
            self.config = yaml.safe_load(f)

        org_id = os.environ.get("SNYK_ORG_ID") or self.config["snyk"]["org_id"]
        org_prefix = os.environ.get("GIT_ORG") or self.config["git"].get("org", "")
        self.snyk_client = SnykClient(
            token=os.environ.get("SNYK_TOKEN", ""),
            org_id=org_id,
            api_version=self.config["snyk"].get("api_version", "2024-04-29"),
            org_prefix=org_prefix,
        )

        llm_cfg = self.config["llm"]
        self.llm_client = LLMClient(
            provider=llm_cfg["provider"],
            gemini_api_key=os.environ.get("GEMINI_API_KEY", ""),
            anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
            gemini_model=os.environ.get("GEMINI_MODEL") or llm_cfg.get("gemini_model", "gemini-2.5-flash"),
            anthropic_model=os.environ.get("ANTHROPIC_MODEL") or llm_cfg.get("anthropic_model", "claude-sonnet-4-6"),
            max_retries=llm_cfg.get("max_retries", 2),
            timeout_seconds=llm_cfg.get("timeout_seconds", 30),
        )

        git_cfg = self.config["git"]
        self.git_ops = GitOps(
            git_token=os.environ.get("GIT_TOKEN", ""),
            git_user=os.environ.get("GIT_USER", ""),
            commit_author_name=git_cfg.get("commit_author_name", "Snyk Auto-Fix"),
            commit_author_email=os.environ.get("GIT_AUTHOR_EMAIL") or git_cfg.get("commit_author_email", "snykrai-bot@users.noreply.github.com"),
            branch_prefix=git_cfg.get("branch_prefix", "snyk-fix"),
        )

    def run(
        self,
        target: str = "all",
        strategy_override: str = "",
        max_repos_override: int = 0,
        results_dir: str = "results",
        trigger_source: str = "cron",
        trigger_user: str = "",
    ) -> None:
        os.makedirs(results_dir, exist_ok=True)
        internal_dir = os.path.join(os.path.dirname(results_dir), "_internal")
        os.makedirs(internal_dir, exist_ok=True)

        orch_cfg = self.config.get("orchestrator", {})
        max_repos = max_repos_override or orch_cfg.get("max_repos_per_run", 5)
        always_aggressive = orch_cfg.get("always_include_aggressive", True)
        config_repos = self.config.get("repos", [])
        sla = self.config.get("sla", {"critical": 14, "high": 30, "medium": 60, "low": 180})

        if target != "all":
            self._run_single(target, strategy_override, results_dir, internal_dir)
            return

        logger.info("Fetching all org issues via Snyk API...")
        all_issues, all_projects = self.snyk_client.get_all_org_issues()
        logger.info(f"Found issues in {len(all_issues)} projects")

        # Phase 0: Org-wide cascade analysis
        logger.info("Running org-wide cascade analysis (Phase 0)...")
        org_prefix = os.environ.get("GIT_ORG") or self.config["git"].get("org", "")
        org_analyzer = OrgAnalyzer(self.snyk_client, config_repos, org_prefix=org_prefix)
        org_analysis = org_analyzer.analyze(all_issues)
        analysis_path = os.path.join(results_dir, "org_analysis.json")
        with open(analysis_path, "w") as f:
            json.dump(org_analysis.to_dict(), f, indent=2, default=str)
        logger.info(
            f"Cascade plan: {org_analysis.upstream_fix_count} upstream fix(es) "
            f"→ {org_analysis.downstream_impact_count} downstream repos benefit | "
            f"{len(org_analysis.cascade_entries)} package(s) in chains"
        )

        # Build cascade_context lookup: repo_name → cascade_context dict
        cascade_context_map: dict[str, dict] = {
            entry.repo_name: entry.cascade_context
            for entry in org_analysis.fix_queue
            if entry.cascade_context
        }

        scored = self._score_repos(all_issues, sla)
        selected, queued = self._select_repos(scored, config_repos, max_repos, always_aggressive)

        logger.info(f"Selected {len(selected)} repos for processing, {len(queued)} queued")

        results = []
        for repo_info in selected:
            result = self._process_repo(
                repo_info, strategy_override, results_dir, internal_dir,
                cascade_context=cascade_context_map.get(repo_info["name"]),
            )
            results.append(result)

        clean_count = self._count_clean_repos(all_issues, all_projects)

        report_gen = ReportGenerator()
        report = report_gen.generate(
            results=results,
            queued=queued,
            clean_count=clean_count,
            run_number=int(os.environ.get("RUN_NUMBER", "0")),
            trigger_source=trigger_source,
            trigger_user=trigger_user,
            org_analysis=org_analysis.to_dict(),
        )
        report_path = os.path.join(internal_dir, "fix_report.md")
        with open(report_path, "w") as f:
            f.write(report)

        summary = {
            "results": results,
            "queued": queued,
            "clean_count": clean_count,
            "report_path": report_path,
            "trigger_source": trigger_source,
            "trigger_user": trigger_user,
            "cascade_analysis": {
                "upstream_fixes": org_analysis.upstream_fix_count,
                "downstream_impacted": org_analysis.downstream_impact_count,
                "total_transitive": org_analysis.total_transitive_issues,
            },
        }
        with open(os.path.join(results_dir, "summary.json"), "w") as f:
            json.dump(summary, f, indent=2, default=str)

        logger.info(f"Done. Report: {report_path}")

    def _run_single(self, target: str, strategy_override: str, results_dir: str, internal_dir: str) -> None:
        config_repos = self.config.get("repos", [])
        repo_config = next((r for r in config_repos if r["name"] == target or r["repo"].endswith(f"/{target}")), None)
        if repo_config is None:
            git_org = os.environ.get("GIT_ORG") or self.config["git"]["org"]
            repo_config = {
                "name": target,
                "repo": f"{git_org}/{target}",
                "ecosystem": "npm",
                "default_branch": "main",
                "strategy": strategy_override or "conservative",
                "visibility": "public",
            }
        if strategy_override:
            repo_config = {**repo_config, "strategy": strategy_override}

        projects = self.snyk_client.list_projects()
        dep_types = {"npm", "maven", "pip", "gomodules", "yarn", "nuget", "rubygems", "cocoapods", "gradle"}
        snyk_proj = next(
            (p for p in projects
             if (f"/{target}:" in p["attributes"]["name"]
                 or p["attributes"]["name"].endswith(f"/{target}"))
             and p["attributes"].get("type", "").lower() in dep_types),
            None,
        )
        if snyk_proj:
            repo_config["snyk_project_id"] = snyk_proj["id"]
            proj_type = snyk_proj["attributes"].get("type", "").lower()
            if proj_type and repo_config.get("ecosystem") == "npm":
                repo_config["ecosystem"] = proj_type

        result = self._process_repo_config(repo_config, results_dir, internal_dir)

        report_gen = ReportGenerator()
        report = report_gen.generate(
            results=[result], queued=[], clean_count=0,
            run_number=int(os.environ.get("RUN_NUMBER", "0")),
            trigger_source="manual", trigger_user="",
        )
        report_path = os.path.join(internal_dir, "fix_report.md")
        with open(report_path, "w") as f:
            f.write(report)

        summary = {"results": [result], "report_path": report_path}
        with open(os.path.join(results_dir, "summary.json"), "w") as f:
            json.dump(summary, f, indent=2, default=str)

    def _process_repo(
        self,
        repo_info: dict,
        strategy_override: str,
        results_dir: str,
        internal_dir: str,
        cascade_context: "dict | None" = None,
    ) -> dict:
        config_repos = self.config.get("repos", [])
        git_org = os.environ.get("GIT_ORG") or self.config["git"]["org"]
        repo_config = next(
            (r for r in config_repos if r["name"] == repo_info["name"]),
            {
                "name": repo_info["name"],
                "repo": f"{git_org}/{repo_info['name']}",
                "ecosystem": repo_info.get("ecosystem", "npm"),
                "default_branch": "main",
                "strategy": "conservative",
                "visibility": "public",
            },
        )
        repo_config["snyk_project_id"] = repo_info["project_id"]
        if strategy_override:
            repo_config = {**repo_config, "strategy": strategy_override}
        return self._process_repo_config(repo_config, results_dir, internal_dir, cascade_context)

    def _process_repo_config(
        self,
        repo_config: dict,
        results_dir: str,
        internal_dir: str,
        cascade_context: "dict | None" = None,
    ) -> dict:
        work_dir = tempfile.mkdtemp(prefix=f"snyk-fix-{repo_config['name']}-")
        logger.info(f"Processing {repo_config['repo']} (strategy={repo_config['strategy']})")
        try:
            fixer = SnykFixer(
                repo_config=repo_config,
                snyk_client=self.snyk_client,
                llm_client=self.llm_client,
                git_ops=self.git_ops,
            )
            result = fixer.run(work_dir, cascade_context=cascade_context)
            result_dict = result.to_dict()
        except Exception:
            import traceback
            tb = traceback.format_exc()
            logger.error(f"Unhandled error processing {repo_config['name']}:\n{tb}")
            result_dict = {
                "repo": repo_config["repo"],
                "name": repo_config["name"],
                "success": False,
                "error": tb,
                "strategy": repo_config.get("strategy", ""),
            }
        result_path = os.path.join(results_dir, f"{repo_config['name']}.json")
        with open(result_path, "w") as f:
            json.dump(result_dict, f, indent=2)
        logger.info(f"  Result: {'SUCCESS' if result_dict.get('success') else 'FAILED'} — {(result_dict.get('pr_url') or result_dict.get('error') or 'no action')[:200]}")
        return result_dict

    @staticmethod
    def _score_repos(all_issues: dict, sla: dict) -> list[dict]:
        severity_scores = {"critical": 100, "high": 50, "medium": 10, "low": 1}
        now = datetime.now(timezone.utc)
        scored = []
        for proj_id, proj_data in all_issues.items():
            total_score = 0
            issue_count = len(proj_data["issues"])
            top_severity = "low"
            min_sla_remaining = 999
            for issue in proj_data["issues"]:
                sev = issue.get("severity", "low")
                base_score = severity_scores.get(sev, 1)
                created = issue.get("created_at", "")
                if created:
                    try:
                        created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                        days_open = (now - created_dt).days
                        sla_days = sla.get(sev, 180)
                        remaining = sla_days - days_open
                        min_sla_remaining = min(min_sla_remaining, remaining)
                        if remaining < 3:
                            base_score *= 5
                        elif remaining < 7:
                            base_score *= 3
                        elif remaining < 14:
                            base_score *= 2
                    except (ValueError, TypeError):
                        pass
                total_score += base_score
                sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
                if sev_rank.get(sev, 0) > sev_rank.get(top_severity, 0):
                    top_severity = sev
            repo_name = proj_data["name"].split(":")[0].split("/")[-1] if "/" in proj_data["name"] else proj_data["name"]
            scored.append({
                "project_id": proj_id,
                "name": repo_name,
                "score": total_score,
                "issue_count": issue_count,
                "top_severity": top_severity,
                "sla_days_remaining": max(0, min_sla_remaining),
            })
        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored

    @staticmethod
    def _select_repos(
        scored: list[dict],
        config_repos: list[dict],
        max_repos: int,
        always_include_aggressive: bool,
    ) -> tuple[list[dict], list[dict]]:
        aggressive_names = {r["name"] for r in config_repos if r.get("strategy") == "aggressive"}
        selected = []
        remaining = []

        if always_include_aggressive:
            for item in scored:
                if item["name"] in aggressive_names:
                    selected.append(item)
                else:
                    remaining.append(item)
        else:
            remaining = list(scored)

        selected.extend(remaining[:max_repos])
        queued = remaining[max_repos:]

        return selected, queued

    @staticmethod
    def _count_clean_repos(all_issues: dict, all_projects: list[dict]) -> int:
        dep_types = {"npm", "maven", "pip", "gomodules", "yarn", "nuget", "rubygems", "cocoapods", "gradle"}
        total_dep_projects = sum(
            1 for p in all_projects
            if p.get("attributes", {}).get("type", "").lower() in dep_types
        )
        return max(0, total_dep_projects - len(all_issues))


def main():
    parser = argparse.ArgumentParser(description="Snyk Auto-Fix Orchestrator")
    parser.add_argument("--target", default="all", help="Repo name or 'all'")
    parser.add_argument("--strategy-override", default="", help="Override fix strategy")
    parser.add_argument("--max-repos", type=int, default=0, help="Override max repos per run")
    parser.add_argument("--results-dir", default="results", help="Directory for result artifacts")
    parser.add_argument("--trigger-source", default="cron", help="Trigger source: cron or slack")
    parser.add_argument("--trigger-user", default="", help="User who triggered the run")
    args = parser.parse_args()

    orch = Orchestrator()
    orch.run(
        target=args.target,
        strategy_override=args.strategy_override,
        max_repos_override=args.max_repos,
        results_dir=args.results_dir,
        trigger_source=args.trigger_source,
        trigger_user=args.trigger_user,
    )


if __name__ == "__main__":
    main()
