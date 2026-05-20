import logging
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

logger = logging.getLogger(__name__)

# Max seconds to spend fetching dep chains across the whole org.
CHAIN_FETCH_DEADLINE_SECONDS = 90
CHAIN_FETCH_DELAY = 0.3


@dataclass
class CascadeEntry:
    """One org-owned upstream package whose fix would cascade to downstream repos."""
    org_package_name: str
    upstream_repo_name: Optional[str]
    vuln_package: str
    vuln_issue_ids: list[str] = field(default_factory=list)
    downstream_repos: list[str] = field(default_factory=list)
    downstream_count: int = 0
    fixed_in_version: str = ""
    severity: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FixQueueEntry:
    """One repo in the cascade-aware fix queue."""
    repo_name: str
    project_id: str
    role: str           # "upstream_fix" | "downstream_override" | "sla_priority"
    score: float = 0.0
    cascade_context: Optional[dict] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class OrgAnalysis:
    """Full org-wide cascade analysis result."""
    cascade_entries: list[CascadeEntry] = field(default_factory=list)
    override_only_repos: list[str] = field(default_factory=list)
    fix_queue: list[FixQueueEntry] = field(default_factory=list)
    total_transitive_issues: int = 0
    upstream_fix_count: int = 0
    downstream_impact_count: int = 0
    analysis_duration_seconds: float = 0.0
    fallback_used: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


class OrgAnalyzer:
    """Org-wide cascade analysis (Phase 0 of the fix pipeline).

    Runs before per-repo processing to:
    1. Find all transitive vulnerabilities across the org
    2. Fetch dep chains to identify org-owned upstream packages
    3. Build a cascade map: org upstream package → downstream repos
    4. Output a fix queue: upstream_fix first, downstream_override second, sla_priority last
    """

    def __init__(self, snyk_client, config_repos: list[dict], org_prefix: str = ""):
        self.snyk_client = snyk_client
        self.config_repos = config_repos
        self.org_prefix = org_prefix
        self._name_to_config: dict[str, dict] = {r["name"]: r for r in config_repos}
        self._project_to_repo: dict[str, str] = {}

    def analyze(self, all_issues: dict) -> OrgAnalysis:
        """Run org-wide cascade analysis.

        Args:
            all_issues: output of snyk_client.get_all_org_issues()
                        {project_id: {"name": "org/repo:manifest", "issues": [...]}}
        """
        start = time.monotonic()

        self._build_project_to_repo(all_issues)
        transitive_map = self._find_transitive_issues(all_issues)

        total_transitive = sum(len(v) for v in transitive_map.values())
        logger.info(
            f"[OrgAnalyzer] {total_transitive} transitive issues across "
            f"{len(transitive_map)} projects"
        )

        deadline = start + CHAIN_FETCH_DEADLINE_SECONDS
        chains_map = self._fetch_dep_chains_batched(transitive_map, deadline)
        fallback_used = time.monotonic() >= deadline

        cascade_map = self._build_cascade_map(transitive_map, chains_map)
        scored_repos = self._score_repos_for_cascade(all_issues)
        fix_queue = self._build_fix_queue(cascade_map, scored_repos, all_issues)

        # Repos with transitive issues but no org upstream → override-only
        cascade_downstream = {
            repo
            for data in cascade_map.values()
            for repo in data["downstream_repos"]
        }
        override_only_repos = [
            self._project_to_repo.get(pid, pid)
            for pid in transitive_map
            if self._project_to_repo.get(pid, pid) not in cascade_downstream
        ]

        cascade_entries = []
        for org_pkg, data in cascade_map.items():
            cascade_entries.append(CascadeEntry(
                org_package_name=org_pkg,
                upstream_repo_name=data.get("upstream_repo_name"),
                vuln_package=data.get("vuln_package", ""),
                vuln_issue_ids=data.get("vuln_issue_ids", []),
                downstream_repos=data.get("downstream_repos", []),
                downstream_count=len(data.get("downstream_repos", [])),
                fixed_in_version=data.get("fixed_in_version", ""),
                severity=data.get("severity", ""),
            ))
        cascade_entries.sort(key=lambda e: e.downstream_count, reverse=True)

        duration = round(time.monotonic() - start, 2)
        logger.info(
            f"[OrgAnalyzer] Done in {duration}s — "
            f"{len(cascade_entries)} cascade entries, "
            f"{len(fix_queue)} repos in fix queue"
        )

        return OrgAnalysis(
            cascade_entries=cascade_entries,
            override_only_repos=override_only_repos,
            fix_queue=fix_queue,
            total_transitive_issues=total_transitive,
            upstream_fix_count=sum(1 for e in fix_queue if e.role == "upstream_fix"),
            downstream_impact_count=sum(1 for e in fix_queue if e.role == "downstream_override"),
            analysis_duration_seconds=duration,
            fallback_used=fallback_used,
        )

    def _build_project_to_repo(self, all_issues: dict) -> None:
        """Map project_id → config repo name.

        Snyk project names follow "org/repo:manifest" format.
        """
        config_names = {r["name"] for r in self.config_repos}
        for proj_id, proj_data in all_issues.items():
            proj_name = proj_data.get("name", "")
            slug = proj_name.split(":")[0].split("/")[-1]
            if slug in config_names:
                self._project_to_repo[proj_id] = slug
            else:
                match = next(
                    (name for name in config_names if slug and (slug in name or name in slug)),
                    slug,
                )
                self._project_to_repo[proj_id] = match

    def _find_transitive_issues(self, all_issues: dict) -> dict[str, list[dict]]:
        """Return project_id → list of transitive issues that have a fixed_in version."""
        result: dict[str, list[dict]] = {}
        for proj_id, proj_data in all_issues.items():
            transitive = [
                issue for issue in proj_data.get("issues", [])
                if not issue.get("is_direct") and issue.get("fixed_in")
            ]
            if transitive:
                result[proj_id] = transitive
        return result

    def _fetch_dep_chains_batched(
        self, transitive_map: dict[str, list[dict]], deadline: float
    ) -> dict[tuple[str, str], list[list[str]]]:
        """Fetch dep chains for transitive issues, stopping at deadline.

        Prioritises critical > high > medium > low so the most important
        chains are fetched first if we hit the deadline early.
        """
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        candidates = []
        for proj_id, issues in transitive_map.items():
            for issue in issues:
                sev = issue.get("severity", "low")
                candidates.append((severity_order.get(sev, 3), proj_id, issue))
        candidates.sort(key=lambda x: x[0])

        result: dict[tuple[str, str], list[list[str]]] = {}
        for _, proj_id, issue in candidates:
            if time.monotonic() >= deadline:
                logger.warning(
                    f"[OrgAnalyzer] Chain fetch deadline reached after {len(result)} calls "
                    f"— using partial results ({len(candidates) - len(result)} skipped)"
                )
                break
            issue_id = issue.get("id", "")
            if not issue_id:
                continue
            try:
                chains = self.snyk_client.get_issue_dep_chains(proj_id, issue_id)
                result[(proj_id, issue_id)] = chains
            except Exception as e:
                logger.warning(f"[OrgAnalyzer] Chain fetch failed {proj_id}/{issue_id}: {e}")
                result[(proj_id, issue_id)] = []
            time.sleep(CHAIN_FETCH_DELAY)

        logger.info(f"[OrgAnalyzer] Fetched chains for {len(result)}/{len(candidates)} issues")
        return result

    def _build_cascade_map(
        self,
        transitive_map: dict[str, list[dict]],
        chains_map: dict[tuple[str, str], list[list[str]]],
    ) -> dict[str, dict]:
        """Group transitive issues by org-owned upstream package.

        Returns: org_package_name → {
            vuln_package, vuln_issue_ids, downstream_repos,
            fixed_in_version, severity, upstream_repo_name
        }
        """
        repo_names = {r["name"] for r in self.config_repos}
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        cascade: dict[str, dict] = {}

        for proj_id, issues in transitive_map.items():
            repo_name = self._project_to_repo.get(proj_id, proj_id)
            for issue in issues:
                issue_id = issue.get("id", "")
                chains = chains_map.get((proj_id, issue_id), [])
                org_pkgs = self.snyk_client.find_org_packages_in_chains(chains, repo_names)
                for org_pkg in org_pkgs:
                    if org_pkg not in cascade:
                        cascade[org_pkg] = {
                            "vuln_package": issue.get("package_name", ""),
                            "vuln_issue_ids": [],
                            "downstream_repos": [],
                            "fixed_in_version": issue.get("fixed_in", ""),
                            "severity": issue.get("severity", "low"),
                            "upstream_repo_name": self._resolve_org_package_to_repo(org_pkg),
                        }
                    entry = cascade[org_pkg]
                    if issue_id and issue_id not in entry["vuln_issue_ids"]:
                        entry["vuln_issue_ids"].append(issue_id)
                    if repo_name not in entry["downstream_repos"]:
                        entry["downstream_repos"].append(repo_name)
                    # Escalate to worst seen severity
                    if sev_rank.get(issue.get("severity", "low"), 1) > sev_rank.get(entry["severity"], 1):
                        entry["severity"] = issue.get("severity", "low")

        return cascade

    def _resolve_org_package_to_repo(self, pkg_name: str) -> Optional[str]:
        """Map an org-scoped npm package name to a config.yaml repo name.

        Pass 1: exact match on optional `npm_package_name` field.
        Pass 2: slug normalisation — "@my-org/app-sdk" → "app-sdk"
                compared against repo names with org prefix stripped.
        """
        for repo in self.config_repos:
            if repo.get("npm_package_name") == pkg_name:
                return repo["name"]

        slug = pkg_name.lstrip("@").split("/")[-1].lower()
        org_strip = f"{self.org_prefix}-" if self.org_prefix else ""
        candidates = []
        for repo in self.config_repos:
            repo_slug = repo["name"].lower()
            if org_strip:
                repo_slug = repo_slug.replace(org_strip, "")
            repo_slug = repo_slug.replace("_", "-")
            if slug == repo_slug or slug in repo_slug or repo_slug in slug:
                candidates.append(repo["name"])
        return min(candidates, key=len) if candidates else None

    def _score_repos_for_cascade(self, all_issues: dict) -> dict[str, float]:
        """Severity-weighted score per repo for ordering within each role tier."""
        severity_scores = {"critical": 100, "high": 50, "medium": 10, "low": 1}
        scores: dict[str, float] = {}
        for proj_id, proj_data in all_issues.items():
            repo_name = self._project_to_repo.get(proj_id, proj_id)
            score = sum(
                severity_scores.get(i.get("severity", "low"), 1)
                for i in proj_data.get("issues", [])
            )
            scores[repo_name] = scores.get(repo_name, 0) + score
        return scores

    def _build_fix_queue(
        self,
        cascade_map: dict[str, dict],
        scored_repos: dict[str, float],
        all_issues: dict,
    ) -> list[FixQueueEntry]:
        """Priority queue: upstream_fix → downstream_override → sla_priority.

        upstream_fix:       Org-owned repos needing a real dep bump (cascades downstream)
        downstream_override: Repos that get override band-aids while upstream fixes
        sla_priority:       Everything else with open issues, sorted by severity score
        """
        queue: list[FixQueueEntry] = []
        seen: set[str] = set()
        proj_by_repo: dict[str, str] = {v: k for k, v in self._project_to_repo.items()}

        # 1. Upstream fix entries
        for org_pkg, data in cascade_map.items():
            upstream_name = data.get("upstream_repo_name")
            if not upstream_name or upstream_name in seen:
                continue
            seen.add(upstream_name)
            queue.append(FixQueueEntry(
                repo_name=upstream_name,
                project_id=proj_by_repo.get(upstream_name, ""),
                role="upstream_fix",
                score=scored_repos.get(upstream_name, 0) + 10000,
                cascade_context={
                    "org_package": org_pkg,
                    "vuln_package": data["vuln_package"],
                    "downstream_repos": data["downstream_repos"],
                    "downstream_count": len(data["downstream_repos"]),
                    "fixed_in_version": data["fixed_in_version"],
                    "severity": data["severity"],
                },
            ))

        # 2. Downstream override entries
        for org_pkg, data in cascade_map.items():
            for repo_name in data["downstream_repos"]:
                if repo_name in seen:
                    continue
                seen.add(repo_name)
                queue.append(FixQueueEntry(
                    repo_name=repo_name,
                    project_id=proj_by_repo.get(repo_name, ""),
                    role="downstream_override",
                    score=scored_repos.get(repo_name, 0) + 1000,
                    cascade_context={
                        "org_package": org_pkg,
                        "upstream_repo_name": data.get("upstream_repo_name"),
                        "vuln_package": data["vuln_package"],
                        "fixed_in_version": data["fixed_in_version"],
                    },
                ))

        # 3. SLA-priority entries (direct issues only, no cascade involvement)
        for proj_id, proj_data in all_issues.items():
            repo_name = self._project_to_repo.get(proj_id, proj_id)
            if repo_name in seen or not proj_data.get("issues"):
                continue
            seen.add(repo_name)
            queue.append(FixQueueEntry(
                repo_name=repo_name,
                project_id=proj_id,
                role="sla_priority",
                score=scored_repos.get(repo_name, 0),
            ))

        role_order = {"upstream_fix": 0, "downstream_override": 1, "sla_priority": 2}
        queue.sort(key=lambda e: (role_order.get(e.role, 9), -e.score))
        return queue
