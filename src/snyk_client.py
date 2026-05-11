import logging
import time
import requests
from typing import Optional

logger = logging.getLogger(__name__)

# Retry settings
MAX_RETRIES = 3
RETRY_BACKOFF = 2  # exponential: 2s, 4s, 8s
RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class SnykClient:
    BASE_URL = "https://api.snyk.io"

    def __init__(
        self,
        token: str,
        org_id: str,
        org_slug: str = "",
        api_version: str = "2024-10-15",
        org_prefix: str = "",
    ):
        self.token = token
        self.org_id = org_id
        self.org_slug = org_slug
        self.api_version = api_version
        # org_prefix: your GitHub org name (e.g. "my-org"). Used to identify
        # org-owned packages in transitive dep chains.
        self.org_prefix = org_prefix
        self._auth_header = {"Authorization": f"token {token}"}
        # v1 endpoints use application/json
        self.headers = {
            **self._auth_header,
            "Content-Type": "application/json",
        }
        # REST endpoints require application/vnd.api+json per Snyk docs
        self._rest_headers = {
            **self._auth_header,
            "Content-Type": "application/vnd.api+json",
        }

    def _request_with_retry(self, method: str, url: str, headers: dict, **kwargs) -> requests.Response:
        """HTTP request with retry + exponential backoff for rate limits and server errors."""
        for attempt in range(MAX_RETRIES + 1):
            resp = requests.request(method, url, headers=headers, **kwargs)
            if resp.status_code not in RETRYABLE_STATUS:
                return resp
            # Honor Retry-After header (rate limit)
            wait = int(resp.headers.get("Retry-After", RETRY_BACKOFF ** (attempt + 1)))
            logger.warning(
                f"API {resp.status_code} on {method} {url.split('?')[0]} — "
                f"retry {attempt + 1}/{MAX_RETRIES} in {wait}s"
            )
            time.sleep(wait)
        return resp  # return last response after all retries

    def _get(self, path: str, params: Optional[dict] = None) -> dict:
        url = f"{self.BASE_URL}{path}"
        if params is None:
            params = {}
        if "version" not in path:
            params["version"] = self.api_version
        is_rest = "/rest/" in path
        resp = self._request_with_retry(
            "GET", url,
            headers=self._rest_headers if is_rest else self.headers,
            params=params, timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def list_projects(self) -> list[dict]:
        projects = []
        path = f"/rest/orgs/{self.org_id}/projects"
        params = {"limit": 100}
        while path:
            data = self._get(path, params)
            projects.extend(data.get("data", []))
            next_link = data.get("links", {}).get("next")
            if next_link:
                path = next_link
                params = {}
            else:
                path = None
        return projects

    def get_dep_graph(self, project_id: str) -> set[str]:
        """Return set of direct dependency 'name@version' pairs from the dep graph."""
        url = f"{self.BASE_URL}/v1/org/{self.org_id}/project/{project_id}/dep-graph"
        resp = self._request_with_retry("GET", url, headers=self.headers, timeout=30)
        if resp.status_code != 200:
            return set()
        data = resp.json()
        graph = data.get("depGraph") or {}

        # Find root node and its direct dep node IDs (format: "name@version")
        graph_data = graph.get("graph") or {}
        root_id = graph_data.get("rootNodeId", "root-node")
        direct = set()
        for node in graph_data.get("nodes") or []:
            if node.get("nodeId") == root_id:
                for dep in node.get("deps", []):
                    node_id = dep.get("nodeId", "")
                    # Strip Maven qualifier suffix (e.g., "jackson-core@2.18.6|2" → "jackson-core@2.18.6")
                    if "|" in node_id:
                        node_id = node_id.rsplit("|", 1)[0]
                    direct.add(node_id)
                break
        return direct

    def get_issues(self, project_id: str) -> list[dict]:
        """Fetch issues using v1 aggregated-issues API (same as Snyk UI).

        This endpoint returns fixedIn versions, semver ranges, and better
        fixability data than the REST API.
        """
        url = f"{self.BASE_URL}/v1/org/{self.org_id}/project/{project_id}/aggregated-issues"
        body = {
            "includeDescription": False,
            "includeIntroducedThrough": True,
            "filters": {
                "severities": ["critical", "high", "medium", "low"],
                "types": ["vuln"],
                "ignored": False,
                "patched": False,
            },
        }
        resp = self._request_with_retry("POST", url, headers=self.headers, json=body, timeout=30)
        resp.raise_for_status()
        raw_issues = resp.json().get("issues", [])

        # Enrich with dep graph to detect truly direct dependencies
        direct_deps = self.get_dep_graph(project_id)
        parsed = []
        for issue in raw_issues:
            p = self._parse_issue_v1(issue)
            if not p["package_name"]:
                continue
            pkg_key = f"{p['package_name']}@{p['package_version']}"
            if pkg_key in direct_deps:
                p["is_direct"] = True
                p["is_upgradeable"] = True
            else:
                p["is_direct"] = False
            parsed.append(p)
        return parsed

    def get_all_org_issues(self, inter_call_delay: float = 0.2) -> tuple[dict, list[dict]]:
        """Fetch all org issues. Returns (issues_by_project_id, all_projects).

        inter_call_delay: seconds between per-project API calls to avoid rate-limiting.
        Both values are returned so callers can compute accurate clean-repo counts.
        """
        projects = self.list_projects()
        result = {}
        for i, proj in enumerate(projects):
            proj_id = proj["id"]
            proj_name = proj["attributes"]["name"]
            proj_type = proj["attributes"].get("type", "unknown")
            issues = self.get_issues(proj_id)
            if issues:
                result[proj_id] = {
                    "name": proj_name,
                    "type": proj_type,
                    "issues": issues,
                }
            if i < len(projects) - 1:
                time.sleep(inter_call_delay)
        return result, projects

    def get_code_issues(self, project_id: str) -> list[dict]:
        """Fetch Code Analysis (SAST) issues for a project via REST API.

        Only returns issues with status='open'. Resolved/fixed issues are
        excluded to ensure consistent counts across runs.
        """
        path = f"/rest/orgs/{self.org_id}/issues"
        params = {
            "scan_item.id": project_id,
            "scan_item.type": "project",
            "type": "code",
            "status": "open",
            "limit": 100,
        }
        issues = []
        while path:
            data = self._get(path, params)
            for item in data.get("data", []):
                issues.append(self._parse_code_issue(item))
            next_link = (data.get("links") or {}).get("next")
            if next_link:
                path = next_link
                params = {}
            else:
                path = None
        return issues

    def ignore_issue(
        self,
        project_id: str,
        issue_id: str,
        reason_type: str = "not-vulnerable",
        reason_text: str = "",
        ignore_path: str = "*",
        expires_days: Optional[int] = None,
    ) -> bool:
        """Ignore a dependency issue via v1 API."""
        url = f"{self.BASE_URL}/v1/org/{self.org_id}/project/{project_id}/ignore/{issue_id}"
        body = {
            "reason": reason_text or "AI-validated false positive",
            "reasonType": reason_type,
            "disregardIfFixable": False,
            "ignorePath": ignore_path,
        }
        if expires_days:
            from datetime import datetime, timezone, timedelta
            body["expires"] = (datetime.now(timezone.utc) + timedelta(days=expires_days)).isoformat()
        resp = self._request_with_retry("POST", url, headers=self.headers, json=body, timeout=30)
        if resp.status_code != 200:
            logger.warning(f"Ignore API {resp.status_code} for {issue_id}: {resp.text[:200]}")
        return resp.status_code == 200

    def ignore_code_issue(
        self,
        project_id: str,
        issue_id: str,
        reason_type: str = "not-vulnerable",
        reason_text: str = "",
        file_path: str = "",
        expires_days: int = 90,
        key_asset: str = "",
    ) -> bool:
        """Ignore a code analysis (SAST) issue via Policies API.

        Code/SAST issues require the Policies API (asset-scoped / Consistent
        Ignores) — the v1 project-scoped ignore endpoint only works for
        dependency vulnerabilities.
        """
        if not key_asset:
            logger.warning(
                f"Cannot ignore code issue {issue_id}: key_asset is empty. "
                f"Policies API requires key_asset for SAST findings."
            )
            return False

        return self._ignore_via_policy(key_asset, reason_type, reason_text, expires_days)

    def _ignore_via_policy(
        self,
        key_asset: str,
        reason_type: str = "not-vulnerable",
        reason_text: str = "",
        expires_days: int = 90,
    ) -> bool:
        """Create an asset-scoped ignore via the Policies REST API (Consistent Ignores).

        This is the ONLY method that works for code/SAST findings.
        """
        from datetime import datetime, timezone, timedelta

        # Check for existing policy to avoid duplicates
        try:
            existing = self.list_policies()
        except Exception as e:
            logger.warning(f"Failed to list policies for dedup check: {e}")
            existing = []

        for policy in existing:
            conditions = (policy.get("attributes", {})
                          .get("conditions_group", {})
                          .get("conditions", []))
            for cond in conditions:
                if cond.get("value") == key_asset:
                    logger.info(f"Policy already exists for asset {key_asset}, skipping")
                    return True

        url = f"{self.BASE_URL}/rest/orgs/{self.org_id}/policies?version={self.api_version}"
        action_data = {
            "ignore_type": reason_type,
            "reason": reason_text or "AI-validated false positive",
        }
        if expires_days:
            action_data["expires"] = (
                datetime.now(timezone.utc) + timedelta(days=expires_days)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
        body = {
            "data": {
                "attributes": {
                    "action": {"data": action_data},
                    "action_type": "ignore",
                    "conditions_group": {
                        "conditions": [
                            {
                                "field": "snyk/asset/finding/v1",
                                "operator": "includes",
                                "value": key_asset,
                            }
                        ],
                        "logical_operator": "and",
                    },
                    "name": f"SnykrAI auto-ignore — {reason_text[:80]}" if reason_text else "SnykrAI auto-ignore",
                },
                "type": "policy",
            }
        }
        resp = self._request_with_retry("POST", url, headers=self._rest_headers, json=body, timeout=30)
        if resp.status_code in (200, 201):
            logger.info(f"Policy created for asset {key_asset} (ignore)")
            return True
        logger.error(
            f"Policy API failed {resp.status_code} for asset {key_asset}: {resp.text[:300]}"
        )
        return False

    def verify_ignores_applied(self, project_id: str) -> dict:
        """Re-fetch code issues and return updated counts after auto-ignore."""
        issues = self.get_code_issues(project_id)
        ignored = [i for i in issues if i.get("ignored")]
        open_issues = [i for i in issues if not i.get("ignored")]
        counts = {
            "total": len(issues),
            "ignored": len(ignored),
            "open": len(open_issues),
        }
        logger.info(
            f"Post-ignore verification: {counts['total']} total, "
            f"{counts['ignored']} ignored, {counts['open']} open"
        )
        return counts

    def get_issue_detail(self, issue_id: str) -> dict:
        """Fetch full issue detail including exploitability, reachability, and CVSS."""
        path = f"/rest/orgs/{self.org_id}/issues/{issue_id}"
        try:
            data = self._get(path)
            attrs = data.get("data", {}).get("attributes", {})
            return {
                "id": issue_id,
                "title": attrs.get("title", ""),
                "severity": attrs.get("effective_severity_level", ""),
                "exploit_maturity": attrs.get("exploit_maturity", ""),
                "is_reachable": attrs.get("is_reachable", None),
                "cvss_score": (attrs.get("risk", {}).get("score", {}).get("value", 0)
                               if isinstance(attrs.get("risk", {}).get("score"), dict) else 0),
                "slots": attrs.get("slots", {}),
            }
        except Exception as e:
            logger.warning(f"get_issue_detail failed for {issue_id}: {e}")
            return {}

    def check_package_issues(self, purl: str) -> list[dict]:
        """Check if a specific package version has known vulnerabilities.

        purl: Package URL (e.g., "pkg:npm/lodash@4.18.1")
        """
        url = f"{self.BASE_URL}/rest/orgs/{self.org_id}/packages/{purl}/issues"
        params = {"version": self.api_version}
        resp = self._request_with_retry("GET", url, headers=self._rest_headers, params=params, timeout=30)
        if resp.status_code != 200:
            logger.warning(f"Package issues API {resp.status_code} for {purl}: {resp.text[:200]}")
            return []
        issues = []
        for item in resp.json().get("data", []):
            attrs = item.get("attributes", {})
            issues.append({
                "id": item.get("id", ""),
                "title": attrs.get("title", ""),
                "severity": attrs.get("effective_severity_level", ""),
                "exploit_maturity": attrs.get("exploit_maturity", ""),
            })
        return issues

    def check_packages_bulk(self, purls: list[str]) -> dict:
        """Bulk-query issues for multiple package versions.

        purls: list of Package URLs (e.g., ["pkg:npm/lodash@4.18.1", ...])
        Returns: dict mapping purl -> list of issues
        """
        url = f"{self.BASE_URL}/rest/orgs/{self.org_id}/packages/issues"
        params = {"version": self.api_version}
        body = {
            "data": {
                "attributes": {
                    "packages": [{"url": p} for p in purls],
                },
                "type": "resource",
            }
        }
        resp = self._request_with_retry("POST", url, headers=self._rest_headers, params=params, json=body, timeout=60)
        if resp.status_code != 200:
            logger.warning(f"Bulk package issues API {resp.status_code}: {resp.text[:200]}")
            return {}
        result = {}
        for item in resp.json().get("data", []):
            pkg_url = item.get("id", "")
            issues = item.get("attributes", {}).get("issues", [])
            result[pkg_url] = issues
        return result

    def activate_project(self, project_id: str) -> bool:
        """Re-activate a deactivated project so it resumes scanning."""
        url = f"{self.BASE_URL}/v1/org/{self.org_id}/project/{project_id}/activate"
        resp = self._request_with_retry("POST", url, headers=self.headers, json={}, timeout=30)
        if resp.status_code == 200:
            logger.info(f"Activated project {project_id}")
            return True
        logger.warning(f"Activate API {resp.status_code} for {project_id}: {resp.text[:200]}")
        return False

    def deactivate_project(self, project_id: str) -> bool:
        """Deactivate a project to stop scanning (e.g., archived repos)."""
        url = f"{self.BASE_URL}/v1/org/{self.org_id}/project/{project_id}/deactivate"
        resp = self._request_with_retry("POST", url, headers=self.headers, json={}, timeout=30)
        if resp.status_code == 200:
            logger.info(f"Deactivated project {project_id}")
            return True
        logger.warning(f"Deactivate API {resp.status_code} for {project_id}: {resp.text[:200]}")
        return False

    def list_ignores(self, project_id: str) -> dict:
        """List all existing ignores for a project."""
        url = f"{self.BASE_URL}/v1/org/{self.org_id}/project/{project_id}/ignores"
        resp = self._request_with_retry("GET", url, headers=self.headers, timeout=30)
        if resp.status_code != 200:
            logger.warning(f"List ignores API {resp.status_code} for {project_id}: {resp.text[:200]}")
            return {}
        return resp.json()

    def delete_ignore(self, project_id: str, issue_id: str) -> bool:
        """Remove an ignore from a project."""
        url = f"{self.BASE_URL}/v1/org/{self.org_id}/project/{project_id}/ignore/{issue_id}"
        resp = self._request_with_retry("DELETE", url, headers=self.headers, timeout=30)
        if resp.status_code == 200:
            logger.info(f"Deleted ignore for {issue_id} on project {project_id}")
            return True
        logger.warning(f"Delete ignore API {resp.status_code} for {issue_id}: {resp.text[:200]}")
        return False

    def get_issue_paths(self, project_id: str, issue_id: str) -> list[list[str]]:
        """Get dependency paths through which a vulnerability is introduced."""
        url = f"{self.BASE_URL}/v1/org/{self.org_id}/project/{project_id}/issue/{issue_id}/paths"
        resp = self._request_with_retry("GET", url, headers=self.headers, timeout=30)
        if resp.status_code != 200:
            logger.warning(f"Issue paths API {resp.status_code} for {issue_id}: {resp.text[:200]}")
            return []
        paths = []
        for snapshot in resp.json().get("snapshotOf", []):
            chain = []
            for node in snapshot.get("paths", []):
                chain.append(f"{node.get('name', '?')}@{node.get('version', '?')}")
            if chain:
                paths.append(chain)
        return paths

    def get_issue_dep_chains(self, project_id: str, issue_id: str) -> list[list[str]]:
        """Fetch the full dependency chains for a vulnerability.

        Returns: list of chains, each chain is a list of "name@version" strings.
        The first element is the direct/intermediate dep closest to the project root;
        the last element is the vulnerable package itself.
        """
        url = f"{self.BASE_URL}/v1/org/{self.org_id}/project/{project_id}/issue/{issue_id}/paths"
        resp = self._request_with_retry(
            "GET", url, headers=self.headers, params={"perPage": 20}, timeout=30
        )
        if resp.status_code != 200:
            logger.warning(f"Dep chains API {resp.status_code} for {issue_id}: {resp.text[:200]}")
            return []
        raw_paths = resp.json().get("paths", [])
        chains = []
        for chain in raw_paths:
            if isinstance(chain, list):
                names = [
                    f"{n.get('name', '?')}@{n.get('version', '?')}"
                    for n in chain
                    if isinstance(n, dict) and n.get("name")
                ]
                if names:
                    chains.append(names)
        return chains

    def find_org_packages_in_chains(
        self, chains: list[list[str]], our_repo_names: set[str]
    ) -> list[str]:
        """Given dep chains, return any org-owned package names found in intermediate hops.

        Matches on both scoped names (e.g. "@your-org/pkg") and known repo slugs.
        Excludes the last node (the vulnerable package itself).

        Returns: deduplicated list of org package names, ordered by frequency across chains.
        """
        from collections import Counter
        counts: Counter = Counter()
        org_scope = f"@{self.org_prefix}/" if self.org_prefix else ""
        for chain in chains:
            # Exclude the last node (the vulnerable package) and check intermediates
            for node in chain[:-1]:
                pkg_name = node.split("@")[0].rstrip("/").strip()
                is_org_scoped = (
                    (org_scope and pkg_name.startswith(org_scope))
                    or (self.org_prefix and self.org_prefix.lower() in pkg_name.lower())
                )
                slug = pkg_name.lstrip("@").split("/")[-1]
                in_our_repos = slug in our_repo_names or pkg_name.split("/")[-1] in our_repo_names
                if is_org_scoped or in_our_repos:
                    counts[pkg_name] += 1
        return [pkg for pkg, _ in counts.most_common()]

    def list_policies(self) -> list[dict]:
        """List all existing ignore/security policies for the org."""
        path = f"/rest/orgs/{self.org_id}/policies"
        try:
            data = self._get(path)
            return data.get("data", [])
        except Exception as e:
            logger.warning(f"List policies failed: {e}")
            return []

    def list_targets(self) -> list[dict]:
        """List all monitored targets (repos) in the org."""
        targets = []
        path = f"/rest/orgs/{self.org_id}/targets"
        params = {"limit": 100}
        while path:
            try:
                data = self._get(path, params)
            except Exception as e:
                logger.warning(f"List targets failed: {e}")
                break
            for item in data.get("data", []):
                attrs = item.get("attributes", {})
                targets.append({
                    "id": item.get("id", ""),
                    "display_name": attrs.get("display_name", ""),
                    "url": attrs.get("url", ""),
                    "is_private": attrs.get("is_private", False),
                    "origin": attrs.get("origin", ""),
                })
            next_link = (data.get("links") or {}).get("next")
            path = next_link if next_link else None
            params = {}
        return targets

    def delete_target(self, target_id: str) -> bool:
        """Delete a stale/removed target from Snyk."""
        url = f"{self.BASE_URL}/rest/orgs/{self.org_id}/targets/{target_id}?version={self.api_version}"
        resp = self._request_with_retry("DELETE", url, headers=self._rest_headers, timeout=30)
        if resp.status_code in (200, 204):
            logger.info(f"Deleted target {target_id}")
            return True
        logger.warning(f"Delete target API {resp.status_code} for {target_id}: {resp.text[:200]}")
        return False

    def get_project_detail(self, project_id: str) -> dict:
        """Get single project details including last test date and issue counts."""
        path = f"/rest/orgs/{self.org_id}/projects/{project_id}"
        try:
            data = self._get(path)
            attrs = data.get("data", {}).get("attributes", {})
            return {
                "id": project_id,
                "name": attrs.get("name", ""),
                "type": attrs.get("type", ""),
                "status": attrs.get("status", ""),
                "last_tested_date": attrs.get("settings", {}).get("recurring_tests", {}).get("last_tested_date", ""),
                "test_frequency": attrs.get("settings", {}).get("recurring_tests", {}).get("frequency", ""),
            }
        except Exception as e:
            logger.warning(f"get_project_detail failed for {project_id}: {e}")
            return {}

    def get_project_sbom(self, project_id: str, fmt: str = "cyclonedx1.4+json") -> dict:
        """Export project SBOM in CycloneDX or SPDX format."""
        path = f"/rest/orgs/{self.org_id}/projects/{project_id}/sbom"
        params = {"format": fmt}
        try:
            return self._get(path, params)
        except Exception as e:
            logger.warning(f"SBOM export failed for {project_id}: {e}")
            return {}

    def add_project_tag(self, project_id: str, key: str, value: str) -> bool:
        """Add a tag to a project."""
        url = f"{self.BASE_URL}/v1/org/{self.org_id}/project/{project_id}/tags"
        body = {"key": key, "value": value}
        resp = self._request_with_retry("POST", url, headers=self.headers, json=body, timeout=30)
        if resp.status_code == 200:
            return True
        logger.warning(f"Add tag API {resp.status_code} for {project_id}: {resp.text[:200]}")
        return False

    def remove_project_tag(self, project_id: str, key: str, value: str) -> bool:
        """Remove a tag from a project."""
        url = f"{self.BASE_URL}/v1/org/{self.org_id}/project/{project_id}/tags/remove"
        body = {"key": key, "value": value}
        resp = self._request_with_retry("POST", url, headers=self.headers, json=body, timeout=30)
        if resp.status_code == 200:
            return True
        logger.warning(f"Remove tag API {resp.status_code} for {project_id}: {resp.text[:200]}")
        return False

    def update_policy(self, policy_id: str, attrs: dict) -> bool:
        """Update an existing ignore/security policy."""
        url = f"{self.BASE_URL}/rest/orgs/{self.org_id}/policies/{policy_id}?version={self.api_version}"
        body = {"data": {"attributes": attrs, "type": "policy"}}
        resp = self._request_with_retry("PATCH", url, headers=self._rest_headers, json=body, timeout=30)
        if resp.status_code in (200, 204):
            return True
        logger.warning(f"Update policy API {resp.status_code} for {policy_id}: {resp.text[:200]}")
        return False

    def delete_policy(self, policy_id: str) -> bool:
        """Delete an ignore/security policy."""
        url = f"{self.BASE_URL}/rest/orgs/{self.org_id}/policies/{policy_id}?version={self.api_version}"
        resp = self._request_with_retry("DELETE", url, headers=self._rest_headers, timeout=30)
        if resp.status_code in (200, 204):
            logger.info(f"Deleted policy {policy_id}")
            return True
        logger.warning(f"Delete policy API {resp.status_code} for {policy_id}: {resp.text[:200]}")
        return False

    def search_audit_logs(self, event: str = "", user_id: str = "", from_date: str = "", to_date: str = "") -> list[dict]:
        """Search org audit logs."""
        path = f"/rest/orgs/{self.org_id}/audit_logs/search"
        params = {"limit": 100}
        if event:
            params["event"] = event
        if user_id:
            params["user_id"] = user_id
        if from_date:
            params["from"] = from_date
        if to_date:
            params["to"] = to_date
        try:
            data = self._get(path, params)
            return data.get("data", [])
        except Exception as e:
            logger.warning(f"Audit log search failed: {e}")
            return []

    def list_dependencies(self, page: int = 1, per_page: int = 50, sort_by: str = "dependency") -> list[dict]:
        """List all dependencies across the org."""
        url = f"{self.BASE_URL}/v1/org/{self.org_id}/dependencies"
        body = {
            "filters": {},
            "page": page,
            "perPage": per_page,
            "sortBy": sort_by,
        }
        resp = self._request_with_retry("POST", url, headers=self.headers, json=body, timeout=60)
        if resp.status_code != 200:
            logger.warning(f"Dependencies API {resp.status_code}: {resp.text[:200]}")
            return []
        return resp.json().get("results", [])

    def get_sast_settings(self) -> dict:
        """Get Snyk Code (SAST) settings for the org."""
        path = f"/rest/orgs/{self.org_id}/settings/sast"
        try:
            data = self._get(path)
            return data.get("data", {}).get("attributes", {})
        except Exception as e:
            logger.warning(f"SAST settings failed: {e}")
            return {}

    @staticmethod
    def _parse_code_issue(item: dict) -> dict:
        """Parse a REST API issue response for code analysis findings."""
        attrs = item.get("attributes", {})
        coordinates = attrs.get("coordinates", [])

        file_paths = []
        for coord in coordinates:
            for rep in coord.get("representations", []):
                src_loc = rep.get("sourceLocation", {})
                file_path = src_loc.get("file", "")
                if file_path:
                    region = src_loc.get("region", {})
                    start = region.get("start", {})
                    end = region.get("end", {})
                    file_paths.append({
                        "path": file_path,
                        "start_line": start.get("line", 0),
                        "end_line": end.get("line", 0),
                    })

        cwe_list = []
        for cls in attrs.get("classes", []):
            if cls.get("source", "").upper() == "CWE":
                cwe_id = cls.get("id", "")
                cwe_list.append(cwe_id if cwe_id.startswith("CWE-") else f"CWE-{cwe_id}")

        risk = attrs.get("risk", {})
        priority_score = risk.get("score", {}).get("value", 0) if isinstance(risk.get("score"), dict) else 0

        return {
            "id": item.get("id", ""),
            "key": attrs.get("key", ""),
            "key_asset": attrs.get("key_asset", ""),
            "title": attrs.get("title", ""),
            "severity": attrs.get("effective_severity_level", ""),
            "status": attrs.get("status", ""),
            "priority_score": priority_score,
            "cwe": cwe_list,
            "file_paths": file_paths,
            "type": attrs.get("type", ""),
            "ignored": attrs.get("ignored", False),
        }

    def _parse_issue_v1(self, raw: dict) -> dict:
        """Parse a v1 aggregated-issues response item."""
        issue_data = raw.get("issueData", {})
        fix_info = raw.get("fixInfo", {})
        identifiers = issue_data.get("identifiers", {})
        cve_list = identifiers.get("CVE", [])
        cwe_list = identifiers.get("CWE", [])
        severities = issue_data.get("severities", [{}])
        first_sev = severities[0] if severities else {}
        pkg_versions = raw.get("pkgVersions", [])
        fixed_in = fix_info.get("fixedIn", [])
        semver = issue_data.get("semver", {})
        vulnerable_range = semver.get("vulnerable", [])

        return {
            "id": raw.get("id", ""),
            "key": raw.get("id", ""),
            "title": issue_data.get("title", ""),
            "status": "open",
            "severity": issue_data.get("severity", ""),
            "cvss_score": first_sev.get("baseScore", issue_data.get("cvssScore", 0)),
            "cwe": cwe_list[0] if cwe_list else "",
            "cve": cve_list[0] if cve_list else "",
            "package_name": raw.get("pkgName", ""),
            "package_version": pkg_versions[0] if pkg_versions else "",
            "is_upgradeable": fix_info.get("isUpgradable", False),
            "is_patchable": fix_info.get("isPatchable", False),
            "is_pinnable": fix_info.get("isPinnable", False),
            "is_fixable": fix_info.get("isFixable", False),
            "fixed_in": fixed_in[0] if fixed_in else "",
            "vulnerable_range": vulnerable_range[0] if vulnerable_range else "",
            "created_at": issue_data.get("publicationTime", ""),
            "type": raw.get("issueType", ""),
        }
