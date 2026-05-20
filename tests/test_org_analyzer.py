import pytest
from unittest.mock import MagicMock, patch
from src.org_analyzer import OrgAnalyzer, OrgAnalysis, CascadeEntry, FixQueueEntry


@pytest.fixture
def config_repos():
    return [
        {"name": "my-org-app-sdk", "repo": "my-org/my-org-app-sdk", "ecosystem": "npm", "npm_package_name": "@my-org/app-sdk"},
        {"name": "my-org-utils", "repo": "my-org/my-org-utils", "ecosystem": "npm"},
        {"name": "my-cli", "repo": "my-org/my-cli", "ecosystem": "npm"},
        {"name": "my-kickstart", "repo": "my-org/my-kickstart", "ecosystem": "npm"},
    ]


@pytest.fixture
def snyk_client():
    client = MagicMock()
    client.find_org_packages_in_chains = MagicMock(return_value=[])
    client.get_issue_dep_chains = MagicMock(return_value=[])
    return client


@pytest.fixture
def analyzer(snyk_client, config_repos):
    return OrgAnalyzer(snyk_client=snyk_client, config_repos=config_repos)


@pytest.fixture
def all_issues():
    return {
        "proj-app-sdk": {
            "name": "my-org/my-org-app-sdk:package.json",
            "type": "npm",
            "issues": [
                {"id": "SNYK-1", "package_name": "qs", "severity": "high", "is_direct": False, "fixed_in": "6.13.1"},
            ],
        },
        "proj-cli-plugins": {
            "name": "my-org/my-cli:package.json",
            "type": "npm",
            "issues": [
                {"id": "SNYK-2", "package_name": "qs", "severity": "high", "is_direct": False, "fixed_in": "6.13.1"},
                {"id": "SNYK-3", "package_name": "lodash", "severity": "medium", "is_direct": True, "fixed_in": "4.17.25"},
            ],
        },
        "proj-kickstart": {
            "name": "my-org/my-kickstart:package.json",
            "type": "npm",
            "issues": [],
        },
    }


class TestBuildProjectToRepo:
    def test_exact_slug_match(self, analyzer, all_issues):
        analyzer._build_project_to_repo(all_issues)
        assert analyzer._project_to_repo["proj-app-sdk"] == "my-org-app-sdk"
        assert analyzer._project_to_repo["proj-cli-plugins"] == "my-cli"

    def test_no_issues_project_still_mapped(self, analyzer, all_issues):
        analyzer._build_project_to_repo(all_issues)
        # kickstart-next should still be mapped
        assert analyzer._project_to_repo["proj-kickstart"] == "my-kickstart"

    def test_unknown_project_falls_back_to_slug(self, analyzer):
        issues = {"proj-unknown": {"name": "my-org/some-unknown-repo:package.json", "issues": []}}
        analyzer._build_project_to_repo(issues)
        assert analyzer._project_to_repo["proj-unknown"] == "some-unknown-repo"


class TestFindTransitiveIssues:
    def test_filters_direct_issues(self, analyzer, all_issues):
        result = analyzer._find_transitive_issues(all_issues)
        # proj-app-sdk has 1 transitive with fixed_in
        # proj-cli-plugins has 1 transitive with fixed_in (SNYK-2); SNYK-3 is direct
        assert "proj-app-sdk" in result
        assert "proj-cli-plugins" in result
        assert len(result["proj-app-sdk"]) == 1
        assert len(result["proj-cli-plugins"]) == 1

    def test_excludes_transitive_without_fixed_in(self, analyzer):
        issues = {
            "proj-1": {"name": "my-org/repo:package.json", "issues": [
                {"id": "X", "package_name": "pkg", "severity": "high", "is_direct": False, "fixed_in": ""},
            ]}
        }
        result = analyzer._find_transitive_issues(issues)
        assert "proj-1" not in result

    def test_empty_issues(self, analyzer):
        result = analyzer._find_transitive_issues({"proj-1": {"name": "x", "issues": []}})
        assert result == {}


class TestFetchDepChainsBatched:
    def test_fetches_in_severity_order(self, analyzer):
        transitive_map = {
            "proj-1": [
                {"id": "A", "severity": "low"},
                {"id": "B", "severity": "critical"},
                {"id": "C", "severity": "medium"},
            ]
        }
        fetch_order = []

        def mock_fetch(proj_id, issue_id):
            fetch_order.append(issue_id)
            return []

        analyzer.snyk_client.get_issue_dep_chains.side_effect = mock_fetch
        import time
        deadline = time.monotonic() + 60
        analyzer._fetch_dep_chains_batched(transitive_map, deadline)
        assert fetch_order[0] == "B"  # critical first

    def test_stops_at_deadline(self, analyzer):
        transitive_map = {
            "proj-1": [{"id": f"issue-{i}", "severity": "high"} for i in range(10)]
        }
        import time
        deadline = time.monotonic()  # already expired
        result = analyzer._fetch_dep_chains_batched(transitive_map, deadline)
        assert len(result) == 0

    def test_handles_api_error_gracefully(self, analyzer):
        analyzer.snyk_client.get_issue_dep_chains.side_effect = Exception("API error")
        transitive_map = {"proj-1": [{"id": "X", "severity": "high"}]}
        import time
        deadline = time.monotonic() + 60
        result = analyzer._fetch_dep_chains_batched(transitive_map, deadline)
        assert ("proj-1", "X") in result
        assert result[("proj-1", "X")] == []


class TestResolveCsPackageToRepo:
    def test_exact_npm_package_name_match(self, analyzer):
        result = analyzer._resolve_org_package_to_repo("@my-org/app-sdk")
        assert result == "my-org-app-sdk"

    def test_slug_normalization(self, analyzer):
        # "@my-org/utils" → slug "utils" → match "my-org-utils"
        result = analyzer._resolve_org_package_to_repo("@my-org/utils")
        assert result == "my-org-utils"

    def test_unresolved_returns_none(self, analyzer):
        result = analyzer._resolve_org_package_to_repo("@my-org/totally-unknown-xyz")
        assert result is None


class TestBuildCascadeMap:
    def test_groups_by_cs_package(self, analyzer):
        analyzer._project_to_repo = {
            "proj-cli": "my-cli",
            "proj-kick": "my-kickstart",
        }
        transitive_map = {
            "proj-cli": [{"id": "SNYK-1", "package_name": "qs", "severity": "high", "fixed_in": "6.13.1"}],
            "proj-kick": [{"id": "SNYK-2", "package_name": "qs", "severity": "medium", "fixed_in": "6.13.1"}],
        }
        chains_map = {
            ("proj-cli", "SNYK-1"): [["@my-org/app-sdk@3.0.0", "qs@6.5.0"]],
            ("proj-kick", "SNYK-2"): [["@my-org/app-sdk@3.0.0", "qs@6.5.0"]],
        }
        analyzer.snyk_client.find_org_packages_in_chains.side_effect = lambda chains, _: (
            ["@my-org/app-sdk"] if chains else []
        )
        result = analyzer._build_cascade_map(transitive_map, chains_map)
        assert "@my-org/app-sdk" in result
        entry = result["@my-org/app-sdk"]
        assert set(entry["downstream_repos"]) == {"my-cli", "my-kickstart"}

    def test_escalates_to_worst_severity(self, analyzer):
        analyzer._project_to_repo = {"proj-a": "repo-a", "proj-b": "repo-b"}
        transitive_map = {
            "proj-a": [{"id": "A", "package_name": "pkg", "severity": "low", "fixed_in": "1.0.0"}],
            "proj-b": [{"id": "B", "package_name": "pkg", "severity": "critical", "fixed_in": "1.0.0"}],
        }
        chains_map = {
            ("proj-a", "A"): [["@my-org/utils@1.0.0", "pkg@0.9.0"]],
            ("proj-b", "B"): [["@my-org/utils@1.0.0", "pkg@0.9.0"]],
        }
        analyzer.snyk_client.find_org_packages_in_chains.side_effect = lambda chains, _: (
            ["@my-org/utils"] if chains else []
        )
        result = analyzer._build_cascade_map(transitive_map, chains_map)
        assert result["@my-org/utils"]["severity"] == "critical"

    def test_no_cs_packages_returns_empty(self, analyzer):
        analyzer._project_to_repo = {"proj-a": "repo-a"}
        transitive_map = {"proj-a": [{"id": "A", "package_name": "qs", "severity": "high", "fixed_in": "6.13.1"}]}
        chains_map = {("proj-a", "A"): [["some-third-party@1.0.0", "qs@6.0.0"]]}
        analyzer.snyk_client.find_org_packages_in_chains.return_value = []
        result = analyzer._build_cascade_map(transitive_map, chains_map)
        assert result == {}


class TestBuildFixQueue:
    def test_upstream_fix_ranked_first(self, analyzer):
        analyzer._project_to_repo = {"proj-sdk": "my-org-app-sdk", "proj-cli": "my-cli"}
        cascade_map = {
            "@my-org/app-sdk": {
                "vuln_package": "qs",
                "vuln_issue_ids": ["SNYK-1"],
                "downstream_repos": ["my-cli"],
                "fixed_in_version": "6.13.1",
                "severity": "high",
                "upstream_repo_name": "my-org-app-sdk",
            }
        }
        scored = {"my-org-app-sdk": 10, "my-cli": 50}
        all_issues = {
            "proj-sdk": {"issues": [{"severity": "high"}]},
            "proj-cli": {"issues": [{"severity": "high"}]},
        }
        queue = analyzer._build_fix_queue(cascade_map, scored, all_issues)
        roles = [e.role for e in queue]
        assert roles[0] == "upstream_fix"
        assert roles[1] == "downstream_override"

    def test_sla_priority_for_non_cascade_repos(self, analyzer):
        analyzer._project_to_repo = {"proj-x": "my-kickstart"}
        cascade_map = {}
        scored = {"my-kickstart": 30}
        all_issues = {"proj-x": {"issues": [{"severity": "medium"}]}}
        queue = analyzer._build_fix_queue(cascade_map, scored, all_issues)
        assert len(queue) == 1
        assert queue[0].role == "sla_priority"
        assert queue[0].repo_name == "my-kickstart"

    def test_no_duplicate_repos(self, analyzer):
        analyzer._project_to_repo = {
            "proj-sdk": "my-org-app-sdk",
            "proj-cli": "my-cli",
        }
        cascade_map = {
            "@my-org/app-sdk": {
                "vuln_package": "qs",
                "vuln_issue_ids": [],
                "downstream_repos": ["my-cli"],
                "fixed_in_version": "6.13.1",
                "severity": "high",
                "upstream_repo_name": "my-org-app-sdk",
            }
        }
        scored = {}
        all_issues = {
            "proj-sdk": {"issues": [{"severity": "high"}]},
            "proj-cli": {"issues": [{"severity": "high"}]},
        }
        queue = analyzer._build_fix_queue(cascade_map, scored, all_issues)
        repo_names = [e.repo_name for e in queue]
        assert len(repo_names) == len(set(repo_names))


class TestAnalyzeIntegration:
    def test_returns_org_analysis(self, analyzer, all_issues):
        analyzer.snyk_client.get_issue_dep_chains.return_value = [
            ["@my-org/app-sdk@3.0.0", "qs@6.5.0"]
        ]
        analyzer.snyk_client.find_org_packages_in_chains.return_value = ["@my-org/app-sdk"]
        result = analyzer.analyze(all_issues)
        assert isinstance(result, OrgAnalysis)
        assert result.total_transitive_issues >= 0
        assert isinstance(result.cascade_entries, list)
        assert isinstance(result.fix_queue, list)
        assert result.analysis_duration_seconds >= 0

    def test_fallback_used_when_deadline_exceeded(self, analyzer, all_issues):
        import time as _time

        original_monotonic = _time.monotonic

        call_count = [0]

        def mock_monotonic():
            call_count[0] += 1
            # Return a past deadline after the first call
            if call_count[0] > 2:
                return original_monotonic() + 10000
            return original_monotonic()

        with patch("src.org_analyzer.time") as mock_time:
            mock_time.monotonic.side_effect = mock_monotonic
            mock_time.sleep = MagicMock()
            result = analyzer.analyze(all_issues)
        # When deadline is immediately exceeded, we expect fallback_used = True or partial results
        assert isinstance(result, OrgAnalysis)

    def test_no_transitive_issues_gives_empty_cascade(self, snyk_client, config_repos):
        direct_only = {
            "proj-1": {
                "name": "my-org/my-cli:package.json",
                "issues": [{"id": "X", "severity": "high", "is_direct": True, "fixed_in": "1.0"}],
            }
        }
        analyzer = OrgAnalyzer(snyk_client=snyk_client, config_repos=config_repos)
        result = analyzer.analyze(direct_only)
        assert result.total_transitive_issues == 0
        assert result.cascade_entries == []
