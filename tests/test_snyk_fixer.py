import json
import os
import pytest
from unittest.mock import patch, MagicMock, call
from src.snyk_fixer import SnykFixer, FixResult


@pytest.fixture
def fixer_config():
    return {
        "repo": "my-org/my-app",
        "name": "my-app",
        "ecosystem": "npm",
        "default_branch": "main",
        "strategy": "conservative",
        "visibility": "public",
        "snyk_project_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    }


@pytest.fixture
def sample_issues():
    return [
        {
            "id": "issue-1",
            "key": "SNYK-JS-LODASH-1234",
            "title": "Arbitrary Code Injection",
            "severity": "high",
            "cvss_score": 8.6,
            "cwe": "CWE-94",
            "cve": "CVE-2026-1234",
            "package_name": "lodash",
            "package_version": "4.17.23",
            "is_upgradeable": False,
            "is_patchable": False,
            "is_pinnable": False,
            "created_at": "2026-03-01T00:00:00Z",
            "type": "package_vulnerability",
        }
    ]


@pytest.fixture
def sample_llm_response():
    from llm_client import LLMResponse

    return LLMResponse(
        fixes=[
            {
                "file": "package.json",
                "package": "lodash",
                "action": "add_override",
                "from": "4.17.23",
                "to": "4.17.25",
                "reasoning": "4.17.25 patches the vulnerability",
            }
        ],
        unfixable=[],
        provider_used="gemini",
    )


class TestSnykFixerClassifyIssues:
    def test_conservative_marks_transitive_as_unfixable(self, sample_issues):
        fixer = SnykFixer.__new__(SnykFixer)
        fixer.strategy = "conservative"
        fixer.transitive_overrides = False
        fixer.off_limits_packages = set()
        fixer.name = "test-repo"
        fixer.repo_config = {}
        fixable, unfixable = fixer._classify_issues(sample_issues)
        assert len(fixable) == 0
        assert len(unfixable) == 1

    def test_transitive_always_unfixable(self, sample_issues):
        # sample_issues has no fixed_in, so transitive_overrides=True still can't fix it
        fixer = SnykFixer.__new__(SnykFixer)
        fixer.strategy = "aggressive"
        fixer.transitive_overrides = True
        fixer.off_limits_packages = set()
        fixer.name = "test-repo"
        fixer.repo_config = {}
        fixable, unfixable = fixer._classify_issues(sample_issues)
        assert len(fixable) == 0
        assert len(unfixable) == 1

    def test_off_limits_package_skipped(self, sample_issues):
        fixer = SnykFixer.__new__(SnykFixer)
        fixer.strategy = "aggressive"
        fixer.transitive_overrides = True
        fixer.off_limits_packages = {"lodash"}
        fixer.name = "test-repo"
        fixer.repo_config = {}
        fixable, unfixable = fixer._classify_issues(sample_issues)
        assert len(fixable) == 0
        assert unfixable[0].get("_skip_reason") == "off_limits"

    def test_transitive_with_fix_promoted_when_overrides_enabled(self):
        issues = [{
            "id": "issue-2", "package_name": "semver", "severity": "high",
            "is_upgradeable": False, "is_direct": False, "fixed_in": "7.5.2",
        }]
        fixer = SnykFixer.__new__(SnykFixer)
        fixer.strategy = "aggressive"
        fixer.transitive_overrides = True
        fixer.off_limits_packages = set()
        fixer.name = "test-repo"
        fixer.repo_config = {}
        fixer.snyk_project_id = ""
        fixer.snyk_client = None
        fixable, unfixable = fixer._classify_issues(issues)
        assert len(fixable) == 1
        assert fixable[0].get("_fix_mode") == "override"


class TestSnykFixerResult:
    def test_fix_result_to_dict(self):
        result = FixResult(
            repo="my-org/my-cli",
            name="cli",
            success=True,
            fixes_applied=[{"package": "lodash", "from": "4.17.23", "to": "4.17.25"}],
            unfixable=[],
            pr_url="https://github.com/my-org/my-cli/pull/142",
            issues_before=3,
            issues_after=1,
            error=None,
        )
        d = result.to_dict()
        assert d["repo"] == "my-org/my-cli"
        assert d["success"] is True
        assert d["pr_url"] == "https://github.com/my-org/my-cli/pull/142"
        assert d["issues_before"] == 3
