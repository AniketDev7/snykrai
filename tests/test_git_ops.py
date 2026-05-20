import os
import json
import subprocess
import pytest
from unittest.mock import patch, MagicMock
from src.git_ops import GitOps


@pytest.fixture
def git_ops():
    return GitOps(
        git_token="test-token",
        git_user="test-user",
        commit_author_name="Snyk Auto-Fix",
        commit_author_email="snykrai-bot@users.noreply.github.com",
        branch_prefix="snyk-fix",
    )


class TestCommitMessageSanitization:
    def test_public_repo_commit_message(self, git_ops):
        msg = git_ops.build_commit_message(
            packages=[("lodash", "4.17.23", "4.17.25")],
            visibility="public",
        )
        assert "lodash" in msg
        assert "4.17.25" in msg
        assert "CVE" not in msg
        assert "Co-Authored-By" not in msg
        assert "co-authored-by" not in msg.lower()

    def test_private_repo_commit_message(self, git_ops):
        msg = git_ops.build_commit_message(
            packages=[("lodash", "4.17.23", "4.17.25")],
            visibility="private",
        )
        assert "CVE" not in msg
        assert "Co-Authored-By" not in msg

    def test_commit_message_with_multiple_packages(self, git_ops):
        msg = git_ops.build_commit_message(
            packages=[
                ("lodash", "4.17.23", "4.17.25"),
                ("brace-expansion", "5.0.4", "5.0.5"),
            ],
            visibility="public",
        )
        assert "lodash" in msg
        assert "brace-expansion" in msg


class TestBranchNaming:
    def test_branch_name_is_date_based(self, git_ops):
        name = git_ops.get_branch_name()
        assert name.startswith("snyk-fix/")
        assert "CVE" not in name

    def test_branch_name_no_cve(self, git_ops):
        name = git_ops.get_branch_name()
        assert "CVE" not in name
        assert "cve" not in name


class TestAllowlistedStaging:
    def test_filter_changed_files_keeps_only_allowlisted(self, git_ops):
        changed = ["package.json", "package-lock.json", "node_modules/.cache/foo", ".env", "run.log"]
        allowed = ["package.json", "package-lock.json", "npm-shrinkwrap.json", ".snyk"]
        result = git_ops.filter_allowlisted(changed, allowed)
        assert result == ["package.json", "package-lock.json"]
