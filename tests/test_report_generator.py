import pytest
from src.report_generator import ReportGenerator


@pytest.fixture
def sample_results():
    return [
        {
            "repo": "my-org/my-service",
            "name": "my-service",
            "success": True,
            "fixes_applied": [
                {"package": "lodash", "from": "4.17.23", "to": "4.17.25",
                 "reasoning": "Earliest patched version"},
            ],
            "unfixable": [{"package": "brace-expansion", "reason": "Transitive, conservative strategy"}],
            "pr_url": "https://github.com/my-org/my-service/pull/142",
            "issues_before": 3,
            "issues_after": 1,
            "strategy": "conservative",
            "branch": "snyk-fix/2026-04-02",
            "llm_provider": "gemini",
        },
        {
            "repo": "my-org/my-app",
            "name": "my-app",
            "success": False,
            "fixes_applied": [],
            "unfixable": [],
            "pr_url": None,
            "issues_before": 2,
            "issues_after": 2,
            "error": "Install failed: npm ERR!",
            "strategy": "aggressive",
            "branch": "snyk-fix/2026-04-02",
            "llm_provider": "gemini",
        },
    ]


@pytest.fixture
def sample_queued():
    return [
        {"repo": "my-org-ruby", "issue_count": 2, "top_severity": "critical", "sla_days_remaining": 3},
    ]


class TestReportGenerator:
    def test_generates_markdown(self, sample_results, sample_queued):
        gen = ReportGenerator()
        report = gen.generate(
            results=sample_results,
            queued=sample_queued,
            clean_count=47,
            run_number=47,
            trigger_source="cron",
            trigger_user="",
        )
        assert "# SnykrAI Fix Report" in report
        assert "my-org/my-service" in report
        assert "lodash" in report
        assert "4.17.25" in report
        assert "PR:" in report or "pull/142" in report

    def test_includes_failed_repos(self, sample_results, sample_queued):
        gen = ReportGenerator()
        report = gen.generate(
            results=sample_results, queued=sample_queued,
            clean_count=47, run_number=47, trigger_source="cron", trigger_user="",
        )
        assert "my-app" in report
        assert "Install failed" in report

    def test_includes_queued_repos(self, sample_results, sample_queued):
        gen = ReportGenerator()
        report = gen.generate(
            results=sample_results, queued=sample_queued,
            clean_count=47, run_number=47, trigger_source="cron", trigger_user="",
        )
        assert "my-org-ruby" in report
        assert "critical" in report.lower()

    def test_includes_summary_table(self, sample_results, sample_queued):
        gen = ReportGenerator()
        report = gen.generate(
            results=sample_results, queued=sample_queued,
            clean_count=47, run_number=47, trigger_source="cron", trigger_user="",
        )
        assert "Summary" in report

    def test_no_secrets_in_report(self, sample_results, sample_queued):
        gen = ReportGenerator()
        report = gen.generate(
            results=sample_results, queued=sample_queued,
            clean_count=47, run_number=47, trigger_source="cron", trigger_user="",
        )
        assert "SNYK_TOKEN" not in report
        assert "API_KEY" not in report
        assert "xoxb-" not in report
