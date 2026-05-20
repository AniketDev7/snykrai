import json
import os
import pytest
from unittest.mock import patch, MagicMock, mock_open
from src.code_analyzer import CodeAnalyzer, AnalysisResult, AUTO_IGNORE_CONFIDENCE
from src.snyk_client import SnykClient
from src.llm_client import LLMClient


@pytest.fixture
def snyk_client():
    return SnykClient(
        token="test-token",
        org_id="00000000-0000-0000-0000-000000000000",
    )


@pytest.fixture
def llm_client():
    return LLMClient(
        provider="auto",
        anthropic_api_key="test-key",
        gemini_api_key="test-key",
    )


@pytest.fixture
def analyzer(snyk_client, llm_client):
    return CodeAnalyzer(snyk_client=snyk_client, llm_client=llm_client)


SAMPLE_FINDINGS = [
    {
        "id": "issue-1",
        "key": "key-1",
        "key_asset": "asset-1",
        "title": "Server-Side Request Forgery (SSRF)",
        "severity": "low",
        "priority_score": 493,
        "cwe": ["CWE-918"],
        "file_paths": [{"path": "src/utils/API_calls_Config.java", "start_line": 670, "end_line": 673}],
        "type": "code",
        "ignored": False,
        "raw": {},
    },
    {
        "id": "issue-2",
        "key": "key-2",
        "key_asset": "asset-2",
        "title": "Path Traversal",
        "severity": "medium",
        "priority_score": 570,
        "cwe": ["CWE-23"],
        "file_paths": [{"path": "src/analyzer.py", "start_line": 2070, "end_line": 2075}],
        "type": "code",
        "ignored": False,
        "raw": {},
    },
]

LLM_RESPONSE_JSON = json.dumps({
    "findings": [
        {
            "id": "issue-1",
            "verdict": "false_positive",
            "confidence": 0.95,
            "reasoning": "URL is constructed from hardcoded config, not user input",
            "evidence": "line 670: url = config.get('base_url')",
            "suggested_ignore_reason": "URL from hardcoded config, no user input reaches HTTP client",
        },
        {
            "id": "issue-2",
            "verdict": "true_positive",
            "confidence": 0.80,
            "reasoning": "User-supplied path used in file open without validation",
            "evidence": "line 2070: open(user_path)",
            "suggested_ignore_reason": "",
        },
    ]
})


class TestCodeAnalyzerClassification:
    @patch.object(SnykClient, "get_code_issues")
    @patch.object(LLMClient, "_call_provider")
    @patch.object(LLMClient, "_get_provider_order")
    def test_classifies_findings_correctly(
        self, mock_providers, mock_call, mock_get_issues, analyzer, tmp_path
    ):
        mock_get_issues.return_value = SAMPLE_FINDINGS
        mock_providers.return_value = ["anthropic"]
        mock_call.return_value = LLM_RESPONSE_JSON

        # Create dummy source files
        src_dir = tmp_path / "src" / "utils"
        src_dir.mkdir(parents=True)
        (src_dir / "API_calls_Config.java").write_text("line\n" * 700)
        (tmp_path / "src" / "analyzer.py").write_text("line\n" * 2100)

        result = analyzer.run(
            project_id="proj-1",
            repo_path=str(tmp_path),
            repo_name="test-repo",
        )

        assert result.total_findings == 2
        assert len(result.false_positives) == 1
        assert len(result.true_positives) == 1
        assert result.false_positives[0]["id"] == "issue-1"
        assert result.true_positives[0]["id"] == "issue-2"

    @patch.object(SnykClient, "get_code_issues")
    def test_handles_no_findings(self, mock_get_issues, analyzer, tmp_path):
        mock_get_issues.return_value = []
        result = analyzer.run(
            project_id="proj-1",
            repo_path=str(tmp_path),
            repo_name="test-repo",
        )
        assert result.total_findings == 0
        assert len(result.false_positives) == 0
        assert len(result.true_positives) == 0

    @patch.object(SnykClient, "get_code_issues")
    def test_skips_already_ignored(self, mock_get_issues, analyzer, tmp_path):
        findings = [
            {**SAMPLE_FINDINGS[0], "ignored": True},
            SAMPLE_FINDINGS[1],
        ]
        mock_get_issues.return_value = findings

        # Mock LLM for the one remaining finding
        with patch.object(LLMClient, "_get_provider_order", return_value=["anthropic"]):
            with patch.object(LLMClient, "_call_provider", return_value=json.dumps({
                "findings": [{
                    "id": "issue-2", "verdict": "needs_review",
                    "confidence": 0.5, "reasoning": "unclear",
                }]
            })):
                (tmp_path / "src").mkdir(parents=True)
                (tmp_path / "src" / "analyzer.py").write_text("line\n" * 2100)
                result = analyzer.run(
                    project_id="proj-1",
                    repo_path=str(tmp_path),
                    repo_name="test-repo",
                )

        assert result.total_findings == 1  # Only the non-ignored one


class TestCodeAnalyzerAutoIgnore:
    @patch.object(SnykClient, "get_code_issues")
    @patch.object(SnykClient, "ignore_code_issue")
    @patch.object(LLMClient, "_call_provider")
    @patch.object(LLMClient, "_get_provider_order")
    def test_auto_ignores_high_confidence_false_positives(
        self, mock_providers, mock_call, mock_ignore, mock_get_issues, analyzer, tmp_path
    ):
        mock_get_issues.return_value = [SAMPLE_FINDINGS[0]]
        mock_providers.return_value = ["anthropic"]
        mock_call.return_value = json.dumps({
            "findings": [{
                "id": "issue-1", "verdict": "false_positive",
                "confidence": 0.95, "reasoning": "hardcoded URL",
                "suggested_ignore_reason": "AI validated: hardcoded URL",
            }]
        })
        mock_ignore.return_value = True

        src_dir = tmp_path / "src" / "utils"
        src_dir.mkdir(parents=True)
        (src_dir / "API_calls_Config.java").write_text("line\n" * 700)

        result = analyzer.run(
            project_id="proj-1",
            repo_path=str(tmp_path),
            repo_name="test-repo",
            auto_ignore=True,
        )

        assert result.ignored_count == 1
        mock_ignore.assert_called_once()
        call_args = mock_ignore.call_args
        assert call_args.kwargs["reason_type"] == "not-vulnerable"
        assert call_args.kwargs["key_asset"] == "asset-1"
        assert "SnykrAI auto-triage" in call_args.kwargs["reason_text"]

    @patch.object(SnykClient, "get_code_issues")
    @patch.object(SnykClient, "ignore_code_issue")
    @patch.object(LLMClient, "_call_provider")
    @patch.object(LLMClient, "_get_provider_order")
    def test_skips_low_confidence_false_positives(
        self, mock_providers, mock_call, mock_ignore, mock_get_issues, analyzer, tmp_path
    ):
        mock_get_issues.return_value = [SAMPLE_FINDINGS[0]]
        mock_providers.return_value = ["anthropic"]
        mock_call.return_value = json.dumps({
            "findings": [{
                "id": "issue-1", "verdict": "false_positive",
                "confidence": 0.70,  # Below threshold
                "reasoning": "probably safe",
            }]
        })

        src_dir = tmp_path / "src" / "utils"
        src_dir.mkdir(parents=True)
        (src_dir / "API_calls_Config.java").write_text("line\n" * 700)

        result = analyzer.run(
            project_id="proj-1",
            repo_path=str(tmp_path),
            repo_name="test-repo",
            auto_ignore=True,
        )

        assert result.ignored_count == 0
        mock_ignore.assert_not_called()


class TestCodeAnalyzerLLMFailure:
    @patch.object(SnykClient, "get_code_issues")
    @patch.object(LLMClient, "_call_provider")
    @patch.object(LLMClient, "_get_provider_order")
    def test_marks_needs_review_on_llm_failure(
        self, mock_providers, mock_call, mock_get_issues, analyzer, tmp_path
    ):
        mock_get_issues.return_value = [SAMPLE_FINDINGS[0]]
        mock_providers.return_value = ["anthropic"]
        mock_call.side_effect = Exception("API timeout")

        src_dir = tmp_path / "src" / "utils"
        src_dir.mkdir(parents=True)
        (src_dir / "API_calls_Config.java").write_text("line\n" * 700)

        result = analyzer.run(
            project_id="proj-1",
            repo_path=str(tmp_path),
            repo_name="test-repo",
        )

        assert len(result.needs_review) == 1
        assert len(result.errors) > 0


class TestCodeAnalyzerResultSerialization:
    def test_to_dict(self):
        result = AnalysisResult(
            project_id="proj-1",
            repo="test-repo",
            total_findings=3,
            false_positives=[{"id": "fp-1"}],
            true_positives=[{"id": "tp-1"}],
            needs_review=[{"id": "nr-1"}],
            ignored_count=1,
        )
        d = result.to_dict()
        assert d["project_id"] == "proj-1"
        assert d["total_findings"] == 3
        assert len(d["false_positives"]) == 1
        assert d["ignored_count"] == 1


class TestSnykClientCodeIssues:
    @patch("src.snyk_client.requests.request")
    def test_get_code_issues_parses_response(self, mock_request):
        client = SnykClient(token="test", org_id="org-1")
        mock_request.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "data": [{
                    "id": "code-issue-1",
                    "attributes": {
                        "title": "Server-Side Request Forgery (SSRF)",
                        "effective_severity_level": "low",
                        "status": "open",
                        "key": "test-key-1",
                        "risk": {"score": {"model": "v1", "value": 493}},
                        "type": "code",
                        "ignored": False,
                        "classes": [
                            {"id": "CWE-918", "source": "CWE", "type": "weakness"}
                        ],
                        "coordinates": [{
                            "representations": [{
                                "sourceLocation": {
                                    "file": "src/utils/Config.java",
                                    "region": {
                                        "start": {"line": 670, "column": 1},
                                        "end": {"line": 673, "column": 1},
                                    }
                                }
                            }]
                        }],
                    },
                }],
                "links": {},
            },
        )
        mock_request.return_value.raise_for_status = MagicMock()

        issues = client.get_code_issues("proj-1")
        assert len(issues) == 1
        assert issues[0]["id"] == "code-issue-1"
        assert issues[0]["title"] == "Server-Side Request Forgery (SSRF)"
        assert issues[0]["severity"] == "low"
        assert issues[0]["cwe"] == ["CWE-918"]
        assert issues[0]["file_paths"][0]["path"] == "src/utils/Config.java"

    @patch("src.snyk_client.requests.request")
    def test_ignore_issue_sends_correct_request(self, mock_request):
        client = SnykClient(token="test", org_id="org-1")
        mock_request.return_value = MagicMock(status_code=200)

        result = client.ignore_issue(
            project_id="proj-1",
            issue_id="issue-1",
            reason_type="not-vulnerable",
            reason_text="AI validated: false positive",
        )
        assert result is True
        mock_request.assert_called_once()
        call_kwargs = mock_request.call_args
        body = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert body["reasonType"] == "not-vulnerable"
        assert "AI validated" in body["reason"]
