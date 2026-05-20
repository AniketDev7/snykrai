import json
import pytest
from unittest.mock import patch, MagicMock
from src.llm_client import LLMClient, LLMResponse


@pytest.fixture
def gemini_client():
    return LLMClient(
        provider="gemini",
        gemini_api_key="test-key",
        gemini_model="gemini-2.5-flash",
    )


@pytest.fixture
def anthropic_client():
    return LLMClient(
        provider="anthropic",
        anthropic_api_key="test-key",
        anthropic_model="claude-sonnet-4-6",
    )


@pytest.fixture
def auto_client():
    return LLMClient(
        provider="auto",
        gemini_api_key="test-gemini-key",
        anthropic_api_key="test-anthropic-key",
        gemini_model="gemini-2.5-flash",
        anthropic_model="claude-sonnet-4-6",
    )


@pytest.fixture
def valid_fix_response():
    return json.dumps({
        "fixes": [
            {
                "file": "package.json",
                "package": "lodash",
                "action": "upgrade",
                "from": "4.17.23",
                "to": "4.17.25",
                "reasoning": "4.17.25 patches arbitrary code injection",
            }
        ],
        "unfixable": [],
    })


@pytest.fixture
def invalid_json_response():
    return "Here is the fix:\n```json\n{invalid}\n```"


class TestLLMClientGemini:
    @patch("src.llm_client.genai")
    def test_gemini_returns_parsed_response(self, mock_genai, gemini_client, valid_fix_response):
        mock_client = MagicMock()
        mock_client.models.generate_content.return_value = MagicMock(text=valid_fix_response)
        mock_genai.Client.return_value = mock_client
        result = gemini_client.get_fix_suggestions(
            ecosystem="npm",
            manifest='{"dependencies": {"lodash": "4.17.23"}}',
            issues=[{"package_name": "lodash", "package_version": "4.17.23", "severity": "high"}],
            strategy="conservative",
        )
        assert isinstance(result, LLMResponse)
        assert len(result.fixes) == 1
        assert result.fixes[0]["package"] == "lodash"
        assert result.fixes[0]["to"] == "4.17.25"


class TestLLMClientAnthropic:
    @patch("src.llm_client.anthropic_sdk")
    def test_anthropic_returns_parsed_response(self, mock_sdk, anthropic_client, valid_fix_response):
        mock_client_instance = MagicMock()
        mock_sdk.Anthropic.return_value = mock_client_instance
        mock_client_instance.messages.create.return_value = MagicMock(
            content=[MagicMock(text=valid_fix_response)]
        )
        result = anthropic_client.get_fix_suggestions(
            ecosystem="npm",
            manifest='{"dependencies": {"lodash": "4.17.23"}}',
            issues=[{"package_name": "lodash", "package_version": "4.17.23", "severity": "high"}],
            strategy="conservative",
        )
        assert isinstance(result, LLMResponse)
        assert len(result.fixes) == 1


class TestLLMClientAutoFailover:
    @patch("src.llm_client.anthropic_sdk")
    @patch("src.llm_client.genai")
    def test_auto_falls_back_to_anthropic_on_gemini_failure(
        self, mock_genai, mock_sdk, auto_client, valid_fix_response
    ):
        mock_model = MagicMock()
        mock_model.generate_content.side_effect = Exception("Gemini rate limited")
        mock_genai.GenerativeModel.return_value = mock_model
        mock_client_instance = MagicMock()
        mock_sdk.Anthropic.return_value = mock_client_instance
        mock_client_instance.messages.create.return_value = MagicMock(
            content=[MagicMock(text=valid_fix_response)]
        )
        result = auto_client.get_fix_suggestions(
            ecosystem="npm",
            manifest='{}',
            issues=[],
            strategy="conservative",
        )
        assert isinstance(result, LLMResponse)


class TestLLMClientValidation:
    @patch("src.llm_client.genai")
    def test_rejects_non_json_response(self, mock_genai, gemini_client, invalid_json_response):
        mock_model = MagicMock()
        mock_model.generate_content.return_value = MagicMock(text=invalid_json_response)
        mock_genai.GenerativeModel.return_value = mock_model
        result = gemini_client.get_fix_suggestions(
            ecosystem="npm", manifest="{}", issues=[], strategy="conservative",
        )
        assert isinstance(result, LLMResponse)
        assert result.raw_error is not None

    @patch("src.llm_client.genai")
    def test_rejects_response_with_shell_commands(self, mock_genai, gemini_client):
        bad_response = json.dumps({
            "fixes": [
                {
                    "file": "package.json",
                    "package": "lodash",
                    "action": "upgrade",
                    "from": "4.17.23",
                    "to": "4.17.25; rm -rf /",
                    "reasoning": "fix",
                }
            ],
            "unfixable": [],
        })
        mock_model = MagicMock()
        mock_model.generate_content.return_value = MagicMock(text=bad_response)
        mock_genai.GenerativeModel.return_value = mock_model
        result = gemini_client.get_fix_suggestions(
            ecosystem="npm", manifest="{}", issues=[], strategy="conservative",
        )
        assert len(result.fixes) == 0
