import json
import os
import pytest
from unittest.mock import patch, MagicMock
from src.snyk_client import SnykClient


@pytest.fixture
def client():
    return SnykClient(
        token="test-token",
        org_id="00000000-0000-0000-0000-000000000000",
        api_version="2024-04-29",
    )



class TestSnykClientListProjects:
    @patch("src.snyk_client.requests.request")
    def test_list_projects_returns_project_list(self, mock_get, client):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "data": [
                    {
                        "id": "proj-1",
                        "attributes": {
                            "name": "my-org/my-cli:package.json",
                            "type": "npm",
                            "origin": "github",
                        },
                    }
                ]
            },
        )
        projects = client.list_projects()
        assert len(projects) == 1
        assert projects[0]["id"] == "proj-1"

    @patch("src.snyk_client.requests.request")
    def test_list_projects_paginates(self, mock_get, client):
        page1 = MagicMock(
            status_code=200,
            json=lambda: {
                "data": [{"id": "p1", "attributes": {"name": "a", "type": "npm", "origin": "github"}}],
                "links": {"next": "/rest/orgs/x/projects?starting_after=p1"},
            },
        )
        page2 = MagicMock(
            status_code=200,
            json=lambda: {
                "data": [{"id": "p2", "attributes": {"name": "b", "type": "npm", "origin": "github"}}],
                "links": {},
            },
        )
        mock_get.side_effect = [page1, page2]
        projects = client.list_projects()
        assert len(projects) == 2


class TestSnykClientGetIssues:
    @patch("src.snyk_client.requests.request")
    def test_get_issues_returns_parsed_issues(self, mock_request, client):
        v1_path = os.path.join(os.path.dirname(__file__), "fixtures", "snyk_issues_v1_response.json")
        with open(v1_path) as f:
            v1_data = json.load(f)
        issues_resp = MagicMock(status_code=200, json=lambda: v1_data)
        issues_resp.raise_for_status = MagicMock()
        dep_graph_resp = MagicMock(
            status_code=200,
            json=lambda: {"depGraph": {"pkgs": [], "graph": {"rootNodeId": "root-node", "nodes": [{"nodeId": "root-node", "deps": []}]}}},
        )
        mock_request.side_effect = [issues_resp, dep_graph_resp]
        issues = client.get_issues(project_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        assert len(issues) == 1
        assert issues[0]["package_name"] == "brace-expansion"
        assert issues[0]["severity"] == "high"
        assert issues[0]["title"] == "Infinite loop"
        assert issues[0]["fixed_in"] == "5.0.5"

    @patch("src.snyk_client.requests.request")
    def test_get_issues_handles_empty_response(self, mock_request, client):
        issues_resp = MagicMock(status_code=200, json=lambda: {'issues': []})
        issues_resp.raise_for_status = MagicMock()
        dep_graph_resp = MagicMock(status_code=404)
        mock_request.side_effect = [issues_resp, dep_graph_resp]
        issues = client.get_issues(project_id='proj-1')
        assert issues == []


class TestSnykClientGetAllOrgIssues:
    @patch("src.snyk_client.requests.request")
    def test_get_all_org_issues_groups_by_project(self, mock_request, client):
        projects_resp = MagicMock(
            status_code=200,
            json=lambda: {
                "data": [
                    {
                        "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                        "attributes": {
                            "name": "my-org/my-app:package.json",
                            "type": "npm",
                            "origin": "github",
                        },
                    }
                ],
                "links": {},
            },
        )
        v1_path = os.path.join(os.path.dirname(__file__), "fixtures", "snyk_issues_v1_response.json")
        with open(v1_path) as f:
            v1_data = json.load(f)
        issues_resp = MagicMock(status_code=200, json=lambda: v1_data)
        issues_resp.raise_for_status = MagicMock()
        dep_graph_resp = MagicMock(
            status_code=200,
            json=lambda: {"depGraph": {"pkgs": [], "graph": {"rootNodeId": "root-node", "nodes": [{"nodeId": "root-node", "deps": []}]}}},
        )
        mock_request.side_effect = [projects_resp, issues_resp, dep_graph_resp]
        result, projects = client.get_all_org_issues()
        assert "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" in result
        assert len(result["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"]["issues"]) == 1
        assert len(projects) == 1
