import os
import unittest

from mpvm_jira.setup.discovery import (
    JiraIssueType,
    JiraProject,
    PermissionResult,
    RequiredField,
)
from mpvm_jira.setup.state import SetupState
from mpvm_jira.setup.validation import SetupValidationService


def complete_state():
    return SetupState(
        mpvm_url="https://mpvm.example.org",
        mpvm_token="mpvm-secret",
        jira_url="https://jira.example.org",
        jira_auth_mode="bearer",
        jira_token="jira-secret",
        project_key="PM",
        issue_type="Task",
        priority_map={
            "High": "High",
            "Medium": "Medium",
            "Low": "Low",
            "Undefined": "Medium",
        },
        default_priority="Medium",
        additional_fields={"customfield_1": {"value": "Security"}},
    )


class FakeMaxPatrolClient:
    configurations = []
    calls = []

    def __init__(self, config):
        self.configurations.append(config)

    def validate_connection(self):
        self.calls.append("validate_connection")


class FakeJiraSetupClient:
    def __init__(self):
        self.api_version = None
        self.calls = []

    def detect_api_version(self):
        self.calls.append("detect_api_version")
        self.api_version = "2"
        return "2"

    def get_project(self, project_key):
        self.calls.append(("get_project", project_key))
        return JiraProject("PM", "Project Management")

    def list_issue_types(self, project_key):
        self.calls.append(("list_issue_types", project_key))
        return (JiraIssueType("10001", "Task"),)

    def list_priorities(self):
        self.calls.append("list_priorities")
        return ("High", "Medium", "Low")

    def required_fields(self, project_key, issue_type):
        self.calls.append(("required_fields", project_key, issue_type))
        return (RequiredField("customfield_1", "Risk", "option"),)

    def validate_permissions(self, project_key):
        self.calls.append(("validate_permissions", project_key))
        return PermissionResult(True, True)


class SetupValidationTests(unittest.TestCase):
    def setUp(self):
        FakeMaxPatrolClient.configurations.clear()
        FakeMaxPatrolClient.calls.clear()

    def test_mpvm_validation_passes_url_token_mapping_and_tls(self):
        state = complete_state()
        service = SetupValidationService(mpvm_client_factory=FakeMaxPatrolClient)

        result = service.validate_mpvm(state)

        self.assertTrue(result.ok)
        config = FakeMaxPatrolClient.configurations[0]
        self.assertEqual(config["base_url"], "https://mpvm.example.org")
        self.assertIs(config["verify_ssl"], True)
        variable = config["access_token_env"]
        self.assertNotIn(variable, os.environ)
        self.assertEqual(FakeMaxPatrolClient.calls, ["validate_connection"])

    def test_complete_validation_checks_every_selected_jira_value(self):
        state = complete_state()
        jira = FakeJiraSetupClient()
        service = SetupValidationService(
            mpvm_client_factory=FakeMaxPatrolClient,
            jira_client_factory=lambda _state: jira,
        )

        summary = service.validate_complete(state)

        self.assertTrue(summary.ok)
        self.assertEqual(state.jira_api_version, "2")
        self.assertIn(("get_project", "PM"), jira.calls)
        self.assertIn(("list_issue_types", "PM"), jira.calls)
        self.assertIn("list_priorities", jira.calls)
        self.assertIn(("required_fields", "PM", "10001"), jira.calls)
        self.assertIn(("validate_permissions", "PM"), jira.calls)
        self.assertNotIn("mpvm-secret", repr(summary))
        self.assertNotIn("jira-secret", repr(summary))

    def test_complete_validation_rejects_missing_attachment_permission(self):
        state = complete_state()
        jira = FakeJiraSetupClient()
        jira.validate_permissions = lambda project: PermissionResult(True, False)
        service = SetupValidationService(
            mpvm_client_factory=FakeMaxPatrolClient,
            jira_client_factory=lambda _state: jira,
        )

        summary = service.validate_complete(state)

        self.assertFalse(summary.ok)
        self.assertIn("Create attachments", summary.message)


if __name__ == "__main__":
    unittest.main()
