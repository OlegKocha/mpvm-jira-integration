import unittest

from mpvm_jira.setup.discovery import (
    JiraSetupClient,
    SetupDiscoveryError,
)


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self.ok = 200 <= status_code < 300
        self._payload = payload

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.headers = {}
        self.auth = None

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses.pop(0)


def client(responses, *, auth_mode="bearer"):
    return JiraSetupClient(
        "https://jira.example.org/",
        auth_mode,
        "secret",
        user="user@example.org",
        session=FakeSession(responses),
    )


class JiraDiscoveryTests(unittest.TestCase):
    def test_detects_api_version_three(self):
        jira = client([FakeResponse(payload={"displayName": "User"})])

        self.assertEqual(jira.detect_api_version(), "3")
        self.assertEqual(len(jira.session.calls), 1)

    def test_falls_back_to_api_version_two_after_not_found(self):
        jira = client([FakeResponse(404, {}), FakeResponse(payload={"name": "user"})])

        self.assertEqual(jira.detect_api_version(), "2")
        self.assertEqual(len(jira.session.calls), 2)

    def test_falls_back_to_api_two_without_following_login_redirect(self):
        jira = client(
            [
                FakeResponse(302),
                FakeResponse(payload={"name": "user"}),
            ]
        )

        self.assertEqual(jira.detect_api_version(), "2")
        self.assertEqual(len(jira.session.calls), 2)
        self.assertTrue(
            all(
                call_kwargs["allow_redirects"] is False
                for _, call_kwargs in jira.session.calls
            )
        )

    def test_falls_back_to_api_two_after_non_json_success(self):
        jira = client(
            [
                FakeResponse(payload=ValueError("HTML login page")),
                FakeResponse(payload={"name": "user"}),
            ]
        )

        self.assertEqual(jira.detect_api_version(), "2")

    def test_authentication_failure_does_not_probe_second_version(self):
        jira = client([FakeResponse(401, {"token": "must-not-appear"})])

        with self.assertRaisesRegex(SetupDiscoveryError, "учетные данные"):
            jira.detect_api_version()

        self.assertEqual(len(jira.session.calls), 1)

    def test_unavailable_versions_do_not_include_response_body(self):
        jira = client(
            [
                FakeResponse(404, {"secret": "first-body"}),
                FakeResponse(500, {"secret": "second-body"}),
            ]
        )

        with self.assertRaises(SetupDiscoveryError) as caught:
            jira.detect_api_version()

        message = str(caught.exception)
        self.assertNotIn("first-body", message)
        self.assertNotIn("second-body", message)

    def test_api_three_projects_are_paged_and_sorted(self):
        jira = client(
            [
                FakeResponse(
                    payload={
                        "values": [{"key": "Z", "name": "zulu"}],
                        "startAt": 0,
                        "maxResults": 1,
                        "total": 2,
                    }
                ),
                FakeResponse(
                    payload={
                        "values": [{"key": "A", "name": "Alpha"}],
                        "startAt": 1,
                        "maxResults": 1,
                        "total": 2,
                    }
                ),
            ]
        )
        jira.api_version = "3"

        projects = jira.list_projects()

        self.assertEqual([project.key for project in projects], ["A", "Z"])

    def test_api_two_projects_use_list_response(self):
        jira = client([FakeResponse(payload=[{"key": "PM", "name": "Project"}])])
        jira.api_version = "2"

        projects = jira.list_projects()

        self.assertEqual(projects[0].key, "PM")

    def test_manual_project_is_verified_by_exact_lookup(self):
        jira = client([FakeResponse(payload={"key": "PM", "name": "Project"})])
        jira.api_version = "2"

        project = jira.get_project("PM")

        self.assertEqual(project.name, "Project")
        self.assertTrue(jira.session.calls[0][0].endswith("/project/PM"))

    def test_modern_issue_types_are_paged_and_sorted(self):
        jira = client(
            [
                FakeResponse(
                    payload={
                        "startAt": 0,
                        "maxResults": 1,
                        "total": 2,
                        "isLast": False,
                        "values": [{"id": "2", "name": "Zulu"}],
                    }
                ),
                FakeResponse(
                    payload={
                        "startAt": 1,
                        "maxResults": 1,
                        "total": 2,
                        "isLast": True,
                        "values": [{"id": "1", "name": "Alpha"}],
                    }
                ),
            ]
        )
        jira.api_version = "2"

        issue_types = jira.list_issue_types("PM")

        self.assertEqual([item.name for item in issue_types], ["Alpha", "Zulu"])
        self.assertTrue(
            all(
                url.endswith("/issue/createmeta/PM/issuetypes")
                for url, _ in jira.session.calls
            )
        )
        self.assertEqual(
            [kwargs["params"]["startAt"] for _, kwargs in jira.session.calls],
            [0, 1],
        )

    def test_modern_required_fields_are_paged_and_normalized(self):
        jira = client(
            [
                FakeResponse(
                    payload={
                        "startAt": 0,
                        "maxResults": 1,
                        "total": 2,
                        "isLast": False,
                        "values": [
                            {
                                "fieldId": "summary",
                                "name": "Summary",
                                "required": True,
                                "schema": {"type": "string"},
                            }
                        ],
                    }
                ),
                FakeResponse(
                    payload={
                        "startAt": 1,
                        "maxResults": 1,
                        "total": 2,
                        "isLast": True,
                        "values": [
                            {
                                "fieldId": "customfield_1",
                                "name": "Risk",
                                "required": True,
                                "hasDefaultValue": False,
                                "schema": {"type": "option"},
                                "allowedValues": [
                                    {"id": "1", "value": "Security"}
                                ],
                            }
                        ],
                    }
                ),
            ]
        )
        jira.api_version = "2"

        fields = jira.required_fields("PM", "10001")

        self.assertEqual([field.field_id for field in fields], ["customfield_1"])
        self.assertEqual(fields[0].to_jira_value("Security"), {"value": "Security"})
        self.assertTrue(
            all(
                url.endswith("/issue/createmeta/PM/issuetypes/10001")
                for url, _ in jira.session.calls
            )
        )

    def test_issue_types_fall_back_to_legacy_createmeta_after_404(self):
        metadata = {
            "projects": [
                {"issuetypes": [{"id": "10001", "name": "Task", "fields": {}}]}
            ]
        }
        jira = client([FakeResponse(404, {}), FakeResponse(payload=metadata)])
        jira.api_version = "2"

        issue_types = jira.list_issue_types("PM")

        self.assertEqual([item.name for item in issue_types], ["Task"])
        self.assertTrue(jira.session.calls[1][0].endswith("/issue/createmeta"))

    def test_required_fields_fall_back_to_legacy_createmeta_after_404(self):
        metadata = {
            "projects": [
                {
                    "issuetypes": [
                        {
                            "id": "10001",
                            "name": "Task",
                            "fields": {
                                "customfield_1": {
                                    "name": "Risk",
                                    "required": True,
                                    "schema": {"type": "option"},
                                }
                            },
                        }
                    ]
                }
            ]
        }
        jira = client([FakeResponse(404, {}), FakeResponse(payload=metadata)])
        jira.api_version = "2"

        fields = jira.required_fields("PM", "10001")

        self.assertEqual([field.field_id for field in fields], ["customfield_1"])
        self.assertTrue(jira.session.calls[1][0].endswith("/issue/createmeta"))

    def test_issue_types_priorities_and_required_fields_are_normalized(self):
        jira = client(
            [
                FakeResponse(
                    payload={
                        "startAt": 0,
                        "maxResults": 50,
                        "total": 1,
                        "isLast": True,
                        "values": [{"id": "10001", "name": "Task"}],
                    }
                ),
                FakeResponse(
                    payload=[
                        {"id": "2", "name": "Medium"},
                        {"id": "1", "name": "High"},
                    ]
                ),
                FakeResponse(
                    payload={
                        "startAt": 0,
                        "maxResults": 50,
                        "total": 3,
                        "isLast": True,
                        "values": [
                            {
                                "fieldId": "summary",
                                "name": "Summary",
                                "required": True,
                                "schema": {"type": "string"},
                            },
                            {
                                "fieldId": "customfield_1",
                                "name": "Risk",
                                "required": True,
                                "schema": {
                                    "type": "option",
                                    "custom": "select",
                                },
                                "allowedValues": [
                                    {"id": "1", "value": "Security"}
                                ],
                            },
                            {
                                "fieldId": "labels",
                                "name": "Labels",
                                "required": False,
                                "schema": {
                                    "type": "array",
                                    "items": "string",
                                },
                            },
                        ],
                    }
                ),
            ]
        )
        jira.api_version = "2"

        issue_types = jira.list_issue_types("PM")
        priorities = jira.list_priorities()
        fields = jira.required_fields("PM", "10001")

        self.assertEqual(issue_types[0].name, "Task")
        self.assertEqual(priorities, ("High", "Medium"))
        self.assertEqual([field.field_id for field in fields], ["customfield_1"])
        self.assertEqual(fields[0].to_jira_value("Security"), {"value": "Security"})

    def test_supported_required_field_values_are_converted(self):
        fields_page = {
            "startAt": 0,
            "maxResults": 50,
            "total": 8,
            "isLast": True,
            "values": [
                {
                    "fieldId": "a",
                    "name": "Text",
                    "required": True,
                    "schema": {"type": "string"},
                },
                {
                    "fieldId": "b",
                    "name": "Number",
                    "required": True,
                    "schema": {"type": "number"},
                },
                {
                    "fieldId": "c",
                    "name": "Options",
                    "required": True,
                    "schema": {"type": "array", "items": "option"},
                },
                {
                    "fieldId": "d",
                    "name": "User",
                    "required": True,
                    "schema": {"type": "user"},
                },
                {
                    "fieldId": "e",
                    "name": "Component",
                    "required": True,
                    "schema": {"type": "component"},
                },
                {
                    "fieldId": "f",
                    "name": "Version",
                    "required": True,
                    "schema": {"type": "version"},
                },
                {
                    "fieldId": "g",
                    "name": "Date",
                    "required": True,
                    "schema": {"type": "date"},
                },
                {
                    "fieldId": "h",
                    "name": "Bool",
                    "required": True,
                    "schema": {"type": "boolean"},
                },
            ],
        }
        jira = client([FakeResponse(payload=fields_page)])
        jira.api_version = "2"

        fields = {field.field_id: field for field in jira.required_fields("PM", "1")}

        self.assertEqual(fields["a"].to_jira_value("hello"), "hello")
        self.assertEqual(fields["b"].to_jira_value("7.5"), 7.5)
        self.assertEqual(
            fields["c"].to_jira_value(["A", "B"]), [{"value": "A"}, {"value": "B"}]
        )
        self.assertEqual(fields["d"].to_jira_value("oleg"), {"name": "oleg"})
        self.assertEqual(fields["e"].to_jira_value("Backend"), {"name": "Backend"})
        self.assertEqual(fields["f"].to_jira_value("1.0"), {"name": "1.0"})
        self.assertEqual(fields["g"].to_jira_value("2026-08-13"), "2026-08-13")
        self.assertIs(fields["h"].to_jira_value("true"), True)

    def test_unsupported_required_field_reports_only_safe_metadata(self):
        fields_page = {
            "startAt": 0,
            "maxResults": 50,
            "total": 1,
            "isLast": True,
            "values": [
                {
                    "fieldId": "customfield_9",
                    "name": "Secret field",
                    "required": True,
                    "schema": {"type": "mystery"},
                }
            ],
        }
        jira = client([FakeResponse(payload=fields_page)])
        jira.api_version = "2"

        with self.assertRaisesRegex(
            SetupDiscoveryError, "customfield_9.*Secret field.*mystery"
        ):
            jira.required_fields("PM", "1")

    def test_permissions_require_issue_creation_and_attachments(self):
        jira = client(
            [
                FakeResponse(
                    payload={
                        "permissions": {
                            "CREATE_ISSUES": {"havePermission": True},
                            "CREATE_ATTACHMENTS": {"havePermission": False},
                        }
                    }
                )
            ]
        )
        jira.api_version = "2"

        result = jira.validate_permissions("PM")

        self.assertFalse(result.ok)
        self.assertTrue(result.create_issues)
        self.assertFalse(result.create_attachments)


if __name__ == "__main__":
    unittest.main()
