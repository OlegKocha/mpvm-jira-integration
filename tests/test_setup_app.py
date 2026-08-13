import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock

from textual.widgets import Checkbox, Input, Select, Static

from mpvm_jira.setup.app import SetupWizardApp
from mpvm_jira.setup.discovery import (
    JiraIssueType,
    JiraProject,
    PermissionResult,
    RequiredField,
)
from mpvm_jira.setup.validation import CheckResult, ValidationSummary


class FakeJiraClient:
    api_version = "2"

    def list_projects(self):
        return (
            JiraProject("PM", "Project Management"),
            JiraProject("SEC", "Security"),
        )

    def get_project(self, key):
        return JiraProject(key, f"Project {key}")

    def list_issue_types(self, project_key):
        return (
            JiraIssueType("10001", "Task"),
            JiraIssueType("10002", "Bug"),
        )

    def list_priorities(self):
        return ("Critical", "High", "Medium", "Low")

    def required_fields(self, project_key, issue_type):
        return (
            RequiredField(
                "customfield_1",
                "Security category",
                "option",
                options=("Application", "Infrastructure"),
            ),
        )

    def validate_permissions(self, project_key):
        return PermissionResult(True, True)


class FakeValidationService:
    def __init__(self):
        self.jira = FakeJiraClient()

    def validate_mpvm(self, state):
        return CheckResult(True, "MP VM доступен")

    def connect_jira(self, state):
        state.jira_api_version = "2"
        return self.jira

    def validate_complete(self, state):
        return ValidationSummary(True, "Все проверки пройдены")


class FailingFinalValidationService(FakeValidationService):
    def validate_complete(self, state):
        return ValidationSummary(False, "Нет разрешения Create attachments")


class SetupWizardNavigationTests(unittest.IsolatedAsyncioTestCase):
    async def test_warning_is_first_and_exit_creates_no_files(self):
        with TemporaryDirectory() as directory:
            base_dir = Path(directory)
            app = SetupWizardApp(base_dir, FakeValidationService())
            app.state.mpvm_token = "temporary-mpvm-secret"
            app.state.jira_token = "temporary-jira-secret"

            async with app.run_test(size=(110, 38)) as pilot:
                visible = " ".join(
                    str(widget.render()) for widget in app.screen.query(Static)
                )
                self.assertIn("MaxPatrol VM", visible)
                self.assertIn("Jira", visible)
                self.assertIn("ручную настройку", visible)
                await pilot.click("#exit")

            self.assertFalse((base_dir / ".env").exists())
            self.assertFalse((base_dir / "config.yaml").exists())
            self.assertEqual(app.state.mpvm_token, "")
            self.assertEqual(app.state.jira_token, "")

    async def test_existing_files_offer_backup_or_overwrite(self):
        with TemporaryDirectory() as directory:
            base_dir = Path(directory)
            (base_dir / ".env").write_text("existing", encoding="utf-8")
            app = SetupWizardApp(base_dir, FakeValidationService())

            async with app.run_test(size=(110, 38)) as pilot:
                await pilot.click("#continue")
                await pilot.pause()
                self.assertIsNotNone(app.screen.query_one("#backup"))
                self.assertIsNotNone(app.screen.query_one("#overwrite"))
                await pilot.click("#backup")
                await pilot.pause()

                token = app.screen.query_one("#mpvm-token", Input)
                self.assertTrue(token.password)
                self.assertEqual(app.state.file_strategy.value, "backup")

    async def test_no_existing_files_open_masked_mpvm_credentials(self):
        with TemporaryDirectory() as directory:
            app = SetupWizardApp(Path(directory), FakeValidationService())

            async with app.run_test(size=(110, 38)) as pilot:
                await pilot.click("#continue")
                await pilot.pause()

                token = app.screen.query_one("#mpvm-token", Input)
                self.assertTrue(token.password)
                self.assertEqual(list(app.screen.query("#show-mpvm-token")), [])

    async def test_mpvm_tls_is_selected_before_connection_validation(self):
        with TemporaryDirectory() as directory:
            app = SetupWizardApp(Path(directory), FakeValidationService())

            async with app.run_test(size=(110, 38)) as pilot:
                app.show_mpvm()
                await pilot.pause()
                tls = app.screen.query_one("#mpvm-tls", Select)
                ca_file = app.screen.query_one("#mpvm-ca", Input)
                confirmation = app.screen.query_one("#mpvm-tls-confirm", Checkbox)

                self.assertEqual(tls.value, "system")
                self.assertFalse(ca_file.display)
                self.assertFalse(confirmation.display)

                tls.value = "ca_file"
                await pilot.pause()
                self.assertTrue(ca_file.display)

    async def test_jira_tls_is_selected_before_api_detection(self):
        with TemporaryDirectory() as directory:
            app = SetupWizardApp(Path(directory), FakeValidationService())

            async with app.run_test(size=(110, 38)) as pilot:
                app.show_jira()
                await pilot.pause()
                tls = app.screen.query_one("#jira-tls", Select)
                ca_file = app.screen.query_one("#jira-ca", Input)
                confirmation = app.screen.query_one("#jira-tls-confirm", Checkbox)

                self.assertEqual(tls.value, "system")
                self.assertFalse(ca_file.display)
                self.assertFalse(confirmation.display)

                tls.value = "ca_file"
                await pilot.pause()
                self.assertTrue(ca_file.display)

    async def test_jira_auth_mode_changes_visible_fields(self):
        with TemporaryDirectory() as directory:
            app = SetupWizardApp(Path(directory), FakeValidationService())

            async with app.run_test(size=(110, 38)) as pilot:
                app.show_jira()
                await pilot.pause()
                user = app.screen.query_one("#jira-user", Input)
                token = app.screen.query_one("#jira-token", Input)
                self.assertTrue(user.display)
                self.assertTrue(token.password)

                select = app.screen.query_one("#jira-auth", Select)
                select.value = "bearer"
                await pilot.pause()
                self.assertFalse(user.display)

    async def test_summary_never_contains_tokens_and_success_saves_once(self):
        with TemporaryDirectory() as directory:
            saver = Mock()
            app = SetupWizardApp(
                Path(directory),
                FakeValidationService(),
                save_function=saver,
            )
            app.state.mpvm_url = "https://mpvm.example.org"
            app.state.mpvm_token = "mpvm-super-secret"
            app.state.jira_url = "https://jira.example.org"
            app.state.jira_token = "jira-super-secret"
            app.state.project_key = "PM"
            app.state.issue_type = "Task"

            async with app.run_test(size=(110, 38)) as pilot:
                app.show_summary()
                await pilot.pause()
                visible = str(app.screen.render())
                self.assertNotIn("mpvm-super-secret", visible)
                self.assertNotIn("jira-super-secret", visible)
                await pilot.click("#save")
                await pilot.pause(0.2)

                self.assertEqual(saver.call_count, 1)
                success = " ".join(
                    str(widget.render()) for widget in app.screen.query(Static)
                )
                self.assertIn("validate", success)
                self.assertIn("run", success)

    async def test_discovery_and_advanced_screens_can_be_composed(self):
        with TemporaryDirectory() as directory:
            app = SetupWizardApp(Path(directory), FakeValidationService())
            app.jira_client = FakeJiraClient()
            app.projects = app.jira_client.list_projects()
            app.issue_types = app.jira_client.list_issue_types("PM")
            app.priorities = app.jira_client.list_priorities()
            app.required_fields = app.jira_client.required_fields("PM", "10001")

            async with app.run_test(size=(110, 38)) as pilot:
                app.show_projects()
                await pilot.pause()
                self.assertIsNotNone(app.screen.query_one("#project-search"))

                app.show_issue_types()
                await pilot.pause()
                self.assertIsNotNone(app.screen.query_one("#issue-type-select"))

                app.show_priorities()
                await pilot.pause()
                self.assertIsNotNone(app.screen.query_one("#priority-high"))

                app.show_required_fields()
                await pilot.pause()
                self.assertIsNotNone(app.screen.query_one("#required-0"))

                app.show_advanced()
                await pilot.pause()
                self.assertEqual(list(app.screen.query("#mpvm-tls")), [])
                self.assertEqual(list(app.screen.query("#jira-tls")), [])
                self.assertIsNotNone(app.screen.query_one("#api-version", Select))

    async def test_disabled_tls_requires_explicit_confirmation(self):
        with TemporaryDirectory() as directory:
            app = SetupWizardApp(Path(directory), FakeValidationService())

            async with app.run_test(size=(110, 38)) as pilot:
                app.show_mpvm()
                await pilot.pause()
                app.screen.query_one("#mpvm-tls", Select).value = "disabled"
                await pilot.pause()
                await pilot.click("#next")
                await pilot.pause()

                status = str(app.screen.query_one("#status", Static).render())
                self.assertIn("Подтвердите риск", status)

    async def test_failed_final_validation_does_not_write_files(self):
        with TemporaryDirectory() as directory:
            saver = Mock()
            app = SetupWizardApp(
                Path(directory),
                FailingFinalValidationService(),
                save_function=saver,
            )

            async with app.run_test(size=(110, 38)) as pilot:
                app.show_summary()
                await pilot.pause()
                await pilot.click("#save")
                await pilot.pause(0.2)

                saver.assert_not_called()
                status = str(app.screen.query_one("#status", Static).render())
                self.assertIn("Create attachments", status)


if __name__ == "__main__":
    unittest.main()
