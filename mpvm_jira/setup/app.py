"""Full-screen Textual application for first-time configuration."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from textual.app import App

from .discovery import JiraIssueType, JiraProject, JiraSetupClient, RequiredField
from .screens import (
    AdvancedScreen,
    FileChoiceScreen,
    IssueTypeScreen,
    JiraScreen,
    MpvmScreen,
    PriorityScreen,
    ProjectScreen,
    RequiredFieldsScreen,
    SuccessScreen,
    SummaryScreen,
    WarningScreen,
)
from .state import SetupState
from .validation import SetupValidationService
from .writer import save_configuration


class SetupWizardApp(App[None]):
    """Guide a user from empty files to a validated integration config."""

    TITLE = "MaxPatrol VM → Jira · Мастер настройки"
    CSS = """
    Screen {
        align: center middle;
        background: #0f172a;
    }
    .panel {
        width: 88%;
        max-width: 100;
        height: auto;
        max-height: 94%;
        padding: 1 2;
        border: round #2563eb;
        background: #111827;
    }
    .title {
        text-style: bold;
        color: #e2e8f0;
        margin-bottom: 1;
    }
    .step, .hint {
        color: #94a3b8;
        margin-bottom: 1;
    }
    .warning { color: #f59e0b; }
    #status { min-height: 2; margin-top: 1; color: #22c55e; }
    #status.error { color: #f87171; }
    .buttons { height: auto; align-horizontal: right; margin-top: 1; }
    Button { margin-left: 1; }
    Input, Select { margin-bottom: 1; }
    """

    def __init__(
        self,
        base_dir: Path,
        validation_service: SetupValidationService | None = None,
        *,
        save_function: Callable[..., Any] = save_configuration,
    ):
        super().__init__()
        self.base_dir = base_dir.expanduser().resolve()
        self.validation_service = validation_service or SetupValidationService()
        self.save_function = save_function
        self.state = SetupState()
        self.jira_client: JiraSetupClient | Any = None
        self.projects: tuple[JiraProject, ...] = ()
        self.issue_types: tuple[JiraIssueType, ...] = ()
        self.priorities: tuple[str, ...] = ()
        self.required_fields: tuple[RequiredField, ...] = ()
        self.selected_issue_type_id = ""
        self.save_result: Any = None

    def on_mount(self) -> None:
        self.push_screen(WarningScreen())

    def on_unmount(self) -> None:
        self.state.clear_secrets()

    def _show(self, screen) -> None:
        self.switch_screen(screen)

    def show_warning(self) -> None:
        self._show(WarningScreen())

    def after_warning(self) -> None:
        if (self.base_dir / ".env").exists() or (
            self.base_dir / "config.yaml"
        ).exists():
            self._show(FileChoiceScreen())
        else:
            self.show_mpvm()

    def show_mpvm(self) -> None:
        self._show(MpvmScreen())

    def show_jira(self) -> None:
        self._show(JiraScreen())

    def show_projects(self) -> None:
        self._show(ProjectScreen())

    def show_issue_types(self) -> None:
        self._show(IssueTypeScreen())

    def show_priorities(self) -> None:
        self._show(PriorityScreen())

    def show_required_fields(self) -> None:
        self._show(RequiredFieldsScreen())

    def show_advanced(self) -> None:
        self._show(AdvancedScreen())

    def show_summary(self) -> None:
        self._show(SummaryScreen())

    def show_success(self) -> None:
        self._show(SuccessScreen())
