"""Validation facade used by the interactive setup wizard."""

from __future__ import annotations

import os
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..mpvm import MaxPatrolClient
from .discovery import JiraSetupClient
from .state import SetupState


@dataclass(frozen=True)
class CheckResult:
    """Result of one safe connectivity check."""

    ok: bool
    message: str


@dataclass(frozen=True)
class ValidationSummary:
    """Result of the final non-mutating integration validation."""

    ok: bool
    message: str


class SetupValidationError(RuntimeError):
    """Report a validation failure that is safe to display."""


class SetupValidationService:
    """Coordinate connection and metadata checks without writing files."""

    def __init__(
        self,
        mpvm_client_factory: Callable[[dict[str, Any]], Any] = MaxPatrolClient,
        jira_client_factory: Callable[[SetupState], JiraSetupClient] | None = None,
    ):
        self.mpvm_client_factory = mpvm_client_factory
        self.jira_client_factory = jira_client_factory or self._jira_client

    def validate_mpvm(self, state: SetupState) -> CheckResult:
        """Validate MaxPatrol VM URL, token and TLS settings."""
        variable = "MPVM_SETUP_TOKEN_" + secrets.token_hex(12).upper()
        os.environ[variable] = state.mpvm_token
        try:
            config = {
                "base_url": state.mpvm_url.rstrip("/"),
                "access_token_env": variable,
                "verify_ssl": state.mpvm_tls.config_value(),
                "timeout_seconds": 60,
                "retries": 3,
            }
            client = self.mpvm_client_factory(config)
            client.validate_connection()
            return CheckResult(True, "Подключение к MaxPatrol VM работает")
        except Exception as exc:  # User-facing boundary for remote clients.
            return CheckResult(
                False,
                self._safe_message(
                    "Не удалось подключиться к MaxPatrol VM", exc, state
                ),
            )
        finally:
            os.environ.pop(variable, None)

    def connect_jira(self, state: SetupState) -> JiraSetupClient:
        """Create a Jira discovery client and determine its API version."""
        try:
            client = self.jira_client_factory(state)
            detected = client.detect_api_version()
            if state.jira_api_version is None:
                state.jira_api_version = detected
            elif state.jira_api_version != detected:
                client.api_version = state.jira_api_version
            return client
        except Exception as exc:
            raise SetupValidationError(
                self._safe_message("Не удалось подключиться к Jira", exc, state)
            ) from exc

    def validate_complete(self, state: SetupState) -> ValidationSummary:
        """Check every selected value and both required Jira permissions."""
        mpvm = self.validate_mpvm(state)
        if not mpvm.ok:
            return ValidationSummary(False, mpvm.message)
        try:
            jira = self.connect_jira(state)
            project = jira.get_project(state.project_key)
            issue_types = jira.list_issue_types(project.key)
            selected = next(
                (
                    item
                    for item in issue_types
                    if state.issue_type.casefold()
                    in {item.id.casefold(), item.name.casefold()}
                ),
                None,
            )
            if selected is None:
                raise SetupValidationError(
                    "Выбранный тип задачи недоступен в проекте Jira"
                )

            priorities = {name.casefold() for name in jira.list_priorities()}
            desired = [*state.priority_map.values(), state.default_priority]
            missing = sorted(
                {name for name in desired if name and name.casefold() not in priorities}
            )
            if missing:
                raise SetupValidationError(
                    "В Jira не найдены выбранные приоритеты: " + ", ".join(missing)
                )

            required = jira.required_fields(project.key, selected.id)
            missing_fields = [
                field.name
                for field in required
                if field.field_id not in state.additional_fields
            ]
            if missing_fields:
                raise SetupValidationError(
                    "Не заполнены обязательные поля Jira: " + ", ".join(missing_fields)
                )

            permissions = jira.validate_permissions(project.key)
            if not permissions.create_issues:
                raise SetupValidationError("Нет разрешения Jira Create issues")
            if not permissions.create_attachments:
                raise SetupValidationError("Нет разрешения Jira Create attachments")
            return ValidationSummary(
                True,
                "Проверены MaxPatrol VM, Jira, проект, тип задачи, "
                "приоритеты, обязательные поля и разрешения",
            )
        except Exception as exc:  # Convert remote failures to safe UI text.
            return ValidationSummary(
                False,
                self._safe_message("Итоговая проверка не пройдена", exc, state),
            )

    @staticmethod
    def _jira_client(state: SetupState) -> JiraSetupClient:
        return JiraSetupClient(
            base_url=state.jira_url,
            auth_mode=state.jira_auth_mode,
            token=state.jira_token,
            user=state.jira_user,
            verify_ssl=state.jira_tls.config_value(),
        )

    @staticmethod
    def _safe_message(prefix: str, error: Exception, state: SetupState) -> str:
        message = str(error).strip() or type(error).__name__
        for secret in (state.mpvm_token, state.jira_token):
            if secret:
                message = message.replace(secret, "<скрыто>")
        return f"{prefix}: {message}"
