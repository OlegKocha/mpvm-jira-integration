"""Textual screens used by the console setup wizard."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Checkbox, Input, Label, Select, Static

from .state import FileStrategy, TlsSettings

if TYPE_CHECKING:
    from .app import SetupWizardApp


def _options(values: tuple[str, ...] | list[str]) -> list[tuple[str, str]]:
    return [(value, value) for value in values]


TLS_OPTIONS = [
    ("Системное хранилище сертификатов", "system"),
    ("Свой PEM-файл CA", "ca_file"),
    (
        "Отключить проверку (не рекомендуется)",
        "disabled",
    ),
]


class WizardScreen(Screen):
    """Base screen with common status and navigation helpers."""

    def status(self, message: str, *, error: bool = False) -> None:
        """Display a safe result or validation error."""
        widget = self.query_one("#status", Static)
        widget.update(message)
        widget.set_class(error, "error")

    @property
    def wizard(self) -> SetupWizardApp:
        """Return the concrete application type for type checkers."""
        return self.app  # type: ignore[return-value]


class WarningScreen(WizardScreen):
    """Explain connectivity requirements before collecting secrets."""

    def compose(self) -> ComposeResult:
        yield Vertical(
            Static("Настройка интеграции MaxPatrol VM → Jira", classes="title"),
            Static("Шаг 1 из 10 · Перед началом", classes="step"),
            Static(
                "Для корректной настройки стенды MaxPatrol VM и Jira "
                "должны быть доступны с этого компьютера. Мастер проверит "
                "подключения и права, но не создаст задачи. Если один из "
                "стендов сейчас недоступен, выйдите и используйте ручную "
                "настройку из README."
            ),
            Static("", id="status"),
            Horizontal(
                Button("Выйти", id="exit", variant="error"),
                Button("Продолжить", id="continue", variant="primary"),
                classes="buttons",
            ),
            classes="panel",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "exit":
            self.wizard.exit()
        elif event.button.id == "continue":
            self.wizard.after_warning()


class FileChoiceScreen(WizardScreen):
    """Choose how existing configuration files are preserved."""

    def compose(self) -> ComposeResult:
        existing = [
            name
            for name in (".env", "config.yaml")
            if (self.wizard.base_dir / name).exists()
        ]
        yield Vertical(
            Static("Найдены существующие файлы", classes="title"),
            Static("Шаг 2 из 10 · Сохранение", classes="step"),
            Static(
                "Обнаружено: " + ", ".join(existing) + ". Выберите, как "
                "мастер должен поступить с ними."
            ),
            Static("", id="status"),
            Horizontal(
                Button("Выйти", id="exit"),
                Button("Перезаписать", id="overwrite", variant="warning"),
                Button("Сделать backup", id="backup", variant="primary"),
                classes="buttons",
            ),
            classes="panel",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "exit":
            self.wizard.exit()
        elif event.button.id in {"overwrite", "backup"}:
            self.wizard.state.file_strategy = (
                FileStrategy.BACKUP
                if event.button.id == "backup"
                else FileStrategy.OVERWRITE
            )
            self.wizard.show_mpvm()


class MpvmScreen(WizardScreen):
    """Collect and validate MaxPatrol VM credentials."""

    def compose(self) -> ComposeResult:
        state = self.wizard.state
        yield VerticalScroll(
            Static("Подключение к MaxPatrol VM", classes="title"),
            Static("Шаг 3 из 10 · MaxPatrol VM", classes="step"),
            Label("Адрес MaxPatrol VM"),
            Input(
                value=state.mpvm_url,
                placeholder="https://mpvm.example.org",
                id="mpvm-url",
            ),
            Label("Персональный reference-токен"),
            Input(
                value=state.mpvm_token,
                password=True,
                id="mpvm-token",
            ),
            Static("Токен будет сохранен только в .env.", classes="hint"),
            Label("Проверка TLS-сертификата"),
            Select(
                TLS_OPTIONS,
                value=state.mpvm_tls.mode,
                allow_blank=False,
                id="mpvm-tls",
            ),
            Input(
                value=state.mpvm_tls.ca_file,
                placeholder="/etc/ssl/company-ca.pem",
                id="mpvm-ca",
            ),
            Checkbox(
                "Я понимаю риск отключения проверки TLS",
                id="mpvm-tls-confirm",
            ),
            Static("", id="status"),
            Horizontal(
                Button("Назад", id="back"),
                Button("Проверить и продолжить", id="next", variant="primary"),
                classes="buttons",
            ),
            classes="panel",
        )
        self.call_after_refresh(self._update_tls_fields)

    def _update_tls_fields(self) -> None:
        mode = str(self.query_one("#mpvm-tls", Select).value)
        self.query_one("#mpvm-ca", Input).display = mode == "ca_file"
        self.query_one("#mpvm-tls-confirm", Checkbox).display = mode == "disabled"

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "mpvm-tls":
            self._update_tls_fields()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self.wizard.show_warning()
            return
        if event.button.id != "next":
            return
        state = self.wizard.state
        state.mpvm_url = self.query_one("#mpvm-url", Input).value.strip()
        state.mpvm_token = self.query_one("#mpvm-token", Input).value
        tls_mode = str(self.query_one("#mpvm-tls", Select).value)
        if tls_mode == "disabled" and not self.query_one(
            "#mpvm-tls-confirm", Checkbox
        ).value:
            self.status(
                "Подтвердите риск отключения проверки TLS.",
                error=True,
            )
            return
        state.mpvm_tls = TlsSettings(
            mode=tls_mode,  # type: ignore[arg-type]
            ca_file=self.query_one("#mpvm-ca", Input).value.strip(),
        )
        if not state.mpvm_url or not state.mpvm_token:
            self.status("Укажите адрес и reference-токен.", error=True)
            return
        try:
            state.mpvm_tls.config_value()
        except ValueError as exc:
            self.status(str(exc), error=True)
            return
        self.status("Проверяем подключение…")
        result = await asyncio.to_thread(
            self.wizard.validation_service.validate_mpvm, state
        )
        if not result.ok:
            self.status(result.message, error=True)
            return
        self.status(result.message)
        self.wizard.show_jira()


class JiraScreen(WizardScreen):
    """Collect Jira credentials and establish a discovery client."""

    def compose(self) -> ComposeResult:
        state = self.wizard.state
        basic = state.jira_auth_mode == "basic"
        yield VerticalScroll(
            Static("Подключение к Jira", classes="title"),
            Static("Шаг 4 из 10 · Jira", classes="step"),
            Label("Адрес Jira"),
            Input(
                value=state.jira_url,
                placeholder="https://jira.example.org",
                id="jira-url",
            ),
            Label("Способ аутентификации"),
            Select(
                [("Логин + API-токен", "basic"), ("Bearer / PAT", "bearer")],
                value=state.jira_auth_mode,
                allow_blank=False,
                id="jira-auth",
            ),
            Label("Пользователь Jira", id="jira-user-label"),
            Input(value=state.jira_user, id="jira-user"),
            Label("API-токен / PAT"),
            Input(value=state.jira_token, password=True, id="jira-token"),
            Static("Токен будет сохранен только в .env.", classes="hint"),
            Label("Проверка TLS-сертификата"),
            Select(
                TLS_OPTIONS,
                value=state.jira_tls.mode,
                allow_blank=False,
                id="jira-tls",
            ),
            Input(
                value=state.jira_tls.ca_file,
                placeholder="/etc/ssl/company-ca.pem",
                id="jira-ca",
            ),
            Checkbox(
                "Я понимаю риск отключения проверки TLS",
                id="jira-tls-confirm",
            ),
            Static("", id="status"),
            Horizontal(
                Button("Назад", id="back"),
                Button("Проверить и продолжить", id="next", variant="primary"),
                classes="buttons",
            ),
            classes="panel",
        )
        self.call_after_refresh(self._show_basic_fields, basic)
        self.call_after_refresh(self._update_tls_fields)

    def _show_basic_fields(self, visible: bool) -> None:
        self.query_one("#jira-user", Input).display = visible
        self.query_one("#jira-user-label", Label).display = visible

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "jira-auth":
            self._show_basic_fields(event.value == "basic")
        elif event.select.id == "jira-tls":
            self._update_tls_fields()

    def _update_tls_fields(self) -> None:
        mode = str(self.query_one("#jira-tls", Select).value)
        self.query_one("#jira-ca", Input).display = mode == "ca_file"
        self.query_one("#jira-tls-confirm", Checkbox).display = mode == "disabled"

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self.wizard.show_mpvm()
            return
        if event.button.id != "next":
            return
        state = self.wizard.state
        state.jira_url = self.query_one("#jira-url", Input).value.strip()
        state.jira_auth_mode = str(self.query_one("#jira-auth", Select).value)  # type: ignore[assignment]
        state.jira_user = self.query_one("#jira-user", Input).value.strip()
        state.jira_token = self.query_one("#jira-token", Input).value
        tls_mode = str(self.query_one("#jira-tls", Select).value)
        if tls_mode == "disabled" and not self.query_one(
            "#jira-tls-confirm", Checkbox
        ).value:
            self.status(
                "Подтвердите риск отключения проверки TLS.",
                error=True,
            )
            return
        state.jira_tls = TlsSettings(
            mode=tls_mode,  # type: ignore[arg-type]
            ca_file=self.query_one("#jira-ca", Input).value.strip(),
        )
        if not state.jira_url or not state.jira_token:
            self.status("Укажите адрес Jira и токен.", error=True)
            return
        if state.jira_auth_mode == "basic" and not state.jira_user:
            self.status("Для выбранного способа укажите пользователя.", error=True)
            return
        try:
            state.jira_tls.config_value()
        except ValueError as exc:
            self.status(str(exc), error=True)
            return
        self.status("Определяем REST API и загружаем проекты…")
        try:
            jira = await asyncio.to_thread(
                self.wizard.validation_service.connect_jira, state
            )
            projects = await asyncio.to_thread(jira.list_projects)
        except Exception as exc:
            self.status(str(exc), error=True)
            return
        self.wizard.jira_client = jira
        self.wizard.projects = projects
        self.wizard.show_projects()


class ProjectScreen(WizardScreen):
    """Select a searchable Jira project or enter its key manually."""

    manual = False

    def compose(self) -> ComposeResult:
        projects = self.wizard.projects
        options = [(f"{item.name} ({item.key})", item.key) for item in projects]
        initial = self.wizard.state.project_key or (
            options[0][1] if options else Select.BLANK
        )
        yield Vertical(
            Static("Проект Jira", classes="title"),
            Static("Шаг 5 из 10 · Проект", classes="step"),
            Label("Поиск по названию или ключу"),
            Input(id="project-search"),
            Select(options, value=initial, id="project-select"),
            Button("Ввести ключ вручную", id="manual-project"),
            Input(placeholder="PM", id="project-manual"),
            Static("", id="status"),
            Horizontal(
                Button("Назад", id="back"),
                Button("Далее", id="next", variant="primary"),
                classes="buttons",
            ),
            classes="panel",
        )
        self.call_after_refresh(self._set_manual, False)

    def _set_manual(self, enabled: bool) -> None:
        self.manual = enabled
        self.query_one("#project-manual", Input).display = enabled
        self.query_one("#project-select", Select).display = not enabled
        self.query_one("#project-search", Input).display = not enabled

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "project-search":
            return
        search = event.value.casefold()
        choices = [
            (f"{item.name} ({item.key})", item.key)
            for item in self.wizard.projects
            if search in item.name.casefold() or search in item.key.casefold()
        ]
        select = self.query_one("#project-select", Select)
        select.set_options(choices)
        if choices:
            select.value = choices[0][1]

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self.wizard.show_jira()
            return
        if event.button.id == "manual-project":
            self._set_manual(not self.manual)
            return
        if event.button.id != "next":
            return
        try:
            if self.manual:
                key = self.query_one("#project-manual", Input).value.strip()
                project = await asyncio.to_thread(
                    self.wizard.jira_client.get_project, key
                )
                key = project.key
            else:
                key = str(self.query_one("#project-select", Select).value)
            issue_types = await asyncio.to_thread(
                self.wizard.jira_client.list_issue_types, key
            )
        except Exception as exc:
            self.status(str(exc), error=True)
            return
        self.wizard.state.project_key = key
        self.wizard.issue_types = issue_types
        self.wizard.show_issue_types()


class IssueTypeScreen(WizardScreen):
    """Select or manually enter a Jira issue type."""

    manual = False

    def compose(self) -> ComposeResult:
        types = self.wizard.issue_types
        options = [(item.name, item.id) for item in types]
        initial = options[0][1] if options else Select.BLANK
        yield Vertical(
            Static("Тип задачи Jira", classes="title"),
            Static("Шаг 6 из 10 · Тип задачи", classes="step"),
            Select(options, value=initial, id="issue-type-select"),
            Button("Ввести название вручную", id="manual-issue-type"),
            Input(placeholder="Task", id="issue-type-manual"),
            Static("", id="status"),
            Horizontal(
                Button("Назад", id="back"),
                Button("Далее", id="next", variant="primary"),
                classes="buttons",
            ),
            classes="panel",
        )
        self.call_after_refresh(self._set_manual, False)

    def _set_manual(self, enabled: bool) -> None:
        self.manual = enabled
        self.query_one("#issue-type-manual", Input).display = enabled
        self.query_one("#issue-type-select", Select).display = not enabled

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self.wizard.show_projects()
            return
        if event.button.id == "manual-issue-type":
            self._set_manual(not self.manual)
            return
        if event.button.id != "next":
            return
        selected_value = (
            self.query_one("#issue-type-manual", Input).value.strip()
            if self.manual
            else str(self.query_one("#issue-type-select", Select).value)
        )
        selected = next(
            (
                item
                for item in self.wizard.issue_types
                if selected_value.casefold()
                in {item.id.casefold(), item.name.casefold()}
            ),
            None,
        )
        if selected is None:
            self.status("Указанный тип задачи не найден.", error=True)
            return
        try:
            priorities = await asyncio.to_thread(
                self.wizard.jira_client.list_priorities
            )
        except Exception as exc:
            self.status(str(exc), error=True)
            return
        self.wizard.state.issue_type = selected.name
        self.wizard.selected_issue_type_id = selected.id
        self.wizard.priorities = priorities
        self.wizard.show_priorities()


class PriorityScreen(WizardScreen):
    """Map MaxPatrol VM importance values to Jira priorities."""

    LEVELS = ("High", "Medium", "Low", "Undefined")

    def _default(self, level: str) -> str:
        priorities = self.wizard.priorities
        target = "Medium" if level == "Undefined" else level
        return next(
            (item for item in priorities if item.casefold() == target.casefold()),
            priorities[0] if priorities else "",
        )

    def compose(self) -> ComposeResult:
        widgets: list[Any] = [
            Static("Соответствие приоритетов", classes="title"),
            Static("Шаг 7 из 10 · Приоритеты", classes="step"),
            Static(
                "Выберите приоритет Jira для каждого значения значимости "
                "актива MaxPatrol VM."
            ),
        ]
        for level in self.LEVELS:
            widgets.extend(
                [
                    Label(level),
                    Select(
                        _options(list(self.wizard.priorities)),
                        value=self.wizard.state.priority_map.get(
                            level, self._default(level)
                        ),
                        allow_blank=False,
                        id=f"priority-{level.lower()}",
                    ),
                ]
            )
        widgets.extend(
            [
                Static("", id="status"),
                Horizontal(
                    Button("Назад", id="back"),
                    Button("Далее", id="next", variant="primary"),
                    classes="buttons",
                ),
            ]
        )
        yield VerticalScroll(*widgets, classes="panel")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self.wizard.show_issue_types()
            return
        if event.button.id != "next":
            return
        mapping = {
            level: str(self.query_one(f"#priority-{level.lower()}", Select).value)
            for level in self.LEVELS
        }
        self.wizard.state.priority_map = mapping
        self.wizard.state.default_priority = mapping["Undefined"]
        try:
            fields = await asyncio.to_thread(
                self.wizard.jira_client.required_fields,
                self.wizard.state.project_key,
                self.wizard.selected_issue_type_id,
            )
        except Exception as exc:
            self.status(str(exc), error=True)
            return
        self.wizard.required_fields = fields
        if fields:
            self.wizard.show_required_fields()
        else:
            self.wizard.show_advanced()


class RequiredFieldsScreen(WizardScreen):
    """Collect supported required fields from Jira create metadata."""

    def compose(self) -> ComposeResult:
        widgets: list[Any] = [
            Static("Обязательные поля Jira", classes="title"),
            Static("Шаг 8 из 10 · Поля задачи", classes="step"),
        ]
        for index, field in enumerate(self.wizard.required_fields):
            widget_id = f"required-{index}"
            widgets.append(Label(f"{field.name} ({field.field_id})"))
            if field.kind == "boolean":
                widgets.append(
                    Select(
                        [("Да", "true"), ("Нет", "false")],
                        value="false",
                        allow_blank=False,
                        id=widget_id,
                    )
                )
            elif field.options:
                widgets.append(
                    Select(
                        _options(list(field.options)),
                        value=field.options[0],
                        allow_blank=False,
                        id=widget_id,
                    )
                )
            else:
                widgets.append(Input(id=widget_id))
        widgets.extend(
            [
                Static("", id="status"),
                Horizontal(
                    Button("Назад", id="back"),
                    Button("Далее", id="next", variant="primary"),
                    classes="buttons",
                ),
            ]
        )
        yield VerticalScroll(*widgets, classes="panel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self.wizard.show_priorities()
            return
        if event.button.id != "next":
            return
        values: dict[str, Any] = {}
        try:
            for index, field in enumerate(self.wizard.required_fields):
                widget = self.query_one(f"#required-{index}")
                raw: Any
                if isinstance(widget, Select):
                    raw = widget.value
                else:
                    raw = widget.value
                    if field.kind == "array":
                        raw = [item.strip() for item in raw.split(",") if item.strip()]
                values[field.field_id] = field.to_jira_value(raw)
        except ValueError as exc:
            self.status(str(exc), error=True)
            return
        self.wizard.state.additional_fields = values
        self.wizard.show_advanced()


class AdvancedScreen(WizardScreen):
    """Expose the manual Jira API-version override."""

    def compose(self) -> ComposeResult:
        state = self.wizard.state
        warnings = []
        if state.mpvm_url.startswith("http://") or state.jira_url.startswith("http://"):
            warnings.append(
                "Внимание: HTTP передает токены без шифрования и не рекомендуется."
            )
        yield VerticalScroll(
            Static("Дополнительные настройки", classes="title"),
            Static("Шаг 9 из 10 · API", classes="step"),
            Static(" ".join(warnings), classes="warning"),
            Static(
                "Параметры TLS уже применены при проверке подключений "
                "MaxPatrol VM и Jira.",
                classes="hint",
            ),
            Label("Версия Jira REST API"),
            Select(
                [
                    ("Определить автоматически", "auto"),
                    ("API v2", "2"),
                    ("API v3", "3"),
                ],
                value=state.jira_api_version or "auto",
                allow_blank=False,
                id="api-version",
            ),
            Static("PDQL настраивается только вручную в config.yaml.", classes="hint"),
            Static("", id="status"),
            Horizontal(
                Button("Назад", id="back"),
                Button("К итоговой проверке", id="next", variant="primary"),
                classes="buttons",
            ),
            classes="panel",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            if self.wizard.required_fields:
                self.wizard.show_required_fields()
            else:
                self.wizard.show_priorities()
            return
        if event.button.id != "next":
            return
        state = self.wizard.state
        api_version = str(self.query_one("#api-version", Select).value)
        if api_version in {"2", "3"}:
            state.jira_api_version = api_version  # type: ignore[assignment]
        self.wizard.show_summary()


class SummaryScreen(WizardScreen):
    """Show only non-secret values before final validation and save."""

    def compose(self) -> ComposeResult:
        state = self.wizard.state
        strategy = (
            "резервная копия"
            if state.file_strategy == FileStrategy.BACKUP
            else "перезапись"
        )
        yield Vertical(
            Static("Итоговая проверка", classes="title"),
            Static("Шаг 10 из 10 · Подтверждение", classes="step"),
            Static(
                f"MaxPatrol VM: {state.mpvm_url or 'не указано'}\n"
                f"Jira: {state.jira_url or 'не указано'}\n"
                f"Проект: {state.project_key or 'не указан'}\n"
                f"Тип задачи: {state.issue_type or 'не указан'}\n"
                f"REST API: v{state.jira_api_version or 'auto'}\n"
                f"Файлы: {strategy}\n"
                "Токены: скрыты и будут записаны только в .env"
            ),
            Static("", id="status"),
            Horizontal(
                Button("Назад", id="back"),
                Button("Проверить и сохранить", id="save", variant="success"),
                classes="buttons",
            ),
            classes="panel",
        )

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self.wizard.show_advanced()
            return
        if event.button.id != "save":
            return
        self.status("Выполняем итоговую проверку без создания задач…")
        summary = await asyncio.to_thread(
            self.wizard.validation_service.validate_complete,
            self.wizard.state,
        )
        if not summary.ok:
            self.status(summary.message, error=True)
            return
        try:
            result = await asyncio.to_thread(
                self.wizard.save_function,
                self.wizard.base_dir,
                self.wizard.state,
            )
        except Exception as exc:
            self.status(f"Не удалось сохранить конфигурацию: {exc}", error=True)
            return
        self.wizard.save_result = result
        self.wizard.show_success()


class SuccessScreen(WizardScreen):
    """Confirm successful setup and show safe next commands."""

    def compose(self) -> ComposeResult:
        yield Vertical(
            Static("Настройка завершена", classes="title"),
            Static(
                "Файлы .env и config.yaml сохранены. Мастер не создавал "
                "задачи Jira. Следующие команды:\n\n"
                "python -m mpvm_jira validate\n"
                "python -m mpvm_jira run --dry-run\n"
                "python -m mpvm_jira run"
            ),
            Static("", id="status"),
            Horizontal(
                Button("Закрыть", id="finish", variant="primary"),
                classes="buttons",
            ),
            classes="panel",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "finish":
            self.wizard.exit()
