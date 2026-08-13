"""Discover Jira choices needed by the interactive setup wizard."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any, Literal
from urllib.parse import quote

import requests
from requests.auth import HTTPBasicAuth

from ..http import build_session


class SetupDiscoveryError(RuntimeError):
    """Report a safe, user-facing discovery error."""


class _JiraHttpError(SetupDiscoveryError):
    """Retain an HTTP status for internal compatibility fallbacks."""

    def __init__(self, context: str, status_code: int):
        self.status_code = status_code
        super().__init__(f"{context}: Jira вернула HTTP {status_code}")


@dataclass(frozen=True)
class JiraProject:
    """A Jira project available to the configured account."""

    key: str
    name: str


@dataclass(frozen=True)
class JiraIssueType:
    """A Jira issue type available in a project."""

    id: str
    name: str


@dataclass(frozen=True)
class PermissionResult:
    """Permissions required to create an issue and attach XLSX data."""

    create_issues: bool
    create_attachments: bool

    @property
    def ok(self) -> bool:
        """Return whether every required permission is granted."""
        return self.create_issues and self.create_attachments


@dataclass(frozen=True)
class RequiredField:
    """A required create-screen field supported by the wizard."""

    field_id: str
    name: str
    kind: str
    item_kind: str = ""
    options: tuple[str, ...] = ()
    api_version: str = "2"

    def to_jira_value(self, value: Any) -> Any:
        """Convert a scalar wizard answer to an explicit Jira payload."""
        if self.kind == "string":
            if not isinstance(value, str):
                raise ValueError(f"Поле {self.name} ожидает текст")
            return value
        if self.kind == "number":
            if isinstance(value, bool):
                raise ValueError(f"Поле {self.name} ожидает число")
            try:
                number = float(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Поле {self.name} ожидает число") from exc
            return int(number) if number.is_integer() else number
        if self.kind == "option":
            return {"value": self._text(value)}
        if self.kind == "array":
            values = value if isinstance(value, (list, tuple)) else [value]
            if self.item_kind == "option":
                return [{"value": self._text(item)} for item in values]
            if self.item_kind in {"component", "version"}:
                return [{"name": self._text(item)} for item in values]
            if self.item_kind in {"string", ""}:
                return [self._text(item) for item in values]
            raise ValueError(f"Поле {self.name} имеет неподдерживаемый массив")
        if self.kind == "user":
            key = "accountId" if self.api_version == "3" else "name"
            return {key: self._text(value)}
        if self.kind in {"component", "version"}:
            return {"name": self._text(value)}
        if self.kind == "date":
            text = self._text(value)
            try:
                date.fromisoformat(text)
            except ValueError as exc:
                raise ValueError(f"Поле {self.name} ожидает дату ГГГГ-ММ-ДД") from exc
            return text
        if self.kind == "boolean":
            if isinstance(value, bool):
                return value
            normalized = self._text(value).casefold()
            if normalized in {"true", "yes", "1", "да"}:
                return True
            if normalized in {"false", "no", "0", "нет"}:
                return False
            raise ValueError(f"Поле {self.name} ожидает Да или Нет")
        raise ValueError(f"Поле {self.name} имеет неподдерживаемый тип")

    def _text(self, value: Any) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Поле {self.name} не должно быть пустым")
        return value.strip()


class JiraSetupClient:
    """Read Jira metadata without creating or changing Jira objects."""

    def __init__(
        self,
        base_url: str,
        auth_mode: Literal["basic", "bearer"],
        token: str,
        user: str = "",
        verify_ssl: bool | str = True,
        timeout: float = 60,
        retries: int = 3,
        session: requests.Session | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.auth_mode = auth_mode
        self.timeout = timeout
        self.verify = verify_ssl
        self.session = session or build_session(retries, "mpvm-jira-setup/1.0")
        if auth_mode == "basic":
            if not user:
                raise SetupDiscoveryError(
                    "Для Basic-аутентификации укажите пользователя Jira"
                )
            self.session.auth = HTTPBasicAuth(user, token)
        elif auth_mode == "bearer":
            self.session.headers.update({"Authorization": f"Bearer {token}"})
        else:
            raise SetupDiscoveryError(
                f"Неподдерживаемый режим аутентификации: {auth_mode}"
            )
        self.api_version: str | None = None
        self._metadata: dict[str, dict[str, Any]] = {}

    def _url(self, path: str, api_version: str | None = None) -> str:
        version = api_version or self.api_version
        if version not in {"2", "3"}:
            raise SetupDiscoveryError("Версия Jira REST API еще не определена")
        return f"{self.base_url}/rest/api/{version}/{path.lstrip('/')}"

    def _get_json(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        api_version: str | None = None,
        context: str,
    ) -> Any:
        response = self.session.get(
            self._url(path, api_version),
            params=params,
            timeout=self.timeout,
            verify=self.verify,
        )
        if response.status_code in {401, 403}:
            raise SetupDiscoveryError(
                f"{context}: Jira отклонила учетные данные или доступ"
            )
        if not response.ok:
            raise _JiraHttpError(context, response.status_code)
        try:
            return response.json()
        except ValueError as exc:
            raise SetupDiscoveryError(
                f"{context}: Jira вернула ответ не в формате JSON"
            ) from exc

    def detect_api_version(self) -> str:
        """Detect Jira REST API v3 first and then v2."""
        statuses: list[int] = []
        for version in ("3", "2"):
            response = self.session.get(
                self._url("myself", version),
                timeout=self.timeout,
                verify=self.verify,
                allow_redirects=False,
            )
            if response.status_code in {401, 403}:
                raise SetupDiscoveryError(
                    "Jira отклонила учетные данные или доступ"
                )
            if response.ok:
                try:
                    body = response.json()
                except ValueError:
                    body = None
                if isinstance(body, dict):
                    self.api_version = version
                    return version
            statuses.append(response.status_code)
        raise SetupDiscoveryError(
            "Не удалось определить Jira REST API v2/v3; HTTP "
            + "/".join(str(status) for status in statuses)
        )

    def list_projects(self) -> tuple[JiraProject, ...]:
        """Return visible Jira projects sorted by display name."""
        version = self._require_version()
        raw_projects: list[Any] = []
        if version == "3":
            start = 0
            while True:
                body = self._get_json(
                    "project/search",
                    params={"startAt": start, "maxResults": 50},
                    context="Получение проектов Jira",
                )
                if not isinstance(body, dict):
                    raise SetupDiscoveryError(
                        "Jira вернула некорректный список проектов"
                    )
                values = body.get("values")
                if not isinstance(values, list):
                    raise SetupDiscoveryError(
                        "Jira вернула некорректный список проектов"
                    )
                raw_projects.extend(values)
                start += len(values)
                total = int(body.get("total", start))
                if not values or start >= total or body.get("isLast") is True:
                    break
        else:
            body = self._get_json("project", context="Получение проектов Jira")
            if not isinstance(body, list):
                raise SetupDiscoveryError("Jira вернула некорректный список проектов")
            raw_projects = body
        projects = tuple(
            JiraProject(str(item["key"]), str(item.get("name") or item["key"]))
            for item in raw_projects
            if isinstance(item, dict) and item.get("key")
        )
        return tuple(sorted(projects, key=lambda item: item.name.casefold()))

    def get_project(self, project_key: str) -> JiraProject:
        """Validate and return one manually entered project key."""
        key = project_key.strip()
        body = self._get_json(
            f"project/{quote(key, safe='')}",
            context=f"Проверка проекта {key}",
        )
        if not isinstance(body, dict) or not body.get("key"):
            raise SetupDiscoveryError("Jira не подтвердила указанный проект")
        return JiraProject(str(body["key"]), str(body.get("name") or key))

    def list_issue_types(self, project_key: str) -> tuple[JiraIssueType, ...]:
        """Return issue types from modern or legacy create metadata."""
        key = project_key.strip()
        path = f"issue/createmeta/{quote(key, safe='')}/issuetypes"
        try:
            raw_types = self._paged_values(
                path,
                context=f"Получение типов задач проекта {key}",
            )
        except _JiraHttpError as exc:
            if exc.status_code != 404:
                raise
            project = self._create_metadata(key)
            raw_types = project.get("issuetypes")
        if not isinstance(raw_types, list):
            raise SetupDiscoveryError("Jira вернула некорректный список типов задач")
        values = tuple(
            JiraIssueType(str(item["id"]), str(item["name"]))
            for item in raw_types
            if isinstance(item, dict) and item.get("id") and item.get("name")
        )
        return tuple(sorted(values, key=lambda item: item.name.casefold()))

    def list_priorities(self) -> tuple[str, ...]:
        """Return available Jira priority names."""
        body = self._get_json("priority", context="Получение приоритетов Jira")
        if not isinstance(body, list):
            raise SetupDiscoveryError("Jira вернула некорректный список приоритетов")
        values = {
            str(item["name"])
            for item in body
            if isinstance(item, dict) and item.get("name")
        }
        return tuple(sorted(values, key=str.casefold))

    def required_fields(
        self, project_key: str, issue_type: str
    ) -> tuple[RequiredField, ...]:
        """Return required fields from modern or legacy create metadata."""
        key = project_key.strip()
        issue_type_value = issue_type.strip()
        path = (
            f"issue/createmeta/{quote(key, safe='')}/issuetypes/"
            f"{quote(issue_type_value, safe='')}"
        )
        try:
            values = self._paged_values(
                path,
                context=(
                    f"Получение полей типа задачи {issue_type_value} "
                    f"проекта {key}"
                ),
            )
            raw_fields = {
                str(item.get("fieldId") or item.get("key")): item
                for item in values
                if isinstance(item, dict)
                and (item.get("fieldId") or item.get("key"))
            }
        except _JiraHttpError as exc:
            if exc.status_code != 404:
                raise
            raw_fields = self._legacy_required_fields(key, issue_type_value)
        return self._normalize_required_fields(raw_fields)

    def _legacy_required_fields(
        self, project_key: str, issue_type: str
    ) -> dict[str, Any]:
        project = self._create_metadata(project_key)
        issue_types = project.get("issuetypes") or []
        selected = next(
            (
                item
                for item in issue_types
                if isinstance(item, dict)
                and issue_type in {str(item.get("id")), str(item.get("name"))}
            ),
            None,
        )
        if selected is None:
            raise SetupDiscoveryError(
                f"Тип задачи {issue_type!r} не найден в проекте {project_key}"
            )
        return selected.get("fields") or {}

    def _normalize_required_fields(
        self, raw_fields: dict[str, Any]
    ) -> tuple[RequiredField, ...]:
        if not isinstance(raw_fields, dict):
            raise SetupDiscoveryError("Jira вернула некорректные поля экрана создания")
        managed = {
            "project",
            "summary",
            "issuetype",
            "description",
            "priority",
            "labels",
        }
        fields: list[RequiredField] = []
        supported = {
            "string",
            "number",
            "option",
            "array",
            "user",
            "component",
            "version",
            "date",
            "boolean",
        }
        for field_id, raw in raw_fields.items():
            if field_id in managed or not isinstance(raw, dict):
                continue
            if not raw.get("required") or raw.get("hasDefaultValue"):
                continue
            schema = raw.get("schema") or {}
            kind = str(schema.get("type") or "unknown")
            name = str(raw.get("name") or field_id)
            item_kind = str(schema.get("items") or "")
            if kind not in supported or (
                kind == "array"
                and item_kind not in {"string", "option", "component", "version"}
            ):
                raise SetupDiscoveryError(
                    "Неподдерживаемое обязательное поле Jira: "
                    f"{field_id} / {name} / {kind}"
                )
            options = tuple(
                str(option.get("value") or option.get("name") or option.get("id"))
                for option in raw.get("allowedValues") or []
                if isinstance(option, dict)
            )
            fields.append(
                RequiredField(
                    field_id=str(field_id),
                    name=name,
                    kind=kind,
                    item_kind=item_kind,
                    options=options,
                    api_version=self._require_version(),
                )
            )
        return tuple(sorted(fields, key=lambda item: item.field_id))

    def _paged_values(self, path: str, *, context: str) -> list[Any]:
        """Read every page from a modern Jira create-metadata endpoint."""
        start = 0
        values: list[Any] = []
        while True:
            body = self._get_json(
                path,
                params={"startAt": start, "maxResults": 50},
                context=context,
            )
            page = body.get("values") if isinstance(body, dict) else None
            if not isinstance(page, list):
                raise SetupDiscoveryError(
                    f"{context}: Jira вернула некорректную страницу данных"
                )
            values.extend(page)
            next_start = start + len(page)
            total = int(body.get("total", next_start))
            if not page or next_start >= total or body.get("isLast") is True:
                break
            start = next_start
        return values

    def validate_permissions(self, project_key: str) -> PermissionResult:
        """Check the two Jira permissions required by the integration."""
        body = self._get_json(
            "mypermissions",
            params={
                "projectKey": project_key,
                "permissions": "CREATE_ISSUES,CREATE_ATTACHMENTS",
            },
            context="Проверка разрешений Jira",
        )
        permissions = body.get("permissions") if isinstance(body, dict) else None
        if not isinstance(permissions, dict):
            return PermissionResult(False, False)

        def allowed(name: str) -> bool:
            value = permissions.get(name)
            return bool(isinstance(value, dict) and value.get("havePermission") is True)

        return PermissionResult(
            create_issues=allowed("CREATE_ISSUES"),
            create_attachments=(
                allowed("CREATE_ATTACHMENTS") or allowed("CREATE_ATTACHMENT")
            ),
        )

    def _create_metadata(self, project_key: str) -> dict[str, Any]:
        cached = self._metadata.get(project_key)
        if cached is not None:
            return cached
        body = self._get_json(
            "issue/createmeta",
            params={"projectKeys": project_key, "expand": "projects.issuetypes.fields"},
            context="Получение полей экрана создания Jira",
        )
        projects = body.get("projects") if isinstance(body, dict) else None
        if not isinstance(projects, list) or not projects:
            raise SetupDiscoveryError(
                f"Jira не вернула метаданные проекта {project_key}"
            )
        project = projects[0]
        if not isinstance(project, dict):
            raise SetupDiscoveryError("Jira вернула некорректные метаданные")
        self._metadata[project_key] = project
        return project

    def _require_version(self) -> str:
        if self.api_version not in {"2", "3"}:
            raise SetupDiscoveryError("Сначала определите версию Jira REST API")
        return self.api_version
