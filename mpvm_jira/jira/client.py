"""Create Jira issues and MaxPatrol VM vulnerability summaries."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from requests.auth import HTTPBasicAuth

from ..config import ConfigError, env_secret, require
from ..http import ApiError, build_session, checked_json
from ..models import Asset, Vulnerability
from .criticality import (
    CRITICALITY_LEVELS,
    normalize_criticalities,
    vulnerability_criticality,
)

LOG = logging.getLogger(__name__)
_SUMMARY_ROW_STYLES = {
    "Всего уязвимостей": {"bold": True},
    "Критического уровня": {"color": "#FF2400"},
    "Высокого уровня": {"color": "#D32F2F"},
    "Среднего уровня": {"color": "#B86E00"},
    "Низкого уровня": {"color": "#0052CC"},
}
_SUMMARY_ROW_LABELS = {
    "Critical": "Критического уровня",
    "High": "Высокого уровня",
    "Medium": "Среднего уровня",
    "Low": "Низкого уровня",
    "Non-crit": "Без критичности (без вектора CVSS)",
}


class JiraClient:
    """Access the Jira REST API required by the integration."""

    def __init__(self, config: dict[str, Any]):
        """Initialize a Jira client from the configuration mapping."""
        self.config = config
        self.base_url = str(require(config, "base_url")).rstrip("/")
        self.deployment = str(config.get("deployment", "cloud"))
        self.api_version = str(
            config.get(
                "api_version", "3" if self.deployment == "cloud" else "2"
            )
        )
        self.project_key = str(require(config, "project_key"))
        self.timeout = float(config.get("timeout_seconds", 60))
        self.verify = config.get("verify_ssl", True)
        self.session = build_session(
            int(config.get("retries", 3)), "mpvm-jira-integration/1.0"
        )
        self._configure_auth()
        self._priorities: dict[str, str] | None = None
        LOG.debug(
            "Клиент Jira настроен: base_url=%s, api_version=%s, project=%s",
            self.base_url,
            self.api_version,
            self.project_key,
        )

    def _configure_auth(self) -> None:
        """Configure the requests session for the selected auth mode."""
        mode = str(self.config.get("auth_mode", "basic"))
        token = env_secret(self.config, "token_env")
        if mode == "basic":
            user = env_secret(self.config, "user_env")
            self.session.auth = HTTPBasicAuth(user, token)
        elif mode == "bearer":
            self.session.headers.update({"Authorization": f"Bearer {token}"})
        else:
            raise ConfigError(f"Неизвестный jira.auth_mode: {mode}")

    def validate_connection(self) -> dict[str, Any]:
        """Validate credentials, priorities, and project permissions."""
        LOG.debug(
            "Проверка подключения к Jira: %s, project=%s",
            self.base_url,
            self.project_key,
        )
        response = self.session.get(
            f"{self.base_url}/rest/api/{self.api_version}/myself",
            timeout=self.timeout,
            verify=self.verify,
        )
        body = checked_json(response, "Проверка подключения к Jira")
        self.available_priorities()
        self._validate_permissions()
        LOG.debug("Подключение к Jira и проектные разрешения подтверждены")
        return body

    def _validate_permissions(self) -> None:
        """Validate the Jira permissions required by the integration."""
        response = self.session.get(
            f"{self.base_url}/rest/api/{self.api_version}/mypermissions",
            params={
                "projectKey": self.project_key,
                "permissions": "CREATE_ISSUES,CREATE_ATTACHMENTS",
            },
            timeout=self.timeout,
            verify=self.verify,
        )
        body = checked_json(response, "Проверка прав Jira")
        permissions = (
            body.get("permissions", {}) if isinstance(body, dict) else {}
        )
        create_issue = permissions.get("CREATE_ISSUES")
        if isinstance(create_issue, dict) and not create_issue.get(
            "havePermission", False
        ):
            raise ConfigError(
                "Учетной записи Jira не выдано разрешение Create issues"
            )
        attachment = permissions.get("CREATE_ATTACHMENTS") or permissions.get(
            "CREATE_ATTACHMENT"
        )
        LOG.debug(
            "Разрешения Jira: create_issues=%s, create_attachments=%s",
            (
                create_issue.get("havePermission")
                if isinstance(create_issue, dict)
                else "не указано"
            ),
            (
                attachment.get("havePermission")
                if isinstance(attachment, dict)
                else "не указано"
            ),
        )
        if (
            bool(self.config.get("strict_attachment_permissions", True))
            and isinstance(attachment, dict)
            and not attachment.get("havePermission", False)
        ):
            raise ConfigError(
                "Учетной записи Jira не выдано разрешение Create attachments"
            )

    def available_priorities(self) -> dict[str, str]:
        """Return Jira priority names indexed by case-folded names."""
        if self._priorities is not None:
            return self._priorities
        response = self.session.get(
            f"{self.base_url}/rest/api/{self.api_version}/priority",
            timeout=self.timeout,
            verify=self.verify,
        )
        body = checked_json(response, "Получение приоритетов Jira")
        if not isinstance(body, list):
            raise ApiError("Jira вернула некорректный список приоритетов")
        self._priorities = {
            str(item.get("name", "")).casefold(): str(item.get("name", ""))
            for item in body
            if isinstance(item, dict) and item.get("name")
        }
        LOG.debug(
            "Получен справочник приоритетов Jira: %s значений",
            len(self._priorities),
        )
        return self._priorities

    def priority_for(self, importance: str) -> str:
        """Map an MP VM asset importance value to a Jira priority."""
        mapping = self.config.get("priority_map") or {}
        desired = None
        for key, value in mapping.items():
            if str(key).casefold() == importance.casefold():
                desired = str(value)
                break
        desired = desired or str(self.config.get("default_priority", "Medium"))
        priorities = self.available_priorities()
        actual = priorities.get(desired.casefold())
        if actual:
            return actual
        if bool(self.config.get("strict_priorities", True)):
            raise ConfigError(
                f"Приоритет Jira {desired!r} не найден. Доступны: "
                f"{', '.join(sorted(priorities.values()))}"
            )
        LOG.warning(
            "Приоритет Jira %r не найден; поле priority не будет отправлено",
            desired,
        )
        return ""

    def create_issue(
        self,
        asset: Asset,
        criticalities: Sequence[str] | None = None,
    ) -> dict[str, Any]:
        """Create and return one Jira issue for an asset."""
        priority = self.priority_for(asset.importance)
        LOG.debug(
            "Создание задачи Jira: asset_id=%s, summary=%s, "
            "vulnerabilities=%s, priority=%s",
            asset.asset_id,
            asset.title,
            len(asset.vulnerabilities),
            priority or "не задан",
        )
        fields: dict[str, Any] = {
            "project": {"key": self.project_key},
            "summary": asset.title,
            "issuetype": {"name": str(self.config.get("issue_type", "Task"))},
            "description": self._description(asset, criticalities),
        }
        if priority:
            fields["priority"] = {"name": priority}
        labels = self.config.get("labels") or []
        if labels:
            fields["labels"] = [str(item) for item in labels]
        additional = self.config.get("additional_fields") or {}
        if not isinstance(additional, dict):
            raise ConfigError("jira.additional_fields должен быть объектом")
        fields.update(additional)
        response = self.session.post(
            f"{self.base_url}/rest/api/{self.api_version}/issue",
            json={"fields": fields},
            timeout=self.timeout,
            verify=self.verify,
        )
        body = checked_json(
            response, f"Создание задачи Jira для {asset.title}"
        )
        if not isinstance(body, dict) or not body.get("key"):
            raise ApiError("Jira не вернула ключ созданной задачи")
        return body

    def attach_file(self, issue_key: str, path: Path) -> dict[str, Any]:
        """Attach an XLSX file to a Jira issue and return its metadata."""
        LOG.debug(
            "Прикрепление XLSX к Jira: issue=%s, file=%s, size=%s",
            issue_key,
            path,
            path.stat().st_size,
        )
        with path.open("rb") as stream:
            response = self.session.post(
                f"{self.base_url}/rest/api/{self.api_version}/issue/"
                f"{issue_key}/attachments",
                headers={"X-Atlassian-Token": "no-check"},
                files={
                    "file": (
                        path.name,
                        stream,
                        "application/vnd.openxmlformats-officedocument."
                        "spreadsheetml.sheet",
                    )
                },
                timeout=self.timeout,
                verify=self.verify,
            )
        body = checked_json(
            response, f"Прикрепление XLSX к задаче Jira {issue_key}"
        )
        if (
            not isinstance(body, list)
            or not body
            or not isinstance(body[0], dict)
        ):
            raise ApiError("Jira не вернула сведения о созданном вложении")
        return body[0]

    def _description(
        self,
        asset: Asset,
        criticalities: Sequence[str] | None = None,
    ) -> Any:
        """Select the description format supported by the Jira API."""
        if self.api_version == "3":
            return build_adf_description(asset, criticalities)
        return build_wiki_description(asset, criticalities)


def vulnerability_summary(
    vulnerabilities: list[Vulnerability],
    criticalities: Sequence[str] | None = None,
) -> tuple[tuple[str, int], ...]:
    """Count vulnerabilities for the selected criticality groups."""
    selected = normalize_criticalities(criticalities) or CRITICALITY_LEVELS
    counts = {level: 0 for level in selected}
    for vulnerability in vulnerabilities:
        level = vulnerability_criticality(vulnerability)
        if level in counts:
            counts[level] += 1
    rows = tuple(
        (_SUMMARY_ROW_LABELS[level], counts[level]) for level in selected
    )
    return (("Всего уязвимостей", sum(counts.values())), *rows)


def _paragraph(text: str) -> dict[str, Any]:
    """Build one Atlassian Document Format paragraph node."""
    return {"type": "paragraph", "content": [{"type": "text", "text": text}]}


def _table_cell(
    text: str,
    *,
    bold: bool = False,
    color: str | None = None,
) -> dict[str, Any]:
    """Build one Atlassian Document Format table cell node."""
    text_node: dict[str, Any] = {"type": "text", "text": text}
    marks: list[dict[str, Any]] = []
    if bold:
        marks.append({"type": "strong"})
    if color:
        marks.append({"type": "textColor", "attrs": {"color": color}})
    if marks:
        text_node["marks"] = marks
    return {
        "type": "tableCell",
        "attrs": {},
        "content": [{"type": "paragraph", "content": [text_node]}],
    }


def _summary_style(label: str) -> dict[str, Any]:
    """Return the text style assigned to a summary row."""
    return _SUMMARY_ROW_STYLES.get(label, {})


def build_adf_description(
    asset: Asset,
    criticalities: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Build an Atlassian Document Format issue description."""
    rows = [
        {
            "type": "tableRow",
            "content": [
                _table_cell(label, **_summary_style(label)),
                _table_cell(str(count), **_summary_style(label)),
            ],
        }
        for label, count in vulnerability_summary(
            asset.vulnerabilities,
            criticalities,
        )
    ]
    return {
        "version": 1,
        "type": "doc",
        "content": [
            _paragraph("Источник: MaxPatrol VM."),
            _paragraph(f"Актив из MaxPatrol VM: {asset.title}."),
            _paragraph("Актуальные уязвимости:"),
            {
                "type": "table",
                "attrs": {"isNumberColumnEnabled": False},
                "content": rows,
            },
            _paragraph(
                "Подробная информация и рекомендации по устранению "
                "находятся в XLSX-вложении."
            ),
        ],
    }


def build_wiki_description(
    asset: Asset,
    criticalities: Sequence[str] | None = None,
) -> str:
    """Build a Jira wiki-markup issue description."""
    lines = [
        "Источник: MaxPatrol VM.",
        f"Актив из MaxPatrol VM: {asset.title}.",
        "Актуальные уязвимости:",
        "",
    ]
    lines.extend(
        f"|{_wiki_summary_cell(label, label)}|"
        f"{_wiki_summary_cell(str(count), label)}|"
        for label, count in vulnerability_summary(
            asset.vulnerabilities,
            criticalities,
        )
    )
    lines.extend(
        (
            "",
            "Подробная информация и рекомендации по устранению "
            "находятся в XLSX-вложении.",
        )
    )
    return "\n".join(lines)


def _wiki_summary_cell(text: str, label: str) -> str:
    """Apply one summary row style using Jira wiki markup."""
    style = _summary_style(label)
    if style.get("bold"):
        text = f"*{text}*"
    color = style.get("color")
    if color:
        text = f"{{color:{color}}}{text}{{color}}"
    return text
