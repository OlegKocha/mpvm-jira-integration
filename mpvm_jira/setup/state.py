"""State models shared by the interactive setup screens."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal


class FileStrategy(str, Enum):
    """Choose how existing configuration files are handled."""

    OVERWRITE = "overwrite"
    BACKUP = "backup"


@dataclass
class TlsSettings:
    """TLS verification settings for one API endpoint."""

    mode: Literal["system", "ca_file", "disabled"] = "system"
    ca_file: str = ""

    def config_value(self) -> bool | str:
        """Return the value expected by the HTTP client configuration."""
        if self.mode == "system":
            return True
        if self.mode == "disabled":
            return False
        if self.mode == "ca_file":
            path = self.ca_file.strip()
            if not path:
                raise ValueError("Для пользовательского CA укажите PEM-файл")
            return path
        raise ValueError(f"Неизвестный режим TLS: {self.mode}")


@dataclass
class SetupState:
    """Collect non-secret and secret answers entered in the wizard."""

    file_strategy: FileStrategy = FileStrategy.OVERWRITE
    mpvm_url: str = ""
    mpvm_token: str = field(default="", repr=False)
    jira_url: str = ""
    jira_auth_mode: Literal["basic", "bearer"] = "basic"
    jira_user: str = ""
    jira_token: str = field(default="", repr=False)
    jira_api_version: Literal["2", "3"] | None = None
    project_key: str = ""
    issue_type: str = ""
    priority_map: dict[str, str] = field(default_factory=dict)
    default_priority: str = ""
    additional_fields: dict[str, Any] = field(default_factory=dict)
    mpvm_tls: TlsSettings = field(default_factory=TlsSettings)
    jira_tls: TlsSettings = field(default_factory=TlsSettings)

    def clear_secrets(self) -> None:
        """Drop tokens from memory when the wizard exits."""
        self.mpvm_token = ""
        self.jira_token = ""
