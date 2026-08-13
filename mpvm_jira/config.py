"""Load configuration files and secret environment variables."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import yaml


class ConfigError(ValueError):
    """Raised when configuration is missing or invalid."""


def load_dotenv(path: Path) -> None:
    """Load a conservative subset of the .env file format."""
    if not path.exists():
        return
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            raise ConfigError(f"Некорректная строка {line_number} в {path}")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if value[:1] == value[-1:] == '"':
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                value = value[1:-1]
        elif value[:1] == value[-1:] == "'":
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value


def load_config(path: Path, env_file: Path | None = None) -> dict[str, Any]:
    """Load and validate YAML plus an optional environment file."""
    if env_file is not None:
        load_dotenv(env_file)
    if not path.is_file():
        raise ConfigError(f"Файл конфигурации не найден: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ConfigError("Корнем YAML-конфигурации должен быть объект")
    for section in ("mpvm", "jira"):
        if section not in data or not isinstance(data[section], dict):
            raise ConfigError(f"В конфигурации отсутствует секция {section}")
    return data


def env_secret(config: dict[str, Any], field: str, *, required: bool = True) -> str:
    """Read a secret from the environment variable named in config."""
    variable = str(config.get(field, "")).strip()
    value = os.environ.get(variable, "") if variable else ""
    if required and not value:
        raise ConfigError(f"Не задана переменная окружения {variable or field}")
    return value


def require(config: dict[str, Any], field: str) -> Any:
    """Return a required configuration value or raise ConfigError."""
    value = config.get(field)
    if value is None or value == "":
        raise ConfigError(f"Не задан обязательный параметр {field}")
    return value
