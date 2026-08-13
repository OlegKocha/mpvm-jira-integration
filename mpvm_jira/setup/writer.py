"""Render and securely save files produced by the setup wizard."""

from __future__ import annotations

import copy
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from .state import FileStrategy, SetupState


@dataclass(frozen=True)
class SaveResult:
    """Paths written by a successful configuration transaction."""

    env_path: Path
    config_path: Path
    backups: tuple[Path, ...] = ()


def _load_defaults() -> dict[str, Any]:
    template = resources.files("mpvm_jira.templates").joinpath("config.defaults.yaml")
    data = yaml.safe_load(template.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Встроенный шаблон конфигурации поврежден")
    return data


def build_config(state: SetupState) -> dict[str, Any]:
    """Merge wizard-owned values into a copy of packaged defaults."""
    config = copy.deepcopy(_load_defaults())
    mpvm = config["mpvm"]
    jira = config["jira"]
    mpvm.update(
        {
            "base_url": state.mpvm_url.rstrip("/"),
            "access_token_env": "MPVM_ACCESS_TOKEN",
            "verify_ssl": state.mpvm_tls.config_value(),
        }
    )
    jira.update(
        {
            "deployment": ("cloud" if state.jira_api_version == "3" else "data_center"),
            "base_url": state.jira_url.rstrip("/"),
            "api_version": state.jira_api_version or "2",
            "auth_mode": state.jira_auth_mode,
            "user_env": "JIRA_USER",
            "token_env": "JIRA_API_TOKEN",
            "project_key": state.project_key,
            "issue_type": state.issue_type,
            "verify_ssl": state.jira_tls.config_value(),
            "priority_map": copy.deepcopy(state.priority_map),
            "default_priority": state.default_priority,
            "additional_fields": copy.deepcopy(state.additional_fields),
        }
    )
    return config


def _quote_env(value: str) -> str:
    if "\n" in value or "\r" in value:
        raise ValueError("Значение секрета не должно содержать перевод строки")
    special = any(character.isspace() for character in value) or any(
        character in value for character in "#'\\\""
    )
    return json.dumps(value, ensure_ascii=False) if special else value


def render_env(state: SetupState) -> str:
    """Render secrets in the subset of dotenv syntax used by the project."""
    if not state.mpvm_token:
        raise ValueError("Не задан reference-токен MaxPatrol VM")
    if not state.jira_token:
        raise ValueError("Не задан токен Jira")
    lines = [f"MPVM_ACCESS_TOKEN={_quote_env(state.mpvm_token)}"]
    if state.jira_auth_mode == "basic":
        if not state.jira_user:
            raise ValueError("Для Basic-аутентификации укажите пользователя Jira")
        lines.append(f"JIRA_USER={_quote_env(state.jira_user)}")
    lines.append(f"JIRA_API_TOKEN={_quote_env(state.jira_token)}")
    return "\n".join(lines) + "\n"


def _write_private_temp(base_dir: Path, content: str) -> Path:
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=base_dir,
        prefix=".mpvm-jira-",
        delete=False,
    ) as stream:
        stream.write(content)
        path = Path(stream.name)
    if os.name == "posix":
        path.chmod(0o600)
    return path


def _private_copy(path: Path, base_dir: Path) -> Path:
    with tempfile.NamedTemporaryFile(
        dir=base_dir,
        prefix=".mpvm-jira-rollback-",
        delete=False,
    ) as stream:
        rollback = Path(stream.name)
    shutil.copyfile(path, rollback)
    if os.name == "posix":
        rollback.chmod(0o600)
    return rollback


def save_configuration(
    base_dir: Path,
    state: SetupState,
    now: datetime | None = None,
) -> SaveResult:
    """Atomically replace ``.env`` and ``config.yaml`` with rollback."""
    env_content = render_env(state)
    config_content = yaml.safe_dump(
        build_config(state),
        allow_unicode=True,
        sort_keys=False,
        width=100,
    )
    base_dir.mkdir(parents=True, exist_ok=True)
    env_path = base_dir / ".env"
    config_path = base_dir / "config.yaml"
    targets = (env_path, config_path)
    contents = (env_content, config_content)
    temporary: list[Path] = []
    rollback: dict[Path, Path] = {}
    backups: list[Path] = []
    timestamp = (now or datetime.now()).strftime("%Y%m%d_%H%M%S")

    try:
        temporary = [_write_private_temp(base_dir, content) for content in contents]
        for target in targets:
            if not target.exists():
                continue
            rollback[target] = _private_copy(target, base_dir)
            if state.file_strategy == FileStrategy.BACKUP:
                backup = target.with_name(f"{target.name}.bak.{timestamp}")
                shutil.copyfile(target, backup)
                if os.name == "posix":
                    backup.chmod(0o600)
                backups.append(backup)

        replaced: list[Path] = []
        try:
            for source, target in zip(temporary, targets):
                os.replace(source, target)
                replaced.append(target)
                if os.name == "posix":
                    target.chmod(0o600)
        except OSError:
            for target in targets:
                saved = rollback.get(target)
                if saved and saved.exists():
                    os.replace(saved, target)
                elif target in replaced and target.exists():
                    target.unlink()
            raise
    finally:
        for path in [*temporary, *rollback.values()]:
            if path.exists():
                path.unlink()

    return SaveResult(env_path, config_path, tuple(backups))
