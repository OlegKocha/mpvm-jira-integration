"""Provide the command-line interface for the integration."""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Sequence

from .config import ConfigError, load_config
from .jira import IntegrationRunError, JiraClient, sync_latest_to_jira
from .jira.criticality import (
    CRITICALITY_LEVELS,
    normalize_criticalities,
    normalize_criticality,
)
from .mpvm import (
    MaxPatrolClient,
    export_snapshot,
    latest_snapshot,
    normalize_fqdn_filter,
    normalize_ip_selector,
)


LOG = logging.getLogger(__name__)
_SENSITIVE_LOG_PATTERNS = (
    (re.compile(r"(?i)(pdqlToken=)[^&\s'\"]+"), r"\1<redacted>"),
    (re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]+"), r"\1<redacted>"),
    (re.compile(r"\bpat_[A-Za-z0-9_-]{8,}\b"), "pat_<redacted>"),
)


def redact_log_text(value: str) -> str:
    """Replace known secret formats with safe placeholders."""
    for pattern, replacement in _SENSITIVE_LOG_PATTERNS:
        value = pattern.sub(replacement, value)
    return value


class RedactingFormatter(logging.Formatter):
    """Format log records and redact secrets from the result."""

    def format(self, record: logging.LogRecord) -> str:
        """Return a formatted log record without known secrets."""
        return redact_log_text(super().format(record))


def build_parser() -> argparse.ArgumentParser:
    """Build and return the integration argument parser."""
    parser = argparse.ArgumentParser(
        description="Интеграция MaxPatrol VM и Jira",
        epilog=(
            "Флаги отдельных команд:\n"
            "  export --fqdn FQDN [FQDN ...] Получить JSON для "
            "активов с указанными FQDN\n"
            "  export --ip IP_OR_RANGE [IP_OR_RANGE ...] Получить JSON "
            "для IP-адресов и диапазонов\n"
            "  sync --dry-run    Прочитать последний JSON и показать "
            "план без изменений в Jira\n"
            "  sync --criticality LEVEL [LEVEL ...] Фильтровать "
            "уязвимости по критичности\n"
            "  run --fqdn FQDN [FQDN ...] Создать задачи для активов "
            "с указанными FQDN\n"
            "  run --ip IP_OR_RANGE [IP_OR_RANGE ...] Создать задачи "
            "для IP-адресов и диапазонов\n"
            "  run --dry-run     Получить новый JSON из MP VM, но не "
            "изменять Jira\n\n"
            "  run --criticality LEVEL [LEVEL ...] Фильтровать "
            "XLSX и таблицу Jira\n\n"
            "Для подробной справки: %(prog)s <команда> --help"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config.yaml"),
        help="YAML-конфигурация",
    )
    parser.add_argument(
        "--env-file", type=Path, default=Path(".env"), help="Файл с секретами"
    )
    parser.add_argument(
        "--base-dir",
        type=Path,
        default=Path.cwd(),
        help=(
            "Директория для датированных снимков, логов и состояния "
            "(по умолчанию cwd)"
        ),
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Подробный вывод"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Создать каталог logs и записать подробный журнал выполнения",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "validate", help="Проверить подключения и конфигурацию"
    )
    export = subparsers.add_parser(
        "export", help="Получить данные MP VM и сохранить JSON"
    )
    _add_asset_filter_arguments(export)
    sync = subparsers.add_parser(
        "sync", help="Взять последний JSON и создать задачи Jira"
    )
    sync.add_argument(
        "--dry-run", action="store_true", help="Не создавать задачи"
    )
    _add_criticality_argument(sync)
    run = subparsers.add_parser("run", help="Выполнить export, затем sync")
    _add_asset_filter_arguments(run)
    run.add_argument(
        "--dry-run",
        action="store_true",
        help="Получить JSON, но не создавать задачи",
    )
    _add_criticality_argument(run)
    subparsers.add_parser("latest", help="Показать путь к последнему JSON")
    return parser


def _fqdn_argument(value: str) -> str:
    """Parse an FQDN and adapt validation errors for argparse."""
    try:
        return normalize_fqdn_filter(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _ip_argument(value: str) -> str:
    """Parse an IP selector and adapt validation errors for argparse."""
    try:
        return normalize_ip_selector(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _add_asset_filter_arguments(parser: argparse.ArgumentParser) -> None:
    """Add mutually exclusive asset filters to a subcommand."""
    filters = parser.add_mutually_exclusive_group()
    filters.add_argument(
        "--fqdn",
        nargs="+",
        type=_fqdn_argument,
        metavar="FQDN",
        help=(
            "Обработать активы с одним или несколькими FQDN"
        ),
    )
    filters.add_argument(
        "--ip",
        nargs="+",
        type=_ip_argument,
        metavar="IP_OR_RANGE",
        help=(
            "Обработать активы по IP-адресам или диапазонам "
            "НАЧАЛО-КОНЕЦ"
        ),
    )


def _criticality_argument(value: str) -> str:
    """Parse criticality and adapt validation errors for argparse."""
    try:
        return normalize_criticality(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _add_criticality_argument(parser: argparse.ArgumentParser) -> None:
    """Add the vulnerability criticality filter to a subcommand."""
    parser.add_argument(
        "--criticality",
        nargs="+",
        type=_criticality_argument,
        metavar="LEVEL",
        help=(
            "Передать в XLSX и Jira только выбранные уровни: "
            f"{', '.join(CRITICALITY_LEVELS)}"
        ),
    )


def _format_filter_log(values: Sequence[str] | None) -> str:
    """Format optional CLI filter values for a compact log record."""
    return ",".join(values) if values else "-"


def configure_logging(
    base_dir: Path, verbose: bool, debug: bool
) -> Path | None:
    """Configure console logging and optional debug file logging."""
    formatter = RedactingFormatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose or debug else logging.INFO)
    root.handlers.clear()
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(formatter)
    root.addHandler(console)
    if not debug:
        return None
    log_dir = base_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_dir.chmod(0o700)
    log_file = log_dir / f"mpvm_jira_{datetime.now().strftime('%Y%m%d')}.log"
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    log_file.chmod(0o600)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)
    return log_file


def main(argv: Sequence[str] | None = None) -> int:
    """Run the requested command and return its process exit code."""
    args = build_parser().parse_args(argv)
    base_dir = args.base_dir.expanduser().resolve()
    base_dir.mkdir(parents=True, exist_ok=True)
    log_file = configure_logging(base_dir, args.verbose, args.debug)
    criticalities = normalize_criticalities(getattr(args, "criticality", None))
    LOG.info(
        "Начало запуска: команда=%s, base_dir=%s, dry_run=%s, fqdn=%s, "
        "ip=%s, criticality=%s",
        args.command,
        base_dir,
        bool(getattr(args, "dry_run", False)),
        _format_filter_log(getattr(args, "fqdn", None)),
        _format_filter_log(getattr(args, "ip", None)),
        ",".join(criticalities) if criticalities else "all",
    )
    if log_file:
        LOG.info("Файловый журнал включен: %s", log_file)
    LOG.debug(
        "Файлы настроек: config=%s, env_file=%s; verbose=%s",
        args.config.expanduser().resolve(),
        args.env_file.expanduser().resolve(),
        args.verbose,
    )
    try:
        if args.command == "latest":
            path = latest_snapshot(base_dir)
            LOG.info("Последний JSON-снимок: %s", path)
            LOG.info("Запуск успешно завершен: команда=latest")
            print(path)
            return 0
        config = load_config(
            args.config.expanduser().resolve(),
            args.env_file.expanduser().resolve(),
        )
        LOG.debug(
            "Конфигурация загружена: mpvm=%s, jira=%s, jira_project=%s",
            config["mpvm"].get("base_url"),
            config["jira"].get("base_url"),
            config["jira"].get("project_key"),
        )
        if args.command == "validate":
            MaxPatrolClient(config["mpvm"]).validate_connection()
            user = JiraClient(config["jira"]).validate_connection()
            user_name = (
                user.get("displayName") or user.get("name") or "unknown"
            )
            LOG.info(
                "Проверка подключений успешно завершена: Jira user=%s",
                user_name,
            )
            LOG.info("Запуск успешно завершен: команда=validate")
            print(f"Подключения работают. Jira user: {user_name}")
            return 0
        exported_path: Path | None = None
        if args.command in {"export", "run"}:
            exported_path = export_snapshot(
                MaxPatrolClient(config["mpvm"]),
                base_dir,
                fqdn=args.fqdn,
                ip=args.ip,
            )
            print(exported_path)
            if args.command == "export":
                LOG.info(
                    "Запуск успешно завершен: команда=export, snapshot=%s",
                    exported_path,
                )
                return 0
        if args.command in {"sync", "run"}:
            result = sync_latest_to_jira(
                JiraClient(config["jira"]),
                base_dir,
                config["jira"],
                dry_run=bool(args.dry_run),
                snapshot_path=exported_path if args.command == "run" else None,
                criticalities=criticalities,
            )
            LOG.info(
                "Обработка Jira завершена: создано=%s, вложений=%s, "
                "пропущено=%s, ошибок=%s",
                len(result["created"]),
                len(result["attached"]),
                len(result["skipped"]),
                len(result["errors"]),
            )
            LOG.info("Запуск успешно завершен: команда=%s", args.command)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
    except (
        ConfigError,
        IntegrationRunError,
        ValueError,
        OSError,
        RuntimeError,
    ) as exc:
        LOG.error(
            "Запуск завершен с ошибкой: команда=%s, ошибка=%s",
            args.command,
            exc,
        )
        if args.verbose or args.debug:
            LOG.exception("Подробности ошибки")
        return 1
    LOG.error("Команда не была обработана: %s", args.command)
    return 2


if __name__ == "__main__":
    sys.exit(main())
