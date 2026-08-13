"""Create Jira issues and XLSX attachments from MP VM JSON snapshots."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from ..models import Asset
from ..mpvm.snapshot import latest_snapshot, read_snapshot
from .client import JiraClient
from .criticality import (
    CRITICALITY_LEVELS,
    filter_vulnerabilities,
    normalize_criticalities,
)
from .xlsx_export import export_asset_xlsx

LOG = logging.getLogger(__name__)


class IntegrationRunError(RuntimeError):
    """Report one or more failures during a synchronization run."""


def sync_latest_to_jira(
    client: JiraClient,
    base_dir: Path,
    jira_config: dict[str, Any],
    *,
    dry_run: bool = False,
    snapshot_path: Path | None = None,
    criticalities: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Create Jira issues and XLSX attachments from a snapshot."""
    path = snapshot_path or latest_snapshot(base_dir)
    snapshot = read_snapshot(path)
    assets = [Asset.from_dict(item) for item in snapshot["assets"]]
    policy = str(jira_config.get("duplicate_policy", "skip_seen_snapshot"))
    if policy not in {"skip_seen_snapshot", "create"}:
        raise ValueError(f"Неизвестная duplicate_policy: {policy}")
    state_path = base_dir / str(
        jira_config.get("state_file", ".mpvm-jira-state.json")
    )
    state = _read_state(state_path)
    snapshot_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    attachment_dir = path.parent / str(
        jira_config.get("attachment_subdir", "attachments")
    )
    max_issues = int(jira_config.get("max_issues_per_run", 0))
    selected = normalize_criticalities(criticalities)
    created: list[dict[str, str]] = []
    attached: list[dict[str, str]] = []
    skipped: list[str] = []
    filtered_out: list[str] = []
    errors: list[str] = []
    planned = 0
    jira_validated = False

    LOG.info(
        "Начало обработки JSON: snapshot=%s, активов=%s, dry_run=%s, "
        "duplicate_policy=%s, criticality=%s",
        path,
        len(assets),
        dry_run,
        policy,
        ",".join(selected) if selected else "all",
    )

    for asset in assets:
        if not asset.vulnerabilities:
            continue
        if selected:
            asset = replace(
                asset,
                vulnerabilities=filter_vulnerabilities(
                    asset.vulnerabilities,
                    selected,
                ),
            )
            if not asset.vulnerabilities:
                filtered_out.append(asset.title)
                LOG.info(
                    "Пропуск актива без выбранных уровней критичности: %s",
                    asset.title,
                )
                continue
        state_key = _state_key(snapshot_hash, asset.asset_id, selected)
        record = state["processed"].get(state_key)
        if policy == "skip_seen_snapshot" and _is_complete(record):
            skipped.append(asset.title)
            LOG.info("Пропуск уже обработанного актива: %s", asset.title)
            continue
        if max_issues and len(created) >= max_issues and not record:
            LOG.info("Достигнут предел max_issues_per_run=%s", max_issues)
            break
        if dry_run:
            planned += 1
            LOG.info(
                "DRY-RUN: задача %r, приоритет актива %s, XLSX с %s "
                "уязвимостями",
                asset.title,
                asset.importance,
                len(asset.vulnerabilities),
            )
            continue

        if not jira_validated:
            client.validate_connection()
            jira_validated = True
        xlsx_path = export_asset_xlsx(asset, attachment_dir)
        # Preserve progress for other assets when one asset fails.
        try:
            if record and record.get("issue_key"):
                issue_key = str(record["issue_key"])
                LOG.info(
                    "Повторная загрузка XLSX в уже созданную задачу %s",
                    issue_key,
                )
            else:
                result = client.create_issue(asset, criticalities=selected)
                issue_key = str(result["key"])
                created.append({"asset": asset.title, "issue_key": issue_key})
                record = {
                    "asset_id": asset.asset_id,
                    "asset": asset.title,
                    "snapshot": str(path),
                    "issue_key": issue_key,
                    "xlsx": str(xlsx_path),
                    "attachment_uploaded": False,
                    "criticalities": list(selected) if selected else [],
                }
                state["processed"][state_key] = record
                _write_state(state_path, state)
                LOG.info(
                    "Создана задача Jira %s для %s", issue_key, asset.title
                )

            attachment = client.attach_file(issue_key, xlsx_path)
            record["xlsx"] = str(xlsx_path)
            record["attachment_uploaded"] = True
            record["attachment_id"] = str(attachment.get("id") or "")
            record["attachment_name"] = str(
                attachment.get("filename") or xlsx_path.name
            )
            state["processed"][state_key] = record
            _write_state(state_path, state)
            attached.append(
                {
                    "asset": asset.title,
                    "issue_key": issue_key,
                    "xlsx": str(xlsx_path),
                }
            )
            LOG.info(
                "XLSX %s прикреплен к задаче Jira %s",
                xlsx_path.name,
                issue_key,
            )
        except Exception as exc:
            LOG.exception("Не удалось обработать Jira для %s", asset.title)
            errors.append(f"{asset.title}: {exc}")

    result = {
        "snapshot": str(path),
        "created": created,
        "attached": attached,
        "skipped": skipped,
        "filtered_out": filtered_out,
        "errors": errors,
        "dry_run": dry_run,
        "criticalities": list(selected or CRITICALITY_LEVELS),
    }
    LOG.info(
        "Обработка JSON завершена: запланировано=%s, создано=%s, вложений=%s, "
        "пропущено=%s, отфильтровано=%s, ошибок=%s",
        planned,
        len(created),
        len(attached),
        len(skipped),
        len(filtered_out),
        len(errors),
    )
    if errors:
        raise IntegrationRunError(
            f"Создано задач: {len(created)}; "
            f"прикреплено XLSX: {len(attached)}; "
            f"ошибок: {len(errors)}. Первая ошибка: {errors[0]}"
        )
    return result


def _state_key(
    snapshot_hash: str,
    asset_id: str,
    criticalities: Sequence[str] | None,
) -> str:
    """Build a duplicate-state key for a snapshot, asset, and filter."""
    key = f"{snapshot_hash}:{asset_id}"
    selected = normalize_criticalities(criticalities)
    if selected:
        key += f":criticality={','.join(selected)}"
    return key


def _is_complete(record: Any) -> bool:
    """Return whether a state record needs no further processing."""
    if not isinstance(record, dict):
        return False
    if "attachment_uploaded" not in record:
        # State schema v1 did not track attachment completion.
        return True
    return bool(record["attachment_uploaded"])


def _read_state(path: Path) -> dict[str, Any]:
    """Read and validate synchronization state from disk."""
    if not path.exists():
        return {"schema_version": 2, "processed": {}}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(
        data.get("processed"), dict
    ):
        raise ValueError(f"Некорректный файл состояния: {path}")
    data["schema_version"] = 2
    return data


def _write_state(path: Path, state: dict[str, Any]) -> None:
    """Atomically persist synchronization state to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=".state-",
        delete=False,
    ) as stream:
        json.dump(state, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        temporary = Path(stream.name)
    os.replace(temporary, path)
