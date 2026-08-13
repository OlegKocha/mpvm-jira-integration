"""Persist and discover timestamped vulnerability snapshots."""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

_FILE_RE = re.compile(r"^vulnerabilities_(\d{2})\.(\d{2})\.(\d{2})\.json$")


def save_snapshot(
    base_dir: Path, payload: dict[str, Any], now: datetime | None = None
) -> Path:
    """Atomically save a timestamped JSON snapshot."""
    now = now or datetime.now().astimezone()
    target_dir = base_dir / now.strftime("%d.%m.%Y")
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"vulnerabilities_{now.strftime('%H.%M.%S')}.json"
    if target.exists():
        raise FileExistsError(f"Файл снимка уже существует: {target}")
    serialized = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=target_dir,
        prefix=".snapshot-",
        delete=False,
    ) as stream:
        stream.write(serialized)
        temporary = Path(stream.name)
    os.replace(temporary, target)
    return target


def latest_snapshot(base_dir: Path) -> Path:
    """Return the newest snapshot selected from dated directories."""
    dated_dirs: list[tuple[datetime, Path]] = []
    if not base_dir.is_dir():
        raise FileNotFoundError(f"Базовая директория не найдена: {base_dir}")
    for child in base_dir.iterdir():
        if not child.is_dir():
            continue
        try:
            date = datetime.strptime(child.name, "%d.%m.%Y")
        except ValueError:
            continue
        dated_dirs.append((date, child))
    for _, directory in sorted(dated_dirs, reverse=True):
        candidates: list[tuple[tuple[int, int, int], Path]] = []
        for path in directory.iterdir():
            match = _FILE_RE.match(path.name)
            if not path.is_file() or not match:
                continue
            time_key = tuple(int(part) for part in match.groups())
            if time_key[0] > 23 or time_key[1] > 59 or time_key[2] > 59:
                continue
            candidates.append((time_key, path))
        if candidates:
            return max(candidates, key=lambda item: item[0])[1]
    raise FileNotFoundError(
        f"Снимки vulnerabilities_HH.MM.SS.json не найдены в {base_dir}"
    )


def read_snapshot(path: Path) -> dict[str, Any]:
    """Read and validate a vulnerability snapshot from disk."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") not in {1, 2}:
        raise ValueError(f"Неподдерживаемый формат снимка: {path}")
    if not isinstance(data.get("assets"), list):
        raise ValueError(f"В снимке отсутствует массив assets: {path}")
    return data
