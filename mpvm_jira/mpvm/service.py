"""Export MaxPatrol VM vulnerability data to timestamped JSON snapshots."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from pathlib import Path

from .client import MaxPatrolClient
from .snapshot import save_snapshot

LOG = logging.getLogger(__name__)


def export_snapshot(
    client: MaxPatrolClient,
    base_dir: Path,
    *,
    fqdn: Sequence[str] | None = None,
    ip: Sequence[str] | None = None,
) -> Path:
    """Collect MP VM data and save one current JSON snapshot."""
    LOG.debug(
        "Начало экспорта MP VM: base_dir=%s, fqdn=%s, ip=%s",
        base_dir,
        fqdn,
        ip,
    )
    payload = client.collect_snapshot(fqdn=fqdn, ip=ip)
    path = save_snapshot(base_dir, payload)
    stats = payload["statistics"]
    LOG.info(
        "Снимок сохранен: %s (активов с уязвимостями: %s, "
        "уязвимостей: %s)",
        path,
        stats["assets_with_vulnerabilities"],
        stats["vulnerabilities_total"],
    )
    return path
