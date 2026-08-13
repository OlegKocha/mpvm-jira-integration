"""Classify and filter vulnerabilities by user-facing criticality."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from ..models import Vulnerability, localized_severity


CRITICALITY_LEVELS = (
    "Critical",
    "High",
    "Medium",
    "Low",
    "Non-crit",
)
_LEVEL_BY_CASEFOLD = {level.casefold(): level for level in CRITICALITY_LEVELS}
_LEVEL_BY_LOCALIZED_SEVERITY = {
    "Критический": "Critical",
    "Высокий": "High",
    "Средний": "Medium",
    "Низкий": "Low",
}


def normalize_criticality(value: str) -> str:
    """Return a canonical criticality level or raise ValueError."""
    normalized = _LEVEL_BY_CASEFOLD.get(value.strip().casefold())
    if normalized:
        return normalized
    allowed = ", ".join(CRITICALITY_LEVELS)
    raise ValueError(
        f"Неизвестный уровень критичности {value!r}. Допустимы: {allowed}"
    )


def normalize_criticalities(
    values: Sequence[str] | None,
) -> tuple[str, ...] | None:
    """Normalize, deduplicate, and canonically order selected levels."""
    if not values:
        return None
    selected = {normalize_criticality(value) for value in values}
    return tuple(level for level in CRITICALITY_LEVELS if level in selected)


def vulnerability_criticality(vulnerability: Vulnerability) -> str:
    """Return the filter level assigned to one vulnerability."""
    if not vulnerability.cvss_vector.strip():
        return "Non-crit"
    localized = localized_severity(
        vulnerability.severity,
        vulnerability.cvss_score,
    )
    return _LEVEL_BY_LOCALIZED_SEVERITY.get(localized, "Non-crit")


def filter_vulnerabilities(
    vulnerabilities: Iterable[Vulnerability],
    criticalities: Sequence[str] | None,
) -> list[Vulnerability]:
    """Return vulnerabilities matching the selected criticalities."""
    selected = normalize_criticalities(criticalities)
    if selected is None:
        return list(vulnerabilities)
    allowed = set(selected)
    return [
        vulnerability
        for vulnerability in vulnerabilities
        if vulnerability_criticality(vulnerability) in allowed
    ]
