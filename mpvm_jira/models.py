"""Define normalized asset and vulnerability domain models."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

_SEVERITY_RU = {
    "critical": "Критический",
    "критический": "Критический",
    "high": "Высокий",
    "высокий": "Высокий",
    "medium": "Средний",
    "средний": "Средний",
    "low": "Низкий",
    "низкий": "Низкий",
    "info": "Информационный",
    "informational": "Информационный",
    "информационный": "Информационный",
    "undefined": "Не определен",
    "не определен": "Не определен",
    "none": "Не определен",
}


def is_displayable_ip(value: str) -> bool:
    """Return whether an address is useful in a Jira asset title."""
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        # Preserve unexpected MP VM values instead of discarding them.
        return True
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return not (
        address.is_loopback or address.is_link_local or address.is_unspecified
    )


def localized_severity(value: str | None, score: float | None) -> str:
    """Return the Russian severity label for a value or CVSS score."""
    if value:
        normalized = value.strip().casefold()
        if normalized in _SEVERITY_RU:
            return _SEVERITY_RU[normalized]
    if score is None:
        return "Не определен"
    if score >= 9.0:
        return "Критический"
    if score >= 7.0:
        return "Высокий"
    if score >= 4.0:
        return "Средний"
    if score > 0:
        return "Низкий"
    return "Не определен"


@dataclass(frozen=True)
class SoftwarePackage:
    """Represent installed software associated with a vulnerability."""

    name: str = ""
    version: str = ""

    def as_dict(self) -> dict[str, str | None]:
        """Serialize package data to a JSON-compatible mapping."""
        return {
            "name": self.name or None,
            "version": self.version or None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SoftwarePackage:
        """Build an installed package from a snapshot mapping."""
        return cls(
            name=str(data.get("name") or ""),
            version=str(data.get("version") or ""),
        )


@dataclass(frozen=True)
class Vulnerability:
    """Represent one normalized vulnerability from MaxPatrol VM."""

    vulnerability_id: str = ""
    cves: tuple[str, ...] = ()
    bdus: tuple[str, ...] = ()
    packages: tuple[SoftwarePackage, ...] = ()
    cvss_score: float | None = None
    severity: str = ""
    cvss_vector: str = ""
    description: str = ""
    remediation: str = ""
    status: str = ""

    @property
    def criticality(self) -> str:
        """Return a localized severity label with its numeric score."""
        label = localized_severity(self.severity, self.cvss_score)
        score = "—" if self.cvss_score is None else f"{self.cvss_score:.1f}"
        return f"{label} ({score})"

    @property
    def cve_display(self) -> str:
        """Return CVE identifiers or a fallback vulnerability ID."""
        return (
            ", ".join(self.cves)
            if self.cves
            else (self.vulnerability_id or "—")
        )

    @property
    def package_names(self) -> str:
        """Return aligned package names for one report cell."""
        return "; ".join(package.name or "-" for package in self.packages)

    @property
    def package_versions(self) -> str:
        """Return aligned package versions for one report cell."""
        return "; ".join(package.version or "-" for package in self.packages)

    def as_dict(self) -> dict[str, Any]:
        """Serialize the vulnerability to a JSON-compatible mapping."""
        return {
            "vulnerability_id": self.vulnerability_id,
            "cves": list(self.cves),
            "bdus": list(self.bdus),
            "packages": [package.as_dict() for package in self.packages],
            "cvss_score": self.cvss_score,
            "severity": localized_severity(self.severity, self.cvss_score),
            "cvss_vector": self.cvss_vector,
            "criticality": self.criticality,
            "description": self.description,
            "remediation": self.remediation,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Vulnerability:
        """Build a vulnerability from a snapshot mapping."""
        return cls(
            vulnerability_id=str(data.get("vulnerability_id") or ""),
            cves=tuple(str(item) for item in data.get("cves") or []),
            bdus=tuple(str(item) for item in data.get("bdus") or []),
            packages=tuple(
                SoftwarePackage.from_dict(item)
                for item in data.get("packages") or []
                if isinstance(item, dict)
            ),
            cvss_score=data.get("cvss_score"),
            severity=str(data.get("severity") or ""),
            cvss_vector=str(data.get("cvss_vector") or ""),
            description=str(data.get("description") or ""),
            remediation=str(data.get("remediation") or ""),
            status=str(data.get("status") or ""),
        )


@dataclass
class Asset:
    """Represent one MaxPatrol VM asset and its vulnerabilities."""

    asset_id: str
    fqdn: str = ""
    ip_addresses: tuple[str, ...] = ()
    importance: str = "Undefined"
    os_name: str = ""
    os_version: str = ""
    vulnerabilities: list[Vulnerability] = field(default_factory=list)

    @property
    def display_ip_addresses(self) -> tuple[str, ...]:
        """Return IP addresses suitable for Jira display fields."""
        return tuple(
            address
            for address in self.ip_addresses
            if is_displayable_ip(address)
        )

    @property
    def title(self) -> str:
        """Return the preferred Jira title for this asset."""
        ips = ", ".join(self.display_ip_addresses)
        if self.fqdn and ips:
            return f"{self.fqdn} ({ips})"
        if self.fqdn:
            return self.fqdn
        if ips:
            return ips
        return f"Актив {self.asset_id}"

    @property
    def operating_system(self) -> str:
        """Return the operating-system name with a non-duplicate version."""
        name = self.os_name.strip()
        version = self.os_version.strip()
        if name and version and version.casefold() not in name.casefold():
            return f"{name} {version}"
        return name or version

    def as_dict(self) -> dict[str, Any]:
        """Serialize the asset to a JSON-compatible mapping."""
        return {
            "asset_id": self.asset_id,
            "fqdn": self.fqdn or None,
            "ip_addresses": list(self.ip_addresses),
            "importance": self.importance,
            "os_name": self.os_name or None,
            "os_version": self.os_version or None,
            "operating_system": self.operating_system or None,
            "jira_summary": self.title,
            "vulnerabilities": [
                item.as_dict() for item in self.vulnerabilities
            ],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Asset:
        """Build an asset from a snapshot mapping."""
        return cls(
            asset_id=str(data.get("asset_id") or ""),
            fqdn=str(data.get("fqdn") or ""),
            ip_addresses=tuple(
                str(item) for item in data.get("ip_addresses") or []
            ),
            importance=str(data.get("importance") or "Undefined"),
            os_name=str(data.get("os_name") or ""),
            os_version=str(data.get("os_version") or ""),
            vulnerabilities=[
                Vulnerability.from_dict(item)
                for item in data.get("vulnerabilities") or []
            ],
        )
