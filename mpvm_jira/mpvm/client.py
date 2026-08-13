"""Query MaxPatrol VM and normalize asset vulnerability data."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
import time
from collections.abc import Iterable, Iterator, Sequence
from datetime import datetime
from typing import Any

from ..config import env_secret, require
from ..http import ApiError, build_session, checked_json
from ..models import Asset, SoftwarePackage, Vulnerability

LOG = logging.getLogger(__name__)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_BDU_RE = re.compile(r"\b(?:BDU|БДУ)\s*[:\-]?\s*(\d{4}-\d+)\b", re.IGNORECASE)
_FQDN_LABEL_RE = re.compile(
    r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$"
)


def normalize_fqdn_filter(value: str) -> str:
    """Validate and normalize an FQDN supplied through the CLI."""
    normalized = value.strip().rstrip(".")
    if not normalized:
        raise ValueError("FQDN не может быть пустым")
    try:
        normalized = normalized.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError(f"Некорректный FQDN: {value}") from exc
    if len(normalized) > 253:
        raise ValueError("FQDN не может быть длиннее 253 символов")
    if any(
        not _FQDN_LABEL_RE.fullmatch(label) for label in normalized.split(".")
    ):
        raise ValueError(f"Некорректный FQDN: {value}")
    return normalized


def normalize_ip_filter(value: str) -> str:
    """Validate and normalize an IP address supplied through the CLI."""
    normalized = value.strip()
    if not normalized or "%" in normalized:
        raise ValueError(f"Некорректный IP-адрес: {value}")
    try:
        return str(ipaddress.ip_address(normalized))
    except ValueError as exc:
        raise ValueError(f"Некорректный IP-адрес: {value}") from exc


def normalize_ip_selector(value: str) -> str:
    """Validate and normalize one IP address or inclusive IP range."""
    normalized = value.strip()
    if "-" not in normalized:
        return normalize_ip_filter(normalized)

    start_text, separator, end_text = normalized.partition("-")
    if not separator or not start_text.strip() or not end_text.strip():
        raise ValueError(
            f"Некорректный диапазон IP-адресов: {value}"
        )
    try:
        start = ipaddress.ip_address(start_text.strip())
        end = ipaddress.ip_address(end_text.strip())
    except ValueError as exc:
        raise ValueError(
            f"Некорректный диапазон IP-адресов: {value}"
        ) from exc
    if start.version != end.version:
        raise ValueError(
            "Начало и конец диапазона должны использовать "
            "одну версию IP"
        )
    if int(start) > int(end):
        raise ValueError(
            "Начало диапазона IP должно быть не больше конца: "
            f"{value}"
        )
    return f"{start}-{end}"


def asset_filter_expression(
    *,
    fqdn: str | Sequence[str] | None = None,
    ip: str | Sequence[str] | None = None,
) -> tuple[str | None, dict[str, Any]]:
    """Build a safe PDQL asset filter and its snapshot metadata."""
    fqdns = _unique_values(
        normalize_fqdn_filter(item) for item in _filter_values(fqdn)
    )
    ip_selectors = _unique_values(
        normalize_ip_selector(item) for item in _filter_values(ip)
    )
    if fqdns and ip_selectors:
        raise ValueError(
            "Флаги --fqdn и --ip нельзя использовать одновременно"
        )
    if fqdns:
        if len(fqdns) == 1:
            expression = f"Host.FQDN = '{fqdns[0]}'"
        else:
            values = ", ".join(f"'{item}'" for item in fqdns)
            expression = f"Host.FQDN in [{values}]"
        return expression, {"fqdns": list(fqdns)}
    if ip_selectors:
        return _ip_filter_expression(ip_selectors), {
            "ip_selectors": list(ip_selectors)
        }
    return None, {}


def _filter_values(value: str | Sequence[str] | None) -> tuple[str, ...]:
    """Return scalar or sequence filter input as a tuple."""
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(value)


def _unique_values(values: Iterable[str]) -> tuple[str, ...]:
    """Deduplicate normalized values while preserving their order."""
    return tuple(dict.fromkeys(values))


def _ip_filter_expression(selectors: Sequence[str]) -> str:
    """Build a PDQL expression from IP addresses and inclusive ranges."""
    addresses: list[str] = []
    networks: list[str] = []
    for selector in selectors:
        if "-" not in selector:
            addresses.append(selector)
            continue
        start_text, end_text = selector.split("-", 1)
        start = ipaddress.ip_address(start_text)
        end = ipaddress.ip_address(end_text)
        networks.extend(
            str(network)
            for network in ipaddress.summarize_address_range(start, end)
        )

    terms: list[str] = []
    if len(addresses) == 1:
        terms.append(f"Host.@IpAddresses contains {addresses[0]}")
    elif addresses:
        terms.append(
            "Host.@IpAddresses intersect [" + ", ".join(addresses) + "]"
        )
    terms.extend(
        f"Host.@IpAddresses.Item in {network}" for network in networks
    )
    if len(terms) == 1:
        return terms[0]
    return "(" + " or ".join(terms) + ")"


def apply_pdql_filter(pdql: str, expression: str) -> str:
    """Merge an asset expression into the leading PDQL filter."""
    query = pdql.strip()
    leading_filter = re.match(r"(?i)^filter\s*\(", query)
    if not leading_filter:
        return f"Filter({expression}) | {query}"

    opening = leading_filter.end() - 1
    depth = 0
    quote: str | None = None
    escaped = False
    closing: int | None = None
    for index in range(opening, len(query)):
        character = query[index]
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {"'", '"'}:
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                closing = index
                break
    if closing is None:
        raise ValueError(
            "Некорректный PDQL: не закрыта скобка начального Filter"
        )

    existing = query[opening + 1 : closing].strip()
    remainder = query[closing + 1 :].strip()
    if remainder and not remainder.startswith("|"):
        raise ValueError("Некорректный PDQL после начального Filter")
    combined = f"Filter(({expression}) and ({existing}))"
    return f"{combined} {remainder}" if remainder else combined


class MaxPatrolClient:
    """Access MaxPatrol VM authentication and PDQL APIs."""

    def __init__(self, config: dict[str, Any]):
        """Initialize a MaxPatrol VM client from configuration."""
        self.config = config
        self.base_url = str(require(config, "base_url")).rstrip("/")
        self.timeout = float(config.get("timeout_seconds", 60))
        self.verify = config.get("verify_ssl", True)
        self.page_size = int(config.get("page_size", 1000))
        self.max_pages = int(config.get("max_pages", 10000))
        self.session = build_session(
            int(config.get("retries", 3)), "mpvm-jira-integration/1.0"
        )
        self._authenticated = False

    def authenticate(self) -> None:
        """Configure reference-token authorization for API requests."""
        LOG.debug("Авторизация MP VM: base_url=%s", self.base_url)
        token = env_secret(self.config, "access_token_env")
        self.session.headers.update({"Authorization": f"Bearer {token}"})
        self._authenticated = True
        LOG.debug("Авторизация MP VM настроена")

    def _ensure_auth(self) -> None:
        """Authenticate lazily before the first API request."""
        if not self._authenticated:
            self.authenticate()

    def validate_connection(self) -> None:
        """Validate MaxPatrol VM authentication and API access."""
        self._ensure_auth()
        LOG.debug("Проверка подключения к MP VM: %s", self.base_url)
        response = self.session.get(
            f"{self.base_url}/api/scopes/v2/scopes",
            params={"limit": 1, "offset": 0},
            timeout=self.timeout,
            verify=self.verify,
        )
        checked_json(response, "Проверка подключения к MP VM")
        LOG.debug("Подключение к MP VM подтверждено")

    def query_pdql(self, pdql: str) -> str:
        """Submit a PDQL query and return its result token."""
        self._ensure_auth()
        LOG.debug("Отправка PDQL-запроса: %s", pdql)
        response = self.session.post(
            f"{self.base_url}/api/assets_temporal_readmodel/v1/assets_grid",
            json={
                "pdql": pdql,
                "includeNestedGroups": True,
                "utcOffset": str(self.config.get("utc_offset", "+00:00")),
            },
            timeout=self.timeout,
            verify=self.verify,
        )
        body = checked_json(response, "Создание PDQL-запроса")
        token = body.get("token") if isinstance(body, dict) else None
        if not token:
            raise ApiError("MP VM не вернул PDQL-токен")
        LOG.debug("PDQL-запрос принят MP VM")
        return str(token)

    def iter_pdql_records(self, pdql: str) -> Iterator[dict[str, Any]]:
        """Yield all records from a paginated PDQL query result."""
        token = self.query_pdql(pdql)
        delay = float(self.config.get("initial_result_delay_seconds", 5))
        if delay > 0:
            time.sleep(delay)
        received_count = 0
        previous_digest: str | None = None
        for page in range(self.max_pages):
            offset = page * self.page_size
            response = self.session.get(
                f"{self.base_url}/api/assets_temporal_readmodel/"
                "v1/assets_grid/data",
                params={
                    "limit": self.page_size,
                    "offset": offset,
                    "pdqlToken": token,
                },
                timeout=self.timeout,
                verify=self.verify,
            )
            body = checked_json(response, "Получение результата PDQL-запроса")
            page_records = (
                body.get("records") if isinstance(body, dict) else None
            )
            if not isinstance(page_records, list):
                raise ApiError("Ответ MP VM не содержит массив records")
            total = _first_int(body, "totalCount", "total")
            LOG.debug(
                "Страница PDQL получена: offset=%s, записей=%s, всего=%s",
                offset,
                len(page_records),
                total if total is not None else "не указано",
            )
            digest = hashlib.sha256(
                json.dumps(
                    page_records,
                    ensure_ascii=False,
                    sort_keys=True,
                    default=str,
                ).encode("utf-8")
            ).hexdigest()
            if page > 0 and digest == previous_digest:
                LOG.warning(
                    "MP VM повторил страницу данных; пагинация "
                    "остановлена на offset=%s",
                    offset,
                )
                break
            previous_digest = digest
            received_count += len(page_records)
            yield from (
                item for item in page_records if isinstance(item, dict)
            )
            if len(page_records) < self.page_size or (
                total is not None and received_count >= total
            ):
                break
        else:
            raise ApiError(
                f"Превышен предел пагинации MP VM ({self.max_pages} страниц)"
            )

    def fetch_pdql_records(self, pdql: str) -> list[dict[str, Any]]:
        """Return all records from a PDQL query as a list."""
        return list(self.iter_pdql_records(pdql))

    def collect_snapshot(
        self,
        *,
        fqdn: str | Sequence[str] | None = None,
        ip: str | Sequence[str] | None = None,
    ) -> dict[str, Any]:
        """Collect and normalize one current vulnerability snapshot."""
        assets_pdql = str(require(self.config, "assets_pdql"))
        vulnerabilities_pdql = str(
            require(self.config, "vulnerabilities_pdql")
        )
        software_vulnerabilities_pdql = str(
            self.config.get("software_vulnerabilities_pdql") or ""
        ).strip()
        filter_expression, filter_metadata = asset_filter_expression(
            fqdn=fqdn, ip=ip
        )
        if filter_expression:
            assets_pdql = apply_pdql_filter(assets_pdql, filter_expression)
            vulnerabilities_pdql = apply_pdql_filter(
                vulnerabilities_pdql, filter_expression
            )
            if software_vulnerabilities_pdql:
                software_vulnerabilities_pdql = apply_pdql_filter(
                    software_vulnerabilities_pdql,
                    filter_expression,
                )
            LOG.info("Применен фильтр актива: %s", filter_expression)
        LOG.info("Получение активов из MaxPatrol VM")
        asset_records = self.fetch_pdql_records(assets_pdql)
        LOG.info("Получено строк активов: %s", len(asset_records))
        LOG.info("Получение актуальных уязвимостей из MaxPatrol VM")
        vulnerability_count = 0
        software_vulnerability_count = 0

        def vulnerability_records() -> Iterator[dict[str, Any]]:
            nonlocal vulnerability_count
            for record in self.iter_pdql_records(vulnerabilities_pdql):
                vulnerability_count += 1
                yield record

        def software_vulnerability_records() -> Iterator[dict[str, Any]]:
            nonlocal software_vulnerability_count
            if not software_vulnerabilities_pdql:
                return
            LOG.info(
                "Получение связей уязвимостей с установленным ПО из MP VM"
            )
            for record in self.iter_pdql_records(
                software_vulnerabilities_pdql
            ):
                software_vulnerability_count += 1
                yield record

        snapshot = build_snapshot_from_records(
            asset_records,
            vulnerability_records(),
            software_vulnerability_records(),
            source_url=self.base_url,
            active_statuses=[
                str(item) for item in self.config.get("active_statuses", [])
            ],
        )
        LOG.info("Получено строк уязвимостей: %s", vulnerability_count)
        if software_vulnerabilities_pdql:
            LOG.info(
                "Получено связей уязвимостей с установленным ПО: %s",
                software_vulnerability_count,
            )
        else:
            LOG.warning(
                "mpvm.software_vulnerabilities_pdql не настроен; "
                "поля пакета будут пустыми"
            )
        snapshot["filters"].update(filter_metadata)
        matched_assets = int(snapshot["statistics"]["assets_total"])
        if filter_metadata and matched_assets == 0:
            LOG.warning(
                "Активы по заданному фильтру не найдены; JSON будет пустым"
            )
        LOG.debug(
            "Статистика сформированного снимка: %s", snapshot["statistics"]
        )
        return snapshot


def build_snapshot_from_records(
    asset_records: Iterable[dict[str, Any]],
    vulnerability_records: Iterable[dict[str, Any]],
    software_vulnerability_records: Iterable[dict[str, Any]] = (),
    *,
    source_url: str,
    active_statuses: list[str],
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Normalize raw asset and vulnerability records into a snapshot."""
    assets: dict[str, Asset] = {}
    for record in asset_records:
        asset_id = _asset_id(record)
        if not asset_id:
            LOG.warning("Пропущена строка актива без AssetId: %r", record)
            continue
        assets[asset_id] = Asset(
            asset_id=asset_id,
            fqdn=_text(_field(record, "Fqdn", "FQDN", "Host.FQDN")).strip(),
            ip_addresses=tuple(
                _ip_addresses(
                    _field(record, "IpAddresses", "IPLIST", "@IPLIST")
                )
            ),
            importance=_text(
                _field(record, "AssetImportance", "Importance", "@Importance")
            ).strip()
            or "Undefined",
            os_name=_text(
                _field(record, "OsName", "OSName", "Host.OsName")
            ).strip(),
            os_version=_text(
                _field(record, "OsVersion", "OSVersion", "Host.OsVersion")
            ).strip(),
        )

    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    active = {item.casefold() for item in active_statuses}
    for record in vulnerability_records:
        asset_id = _asset_id(record)
        if not asset_id:
            LOG.warning("Пропущена строка уязвимости без AssetId: %r", record)
            continue
        status = _text(_field(record, "Status", "@Vulners.Status")).strip()
        if active and status and status.casefold() not in active:
            continue
        vulnerability_id = _text(
            _field(record, "VulnerabilityId", "VulnerId", "@Vulners.Id")
        ).strip()
        grouping_id = (
            vulnerability_id
            or "anonymous:"
            + hashlib.sha256(
                json.dumps(
                    {
                        "cves": _field(record, "Cves", "CVE", "@Vulners.Cves"),
                        "description": _field(
                            record, "Description", "@Vulners.Description"
                        ),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                    default=str,
                ).encode("utf-8")
            ).hexdigest()
        )
        key = (asset_id, grouping_id)
        item = grouped.setdefault(
            key,
            {
                "asset_id": asset_id,
                "vulnerability_id": vulnerability_id,
                "cves": set(),
                "bdus": set(),
                "score": None,
                "severity": "",
                "vector": "",
                "description": "",
                "remediation": "",
                "status": status,
            },
        )
        identifier_values = _field(
            record, "Identifiers", "ExternalIdentifiers", "@Vulners.Ids"
        )
        item["cves"].update(
            _cves(_field(record, "Cves", "CVE", "@Vulners.Cves"))
        )
        item["cves"].update(_cves(identifier_values))
        item["bdus"].update(_bdus(identifier_values))
        score = _float(_field(record, "CvssScore", "Score", "@Vulners.Score"))
        if score is not None:
            item["score"] = score
        for target, value in (
            (
                "severity",
                _text(
                    _field(
                        record,
                        "Severity",
                        "SeverityRating",
                        "@Vulners.SeverityRating",
                    )
                ),
            ),
            (
                "vector",
                _text(
                    _field(record, "Cvss3Vector", "@Vulners.Cvss3Vector")
                    or _field(record, "Cvss2Vector", "@Vulners.Cvss2Vector")
                ),
            ),
            (
                "description",
                _text(_field(record, "Description", "@Vulners.Description")),
            ),
            (
                "remediation",
                _text(
                    _field(
                        record, "HowToFix", "Remediation", "@Vulners.HowToFix"
                    )
                ),
            ),
            ("status", status),
        ):
            if value.strip():
                item[target] = value.strip()

    packages: dict[tuple[str, str], set[SoftwarePackage]] = {}
    for record in software_vulnerability_records:
        asset_id = _asset_id(record)
        vulnerability_id = _text(
            _field(record, "VulnerabilityId", "VulnerId", "@Vulners.Id")
        ).strip()
        if not asset_id or not vulnerability_id:
            continue
        status = _text(_field(record, "Status", "@Vulners.Status")).strip()
        if active and status and status.casefold() not in active:
            continue
        package = SoftwarePackage(
            name=_text(
                _field(record, "PackageName", "SoftwareName", "Softs.Name")
            ).strip(),
            version=_text(
                _field(
                    record,
                    "PackageVersion",
                    "SoftwareVersion",
                    "Softs.Version",
                )
            ).strip(),
        )
        if package.name or package.version:
            packages.setdefault((asset_id, vulnerability_id), set()).add(
                package
            )

    for item in grouped.values():
        vulnerability = Vulnerability(
            vulnerability_id=item["vulnerability_id"],
            cves=tuple(sorted(item["cves"])),
            bdus=tuple(sorted(item["bdus"])),
            packages=tuple(
                sorted(
                    packages.get(
                        (item["asset_id"], item["vulnerability_id"]),
                        (),
                    ),
                    key=lambda package: (
                        package.name.casefold(),
                        package.version.casefold(),
                    ),
                )
            ),
            cvss_score=item["score"],
            severity=item["severity"],
            cvss_vector=item["vector"],
            description=item["description"],
            remediation=item["remediation"],
            status=item["status"],
        )
        asset = assets.setdefault(
            item["asset_id"], Asset(asset_id=item["asset_id"])
        )
        asset.vulnerabilities.append(vulnerability)

    for asset in assets.values():
        asset.vulnerabilities.sort(
            key=lambda item: (
                -(item.cvss_score if item.cvss_score is not None else -1),
                item.cve_display,
            )
        )
    now = generated_at or datetime.now().astimezone()
    vulnerable_assets = sorted(
        (asset for asset in assets.values() if asset.vulnerabilities),
        key=lambda item: item.title.casefold(),
    )
    return {
        "schema_version": 2,
        "generated_at": now.isoformat(timespec="seconds"),
        "source": {"product": "MaxPatrol VM", "base_url": source_url},
        "filters": {"active_statuses": active_statuses},
        "statistics": {
            "assets_total": len(assets),
            "assets_with_vulnerabilities": len(vulnerable_assets),
            "vulnerabilities_total": sum(
                len(asset.vulnerabilities) for asset in vulnerable_assets
            ),
        },
        "assets": [asset.as_dict() for asset in vulnerable_assets],
    }


def _normalized_key(value: str) -> str:
    """Normalize an API field name for tolerant record lookup."""
    return re.sub(r"[^a-z0-9]", "", value.casefold().replace("@", ""))


def _field(record: dict[str, Any], *names: str) -> Any:
    """Return the first matching record field using tolerant names."""
    for name in names:
        if name in record:
            return record[name]
    normalized = {
        _normalized_key(str(key)): value for key, value in record.items()
    }
    for name in names:
        if _normalized_key(name) in normalized:
            return normalized[_normalized_key(name)]
    return None


def _asset_id(record: dict[str, Any]) -> str:
    """Extract a normalized asset identifier from an API record."""
    value = _field(record, "AssetId", "@ID", "Id", "@Host")
    if isinstance(value, dict):
        value = value.get("id") or value.get("Id") or value.get("value")
    return _text(value).strip()


def _text(value: Any) -> str:
    """Convert a nested API value to display text."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, list):
        return "\n".join(part for item in value if (part := _text(item)))
    if isinstance(value, dict):
        for key in (
            "displayValue",
            "displayName",
            "localizedName",
            "value",
            "name",
            "label",
            "id",
        ):
            if key in value:
                return _text(value[key])
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def _iter_scalars(value: Any) -> Iterable[str]:
    """Yield scalar strings from nested API values."""
    if isinstance(value, dict):
        for child in value.values():
            yield from _iter_scalars(child)
    elif isinstance(value, (list, tuple, set)):
        for child in value:
            yield from _iter_scalars(child)
    elif value is not None:
        yield str(value)


def _cves(value: Any) -> list[str]:
    """Extract unique CVE identifiers from a nested value."""
    found: set[str] = set()
    for text in _iter_scalars(value):
        found.update(match.upper() for match in _CVE_RE.findall(text))
    return sorted(found)


def _bdus(value: Any) -> list[str]:
    """Extract unique BDU identifiers from a nested value."""
    found: set[str] = set()
    for text in _iter_scalars(value):
        found.update(f"BDU:{match}" for match in _BDU_RE.findall(text))
    return sorted(found)


def _ip_addresses(value: Any) -> list[str]:
    """Extract unique IP addresses from a nested value."""
    found: list[str] = []
    for text in _iter_scalars(value):
        for candidate in re.split(r"[|,;\s]+", text):
            candidate = candidate.strip("[]()")
            if not candidate:
                continue
            try:
                normalized = str(ipaddress.ip_address(candidate))
            except ValueError:
                continue
            if normalized not in found:
                found.append(normalized)
    return found


def _float(value: Any) -> float | None:
    """Return the first parseable floating-point value."""
    if isinstance(value, dict):
        value = next(
            (
                value[key]
                for key in ("value", "score", "displayValue")
                if key in value
            ),
            None,
        )
    if value in (None, ""):
        return None
    try:
        return float(str(value).replace(",", "."))
    except ValueError:
        return None


def _first_int(body: dict[str, Any], *keys: str) -> int | None:
    """Return the first parseable integer for the requested keys."""
    for key in keys:
        value = body.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return None
