"""Provide shared HTTP helpers for MaxPatrol VM and Jira."""

from __future__ import annotations

from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class ApiError(RuntimeError):
    """Report an invalid or unsuccessful remote API response."""


def build_session(retries: int, user_agent: str) -> requests.Session:
    """Build a requests session with retries and common headers."""
    session = requests.Session()
    retry = Retry(
        total=retries,
        connect=retries,
        read=retries,
        status=retries,
        backoff_factor=0.7,
        status_forcelist=(429, 502, 503, 504),
        allowed_methods=frozenset({"GET", "HEAD", "OPTIONS"}),
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    # HTTP оставлен для совместимости с отдельными инсталляциями продукта.
    # Он передает токены без шифрования и не рекомендуется к использованию.
    session.mount("http://", adapter)
    session.headers.update(
        {"User-Agent": user_agent, "Accept": "application/json"}
    )
    return session


def checked_json(response: requests.Response, context: str) -> Any:
    """Validate an HTTP response and return its decoded JSON body."""
    if not response.ok:
        raise ApiError(f"{context}: HTTP {response.status_code}")
    try:
        return response.json()
    except ValueError as exc:
        raise ApiError(f"{context}: сервер вернул не JSON") from exc
