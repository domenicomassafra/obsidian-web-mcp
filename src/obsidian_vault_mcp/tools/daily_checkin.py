"""Thin client for the single Signal Deck ``daily.checkin`` writer.

The ChatGPT app is only a typed client. Signal Deck remains the sole owner of
Notion mutation, idempotency receipts, Registry ordering and rollback.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


SIGNAL_DECK_URL_ENV = "LIFEOS_SIGNAL_DECK_URL"
DEFAULT_SIGNAL_DECK_URL = "https://minipc-ubuntu.garibaldi-atlas.ts.net:8443"
_ALLOWED_SIGNAL_DECK_HOSTS = frozenset({"minipc-ubuntu.garibaldi-atlas.ts.net"})
_MAX_RESPONSE_BYTES = 512 * 1024


def _base_url() -> str:
    value = os.environ.get(SIGNAL_DECK_URL_ENV, DEFAULT_SIGNAL_DECK_URL).strip()
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in _ALLOWED_SIGNAL_DECK_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            f"{SIGNAL_DECK_URL_ENV} must be the private HTTPS Signal Deck origin"
        )
    return value.rstrip("/")


def _bounded_json(response) -> dict[str, Any]:
    body = response.read(_MAX_RESPONSE_BYTES + 1)
    if len(body) > _MAX_RESPONSE_BYTES:
        raise RuntimeError("Signal Deck response exceeded the client limit")
    payload = json.loads(body)
    if not isinstance(payload, dict):
        raise RuntimeError("Signal Deck returned a non-object response")
    return payload


def _http_error_message(error: urllib.error.HTTPError) -> str:
    try:
        payload = _bounded_json(error)
    except Exception:
        return f"HTTP {error.code}"
    detail = payload.get("detail")
    if isinstance(detail, dict):
        detail = detail.get("message") or detail.get("code")
    return str(detail or f"HTTP {error.code}")[:240]


def _request(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    base_url = _base_url()
    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cookies)
    )
    try:
        with opener.open(f"{base_url}/", timeout=15) as bootstrap:
            bootstrap.read(1)
        csrf = next(
            cookie.value
            for cookie in cookies
            if cookie.name == "__Host-controlcenter_csrf"
        )
        request = urllib.request.Request(
            f"{base_url}{path}",
            data=json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Origin": base_url,
                "X-CSRF-Token": csrf,
            },
            method="POST",
        )
        with opener.open(request, timeout=45) as response:
            return _bounded_json(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError(
            f"Signal Deck rejected daily.checkin: {_http_error_message(error)}"
        ) from error
    except StopIteration as error:
        raise RuntimeError("Signal Deck did not establish an owner CSRF session") from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise RuntimeError(
            f"Signal Deck daily.checkin unavailable: {type(error).__name__}"
        ) from error


def preview_daily_checkin(
    *,
    date: str,
    bedtime: str,
    wake_time: str,
    mood: float | None,
    morning_journal: str,
    evening_journal: str,
    idempotency_key: str,
    provenance_source: str,
) -> dict[str, Any]:
    return _request(
        "/api/lifeos/operations/daily.checkin/preview",
        {
            "date": date,
            "bedtime": bedtime,
            "wake_time": wake_time,
            "mood": mood,
            "morning_journal": morning_journal,
            "evening_journal": evening_journal,
            "actor": "Domenico",
            "surface": "ordinary-chatgpt",
            "idempotency_key": idempotency_key,
            "provenance": {
                "client": "chatgpt-obsidian-app",
                "source": provenance_source,
            },
        },
    )


def apply_daily_checkin(
    *,
    date: str,
    bedtime: str,
    wake_time: str,
    mood: float | None,
    morning_journal: str,
    evening_journal: str,
    idempotency_key: str,
    provenance_source: str,
    operation_id: str,
    packet_id: str,
    confirmation: str,
) -> dict[str, Any]:
    return _request(
        "/api/lifeos/operations/daily.checkin/apply",
        {
            "date": date,
            "bedtime": bedtime,
            "wake_time": wake_time,
            "mood": mood,
            "morning_journal": morning_journal,
            "evening_journal": evening_journal,
            "actor": "Domenico",
            "surface": "ordinary-chatgpt",
            "idempotency_key": idempotency_key,
            "provenance": {
                "client": "chatgpt-obsidian-app",
                "source": provenance_source,
            },
            "operation_id": operation_id,
            "packet_id": packet_id,
            "confirmation": confirmation,
        },
    )


def rollback_daily_checkin(
    *,
    operation_id: str,
    idempotency_key: str,
    confirmation: str,
) -> dict[str, Any]:
    return _request(
        "/api/lifeos/operations/daily.checkin/rollback",
        {
            "operation_id": operation_id,
            "idempotency_key": idempotency_key,
            "actor": "Domenico",
            "surface": "ordinary-chatgpt",
            "confirmation": confirmation,
        },
    )
