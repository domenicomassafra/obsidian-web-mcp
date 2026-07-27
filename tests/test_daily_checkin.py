from __future__ import annotations

import http.cookiejar
import json

import pytest

from obsidian_vault_mcp.tools import daily_checkin


class _Response:
    status = 200

    def __init__(self, payload: dict | bytes):
        self.body = (
            payload
            if isinstance(payload, bytes)
            else json.dumps(payload).encode("utf-8")
        )

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, amount: int = -1):
        if amount < 0:
            return self.body
        return self.body[:amount]


def _csrf_cookie() -> http.cookiejar.Cookie:
    return http.cookiejar.Cookie(
        version=0,
        name="__Host-controlcenter_csrf",
        value="csrf-value",
        port=None,
        port_specified=False,
        domain="minipc-ubuntu.garibaldi-atlas.ts.net",
        domain_specified=True,
        domain_initial_dot=False,
        path="/",
        path_specified=True,
        secure=True,
        expires=None,
        discard=True,
        comment=None,
        comment_url=None,
        rest={},
    )


def test_preview_uses_signal_deck_owner_session_and_fixed_chatgpt_surface(
    monkeypatch,
):
    opened = []

    class _Opener:
        def open(self, request, timeout):
            opened.append((request, timeout))
            if isinstance(request, str):
                jar.set_cookie(_csrf_cookie())
                return _Response(b"<html>")
            return _Response(
                {
                    "operation_type": "daily.checkin",
                    "surface": "ordinary-chatgpt",
                    "status": "dry-run",
                }
            )

    def build_opener(processor):
        nonlocal jar
        jar = processor.cookiejar
        return _Opener()

    jar = None
    monkeypatch.setattr(daily_checkin.urllib.request, "build_opener", build_opener)

    result = daily_checkin.preview_daily_checkin(
        date="2026-07-27",
        bedtime="23:30",
        wake_time="07:15",
        mood=8,
        morning_journal="Focus.",
        evening_journal="",
        idempotency_key="packet5:daily.checkin:test",
        provenance_source="direct-app-canary",
    )

    assert result["surface"] == "ordinary-chatgpt"
    request = opened[1][0]
    body = json.loads(request.data)
    assert body["actor"] == "Domenico"
    assert body["surface"] == "ordinary-chatgpt"
    assert body["provenance"] == {
        "client": "chatgpt-obsidian-app",
        "source": "direct-app-canary",
    }
    assert request.headers["Origin"] == daily_checkin.DEFAULT_SIGNAL_DECK_URL
    assert request.headers["X-csrf-token"] == "csrf-value"


def test_signal_deck_origin_is_fixed_to_private_owner_host(monkeypatch):
    monkeypatch.setenv(
        daily_checkin.SIGNAL_DECK_URL_ENV,
        "https://attacker.example",
    )
    with pytest.raises(ValueError, match="private HTTPS Signal Deck origin"):
        daily_checkin.preview_daily_checkin(
            date="2026-07-27",
            bedtime="",
            wake_time="",
            mood=None,
            morning_journal="",
            evening_journal="",
            idempotency_key="packet5:blocked",
            provenance_source="test",
        )
