"""Tests of the durable OAuth state."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from obsidian_vault_mcp.oauth_state import (
    InvalidClient,
    InvalidGrant,
    InvalidTarget,
    OAuthState,
    OAuthStateError,
)

RESOURCE = "https://vault.example.test"
REDIRECT = "https://client.example.test/callback"


from .test_oauth_state import _open, state_path

# --- Import of the JSON registry ---------------------------------------------------------

SHARED_CALLBACK = "https://claude.ai/api/mcp/auth_callback"
PRIVATE = "registry-value-that-must-stay-out-of-the-log"
PRIVATE_URL = "https://callback.example.test/must-stay-out-of-the-log"


@pytest.fixture
def legacy_path(state_path: Path) -> Path:
    """Path of the JSON registry."""
    return state_path.parent / "oauth_clients.json"


def _write_registry(legacy_path: Path, registry: object) -> None:
    """Write the JSON registry."""
    legacy_path.parent.mkdir(parents=True, exist_ok=True)
    legacy_path.write_text(json.dumps(registry))


def _entry(secret: str, redirect_uris: list[str], created_at: float = 500.0) -> dict:
    """A registry entry as main wrote it."""
    return {"client_secret": secret, "redirect_uris": redirect_uris, "created_at": created_at}


def _imported_ids(state: OAuthState) -> set[str]:
    """Ids of the stored clients."""
    return {client.client_id for client in state.list_clients()}


def test_import_reads_a_registry_as_main_wrote_it(state_path, legacy_path):
    _write_registry(
        legacy_path,
        {
            "vault-mcp-one": _entry("secret-one", [SHARED_CALLBACK], created_at=100.0),
            "vault-mcp-two": _entry("secret-two", [SHARED_CALLBACK], created_at=200.0),
            "vault-mcp-three": _entry("secret-three", [SHARED_CALLBACK, SHARED_CALLBACK]),
            "vault-mcp-empty": _entry("secret-empty", []),
        },
    )
    before = legacy_path.read_bytes()

    state = OAuthState(state_path, legacy_path=legacy_path, clock=lambda: 9_000.0)

    assert _imported_ids(state) == {
        "vault-mcp-one",
        "vault-mcp-two",
        "vault-mcp-three",
        "vault-mcp-empty",
    }
    for name in ("one", "two", "three"):
        assert state.verify_client_secret(f"vault-mcp-{name}", f"secret-{name}")
        assert state.client_redirect_uri_allowed(f"vault-mcp-{name}", SHARED_CALLBACK)
    assert state.get_client("vault-mcp-three").redirect_uris == (SHARED_CALLBACK,)
    assert state.verify_client_secret("vault-mcp-empty", "secret-empty")
    assert state.get_client("vault-mcp-empty").redirect_uris == ()
    assert state.get_client("vault-mcp-one").created_at == 9_000.0
    assert state.get_client("vault-mcp-one").is_static is False
    assert b"secret-one" not in state_path.read_bytes()
    state.close()
    assert legacy_path.read_bytes() == before


LONE_SURROGATE = "\ud800"


@pytest.mark.parametrize(
    ("client_id", "entry"),
    [
        ("vault-mcp-odd", _entry("secret" + LONE_SURROGATE, [REDIRECT])),
        ("vault-mcp-odd", _entry("secret-odd", [REDIRECT, REDIRECT + LONE_SURROGATE])),
        ("vault-mcp-odd" + LONE_SURROGATE, _entry("secret-odd", [REDIRECT])),
    ],
    ids=["secret", "redirect", "client-id"],
)
def test_import_skips_an_entry_sqlite_cannot_store(
    state_path, legacy_path, client_id, entry, caplog
):
    _write_registry(
        legacy_path,
        {
            "vault-mcp-before": _entry("secret-before", [REDIRECT]),
            client_id: entry,
            "vault-mcp-after": _entry("secret-after", [REDIRECT]),
        },
    )

    with caplog.at_level("WARNING", logger="obsidian_vault_mcp.oauth_state"):
        state = OAuthState(state_path, legacy_path=legacy_path)

    assert _imported_ids(state) == {"vault-mcp-before", "vault-mcp-after"}
    assert state.verify_client_secret("vault-mcp-before", "secret-before")
    assert state.verify_client_secret("vault-mcp-after", "secret-after")
    assert state.client_redirect_uri_allowed("vault-mcp-after", REDIRECT)
    messages = [record.getMessage() for record in caplog.records]
    assert len(messages) == 1
    assert "skipped 1 entries" in messages[0]
    state.close()


def test_missing_registry_is_not_worth_a_warning(state_path, legacy_path, caplog):
    with caplog.at_level("WARNING", logger="obsidian_vault_mcp.oauth_state"):
        state = OAuthState(state_path, legacy_path=legacy_path)

    assert state.list_clients() == ()
    assert caplog.records == []
    state.close()


def test_import_retries_when_legacy_file_appears(state_path, legacy_path):
    OAuthState(state_path, legacy_path=legacy_path).close()

    _write_registry(legacy_path, {"vault-mcp-one": _entry("secret-one", [REDIRECT])})
    state = OAuthState(state_path, legacy_path=legacy_path)
    assert _imported_ids(state) == {"vault-mcp-one"}
    state.close()

    _write_registry(
        legacy_path,
        {
            "vault-mcp-one": _entry("secret-one", [REDIRECT]),
            "vault-mcp-late": _entry("secret-late", [REDIRECT]),
        },
    )
    reopened = OAuthState(state_path, legacy_path=legacy_path)
    assert _imported_ids(reopened) == {"vault-mcp-one", "vault-mcp-late"}
    assert reopened.verify_client_secret("vault-mcp-late", "secret-late")
    reopened.close()


def test_import_skips_malformed_entry(state_path, legacy_path, caplog):
    _write_registry(
        legacy_path,
        {
            "record-is-not-an-object": PRIVATE,
            "secret-is-missing": {"redirect_uris": [PRIVATE_URL]},
            "secret-is-not-a-string": {"client_secret": 42, "redirect_uris": [PRIVATE_URL]},
            "redirects-are-missing": {"client_secret": PRIVATE},
            "redirects-are-not-a-list": {"client_secret": PRIVATE, "redirect_uris": PRIVATE_URL},
            "redirect-is-not-a-string": {"client_secret": PRIVATE, "redirect_uris": [PRIVATE_URL, 7]},
            "vault-mcp-good": _entry("secret-good", [REDIRECT]),
        },
    )

    with caplog.at_level("WARNING", logger="obsidian_vault_mcp.oauth_state"):
        state = OAuthState(state_path, legacy_path=legacy_path)

    assert _imported_ids(state) == {"vault-mcp-good"}
    assert state.verify_client_secret("vault-mcp-good", "secret-good")
    messages = [record.getMessage() for record in caplog.records]
    assert len(messages) == 1
    assert "skipped 6 entries" in messages[0]
    assert PRIVATE not in messages[0]
    assert PRIVATE_URL not in messages[0]
    assert "secret-good" not in messages[0]
    state.close()


@pytest.mark.parametrize(
    "content",
    ['{"' + PRIVATE, '["' + PRIVATE + '"]', '"' + PRIVATE + '"', ""],
    ids=["broken-json", "list", "string", "empty"],
)
def test_import_tolerates_a_registry_it_cannot_read(state_path, legacy_path, content, caplog):
    legacy_path.parent.mkdir(parents=True)
    legacy_path.write_text(content)

    with caplog.at_level("WARNING", logger="obsidian_vault_mcp.oauth_state"):
        state = OAuthState(state_path, legacy_path=legacy_path)

    assert state.list_clients() == ()
    assert len(caplog.records) == 1
    assert PRIVATE not in caplog.records[0].getMessage()
    registered = state.register_client([REDIRECT])
    assert state.get_client(registered.client.client_id) is not None
    state.close()
    assert legacy_path.read_text() == content


def test_import_does_not_overwrite_existing_client(state_path, legacy_path):
    _write_registry(
        legacy_path,
        {
            "vault-mcp-active": _entry("old-secret", [REDIRECT]),
            "vault-mcp-revoked": _entry("revoked-secret", [REDIRECT]),
        },
    )
    state = OAuthState(state_path, legacy_path=legacy_path)
    state.revoke_client("vault-mcp-revoked")
    state.close()

    other = "https://other.example.test/callback"
    _write_registry(
        legacy_path,
        {
            "vault-mcp-active": _entry("new-secret", [other]),
            "vault-mcp-revoked": _entry("revoked-secret", [REDIRECT]),
        },
    )
    reopened = OAuthState(state_path, legacy_path=legacy_path)

    assert reopened.verify_client_secret("vault-mcp-active", "old-secret")
    assert not reopened.verify_client_secret("vault-mcp-active", "new-secret")
    assert reopened.get_client("vault-mcp-active").redirect_uris == (REDIRECT,)
    assert reopened.get_client("vault-mcp-revoked").revoked_at is not None
    assert not reopened.client_redirect_uri_allowed("vault-mcp-revoked", REDIRECT)
    reopened.close()
