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


@pytest.fixture
def state_path(tmp_path: Path) -> Path:
    """Path of the state file."""
    return tmp_path / "state" / "oauth_state.sqlite3"


def _open(state_path: Path, *, now: list[float] | None = None) -> OAuthState:
    """Open the store with an optional clock."""
    clock = (lambda: now[0]) if now is not None else None
    return OAuthState(state_path, clock=clock)


# --- Clients -----------------------------------------------------------------------------


def test_registered_client_survives_reopen(state_path):
    state = _open(state_path, now=[1_000.0])
    registered = state.register_client([REDIRECT], client_name="Claude")
    state.close()

    reopened = _open(state_path)
    client = reopened.get_client(registered.client.client_id)
    reopened.close()

    assert client is not None
    assert client.redirect_uris == (REDIRECT,)
    assert client.client_name == "Claude"
    assert client.created_at == 1_000.0
    assert client.revoked_at is None
    assert client.is_static is False


def test_client_secret_is_never_written_to_disk(state_path):
    state = _open(state_path)
    registered = state.register_client([REDIRECT])

    assert registered.client_secret.encode() not in state_path.read_bytes()
    state.close()
    assert registered.client_secret.encode() not in state_path.read_bytes()


def test_client_secret_verifies_only_for_its_own_client(state_path):
    state = _open(state_path)
    first = state.register_client([REDIRECT])
    second = state.register_client([REDIRECT])

    assert state.verify_client_secret(first.client.client_id, first.client_secret)
    assert not state.verify_client_secret(first.client.client_id, second.client_secret)
    assert not state.verify_client_secret(first.client.client_id, "")
    assert not state.verify_client_secret("vault-mcp-unknown", first.client_secret)
    state.close()


def test_list_clients_returns_every_client_oldest_first(state_path):
    # Ids are chosen so that neither id order nor reverse creation order gives this result.
    now = [1_000.0]
    state = _open(state_path, now=now)
    state.ensure_static_client("zzz-first")
    now[0] = 2_000.0
    middle = state.register_client([REDIRECT]).client.client_id
    now[0] = 3_000.0
    state.ensure_static_client("aaa-last")

    listed = state.list_clients()
    state.close()

    assert [client.client_id for client in listed] == ["zzz-first", middle, "aaa-last"]


def test_redirect_repeated_in_one_registration_is_stored_once(state_path):
    state = _open(state_path)

    registered = state.register_client([REDIRECT, REDIRECT])

    assert registered.client.redirect_uris == (REDIRECT,)
    assert state.client_redirect_uri_allowed(registered.client.client_id, REDIRECT)
    state.close()


def test_state_written_by_a_newer_version_is_refused(state_path):
    _open(state_path).close()
    connection = sqlite3.connect(state_path)
    connection.execute("PRAGMA user_version = 2")
    connection.close()

    with pytest.raises(OAuthStateError, match="schema version 2"):
        _open(state_path)


# --- Access tokens -----------------------------------------------------------------------


def test_issuing_a_pair_records_when_the_client_last_authorized(state_path):
    now = [1_000.0]
    state = _open(state_path, now=now)
    client_id = state.register_client([REDIRECT]).client.client_id
    assert state.get_client(client_id).last_authorized_at is None

    now[0] = 5_000.0
    state.issue_token_pair(client_id=client_id, resource=RESOURCE)

    assert state.get_client(client_id).last_authorized_at == 5_000.0
    state.close()


def test_tokens_are_never_written_to_disk(state_path):
    state = _open(state_path)
    client_id = state.register_client([REDIRECT]).client.client_id
    issued = state.issue_token_pair(client_id=client_id, resource=RESOURCE)
    state.close()

    on_disk = state_path.read_bytes()
    assert issued.access_token.split(".")[2].encode() not in on_disk
    assert issued.refresh_token.split(".")[2].encode() not in on_disk


def test_access_token_is_found_by_its_exact_value_only(state_path):
    state = _open(state_path)
    client_id = state.register_client([REDIRECT]).client.client_id
    issued = state.issue_token_pair(client_id=client_id, resource=RESOURCE)

    assert state.lookup_access_token(issued.access_token) == issued.token
    assert state.lookup_access_token(issued.access_token + "x") is None
    assert state.lookup_access_token(issued.refresh_token) is None
    assert state.lookup_access_token("v1.unknown.secret") is None
    assert state.lookup_access_token("not-a-token") is None
    state.close()


def test_access_token_lives_one_day(state_path):
    now = [1_000.0]
    state = _open(state_path, now=now)
    client_id = state.register_client([REDIRECT]).client.client_id
    issued = state.issue_token_pair(client_id=client_id, resource=RESOURCE)

    now[0] = 1_000.0 + 86_400 - 1
    assert state.lookup_access_token(issued.access_token) == issued.token
    now[0] = 1_000.0 + 86_400
    assert state.lookup_access_token(issued.access_token) is None
    state.close()


@pytest.mark.parametrize("issue", ["issue_token_pair", "issue_access_token"])
def test_unknown_client_gets_no_token(state_path, issue):
    state = _open(state_path)

    with pytest.raises(InvalidClient):
        getattr(state, issue)(client_id="vault-mcp-unknown", resource=RESOURCE)
    state.close()


# --- Refresh tokens ----------------------------------------------------------------------


def _pair(state: OAuthState):
    """A client with a token pair."""
    client_id = state.register_client([REDIRECT]).client.client_id
    return client_id, state.issue_token_pair(client_id=client_id, resource=RESOURCE)


def _refresh(state: OAuthState, refresh_token: str, client_id: str, resource: str = RESOURCE):
    """Redeem a refresh token, accepting only the given resource."""
    return state.redeem_refresh_token(
        refresh_token=refresh_token, client_id=client_id,
        resource_ok=lambda stored: stored == resource,
    )


def test_refresh_works_after_the_access_token_expired(state_path):
    now = [1_000.0]
    state = _open(state_path, now=now)
    client_id, issued = _pair(state)

    now[0] = 1_000.0 + 86_400 + 1
    assert state.lookup_access_token(issued.access_token) is None
    rotated = _refresh(state, issued.refresh_token, client_id)

    assert state.lookup_access_token(rotated.access_token) == rotated.token
    state.close()


def test_token_pair_survives_reopen(state_path):
    state = _open(state_path)
    client_id, issued = _pair(state)
    state.close()

    reopened = _open(state_path)
    assert reopened.lookup_access_token(issued.access_token) == issued.token
    rotated = _refresh(reopened, issued.refresh_token, client_id)
    assert reopened.lookup_access_token(rotated.access_token) == rotated.token
    reopened.close()


def test_refresh_token_lives_thirty_days(state_path):
    now = [1_000.0]
    state = _open(state_path, now=now)
    client_id, issued = _pair(state)

    now[0] = 1_000.0 + 30 * 86_400
    with pytest.raises(InvalidGrant):
        _refresh(state, issued.refresh_token, client_id)

    now[0] = 1_000.0 + 30 * 86_400 - 1
    rotated = _refresh(state, issued.refresh_token, client_id)
    assert state.lookup_access_token(rotated.access_token) == rotated.token
    state.close()


def test_refresh_for_another_resource_is_refused_and_not_spent(state_path):
    state = _open(state_path)
    client_id, issued = _pair(state)

    with pytest.raises(InvalidTarget):
        _refresh(state, issued.refresh_token, client_id, resource="https://other.example.test")

    rotated = _refresh(state, issued.refresh_token, client_id)
    assert rotated.token.resource == RESOURCE
    state.close()


def test_refresh_token_works_only_for_the_client_it_was_issued_to(state_path):
    state = _open(state_path)
    client_id, issued = _pair(state)
    other_id = state.register_client([REDIRECT]).client.client_id

    with pytest.raises(InvalidGrant):
        _refresh(state, issued.refresh_token, other_id)

    rotated = _refresh(state, issued.refresh_token, client_id)
    assert rotated.token.client_id == client_id
    state.close()


@pytest.mark.parametrize(
    "forged",
    ["not-a-token", "r1.unknown.secret", "v1.aaa.bbb", "r1..secret", ""],
)
def test_forged_refresh_token_is_refused(state_path, forged):
    state = _open(state_path)
    client_id, _issued = _pair(state)

    with pytest.raises(InvalidGrant):
        _refresh(state, forged, client_id)
    state.close()


def test_refresh_token_with_a_wrong_secret_is_refused(state_path):
    state = _open(state_path)
    client_id, issued = _pair(state)

    with pytest.raises(InvalidGrant):
        _refresh(state, issued.refresh_token + "x", client_id)

    rotated = _refresh(state, issued.refresh_token, client_id)
    assert state.lookup_access_token(rotated.access_token) == rotated.token
    state.close()


def test_two_simultaneous_refreshes_issue_exactly_one_pair(state_path):
    state = _open(state_path)
    client_id, issued = _pair(state)
    state.close()
    barrier = threading.Barrier(2)

    def refresh_once(_):
        """Refresh once from its own connection."""
        local = _open(state_path)
        barrier.wait()
        try:
            return _refresh(local, issued.refresh_token, client_id).access_token
        except InvalidGrant:
            return None
        finally:
            local.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(refresh_once, range(2)))

    assert sum(result is not None for result in results) == 1


def test_refresh_records_when_the_client_last_authorized(state_path):
    now = [1_000.0]
    state = _open(state_path, now=now)
    client_id, issued = _pair(state)

    now[0] = 7_000.0
    _refresh(state, issued.refresh_token, client_id)

    assert state.get_client(client_id).last_authorized_at == 7_000.0
    state.close()


# --- Revocation --------------------------------------------------------------------------


def test_revoking_a_client_kills_everything_it_holds(state_path):
    now = [1_000.0]
    state = _open(state_path, now=now)
    registered = state.register_client([REDIRECT])
    client_id = registered.client.client_id
    issued = state.issue_token_pair(client_id=client_id, resource=RESOURCE)

    now[0] = 2_000.0
    assert state.revoke_client(client_id) is True

    assert state.get_client(client_id).revoked_at == 2_000.0
    assert state.lookup_access_token(issued.access_token) is None
    assert not state.verify_client_secret(client_id, registered.client_secret)
    assert not state.client_redirect_uri_allowed(client_id, REDIRECT)
    with pytest.raises(InvalidClient):
        _refresh(state, issued.refresh_token, client_id)
    with pytest.raises(InvalidClient):
        state.issue_token_pair(client_id=client_id, resource=RESOURCE)
    with pytest.raises(InvalidClient):
        state.issue_access_token(client_id=client_id, resource=RESOURCE)
    state.close()


# --- The operator-configured client ------------------------------------------------------


def test_configured_client_is_created_without_a_stored_secret(state_path):
    state = _open(state_path)

    client = state.ensure_static_client("operator-client")

    assert client.is_static is True
    assert client.redirect_uris == ()
    assert not state.verify_client_secret("operator-client", "any-secret")
    issued = state.issue_access_token(client_id="operator-client", resource=RESOURCE)
    assert state.lookup_access_token(issued.access_token) == issued.token
    state.close()


def test_configured_client_id_cannot_take_over_a_registered_client(state_path):
    state = _open(state_path)
    registered = state.register_client([REDIRECT])

    with pytest.raises(ValueError, match="already registered"):
        state.ensure_static_client(registered.client.client_id)

    assert state.get_client(registered.client.client_id).is_static is False
    assert state.verify_client_secret(
        registered.client.client_id, registered.client_secret
    )
    state.close()


# --- File permissions --------------------------------------------------------------------

posix_modes = pytest.mark.skipif(
    os.name == "nt", reason="file modes are meaningless on Windows"
)


def _mode(path: Path) -> int:
    """Permission bits of a path."""
    return path.stat().st_mode & 0o777


@posix_modes
def test_existing_database_is_tightened(state_path):
    running = _open(state_path)
    registered = running.register_client([REDIRECT])
    state_path.chmod(0o644)

    state = _open(state_path)

    assert _mode(state_path) == 0o600
    assert state.get_client(registered.client.client_id) is not None
    state.close()
    running.close()
