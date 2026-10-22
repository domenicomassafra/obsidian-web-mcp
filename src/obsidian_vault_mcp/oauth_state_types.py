"""Upstream #108 OAuth schema, records and pure helpers (MIT, ce39d209).

Moved unchanged from oauth_state.py to keep adopted modules below 20 KB.
"""
from __future__ import annotations
import hashlib
import sqlite3
from dataclasses import dataclass

SCHEMA_VERSION = 1
ACCESS_TOKEN_TTL_SECONDS = 24 * 60 * 60
REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60

_SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    client_id TEXT PRIMARY KEY,
    secret_verifier BLOB,
    is_static INTEGER NOT NULL CHECK (is_static IN (0, 1)),
    client_name TEXT NOT NULL,
    created_at REAL NOT NULL,
    last_authorized_at REAL,
    revoked_at REAL
);
CREATE TABLE IF NOT EXISTS client_redirect_uris (
    client_id TEXT NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    PRIMARY KEY (client_id, redirect_uri)
);
CREATE TABLE IF NOT EXISTS access_tokens (
    token_id TEXT PRIMARY KEY,
    secret_verifier BLOB NOT NULL,
    client_id TEXT NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    resource TEXT NOT NULL,
    issued_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_id TEXT PRIMARY KEY,
    secret_verifier BLOB NOT NULL,
    client_id TEXT NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    access_token_id TEXT NOT NULL REFERENCES access_tokens(token_id) ON DELETE CASCADE,
    resource TEXT NOT NULL,
    issued_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    consumed_at REAL
);
"""


# --- Errors ------------------------------------------------------------------------------


class OAuthStateError(RuntimeError):
    """Base class for OAuth state errors that map to protocol failures."""


class InvalidClient(OAuthStateError):
    """The client is unknown or revoked."""


class InvalidGrant(OAuthStateError):
    """The presented refresh token cannot be used."""


class InvalidTarget(OAuthStateError):
    """The token was issued for a different resource."""


# --- Records -----------------------------------------------------------------------------


@dataclass(frozen=True)
class ClientMetadata:
    """A registered client."""
    client_id: str
    redirect_uris: tuple[str, ...]
    client_name: str
    created_at: float
    last_authorized_at: float | None
    revoked_at: float | None
    is_static: bool


@dataclass(frozen=True)
class RegisteredClient:
    """A new client with its secret."""
    client: ClientMetadata
    client_secret: str


@dataclass(frozen=True)
class TokenMetadata:
    """An access token record."""
    token_id: str
    client_id: str
    resource: str
    issued_at: float
    expires_at: float


@dataclass(frozen=True)
class IssuedToken:
    """Tokens handed to a client."""
    access_token: str
    token: TokenMetadata
    refresh_token: str | None = None


# --- The store ---------------------------------------------------------------------------


# --- Helpers -----------------------------------------------------------------------------


def _secret_verifier(kind: str, secret: str) -> bytes:
    """Hash of a secret, separated by kind so one hash never verifies as another."""
    digest = hashlib.sha256()
    digest.update(b"obsidian-vault-mcp/oauth-state/v1\0")
    digest.update(kind.encode("ascii"))
    digest.update(b"\0")
    digest.update(secret.encode("utf-8"))
    return digest.digest()


def _legacy_record_ok(record: object) -> bool:
    """The same test main applied when it loaded its registry."""
    return (
        isinstance(record, dict)
        and isinstance(record.get("client_secret"), str)
        and isinstance(record.get("redirect_uris"), list)
        and all(isinstance(uri, str) for uri in record["redirect_uris"])
    )


def _storable(*texts: str) -> bool:
    """False for text that cannot be encoded, such as a lone surrogate."""
    try:
        for text in texts:
            text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _parse_token(prefix: str, token: str) -> tuple[str, str] | None:
    """Split "<prefix>.<id>.<secret>" into id and secret, or None if it is not that."""
    if not isinstance(token, str):
        return None
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != prefix or not parts[1] or not parts[2]:
        return None
    return parts[1], parts[2]


def _client_from_row(row: sqlite3.Row, redirect_uris: tuple[str, ...]) -> ClientMetadata:
    """Client metadata from a row."""
    return ClientMetadata(
        client_id=str(row["client_id"]),
        redirect_uris=redirect_uris,
        client_name=str(row["client_name"]),
        created_at=float(row["created_at"]),
        last_authorized_at=(
            float(row["last_authorized_at"]) if row["last_authorized_at"] is not None else None
        ),
        revoked_at=float(row["revoked_at"]) if row["revoked_at"] is not None else None,
        is_static=bool(row["is_static"]),
    )
