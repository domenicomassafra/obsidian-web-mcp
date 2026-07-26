"""Tests for the bearer-auth middleware's RFC 9728 WWW-Authenticate challenge."""

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from obsidian_vault_mcp import auth as auth_module
from obsidian_vault_mcp.context import current_request_context


@pytest.fixture
def client(monkeypatch):
    # Bind a known token into the middleware's module namespace.
    monkeypatch.setattr(auth_module, "VAULT_MCP_TOKEN", "secret-token")

    async def ok(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", ok)])
    app.add_middleware(auth_module.BearerAuthMiddleware)
    return TestClient(app)


def test_missing_auth_returns_401_with_challenge(client):
    r = client.get("/")
    assert r.status_code == 401
    wa = r.headers.get("WWW-Authenticate", "")
    assert wa.startswith("Bearer ")
    assert "/.well-known/oauth-protected-resource" in wa
    assert 'resource_metadata="' in wa
    assert 'error="invalid_request"' in wa


def test_bad_token_returns_401_with_invalid_token_challenge(client):
    r = client.get("/", headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401
    wa = r.headers.get("WWW-Authenticate", "")
    assert 'error="invalid_token"' in wa
    assert "/.well-known/oauth-protected-resource" in wa


def test_valid_token_passes_through(client):
    r = client.get("/", headers={"Authorization": "Bearer secret-token"})
    assert r.status_code == 200
    assert r.text == "ok"
    assert "WWW-Authenticate" not in r.headers


def test_owner_controlled_profile_header_reaches_tool_context(monkeypatch):
    monkeypatch.setattr(auth_module, "VAULT_MCP_TOKEN", "secret-token")

    async def show_profile(request):
        return PlainTextResponse(current_request_context().get("profile") or "")

    app = Starlette(routes=[Route("/", show_profile)])
    app.add_middleware(auth_module.BearerAuthMiddleware)
    scoped_client = TestClient(app)

    response = scoped_client.get(
        "/",
        headers={
            "Authorization": "Bearer secret-token",
            "X-Dodo-Profile": "signorstudio",
        },
    )

    assert response.status_code == 200
    assert response.text == "signorstudio"


def test_invalid_profile_header_fails_closed(client):
    response = client.get(
        "/",
        headers={
            "Authorization": "Bearer secret-token",
            "X-Dodo-Profile": "../signorstudio",
        },
    )

    assert response.status_code == 400
    assert response.json()["error"] == "Invalid X-Dodo-Profile header"
