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
    monkeypatch.setattr(auth_module, "VAULT_MCP_SIGNORSTUDIO_TOKEN", "")

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


def test_profile_is_bound_to_authenticated_bearer(monkeypatch):
    monkeypatch.setattr(auth_module, "VAULT_MCP_TOKEN", "secret-token")
    monkeypatch.setattr(
        auth_module,
        "VAULT_MCP_SIGNORSTUDIO_TOKEN",
        "signor-studio-token",
    )

    async def show_profile(request):
        return PlainTextResponse(current_request_context().get("profile") or "")

    app = Starlette(routes=[Route("/", show_profile)])
    app.add_middleware(auth_module.BearerAuthMiddleware)
    scoped_client = TestClient(app)

    response = scoped_client.get(
        "/",
        headers={
            "Authorization": "Bearer signor-studio-token",
        },
    )

    assert response.status_code == 200
    assert response.text == "signorstudio"


def test_owner_bearer_binds_owner_when_header_is_absent(monkeypatch):
    monkeypatch.setattr(auth_module, "VAULT_MCP_TOKEN", "secret-token")
    monkeypatch.setattr(
        auth_module,
        "VAULT_MCP_SIGNORSTUDIO_TOKEN",
        "signor-studio-token",
    )

    async def show_profile(request):
        return PlainTextResponse(current_request_context().get("profile") or "")

    app = Starlette(routes=[Route("/", show_profile)])
    app.add_middleware(auth_module.BearerAuthMiddleware)
    response = TestClient(app).get(
        "/",
        headers={"Authorization": "Bearer secret-token"},
    )

    assert response.status_code == 200
    assert response.text == "owner"


def test_self_asserted_profile_cannot_change_bearer_binding(monkeypatch):
    monkeypatch.setattr(auth_module, "VAULT_MCP_TOKEN", "secret-token")
    monkeypatch.setattr(
        auth_module,
        "VAULT_MCP_SIGNORSTUDIO_TOKEN",
        "signor-studio-token",
    )

    async def ok(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", ok)])
    app.add_middleware(auth_module.BearerAuthMiddleware)
    scoped_client = TestClient(app)

    owner_claim = scoped_client.get(
        "/",
        headers={
            "Authorization": "Bearer secret-token",
            "X-Dodo-Profile": "signorstudio",
        },
    )
    studio_claim = scoped_client.get(
        "/",
        headers={
            "Authorization": "Bearer signor-studio-token",
            "X-Dodo-Profile": "other",
        },
    )

    assert owner_claim.status_code == 403
    assert studio_claim.status_code == 403


def test_profile_tokens_must_be_distinct(monkeypatch):
    monkeypatch.setattr(auth_module, "VAULT_MCP_TOKEN", "same-token")
    monkeypatch.setattr(auth_module, "VAULT_MCP_SIGNORSTUDIO_TOKEN", "same-token")

    async def ok(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", ok)])
    app.add_middleware(auth_module.BearerAuthMiddleware)
    response = TestClient(app).get(
        "/",
        headers={"Authorization": "Bearer same-token"},
    )

    assert response.status_code == 500


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
