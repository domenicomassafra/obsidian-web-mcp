"""Vault OAuth refresh survives restart and respects live revocation."""
import base64
import hashlib
from urllib.parse import parse_qs, urlsplit

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from obsidian_vault_mcp import auth, config, oauth


def test_refresh_without_login_survives_restart_and_revocation(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "OAUTH_CLIENTS_PATH", tmp_path / "clients.json")
    monkeypatch.setattr(config, "VAULT_OAUTH_PASSWORD", "test-password")
    monkeypatch.setattr(config, "VAULT_MCP_TOKEN", "master")
    monkeypatch.setattr(auth, "VAULT_MCP_TOKEN", "master")
    monkeypatch.setattr(config, "VAULT_MCP_PUBLIC_URL", "https://obsidian.example")
    monkeypatch.setattr(config, "VAULT_MCP_PATH", "/mcp")
    async def protected(request):
        return PlainTextResponse("obsidian")
    app = Starlette(routes=[*oauth.oauth_routes, Route("/mcp", protected)])
    app.add_middleware(auth.BearerAuthMiddleware)
    with TestClient(app) as client:
        redirect = "https://claude.example/callback"
        cid = client.post("/oauth/register", json={"redirect_uris": [redirect]}).json()["client_id"]
        verifier = "a" * 64
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        response = client.post("/oauth/authorize", data={
            "response_type": "code", "client_id": cid, "redirect_uri": redirect,
            "code_challenge": challenge, "code_challenge_method": "S256",
            "username": config.VAULT_OAUTH_USERNAME, "password": "test-password",
        }, follow_redirects=False)
        assert response.status_code == 302
        code = parse_qs(urlsplit(response.headers["location"]).query)["code"][0]
        first = client.post("/oauth/token", data={
            "grant_type": "authorization_code", "client_id": cid, "code": code,
            "code_verifier": verifier, "redirect_uri": redirect,
        }).json()
        assert first.get("refresh_token"), "Daily login regression: missing refresh token"
        assert first["access_token"] != "master"
        oauth.close_oauth_state()
        second = client.post("/oauth/token", data={
            "grant_type": "refresh_token", "client_id": cid,
            "refresh_token": first["refresh_token"],
        })
        assert second.status_code == 200
        second = second.json()
        assert second["access_token"] != first["access_token"]
        assert second["refresh_token"] != first["refresh_token"]
        headers = {"Authorization": "Bearer " + second["access_token"]}
        assert client.get("/mcp", headers=headers).status_code == 200
        assert client.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": cid,
                                                "refresh_token": first["refresh_token"]}).status_code == 400
        oauth.get_oauth_state().revoke_client(cid)
        assert client.get("/mcp", headers=headers).status_code == 401
        assert client.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": cid,
                                                "refresh_token": second["refresh_token"]}).status_code == 401
        assert client.get("/mcp").status_code == 401
