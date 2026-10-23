"""Resource names must describe the consumer, and remain HTML-safe."""
from starlette.applications import Starlette
from starlette.testclient import TestClient
from obsidian_vault_mcp import config, oauth


def test_computer_resource_name(monkeypatch):
    monkeypatch.setattr(config, "VAULT_OAUTH_RESOURCE_NAME", "Computer (Studio e MiniPC)")
    monkeypatch.setattr(config, "VAULT_OAUTH_PASSWORD", "test")
    client = TestClient(Starlette(routes=oauth.oauth_routes))
    cid = client.post("/oauth/register", json={"redirect_uris": ["https://client.example/cb"]}).json()["client_id"]
    response = client.get("/oauth/authorize", params={"client_id": cid, "redirect_uri": "https://client.example/cb",
        "response_type": "code", "code_challenge": "a" * 43, "code_challenge_method": "S256"})
    assert response.status_code == 200
    assert "Computer (Studio e MiniPC)" in response.text
    assert "your vault" not in response.text.lower()
    assert "Obsidian" not in response.text
    assert client.get("/.well-known/oauth-authorization-server").json()["server_name"] == config.VAULT_OAUTH_RESOURCE_NAME
    assert client.get("/.well-known/oauth-protected-resource").json()["resource_name"] == config.VAULT_OAUTH_RESOURCE_NAME
    monkeypatch.setattr(config, "VAULT_OAUTH_RESOURCE_NAME", "<script>alert(1)</script>")
    assert "<script>" not in oauth._login_form({}).body.decode()
