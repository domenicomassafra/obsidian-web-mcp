"""The Obsidian server has its own identity, not a configurable computer brand."""
import runpy
from pathlib import Path
from starlette.applications import Starlette
from starlette.testclient import TestClient
from obsidian_vault_mcp import config, oauth


def test_vault_identity_is_not_an_environment_override(monkeypatch):
    monkeypatch.setenv('VAULT_OAUTH_RESOURCE_NAME', 'Unrelated service')
    values = runpy.run_path(str(Path(config.__file__)))
    assert 'VAULT_OAUTH_RESOURCE_NAME' not in values


def test_authorization_and_metadata_identify_obsidian(monkeypatch):
    monkeypatch.setattr(config, 'VAULT_OAUTH_PASSWORD', 'test-only')
    client = TestClient(Starlette(routes=oauth.oauth_routes))
    cid = client.post('/oauth/register', json={
        'redirect_uris': ['https://client.example/cb'],
    }).json()['client_id']
    response = client.get('/oauth/authorize', params={
        'client_id': cid, 'redirect_uri': 'https://client.example/cb',
        'response_type': 'code', 'code_challenge': 'a' * 43,
        'code_challenge_method': 'S256',
    })
    assert response.status_code == 200
    assert 'Authorize Obsidian Vault' in response.text
    assert client.get('/.well-known/oauth-authorization-server').json()['server_name'] == 'Obsidian Vault'
    assert client.get('/.well-known/oauth-protected-resource').json()['resource_name'] == 'Obsidian Vault'
