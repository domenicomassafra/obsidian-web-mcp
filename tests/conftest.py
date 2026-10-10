"""Test fixtures for the Obsidian vault MCP server."""

import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def fresh_oauth_brakes(monkeypatch):
    from obsidian_vault_mcp import oauth
    monkeypatch.setattr(oauth, "_login_failures",
                        oauth._SlidingLimit(oauth.LOGIN_FAILURE_LIMIT, oauth.LOGIN_FAILURE_WINDOW_SECONDS))
    monkeypatch.setattr(oauth, "_registrations",
                        oauth._SlidingLimit(oauth.REGISTRATION_LIMIT, oauth.REGISTRATION_WINDOW_SECONDS))


@pytest.fixture(autouse=True)
def isolated_oauth_state(tmp_path, monkeypatch):
    """The OAuth store opens lazily at a path derived from OAUTH_CLIENTS_PATH. Point
    that at a throwaway directory before anything opens it, so no test reads or writes
    the real one, and close the store afterwards so the next test starts fresh."""
    from obsidian_vault_mcp import config, oauth

    oauth.close_oauth_state()
    monkeypatch.setattr(config, "OAUTH_CLIENTS_PATH", tmp_path / "oauth-state" / "oauth_clients.json")
    yield
    oauth.close_oauth_state()


@pytest.fixture
def vault_dir(tmp_path, monkeypatch):
    """Create a temporary vault directory with sample files."""
    vault = tmp_path / "test-vault"
    vault.mkdir()

    # test-note.md with frontmatter
    (vault / "test-note.md").write_text(
        "---\nstatus: active\ntype: note\n---\n\nThis is a test note with some content.\n"
    )

    # subfolder/nested-note.md with frontmatter
    subfolder = vault / "subfolder"
    subfolder.mkdir()
    (subfolder / "nested-note.md").write_text(
        "---\nstatus: draft\ntype: client-hub\nclient: TestCorp\n---\n\nNested note content.\n"
    )

    # no-frontmatter.md
    (vault / "no-frontmatter.md").write_text("Just plain text, no frontmatter here.\n")

    # .obsidian/config.json (should be excluded)
    obsidian_dir = vault / ".obsidian"
    obsidian_dir.mkdir()
    (obsidian_dir / "config.json").write_text('{"theme": "dark"}')

    # Set environment variable for config module
    monkeypatch.setenv("VAULT_PATH", str(vault))
    monkeypatch.setenv("VAULT_MCP_TOKEN", "test-token-12345")

    # Reload config to pick up new env var
    import obsidian_vault_mcp.config as config
    config.VAULT_PATH = Path(str(vault))

    yield vault
