"""Conflict guards for whole-file text writes."""

import hashlib
import json

from obsidian_vault_mcp import config
from obsidian_vault_mcp.tools.read import vault_read
from obsidian_vault_mcp.tools.write import vault_write


def test_existing_file_is_not_clobbered_by_default(vault_dir):
    target = config.VAULT_PATH / "guarded.md"
    target.write_text("original", encoding="utf-8")

    result = json.loads(vault_write("guarded.md", "replacement"))

    assert "error" in result
    assert "overwrite=true" in result["error"]
    assert target.read_text(encoding="utf-8") == "original"


def test_explicit_overwrite_replaces_existing_file(vault_dir):
    target = config.VAULT_PATH / "guarded.md"
    target.write_text("original", encoding="utf-8")

    result = json.loads(vault_write("guarded.md", "replacement", overwrite=True))

    assert result["created"] is False
    assert target.read_text(encoding="utf-8") == "replacement"


def test_matching_expected_sha256_replaces_known_version(vault_dir):
    target = config.VAULT_PATH / "guarded.md"
    target.write_text("original", encoding="utf-8")
    digest = hashlib.sha256(b"original").hexdigest()

    result = json.loads(
        vault_write("guarded.md", "replacement", expected_sha256=digest)
    )

    assert result["created"] is False
    assert target.read_text(encoding="utf-8") == "replacement"


def test_stale_expected_sha256_rejects_write(vault_dir):
    target = config.VAULT_PATH / "guarded.md"
    target.write_text("current", encoding="utf-8")
    stale_digest = hashlib.sha256(b"old version").hexdigest()

    result = json.loads(
        vault_write("guarded.md", "replacement", expected_sha256=stale_digest)
    )

    assert "changed since it was read" in result["error"]
    assert target.read_text(encoding="utf-8") == "current"


def test_expected_sha256_requires_existing_file(vault_dir):
    digest = hashlib.sha256(b"missing").hexdigest()

    result = json.loads(vault_write("missing.md", "content", expected_sha256=digest))

    assert "Expected an existing file" in result["error"]
    assert not (config.VAULT_PATH / "missing.md").exists()


def test_vault_read_returns_version_digest(vault_dir):
    target = config.VAULT_PATH / "guarded.md"
    target.write_text("original", encoding="utf-8")

    result = json.loads(vault_read("guarded.md"))

    assert result["metadata"]["sha256"] == hashlib.sha256(b"original").hexdigest()
