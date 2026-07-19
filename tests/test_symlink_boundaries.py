"""Discovery paths must never follow vault symlinks into another tree."""

import json

from obsidian_vault_mcp import server
from obsidian_vault_mcp.context_engine import _link_candidates
from obsidian_vault_mcp.legacy import life_os_mcp_gateway as legacy_gateway
from obsidian_vault_mcp.tools import search as search_module
from obsidian_vault_mcp.tools.search import vault_search, vault_search_frontmatter
from obsidian_vault_mcp.vault import list_directory


def _json(payload: str) -> dict:
    return json.loads(payload)


def test_list_does_not_traverse_external_directory_symlink(vault_dir, tmp_path):
    outside = tmp_path / "outside-list"
    outside.mkdir()
    (outside / "synthetic-private-name.md").write_text("redacted", encoding="utf-8")
    (vault_dir / "escape").symlink_to(outside, target_is_directory=True)

    paths = {item["path"] for item in list_directory("", depth=2)}

    assert "escape" not in paths
    assert "escape/synthetic-private-name.md" not in paths


def test_search_index_and_link_checks_ignore_external_file_symlink(
    vault_dir, tmp_path, monkeypatch
):
    outside = tmp_path / "outside-note.md"
    outside.write_text(
        "---\nstatus: external-private\n---\nsynthetic external needle\n",
        encoding="utf-8",
    )
    (vault_dir / "external-alias.md").symlink_to(outside)
    monkeypatch.setattr(search_module.shutil, "which", lambda _name: None)

    assert _json(vault_search("synthetic external needle"))["results"] == []
    server.frontmatter_index.rebuild()
    assert _json(vault_search_frontmatter("status", "external-private"))["results"] == []
    assert _link_candidates("external-alias.md") == []


def test_legacy_compatibility_search_ignores_external_symlink(
    vault_dir, tmp_path, monkeypatch
):
    areas = vault_dir / "04-areas"
    areas.mkdir()
    outside = tmp_path / "outside-legacy.md"
    outside.write_text("synthetic legacy needle", encoding="utf-8")
    (areas / "external-alias.md").symlink_to(outside)
    monkeypatch.setattr(legacy_gateway, "ROOT", vault_dir)
    monkeypatch.setattr(legacy_gateway, "AREAS_DIR", areas)
    monkeypatch.setattr(legacy_gateway, "READ_ALLOWED_ROOTS", [areas])

    assert legacy_gateway.search_paths("synthetic legacy needle", [areas], 10) == []
