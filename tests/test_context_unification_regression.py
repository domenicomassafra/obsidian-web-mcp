"""Regression for synchronous index consistency after mutation."""

import json

from obsidian_vault_mcp import write_events
from obsidian_vault_mcp.frontmatter_index import FrontmatterIndex
from obsidian_vault_mcp.tools.write import vault_write


def test_index_updates_synchronously_after_mutation(vault_dir):
    index = FrontmatterIndex()
    index.start()
    write_events.register_write_listener(index.sync_write)
    try:
        vault_write("sync-created.md", "---\nstatus: active\n---\nbody")
        results = index.search_by_field("status", "active", "exact")
        assert any(item["path"] == "sync-created.md" for item in results)
    finally:
        index.stop()
