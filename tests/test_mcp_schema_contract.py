"""Regression tests for the public MCP tool contracts."""

from obsidian_vault_mcp import server


def _tool_schema(name: str) -> dict:
    tool = server.mcp._tool_manager.get_tool(name)
    assert tool is not None
    return tool.parameters


def _resolve(schema: dict, fragment: dict) -> dict:
    ref = fragment.get("$ref")
    if not ref:
        return fragment
    assert ref.startswith("#/$defs/")
    return schema["$defs"][ref.rsplit("/", 1)[-1]]


def test_read_tool_choices_are_enumerated():
    analytics = _tool_schema("vault_analytics_findings")
    category = analytics["properties"]["category"]
    assert set(category["enum"]) == {
        "frontmatter_missing",
        "required_frontmatter_missing",
        "broken_wikilinks",
        "suspicious_tag_variants",
        "encoding_issues",
        "oversized_files",
    }

    frontmatter = _tool_schema("vault_search_frontmatter")
    assert frontmatter["properties"]["match_type"]["enum"] == ["exact", "contains", "exists"]


def test_mutation_object_contracts_are_advertised():
    batch = _tool_schema("vault_batch_frontmatter_update")
    update = _resolve(batch, batch["properties"]["updates"]["items"])
    assert {"path", "fields"} <= set(update["properties"])
    assert set(update["required"]) == {"path", "fields"}

    edit = _tool_schema("vault_edit")
    operation = _resolve(edit, edit["properties"]["edits"]["items"])
    assert set(operation["required"]) == {"old_text", "new_text"}

    node_tool = _tool_schema("vault_canvas_add_node")
    node = _resolve(node_tool, node_tool["properties"]["node"])
    assert {"type", "x", "y", "width", "height"} <= set(node["required"])
    assert node["properties"]["type"]["enum"] == ["text", "file", "link", "group"]

    edge_tool = _tool_schema("vault_canvas_add_edge")
    edge = _resolve(edge_tool, edge_tool["properties"]["edge"])
    assert set(edge["required"]) == {"fromNode", "fromSide", "toNode", "toSide"}
    assert edge["properties"]["fromSide"]["enum"] == ["top", "right", "bottom", "left"]


def test_vault_write_advertises_conflict_guards():
    schema = _tool_schema("vault_write")
    properties = schema["properties"]
    assert properties["overwrite"]["default"] is False
    assert properties["expected_sha256"]["anyOf"][0]["pattern"] == "^[0-9a-fA-F]{64}$"


def test_public_tool_count_remains_stable():
    assert len(server.mcp._tool_manager._tools) == 20


def test_batch_frontmatter_update_is_marked_destructive():
    tool = server.mcp._tool_manager.get_tool("vault_batch_frontmatter_update")
    assert tool.annotations.destructiveHint is True
