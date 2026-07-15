"""Bound serialized tool results without making mutation outcomes ambiguous."""

import json

import pytest

from obsidian_vault_mcp import serialization
from obsidian_vault_mcp.serialization import dumps
from obsidian_vault_mcp.tools.canvas import vault_canvas_add_node
from obsidian_vault_mcp.tools.read import vault_batch_read, vault_read
from obsidian_vault_mcp.tools.write import vault_edit


CAP = 1024


@pytest.fixture(autouse=True)
def _small_result_cap(monkeypatch):
    monkeypatch.setattr(serialization, "MAX_TOOL_RESULT_BYTES", CAP)


def _assert_omitted(raw: str, *, status: str = "success") -> dict:
    assert len(raw.encode("utf-8")) <= CAP
    payload = json.loads(raw)
    assert payload["result_omitted"] is True
    assert payload["reason"] == "tool_result_too_large"
    assert payload["original_status"] == status
    assert payload["actual_bytes"] > CAP
    assert payload["max_bytes"] == CAP
    return payload


def test_small_result_is_byte_for_byte_unchanged():
    obj = {"path": "notes/riunione.md", "changed": True, "size": 42}
    expected = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    assert dumps(obj) == expected


def test_limit_counts_utf8_bytes_and_omits_original_content():
    marker = "RISERVATO-🚀"
    raw = dumps({"content": marker * 200})
    payload = _assert_omitted(raw)
    assert marker not in raw
    assert payload["actual_bytes"] > len(marker) * 200


def test_oversized_original_error_remains_an_error_without_leaking_detail():
    marker = "PRIVATE-ERROR-DETAIL"
    raw = dumps({"error": marker * 200, "path": "notes/error.md"})
    payload = _assert_omitted(raw, status="error")
    assert "error" in payload
    assert marker not in raw
    assert payload["summary"]["path"] == "notes/error.md"


def test_rejects_a_limit_too_small_for_the_overflow_envelope():
    with pytest.raises(ValueError, match="at least"):
        dumps({"ok": True}, max_bytes=100)


def test_vault_read_large_note_returns_bounded_success_envelope(vault_dir):
    marker = "PRIVATE-READ-CONTENT"
    (vault_dir / "large.md").write_text(marker * 400, encoding="utf-8")

    raw = vault_read("large.md")
    payload = _assert_omitted(raw)

    assert marker not in raw
    assert payload["summary"]["path"] == "large.md"


def test_vault_batch_read_large_notes_preserves_counts(vault_dir):
    marker = "PRIVATE-BATCH-CONTENT"
    (vault_dir / "one.md").write_text(marker * 200, encoding="utf-8")
    (vault_dir / "two.md").write_text(marker * 200, encoding="utf-8")

    raw = vault_batch_read(["one.md", "two.md"])
    payload = _assert_omitted(raw)

    assert marker not in raw
    assert payload["summary"]["found"] == 2
    assert payload["summary"]["missing"] == 0


def test_vault_edit_large_diff_reports_success_after_mutation(vault_dir):
    before = "prefix\n" + ("A" * 5000) + "\nsuffix\n"
    after = "prefix\n" + ("B" * 5000) + "\nsuffix\n"
    (vault_dir / "edit.md").write_text(before, encoding="utf-8")

    raw = vault_edit("edit.md", [{"old_text": "A" * 5000, "new_text": "B" * 5000}])
    payload = _assert_omitted(raw)

    assert (vault_dir / "edit.md").read_text(encoding="utf-8") == after
    assert payload["summary"]["changed"] is True
    assert payload["summary"]["dry_run"] is False
    assert payload["summary"]["edits_applied"] == 1


def test_canvas_mutation_is_applied_once_and_reports_success(vault_dir):
    nodes = [
        {
            "id": f"n{i}",
            "type": "text",
            "x": i,
            "y": 0,
            "width": 100,
            "height": 60,
            "text": "PRIVATE-CANVAS-CONTENT" * 20,
        }
        for i in range(20)
    ]
    (vault_dir / "large.canvas").write_text(
        json.dumps({"nodes": nodes, "edges": []}), encoding="utf-8"
    )
    new_node = {
        "id": "newnode",
        "type": "text",
        "x": 100,
        "y": 100,
        "width": 120,
        "height": 80,
        "text": "added once",
    }

    raw = vault_canvas_add_node("large.canvas", new_node)
    payload = _assert_omitted(raw)

    written = json.loads((vault_dir / "large.canvas").read_text(encoding="utf-8"))
    assert [node["id"] for node in written["nodes"]].count("newnode") == 1
    assert payload["summary"]["created"] is False
    assert payload["summary"]["node_count"] == 21
    assert payload["summary"]["edge_count"] == 0
