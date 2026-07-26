"""Regressions for the thin Life OS learning adapter."""

from __future__ import annotations

import hashlib
import json

from obsidian_vault_mcp import audit, config, server
from obsidian_vault_mcp.tools import learning


def test_today_is_read_only_and_stale_notebook_is_fail_closed(
    vault_dir, monkeypatch
):
    note = vault_dir / "05-knowledge" / "concepts" / "coding.md"
    note.parent.mkdir(parents=True)
    note.write_text("# Coding\n", encoding="utf-8")
    registry = (
        vault_dir
        / "02-workbench"
        / "analysis"
        / "gemini-notebook"
        / "notebook-artifact-registry.json"
    )
    registry.parent.mkdir(parents=True)
    registry.write_text(json.dumps({
        "notebooks": [{
            "notebook_id": "notebook-1",
            "title": "Coding",
            "notebook_url": "https://notebooklm.google.com/notebook/notebook-1",
            "review_state": "stale",
            "sources": [{
                "path": "05-knowledge/concepts/coding.md",
                "sha256": hashlib.sha256(b"old body").hexdigest(),
            }],
            "artifacts": [{
                "type": "video", "title": "Coding lesson", "status": "completed",
            }],
        }],
    }), encoding="utf-8")
    monkeypatch.setattr(learning, "_run_learning", lambda _args: {
        "writes_performed": 0,
        "due": [],
        "new": [{
            "uid": "knowledge-coding",
            "obsidian_uri": (
                "obsidian://open?vault=Obsidian&file="
                "05-knowledge%2Fconcepts%2Fcoding.md"
            ),
        }],
        "triage": [],
    })

    payload = json.loads(learning.learning_get_today())
    assert payload["status"] == "pass"
    assert payload["writes_performed"] == 0
    material = payload["new"][0]["notebook_materials"][0]
    assert material["review_state"] == "stale"
    assert material["usable_as_current"] is False
    assert "content" not in material
    assert payload["notebooklm_capabilities"] == {
        "available_tools": ["notebooklm_list", "notebooklm_ask"],
        "artifact_generation": False,
        "artifact_status": False,
        "artifact_download": False,
    }
    assert "artifacts" not in material
    assert material["existing_registry_artifacts"] == [{
        "type": "video",
        "title": "Coding lesson",
        "status": "completed",
    }]


def test_intent_and_review_use_stable_ids_without_second_scheduler(monkeypatch):
    calls: list[list[str]] = []

    def fake_run(arguments):
        calls.append(arguments)
        return {"status": "applied", "event_id": arguments[arguments.index("--event-id") + 1]}

    monkeypatch.setattr(learning, "_run_learning", fake_run)
    first = json.loads(learning.learning_set_intent(
        "knowledge-coding", "study", "Owner path", "attempt-1", "chatgpt"
    ))
    second = json.loads(learning.learning_set_intent(
        "knowledge-coding", "study", "Owner path", "attempt-1", "chatgpt"
    ))
    assert first["event_id"] == second["event_id"]
    assert calls[0][-1] == "--apply"
    assert "intent-only" in first["learning_claim"]

    review = json.loads(learning.learning_record_review(
        "knowledge-coding", "Good", True, "Richiamo reale", "review-1",
        12000, None, "hermes",
    ))
    assert review["status"] == "applied"
    assert "--all-items" in calls[-1]
    blocked = json.loads(learning.learning_record_review(
        "knowledge-coding", "Good", False, "", "review-2",
    ))
    assert blocked["status"] == "error"
    assert blocked["write_executed"] is False


def test_public_learning_schemas_are_narrow_and_uniform():
    today = server.mcp._tool_manager.get_tool("learning_get_today").parameters
    assert set(today["properties"]["surface"]["enum"]) == {"knowledge", "media"}
    intent = server.mcp._tool_manager.get_tool("learning_set_intent").parameters
    assert set(intent["properties"]["intent"]["enum"]) == {
        "reference_only", "read_later", "study", "apply", "archive",
    }
    review = server.mcp._tool_manager.get_tool("learning_record_review").parameters
    assert review["properties"]["recall_attempted"]["const"] is True
    assert review["properties"]["attempt_id"]["pattern"] == r"^[A-Za-z0-9._:-]+$"


def test_missing_or_symlinked_scheduler_fails_closed(vault_dir):
    missing = json.loads(learning.learning_get_history("knowledge-coding"))
    assert missing["status"] == "error"
    assert missing["write_executed"] is False

    script = vault_dir / "00-system" / "tools" / "learning_state.py"
    script.parent.mkdir(parents=True)
    target = vault_dir / "real-learning.py"
    target.write_text("print('{}')\n", encoding="utf-8")
    script.symlink_to(target)
    symlinked = json.loads(learning.learning_get_history("knowledge-coding"))
    assert symlinked["status"] == "error"
    assert "symlink" in symlinked["error"]


def test_notebook_source_path_traversal_is_stale(vault_dir, monkeypatch):
    outside = vault_dir.parent / "outside.md"
    outside.write_text("# Outside\n", encoding="utf-8")
    registry = (
        vault_dir
        / "02-workbench"
        / "analysis"
        / "gemini-notebook"
        / "notebook-artifact-registry.json"
    )
    registry.parent.mkdir(parents=True)
    registry.write_text(json.dumps({
        "notebooks": [{
            "notebook_id": "notebook-escape",
            "title": "Unsafe",
            "review_state": "reviewed",
            "sources": [{
                "path": "../outside.md",
                "sha256": hashlib.sha256(outside.read_bytes()).hexdigest(),
            }],
            "artifacts": [],
        }],
    }), encoding="utf-8")
    monkeypatch.setattr(learning, "_run_learning", lambda _args: {
        "writes_performed": 0,
        "due": [],
        "new": [{
            "uid": "knowledge-unsafe",
            "obsidian_uri": (
                "obsidian://open?vault=Obsidian&file=..%2Foutside.md"
            ),
        }],
        "triage": [],
    })

    payload = json.loads(learning.learning_get_today())
    assert payload["new"][0]["notebook_materials"] == []


def test_learning_review_audit_never_copies_recall_text(
    vault_dir, tmp_path, monkeypatch
):
    audit_log = tmp_path / "audit" / "mutations.jsonl"
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", str(audit_log))
    event_path = "00-system/learning/events/chatgpt.jsonl"
    event_file = vault_dir / event_path
    event_file.parent.mkdir(parents=True)
    secret_recall = "richiamo privato che non deve entrare nel receipt"

    def append_event():
        event_file.write_text(
            json.dumps({"kind": "review", "recall_text": secret_recall}) + "\n",
            encoding="utf-8",
        )
        return json.dumps({"status": "applied", "event_id": "review-1"})

    result = json.loads(server._run_audited(
        "learning_record_review", append_event, path=event_path
    ))
    records = [
        json.loads(line)
        for line in audit_log.read_text(encoding="utf-8").splitlines()
    ]
    assert result["status"] == "applied"
    assert "mutation_receipt" not in result
    assert records[-1]["operation"] == "learning_record_review"
    assert records[-1]["checksum_before"] is None
    assert records[-1]["checksum_after"]
    assert secret_recall not in audit_log.read_text(encoding="utf-8")
    assert not (audit_log.parent / "mutation-receipts").exists()
