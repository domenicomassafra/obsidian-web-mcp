"""Tests for the append-only JSONL audit log (VAULT_AUDIT_LOG_PATH).

The vault_dir fixture (conftest) points the server at a temp vault. These tests drive the
server-level tool functions directly -- the same callables FastMCP registers -- so the
_run_audited wrapper is exercised end to end. The bearer middleware is not in the loop
here, so the authenticated principal is bound manually via context.set_request_context.
"""

import base64
import json

import pytest

from obsidian_vault_mcp import audit, config, context, server
from obsidian_vault_mcp.models import VaultMutationContextInput

PRINCIPAL = "test-bearer-token-abc123"
EXPECTED_HASH = __import__("hashlib").sha256(PRINCIPAL.encode("utf-8")).hexdigest()


def _sha_text(value: str) -> str:
    return __import__("hashlib").sha256(value.encode("utf-8")).hexdigest()


def _preflight(path, *, operation="create", preimage="absent", file_kind="atomic-note", reason="test capture"):
    return VaultMutationContextInput.model_validate({
        "reason": reason,
        "destination": path,
        "preflight": {
            "source_input_class": "test-fixture",
            "entity_area": "01-input/capture",
            "capability": "capture",
            "canonical_destination": path,
            "candidate_destinations": [path],
            "file_kind": file_kind,
            "operation": operation,
            "confidence": 0.99,
            "reason": reason,
            "preimage_requirement": preimage,
            "rollback_target": (
                f"delete-if-postimage:{path}" if operation == "create"
                else f"restore-preimage:{path}"
            ),
        },
    })


@pytest.fixture
def audit_log(vault_dir, tmp_path, monkeypatch):
    """Enable auditing to a temp log file with a bound principal; isolate global state."""
    log_path = tmp_path / "audit" / "mutations.jsonl"
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", str(log_path))
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_INCLUDE_READS", False)
    token = context.set_request_context(principal=PRINCIPAL, request_id="req-1", client="pytest")
    yield log_path
    context.reset_request_context(token)


def _records(log_path):
    if not log_path.exists():
        return []
    return [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line]


# --- off by default ---

def test_audit_off_by_default(vault_dir, monkeypatch, tmp_path):
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", "")
    log_path = tmp_path / "should-not-exist.jsonl"
    path = "01-input/capture/note.md"
    result = json.loads(server.vault_write(path, "body", _preflight(path)))
    assert result["path"] == path
    assert result["mutation_receipt"]["rollback"]["status"] == "unavailable"
    assert not log_path.exists()
    assert audit.should_audit_operation("vault_write") is False


# --- mutations ---

def test_mutation_writes_record_with_required_fields(audit_log):
    path = "01-input/capture/audited.md"
    server.vault_write(path, "hello audit", _preflight(path))
    records = _records(audit_log)
    assert len(records) == 1
    rec = records[0]
    for field in (
        "timestamp", "token_id_hash", "client_id", "operation", "target_path",
        "size_before", "size_after", "checksum_before", "checksum_after",
        "request_id", "operation_status", "error",
    ):
        assert field in rec
    assert rec["operation"] == "vault_write"
    assert rec["target_path"] == path
    assert rec["operation_status"] == "success"
    assert rec["size_before"] is None          # new file
    assert rec["size_after"] == len(b"hello audit")
    assert rec["checksum_after"] is not None


def test_raw_token_never_written_only_hash(audit_log):
    path = "01-input/capture/audited.md"
    server.vault_write(path, "secret content", _preflight(path))
    raw = audit_log.read_text(encoding="utf-8")
    assert PRINCIPAL not in raw
    assert _records(audit_log)[0]["token_id_hash"] == EXPECTED_HASH
    assert _records(audit_log)[0]["client_id"] == "pytest"


def test_overwrite_captures_before_and_after(audit_log):
    path = "01-input/capture/note.md"
    first = json.loads(server.vault_write(path, "first version", _preflight(path)))
    server.vault_write(
        path,
        "second, longer version",
        _preflight(path, operation="update", preimage=f"sha256:{first['sha256']}"),
        overwrite=True,
        expected_sha256=first["sha256"],
    )
    rec = _records(audit_log)[-1]
    assert rec["size_before"] == len(b"first version")
    assert rec["size_after"] == len(b"second, longer version")
    assert rec["checksum_before"] != rec["checksum_after"]


def test_text_mutation_returns_markdown_provenance_and_guarded_rollback(audit_log, vault_dir):
    path = "01-input/capture/receipt.md"
    initial = "Owner content stays.\n"
    server.vault_write(path, initial, _preflight(path))
    original = (vault_dir / path).read_text(encoding="utf-8")
    source = {
        "provider": "chatgpt",
        "conversation_id": "conversation-1",
        "message_id": "message-2",
        "content_sha256": "a" * 64,
        "message_sha256": "b" * 64,
        "channel": "chatgpt",
    }
    mutation = VaultMutationContextInput(
        reason="Record the missing durable preference",
        destination="06-life/profile.md",
        section="Preferences",
        source=source,
        semantic_facts=["The owner prefers one canonical note."],
        preflight={
            "source_input_class": "owner-capture",
            "entity_area": "01-input/capture",
            "capability": "capture",
            "canonical_destination": path,
            "candidate_destinations": [path],
            "file_kind": "atomic-note",
            "operation": "append",
            "confidence": 0.99,
            "reason": "Record the missing durable preference",
            "preimage_requirement": f"sha256:{_sha_text(original)}",
            "rollback_target": f"restore-preimage:{path}",
        },
    )
    result = json.loads(
        server.vault_append(
            path,
            "The owner prefers one canonical note.",
            separator="",
            mutation=mutation,
        )
    )
    receipt = result["mutation_receipt"]
    assert receipt["outcome"] == "applied"
    assert receipt["lines_added"] == 1
    assert receipt["lines_removed"] == 1
    assert receipt["section"] == "Preferences"
    assert receipt["source_identity"] == source
    assert receipt["semantic_fact_ids"] == [
        audit.semantic_fact_id("The owner prefers one canonical note.")
    ]
    assert "### Obsidian mutation" in receipt["markdown"]
    assert "Rollback: available" in receipt["markdown"]

    receipt_path = audit.mutation_receipt_dir() / f"{receipt['mutation_id']}.json"
    preimage_path = audit.mutation_receipt_dir() / f"{receipt['mutation_id']}.preimage"
    assert receipt_path.stat().st_mode & 0o777 == 0o600
    assert preimage_path.stat().st_mode & 0o777 == 0o600
    assert preimage_path.read_text(encoding="utf-8") == original
    assert _records(audit_log)[-1]["semantic_fact_ids"] == receipt["semantic_fact_ids"]

    rollback = audit.rollback_mutation(receipt["mutation_id"], confirm=True)
    assert rollback["status"] == "rollback_applied"
    assert (vault_dir / path).read_text(encoding="utf-8") == original
    assert audit.rollback_mutation(receipt["mutation_id"], confirm=True)["status"] == "already_rolled_back"


def test_mutation_preview_redacts_possible_secret(audit_log):
    path = "01-input/capture/redacted-preview.md"
    mutation = _preflight(path, reason="token=never-show")
    result = json.loads(server.vault_write(path, "api_key=never-show", mutation))
    public = result["mutation_receipt"]
    assert "never-show" not in public["markdown"]
    assert "[redacted possible secret]" in public["markdown"]


def test_semantic_fact_identity_normalizes_case_and_whitespace():
    assert audit.semantic_fact_id("  Stable   Fact ") == audit.semantic_fact_id("stable fact")


def test_binary_receipt_never_promises_an_unrestorable_rollback(audit_log):
    payload = base64.b64encode(b"binary payload").decode()
    result = json.loads(server.vault_write_binary("binary.pdf", payload, "application/pdf"))
    receipt = result["mutation_receipt"]

    assert receipt["outcome"] == "applied"
    assert receipt["rollback"]["status"] == "unavailable"
    assert "Rollback: unavailable for this operation." in receipt["markdown"]
    assert audit.rollback_mutation(receipt["mutation_id"], confirm=True) == {
        "status": "rollback_unavailable",
        "mutation_id": receipt["mutation_id"],
    }


def test_mutation_id_binds_source_and_semantic_fact_identity(audit_log):
    base = {
        "timestamp": "2026-07-22T00:00:00Z",
        "request_id": "request-1",
        "operation": "vault_write",
        "operation_status": "success",
        "target_path": "note.md",
        "checksum_before": None,
        "checksum_after": "a" * 64,
    }
    first = audit.build_mutation_receipt(
        base,
        None,
        "fact one",
        {"source": {"conversation_id": "conversation-1"}, "semantic_facts": ["fact one"]},
    )
    second = audit.build_mutation_receipt(
        base,
        None,
        "fact one",
        {"source": {"conversation_id": "conversation-2"}, "semantic_facts": ["fact two"]},
    )

    assert first["mutation_id"] != second["mutation_id"]


def test_binary_write_success_and_overwrite_are_audited(audit_log):
    first = base64.b64encode(b"first binary version").decode()
    second = base64.b64encode(b"second binary version").decode()

    server.vault_write_binary("asset.png", first, "image/png")
    server.vault_write_binary("asset.png", second, "image/png", overwrite=True)

    recs = [r for r in _records(audit_log) if r["operation"] == "vault_write_binary"]
    assert len(recs) == 2
    assert recs[0]["operation_status"] == "success"
    assert recs[0]["size_before"] is None
    assert recs[0]["size_after"] == len(b"first binary version")
    assert recs[1]["size_before"] == len(b"first binary version")
    assert recs[1]["size_after"] == len(b"second binary version")
    assert recs[1]["checksum_before"] != recs[1]["checksum_after"]


def test_binary_write_error_is_audited_without_creating_file(audit_log):
    result = json.loads(
        server.vault_write_binary("invalid.png", "not-base64!", "image/png")
    )

    assert "error" in result
    rec = _records(audit_log)[-1]
    assert rec["operation"] == "vault_write_binary"
    assert rec["operation_status"] == "error"
    assert rec["target_path"] == "invalid.png"
    assert rec["size_before"] is None
    assert rec["size_after"] is None


def test_mutation_error_recorded(audit_log):
    # A path that escapes the vault returns an error payload (a mutation attempt).
    path = "../escape.md"
    mutation = VaultMutationContextInput.model_validate({
        "preflight": {
            "source_input_class": "test-fixture", "entity_area": "01-input/capture",
            "capability": "capture", "canonical_destination": path,
            "candidate_destinations": [path], "file_kind": "atomic-note",
            "operation": "create", "confidence": 0.99, "reason": "invalid path",
            "preimage_requirement": "absent", "rollback_target": f"delete-if-postimage:{path}",
        }
    })
    result = json.loads(server.vault_write(path, "x", mutation))
    assert result["error"] == "write_preflight_blocked"
    assert _records(audit_log) == []


def test_move_records_destination(audit_log):
    source = "01-input/capture/src.md"
    destination = "01-input/capture/dst.md"
    server.vault_write(source, "movable", _preflight(source))
    move = _preflight(source, operation="move", preimage=f"sha256:{_sha_text('movable')}")
    move.preflight.canonical_destination = destination
    move.preflight.candidate_destinations = [destination]
    move.preflight.rollback_target = f"move-back:{destination}->{source}"
    move.destination = destination
    server.vault_move(source, destination, move)
    rec = _records(audit_log)[-1]
    assert rec["operation"] == "vault_move"
    assert rec["target_path"] == destination
    assert rec["size_after"] == len(b"movable")


# --- reads (opt-in) ---

def test_reads_not_logged_by_default(audit_log):
    server.vault_read("test-note.md")
    assert _records(audit_log) == []
    assert audit.should_audit_operation("vault_read") is False


def test_reads_logged_when_enabled(audit_log, monkeypatch):
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_INCLUDE_READS", True)
    server.vault_read("test-note.md")
    rec = _records(audit_log)[-1]
    assert rec["operation"] == "vault_read"
    assert rec["target_path"] == "test-note.md"
    assert rec["checksum_before"] is not None   # captured as read


# --- failure isolation ---

def test_audit_write_failure_does_not_break_tool(vault_dir, monkeypatch):
    # Parent of the log path is an existing FILE, so mkdir/open fails on every write.
    bad = vault_dir / "test-note.md" / "audit.jsonl"
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", str(bad))
    assert audit.audit_path_writable() is False
    token = context.set_request_context(principal=PRINCIPAL, request_id="r", client="c")
    try:
        path = "01-input/capture/still-works.md"
        result = json.loads(server.vault_write(path, "body", _preflight(path)))
        assert result["created"] is True        # the write itself succeeded despite audit failing
    finally:
        context.reset_request_context(token)


def test_audit_log_rotation_is_bounded(audit_log, monkeypatch):
    monkeypatch.setattr(audit, "AUDIT_LOG_MAX_BYTES", 1)
    monkeypatch.setattr(audit, "AUDIT_LOG_BACKUPS", 3)

    for index in range(6):
        path = f"01-input/capture/rotated-{index}.md"
        server.vault_write(path, str(index), _preflight(path))

    assert audit_log.exists()
    assert audit_log.with_name(f"{audit_log.name}.1").exists()
    assert audit_log.with_name(f"{audit_log.name}.2").exists()
    assert audit_log.with_name(f"{audit_log.name}.3").exists()
    assert not audit_log.with_name(f"{audit_log.name}.4").exists()
    assert (audit_log.stat().st_mode & 0o777) == 0o600


# --- in-vault audit log rejected (#2 integrity) ---

def test_audit_path_inside_vault_detected(vault_dir, monkeypatch):
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", str(vault_dir / "audit.jsonl"))
    assert audit.audit_path_inside_vault() is True
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", str(vault_dir / "subfolder" / "a.jsonl"))
    assert audit.audit_path_inside_vault() is True


def test_audit_path_outside_vault_ok(vault_dir, tmp_path, monkeypatch):
    # tmp_path is the vault's parent, so a sibling dir is outside the vault.
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", str(tmp_path / "outside" / "audit.jsonl"))
    assert audit.audit_path_inside_vault() is False


# --- writability ---

def test_path_writable_checks(vault_dir, tmp_path, monkeypatch):
    good = tmp_path / "ok.jsonl"
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", str(good))
    assert audit.audit_path_writable() is True
    bad = vault_dir / "test-note.md" / "nope.jsonl"   # parent is a file
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", str(bad))
    assert audit.audit_path_writable() is False


# --- snapshot safety ---

def test_snapshot_path_stays_in_vault(vault_dir):
    assert audit.snapshot_path("../outside.md") == {"size": None, "checksum": None}
    assert audit.snapshot_path("does-not-exist.md") == {"size": None, "checksum": None}
    snap = audit.snapshot_path("test-note.md")
    assert snap["size"] > 0 and snap["checksum"]


# --- wiring: tools stay registered (wrapper preserved the schema) ---

@pytest.mark.parametrize("name", [
    "vault_write", "vault_write_binary", "vault_edit", "vault_append", "vault_move", "vault_delete",
    "vault_read", "vault_search", "vault_canvas_add_node", "vault_daily_note_append",
])
def test_audited_tools_still_registered(vault_dir, name):
    assert server.mcp._tool_manager.get_tool(name) is not None


# --- batch: one record per file with correct per-file status (#3) ---

def test_batch_emits_one_record_per_file_with_status(audit_log):
    path = "01-input/capture/a.md"
    server.vault_write(path, "---\nx: 1\n---\nbody", _preflight(path))
    # a.md exists, missing.md does not -> partial failure within one batch call
    updates = [
        {"path": path, "fields": {"status": "done"}},
        {"path": "01-input/capture/missing.md", "fields": {"status": "done"}},
    ]
    server.vault_batch_frontmatter_update(updates)
    recs = [r for r in _records(audit_log) if r["operation"] == "vault_batch_frontmatter_update"]
    assert len(recs) == 2                      # one record per file, not one for the call
    by_path = {r["target_path"]: r for r in recs}
    assert by_path[path]["operation_status"] == "success"
    assert by_path[path]["checksum_after"] is not None   # real snapshot, not null
    assert by_path["01-input/capture/missing.md"]["operation_status"] == "error"   # partial failure surfaced
    assert by_path["01-input/capture/missing.md"]["error"]


# --- dry-run edit is not recorded as a mutation (non-blocking item) ---

def test_dry_run_edit_not_audited(audit_log):
    path = "01-input/capture/edit.md"
    server.vault_write(path, "alpha beta", _preflight(path))
    before = len(_records(audit_log))
    update = _preflight(path, operation="update", preimage=f"sha256:{_sha_text('alpha beta')}")
    server.vault_edit(path, [{"old_text": "alpha", "new_text": "ALPHA"}], update, dry_run=True)
    assert len(_records(audit_log)) == before          # dry run wrote nothing, logged nothing
    server.vault_edit(path, [{"old_text": "alpha", "new_text": "ALPHA"}], update)
    assert len(_records(audit_log)) == before + 1       # the real edit IS audited


def test_daily_append_captures_before_snapshot(audit_log, monkeypatch):
    monkeypatch.setattr(config, "VAULT_DAILY_NOTES_FOLDER", "")
    server.vault_daily_note_append("first line")
    server.vault_daily_note_append("second line")
    recs = [r for r in _records(audit_log) if r["operation"] == "vault_daily_note_append"]
    assert recs[-1]["size_before"] is not None          # before-snapshot now captured
