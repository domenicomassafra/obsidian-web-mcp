"""Append-only JSON-lines audit log for vault mutations.

When VAULT_AUDIT_LOG_PATH is set, every vault mutation appends one JSON record to that
file: a UTC timestamp, a SHA-256 hash of the bearer token (never the token itself), the
operation, the target path, and the size + checksum of the target before and after the
change. Read/search operations are logged too when VAULT_AUDIT_LOG_INCLUDE_READS is on.

Auditing is off unless a log path is configured. At startup the path is validated as
writable AND rejected if it resolves inside the vault (where the vault tools could rewrite
it), so a misconfigured path fails the server closed. At runtime the log is best-effort:
a failure to write a record is logged but never alters the tool result -- the audit trail
must not be able to break a write.
"""

from __future__ import annotations

import hashlib
import difflib
import json
import logging
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import config
from .context import current_request_context
from .serialization import dumps
from .vault import resolve_vault_path, write_file_atomic

logger = logging.getLogger(__name__)

AUDIT_LOG_MAX_BYTES = 10_000_000
AUDIT_LOG_BACKUPS = 3
_audit_lock = threading.Lock()
FACT_ID_SCHEME = "obsidian-semantic-fact-v1"
_MUTATION_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_ROLLBACKABLE_TEXT_OPERATIONS = {
    "vault_write",
    "vault_edit",
    "vault_append",
    "vault_canvas_add_node",
    "vault_canvas_add_edge",
    "vault_daily_note_append",
}
_SECRET_LINE_RE = re.compile(
    r"(?i)(?:bearer\s+\S+|(?:password|passwd|token|secret|api[_-]?key)\s*[:=])"
)

# Operations that change the vault. Always audited when a log path is configured.
MUTATION_OPERATIONS = {
    "vault_write",
    "vault_write_binary",
    "vault_edit",
    "vault_append",
    "vault_batch_frontmatter_update",
    "vault_move",
    "vault_delete",
    "vault_canvas_add_node",
    "vault_canvas_add_edge",
    "vault_daily_note_append",
}

# Read/search operations. Audited only when VAULT_AUDIT_LOG_INCLUDE_READS is enabled.
READ_OPERATIONS = {
    "vault_read",
    "vault_batch_read",
    "vault_search",
    "vault_search_frontmatter",
    "vault_list",
    "vault_canvas_read",
    "vault_daily_note_read",
}

# Mutations whose result reports per-file outcomes; audited one record per file.
BATCH_OPERATIONS = {"vault_batch_frontmatter_update"}


def audit_enabled() -> bool:
    """True when append-only audit logging is configured."""
    return bool(config.VAULT_AUDIT_LOG_PATH)


def read_audit_enabled() -> bool:
    """True when read/search operations should also be audited."""
    return audit_enabled() and bool(config.VAULT_AUDIT_LOG_INCLUDE_READS)


def should_audit_operation(operation: str) -> bool:
    """True when this operation should emit a record under the current config.

    False whenever auditing is off, so the wrapper is a true passthrough (no snapshot
    work) on the default path.
    """
    if not audit_enabled():
        return False
    return operation in MUTATION_OPERATIONS or (
        operation in READ_OPERATIONS and read_audit_enabled()
    )


def audit_log_path() -> Path:
    return Path(config.VAULT_AUDIT_LOG_PATH).expanduser()


def audit_path_writable(path: Path | None = None) -> bool:
    """True when the audit log can be written (creating intermediate dirs if needed).

    An existing log must be a writable file. Otherwise the log is creatable when the
    nearest existing ancestor is a writable directory -- write_audit_record mkdirs the
    intermediate dirs. A path whose parent is a regular file is rejected.
    """
    path = path or audit_log_path()
    try:
        if path.exists():
            return path.is_file() and os.access(path, os.W_OK)
        ancestor = path.parent
        while not ancestor.exists():
            if ancestor.parent == ancestor:
                return False
            ancestor = ancestor.parent
        return ancestor.is_dir() and os.access(ancestor, os.W_OK)
    except OSError:
        return False


def audit_path_inside_vault() -> bool:
    """True when the configured audit log resolves inside the vault.

    A same-vault log is just another file the vault tools can reach: resolve_vault_path
    only blocks traversal and dotfiles, so an authenticated caller could overwrite it via
    vault_write or relocate it via vault_delete, defeating the append-only integrity
    premise. Such a path is rejected at startup (see server.main).
    """
    if not audit_enabled():
        return False
    try:
        log = audit_log_path().resolve()
        vault = config.VAULT_PATH.resolve()
    except OSError:
        return False
    return log == vault or vault in log.parents


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _hash_value(value: str | None) -> str | None:
    if not value:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def snapshot_path(path: Any) -> dict[str, Any]:
    """Capture (size, checksum) for a vault-relative path; nulls when absent or invalid.

    Routes through resolve_vault_path so a path that escapes the vault is treated as
    absent rather than read.
    """
    empty: dict[str, Any] = {"size": None, "checksum": None}
    if not isinstance(path, str) or not path:
        return empty
    try:
        resolved = resolve_vault_path(path)
    except ValueError:
        return empty
    if not resolved.is_file():
        return empty
    return {"size": resolved.stat().st_size, "checksum": _sha256_file(resolved)}


def snapshot_text(path: Any) -> str | None:
    """Read a UTF-8 pre/postimage for receipt generation; absent/binary targets return null."""
    if not isinstance(path, str) or not path:
        return None
    try:
        resolved = resolve_vault_path(path)
        return resolved.read_text(encoding="utf-8") if resolved.is_file() else None
    except (OSError, UnicodeError, ValueError):
        return None


def semantic_fact_id(text: str) -> str:
    """Identity shared with the canonical nightly consumer."""
    normalized = " ".join(text.split()).casefold()
    return hashlib.sha256(f"{FACT_ID_SCHEME}\n{normalized}".encode("utf-8")).hexdigest()


def mutation_receipt_dir() -> Path | None:
    """Keep private receipts beside (never inside) the configured audit log."""
    return audit_log_path().parent / "mutation-receipts" if audit_enabled() else None


def _line_delta(before: str | None, after: str | None) -> tuple[int, int, list[str], str]:
    before_lines = (before or "").splitlines(keepends=True)
    after_lines = (after or "").splitlines(keepends=True)
    diff_lines = list(
        difflib.unified_diff(before_lines, after_lines, fromfile="before", tofile="after", lineterm="")
    )
    added = [line[1:].rstrip("\n") for line in diff_lines if line.startswith("+") and not line.startswith("+++")]
    removed = [line[1:].rstrip("\n") for line in diff_lines if line.startswith("-") and not line.startswith("---")]
    return len(added), len(removed), added, "".join(diff_lines)


def _safe_preview(lines: list[str]) -> str:
    preview: list[str] = []
    for line in lines[:3]:
        value = "[redacted possible secret]" if _SECRET_LINE_RE.search(line) else line.strip()
        if value:
            preview.append(value[:180])
    return " / ".join(preview)[:400] or "(no added text)"


def build_mutation_receipt(
    record: dict[str, Any],
    before_text: str | None,
    after_text: str | None,
    mutation_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the JSON + bounded Markdown receipt returned by text mutations."""
    mutation_context = mutation_context or {}
    write_preflight = mutation_context.get("preflight") or {}
    fact_ids = sorted({semantic_fact_id(text) for text in mutation_context.get("semantic_facts") or []})
    source_identity = mutation_context.get("source")
    identity = {
        "request_id": record.get("request_id"),
        "operation": record.get("operation"),
        "target_path": record.get("target_path"),
        "checksum_before": record.get("checksum_before"),
        "checksum_after": record.get("checksum_after"),
        "source_identity": source_identity,
        "semantic_fact_ids": fact_ids,
    }
    mutation_id = hashlib.sha256(dumps(identity, sort_keys=True).encode("utf-8")).hexdigest()
    added, removed, added_lines, exact_diff = _line_delta(before_text, after_text)
    status = record.get("operation_status")
    if status == "error":
        outcome = "failed"
    elif record.get("checksum_before") == record.get("checksum_after"):
        outcome = "already_applied"
    else:
        outcome = "applied"
    rollback_can_restore = (
        record.get("operation") in _ROLLBACKABLE_TEXT_OPERATIONS
        and after_text is not None
        and (record.get("checksum_before") is None or before_text is not None)
    )
    if status == "success" and outcome == "applied" and rollback_can_restore:
        rollback_status = "available" if audit_enabled() else "unavailable"
    elif status == "success" and outcome == "applied":
        rollback_status = "unavailable"
    else:
        rollback_status = "not_required"
    reason = mutation_context.get("reason") or write_preflight.get("reason") or "not supplied"
    section = mutation_context.get("section") or "not supplied"
    destination = (
        mutation_context.get("destination")
        or write_preflight.get("canonical_destination")
        or record.get("target_path")
        or "unknown"
    )
    safe_reason = "[redacted possible secret]" if _SECRET_LINE_RE.search(str(reason)) else str(reason)[:500]
    rollback_summary = {
        "available": "available with this mutation ID; guarded by postimage SHA-256.",
        "unavailable": "unavailable for this operation.",
        "not_required": "not required.",
    }[rollback_status]
    markdown = "\n".join(
        [
            f"### Obsidian mutation `{mutation_id[:12]}`",
            f"- File: `{record.get('target_path')}`",
            f"- Section: {section}",
            f"- Change: +{added} / -{removed} lines ({outcome})",
            f"- Preview: {_safe_preview(added_lines)}",
            f"- Reason / destination: {safe_reason} → {destination}",
            f"- Mutation ID: `{mutation_id}`",
            f"- Rollback: {rollback_summary}",
        ]
    )
    return {
        "schema_version": 1,
        "kind": "obsidian-mutation-receipt",
        "mutation_id": mutation_id,
        "timestamp": record.get("timestamp"),
        "operation": record.get("operation"),
        "outcome": outcome,
        "target_path": record.get("target_path"),
        "section": mutation_context.get("section"),
        "reason": safe_reason,
        "destination": destination,
        "lines_added": added,
        "lines_removed": removed,
        "preview": _safe_preview(added_lines),
        "checksum_before": record.get("checksum_before"),
        "checksum_after": record.get("checksum_after"),
        "source_identity": source_identity,
        "fact_id_scheme": FACT_ID_SCHEME,
        "semantic_fact_ids": fact_ids,
        "rollback": {"status": rollback_status, "mutation_id": mutation_id},
        "markdown": markdown,
        "exact_diff": exact_diff,
        "preimage_present": before_text is not None,
        "write_preflight": {
            "schema": "obsidian-write-preflight/v1",
            "source_input_class": write_preflight.get("source_input_class"),
            "entity_area": write_preflight.get("entity_area"),
            "capability": write_preflight.get("capability"),
            "canonical_destination": write_preflight.get("canonical_destination"),
            "file_kind": write_preflight.get("file_kind"),
            "operation": write_preflight.get("operation"),
            "confidence": write_preflight.get("confidence"),
            "reason": write_preflight.get("reason"),
            "preimage_requirement": write_preflight.get("preimage_requirement"),
            "rollback_target": write_preflight.get("rollback_target"),
        },
    }


def persist_mutation_receipt(receipt: dict[str, Any], before_text: str | None) -> bool:
    """Persist exact owner-local evidence and its preimage with mode 0600."""
    root = mutation_receipt_dir()
    if root is None:
        return False
    try:
        root.mkdir(parents=True, exist_ok=True)
        root.chmod(0o700)
        mutation_id = str(receipt["mutation_id"])
        if before_text is not None:
            preimage = root / f"{mutation_id}.preimage"
            preimage.write_text(before_text, encoding="utf-8")
            preimage.chmod(0o600)
        path = root / f"{mutation_id}.json"
        path.write_text(dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
        path.chmod(0o600)
        return True
    except Exception as exc:
        logger.error("Mutation receipt write failed: %s", type(exc).__name__)
        return False


def attach_mutation_receipt(result: str, receipt: dict[str, Any]) -> str:
    """Add the bounded public recap without changing a tool's success/error truth."""
    try:
        payload = json.loads(result)
    except (TypeError, ValueError):
        return result
    if not isinstance(payload, dict):
        return result
    public = {key: value for key, value in receipt.items() if key not in {"exact_diff", "preimage_present"}}
    payload["mutation_receipt"] = public
    return dumps(payload)


def rollback_mutation(mutation_id: str, confirm: bool = False) -> dict[str, Any]:
    """Restore a recorded text preimage only while the postimage still matches."""
    if not confirm:
        return {"status": "confirmation_required", "mutation_id": mutation_id}
    if not _MUTATION_ID_RE.fullmatch(mutation_id):
        return {"status": "invalid_mutation_id", "mutation_id": mutation_id}
    root = mutation_receipt_dir()
    if root is None:
        return {"status": "receipt_store_unavailable", "mutation_id": mutation_id}
    receipt_path = root / f"{mutation_id}.json"
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        if (receipt.get("rollback") or {}).get("status") != "available":
            return {"status": "rollback_unavailable", "mutation_id": mutation_id}
        target_path = str(receipt["target_path"])
        resolved = resolve_vault_path(target_path)
        current = _sha256_file(resolved)
        before = receipt.get("checksum_before")
        after = receipt.get("checksum_after")
        if current == before:
            return {"status": "already_rolled_back", "mutation_id": mutation_id, "target_path": target_path}
        if current != after:
            return {"status": "rollback_conflict", "mutation_id": mutation_id, "target_path": target_path}
        if before is None:
            resolved.unlink()
        else:
            preimage = (root / f"{mutation_id}.preimage").read_text(encoding="utf-8")
            if hashlib.sha256(preimage.encode("utf-8")).hexdigest() != before:
                return {"status": "preimage_invalid", "mutation_id": mutation_id, "target_path": target_path}
            write_file_atomic(target_path, preimage, create_dirs=False, expected_sha256=after)
        return {"status": "rollback_applied", "mutation_id": mutation_id, "target_path": target_path, "checksum_restored": before}
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        return {"status": "receipt_invalid", "mutation_id": mutation_id}


def before_target_path(operation: str, context: dict[str, Any]) -> Any:
    """The path to snapshot before a mutation runs."""
    if operation == "vault_move":
        return context.get("source")
    return context.get("path") or context.get("source")


def infer_target_path(operation: str, context: dict[str, Any], result: dict[str, Any] | None = None) -> Any:
    """Best-effort target path from the call context and the parsed result payload."""
    result = result or {}
    if operation == "vault_move":
        return result.get("destination") or context.get("destination")
    if operation == "vault_batch_frontmatter_update":
        results = result.get("results")
        if isinstance(results, list):
            paths = [item.get("path") for item in results if isinstance(item, dict) and item.get("path")]
            if paths:
                return paths
    return result.get("path") or context.get("path") or context.get("source")


def build_audit_record(
    *,
    operation: str,
    target_path: Any,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    operation_status: str = "success",
    error: str | None = None,
) -> dict[str, Any]:
    """Build one normalized audit record from the current request context."""
    ctx = current_request_context()
    before = before or {"size": None, "checksum": None}
    after = after or {"size": None, "checksum": None}
    return {
        "timestamp": _now_utc().isoformat(),
        "token_id_hash": _hash_value(ctx.get("principal")),
        "client_id": ctx.get("client"),
        "operation": operation,
        "target_path": target_path,
        "size_before": before.get("size"),
        "size_after": after.get("size"),
        "checksum_before": before.get("checksum"),
        "checksum_after": after.get("checksum"),
        "request_id": ctx.get("request_id") or uuid.uuid4().hex,
        "operation_status": operation_status,
        "error": error,
    }


def write_audit_record(record: dict[str, Any]) -> bool:
    """Append one JSON record with bounded rotation.

    A write/rotation failure is logged and swallowed (best-effort), preserving the
    existing contract that audit storage cannot make a vault mutation fail.
    """
    if not audit_enabled():
        return False
    try:
        path = audit_log_path()
        line = dumps(record, sort_keys=True) + "\n"
        with _audit_lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.is_file() and path.stat().st_size + len(line.encode("utf-8")) > AUDIT_LOG_MAX_BYTES:
                oldest = path.with_name(f"{path.name}.{AUDIT_LOG_BACKUPS}")
                if oldest.exists():
                    oldest.unlink()
                for index in range(AUDIT_LOG_BACKUPS - 1, 0, -1):
                    source = path.with_name(f"{path.name}.{index}")
                    if source.exists():
                        source.replace(path.with_name(f"{path.name}.{index + 1}"))
                path.replace(path.with_name(f"{path.name}.1"))
            with path.open("a", encoding="utf-8") as handle:
                handle.write(line)
            path.chmod(0o600)
        return True
    except Exception as exc:
        logger.error("Audit log write failed: %s", exc)
        return False
