"""Thin adapter to the vault-owned Life OS learning ledger.

The scheduler, events and mastery rules remain canonical in
``00-system/tools/learning_state.py`` inside the configured vault. This module
only validates the executable boundary, invokes it and adds body-free study
material pointers for MCP clients.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .. import config
from ..serialization import dumps


class LearningToolError(RuntimeError):
    """Bounded error returned by the learning adapter."""


_NOTEBOOKLM_CAPABILITIES = {
    "available_tools": ["notebooklm_list", "notebooklm_ask"],
    "artifact_generation": False,
    "artifact_status": False,
    "artifact_download": False,
}


def _resolve_vault_file(relative_path: str) -> Path:
    """Resolve one regular vault file without aliases or path traversal."""
    relative = Path(relative_path)
    if (
        not relative_path
        or relative.is_absolute()
        or ".." in relative.parts
    ):
        raise LearningToolError("vault file path is not a safe relative path")
    root = config.VAULT_PATH.expanduser().resolve()
    candidate = root.joinpath(*relative.parts)
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise LearningToolError("vault file path must not contain symlinks")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise LearningToolError("vault file is unavailable") from exc
    if root not in resolved.parents or not resolved.is_file():
        raise LearningToolError("vault file is outside the configured vault")
    return resolved


def _learning_script() -> Path:
    try:
        return _resolve_vault_file("00-system/tools/learning_state.py")
    except LearningToolError as exc:
        raise LearningToolError(
            f"canonical learning_state.py is unavailable: {exc}"
        ) from exc


def _run_learning(arguments: list[str], *, timeout: int = 30) -> dict[str, Any]:
    environment = os.environ.copy()
    environment["LIFEOS_LEARNING_ROOT"] = str(config.VAULT_PATH.expanduser().resolve())
    try:
        completed = subprocess.run(
            [sys.executable, str(_learning_script()), *arguments],
            cwd=str(config.VAULT_PATH),
            env=environment,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise LearningToolError("learning command timed out") from exc
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise LearningToolError("learning command returned invalid JSON") from exc
    if completed.returncode != 0 or not isinstance(payload, dict):
        reason = payload.get("reason") if isinstance(payload, dict) else None
        raise LearningToolError(str(reason or "learning command failed")[:500])
    return payload


def _event_id(kind: str, attempt_id: str, uid: str, client: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", attempt_id):
        raise LearningToolError("attempt_id is not a stable identifier")
    digest = hashlib.sha256(
        f"{kind}\0{client}\0{uid}\0{attempt_id}".encode()
    ).hexdigest()[:24]
    return f"{kind}-{digest}"


def _note_path(uri: str) -> str:
    try:
        return parse_qs(urlparse(uri).query).get("file", [""])[0]
    except Exception:
        return ""


def _notebook_materials(relative_path: str) -> list[dict[str, Any]]:
    registry_path = (
        config.VAULT_PATH
        / "02-workbench"
        / "analysis"
        / "gemini-notebook"
        / "notebook-artifact-registry.json"
    )
    allowed_roots = ("05-knowledge/", "01-input/sources/")
    if (
        not relative_path
        or not relative_path.startswith(allowed_roots)
        or "/archive/" in f"/{relative_path.casefold()}/"
        or not registry_path.is_file()
    ):
        return []
    try:
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    materials: list[dict[str, Any]] = []
    for notebook in registry.get("notebooks", []):
        if not isinstance(notebook, dict):
            continue
        sources = notebook.get("sources", [])
        if not any(
            isinstance(source, dict) and source.get("path") == relative_path
            for source in sources
        ):
            continue
        drift = False
        for source in sources:
            if not isinstance(source, dict):
                drift = True
                continue
            expected = str(source.get("sha256", ""))
            source_relative = str(source.get("path", ""))
            if (
                not source_relative.startswith(allowed_roots)
                or "/archive/" in f"/{source_relative.casefold()}/"
            ):
                drift = True
                continue
            try:
                path = _resolve_vault_file(source_relative)
            except LearningToolError:
                drift = True
                continue
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                drift = True
        review_state = str(notebook.get("review_state", "stale"))
        materials.append({
            "notebook_id": notebook.get("notebook_id"),
            "title": notebook.get("title"),
            "notebook_url": notebook.get("notebook_url"),
            "review_state": review_state,
            "usable_as_current": review_state != "stale" and not drift,
            "existing_registry_artifacts": [
                {
                    "type": artifact.get("type"),
                    "title": artifact.get("title"),
                    "status": artifact.get("status"),
                }
                for artifact in notebook.get("artifacts", [])
                if isinstance(artifact, dict)
            ],
        })
    return materials


def learning_event_path(client: str) -> str:
    return f"00-system/learning/events/{client}.jsonl"


def learning_get_today(
    target_date: str | None = None,
    surface: str = "knowledge",
    all_items: bool = False,
) -> str:
    command = ["today", "--surface", surface]
    if target_date:
        command.extend(["--date", target_date])
    if all_items:
        command.append("--all-items")
    try:
        payload = _run_learning(command)
    except LearningToolError as exc:
        return dumps({"status": "error", "error": str(exc), "write_executed": False})
    for group in ("due", "new", "triage"):
        for row in payload.get(group, []):
            if not isinstance(row, dict):
                continue
            relative = _note_path(str(row.get("obsidian_uri", "")))
            row["obsidian_path"] = relative
            row["notebook_materials"] = _notebook_materials(relative)
    payload.setdefault("status", "pass")
    payload["study_contract"] = {
        "order": "due-first-then-owner-enrolled-new",
        "recall_before_reveal": True,
        "saved_is_not_learned": True,
        "notebook_artifacts_are_derived": True,
    }
    payload["notebooklm_capabilities"] = dict(_NOTEBOOKLM_CAPABILITIES)
    return dumps(payload)


def learning_set_intent(
    uid: str,
    intent: str,
    reason: str,
    attempt_id: str,
    client: str = "chatgpt",
) -> str:
    try:
        payload = _run_learning([
            "intent", "--uid", uid, "--intent", intent, "--reason", reason,
            "--device", client,
            "--event-id", _event_id("intent", attempt_id, uid, client),
            "--apply",
        ])
    except LearningToolError as exc:
        return dumps({"status": "error", "error": str(exc), "write_executed": False})
    payload["learning_claim"] = "intent-only; engagement and mastery unchanged"
    return dumps(payload)


def learning_record_review(
    uid: str,
    rating: str,
    recall_attempted: bool,
    recall_text: str,
    attempt_id: str,
    elapsed_ms: int = 0,
    mastery: str | None = None,
    client: str = "chatgpt",
) -> str:
    if recall_attempted is not True:
        return dumps({
            "status": "error",
            "error": "recall_attempted=true is required before recording a review",
            "write_executed": False,
        })
    command = [
        "review", "--uid", uid, "--rating", rating, "--recall", recall_text,
        "--elapsed-ms", str(elapsed_ms), "--device", client,
        "--event-id", _event_id("review", attempt_id, uid, client),
        "--all-items", "--apply",
    ]
    if mastery:
        command.extend(["--mastery", mastery])
    try:
        payload = _run_learning(command)
    except LearningToolError as exc:
        return dumps({"status": "error", "error": str(exc), "write_executed": False})
    payload["learning_claim"] = (
        "real recall event; mastery changes only when explicitly supplied and valid"
    )
    return dumps(payload)


def learning_get_history(uid: str, target_date: str | None = None) -> str:
    command = ["history", "--uid", uid]
    if target_date:
        command.extend(["--date", target_date])
    try:
        payload = _run_learning(command)
        catalog = _run_learning(["query", "--uid", uid, "--limit", "1"])
    except LearningToolError as exc:
        return dumps({"status": "error", "error": str(exc), "write_executed": False})
    row = catalog.get("rows", [{}])[0] if catalog.get("rows") else {}
    relative = _note_path(str(row.get("obsidian_uri", "")))
    payload["obsidian_path"] = relative
    payload["obsidian_uri"] = row.get("obsidian_uri", "")
    payload["notebook_materials"] = _notebook_materials(relative)
    payload["notebooklm_capabilities"] = dict(_NOTEBOOKLM_CAPABILITIES)
    payload.setdefault("status", "pass")
    return dumps(payload)
