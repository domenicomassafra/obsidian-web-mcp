"""Deterministic, policy-bound context selection for the Obsidian MCP front door.

This module intentionally uses lexical routing and filesystem truth.  It does not
embed, diagnose, or materialize writes.  Public results contain paths, hashes and
bounded excerpts; bootstrap policy bodies stay server-side.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date as Date, datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import frontmatter

from . import config
from .vault import (
    archive_policy_receipt,
    is_archive_path,
    is_discoverable_vault_path,
    is_hidden_read_allowed,
    read_file,
)


ROME = ZoneInfo("Europe/Rome")
BOOTSTRAP_PATHS = (
    "AGENTS.md",
    "00-system/guides/00-vault-operating-model.md",
)
FAMILY_PATHS = (
    "06-life/index.md",
    "06-life/profile.md",
    "06-life/preferences.md",
    "06-life/health.md",
    "06-life/people/index.md",
    "04-areas/family-relations.md",
    "04-areas/persone-chiave.md",
    "01-input/capture/ai-memory/2026-07-09-chatgpt-mega-context.md",
)
SAFETY_TERMS = (
    "suicidio",
    "suicida",
    "farsi del male",
    "uccidersi",
    "pericolo immediato",
    "rischio immediato",
)
MENTAL_HEALTH_TERMS = (
    "depressione",
    "salute mentale",
    "psicolog",
    "psichiatr",
    "terapia",
)
FAMILY_TERMS = (
    "famiglia",
    "familiare",
    "sorella",
    "fratello",
    "genitore",
    "madre",
    "padre",
    "relazione",
)

_bootstrap_cache_key: tuple | None = None
_bootstrap_cache_value: dict[str, Any] | None = None


def clear_bootstrap_cache() -> None:
    global _bootstrap_cache_key, _bootstrap_cache_value
    _bootstrap_cache_key = None
    _bootstrap_cache_value = None


def _bootstrap_signature() -> tuple:
    signature = []
    for rel in BOOTSTRAP_PATHS:
        path = config.VAULT_PATH / rel
        try:
            stat = path.stat()
            signature.append((rel, stat.st_mtime_ns, stat.st_size))
        except OSError:
            signature.append((rel, None, None))
    return tuple(signature)


def _load_bootstrap() -> tuple[dict[str, Any], bool]:
    global _bootstrap_cache_key, _bootstrap_cache_value
    signature = _bootstrap_signature()
    if signature == _bootstrap_cache_key and _bootstrap_cache_value is not None:
        return _bootstrap_cache_value, True

    files = []
    missing = []
    policy_material = []
    for rel in BOOTSTRAP_PATHS:
        try:
            content, metadata = read_file(rel)
        except FileNotFoundError:
            missing.append(rel)
            files.append({"path": rel, "status": "missing"})
            policy_material.append(f"{rel}:missing")
            continue
        files.append({
            "path": rel,
            "status": "ready",
            "sha256": metadata["sha256"],
            "size": metadata["size"],
            "modified": metadata["modified"],
            "content": content,
        })
        policy_material.append(f"{rel}:{metadata['sha256']}")

    policy_hash = hashlib.sha256("\n".join(policy_material).encode("utf-8")).hexdigest()
    value = {
        "status": "ready" if not missing else "degraded",
        "policy_hash": policy_hash,
        "files": files,
        "missing": missing,
    }
    _bootstrap_cache_key = signature
    _bootstrap_cache_value = value
    return value, False


def bootstrap_status() -> dict[str, Any]:
    """Return a body-free status receipt for the server-applied bootstrap policy."""
    data, cached = _load_bootstrap()
    return {
        "status": data["status"],
        "policy_hash": data["policy_hash"],
        "files": [{k: v for k, v in item.items() if k != "content"} for item in data["files"]],
        "missing": list(data["missing"]),
        "cached": cached,
    }


def _parse_date(value: str | None, label: str) -> Date | None:
    if not value:
        return None
    try:
        return Date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{label} must use ISO format YYYY-MM-DD") from exc


def _date_range(
    request: str,
    reference_date: str | None,
    start_date: str | None,
    end_date: str | None,
) -> dict[str, str]:
    today = _parse_date(reference_date, "reference_date") or datetime.now(ROME).date()
    start = _parse_date(start_date, "start_date")
    end = _parse_date(end_date, "end_date")
    lowered = request.casefold()
    if start is None:
        start = today + timedelta(days=1) if any(x in lowered for x in ("domani", "tomorrow")) else today
    if end is None:
        end = start + timedelta(days=6) if any(x in lowered for x in ("questa settimana", "this week")) else start
    if end < start:
        raise ValueError("end_date must not be before start_date")
    if (end - start).days > 31:
        raise ValueError("context date range exceeds the declared 31-day limit")
    return {"start": start.isoformat(), "end": end.isoformat()}


def _classify(request: str) -> tuple[str, list[str], str | None]:
    lowered = request.casefold()
    if any(term in lowered for term in SAFETY_TERMS):
        return "safety_handoff", ["mental_health_sensitive", "immediate_safety"], "mental_health_sensitive"
    if any(term in lowered for term in FAMILY_TERMS):
        risk = "mental_health_sensitive" if any(term in lowered for term in MENTAL_HEALTH_TERMS) else "personal_sensitive"
        secondary = ["family_relationship_change", "personal_support_plan"]
        if risk == "mental_health_sensitive":
            secondary.append("mental_health_sensitive")
        return "personal_family_mental_health_change", secondary, risk
    if any(term in lowered for term in ("salute", "stanco", "sonno", "ginocchio", "energia")):
        return "personal_health_recent_state", ["recent_daily_context"], "health_sensitive"
    if any(term in lowered for term in ("tnd", "aiconic", "creator spagnolo", "business", "azienda")):
        return "business_or_project_context", ["project_canon"], None
    return "general_life_context", ["general_recall"], None


def _paths_for_intent(intent: str, request: str, dates: dict[str, str]) -> list[dict[str, str]]:
    if intent == "personal_family_mental_health_change":
        paths = [
            {
                "path": path,
                "requirement": "required",
                "mode": "sections" if "mega-context" in path else "metadata",
                "reason": "family-sensitive deterministic route",
            }
            for path in FAMILY_PATHS
        ]
        lowered = request.casefold()
        for terms, path, reason in (
            (("abitudine", "routine"), "06-life/habits.md", "habit change requested"),
            (("allenamento", "fitness", "sport"), "06-life/fitness.md", "fitness context requested"),
            (("soldi", "budget", "spesa"), "06-life/money.md", "money context requested"),
            (("input", "cattura", "capture"), "01-input/index.md", "input gate requested"),
        ):
            if any(term in lowered for term in terms):
                paths.append({
                    "path": path,
                    "requirement": "conditional",
                    "mode": "sections",
                    "reason": reason,
                })
        return paths
    if intent == "personal_health_recent_state":
        return [
            {"path": "06-life/index.md", "requirement": "required", "mode": "metadata", "reason": "life canon"},
            {"path": "06-life/health.md", "requirement": "required", "mode": "sections", "reason": "health canon"},
        ]
    if intent == "business_or_project_context":
        lowered = request.casefold()
        slug = "tnd" if "tnd" in lowered else "aiconic" if "aiconic" in lowered else ""
        paths = [{"path": "04-areas/index.md", "requirement": "required", "mode": "metadata", "reason": "area index"}]
        if slug:
            paths.append({"path": f"04-areas/{slug}/index.md", "requirement": "conditional", "mode": "sections", "reason": "named area"})
        return paths
    if intent == "safety_handoff":
        return []
    return [
        {"path": "06-life/index.md", "requirement": "required", "mode": "metadata", "reason": "life canon"},
        {"path": "06-life/profile.md", "requirement": "conditional", "mode": "metadata", "reason": "personal context"},
    ]


def _wikilinks(content: str) -> list[str]:
    values = []
    for raw in re.findall(r"\[\[([^\]]+)\]\]", content):
        target = raw.split("|", 1)[0].split("#", 1)[0].strip()
        if target and "://" not in target:
            values.append(target if target.lower().endswith(".md") else f"{target}.md")
    return values[:50]


def _link_candidates(target: str) -> list[str]:
    direct = config.VAULT_PATH / target
    candidates = []
    if is_discoverable_vault_path(direct, allow_hidden_read=True) and direct.is_file():
        candidates.append(target)
    if "/" not in target:
        for path in config.VAULT_PATH.rglob(target):
            if not is_discoverable_vault_path(path, allow_hidden_read=True):
                continue
            try:
                rel = str(path.relative_to(config.VAULT_PATH))
            except ValueError:
                continue
            if any(part in config.EXCLUDED_DIRS for part in Path(rel).parts):
                continue
            if any(part.startswith(".") for part in Path(rel).parts) and not is_hidden_read_allowed(rel):
                continue
            candidates.append(rel)
            if len(candidates) >= 20:
                break
    return sorted(set(candidates))


def _check_links(selected_paths: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
    checks = []
    missing = []
    seen = set()
    for source in selected_paths:
        try:
            content, _ = read_file(source)
        except (FileNotFoundError, ValueError):
            continue
        for target in _wikilinks(content):
            key = (source, target)
            if key in seen:
                continue
            seen.add(key)
            candidates = _link_candidates(target)
            canonical = [path for path in candidates if not is_archive_path(path)]
            archived = [path for path in candidates if is_archive_path(path)]
            if canonical:
                status = "canonical"
            elif archived:
                status = "archive_only"
            else:
                status = "broken"
                missing.append(target)
            checks.append({
                "source": source,
                "target": target,
                "status": status,
                "canonical_candidates": canonical,
                "archive_candidates": archived,
                "followed": status == "canonical",
            })
    return checks, missing


def _duplicate_uids(paths: list[str], index) -> list[dict[str, Any]]:
    duplicates = []
    seen_uids = set()
    for path in paths:
        try:
            content, _ = read_file(path)
            uid = frontmatter.loads(content).metadata.get("uid")
        except Exception:
            continue
        if not uid or str(uid) in seen_uids:
            continue
        seen_uids.add(str(uid))
        matches = index.search_by_field("uid", str(uid), "exact", include_archives=True)
        if len(matches) > 1:
            candidates = sorted(item["path"] for item in matches)
            canonical = [candidate for candidate in candidates if not is_archive_path(candidate)]
            duplicates.append({
                "uid": str(uid),
                "selected": path if path in canonical else (canonical[0] if canonical else None),
                "candidates": candidates,
                "archive_skipped": [candidate for candidate in candidates if is_archive_path(candidate)],
            })
    return duplicates


def route_context(
    request: str,
    index,
    *,
    reference_date: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    include_archives: bool = False,
) -> dict[str, Any]:
    """Classify a request and return a deterministic, auditable path receipt."""
    if not request.strip():
        raise ValueError("request must not be empty")
    bootstrap = bootstrap_status()
    intent, secondary, risk = _classify(request)
    dates = _date_range(request, reference_date, start_date, end_date)
    requested = _paths_for_intent(intent, request, dates)
    selected = []
    missing = []
    skipped = []
    for item in requested:
        path = item["path"]
        if is_archive_path(path) and not include_archives:
            skipped.append({"path": path, "reason": "archive_excluded"})
            continue
        if not (config.VAULT_PATH / path).is_file():
            missing.append(path)
            continue
        selected.append(item)
    selected_paths = [item["path"] for item in selected]
    link_checks, broken = _check_links(selected_paths)
    missing = list(dict.fromkeys([*missing, *broken]))
    duplicates = _duplicate_uids(selected_paths, index)
    for duplicate in duplicates:
        skipped.extend(
            {"path": path, "reason": "archive_duplicate"}
            for path in duplicate["archive_skipped"]
        )
    archive_policy = archive_policy_receipt(include_archives)
    return {
        "receipt": {
            "intent": intent,
            "secondary_intents": secondary,
            "risk_domain": risk,
            "timezone": "Europe/Rome",
            "date_range": dates,
            "write_mode": "proposal_only" if risk else "read_only",
            "required": [item["path"] for item in requested if item["requirement"] == "required"],
            "selected": selected,
            "selected_paths": selected_paths,
            "missing": missing,
            "skipped": skipped,
            "duplicates": duplicates,
            "archive_decisions": archive_policy,
            "link_checks": link_checks,
            "policy_status": bootstrap["status"],
            "policy_hash": bootstrap["policy_hash"],
            "index_hash": index.snapshot_hash(),
            "safety_handoff": intent == "safety_handoff",
        }
    }


def _keywords(request: str) -> list[str]:
    return [word for word in re.findall(r"[\wàèéìòù]+", request.casefold()) if len(word) >= 5][:20]


def _snippet(content: str, request: str, limit: int) -> str:
    words = _keywords(request)
    lines = content.splitlines()
    chosen = []
    for index, line in enumerate(lines):
        if any(word in line.casefold() for word in words):
            chosen.extend(lines[max(0, index - 1): min(len(lines), index + 2)])
        if len("\n".join(chosen)) >= limit:
            break
    return ("\n".join(dict.fromkeys(chosen)) or content[:limit])[:limit]


def _sections(content: str, request: str, limit: int) -> str:
    parts = re.split(r"(?m)(?=^#{1,6}\s+)", content)
    words = _keywords(request)
    chosen = [part for part in parts if any(word in part.casefold() for word in words)]
    fallback = next((part for part in parts if part.strip()), content)
    return ("".join(chosen) or fallback)[:limit]


def read_context(
    request: str,
    index,
    *,
    mode: str = "sections",
    max_files: int = 12,
    max_chars_per_file: int = 8000,
    total_chars: int = 40000,
    reference_date: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    include_archives: bool = False,
) -> dict[str, Any]:
    route = route_context(
        request,
        index,
        reference_date=reference_date,
        start_date=start_date,
        end_date=end_date,
        include_archives=include_archives,
    )
    receipt = route["receipt"]
    if receipt["safety_handoff"]:
        receipt.update({"read_mode": mode, "chars_returned": 0, "files_returned": 0})
        return {"files": [], "receipt": receipt, "safety": _safety_receipt()}
    files = []
    chars = 0
    for selection in receipt["selected"][:max_files]:
        path = selection["path"]
        try:
            content, metadata = read_file(path)
        except (FileNotFoundError, ValueError):
            if path not in receipt["missing"]:
                receipt["missing"].append(path)
            continue
        remaining = total_chars - chars
        if remaining <= 0:
            break
        limit = min(max_chars_per_file, remaining)
        body = ""
        if mode == "full":
            body = content[:limit]
        elif mode == "sections":
            body = _sections(content, request, limit)
        elif mode == "snippets":
            body = _snippet(content, request, limit)
        item = {
            "path": path,
            "metadata": metadata,
            "mode": mode,
            "chars_returned": len(body),
            "truncated": bool(body) and len(body) < len(content),
        }
        if mode != "metadata":
            item["content"] = body
        files.append(item)
        chars += len(body)
    receipt.update({
        "read_mode": mode,
        "declared_budgets": {
            "max_files": max_files,
            "max_chars_per_file": max_chars_per_file,
            "total_chars": total_chars,
        },
        "files_returned": len(files),
        "chars_returned": chars,
    })
    return {"files": files, "receipt": receipt}


def _safety_receipt() -> dict[str, Any]:
    return {
        "handoff": True,
        "reason": "immediate_safety_language",
        "guidance": "Prioritize immediate human help and local emergency services (112 in Italy).",
        "diagnosis_performed": False,
    }


def propose_context(
    request: str,
    index,
    *,
    reference_date: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
) -> dict[str, Any]:
    route = route_context(
        request,
        index,
        reference_date=reference_date,
        start_date=start_date,
        end_date=end_date,
        include_archives=False,
    )
    receipt = route["receipt"]
    if receipt["safety_handoff"]:
        return {
            "write_mode": "proposal_only",
            "write_executed": False,
            "proposals": [],
            "external_actions": {"notion": False, "calendar": False},
            "safety": _safety_receipt(),
            "receipt": receipt,
        }
    proposals = []
    if receipt["intent"] == "personal_family_mental_health_change":
        person_path = (
            "06-life/people/sorella.md"
            if "sorella" in request.casefold()
            else "06-life/people/persona-familiare.md"
        )
        proposals = [
            {"operation": "create_if_missing", "path": person_path, "scope": "relationship facts and support preferences only"},
            {"operation": "targeted_update", "path": "06-life/people/index.md", "scope": "canonical people index link"},
            {"operation": "targeted_update", "path": "04-areas/family-relations.md", "scope": "family hub canonical link"},
        ]
    return {
        "write_mode": "proposal_only",
        "write_executed": False,
        "proposals": proposals,
        "external_actions": {"notion": False, "calendar": False},
        "safety": {"handoff": False, "diagnosis_performed": False},
        "receipt": receipt,
        "apply_contract": {
            "separate_step_required": True,
            "tools": ["vault_write", "vault_edit"],
            "requires_fresh_sha256_for_existing_files": True,
        },
    }
