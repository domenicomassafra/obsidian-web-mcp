#!/usr/bin/env python3
"""
Route Hermes/Poke/agent captures to the correct Life OS owner.

Default mode is dry-run. In --apply mode this tool only writes to approved
local staging surfaces:

- Obsidian capture notes under 01-input/capture/
- Notion write queue under 02-workbench/analysis/agent-inbox/
- Calendar write queue under 02-workbench/analysis/agent-inbox/

It does not call Notion, Google Calendar or external MCP servers.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


SERVICE_DIR = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("LIFE_OS_VAULT_ROOT", Path.home() / "Obsidian")).expanduser().resolve()
IMPORTS = ROOT / "02-workbench" / "imports"
AGENT_INBOX = ROOT / "02-workbench" / "analysis" / "agent-inbox"
CAPTURE_DIR = ROOT / "01-input" / "capture"
MCP_SPEC = Path(
    os.environ.get("LIFE_OS_MCP_SPEC", SERVICE_DIR / "life-os-mcp-gateway-tool-spec.json")
).expanduser()

NOTION_QUEUE = AGENT_INBOX / "notion-write-queue.jsonl"
CALENDAR_QUEUE = AGENT_INBOX / "calendar-write-queue.jsonl"
AUDIT_LOG = AGENT_INBOX / "life-os-router-audit.jsonl"


KEYWORDS: dict[str, tuple[str, ...]] = {
    "event": (
        "appuntamento",
        "evento",
        "calendar",
        "calendario",
        "meeting",
        "call",
        "riunione",
        "prenota",
        "alle ",
        "domani alle",
    ),
    "content": (
        "tiktok",
        "instagram",
        "reel",
        "video",
        "post",
        "contenuto",
        "script",
        "divulgazione",
        "creator spagnolo",
        "aiconic",
    ),
    "finance": (
        "fattura",
        "pagare",
        "abbonamento",
        "budget",
        "soldi",
        "spesa",
        "euro",
        "eur",
        "iva",
        "tasse",
    ),
    "people": (
        "cliente",
        "lead",
        "contatto",
        "partner",
        "fornitore",
        "persona",
        "follow up",
    ),
    "daily_metric": (
        "ore lavorate",
        "ho lavorato",
        "work hours",
        "output",
        "energia",
        "salute",
        "disciplina",
        "allenamento",
        "peso",
    ),
    "task": (
        "devo ",
        "todo",
        "task",
        "review ",
        "choose ",
        "ricordami",
        "da fare",
        "fare ",
        "chiama",
        "scrivi",
        "compra",
        "sistema",
        "fix",
    ),
    "knowledge": (
        "nota",
        "idea",
        "ricerca",
        "studio",
        "sop",
        "decisione",
        "decision:",
        "decision ",
        "journal",
        "riflessione",
        "memoria",
        "knowledge",
    ),
}


ROUTES: dict[str, dict[str, str]] = {
    "task": {"system": "notion", "database": "Action Items", "tool": "create_action_item"},
    "event": {"system": "google-calendar", "database": "Google Calendar", "tool": "calendar_queue"},
    "content": {"system": "notion", "database": "Capture Inbox", "tool": "queue_capture_triage"},
    "finance": {"system": "notion", "database": "Capture Inbox", "tool": "queue_capture_triage"},
    "people": {"system": "notion", "database": "Capture Inbox", "tool": "queue_capture_triage"},
    "daily_metric": {"system": "notion", "database": "Daily Log", "tool": "append_daily_log"},
    "knowledge": {"system": "obsidian", "path": "01-input/capture/", "tool": "capture_note"},
    "ambiguous": {"system": "queue", "database": "pending-classification", "tool": "manual_classification"},
}

AREA_ALIASES: dict[str, tuple[str, ...]] = {
    "TND": ("tnd", "the noir division"),
    "AIconic Agency": ("aiconic", "aiconic agency"),
    "Divulgazione AI / marketing": (
        "divulgazione",
        "divulgazione ai",
        "divulgazione ai marketing",
        "marketing italiano",
    ),
    "Creator spagnolo": ("creator spagnolo", "creator spagnola", "spagnolo", "spagnola"),
}

CONTENT_LANES_BY_AREA = {
    "AIconic Agency": "AIconic",
    "Divulgazione AI / marketing": "Divulgazione",
    "Creator spagnolo": "Creator spagnolo",
}


@dataclass
class RouteResult:
    kind: str
    confidence: float
    system: str
    target: str
    tool: str
    text_hash: str
    payload: dict[str, Any]
    writes: list[str]
    reason: str


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def load_spec() -> dict[str, Any]:
    return json.loads(MCP_SPEC.read_text(encoding="utf-8"))


def slugify(value: str, max_length: int = 64) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value.lower()).strip("-")
    return (slug or "capture")[:max_length].strip("-") or "capture"


def score_text(text: str) -> dict[str, int]:
    lowered = f" {text.lower()} "
    scores: dict[str, int] = {}
    for kind, words in KEYWORDS.items():
        scores[kind] = sum(1 for word in words if word in lowered)
    return scores


def normalized_label(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().casefold())


def contains_alias(text: str, alias: str) -> bool:
    return re.search(rf"(?<!\w){re.escape(alias)}(?!\w)", text) is not None


def canonical_area_name(value: str | None) -> str | None:
    if not value:
        return None
    normalized = normalized_label(value)
    for canonical, aliases in AREA_ALIASES.items():
        if normalized == normalized_label(canonical) or normalized in aliases:
            return canonical
    return None


def choose_kind(text: str, forced_kind: str) -> tuple[str, float, str]:
    if forced_kind != "auto":
        return forced_kind, 1.0, "forced by caller"

    scores = score_text(text)
    ranked = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    best_kind, best_score = ranked[0]
    second_score = ranked[1][1] if len(ranked) > 1 else 0

    if best_score <= 0:
        return "ambiguous", 0.2, "no strong routing keyword found"
    if best_score == second_score and second_score > 0:
        return "ambiguous", 0.45, f"tie between likely routes: {scores}"
    confidence = min(0.95, 0.55 + (best_score * 0.12))
    return best_kind, confidence, f"keyword score: {scores}"


def infer_area(text: str, explicit: str | None) -> str | None:
    if explicit:
        return canonical_area_name(explicit) or explicit
    lowered = normalized_label(text)
    for canonical, aliases in AREA_ALIASES.items():
        if any(contains_alias(lowered, alias) for alias in aliases):
            return canonical
    return None


def infer_content_lane(area: str | None) -> str | None:
    return CONTENT_LANES_BY_AREA.get(area or "")


def build_payload(kind: str, text: str, source: str, project: str | None, area: str | None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "title": text[:160],
        "text": text,
        "source": source,
        "created": now_iso(),
    }
    if project:
        payload["project"] = project
    if area:
        payload["area"] = area
    if kind == "content":
        lane = infer_content_lane(area)
        if lane:
            payload["lane"] = lane
    if kind == "daily_metric":
        payload.setdefault("kind", "narrative" if len(text) > 180 else "work_hours")
    return payload


def validate_writes(writes: list[str], spec: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    guards = spec.get("guards", {})
    allowed_notion = set(guards.get("notion_write_allowed_databases", []))
    allowed_obsidian = tuple(guards.get("obsidian_write_allowed_paths", []))
    blocked_obsidian = tuple(guards.get("obsidian_write_blocked_paths", []))

    for write in writes:
        if write.startswith("Notion:"):
            database = write.removeprefix("Notion:")
            if database not in allowed_notion:
                errors.append(f"Notion write target is not allowed in v1: {database}")
        elif write.startswith("Obsidian:"):
            path = write.removeprefix("Obsidian:")
            if not path.startswith(allowed_obsidian):
                errors.append(f"Obsidian write target is not allowed in v1: {path}")
            if path.startswith(blocked_obsidian):
                errors.append(f"Obsidian write target is blocked in v1: {path}")
        elif write.startswith("GoogleCalendar:"):
            continue
        elif write.startswith("Queue:"):
            continue
        else:
            errors.append(f"Unknown write target: {write}")
    return errors


def route_capture(text: str, source: str, forced_kind: str, project: str | None, area: str | None) -> RouteResult:
    kind, confidence, reason = choose_kind(text, forced_kind)
    route = ROUTES[kind]
    normalized_project = project
    normalized_area = canonical_area_name(area) or area
    if normalized_project and not normalized_area:
        project_as_area = canonical_area_name(normalized_project)
        if project_as_area:
            normalized_area = project_as_area
            normalized_project = None
    inferred_area = infer_area(text, normalized_area)
    payload = build_payload(kind, text, source, normalized_project, inferred_area)
    text_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]

    if route["system"] == "notion":
        target = route["database"]
        writes = [f"Notion:{target}"]
    elif route["system"] == "google-calendar":
        target = route["database"]
        writes = ["GoogleCalendar:events"]
    elif route["system"] == "obsidian":
        target = route["path"]
        writes = [f"Obsidian:{target}"]
    else:
        target = route["database"]
        writes = ["Queue:pending-classification"]

    return RouteResult(
        kind=kind,
        confidence=confidence,
        system=route["system"],
        target=target,
        tool=route["tool"],
        text_hash=text_hash,
        payload=payload,
        writes=writes,
        reason=reason,
    )


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=True) + "\n")


def write_capture_note(result: RouteResult, source: str) -> Path:
    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    title = slugify(result.payload["title"])
    path = CAPTURE_DIR / f"{stamp}-{title}.md"
    body = [
        "---",
        "type: capture",
        "status: inbox",
        f"source: {json.dumps(source)}",
        f"route_kind: {result.kind}",
        f"route_confidence: {result.confidence}",
        f"created: {result.payload['created']}",
        f"text_hash: {result.text_hash}",
        "---",
        "",
        "# Capture",
        "",
        result.payload["text"].strip(),
        "",
    ]
    path.write_text("\n".join(body), encoding="utf-8")
    return path


def apply_route(result: RouteResult, source: str) -> dict[str, Any]:
    record = {
        "created": now_iso(),
        "kind": result.kind,
        "confidence": result.confidence,
        "system": result.system,
        "target": result.target,
        "tool": result.tool,
        "text_hash": result.text_hash,
        "payload": result.payload,
        "writes": result.writes,
        "reason": result.reason,
    }

    materialized: dict[str, Any] = {}
    if result.system == "obsidian":
        path = write_capture_note(result, source)
        materialized["capture_path"] = str(path)
    elif result.system == "notion":
        append_jsonl(NOTION_QUEUE, record)
        materialized["queue_path"] = str(NOTION_QUEUE)
    elif result.system == "google-calendar":
        append_jsonl(CALENDAR_QUEUE, record)
        materialized["queue_path"] = str(CALENDAR_QUEUE)
    else:
        append_jsonl(NOTION_QUEUE, record)
        materialized["queue_path"] = str(NOTION_QUEUE)

    append_jsonl(AUDIT_LOG, record | {"materialized": materialized})
    return materialized


def as_dict(result: RouteResult) -> dict[str, Any]:
    return {
        "kind": result.kind,
        "confidence": result.confidence,
        "system": result.system,
        "target": result.target,
        "tool": result.tool,
        "text_hash": result.text_hash,
        "payload": result.payload,
        "writes": result.writes,
        "reason": result.reason,
    }


def run_self_test() -> int:
    cases = [
        ("Devo scrivere la landing TND domani", "task", "notion", "Action Items"),
        ("Review TND priorities and choose the next cashflow action", "task", "notion", "Action Items"),
        ("Decision: keep TND Fanvue-first", "knowledge", "obsidian", "01-input/capture/"),
        ("Idea video TikTok per divulgazione su nuovi tool AI", "content", "notion", "Capture Inbox"),
        ("Nota: questa SOP va trasformata in knowledge base", "knowledge", "obsidian", "01-input/capture/"),
        ("Pagare abbonamento software 29 euro", "finance", "notion", "Capture Inbox"),
        ("Meeting con cliente alle 15 domani", "event", "google-calendar", "Google Calendar"),
    ]
    failures: list[str] = []
    for text, expected_kind, expected_system, expected_target in cases:
        result = route_capture(text, "self-test", "auto", None, None)
        if (result.kind, result.system, result.target) != (expected_kind, expected_system, expected_target):
            failures.append(
                f"{text!r}: got {(result.kind, result.system, result.target)}, "
                f"expected {(expected_kind, expected_system, expected_target)}"
            )
    area_result = route_capture("Review TND priorities", "self-test", "auto", None, None)
    if area_result.payload.get("area") != "TND" or "project" in area_result.payload:
        failures.append(f"known evergreen Area was not routed as area-only: {area_result.payload}")
    explicit_area_result = route_capture(
        "Decision: keep the operating focus",
        "self-test",
        "knowledge",
        "TND",
        None,
    )
    if explicit_area_result.payload.get("area") != "TND" or "project" in explicit_area_result.payload:
        failures.append(f"Area passed through project compatibility field was not normalized: {explicit_area_result.payload}")
    finite_project_result = route_capture(
        "Review the roster validation sprint",
        "self-test",
        "task",
        "TND roster validation sprint",
        "TND",
    )
    if finite_project_result.payload.get("project") != "TND roster validation sprint":
        failures.append(f"explicit finite project was lost: {finite_project_result.payload}")
    generic_creator_result = route_capture("Review creator strategy", "self-test", "auto", None, None)
    if generic_creator_result.payload.get("area") == "Creator spagnolo":
        failures.append(f"generic creator wording caused a false Area match: {generic_creator_result.payload}")
    generic_content_result = route_capture("Idea video about creator economy tools", "self-test", "auto", None, None)
    if generic_content_result.payload.get("lane") == "Creator spagnolo":
        failures.append(f"generic creator content caused a false lane match: {generic_content_result.payload}")
    print(json.dumps({"status": "pass" if not failures else "fail", "failures": failures}, indent=2))
    return 0 if not failures else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Route a Life OS capture without broad live writes.")
    parser.add_argument("--text", help="Capture text to route.")
    parser.add_argument("--source", default="manual", help="Source label, e.g. poke, telegram, hermes, codex.")
    parser.add_argument("--kind", default="auto", choices=sorted(set(ROUTES) | {"auto"}), help="Force a route kind or use auto.")
    parser.add_argument("--project", help="Optional project name override.")
    parser.add_argument("--area", help="Optional area name override.")
    parser.add_argument("--apply", action="store_true", help="Materialize to local capture/queue only.")
    parser.add_argument("--self-test", action="store_true", help="Run router self-tests.")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()
    if not args.text:
        parser.error("--text is required unless --self-test is used")

    spec = load_spec()
    result = route_capture(args.text, args.source, args.kind, args.project, args.area)
    errors = validate_writes(result.writes, spec)
    output = as_dict(result)
    output["status"] = "blocked" if errors else "dry-run"
    output["write_validation_errors"] = errors

    if errors:
        print(json.dumps(output, indent=2))
        return 2

    if args.apply:
        output["status"] = "applied-local"
        output["materialized"] = apply_route(result, args.source)

    print(json.dumps(output, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
