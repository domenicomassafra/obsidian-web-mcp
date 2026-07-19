#!/usr/bin/env python3
"""
Minimal HTTP MCP gateway for the local Life OS.

This server is intentionally narrow. It exposes the tools declared in
02-workbench/imports/life-os-mcp-gateway-tool-spec.json and routes write-like
requests through life_os_router.py, which only writes to approved local capture
and queue surfaces.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import re
import subprocess
import sys
from datetime import date, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote
from urllib.request import Request, urlopen


SERVICE_DIR = Path(__file__).resolve().parent


def env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


ROOT = Path(os.environ.get("LIFE_OS_VAULT_ROOT", Path.home() / "Obsidian")).expanduser().resolve()
TOOLS = ROOT / "00-system" / "tools"
IMPORTS = ROOT / "02-workbench" / "imports"
AGENT_INBOX = ROOT / "02-workbench" / "analysis" / "agent-inbox"
CAPTURE_DIR = ROOT / "01-input" / "capture"
PROJECTS_DIR = ROOT / "03-projects"
AREAS_DIR = ROOT / "04-areas"
KNOWLEDGE_DIR = ROOT / "05-knowledge"
SOURCES_DIR = ROOT / "01-input" / "sources"
WORKBENCH_DIR = ROOT / "02-workbench" / "analysis"
COMPILED_WIKIS_DIR = ROOT / "02-workbench" / "compiled-wikis"

MCP_SPEC = Path(
    os.environ.get("LIFE_OS_MCP_SPEC", SERVICE_DIR / "life-os-mcp-gateway-tool-spec.json")
).expanduser()
ROUTER = Path(os.environ.get("LIFE_OS_ROUTER", SERVICE_DIR / "life_os_router.py")).expanduser()
GATEWAY_AUDIT = AGENT_INBOX / "life-os-mcp-gateway-audit.jsonl"
ROUTER_AUDIT = AGENT_INBOX / "life-os-router-audit.jsonl"
NOTION_QUEUE = AGENT_INBOX / "notion-write-queue.jsonl"
CALENDAR_QUEUE = AGENT_INBOX / "calendar-write-queue.jsonl"
HERMES_RUNS = AGENT_INBOX / "hermes-mcp-runs.jsonl"

SERVER_NAME = "life-os-mcp-gateway"
SERVER_VERSION = "0.3.3"
SUPPORTED_PROTOCOLS = {"2025-06-18", "2025-03-26", "2024-11-05"}
DEFAULT_PROTOCOL = "2025-06-18"

SERVER_INSTRUCTIONS = (
    "Use this Life OS integration for personal operating-system actions and "
    "recall. Notion owns operational records, Obsidian owns canonical memory, "
    "and Google Calendar owns hard events. Prefer read tools first. For writes, "
    "use one narrow tool call at a time. Never request deletes, bulk rewrites, "
    "or direct edits to stable knowledge notes."
)

TEXT_EXTENSIONS = {".md", ".txt", ".csv", ".json", ".jsonl", ".base"}
MAX_FILE_BYTES = 512_000
MAX_SCAN_FILES = 2500
MAX_READ_CHARS = 20_000
OBSIDIAN_VAULT_NAME = os.environ.get("LIFE_OS_OBSIDIAN_VAULT", "Obsidian")
HERMES_HOME = Path(os.environ.get("HERMES_HOME", r"C:\Users\domen\AppData\Local\hermes"))
HERMES_EXE = Path(
    os.environ.get(
        "LIFE_OS_HERMES_EXE",
        r"C:\Users\domen\AppData\Local\hermes\hermes-agent\venv\Scripts\hermes.exe",
    )
)
HERMES_ALLOWED_PROFILES = {"poke", "planner", "research"}
HERMES_TARGETS = {
    "telegram_home": "telegram",
    "discord_hermes": "discord:#hermes",
}
CONTENT_AREA_BY_LANE = {
    "Divulgazione": "Divulgazione AI / marketing",
    "Creator spagnolo": "Creator spagnolo",
    "AIconic": "AIconic Agency",
}
MAX_HERMES_MESSAGE_CHARS = 2000
MAX_HERMES_TASK_CHARS = 6000
MAX_HERMES_LOG_TAIL_BYTES = 12000
QMD_QUERY_URL = "http://127.0.0.1:18181/query"
QMD_COLLECTION = os.environ.get("LIFE_OS_QMD_COLLECTION", "obsidian-knowledge-pilot").strip() or "obsidian-knowledge-pilot"
QMD_TIMEOUT_SECONDS = min(max(env_float("LIFE_OS_QMD_TIMEOUT_SECONDS", 0.25), 0.05), 2.0)
QMD_MIN_SCORE = min(max(env_float("LIFE_OS_QMD_MIN_SCORE", 0.5), 0.0), 1.0)

READ_ALLOWED_ROOTS = [
    CAPTURE_DIR,
    SOURCES_DIR,
    WORKBENCH_DIR,
    COMPILED_WIKIS_DIR,
    PROJECTS_DIR,
    AREAS_DIR,
    KNOWLEDGE_DIR,
]

TOOL_ALIASES = {
    "search_life_os": "lifeos_search",
    "get_today_brief": "lifeos_today_brief",
    "create_action": "notion_create_task",
    "capture_note": "obsidian_capture_note",
    "create_content_idea": "notion_create_content_idea",
    "get_project_status": "project_get_brief",
    "search_knowledge": "lifeos_search",
    "append_daily_log": "notion_log_daily_metric",
    "list_agent_errors": "agent_review_errors",
}


class GatewayConfig:
    def __init__(self, write_mode: str = "local", api_key_file: str | None = None) -> None:
        self.write_mode = write_mode
        self.api_key_file = api_key_file
        self.api_key = load_api_key(api_key_file)
        self.allow_unauthenticated_loopback = False


def load_api_key(api_key_file: str | None = None) -> str:
    api_key = os.environ.get("LIFE_OS_MCP_API_KEY", "").strip()
    if api_key:
        return api_key

    key_file = api_key_file or os.environ.get("LIFE_OS_MCP_API_KEY_FILE")
    if key_file:
        candidate = Path(key_file).expanduser()
    else:
        candidate = Path.home() / ".config" / "life-os" / "mcp-api-key.txt"
    try:
        if candidate.exists():
            return candidate.read_text(encoding="utf-8").strip()
    except OSError:
        return ""
    return ""


CONFIG = GatewayConfig()


def configure_http_auth(host: str, allow_unauthenticated_loopback: bool) -> None:
    """Require an API key unless no-auth was explicitly limited to loopback."""
    CONFIG.allow_unauthenticated_loopback = False
    if CONFIG.api_key:
        return
    if not allow_unauthenticated_loopback:
        raise ValueError(
            "Life OS MCP HTTP authentication is required; configure an API key "
            "or use --allow-unauthenticated-loopback for isolated local development"
        )
    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback = False
    if not is_loopback:
        raise ValueError("--allow-unauthenticated-loopback requires a loopback --host")
    CONFIG.allow_unauthenticated_loopback = True


class JsonRpcError(Exception):
    def __init__(self, code: int, message: str, data: Any | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def load_spec() -> dict[str, Any]:
    return json.loads(MCP_SPEC.read_text(encoding="utf-8"))


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=True) + "\n")


def text_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def count_jsonl(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return sum(1 for line in handle if line.strip())


def clamp_int(value: Any, *, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))


def safe_tail(value: str, limit: int = 4000) -> str:
    text = value or ""
    if CONFIG.api_key:
        text = text.replace(CONFIG.api_key, "[redacted-api-key]")
    text = re.sub(r"(?i)(authorization|api[-_ ]?key|token|password)\s*[:=]\s*\S+", r"\1=[redacted]", text)
    return text[-limit:]


def run_hermes(args: list[str], *, timeout: int = 60) -> dict[str, Any]:
    if not HERMES_EXE.exists():
        raise JsonRpcError(-32603, "Hermes executable not found", str(HERMES_EXE))
    env = os.environ.copy()
    env.setdefault("HERMES_HOME", str(HERMES_HOME))
    env.setdefault("HERMES_REDACT_SECRETS", "true")
    env.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        completed = subprocess.run(
            [str(HERMES_EXE), *args],
            cwd=str(Path.home()),
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise JsonRpcError(-32603, "Hermes command timed out", {"args": args, "timeout": timeout}) from exc
    return {
        "returncode": completed.returncode,
        "stdout": safe_tail(completed.stdout),
        "stderr": safe_tail(completed.stderr),
    }


def try_parse_json(value: str) -> Any:
    try:
        return json.loads(value)
    except Exception:
        return None


def read_json_file(path: Path) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None
    return None


def read_recent_jsonl(path: Path, limit: int) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                records.append(record)
    return records[-limit:]


def find_run(run_id: str) -> dict[str, Any] | None:
    if not HERMES_RUNS.exists():
        return None
    with HERMES_RUNS.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("run_id") == run_id:
                return record
    return None


def extract_task_id(payload: Any, stdout: str) -> str | None:
    if isinstance(payload, dict):
        for key in ("task_id", "id", "task"):
            value = payload.get(key)
            if isinstance(value, (str, int)) and str(value).strip():
                return str(value).strip()
        for value in payload.values():
            if isinstance(value, dict):
                nested = extract_task_id(value, "")
                if nested:
                    return nested
    match = re.search(r"\b(?:task[_ -]?id|id)\s*[:=]\s*([A-Za-z0-9_.:-]+)", stdout, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def recent_files(root: Path, limit: int = 5) -> list[dict[str, Any]]:
    if not root.exists():
        return []
    files = [path for path in root.rglob("*") if path.is_file() and file_matches(path)]
    files.sort(key=lambda path: path.stat().st_mtime, reverse=True)
    results = []
    for path in files[:limit]:
        stat = path.stat()
        results.append(
            {
                "path": path.relative_to(ROOT).as_posix(),
                "modified": datetime.fromtimestamp(stat.st_mtime).astimezone().isoformat(timespec="seconds"),
            }
        )
    return results


def recent_files_for_roots(roots: list[Path], limit: int = 10) -> list[dict[str, Any]]:
    files: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        files.extend(path for path in root.rglob("*") if path.is_file() and file_matches(path))
    files.sort(key=lambda path: path.stat().st_mtime, reverse=True)
    results = []
    for path in files[:limit]:
        stat = path.stat()
        results.append(
            {
                "path": path.relative_to(ROOT).as_posix(),
                "modified": datetime.fromtimestamp(stat.st_mtime).astimezone().isoformat(timespec="seconds"),
                "size_bytes": stat.st_size,
            }
        )
    return results


def obsidian_uri(relative_path: str) -> str:
    return f"obsidian://open?vault={quote(OBSIDIAN_VAULT_NAME)}&file={quote(relative_path, safe='')}"


def resolve_read_path(raw_path: str) -> Path:
    clean_path = raw_path.strip().replace("\\", "/").lstrip("/")
    if not clean_path:
        raise JsonRpcError(-32602, "path is required")
    candidate = ROOT / clean_path
    try:
        resolved = candidate.resolve()
    except OSError as exc:
        raise JsonRpcError(-32602, "invalid path", raw_path) from exc

    root_resolved = ROOT.resolve()
    if resolved == root_resolved or root_resolved not in resolved.parents:
        raise JsonRpcError(-32602, "path must stay inside the Obsidian vault", raw_path)
    if not resolved.exists() or not resolved.is_file():
        raise JsonRpcError(-32602, "note path does not exist", clean_path)
    if not file_matches(resolved):
        raise JsonRpcError(-32602, "path is not a supported small text file", clean_path)

    allowed = False
    for allowed_root in READ_ALLOWED_ROOTS:
        allowed_resolved = allowed_root.resolve()
        if resolved == allowed_resolved or allowed_resolved in resolved.parents:
            allowed = True
            break
    if not allowed:
        raise JsonRpcError(-32602, "path is outside the gateway read allowlist", clean_path)
    return resolved


def tool_specs() -> list[dict[str, Any]]:
    spec = load_spec()
    tools = []
    for tool in spec.get("tools", []):
        tools.append(
            {
                "name": tool["name"],
                "description": tool.get("description", ""),
                "inputSchema": tool.get("input_schema", {"type": "object"}),
            }
        )
    return tools


def scope_roots(scope: str) -> list[Path]:
    if scope == "capture":
        return [CAPTURE_DIR]
    if scope == "sources":
        return [SOURCES_DIR]
    if scope == "projects":
        return [PROJECTS_DIR]
    if scope == "areas":
        return [AREAS_DIR]
    if scope == "knowledge":
        return [KNOWLEDGE_DIR]
    if scope == "compiled-wikis":
        return [COMPILED_WIKIS_DIR]
    if scope == "workbench":
        return [WORKBENCH_DIR, COMPILED_WIKIS_DIR]
    if scope == "agent-inbox":
        return [AGENT_INBOX]
    if scope == "notion-operational":
        return [AGENT_INBOX, IMPORTS]
    if scope == "obsidian-knowledge":
        return [KNOWLEDGE_DIR]
    if scope == "daily":
        return [AREAS_DIR, CAPTURE_DIR]
    return [PROJECTS_DIR, AREAS_DIR, KNOWLEDGE_DIR, COMPILED_WIKIS_DIR, CAPTURE_DIR, SOURCES_DIR, AGENT_INBOX]


def file_matches(path: Path) -> bool:
    try:
        root = ROOT.resolve()
        relative = path.relative_to(ROOT)
        lexical = root / relative
        resolved = path.resolve()
    except (OSError, ValueError):
        return False
    if resolved != lexical or (resolved != root and root not in resolved.parents):
        return False
    if path.suffix.lower() not in TEXT_EXTENSIONS:
        return False
    try:
        return path.stat().st_size <= MAX_FILE_BYTES
    except OSError:
        return False


def search_paths(query: str, roots: list[Path], limit: int) -> list[dict[str, Any]]:
    terms = [term for term in query.lower().split() if term]
    if not terms:
        return []

    matches: list[dict[str, Any]] = []
    scanned = 0
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or not file_matches(path):
                continue
            scanned += 1
            if scanned > MAX_SCAN_FILES:
                return matches
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            lowered = text.lower()
            if not all(term in lowered or term in path.name.lower() for term in terms):
                continue
            line_number = 1
            snippet = ""
            for index, line in enumerate(text.splitlines(), start=1):
                low_line = line.lower()
                if any(term in low_line for term in terms):
                    line_number = index
                    snippet = line.strip()[:260]
                    break
            matches.append(
                {
                    "path": path.relative_to(ROOT).as_posix(),
                    "line": line_number,
                    "snippet": snippet,
                }
            )
            if len(matches) >= limit:
                return matches
    return matches


def redacted_knowledge_fallback(query: str, limit: int) -> list[dict[str, Any]]:
    return [
        {
            "path": match["path"],
            "score": None,
            "provenance": {"source": "native", "scope": "05-knowledge", "retrieval": "lexical"},
        }
        for match in search_paths(query, [KNOWLEDGE_DIR], limit)
    ]


def knowledge_semantic_search(query: str, limit: int = 3) -> dict[str, Any]:
    """Read-only QMD shadow lookup; deliberately not registered as an MCP tool."""
    query = query.strip()
    limit = max(1, min(limit, 3))
    if not query:
        return {"status": "no_evidence", "query": query, "matches": [], "minimum_score": QMD_MIN_SCORE}

    try:
        request = Request(
            QMD_QUERY_URL,
            data=json.dumps(
                {
                    "searches": [{"type": "vec", "query": query}],
                    "collections": [QMD_COLLECTION],
                    "limit": limit,
                    "minScore": QMD_MIN_SCORE,
                    "rerank": False,
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=QMD_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError):
        payload = {}
        sidecar = "unavailable"
    else:
        sidecar = "qmd"

    matches: list[dict[str, Any]] = []
    prefix = f"qmd://{QMD_COLLECTION}/"
    for result in payload.get("results", []) if isinstance(payload, dict) else []:
        raw_file = str(result.get("file", ""))
        score = result.get("score")
        if (
            not raw_file.startswith(prefix)
            or isinstance(score, bool)
            or not isinstance(score, (int, float))
            or score < QMD_MIN_SCORE
        ):
            continue
        relative = unquote(raw_file[len(prefix) :]).replace("\\", "/").lstrip("/")
        if not relative or ".." in Path(relative).parts:
            continue
        path = f"05-knowledge/{relative}"
        try:
            resolve_read_path(path)
        except JsonRpcError:
            continue
        if any(match["path"] == path for match in matches):
            continue
        matches.append(
            {
                "path": path,
                "score": round(float(score), 3),
                "provenance": {"source": "qmd", "collection": QMD_COLLECTION, "retrieval": "vector", "mode": "shadow"},
            }
        )
        if len(matches) == limit:
            break

    if matches:
        return {"status": "shadow", "query": query, "matches": matches, "minimum_score": QMD_MIN_SCORE, "sidecar": sidecar}
    fallback = redacted_knowledge_fallback(query, limit)
    return {
        "status": "fallback" if fallback else "no_evidence",
        "query": query,
        "matches": fallback,
        "minimum_score": QMD_MIN_SCORE,
        "sidecar": sidecar,
    }


def matching_hubs(query: str, limit: int) -> list[dict[str, Any]]:
    lowered_query = query.lower().strip()
    if not lowered_query:
        return []
    exact_matches: list[dict[str, Any]] = []
    broad_matches: list[dict[str, Any]] = []
    for path in AREAS_DIR.rglob("*hub.md"):
        if not path.is_file() or not file_matches(path):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if lowered_query not in text.lower() and lowered_query not in path.as_posix().lower():
            continue
        match = {
            "path": path.relative_to(ROOT).as_posix(),
            "line": 1,
            "snippet": f"Canonical Area hub matching {query}",
        }
        frontmatter_area = re.search(r"(?mi)^area:\s*(.+?)\s*$", text)
        area_value = frontmatter_area.group(1).strip().lower() if frontmatter_area else ""
        if area_value == lowered_query or lowered_query in path.stem.lower():
            exact_matches.append(match)
        else:
            broad_matches.append(match)
    return (exact_matches + broad_matches)[:limit]


def run_router(text: str, kind: str, source: str, project: str | None = None, area: str | None = None) -> dict[str, Any]:
    command = [sys.executable, str(ROUTER), "--text", text, "--source", source, "--kind", kind]
    if project:
        command.extend(["--project", project])
    if area:
        command.extend(["--area", area])
    if CONFIG.write_mode == "local":
        command.append("--apply")

    completed = subprocess.run(
        command,
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise JsonRpcError(
            -32603,
            "life_os_router.py failed",
            {"returncode": completed.returncode, "stdout": completed.stdout[-1000:], "stderr": completed.stderr[-1000:]},
        )
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise JsonRpcError(-32603, "life_os_router.py returned invalid JSON", completed.stdout[-1000:]) from exc


def tool_get_today_brief(arguments: dict[str, Any]) -> dict[str, Any]:
    target_date = arguments.get("date") or date.today().isoformat()
    return {
        "date": target_date,
        "mode": "local_gateway",
        "server_version": SERVER_VERSION,
        "notion_queue_rows": count_jsonl(NOTION_QUEUE),
        "calendar_queue_rows": count_jsonl(CALENDAR_QUEUE),
        "router_audit_rows": count_jsonl(ROUTER_AUDIT),
        "gateway_audit_rows": count_jsonl(GATEWAY_AUDIT),
        "recent_captures": recent_files(CAPTURE_DIR, 5),
        "recent_areas": recent_files(AREAS_DIR, 5),
        "recent_projects": recent_files(PROJECTS_DIR, 5),
        "recent_knowledge": recent_files(KNOWLEDGE_DIR, 5),
        "recommended_first_tools": ["lifeos_search", "project_get_brief", "obsidian_read_note", "lifeos_route_capture"],
        "note": "Live Notion and Google Calendar are not queried here; writes go to local queues/capture first.",
    }


def tool_search_life_os(arguments: dict[str, Any]) -> dict[str, Any]:
    query = str(arguments.get("query", "")).strip()
    scope = str(arguments.get("scope") or "all")
    limit = int(arguments.get("limit") or 10)
    limit = max(1, min(limit, 25))
    return {"query": query, "scope": scope, "matches": search_paths(query, scope_roots(scope), limit)}


def tool_lifeos_recent_activity(arguments: dict[str, Any]) -> dict[str, Any]:
    scope = str(arguments.get("scope") or "all")
    limit = int(arguments.get("limit") or 10)
    limit = max(1, min(limit, 25))
    return {"scope": scope, "files": recent_files_for_roots(scope_roots(scope), limit)}


def tool_obsidian_read_note(arguments: dict[str, Any]) -> dict[str, Any]:
    path = resolve_read_path(str(arguments.get("path", "")))
    max_chars = int(arguments.get("max_chars") or 8000)
    max_chars = max(500, min(max_chars, MAX_READ_CHARS))
    text = path.read_text(encoding="utf-8", errors="replace")
    relative = path.relative_to(ROOT).as_posix()
    stat = path.stat()
    return {
        "path": relative,
        "obsidian_uri": obsidian_uri(relative),
        "modified": datetime.fromtimestamp(stat.st_mtime).astimezone().isoformat(timespec="seconds"),
        "size_bytes": stat.st_size,
        "truncated": len(text) > max_chars,
        "content": text[:max_chars],
    }


def tool_search_knowledge(arguments: dict[str, Any]) -> dict[str, Any]:
    query = str(arguments.get("query", "")).strip()
    limit = int(arguments.get("limit") or 10)
    limit = max(1, min(limit, 25))
    return {"query": query, "scope": "05-knowledge", "matches": search_paths(query, [KNOWLEDGE_DIR], limit)}


def tool_get_project_status(arguments: dict[str, Any]) -> dict[str, Any]:
    project = str(arguments.get("project", "")).strip()
    limit = int(arguments.get("limit") or 8)
    limit = max(1, min(limit, 20))
    hub_matches = matching_hubs(project, limit)
    broad_matches = search_paths(project, [AREAS_DIR, PROJECTS_DIR], limit) if project else []
    hub_paths = {match["path"] for match in hub_matches}
    matches = (hub_matches + [match for match in broad_matches if match["path"] not in hub_paths])[:limit]
    return {
        "project": project,
        "matches": matches,
        "recent_area_files": recent_files(AREAS_DIR, min(limit, 10)),
        "recent_project_files": recent_files(PROJECTS_DIR, min(limit, 10)),
        "note": "This is local Obsidian Area/Project evidence only; live Notion state is not queried here.",
    }


def tool_lifeos_route_capture(arguments: dict[str, Any], source: str) -> dict[str, Any]:
    text = str(arguments.get("text", "")).strip()
    if not text:
        raise JsonRpcError(-32602, "lifeos_route_capture requires text")
    kind = str(arguments.get("kind") or "auto")
    project = arguments.get("project")
    area = arguments.get("area")
    source_label = str(arguments.get("source") or source)
    return run_router(text, kind, source_label, str(project) if project else None, str(area) if area else None)


def tool_create_action(arguments: dict[str, Any], source: str) -> dict[str, Any]:
    title = str(arguments.get("title", "")).strip()
    if not title:
        raise JsonRpcError(-32602, "create_action requires title")
    project = arguments.get("project")
    area = arguments.get("area")
    details = []
    for key in ("priority", "scheduled", "deadline"):
        if arguments.get(key):
            details.append(f"{key}: {arguments[key]}")
    context = arguments.get("context")
    if isinstance(context, list) and context:
        details.append("context: " + "; ".join(str(item) for item in context))
    text = title if not details else title + "\n" + "\n".join(details)
    return run_router(text, "task", source, str(project) if project else None, str(area) if area else None)


def tool_capture_note(arguments: dict[str, Any], source: str) -> dict[str, Any]:
    text = str(arguments.get("text", "")).strip()
    if not text:
        raise JsonRpcError(-32602, "capture_note requires text")
    suggested_project = arguments.get("suggested_project")
    suggested_area = arguments.get("suggested_area")
    return run_router(
        text,
        "knowledge",
        str(arguments.get("source") or source),
        str(suggested_project) if suggested_project else None,
        str(suggested_area) if suggested_area else None,
    )


def tool_create_content_idea(arguments: dict[str, Any], source: str) -> dict[str, Any]:
    title = str(arguments.get("title", "")).strip()
    if not title:
        raise JsonRpcError(-32602, "create_content_idea requires title")
    lane = str(arguments.get("lane", "")).strip()
    project = str(arguments.get("project", "")).strip()
    area = str(arguments.get("area", "")).strip() or CONTENT_AREA_BY_LANE.get(lane, "")
    notes = arguments.get("notes")
    text = title
    if lane:
        text += f"\nlane: {lane}"
    if arguments.get("format"):
        text += f"\nformat: {arguments['format']}"
    if arguments.get("source_uri"):
        text += f"\nsource_uri: {arguments['source_uri']}"
    if notes:
        text += f"\nnotes: {notes}"
    return run_router(text, "content", source, project or None, area or None)


def tool_append_daily_log(arguments: dict[str, Any], source: str) -> dict[str, Any]:
    kind = str(arguments.get("kind", "")).strip()
    value = arguments.get("value")
    note = arguments.get("note")
    target_date = arguments.get("date")
    if not kind:
        raise JsonRpcError(-32602, "append_daily_log requires kind")
    text = f"{kind}: {value}"
    if target_date:
        text += f"\ndate: {target_date}"
    if note:
        text += f"\nnote: {note}"
    router_kind = "knowledge" if kind == "narrative" else "daily_metric"
    return run_router(text, router_kind, source, None, None)


def tool_calendar_queue_event(arguments: dict[str, Any], source: str) -> dict[str, Any]:
    title = str(arguments.get("title", "")).strip()
    when = str(arguments.get("when", "")).strip()
    if not title or not when:
        raise JsonRpcError(-32602, "calendar_queue_event requires title and when")
    details = [f"when: {when}"]
    if arguments.get("duration_minutes"):
        details.append(f"duration_minutes: {arguments['duration_minutes']}")
    if arguments.get("location"):
        details.append(f"location: {arguments['location']}")
    participants = arguments.get("participants")
    if isinstance(participants, list) and participants:
        details.append("participants: " + "; ".join(str(item) for item in participants))
    if arguments.get("note"):
        details.append(f"note: {arguments['note']}")
    text = title + "\n" + "\n".join(details)
    return run_router(text, "event", source, None, None)


def tool_project_capture_update(arguments: dict[str, Any], source: str) -> dict[str, Any]:
    project = str(arguments.get("project", "")).strip()
    area = str(arguments.get("area", "")).strip()
    text = str(arguments.get("text", "")).strip()
    if not text or not (project or area):
        raise JsonRpcError(-32602, "project_capture_update requires text and either project or area")
    source_label = str(arguments.get("source") or source)
    return run_router(text, "knowledge", source_label, project or None, area or None)


def tool_list_agent_errors(arguments: dict[str, Any]) -> dict[str, Any]:
    status = str(arguments.get("status") or "open")
    limit = int(arguments.get("limit") or 20)
    limit = max(1, min(limit, 50))
    records = []
    for path in (GATEWAY_AUDIT, ROUTER_AUDIT):
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                has_error = bool(record.get("error") or record.get("write_validation_errors"))
                if status == "all" or (status == "open" and has_error) or (status == "resolved" and not has_error):
                    records.append(record)
    return {"status": status, "records": records[-limit:]}


def canonical_tool_name(name: str) -> str:
    return TOOL_ALIASES.get(name, name)


def dispatch_tool(name: str, arguments: dict[str, Any], poke_user_id: str | None) -> dict[str, Any]:
    name = canonical_tool_name(name)
    source = "poke-mcp"
    if poke_user_id:
        source += f":{poke_user_id}"

    if name == "lifeos_today_brief":
        return tool_get_today_brief(arguments)
    if name == "lifeos_search":
        if "scope" not in arguments and "types" in arguments:
            arguments = arguments | {"scope": "knowledge"}
        return tool_search_life_os(arguments)
    if name == "lifeos_recent_activity":
        return tool_lifeos_recent_activity(arguments)
    if name == "lifeos_route_capture":
        return tool_lifeos_route_capture(arguments, source)
    if name == "obsidian_read_note":
        return tool_obsidian_read_note(arguments)
    if name == "obsidian_capture_note":
        return tool_capture_note(arguments, source)
    if name == "notion_create_task":
        return tool_create_action(arguments, source)
    if name == "notion_create_content_idea":
        return tool_create_content_idea(arguments, source)
    if name == "notion_log_daily_metric":
        return tool_append_daily_log(arguments, source)
    if name == "calendar_queue_event":
        return tool_calendar_queue_event(arguments, source)
    if name == "project_get_brief":
        return tool_get_project_status(arguments)
    if name == "project_capture_update":
        return tool_project_capture_update(arguments, source)
    if name == "agent_review_errors":
        return tool_list_agent_errors(arguments)
    raise JsonRpcError(-32601, f"Unknown tool: {name}")


def log_gateway_call(tool_name: str, arguments: dict[str, Any], poke_user_id: str | None, ok: bool, result: Any = None, error: Any = None) -> None:
    if poke_user_id == "self-test":
        return
    text_fields = []
    for key in ("query", "text", "title", "note", "project", "area"):
        if key in arguments and arguments[key] is not None:
            text_fields.append(str(arguments[key]))
    append_jsonl(
        GATEWAY_AUDIT,
        {
            "created": now_iso(),
            "tool": tool_name,
            "poke_user_id": poke_user_id,
            "argument_keys": sorted(arguments),
            "argument_hash": text_hash("\n".join(text_fields)) if text_fields else None,
            "write_mode": CONFIG.write_mode,
            "ok": ok,
            "result_status": result.get("status") if isinstance(result, dict) else None,
            "error": error,
        },
    )


def make_result_content(payload: Any) -> dict[str, Any]:
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(payload, ensure_ascii=False, indent=2),
            }
        ]
    }


def jsonrpc_error_response(request_id: Any, code: int, message: str, data: Any | None = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def handle_jsonrpc(request: dict[str, Any], poke_user_id: str | None = None) -> dict[str, Any] | None:
    request_id = request.get("id")
    method = request.get("method")
    params = request.get("params") or {}

    try:
        if method == "initialize":
            requested = str(params.get("protocolVersion") or DEFAULT_PROTOCOL)
            protocol = requested if requested in SUPPORTED_PROTOCOLS else DEFAULT_PROTOCOL
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": protocol,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {
                        "name": SERVER_NAME,
                        "version": SERVER_VERSION,
                        "title": "Life OS MCP Gateway",
                        "instructions": SERVER_INSTRUCTIONS,
                    },
                    "instructions": SERVER_INSTRUCTIONS,
                },
            }

        if method == "notifications/initialized":
            return None if request_id is None else {"jsonrpc": "2.0", "id": request_id, "result": {}}

        if method == "ping":
            return {"jsonrpc": "2.0", "id": request_id, "result": {}}

        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": tool_specs()}}

        if method == "tools/call":
            name = canonical_tool_name(str(params.get("name") or ""))
            arguments = params.get("arguments") or {}
            if not isinstance(arguments, dict):
                raise JsonRpcError(-32602, "tools/call arguments must be an object")
            try:
                result = dispatch_tool(name, arguments, poke_user_id)
                log_gateway_call(name, arguments, poke_user_id, True, result=result)
            except JsonRpcError as exc:
                log_gateway_call(name, arguments, poke_user_id, False, error={"code": exc.code, "message": exc.message})
                raise
            return {"jsonrpc": "2.0", "id": request_id, "result": make_result_content(result)}

        raise JsonRpcError(-32601, f"Unsupported method: {method}")
    except JsonRpcError as exc:
        return jsonrpc_error_response(request_id, exc.code, exc.message, exc.data)
    except Exception as exc:  # pragma: no cover - defensive boundary for MCP clients.
        return jsonrpc_error_response(request_id, -32603, "Internal gateway error", str(exc))


class LifeOsMcpHandler(BaseHTTPRequestHandler):
    server_version = f"{SERVER_NAME}/{SERVER_VERSION}"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "authorization, content-type, x-api-key, api-key, x-poke-api-key, x-poke-user-id")
        self.end_headers()
        self.wfile.write(body)

    def _send_empty(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "authorization, content-type, x-api-key, api-key, x-poke-api-key, x-poke-user-id")
        self.end_headers()

    def _authorized(self) -> bool:
        if not CONFIG.api_key:
            return CONFIG.allow_unauthenticated_loopback
        candidates = [
            self.headers.get("Authorization", ""),
            self.headers.get("X-API-Key", ""),
            self.headers.get("X-Api-Key", ""),
            self.headers.get("Api-Key", ""),
            self.headers.get("X-Poke-Api-Key", ""),
            self.headers.get("X-Poke-API-Key", ""),
        ]
        for header in candidates:
            value = header.strip()
            if not value:
                continue
            if hmac.compare_digest(value, CONFIG.api_key):
                return True
            if hmac.compare_digest(value, f"Bearer {CONFIG.api_key}"):
                return True
        return False

    def do_OPTIONS(self) -> None:
        self._send_empty(HTTPStatus.NO_CONTENT)

    def do_GET(self) -> None:
        if self.path.rstrip("/") in ("", "/"):
            self._send_json(HTTPStatus.OK, {"name": SERVER_NAME, "version": SERVER_VERSION, "mcp": "/mcp", "health": "/health"})
            return
        if self.path.startswith("/health"):
            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "name": SERVER_NAME,
                    "version": SERVER_VERSION,
                    "write_mode": CONFIG.write_mode,
                    "auth_required": bool(CONFIG.api_key),
                    "tools": len(tool_specs()),
                },
            )
            return
        if self.path.startswith("/mcp"):
            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "name": SERVER_NAME,
                    "version": SERVER_VERSION,
                    "transport": "streamable-http",
                    "jsonrpc_endpoint": "/mcp",
                    "accepted_methods": ["POST", "OPTIONS"],
                    "auth_required": bool(CONFIG.api_key),
                    "tools": len(tool_specs()),
                    "note": "Use JSON-RPC POST /mcp for MCP initialize, tools/list and tools/call.",
                },
            )
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:
        if not self.path.startswith("/mcp"):
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        if not self._authorized():
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            self._send_json(HTTPStatus.BAD_REQUEST, jsonrpc_error_response(None, -32700, "Parse error"))
            return

        poke_user_id = self.headers.get("X-Poke-User-Id")
        if isinstance(payload, list):
            responses = [handle_jsonrpc(item, poke_user_id) for item in payload if isinstance(item, dict)]
            responses = [response for response in responses if response is not None]
            if not responses:
                self._send_empty(HTTPStatus.NO_CONTENT)
                return
            self._send_json(HTTPStatus.OK, responses)
            return

        if not isinstance(payload, dict):
            self._send_json(HTTPStatus.BAD_REQUEST, jsonrpc_error_response(None, -32600, "Invalid Request"))
            return

        response = handle_jsonrpc(payload, poke_user_id)
        if response is None:
            self._send_empty(HTTPStatus.NO_CONTENT)
            return
        self._send_json(HTTPStatus.OK, response)


def run_server(host: str, port: int, write_mode: str) -> None:
    CONFIG.write_mode = write_mode
    server = ThreadingHTTPServer((host, port), LifeOsMcpHandler)
    print(json.dumps({"status": "listening", "host": host, "port": port, "write_mode": write_mode}, indent=2))
    server.serve_forever()


def run_self_test() -> int:
    original_write_mode = CONFIG.write_mode
    CONFIG.write_mode = "dry-run"
    failures: list[str] = []

    init_response = handle_jsonrpc({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}})
    if not init_response or init_response.get("result", {}).get("capabilities", {}).get("tools") is None:
        failures.append("initialize did not advertise tools capability")

    list_response = handle_jsonrpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tool_count = len(list_response.get("result", {}).get("tools", [])) if list_response else 0
    if tool_count != len(load_spec().get("tools", [])):
        failures.append(f"tools/list count mismatch: {tool_count}")
    public_names = [tool["name"] for tool in list_response.get("result", {}).get("tools", [])] if list_response else []
    if "create_action" in public_names or "search_life_os" in public_names:
        failures.append(f"tools/list still advertises v1 names: {public_names}")

    call_response = handle_jsonrpc(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "notion_create_task", "arguments": {"title": "Devo testare il gateway MCP"}},
        },
        "self-test",
    )
    text = ""
    try:
        text = call_response["result"]["content"][0]["text"] if call_response else ""
        parsed = json.loads(text)
        if parsed.get("status") != "dry-run" or parsed.get("target") != "Action Items":
            failures.append(f"notion_create_task dry-run result mismatch: {parsed}")
    except Exception as exc:
        failures.append(f"notion_create_task response parse failed: {exc}; {text}")

    route_response = handle_jsonrpc(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "lifeos_route_capture", "arguments": {"text": "Idea video TikTok per divulgazione su nuovi tool AI"}},
        },
        "self-test",
    )
    try:
        text = route_response["result"]["content"][0]["text"] if route_response else ""
        parsed = json.loads(text)
        if parsed.get("status") != "dry-run" or parsed.get("target") != "Capture Inbox":
            failures.append(f"lifeos_route_capture dry-run result mismatch: {parsed}")
    except Exception as exc:
        failures.append(f"lifeos_route_capture response parse failed: {exc}; {text}")

    alias_response = handle_jsonrpc(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "create_action", "arguments": {"title": "Compat alias smoke"}},
        },
        "self-test",
    )
    try:
        text = alias_response["result"]["content"][0]["text"] if alias_response else ""
        parsed = json.loads(text)
        if parsed.get("status") != "dry-run" or parsed.get("target") != "Action Items":
            failures.append(f"v1 alias dry-run result mismatch: {parsed}")
    except Exception as exc:
        failures.append(f"v1 alias response parse failed: {exc}; {text}")

    brief_response = handle_jsonrpc(
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {"name": "project_get_brief", "arguments": {"project": "TND"}},
        },
        "self-test",
    )
    try:
        text = brief_response["result"]["content"][0]["text"] if brief_response else ""
        parsed = json.loads(text)
        paths = [match.get("path") for match in parsed.get("matches", [])]
        if not paths or paths[0] != "04-areas/tnd/tnd-hub.md":
            failures.append(f"project_get_brief did not prioritize TND Area hub: {parsed}")
    except Exception as exc:
        failures.append(f"project_get_brief response parse failed: {exc}; {text}")

    area_capture_response = handle_jsonrpc(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "project_capture_update",
                "arguments": {"project": "TND", "text": "Decision: keep TND Fanvue-first"},
            },
        },
        "self-test",
    )
    try:
        text = area_capture_response["result"]["content"][0]["text"] if area_capture_response else ""
        parsed = json.loads(text)
        payload = parsed.get("payload", {})
        if payload.get("area") != "TND" or "project" in payload:
            failures.append(f"project_capture_update did not normalize TND as an Area: {parsed}")
    except Exception as exc:
        failures.append(f"project_capture_update response parse failed: {exc}; {text}")

    content_response = handle_jsonrpc(
        {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {
                "name": "notion_create_content_idea",
                "arguments": {"title": "Spanish creator format test", "lane": "Creator spagnolo"},
            },
        },
        "self-test",
    )
    try:
        text = content_response["result"]["content"][0]["text"] if content_response else ""
        parsed = json.loads(text)
        payload = parsed.get("payload", {})
        if payload.get("area") != "Creator spagnolo" or "project" in payload:
            failures.append(f"notion_create_content_idea treated an Area lane as a project: {parsed}")
    except Exception as exc:
        failures.append(f"notion_create_content_idea response parse failed: {exc}; {text}")

    CONFIG.write_mode = original_write_mode
    print(json.dumps({"status": "pass" if not failures else "fail", "failures": failures}, indent=2))
    return 0 if not failures else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the local Life OS MCP gateway.")
    parser.add_argument("--host", default="127.0.0.1", help="Host/interface to bind.")
    parser.add_argument("--port", type=int, default=3010, help="Port to bind.")
    parser.add_argument("--write-mode", choices=["local", "dry-run"], default=os.environ.get("LIFE_OS_MCP_WRITE_MODE", "local"))
    parser.add_argument("--api-key-file", dest="api_key_file", help="Explicit file path containing the API key.")
    parser.add_argument("--auth-file", dest="api_key_file", help="Alias for --api-key-file.")
    parser.add_argument(
        "--allow-unauthenticated-loopback",
        action="store_true",
        help="Allow unauthenticated HTTP only on an explicit loopback bind for isolated local development.",
    )
    parser.add_argument("--self-test", action="store_true", help="Run local JSON-RPC self-tests without opening a server.")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    CONFIG.write_mode = args.write_mode
    CONFIG.api_key_file = args.api_key_file
    CONFIG.api_key = load_api_key(args.api_key_file)
    try:
        configure_http_auth(args.host, args.allow_unauthenticated_loopback)
    except ValueError as exc:
        parser.error(str(exc))
    run_server(args.host, args.port, args.write_mode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
