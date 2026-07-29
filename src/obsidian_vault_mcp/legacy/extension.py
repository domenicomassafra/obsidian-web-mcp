from __future__ import annotations

import json
from typing import Annotated, Any, Literal

from pydantic import Field

from ..extensions import Extension
from . import life_os_mcp_gateway as legacy


def _call(name: str, arguments: dict[str, Any]) -> str:
    """Run one legacy operation in proposal-only compatibility mode."""
    legacy.CONFIG.write_mode = "dry-run"
    try:
        payload = legacy.dispatch_tool(name, arguments, "unified-obsidian")
        if isinstance(payload, dict):
            payload = dict(payload)
            if name in {
                "lifeos_route_capture",
                "obsidian_capture_note",
                "notion_create_task",
                "notion_create_content_idea",
                "notion_log_daily_metric",
                "calendar_queue_event",
                "project_capture_update",
            }:
                payload["proposal_only"] = True
                payload["write_executed"] = False
            return json.dumps(payload, ensure_ascii=False)
        return json.dumps({"result": payload}, ensure_ascii=False)
    except legacy.JsonRpcError as exc:
        return json.dumps({"error": exc.message, "code": exc.code}, ensure_ascii=False)


class LegacyLifeOsExtension(Extension):
    """Expose the proven Life OS adapter inside the Obsidian MCP app.

    The old HTTP gateway is not started. Its 13 historical compatibility calls
    plus the public zero-write daily planner share this process, bearer auth,
    audit boundary, vault root, and proposal-only write mode.
    """

    def register_tools(self, mcp) -> None:
        mcp.add_tool(
            self.lifeos_today_brief,
            name="lifeos_today_brief",
            description="Read the Life OS daily brief and queue counters. Read-only compatibility tool.",
            annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        )
        mcp.add_tool(
            self.lifeos_search,
            name="lifeos_search",
            description="Search bounded Life OS scopes using lexical matching. Read-only; max 25 results.",
            annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        )
        mcp.add_tool(
            self.lifeos_recent_activity,
            name="lifeos_recent_activity",
            description="List recent bounded Life OS activity. Read-only; max 25 results.",
            annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        )
        mcp.add_tool(
            self.lifeos_route_capture,
            name="lifeos_route_capture",
            description="Return a proposal-only Life OS capture route. It never materializes a write.",
            annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        )
        mcp.add_tool(
            self.obsidian_read_note,
            name="obsidian_read_note",
            description="Read an allowlisted Life OS note with a bounded character limit.",
            annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        )
        mcp.add_tool(
            self.obsidian_capture_note,
            name="obsidian_capture_note",
            description="Return a proposal-only Obsidian capture route. It never writes the vault.",
            annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        )
        mcp.add_tool(
            self.notion_create_task,
            name="notion_create_task",
            description="Return a proposal-only Notion task queue request; no Notion or vault write is executed.",
            annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        )
        mcp.add_tool(
            self.notion_create_content_idea,
            name="notion_create_content_idea",
            description="Return a proposal-only content idea route; no write is executed.",
            annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        )
        mcp.add_tool(
            self.notion_log_daily_metric,
            name="notion_log_daily_metric",
            description="Return a proposal-only daily metric route; no write is executed.",
            annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        )
        mcp.add_tool(
            self.lifeos_daily_dual_surface_plan,
            name="lifeos_daily_dual_surface_plan",
            description=(
                "Build a zero-write morning or evening plan shared by ordinary "
                "ChatGPT and Hermes. It proposes at most three Action Items, "
                "Daily Log metrics and an optional canonical Obsidian narrative "
                "without queueing, creating or updating anything."
            ),
            annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        )
        mcp.add_tool(
            self.calendar_queue_event,
            name="calendar_queue_event",
            description="Return a proposal-only calendar event route; no event is created.",
            annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        )
        mcp.add_tool(
            self.project_get_brief,
            name="project_get_brief",
            description="Read a bounded project brief from the Life OS vault. Read-only.",
            annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        )
        mcp.add_tool(
            self.project_capture_update,
            name="project_capture_update",
            description="Return a proposal-only project update route; no write is executed.",
            annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        )
        mcp.add_tool(
            self.agent_review_errors,
            name="agent_review_errors",
            description="Review bounded legacy gateway/router error records. Read-only; max 50 records.",
            annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        )

    def lifeos_today_brief(self, date: str | None = None) -> str:
        return _call("lifeos_today_brief", {"date": date} if date else {})

    def lifeos_search(
        self,
        query: str,
        scope: Literal["all", "projects", "areas", "knowledge", "compiled-wikis", "capture", "sources", "workbench", "agent-inbox", "notion-operational", "obsidian-knowledge", "daily"] = "all",
        limit: int = 10,
    ) -> str:
        return _call("lifeos_search", {"query": query, "scope": scope, "limit": limit})

    def lifeos_recent_activity(
        self,
        scope: Literal["all", "projects", "areas", "knowledge", "compiled-wikis", "capture", "sources", "workbench", "agent-inbox", "daily"] = "all",
        limit: int = 10,
    ) -> str:
        return _call("lifeos_recent_activity", {"scope": scope, "limit": limit})

    def lifeos_route_capture(
        self,
        text: str,
        kind: Literal["auto", "task", "event", "content", "finance", "people", "daily_metric", "knowledge", "ambiguous"] = "auto",
        project: str | None = None,
        area: str | None = None,
        source: str | None = None,
    ) -> str:
        return _call("lifeos_route_capture", {"text": text, "kind": kind, "project": project, "area": area, "source": source})

    def obsidian_read_note(self, path: str, max_chars: int = 8000) -> str:
        return _call("obsidian_read_note", {"path": path, "max_chars": max_chars})

    def obsidian_capture_note(
        self,
        text: str,
        source: str = "poke",
        suggested_area: str | None = None,
        suggested_project: str | None = None,
    ) -> str:
        return _call("obsidian_capture_note", {"text": text, "source": source, "suggested_area": suggested_area, "suggested_project": suggested_project})

    def notion_create_task(
        self,
        title: str,
        project: str | None = None,
        area: str | None = None,
        priority: Literal["critical", "high", "medium", "low"] | None = None,
        scheduled: str | None = None,
        deadline: str | None = None,
        context: list[str] | None = None,
        obsidian_context_uri: str | None = None,
    ) -> str:
        return _call("notion_create_task", {"title": title, "project": project, "area": area, "priority": priority, "scheduled": scheduled, "deadline": deadline, "context": context, "obsidian_context_uri": obsidian_context_uri})

    def notion_create_content_idea(
        self,
        title: str,
        lane: Literal["Divulgazione", "Creator spagnolo", "AIconic"] | None = None,
        format: str | None = None,
        source_uri: str | None = None,
        notes: str | None = None,
        area: str | None = None,
        project: str | None = None,
    ) -> str:
        return _call("notion_create_content_idea", {"title": title, "lane": lane, "format": format, "source_uri": source_uri, "notes": notes, "area": area, "project": project})

    def notion_log_daily_metric(
        self,
        kind: Literal["work_hours", "output_count", "health_score", "discipline_score", "money_admin_done", "narrative"],
        value: Any,
        date: str | None = None,
        note: str | None = None,
    ) -> str:
        return _call("notion_log_daily_metric", {"kind": kind, "value": value, "date": date, "note": note})

    def lifeos_daily_dual_surface_plan(
        self,
        phase: Literal["morning", "evening"],
        date: Annotated[str, Field(pattern=r"^\d{4}-\d{2}-\d{2}$")],
        top_actions: Annotated[list[str | dict[str, Any]] | None, Field(max_length=3)] = None,
        tomorrow_actions: Annotated[list[str | dict[str, Any]] | None, Field(max_length=3)] = None,
        metrics: Annotated[list[dict[str, Any]] | None, Field(max_length=20)] = None,
        narrative: dict[str, str | list[str]] | None = None,
    ) -> str:
        arguments = {
            "phase": phase,
            "date": date,
            "top_actions": top_actions,
            "tomorrow_actions": tomorrow_actions,
            "metrics": metrics,
            "narrative": narrative,
        }
        return _call(
            "lifeos_daily_dual_surface_plan",
            {key: value for key, value in arguments.items() if value is not None},
        )

    def calendar_queue_event(
        self,
        title: str,
        when: str,
        duration_minutes: int | None = None,
        location: str | None = None,
        participants: list[str] | None = None,
        note: str | None = None,
    ) -> str:
        return _call("calendar_queue_event", {"title": title, "when": when, "duration_minutes": duration_minutes, "location": location, "participants": participants, "note": note})

    def project_get_brief(self, project: str, limit: int = 8) -> str:
        return _call("project_get_brief", {"project": project, "limit": limit})

    def project_capture_update(
        self,
        text: str,
        project: str | None = None,
        area: str | None = None,
        source: str = "poke",
    ) -> str:
        return _call("project_capture_update", {"text": text, "project": project, "area": area, "source": source})

    def agent_review_errors(
        self,
        status: Literal["open", "resolved", "all"] = "open",
        limit: int = 20,
    ) -> str:
        return _call("agent_review_errors", {"status": status, "limit": limit})
