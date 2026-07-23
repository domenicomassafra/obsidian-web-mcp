"""Obsidian Vault MCP Server.

Exposes read/write access to an Obsidian vault over Streamable HTTP.
Designed to run behind Cloudflare Tunnel for secure remote access.
"""

import atexit
import json
import logging
import os
import re
import sys
import threading
import time
import urllib.parse
import urllib.request
from contextlib import asynccontextmanager
from pathlib import PurePosixPath
from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import Field

from .config import (
    VAULT_AUDIT_LOG_INCLUDE_READS,
    VAULT_MCP_ALLOWED_HOSTS,
    VAULT_MCP_FORWARDED_ALLOW_IPS,
    VAULT_MCP_HEARTBEAT_URL,
    VAULT_MCP_HOST,
    VAULT_MCP_PATH,
    VAULT_MCP_PORT,
    VAULT_MCP_TOKEN,
    VAULT_PATH,
)
from .frontmatter_index import FrontmatterIndex
from .audit import (
    BATCH_OPERATIONS,
    MUTATION_OPERATIONS,
    audit_enabled,
    audit_log_path,
    audit_path_inside_vault,
    audit_path_writable,
    attach_mutation_receipt,
    before_target_path,
    build_audit_record,
    build_mutation_receipt,
    infer_target_path,
    persist_mutation_receipt,
    should_audit_operation,
    snapshot_path,
    snapshot_text,
    write_audit_record,
)
from .rate_limit import check_tool_rate_limit
from .serialization import dumps
from .write_events import register_write_listener

logger = logging.getLogger(__name__)

# Global frontmatter index instance
frontmatter_index = FrontmatterIndex()


# Liveness pings don't need the response body; read just enough to complete the
# request without pulling a large/hostile body into memory.
_HEARTBEAT_MAX_BYTES = 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow redirects on the heartbeat GET.

    The configured URL is operator-trusted, but a redirect is not -- following one
    would let a compromised/typo'd monitor bounce the ping to an arbitrary target
    (incl. another scheme). Returning None makes urllib raise instead of follow.
    """

    def redirect_request(self, *args, **kwargs):
        return None


_heartbeat_opener = urllib.request.build_opener(_NoRedirect)


def _heartbeat_ping(url: str) -> None:
    """Send a single liveness GET. Split out from the loop so it is unit-testable.

    Does not follow redirects and reads at most _HEARTBEAT_MAX_BYTES of the body.
    """
    with _heartbeat_opener.open(url, timeout=10) as resp:
        resp.read(_HEARTBEAT_MAX_BYTES)


def _heartbeat_forever(url: str, interval: int) -> None:
    """Ping ``url`` every ``interval`` seconds for the process lifetime.

    Runs in a daemon thread started from main() -- NOT the per-request MCP lifespan,
    which fires on every request and would spawn a heartbeat per session. Failures
    are logged and swallowed so a flaky monitor can never take the server down.
    """
    # The heartbeat URL is a capability URL (the secret is in the path), so log only
    # the host + exception type on failure, never the full URL or exception string.
    host = urllib.parse.urlsplit(url).hostname or "?"
    while True:
        try:
            _heartbeat_ping(url)
        except Exception as e:
            logger.warning("Heartbeat ping to %s failed: %s", host, type(e).__name__)
        time.sleep(interval)


@asynccontextmanager
async def lifespan(server):
    """Per-request MCP lifespan.

    With stateless_http=True this runs on EVERY HTTP request, so it must NOT build
    or tear down the index -- doing so rebuilt the whole index per request and timed
    out large vaults (#28). The index is built once in main() before serving; here we
    only expose the already-built instance to tools.
    """
    yield {"frontmatter_index": frontmatter_index}


# Create the MCP server
mcp = FastMCP(
    "obsidian_web_mcp",
    stateless_http=True,
    json_response=True,
    # Mount path for the MCP transport. Defaults to "/" (via VAULT_MCP_PATH) so
    # connectors that POST to the root complete the handshake instead of 404ing
    # (#19); set VAULT_MCP_PATH to host under a prefix like "/mcp".
    streamable_http_path=VAULT_MCP_PATH,
    lifespan=lifespan,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[
            "127.0.0.1:*",
            "localhost:*",
            "[::1]:*",
            # Operator hostnames from VAULT_MCP_ALLOWED_HOSTS are appended to the
            # loopback defaults above (set it to your tunnel/proxy hostname).
            *VAULT_MCP_ALLOWED_HOSTS,
        ],
    ),
)


# --- Register all tools ---

from .tools.read import vault_read as _vault_read, vault_batch_read as _vault_batch_read
from .tools.write import (
    vault_append as _vault_append,
    vault_batch_frontmatter_update as _vault_batch_frontmatter_update,
    vault_edit as _vault_edit,
    vault_write as _vault_write,
    vault_write_binary as _vault_write_binary,
)
from .tools.search import vault_search as _vault_search, vault_search_frontmatter as _vault_search_frontmatter
from .tools.manage import vault_list as _vault_list, vault_move as _vault_move, vault_delete as _vault_delete
from .tools.canvas import (
    vault_canvas_read as _vault_canvas_read,
    vault_canvas_add_node as _vault_canvas_add_node,
    vault_canvas_add_edge as _vault_canvas_add_edge,
)
from .tools.daily import (
    _daily_note_path,
    _today,
    vault_daily_note_path as _vault_daily_note_path,
    vault_daily_note_read as _vault_daily_note_read,
    vault_daily_note_read_range as _vault_daily_note_read_range,
    vault_daily_note_append as _vault_daily_note_append,
)
from .context_engine import (
    bootstrap_status as _bootstrap_status,
    propose_context as _propose_context,
    read_context as _read_context,
    route_context as _route_context,
)
from .tools.analytics import (
    vault_analytics_summary as _vault_analytics_summary,
    vault_analytics_findings as _vault_analytics_findings,
)
from .models import (
    VaultReadInput,
    VaultWriteInput,
    ExpectedSha256,
    VaultWriteBinaryInput,
    VaultEditOperationInput,
    VaultEditInput,
    VaultAppendInput,
    VaultMutationContextInput,
    VaultWritePreflightInput,
    VaultBatchReadInput,
    FrontmatterUpdateInput,
    VaultBatchFrontmatterUpdateInput,
    VaultSearchInput,
    VaultSearchFrontmatterInput,
    FrontmatterMatchType,
    VaultListInput,
    VaultMoveInput,
    VaultDeleteInput,
    VaultCanvasReadInput,
    CanvasNodeInput,
    CanvasEdgeInput,
    VaultCanvasAddNodeInput,
    VaultCanvasAddEdgeInput,
    VaultDailyNoteAppendInput,
    VaultAnalyticsSummaryInput,
    AnalyticsFindingCategory,
    VaultAnalyticsFindingsInput,
)


_PREFLIGHT_REQUIRED_OPERATIONS = frozenset({
    "vault_write",
    "vault_edit",
    "vault_append",
    "vault_move",
    "vault_delete",
})
_INDEX_NAMES = frozenset({"readme.md", "index.md"})
_ATOMIC_MARKERS = (
    "storyboard",
    "produzione",
    "production",
    "research",
    "ricerca",
    "lifecycle",
    "format",
    "scaletta",
    "script",
    "review cycle",
    "episodio",
    "episode",
    "serie",
    "series",
)


def _is_index_path(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    return name in _INDEX_NAMES or name.endswith("-hub.md")


def _requires_atomic_note(content: str) -> bool:
    body = content.strip()
    heading_count = sum(1 for line in body.splitlines() if line.lstrip().startswith("#"))
    lowered = body.casefold()
    return (
        len(body) > 240
        or heading_count >= 2
        or any(marker in lowered for marker in _ATOMIC_MARKERS)
    )


def _preflight_block(operation: str, plan: dict | None, errors: list[str]) -> str:
    """Return a bounded no-write receipt that exposes the correction needed."""
    return dumps({
        "error": "write_preflight_blocked",
        "status": "blocked",
        "write_executed": False,
        "operation": operation,
        "errors": list(dict.fromkeys(errors)),
        "write_preflight_receipt": {
            "schema": "obsidian-write-preflight/v1",
            "status": "blocked",
            "path": (plan or {}).get("canonical_destination"),
            "operation": (plan or {}).get("operation"),
            "reason": (plan or {}).get("reason"),
            "preimage_requirement": (plan or {}).get("preimage_requirement"),
            "rollback_target": (plan or {}).get("rollback_target"),
        },
    })


def _validate_write_preflight(operation: str, context: dict) -> tuple[dict | None, list[str]]:
    """Validate the model's plan against the real path and preimage at the write gate."""
    mutation = context.get("mutation_context")
    if not isinstance(mutation, dict):
        return None, ["mutation.preflight is required before every public vault mutation"]
    raw_plan = mutation.get("preflight")
    if not isinstance(raw_plan, dict):
        return None, ["mutation.preflight is required before every public vault mutation"]
    try:
        plan = VaultWritePreflightInput.model_validate(raw_plan).model_dump(exclude_none=True)
    except Exception as exc:
        return raw_plan, [f"invalid structured preflight: {exc}"]

    errors: list[str] = []
    canonical = plan["canonical_destination"].strip("/")
    candidates = [candidate.strip("/") for candidate in plan["candidate_destinations"]]
    entity_area = plan["entity_area"].strip("/")
    source = str(context.get("source") or "").strip("/")
    actual_path = str(context.get("destination") or context.get("path") or source).strip("/")
    content = str(context.get("proposed_content") or "")

    for value, label in ((canonical, "canonical_destination"), (entity_area, "entity_area"), (actual_path, "path")):
        parts = PurePosixPath(value).parts
        if not value or value.startswith("/") or ".." in parts or "." in parts:
            errors.append(f"{label} must be a normalized vault-relative path")

    if canonical != actual_path:
        errors.append("canonical_destination does not match the actual tool path")
    if len(candidates) != 1 or candidates[0] != canonical:
        errors.append("destination is ambiguous; exactly one canonical candidate is required")
    if not (canonical == entity_area or canonical.startswith(f"{entity_area}/")):
        errors.append("canonical_destination is outside the resolved entity/Area owner")
    if plan["confidence"] < 0.80:
        errors.append("confidence below 0.80; resolve context or ask one question before writing")

    parts = PurePosixPath(canonical).parts
    root = parts[0] if parts else ""
    capability = plan["capability"]
    allowed_roots = {
        "capture": {"01-input"},
        "business": {"04-areas"},
        "brand": {"04-areas"},
        "content": {"04-areas"},
        "operations": {"04-areas"},
        "knowledge": {"05-knowledge"},
        "research": {"05-knowledge"},
        "life": {"06-life"},
        "people": {"06-life"},
        "media": {"04-areas", "05-knowledge"},
    }
    if capability in {"task", "self-improvement"}:
        owner = "Notion task owner" if capability == "task" else "proposal-only owner scope"
        errors.append(f"{capability} cannot mutate Obsidian through this gateway; route to {owner}")
    elif root not in allowed_roots.get(capability, set()):
        errors.append(f"capability '{capability}' does not own destination root '{root}'")
    if root == "04-areas" and len(PurePosixPath(entity_area).parts) != 2:
        errors.append("business/creator writes require an exact current Area root: 04-areas/<slug>")
    if capability == "people" and not entity_area.startswith("06-life/people"):
        errors.append("people content must resolve to the People owner under 06-life")
    if capability == "media" and not plan.get("provenance"):
        errors.append("media writes require provenance (source URL, receipt, or SHA-256 identity)")

    before_path = source if operation == "vault_move" else actual_path
    before = snapshot_path(before_path)
    before_checksum = before.get("checksum")
    destination_exists = snapshot_path(actual_path).get("checksum") is not None
    expected_operation = {
        "vault_write": "update" if destination_exists else "create",
        "vault_edit": "update",
        "vault_append": "append",
        "vault_move": "move",
        "vault_delete": "delete",
    }[operation]
    if plan["operation"] != expected_operation:
        errors.append(f"operation must be '{expected_operation}' for the current target state")
    if expected_operation in {"append", "update", "delete", "move"} and before_checksum is None:
        errors.append("required preimage does not exist")
    if expected_operation in {"create", "move"} and destination_exists:
        errors.append("destination already exists; no-overwrite preflight failed")

    expected_preimage = "absent" if expected_operation == "create" else (
        f"sha256:{before_checksum}" if before_checksum else "sha256:<missing>"
    )
    if plan["preimage_requirement"] != expected_preimage:
        errors.append("preimage_requirement does not match the current file SHA-256/state")
    expected_rollback = {
        "create": f"delete-if-postimage:{canonical}",
        "append": f"restore-preimage:{canonical}",
        "update": f"restore-preimage:{canonical}",
        "move": f"move-back:{canonical}->{source}",
        "delete": f"restore-from-trash:{canonical}",
    }[expected_operation]
    if plan["rollback_target"] != expected_rollback:
        errors.append("rollback_target does not match the exact operation target")

    is_index = _is_index_path(canonical)
    file_kind = plan["file_kind"]
    needs_atomic = _requires_atomic_note(content)
    if is_index and needs_atomic:
        errors.append("README/index/hub cannot contain an atomic brief; create an atomic note and append only its link")
    if is_index and file_kind not in {"quick-seed-register", "index-link"}:
        errors.append("README/index/hub accepts only a quick-seed register entry or an atomic-note link")
    if file_kind in {"quick-seed-register", "index-link"} and not is_index:
        errors.append("register/link file_kind requires the resolved existing README/index/hub")
    if file_kind == "quick-seed-register" and expected_operation != "append":
        errors.append("a quick seed must append to an existing ordered register")
    if capability == "content" and not needs_atomic and file_kind == "atomic-note":
        errors.append("a short content seed without lifecycle must append to the ordered register")
    if needs_atomic and file_kind != "atomic-note":
        errors.append("brief/lifecycle content requires file_kind atomic-note")
    if file_kind == "atomic-note" and is_index:
        errors.append("atomic-note cannot target README/index/hub")
    if operation == "vault_write":
        supplied_expected = context.get("expected_sha256")
        if expected_operation == "update" and supplied_expected != before_checksum:
            errors.append("expected_sha256 must match the validated preimage")

    return plan, list(dict.fromkeys(errors))


def _parse_tool_result(result: str) -> dict:
    """Parse a tool's JSON result into a dict, or {} when it is not a JSON object."""
    try:
        payload = json.loads(result)
    except (ValueError, TypeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _run_audited(operation: str, func, **context) -> str:
    """Run a tool and emit audit records when auditing covers this operation.

    A straight passthrough when auditing is off (no log path) or the operation is a read
    and read-audit is disabled, so there is no cost on the default path. For mutations the
    target is snapshotted (size + checksum) before and after; reads capture the target as
    it is read. Batch mutations emit one record per file (see _run_audited_batch). An
    audit-write failure is swallowed inside write_audit_record so the trail can never break
    the tool result.
    """
    if operation in _PREFLIGHT_REQUIRED_OPERATIONS:
        plan, errors = _validate_write_preflight(operation, context)
        if errors:
            return _preflight_block(operation, plan, errors)

    rate_limit = check_tool_rate_limit(operation)
    if rate_limit is not None:
        result = json.dumps({
            "error": "Rate limit exceeded",
            "retry_after_seconds": rate_limit,
        })
        if should_audit_operation(operation):
            target_path = infer_target_path(operation, context)
            before = (
                snapshot_path(before_target_path(operation, context))
                if operation in MUTATION_OPERATIONS
                else None
            )
            write_audit_record(build_audit_record(
                operation=operation,
                target_path=target_path,
                before=before,
                after=before if operation in MUTATION_OPERATIONS else None,
                operation_status="error",
                error="Rate limit exceeded",
            ))
        return result

    audited = should_audit_operation(operation)
    is_mutation = operation in MUTATION_OPERATIONS
    if not audited and not is_mutation:
        return func()

    if operation in BATCH_OPERATIONS and audited:
        return _run_audited_batch(operation, func, context)

    before = snapshot_path(before_target_path(operation, context)) if is_mutation else None
    before_text = snapshot_text(before_target_path(operation, context)) if is_mutation else None

    try:
        result = func()
    except Exception:
        if audited:
            write_audit_record(build_audit_record(
                operation=operation,
                target_path=infer_target_path(operation, context),
                before=before,
                operation_status="error",
                error="tool exception",
            ))
        raise

    parsed = _parse_tool_result(result)
    target_path = infer_target_path(operation, context, parsed)
    status = "error" if "error" in parsed else "success"
    error = parsed.get("error") if status == "error" else None
    if is_mutation:
        record = build_audit_record(
            operation=operation, target_path=target_path, before=before,
            after=snapshot_path(target_path), operation_status=status, error=error,
        )
        receipt = build_mutation_receipt(
            record,
            before_text,
            snapshot_text(target_path),
            context.get("mutation_context") if isinstance(context.get("mutation_context"), dict) else None,
        )
        persisted = persist_mutation_receipt(receipt, before_text)
        if receipt["rollback"]["status"] == "available" and not persisted:
            receipt["rollback"]["status"] = "unavailable"
            receipt["markdown"] = re.sub(
                r"(?m)^- Rollback:.*$",
                "- Rollback: unavailable because the private receipt store could not be written.",
                receipt["markdown"],
            )
        record["mutation_id"] = receipt["mutation_id"]
        record["fact_id_scheme"] = receipt["fact_id_scheme"]
        record["semantic_fact_ids"] = receipt["semantic_fact_ids"]
        record["source_identity"] = receipt["source_identity"]
    else:
        record = build_audit_record(
            operation=operation, target_path=target_path,
            before=snapshot_path(target_path), operation_status=status, error=error,
        )
    if audited:
        write_audit_record(record)
    return attach_mutation_receipt(result, receipt) if is_mutation else result


def _run_audited_batch(operation: str, func, context: dict) -> str:
    """Audit a batch mutation as one record per file with correct per-file status.

    The batch tools report per-file outcomes inside ``results`` (some files can fail while
    the call as a whole "succeeds"), so a single top-level record would both hide partial
    failures and lose per-file snapshots. Each file gets its own before/after snapshot and
    its own operation_status.
    """
    paths = [p for p in (context.get("paths") or []) if isinstance(p, str) and p]
    before_map = {p: snapshot_path(p) for p in paths}

    try:
        result = func()
    except Exception:
        for p in paths:
            write_audit_record(build_audit_record(
                operation=operation, target_path=p, before=before_map.get(p),
                operation_status="error", error="tool exception",
            ))
        raise

    parsed = _parse_tool_result(result)
    items = parsed.get("results")
    if not isinstance(items, list) or not items:
        # A tool-level failure (e.g. validation) before any per-file work ran.
        write_audit_record(build_audit_record(
            operation=operation, target_path=paths or None,
            operation_status="error" if "error" in parsed else "success",
            error=parsed.get("error"),
        ))
        return result

    for item in items:
        if not isinstance(item, dict):
            continue
        path = item.get("path")
        item_error = item.get("error")
        item_status = "error" if item_error else "success"
        before = before_map.get(path) if isinstance(path, str) else None
        after = snapshot_path(path) if (item_status == "success" and isinstance(path, str)) else None
        write_audit_record(build_audit_record(
            operation=operation, target_path=path, before=before, after=after,
            operation_status=item_status, error=item_error,
        ))
    return result


@mcp.tool(
    name="vault_read",
    description=(
        "Read one vault file with content, metadata and parsed YAML frontmatter. "
        "Archives are blocked by default; include_archives=true is explicit and receipted. "
        "Only .agents/skills/** and notice files are readable among hidden paths."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_read(path: str, include_archives: bool = False) -> str:
    """Read a file from the vault."""
    inp = VaultReadInput(path=path, include_archives=include_archives)
    return _run_audited(
        "vault_read",
        lambda: _vault_read(inp.path, inp.include_archives),
        path=inp.path,
    )


@mcp.tool(
    name="vault_batch_read",
    description=(
        "Read multiple vault files in one call and report missing files individually. "
        "Archives are blocked by default; include_archives=true is explicit and receipted."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_batch_read(
    paths: list[str], include_content: bool = True, include_archives: bool = False
) -> str:
    """Read multiple files at once."""
    inp = VaultBatchReadInput(
        paths=paths, include_content=include_content, include_archives=include_archives
    )
    return _run_audited(
        "vault_batch_read",
        lambda: _vault_batch_read(inp.paths, inp.include_content, inp.include_archives),
    )


@mcp.tool(
    name="vault_write",
    description=(
        "Create a file in the Obsidian vault without clobbering an existing note by default. "
        "Every replacement requires expected_sha256; overwrite=true never bypasses the "
        "version check. mutation.preflight is mandatory and is validated against the real "
        "owner, destination, file kind, preimage and rollback target. Supports frontmatter merging."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
)
def vault_write(
    path: str,
    content: str,
    mutation: VaultMutationContextInput,
    create_dirs: bool = True,
    merge_frontmatter: bool = False,
    overwrite: bool = False,
    expected_sha256: ExpectedSha256 | None = None,
) -> str:
    """Write a file to the vault."""
    inp = VaultWriteInput(
        path=path,
        content=content,
        create_dirs=create_dirs,
        merge_frontmatter=merge_frontmatter,
        overwrite=overwrite,
        expected_sha256=expected_sha256,
    )
    return _run_audited(
        "vault_write",
        lambda: _vault_write(
            inp.path,
            inp.content,
            inp.create_dirs,
            inp.merge_frontmatter,
            inp.overwrite,
            inp.expected_sha256,
        ),
        path=inp.path,
        proposed_content=inp.content,
        expected_sha256=inp.expected_sha256,
        mutation_context=mutation.model_dump(exclude_none=True),
    )


@mcp.tool(
    name="vault_write_binary",
    description="Write an allowed binary file (image or PDF) to the Obsidian vault from base64-encoded content. Enforces a media-type/extension allowlist and a size cap; writes atomically.",
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
)
def vault_write_binary(path: str, data: str, media_type: str, overwrite: bool = False, create_dirs: bool = True) -> str:
    """Write a base64-encoded binary file to the vault."""
    inp = VaultWriteBinaryInput(path=path, data=data, media_type=media_type, overwrite=overwrite, create_dirs=create_dirs)
    return _run_audited(
        "vault_write_binary",
        lambda: _vault_write_binary(
            inp.path,
            inp.data,
            inp.media_type,
            inp.overwrite,
            inp.create_dirs,
        ),
        path=inp.path,
    )


@mcp.tool(
    name="vault_edit",
    description=(
        "Patch an existing vault file with exact text replacements. Use this for token-efficient partial edits "
        "when only small fragments change; mutation.preflight is mandatory before a real write. "
        "Supports dry-run diff previews and avoids resending the full file."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
)
def vault_edit(
    path: str,
    edits: list[VaultEditOperationInput],
    mutation: VaultMutationContextInput,
    dry_run: bool = False,
) -> str:
    """Patch a file with exact text replacements."""
    inp = VaultEditInput(path=path, edits=edits, dry_run=dry_run)
    if inp.dry_run:
        # A dry run writes nothing; don't record it as a mutation.
        return _vault_edit(inp.path, [edit.model_dump() for edit in inp.edits], inp.dry_run)
    return _run_audited(
        "vault_edit",
        lambda: _vault_edit(inp.path, [edit.model_dump() for edit in inp.edits], inp.dry_run),
        path=inp.path,
        proposed_content="\n".join(edit.new_text for edit in inp.edits),
        mutation_context=mutation.model_dump(exclude_none=True),
    )


@mcp.tool(
    name="vault_append",
    description=(
        "Append content to a vault file without sending the existing file body. Use this for token-efficient "
        "additions. mutation.preflight is mandatory; quick seeds append to an existing register, "
        "while briefs must use an atomic note."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
)
def vault_append(
    path: str,
    content: str,
    mutation: VaultMutationContextInput,
    separator: str = "\n\n",
    create_dirs: bool = True,
) -> str:
    """Append content to a file."""
    inp = VaultAppendInput(path=path, content=content, separator=separator, create_dirs=create_dirs)
    return _run_audited(
        "vault_append",
        lambda: _vault_append(inp.path, inp.content, inp.separator, inp.create_dirs),
        path=inp.path,
        proposed_content=inp.content,
        mutation_context=mutation.model_dump(exclude_none=True),
    )


@mcp.tool(
    name="vault_batch_frontmatter_update",
    description="Update YAML frontmatter fields on multiple files without changing body content. Each update merges new fields into existing frontmatter.",
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": False},
)
def vault_batch_frontmatter_update(updates: list[FrontmatterUpdateInput]) -> str:
    """Batch update frontmatter fields."""
    inp = VaultBatchFrontmatterUpdateInput(updates=updates)
    update_data = [update.model_dump() for update in inp.updates]
    return _run_audited(
        "vault_batch_frontmatter_update",
        lambda: _vault_batch_frontmatter_update(update_data),
        paths=[update.path for update in inp.updates],
    )


@mcp.tool(
    name="vault_search",
    description=(
        "Search vault text with at most 100 results and 10 context lines per match. "
        "Returns matching lines and frontmatter excerpts; archives are excluded by "
        "default and included only with include_archives=true."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_search(
    query: str,
    path_prefix: str | None = None,
    file_pattern: str = "*.md",
    max_results: int = 20,
    context_lines: int = 2,
    include_archives: bool = False,
) -> str:
    """Search vault file contents."""
    inp = VaultSearchInput(
        query=query,
        path_prefix=path_prefix,
        file_pattern=file_pattern,
        max_results=max_results,
        context_lines=context_lines,
        include_archives=include_archives,
    )
    return _run_audited(
        "vault_search",
        lambda: _vault_search(
            inp.query,
            inp.path_prefix,
            inp.file_pattern,
            inp.max_results,
            inp.context_lines,
            inp.include_archives,
        ),
    )


@mcp.tool(
    name="vault_search_frontmatter",
    description=(
        "Search the revalidated in-memory frontmatter index with exact, contains or "
        "field-exists matching and at most 100 results. Archives are excluded by "
        "default and included only with include_archives=true."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_search_frontmatter(
    field: str,
    value: str = "",
    match_type: FrontmatterMatchType = "exact",
    path_prefix: str | None = None,
    max_results: int = 20,
    include_archives: bool = False,
) -> str:
    """Search by frontmatter fields."""
    inp = VaultSearchFrontmatterInput(
        field=field,
        value=value,
        match_type=match_type,
        path_prefix=path_prefix,
        max_results=max_results,
        include_archives=include_archives,
    )
    return _run_audited(
        "vault_search_frontmatter",
        lambda: _vault_search_frontmatter(
            inp.field,
            inp.value,
            inp.match_type,
            inp.path_prefix,
            inp.max_results,
            inp.include_archives,
        ),
    )


@mcp.tool(
    name="vault_list",
    description=(
        "List vault contents with recursion depth, file/directory filters and glob "
        "patterns. Hidden secret/runtime surfaces and archives are excluded by default; "
        "archives require include_archives=true."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_list(
    path: str = "",
    depth: int = 1,
    include_files: bool = True,
    include_dirs: bool = True,
    pattern: str | None = None,
    include_archives: bool = False,
) -> str:
    """List vault directory contents."""
    inp = VaultListInput(
        path=path,
        depth=depth,
        include_files=include_files,
        include_dirs=include_dirs,
        pattern=pattern,
        include_archives=include_archives,
    )
    return _run_audited(
        "vault_list",
        lambda: _vault_list(
            inp.path,
            inp.depth,
            inp.include_files,
            inp.include_dirs,
            inp.pattern,
            inp.include_archives,
        ),
        path=inp.path,
    )


@mcp.tool(
    name="vault_move",
    description="Move a file or directory within the vault. Requires mutation.preflight and validates both source and destination paths, owner, preimage and rollback target.",
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
)
def vault_move(
    source: str,
    destination: str,
    mutation: VaultMutationContextInput,
    create_dirs: bool = True,
) -> str:
    """Move a file or directory."""
    inp = VaultMoveInput(source=source, destination=destination, create_dirs=create_dirs)
    return _run_audited(
        "vault_move",
        lambda: _vault_move(inp.source, inp.destination, inp.create_dirs),
        source=inp.source,
        destination=inp.destination,
        mutation_context=mutation.model_dump(exclude_none=True),
    )


@mcp.tool(
    name="vault_delete",
    description="Delete a file by moving it to .trash/ in the vault root. Requires mutation.preflight plus confirm=true. Does NOT hard delete.",
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
)
def vault_delete(path: str, mutation: VaultMutationContextInput, confirm: bool = False) -> str:
    """Delete a file (move to .trash/)."""
    inp = VaultDeleteInput(path=path, confirm=confirm)
    return _run_audited(
        "vault_delete",
        lambda: _vault_delete(inp.path, inp.confirm),
        path=inp.path,
        mutation_context=mutation.model_dump(exclude_none=True),
    )


@mcp.tool(
    name="vault_canvas_read",
    description="Read an Obsidian .canvas file and return its parsed nodes and edges.",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_canvas_read(path: str) -> str:
    """Read an Obsidian Canvas file."""
    inp = VaultCanvasReadInput(path=path)
    return _run_audited("vault_canvas_read", lambda: _vault_canvas_read(inp.path), path=inp.path)


@mcp.tool(
    name="vault_canvas_add_node",
    description=(
        "Append a node to an Obsidian .canvas file, creating the file if it does not exist. Requires type, x, y, "
        "width, height; an alphanumeric id is generated when omitted. Unknown node fields are preserved."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
)
def vault_canvas_add_node(path: str, node: CanvasNodeInput) -> str:
    """Append a node to a Canvas file."""
    inp = VaultCanvasAddNodeInput(path=path, node=node)
    return _run_audited(
        "vault_canvas_add_node",
        lambda: _vault_canvas_add_node(inp.path, inp.node.model_dump(exclude_none=True, mode="json")),
        path=inp.path,
    )


@mcp.tool(
    name="vault_canvas_add_edge",
    description=(
        "Append an edge to an existing Obsidian .canvas file. Requires fromNode, toNode, and fromSide/toSide "
        "(top, right, bottom, left); both endpoints must reference existing node ids. An alphanumeric id is "
        "generated when omitted."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
)
def vault_canvas_add_edge(path: str, edge: CanvasEdgeInput) -> str:
    """Append an edge to a Canvas file."""
    inp = VaultCanvasAddEdgeInput(path=path, edge=edge)
    return _run_audited(
        "vault_canvas_add_edge",
        lambda: _vault_canvas_add_edge(inp.path, inp.edge.model_dump(exclude_none=True, mode="json")),
        path=inp.path,
    )


@mcp.tool(
    name="vault_daily_note_path",
    description=(
        "Return an arbitrary ISO-date daily-note path using Europe/Rome when date is "
        "omitted. Derived from the configured folder and format; never reads or creates."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_daily_note_path(date: str | None = None) -> str:
    """Resolve a Europe/Rome daily-note path; omit date for today."""
    return _vault_daily_note_path(date)


@mcp.tool(
    name="vault_daily_note_read",
    description=(
        "Read an arbitrary ISO-date daily note, using Europe/Rome when date is omitted. "
        "Returns an error payload and never creates a missing note."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_daily_note_read(date: str | None = None) -> str:
    """Read an arbitrary Europe/Rome daily note; omit date for today."""
    return _run_audited("vault_daily_note_read", lambda: _vault_daily_note_read(date))


@mcp.tool(
    name="vault_daily_note_read_range",
    description=(
        "Read an inclusive Europe/Rome daily-note date range. The range is limited "
        "to 31 days, 20,000 characters per file and 80,000 characters total."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_daily_note_read_range(
    start_date: str,
    end_date: str,
    max_chars_per_file: Annotated[int, Field(ge=1, le=20000)] = 8000,
    total_chars: Annotated[int, Field(ge=1, le=80000)] = 40000,
) -> str:
    """Read a bounded inclusive daily-note range."""
    return _run_audited(
        "vault_daily_note_read_range",
        lambda: _vault_daily_note_read_range(
            start_date, end_date, max_chars_per_file, total_chars
        ),
    )


@mcp.tool(
    name="vault_daily_note_append",
    description="Append content to today's daily note, creating it from VAULT_DAILY_NOTES_TEMPLATE when missing. Token-efficient daily logging without resending the note body.",
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
)
def vault_daily_note_append(content: str) -> str:
    """Append to today's daily note."""
    inp = VaultDailyNoteAppendInput(content=content)
    return _run_audited(
        "vault_daily_note_append",
        lambda: _vault_daily_note_append(inp.content),
        path=_daily_note_path(_today()),
    )


@mcp.tool(
    name="vault_bootstrap_status",
    description=(
        "Return the server-applied bootstrap status and hashes for AGENTS.md and "
        "the vault operating model. Policy bodies remain server-side; degraded or "
        "missing files are explicit."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_bootstrap_status() -> str:
    """Return the hash-bound bootstrap policy receipt."""
    return dumps(_bootstrap_status())


@mcp.tool(
    name="vault_context_route",
    description=(
        "Classify a request deterministically and return required, selected, missing, "
        "skipped and duplicate paths plus archive, link, policy, index and Europe/Rome date receipts."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_context_route(
    request: Annotated[str, Field(min_length=1, max_length=4000)],
    reference_date: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    include_archives: bool = False,
) -> str:
    """Return a body-free deterministic context route."""
    try:
        return dumps(_route_context(
            request,
            frontmatter_index,
            reference_date=reference_date,
            start_date=start_date,
            end_date=end_date,
            include_archives=include_archives,
        ))
    except ValueError as exc:
        return dumps({"error": str(exc)})


@mcp.tool(
    name="vault_context_read",
    description=(
        "Route and read context in metadata, snippets, sections or full mode. "
        "Hard limits: 20 files, 20,000 characters per file and 80,000 total; "
        "archives remain excluded unless explicitly included."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_context_read(
    request: Annotated[str, Field(min_length=1, max_length=4000)],
    mode: Literal["metadata", "snippets", "sections", "full"] = "sections",
    max_files: Annotated[int, Field(ge=1, le=20)] = 12,
    max_chars_per_file: Annotated[int, Field(ge=1, le=20000)] = 8000,
    total_chars: Annotated[int, Field(ge=1, le=80000)] = 40000,
    reference_date: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    include_archives: bool = False,
) -> str:
    """Return bounded routed context with a complete selection receipt."""
    try:
        return dumps(_read_context(
            request,
            frontmatter_index,
            mode=mode,
            max_files=max_files,
            max_chars_per_file=max_chars_per_file,
            total_chars=total_chars,
            reference_date=reference_date,
            start_date=start_date,
            end_date=end_date,
            include_archives=include_archives,
        ))
    except ValueError as exc:
        return dumps({"error": str(exc)})


@mcp.tool(
    name="vault_context_proposal",
    description=(
        "Produce a proposal-only plan for sensitive personal context. This tool never "
        "writes the vault, Notion or Calendar; apply is a separate, fresh-SHA step."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_context_proposal(
    request: Annotated[str, Field(min_length=1, max_length=4000)],
    reference_date: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
) -> str:
    """Return a no-write proposal or an immediate-safety handoff."""
    try:
        return dumps(_propose_context(
            request,
            frontmatter_index,
            reference_date=reference_date,
            start_date=start_date,
            end_date=end_date,
        ))
    except ValueError as exc:
        return dumps({"error": str(exc), "write_executed": False})


@mcp.tool(
    name="vault_analytics_summary",
    description=(
        "Return a compact analytics summary for vault hygiene, including frontmatter, link, tag, and encoding "
        "findings. Read-only; scoped to an optional folder prefix."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_analytics_summary(
    path_prefix: str | None = None,
    required_frontmatter: list[str] | None = None,
    max_examples: int = 3,
) -> str:
    """Return a compact analytics summary for vault hygiene."""
    inp = VaultAnalyticsSummaryInput(
        path_prefix=path_prefix,
        required_frontmatter=required_frontmatter,
        max_examples=max_examples,
    )
    return _vault_analytics_summary(inp.path_prefix or "", inp.required_frontmatter, inp.max_examples)


@mcp.tool(
    name="vault_analytics_findings",
    description=(
        "Return detailed findings for one vault analytics category: frontmatter_missing, "
        "required_frontmatter_missing, broken_wikilinks, suspicious_tag_variants, encoding_issues, "
        "or oversized_files. Read-only."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_analytics_findings(
    category: AnalyticsFindingCategory,
    path_prefix: str | None = None,
    required_frontmatter: list[str] | None = None,
    max_results: int = 50,
) -> str:
    """Return detailed findings for one analytics category."""
    inp = VaultAnalyticsFindingsInput(
        category=category,
        path_prefix=path_prefix,
        required_frontmatter=required_frontmatter,
        max_results=max_results,
    )
    return _vault_analytics_findings(
        inp.category,
        inp.path_prefix or "",
        inp.required_frontmatter,
        inp.max_results,
    )


_CONTEXT_PROFILE_TOOLS = frozenset({
    "vault_bootstrap_status",
    "vault_context_route",
    "vault_context_read",
    "vault_context_proposal",
    "vault_daily_note_read_range",
    "vault_read",
    "vault_batch_read",
    "vault_search",
    "vault_search_frontmatter",
    "vault_list",
    "vault_write",
    "vault_edit",
    "vault_append",
    "vault_move",
    "vault_delete",
})


def context_profile_tool_names() -> set[str]:
    """Return the stable ChatGPT-facing context profile without mutating registration."""
    return set(_CONTEXT_PROFILE_TOOLS)


def _apply_public_tool_profile() -> str:
    """Apply a reversible public exposure profile after all implementations register."""
    profile = os.environ.get("VAULT_PUBLIC_TOOL_PROFILE", "full").strip().lower() or "full"
    if profile not in {"full", "context"}:
        raise ValueError("VAULT_PUBLIC_TOOL_PROFILE must be 'full' or 'context'")
    if profile == "context":
        for name in list(mcp._tool_manager._tools):
            if name not in _CONTEXT_PROFILE_TOOLS:
                mcp.remove_tool(name)
    return profile


def build_app(extensions=()):
    """Assemble the authenticated Starlette app served to clients.

    MCP transport + OAuth routes + (off-root only) the unauthenticated spec probe
    at GET/HEAD / + any extension routes + the bearer-auth middleware. Extracted
    from main() so the exact composition that serves the vault can be exercised
    end-to-end in tests, rather than only the validation helper.

    extensions: optional iterable of extensions.Extension instances; each
    register_routes(app) runs before the auth middleware is attached, so extension
    routes are bearer-protected. A route that collides with an auth-exempt path is
    rejected (fail closed) so an extension cannot expose an unauthenticated endpoint.
    """
    from starlette.responses import JSONResponse, Response
    from starlette.routing import Route

    from .auth import BearerAuthMiddleware
    from .oauth import oauth_routes

    app = mcp.streamable_http_app()

    # MCP spec 2025-06-18 probe: GET/HEAD / answers with the protocol version.
    # Only mount it when MCP is NOT at root -- otherwise the transport owns
    # GET/HEAD / and this route would shadow it. (auth.py exempts GET/HEAD /
    # from bearer auth under the same VAULT_MCP_PATH != "/" guard.)
    if VAULT_MCP_PATH != "/":
        async def mcp_root_probe(request):
            return Response(
                status_code=200,
                headers={"MCP-Protocol-Version": "2025-06-18"},
            )

        app.routes.insert(0, Route("/", mcp_root_probe, methods=["GET", "HEAD"]))

    # Mount OAuth routes (these are excluded from bearer auth via the middleware)
    for route in oauth_routes:
        app.routes.insert(0, route)

    # Health endpoint (bearer-exempt, see auth._AUTH_EXEMPT_PATHS). Surfaces audit status
    # so an operator can confirm the log is enabled and being written.
    async def health(_request):
        # Unauthenticated and reachable over the public tunnel, so keep it to liveness:
        # report only whether auditing is on -- never the log path or write counters,
        # which would leak the host filesystem layout and a vault-activity side-channel.
        return JSONResponse({"status": "ok", "audit": {"enabled": audit_enabled()}})

    app.routes.insert(0, Route("/health", health, methods=["GET"]))

    # Extension routes (e.g. a localhost search endpoint), added before the auth
    # middleware so they are bearer-protected like the MCP transport.
    #
    # TRUST MODEL: extensions are fully-trusted, in-process code the operator passes
    # to serve(). They can do anything the server can (read VAULT_MCP_TOKEN, touch the
    # vault, mutate any route). This is NOT a sandbox and CANNOT stop a hostile
    # extension. The check below is a best-effort FOOTGUN guard for honest authors: it
    # fails closed when a newly-added route would land on an auth-exempt path (which
    # the bearer middleware skips before routing) and would thus be served
    # unauthenticated. It does not (and cannot) defend against an extension that
    # mutates an existing route in place, opens a raw socket, etc.
    from starlette.routing import Match, Mount, WebSocketRoute

    from .auth import _AUTH_EXEMPT_METHOD_PATHS, _AUTH_EXEMPT_PATHS

    extensions = tuple(extensions)
    before_ids = {id(r) for r in app.routes}
    for ext in extensions:
        ext.register_routes(app)
    ext_routes = [r for r in app.routes if id(r) not in before_ids]

    def _covers(route, method, path):
        """Match enum for route vs (method, path); NONE if the probe can't run."""
        try:
            match, _ = route.matches(
                {"type": "http", "method": method, "path": path, "headers": []}
            )
            return match
        except Exception:
            logger.warning(
                "extension route %r could not be auth-checked; allowing "
                "(trusted-extension model)", getattr(route, "path", route)
            )
            return Match.NONE

    for r in ext_routes:
        # Footguns: a Mount can shadow an exempt prefix; a WebSocketRoute isn't covered
        # by the HTTP bearer middleware at all. Reject both with a clear error.
        if isinstance(r, (Mount, WebSocketRoute)):
            raise ValueError(
                f"extension {type(r).__name__} is not allowed: it can serve an "
                "unauthenticated surface -- register plain HTTP Routes instead"
            )
        # Method-AGNOSTIC exempt paths: the whole path is unauthenticated, so ANY
        # coverage (PARTIAL = path matches even if method differs, or FULL) is unsafe.
        for p in _AUTH_EXEMPT_PATHS:
            if _covers(r, "GET", p) is not Match.NONE:
                raise ValueError(
                    f"extension route {getattr(r, 'path', r)!r} covers auth-exempt path "
                    f"{p!r}; it would be served without bearer authentication"
                )
        # Method-SPECIFIC exempt pairs (e.g. GET/HEAD / probe when off-root): only a
        # FULL match of that exact method+path is unsafe -- a POST / route is fine.
        for m, p in _AUTH_EXEMPT_METHOD_PATHS:
            if _covers(r, m, p) is Match.FULL:
                raise ValueError(
                    f"extension route {getattr(r, 'path', r)!r} covers auth-exempt "
                    f"{m} {p!r}; it would be served without bearer authentication"
                )
    app.add_middleware(BearerAuthMiddleware)
    return app


def main():
    """Console-script entry point: run the stock server with no extensions."""
    serve()


def serve(extensions=()):
    """Run the server with the streamable HTTP transport.

    extensions: optional iterable of extensions.Extension instances. A custom
    deployment calls serve([MyExtension()]) from its own entry point to add tools,
    routes, and index hooks without forking this module. With no extensions the
    behavior is identical to the stock server.
    """
    extensions = tuple(extensions)  # consumed multiple times; never a generator
    # The historical 13-tool Life OS/Poke contract is opt-in so donor tests and
    # stock deployments retain their focused stock surface. The canonical MiniPC candidate
    # enables it inside this same process; no second HTTP MCP server is started.
    if os.environ.get("VAULT_ENABLE_LIFEOS_COMPAT", "").strip() == "1":
        from .legacy.extension import LegacyLifeOsExtension
        extensions = (LegacyLifeOsExtension(), *extensions)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )

    if not VAULT_PATH.is_dir():
        logger.error(f"Vault path does not exist: {VAULT_PATH}")
        sys.exit(1)

    # Validate operator config before serving; fail CLOSED on a bad value.
    try:
        from .config import validate_config
        validate_config()
    except ValueError as e:
        logger.error(f"Invalid configuration: {e}")
        sys.exit(1)

    if not VAULT_MCP_TOKEN:
        logger.warning("VAULT_MCP_TOKEN is not set -- auth will reject all requests")

    # Fail CLOSED on a misconfigured audit log: if auditing is requested but the log path
    # is not writable, refuse to start rather than silently dropping mutation records.
    if audit_enabled() and not audit_path_writable():
        logger.error(f"VAULT_AUDIT_LOG_PATH is not writable: {audit_log_path()}")
        sys.exit(1)
    # Fail CLOSED on an audit log that resolves inside the vault: the vault tools could
    # then overwrite or delete it, defeating the append-only integrity premise.
    if audit_enabled() and audit_path_inside_vault():
        logger.error(
            f"VAULT_AUDIT_LOG_PATH resolves inside the vault ({audit_log_path()}); "
            "the vault tools could rewrite it. Choose a path outside VAULT_PATH."
        )
        sys.exit(1)
    if audit_enabled():
        logger.info(
            "Audit log enabled: %s (reads included: %s)",
            audit_log_path(),
            VAULT_AUDIT_LOG_INCLUDE_READS,
        )

    # Extension setup: register tools BEFORE the app/tool-schema is built, and let
    # each extension prepare before the frontmatter index starts (e.g. attach a
    # change listener so no change is missed between build and listener attach).
    for ext in extensions:
        ext.register_tools(mcp)
        ext.before_indexes_start(frontmatter_index)

    try:
        public_profile = _apply_public_tool_profile()
    except ValueError as e:
        logger.error("Invalid public tool profile: %s", e)
        sys.exit(1)
    logger.info(
        "Public tool profile: %s (%d tools)",
        public_profile,
        len(mcp._tool_manager._tools),
    )

    # Keep mutation results and frontmatter search in the same consistency window.
    # The watcher remains a recovery path for external edits.
    register_write_listener(frontmatter_index.sync_write)

    # Build the frontmatter index ONCE, before serving. With stateless_http the
    # per-request MCP lifespan would otherwise rebuild it on every request (#28).
    logger.info(f"Starting vault MCP server. Vault: {VAULT_PATH}")
    frontmatter_index.start()
    atexit.register(frontmatter_index.stop)

    # After the index is built and watching: extensions can start dependent work
    # (e.g. a reconcile loop). shutdown() is registered last so atexit (LIFO) runs
    # it BEFORE frontmatter_index.stop().
    for ext in extensions:
        ext.after_indexes_start(frontmatter_index)
        atexit.register(ext.shutdown)

    # Optional liveness heartbeat. Daemon thread tied to the process (not the
    # per-request lifespan), started only when configured. Validated here so a bad
    # URL scheme or interval fails CLOSED instead of booting silently broken.
    try:
        from .config import validate_heartbeat
        heartbeat_interval = validate_heartbeat()
    except ValueError as e:
        logger.error(f"Invalid heartbeat configuration: {e}")
        sys.exit(1)
    if heartbeat_interval is not None:
        threading.Thread(
            target=_heartbeat_forever,
            args=(VAULT_MCP_HEARTBEAT_URL, heartbeat_interval),
            daemon=True,
            name="heartbeat",
        ).start()
        logger.info("Heartbeat enabled (interval: %ds)", heartbeat_interval)

    # Build the Starlette app with auth middleware and OAuth endpoints
    try:
        app = build_app(extensions)
        logger.info(f"Starting server on {VAULT_MCP_HOST}:{VAULT_MCP_PORT} with bearer auth + OAuth")
    except Exception as e:
        # Fail CLOSED: never fall back to an unauthenticated server.
        logger.error(f"Could not build the authenticated app: {e}")
        sys.exit(1)

    import uvicorn
    uvicorn.run(
        app,
        host=VAULT_MCP_HOST,
        port=VAULT_MCP_PORT,
        log_level="info",
        # Honor X-Forwarded-* ONLY from the trusted loopback proxy (Cloudflare
        # Tunnel / Caddy), never from arbitrary clients. Trusting "*" let any
        # caller spoof the advertised OAuth origin via X-Forwarded-Host.
        proxy_headers=True,
        forwarded_allow_ips=VAULT_MCP_FORWARDED_ALLOW_IPS,
    )


if __name__ == "__main__":
    main()
