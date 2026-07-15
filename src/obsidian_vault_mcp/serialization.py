"""JSON serialization helpers for the Obsidian vault MCP server.

python-frontmatter parses YAML date fields into Python date/datetime objects,
which the stdlib json encoder can't handle. This module provides a drop-in
replacement for json.dumps that serializes those types as ISO 8601 strings (#5).

It is also the single place that controls how each tool serializes its result
payload, so all tool modules should route through dumps() rather than calling
json.dumps directly. Two defaults make responses token-efficient:

- ensure_ascii=False: non-ASCII text (Korean, Japanese, emoji, etc.) is emitted
  verbatim as UTF-8 instead of \\uXXXX escapes. The default True roughly doubled
  the size of a CJK-heavy response (and up to tripled it for non-BMP emoji, which
  escape to 12-character surrogate pairs), and produced escaped paths that could
  fail to round-trip. The decoded object is identical either way; ASCII-only
  responses are unaffected.
- compact separators: drops the spaces after ',' and ':' that json.dumps inserts
  by default. Responses are consumed by a model, not read raw, so that whitespace
  is pure overhead.

Callers may override either default by passing the keyword explicitly.
"""

import json
import logging
from datetime import date, datetime

from .config import MAX_TOOL_RESULT_BYTES, MIN_TOOL_RESULT_BYTES

logger = logging.getLogger(__name__)


class _VaultEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        return super().default(obj)


_SUMMARY_KEYS = (
    "path",
    "source",
    "destination",
    "changed",
    "created",
    "moved",
    "deleted",
    "dry_run",
    "size",
    "edits_applied",
    "found",
    "missing",
    "total",
    "total_matches",
)


def _overflow_summary(obj) -> dict:
    """Keep only bounded scalar status fields from an omitted result.

    This preserves mutation truth (for example ``changed=true``) without
    accidentally copying a large body, diff, error string, or nested payload
    into the overflow envelope.
    """
    if not isinstance(obj, dict):
        return {}

    summary = {}
    for key in _SUMMARY_KEYS:
        value = obj.get(key)
        if isinstance(value, (bool, int, float)):
            summary[key] = value
        elif isinstance(value, str):
            try:
                encoded = value.encode("utf-8")
            except UnicodeEncodeError:
                continue
            if len(encoded) <= 256:
                summary[key] = value

    for source_key, count_key in (("nodes", "node_count"), ("edges", "edge_count")):
        value = obj.get(source_key)
        if isinstance(value, list):
            summary[count_key] = len(value)
    return summary


def _overflow_result(obj, *, actual_bytes: int, max_bytes: int) -> str:
    original_had_error = isinstance(obj, dict) and "error" in obj
    envelope = {
        "result_omitted": True,
        "reason": "tool_result_too_large",
        "original_status": "error" if original_had_error else "success",
        "actual_bytes": actual_bytes,
        "max_bytes": max_bytes,
        "summary": _overflow_summary(obj),
    }
    if original_had_error:
        # Preserve error semantics for auditing without reflecting an unbounded
        # exception string or other sensitive detail.
        envelope["error"] = "Original tool error details exceeded the result byte limit"

    result = json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))
    if len(result.encode("utf-8")) <= max_bytes:
        return result

    # Defensive fallback. With the validated 1 KiB minimum this fixed envelope
    # is comfortably bounded even if a future summary field grows unexpectedly.
    minimal = {
        "result_omitted": True,
        "reason": "tool_result_too_large",
        "original_status": envelope["original_status"],
        "actual_bytes": actual_bytes,
        "max_bytes": max_bytes,
    }
    if original_had_error:
        minimal["error"] = "Original tool error details exceeded the result byte limit"
    return json.dumps(minimal, ensure_ascii=False, separators=(",", ":"))


def dumps(obj, *, max_bytes: int | None = None, **kwargs) -> str:
    """Serialize a bounded, UTF-8-safe JSON tool result.

    Small results are byte-for-byte compatible with the previous encoder. When
    the serialized UTF-8 payload exceeds the configured limit, return a compact
    valid-JSON envelope that says whether the original operation succeeded or
    failed and retains only bounded scalar status fields. This avoids reporting
    a successful mutation as an error merely because its response was large.
    """
    byte_limit = MAX_TOOL_RESULT_BYTES if max_bytes is None else max_bytes
    if byte_limit < MIN_TOOL_RESULT_BYTES:
        raise ValueError(f"max_bytes must be at least {MIN_TOOL_RESULT_BYTES}")

    kwargs.setdefault("ensure_ascii", False)
    kwargs.setdefault("separators", (",", ":"))
    result = json.dumps(obj, cls=_VaultEncoder, **kwargs)
    if not kwargs["ensure_ascii"]:
        # A filename that is not valid UTF-8 reaches us as a lone surrogate
        # (os.fsdecode uses surrogateescape). json.dumps accepts it, but the
        # resulting string then raises UnicodeEncodeError when the transport
        # encodes it to UTF-8 -- outside any tool's error handling. Fall back to
        # escaped output so one odd filename cannot crash an otherwise fine
        # response.
        try:
            result.encode("utf-8")
        except UnicodeEncodeError:
            logger.warning(
                "Response contains a non-UTF-8 (surrogate) string, likely from a "
                "filename that is not valid UTF-8; falling back to escaped output"
            )
            result = json.dumps(obj, cls=_VaultEncoder, **{**kwargs, "ensure_ascii": True})

    actual_bytes = len(result.encode("utf-8"))
    if actual_bytes <= byte_limit:
        return result
    return _overflow_result(obj, actual_bytes=actual_bytes, max_bytes=byte_limit)
