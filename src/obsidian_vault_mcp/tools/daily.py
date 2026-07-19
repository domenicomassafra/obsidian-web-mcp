"""Daily-note convenience tools.

Resolve, read, and append to a date-stamped daily note. The path is built from
the server's local date and three config knobs:

- ``VAULT_DAILY_NOTES_FOLDER``   directory for daily notes ("" = vault root)
- ``VAULT_DAILY_NOTES_FORMAT``   strftime pattern for the filename (default %Y-%m-%d)
- ``VAULT_DAILY_NOTES_TEMPLATE`` strftime template prepended when the note is first created

Pure filesystem: no plugin, no network. Writes go through the existing
``vault_append`` path (atomic write); paths go through ``resolve_vault_path``.
"""

import json
import logging
from datetime import date as Date, datetime, timedelta
from pathlib import PurePosixPath
from zoneinfo import ZoneInfo

from .. import config
from ..serialization import dumps
from ..vault import read_file, resolve_vault_path
from .write import vault_append

logger = logging.getLogger(__name__)
ROME = ZoneInfo("Europe/Rome")


def _today():
    """Return the current date in the Life OS canonical timezone."""
    return datetime.now(ROME).date()


def _parse_date(value: str | None):
    if value is None:
        return _today()
    try:
        return Date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("date must use ISO format YYYY-MM-DD") from exc


def _daily_note_path(for_date) -> str:
    """Build the configured daily-note path for a date."""
    filename = for_date.strftime(config.VAULT_DAILY_NOTES_FORMAT)
    if not filename.lower().endswith((".md", ".markdown")):
        filename = f"{filename}.md"
    folder = config.VAULT_DAILY_NOTES_FOLDER.strip().strip("/\\")
    if folder:
        return str(PurePosixPath(folder) / filename)
    return filename


def _initial_content(content: str, for_date) -> str:
    """Template (if any) prepended to the first content written to a new note."""
    template = for_date.strftime(config.VAULT_DAILY_NOTES_TEMPLATE)
    if not template:
        return content
    if content and not template.endswith("\n"):
        return f"{template}\n{content}"
    return f"{template}{content}"


def vault_daily_note_path(date: str | None = None) -> str:
    """Return a daily-note path for an arbitrary date in Europe/Rome."""
    try:
        day = _parse_date(date)
        path = _daily_note_path(day)
        resolve_vault_path(path)
        return dumps({
            "path": path,
            "date": day.isoformat(),
            "folder": config.VAULT_DAILY_NOTES_FOLDER,
            "format": config.VAULT_DAILY_NOTES_FORMAT,
            "timezone": "Europe/Rome",
        })
    except ValueError as e:
        return dumps({"error": str(e)})
    except Exception as e:
        logger.error(f"vault_daily_note_path error: {e}")
        return dumps({"error": str(e)})


def vault_daily_note_read(date: str | None = None) -> str:
    """Read a daily note. Returns an error payload when it does not exist
    (does not create it)."""
    try:
        day = _parse_date(date)
        path = _daily_note_path(day)
        content, metadata = read_file(path)
        return dumps({
            "path": path,
            "date": day.isoformat(),
            "timezone": "Europe/Rome",
            "content": content,
            "metadata": metadata,
        })
    except FileNotFoundError:
        return dumps({"error": f"Daily note not found: {path}", "path": path, "date": day.isoformat()})
    except ValueError as e:
        return dumps({"error": str(e)})
    except Exception as e:
        logger.error("vault_daily_note_read error: %s", e)
        return dumps({"error": str(e)})


def vault_daily_note_read_range(
    start_date: str,
    end_date: str,
    max_chars_per_file: int = 8000,
    total_chars: int = 40000,
) -> str:
    """Read an inclusive, bounded daily-note date range in Europe/Rome."""
    try:
        start = _parse_date(start_date)
        end = _parse_date(end_date)
        if end < start:
            raise ValueError("end_date must not be before start_date")
        days = (end - start).days + 1
        if days > 31:
            raise ValueError("daily-note range exceeds the declared 31-day limit")
        per_file = max(1, min(max_chars_per_file, 20000))
        total_limit = max(1, min(total_chars, 80000))
        notes = []
        missing = []
        chars = 0
        for offset in range(days):
            day = start + timedelta(days=offset)
            path = _daily_note_path(day)
            try:
                content, metadata = read_file(path)
            except FileNotFoundError:
                missing.append(day.isoformat())
                continue
            remaining = total_limit - chars
            if remaining <= 0:
                break
            body = content[: min(per_file, remaining)]
            chars += len(body)
            notes.append({
                "path": path,
                "date": day.isoformat(),
                "content": body,
                "metadata": metadata,
                "chars_returned": len(body),
                "truncated": len(body) < len(content),
            })
        return dumps({
            "timezone": "Europe/Rome",
            "date_range": {"start": start.isoformat(), "end": end.isoformat()},
            "declared_limits": {
                "max_days": 31,
                "max_chars_per_file": per_file,
                "total_chars": total_limit,
            },
            "notes": notes,
            "found": len(notes),
            "missing": missing,
            "chars_returned": chars,
        })
    except ValueError as e:
        return dumps({"error": str(e), "timezone": "Europe/Rome"})
    except Exception as e:
        logger.error("vault_daily_note_read_range error: %s", e)
        return dumps({"error": str(e), "timezone": "Europe/Rome"})
def vault_daily_note_append(content: str) -> str:
    """Append to today's daily note, creating it (with the template) when missing."""
    day = _today()
    path = _daily_note_path(day)
    try:
        try:
            read_file(path)
            created = False
            payload = content
        except FileNotFoundError:
            created = True
            payload = _initial_content(content, day)

        result = json.loads(vault_append(path, payload))
        if "error" not in result:
            result["date"] = day.isoformat()
            result["daily_note"] = True
            result["created"] = created
        return dumps(result)
    except ValueError as e:
        return dumps({"error": str(e), "path": path})
    except Exception as e:
        logger.error(f"vault_daily_note_append error for {path}: {e}")
        return dumps({"error": str(e), "path": path})
