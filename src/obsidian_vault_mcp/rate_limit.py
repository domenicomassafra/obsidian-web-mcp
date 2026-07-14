"""Small in-memory per-token tool rate limiter."""

from __future__ import annotations

import hashlib
import math
import threading
import time
from collections import deque

from . import config
from .audit import MUTATION_OPERATIONS, READ_OPERATIONS
from .context import current_request_context

_WINDOW_SECONDS = 60.0
_lock = threading.Lock()
_events: dict[tuple[str, str], deque[float]] = {}


def _bucket(operation: str) -> tuple[str, int] | None:
    if operation in MUTATION_OPERATIONS:
        return "write", config.RATE_LIMIT_WRITE
    if operation in READ_OPERATIONS:
        return "read", config.RATE_LIMIT_READ
    return None


def check_tool_rate_limit(operation: str, *, now: float | None = None) -> int | None:
    """Return retry-after seconds when the authenticated token is over limit.

    Calls without an authenticated request principal are internal/test calls and are
    not limited. Token material is hashed before it becomes a dictionary key.
    """
    principal = current_request_context().get("principal")
    bucket = _bucket(operation)
    if not principal or bucket is None:
        return None

    category, limit = bucket
    if limit <= 0:
        return 60

    timestamp = time.monotonic() if now is None else now
    cutoff = timestamp - _WINDOW_SECONDS
    token_id = hashlib.sha256(str(principal).encode("utf-8")).hexdigest()
    key = (token_id, category)

    with _lock:
        events = _events.setdefault(key, deque())
        while events and events[0] <= cutoff:
            events.popleft()
        if len(events) >= limit:
            return max(1, math.ceil(_WINDOW_SECONDS - (timestamp - events[0])))
        events.append(timestamp)

        if len(_events) > 1024:
            stale = [k for k, values in _events.items() if not values or values[-1] <= cutoff]
            for stale_key in stale:
                _events.pop(stale_key, None)

    return None


def _reset_for_tests() -> None:
    with _lock:
        _events.clear()
