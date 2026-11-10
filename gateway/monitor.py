"""Behaviour monitor state: sliding call windows, denial counts, kill events.

Revocations themselves live in SQLite (gateway.auth / gateway.db) so they
survive restarts. This module holds the volatile counters used to decide when
to pull the trigger.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Any

WINDOW_SECONDS = 60.0

_lock = threading.Lock()
_calls: dict[str, deque[float]] = defaultdict(deque)
_denies: dict[str, int] = defaultdict(int)
_deny_owners: dict[str, str] = {}
_last_kill: dict[str, Any] | None = None


def reset() -> None:
    global _last_kill
    with _lock:
        _calls.clear()
        _denies.clear()
        _deny_owners.clear()
        _last_kill = None


def reset_agent(agent_id: str) -> None:
    with _lock:
        _calls.pop(agent_id, None)
        for task_id, owner in list(_deny_owners.items()):
            if owner == agent_id:
                _denies.pop(task_id, None)
                _deny_owners.pop(task_id, None)


def record_attempt(agent_id: str) -> int:
    """Record a call attempt and return the number in the last 60 seconds."""
    now = time.monotonic()
    cutoff = now - WINDOW_SECONDS
    with _lock:
        window = _calls[agent_id]
        while window and window[0] < cutoff:
            window.popleft()
        window.append(now)
        return len(window)


def calls_in_window(agent_id: str) -> int:
    now = time.monotonic()
    cutoff = now - WINDOW_SECONDS
    with _lock:
        window = _calls.get(agent_id)
        if not window:
            return 0
        while window and window[0] < cutoff:
            window.popleft()
        return len(window)


def record_denial(agent_id: str, task_id: str) -> int:
    with _lock:
        _deny_owners[task_id] = agent_id
        _denies[task_id] += 1
        return _denies[task_id]


def denial_count(task_id: str) -> int:
    with _lock:
        return _denies.get(task_id, 0)


def register_kill(
    agent_id: str,
    task_id: str,
    reason: str,
    latency_ms: float,
    resource: str | None = None,
    action: str | None = None,
) -> dict[str, Any]:
    global _last_kill
    from .db import now_iso

    event = {
        "agent_id": agent_id,
        "task_id": task_id,
        "reason": reason,
        "latency_ms": round(float(latency_ms), 2),
        "resource": resource,
        "action": action,
        "at": now_iso(),
    }
    with _lock:
        _last_kill = event
    return event


def last_kill_info() -> dict[str, Any] | None:
    with _lock:
        return dict(_last_kill) if _last_kill else None
