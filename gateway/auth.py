"""Agent registry, task-scoped JWTs and revocation state.

Tokens are short-lived HS256 JWTs whose ``scopes`` claim is copied from
policy.yaml at task start. The gateway treats that claim as the ceiling of what
the agent may do for the lifetime of the task.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt

from . import db

JWT_SECRET = (
    os.environ.get("AYN_JWT_SECRET")
    or "ayn-al-saqr-dev-secret-do-not-use-in-production"
)
JWT_ALG = "HS256"
TOKEN_TTL_SECONDS = int(os.environ.get("AYN_TOKEN_TTL", "300"))


class TokenError(Exception):
    """Raised when a task token cannot be trusted."""

    def __init__(self, code: str = "invalid_token"):
        super().__init__(code)
        self.code = code


def get_agent(agent_id: str) -> dict[str, Any] | None:
    with db.session() as conn:
        row = conn.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
    return dict(row) if row else None


def list_agents() -> list[dict[str, Any]]:
    with db.session() as conn:
        rows = conn.execute("SELECT * FROM agents ORDER BY agent_id").fetchall()
    return [dict(row) for row in rows]


def active_revocation(agent_id: str) -> dict[str, Any] | None:
    with db.session() as conn:
        row = conn.execute(
            "SELECT * FROM revocations WHERE agent_id = ? ORDER BY id DESC LIMIT 1",
            (agent_id,),
        ).fetchone()
    return dict(row) if row else None


def is_task_revoked(task_id: str) -> bool:
    with db.session() as conn:
        row = conn.execute(
            "SELECT 1 FROM revocations WHERE task_id = ? LIMIT 1", (task_id,)
        ).fetchone()
    return row is not None


def revoke_agent(agent_id: str, reason: str, task_id: str | None = None) -> dict[str, Any] | None:
    """Revoke an agent immediately (agent-wide) and optionally its current task."""
    revoked_at = db.now_iso()
    with db.session() as conn:
        row = conn.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
        if row is None:
            return None
        conn.execute("UPDATE agents SET status = 'revoked' WHERE agent_id = ?", (agent_id,))
        conn.execute(
            "INSERT INTO revocations(agent_id, task_id, reason, revoked_at) VALUES (?, ?, ?, ?)",
            (agent_id, task_id, reason, revoked_at),
        )
    return {
        "agent_id": agent_id,
        "task_id": task_id,
        "reason": reason,
        "revoked_at": revoked_at,
    }


def reinstate_agent(agent_id: str) -> dict[str, Any] | None:
    """Clear revocations for an agent. Demo convenience only."""
    with db.session() as conn:
        row = conn.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
        if row is None:
            return None
        conn.execute(
            "UPDATE agents SET status = 'active', last_task = NULL, last_task_id = NULL "
            "WHERE agent_id = ?",
            (agent_id,),
        )
        conn.execute("DELETE FROM revocations WHERE agent_id = ?", (agent_id,))
        updated = conn.execute(
            "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
        ).fetchone()
    return dict(updated) if updated else None


def touch_task(agent_id: str, task: str, task_id: str) -> None:
    """Keep the displayed current task in sync, including after a demo reset."""
    with db.session() as conn:
        conn.execute(
            "UPDATE agents SET last_task = ?, last_task_id = ? WHERE agent_id = ?",
            (task, task_id, agent_id),
        )


def issue_task_token(
    agent_id: str,
    task: str,
    scopes: list[str],
    *,
    ttl_seconds: int = TOKEN_TTL_SECONDS,
    task_id: str | None = None,
    secret: str | None = None,
) -> tuple[str, dict[str, Any]]:
    """Mint a task token and remember the agent's current task."""
    task_id = task_id or str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=ttl_seconds)
    claims: dict[str, Any] = {
        "agent_id": agent_id,
        "task_id": task_id,
        "task": task,
        "scopes": list(scopes),
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    token = jwt.encode(claims, secret or JWT_SECRET, algorithm=JWT_ALG)
    with db.session() as conn:
        conn.execute(
            "UPDATE agents SET last_task = ?, last_task_id = ? WHERE agent_id = ?",
            (task, task_id, agent_id),
        )
    claims["expires_at"] = expires_at.isoformat(timespec="seconds")
    return token, claims


def decode_token(token: str) -> dict[str, Any]:
    """Verify signature and expiry. Raises TokenError with a stable code."""
    try:
        claims = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALG],
            options={"require": ["exp", "agent_id", "task_id", "task", "scopes"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("expired_token") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError("invalid_token") from exc

    scopes = claims.get("scopes")
    if (
        not isinstance(claims.get("agent_id"), str)
        or not isinstance(claims.get("task_id"), str)
        or not isinstance(claims.get("task"), str)
        or not isinstance(scopes, list)
        or not all(isinstance(s, str) for s in scopes)
    ):
        raise TokenError("malformed_token")
    return claims
