"""Mock government backends. Only the gateway calls these functions."""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

from . import db


class BackendError(Exception):
    """A tool exists but the request could not be served."""


def _rows(rows: Any) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


def _permits_read(params: dict[str, Any]) -> dict[str, Any]:
    permit_id = params.get("permit_id")
    with db.session() as conn:
        if permit_id:
            row = conn.execute(
                "SELECT * FROM permits WHERE permit_id = ?", (str(permit_id),)
            ).fetchone()
            if row is None:
                raise BackendError(f"permit_not_found: {permit_id}")
            return {"permit": dict(row)}
        rows = conn.execute("SELECT * FROM permits ORDER BY permit_id").fetchall()
    return {"permits": _rows(rows), "count": len(rows)}


def _permits_update(params: dict[str, Any]) -> dict[str, Any]:
    permit_id = params.get("permit_id")
    if not permit_id:
        raise BackendError("permit_id is required to renew a permit")
    with db.session() as conn:
        row = conn.execute(
            "SELECT * FROM permits WHERE permit_id = ?", (str(permit_id),)
        ).fetchone()
        if row is None:
            raise BackendError(f"permit_not_found: {permit_id}")
        today = date.today()
        try:
            current = date.fromisoformat(row["expiry_date"])
        except ValueError:
            current = today
        target = max(current, today + timedelta(days=365))
        conn.execute(
            "UPDATE permits SET status = 'active', expiry_date = ? WHERE permit_id = ?",
            (target.isoformat(), str(permit_id)),
        )
        updated = conn.execute(
            "SELECT * FROM permits WHERE permit_id = ?", (str(permit_id),)
        ).fetchone()
    return {
        "permit": dict(updated),
        "message": f"Permit {permit_id} renewed; expiry extended to {target.isoformat()}.",
    }


def _case_files_read(params: dict[str, Any]) -> dict[str, Any]:
    case_id = params.get("case_id")
    with db.session() as conn:
        if case_id:
            row = conn.execute(
                "SELECT * FROM case_files WHERE case_id = ?", (str(case_id),)
            ).fetchone()
            if row is None:
                raise BackendError(f"case_file_not_found: {case_id}")
            return {"case_file": dict(row)}
        rows = conn.execute(
            "SELECT case_id, title FROM case_files ORDER BY case_id"
        ).fetchall()
    return {"case_files": _rows(rows), "count": len(rows)}


def _citizens_read(params: dict[str, Any]) -> dict[str, Any]:
    with db.session() as conn:
        citizen_id = params.get("citizen_id")
        if citizen_id:
            row = conn.execute(
                "SELECT * FROM citizens WHERE citizen_id = ?", (str(citizen_id),)
            ).fetchone()
            if row is None:
                raise BackendError(f"citizen_not_found: {citizen_id}")
            return {"citizen": dict(row)}
        rows = conn.execute("SELECT * FROM citizens ORDER BY citizen_id").fetchall()
    return {"citizens": _rows(rows), "count": len(rows)}


def execute(
    resource: str,
    action: str,
    params: dict[str, Any] | None = None,
    *,
    agent_id: str | None = None,
) -> dict[str, Any]:
    """Dispatch a tool call. Raises BackendError for unknown tools."""
    params = params or {}
    key = f"{resource.strip().lower()}:{action.strip().lower()}"
    if key == "permits:read":
        return _permits_read(params)
    if key in {"permits:update", "permits:renew"}:
        return _permits_update(params)
    if key == "case_files:read":
        return _case_files_read(params)
    if key in {"citizens:read", "citizens:list"}:
        return _citizens_read(params)
    raise BackendError(f"unknown_tool: {key}")
