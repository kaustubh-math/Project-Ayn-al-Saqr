"""Tamper-evident audit ledger.

Each row's hash is SHA256(prev_hash + canonical_json(entry fields)). The first
row chains from 64 zeros. Editing any historical row without recomputing every
following hash makes /audit/verify fail.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from typing import Any

from . import db

GENESIS = "0" * 64
ENTRY_FIELDS = (
    "timestamp",
    "agent_id",
    "task_id",
    "resource",
    "action",
    "decision",
    "reason",
    "latency_ms",
)

_lock = threading.RLock()


def canonical(entry: dict[str, Any]) -> str:
    payload = {field: entry.get(field) for field in ENTRY_FIELDS}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_hash(prev_hash: str, entry: dict[str, Any]) -> str:
    return hashlib.sha256((prev_hash + canonical(entry)).encode("utf-8")).hexdigest()


def _row_to_dict(row: Any) -> dict[str, Any]:
    return {key: row[key] for key in row.keys()}


def append(
    *,
    agent_id: str | None,
    task_id: str | None,
    resource: str | None,
    action: str | None,
    decision: str,
    reason: str | None,
    latency_ms: float,
) -> dict[str, Any]:
    """Append one chained audit entry and return it (including id and hash)."""
    entry: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "agent_id": agent_id,
        "task_id": task_id,
        "resource": resource,
        "action": action,
        "decision": decision,
        "reason": reason,
        "latency_ms": round(float(latency_ms), 3),
    }
    with _lock:
        conn = db.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            last = conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            prev_hash = last["hash"] if last else GENESIS
            entry["prev_hash"] = prev_hash
            entry["hash"] = compute_hash(prev_hash, entry)
            cursor = conn.execute(
                "INSERT INTO audit_log("
                "timestamp, agent_id, task_id, resource, action, decision, reason, "
                "latency_ms, prev_hash, hash"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    entry["timestamp"],
                    entry["agent_id"],
                    entry["task_id"],
                    entry["resource"],
                    entry["action"],
                    entry["decision"],
                    entry["reason"],
                    entry["latency_ms"],
                    entry["prev_hash"],
                    entry["hash"],
                ),
            )
            entry["id"] = int(cursor.lastrowid)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    return entry


def _all_entries() -> list[dict[str, Any]]:
    with db.session() as conn:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()
    return [_row_to_dict(row) for row in rows]


def recent(limit: int = 10) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 500))
    with db.session() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_row_to_dict(row) for row in rows]


def head_hash() -> str:
    with db.session() as conn:
        row = conn.execute(
            "SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
    return row["hash"] if row else GENESIS


def verify_chain() -> dict[str, Any]:
    """Recompute the entire chain from genesis and report the first bad row."""
    rows = _all_entries()
    previous = GENESIS
    for index, entry in enumerate(rows):
        stored_prev = entry["prev_hash"]
        expected = compute_hash(stored_prev, entry)
        if stored_prev != previous or entry["hash"] != expected:
            return {
                "valid": False,
                "checked": len(rows),
                "first_broken_index": index,
                "first_broken_id": entry["id"],
                "head_hash": rows[-1]["hash"] if rows else GENESIS,
            }
        previous = entry["hash"]
    return {
        "valid": True,
        "checked": len(rows),
        "first_broken_index": None,
        "first_broken_id": None,
        "head_hash": previous,
    }


def tamper() -> dict[str, Any]:
    """DEMO ONLY: rewrite an old row in place without re-hashing the chain."""
    rows = _all_entries()
    if not rows:
        return {"tampered": False, "error": "audit log is empty"}
    index = len(rows) // 2 if len(rows) > 2 else 0
    target = rows[index]
    marker = f"TAMPERED (demo): was '{target['reason'] or 'none'}'"
    with _lock, db.session() as conn:
        conn.execute(
            "UPDATE audit_log SET reason = ? WHERE id = ?", (marker, target["id"])
        )
    return {
        "tampered": True,
        "demo_only": True,
        "entry_id": target["id"],
        "index": index,
        "new_reason": marker,
        "note": "Hash left unchanged on purpose; run /audit/verify to detect it.",
    }
