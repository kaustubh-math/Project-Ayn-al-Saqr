"""Ayn al-Saqr - FastAPI gateway, dashboard host and SSE event feed."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import sys
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

from . import audit, auth, backend, db, monitor, policy

BASE_DIR = Path(__file__).resolve().parent.parent
DASHBOARD_PATH = BASE_DIR / "dashboard" / "index.html"
LOG_DIR = BASE_DIR / "logs"
PORT = int(os.environ.get("AYN_PORT", "8000"))
GATEWAY_URL = os.environ.get("GATEWAY_URL", f"http://127.0.0.1:{PORT}")
ATTACKER_URL = os.environ.get("ATTACKER_URL", "").rstrip("/")
KILL_REASON = "kill_switch: critical resource access attempt"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("ayn.gateway")


# --------------------------------------------------------------------------
# SSE event bus (thread-safe: gateway calls run in FastAPI's worker threads)
# --------------------------------------------------------------------------
class EventBus:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[str]] = set()
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def subscribe(self) -> asyncio.Queue[str]:
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=1000)
        with self._lock:
            self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[str]) -> None:
        with self._lock:
            self._subscribers.discard(queue)

    def publish(self, event: dict[str, Any]) -> None:
        data = json.dumps(event, ensure_ascii=False, default=str)
        with self._lock:
            subscribers = list(self._subscribers)
            loop = self._loop
        if loop is None or not loop.is_running():
            return
        for queue in subscribers:
            try:
                loop.call_soon_threadsafe(self._offer, queue, data)
            except RuntimeError:
                pass

    @staticmethod
    def _offer(queue: asyncio.Queue[str], data: str) -> None:
        try:
            queue.put_nowait(data)
        except asyncio.QueueFull:
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
            try:
                queue.put_nowait(data)
            except asyncio.QueueFull:
                pass


bus = EventBus()

# Demo subprocesses launched from the dashboard (run.sh owns its own benefits agent)
_proc_lock = threading.Lock()
_attack_proc: subprocess.Popen[bytes] | None = None
_benefits_proc: subprocess.Popen[bytes] | None = None
_last_benefits_seen = 0.0


@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.init_db()
    db.seed_data()
    bus.bind(asyncio.get_running_loop())
    log.info("Ayn al-Saqr gateway ready on port %s (db=%s)", PORT, db.DB_PATH)
    try:
        yield
    finally:
        _terminate(_attack_proc)
        _terminate(_benefits_proc)


app = FastAPI(
    title="Ayn al-Saqr",
    description="Task-scoped agent firewall for government data access.",
    version="0.1.0",
    lifespan=lifespan,
)


# --------------------------------------------------------------------------
# Request models
# --------------------------------------------------------------------------
class StartTaskBody(BaseModel):
    agent_id: str
    task: str


class GatewayCallBody(BaseModel):
    token: str
    tool: str = "unknown"
    resource: str
    action: str
    params: dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _elapsed_ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000.0, 3)


def _terminate(proc: subprocess.Popen[bytes] | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()


def _spawn(script: str, log_name: str) -> tuple[subprocess.Popen[bytes], Path]:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_path = LOG_DIR / log_name
    env = os.environ.copy()
    env["GATEWAY_URL"] = GATEWAY_URL
    env["PYTHONUNBUFFERED"] = "1"
    with open(log_path, "ab") as log_file:
        proc = subprocess.Popen(
            [sys.executable, str(BASE_DIR / "agents" / script)],
            cwd=str(BASE_DIR),
            env=env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
    return proc, log_path


def _reinstate_casefile_agent() -> bool:
    """Make Trigger Attack repeatable without a full reset."""
    agent = auth.get_agent("casefile-agent-02")
    if agent is None or agent["status"] != "revoked":
        return False
    auth.reinstate_agent("casefile-agent-02")
    monitor.reset_agent("casefile-agent-02")
    bus.publish(
        {
            "type": "agent_update",
            "agent_id": "casefile-agent-02",
            "status": "active",
        }
    )
    return True


def _agents_view() -> list[dict[str, Any]]:
    agents = auth.list_agents()
    with db.session() as conn:
        for agent in agents:
            revocation = conn.execute(
                "SELECT reason, revoked_at FROM revocations "
                "WHERE agent_id = ? ORDER BY id DESC LIMIT 1",
                (agent["agent_id"],),
            ).fetchone()
            last = conn.execute(
                "SELECT timestamp, resource, action, decision FROM audit_log "
                "WHERE agent_id = ? ORDER BY id DESC LIMIT 1",
                (agent["agent_id"],),
            ).fetchone()
            agent["revoked_reason"] = revocation["reason"] if revocation else None
            agent["revoked_at"] = revocation["revoked_at"] if revocation else None
            agent["current_task"] = agent.get("last_task")
            agent["current_scopes"] = (
                policy.task_scopes(agent["last_task"]) or []
                if agent.get("last_task")
                else []
            )
            agent["last_activity"] = last["timestamp"] if last else None
            agent["last_call"] = (
                f"{last['resource']}:{last['action']}" if last else None
            )
    return agents


def _stats() -> dict[str, Any]:
    with db.session() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS total_calls, "
            "COALESCE(SUM(CASE WHEN decision = 'deny' THEN 1 ELSE 0 END), 0) AS blocked, "
            "COALESCE(AVG(latency_ms), 0) AS avg_latency "
            "FROM audit_log"
        ).fetchone()
        revoked = conn.execute(
            "SELECT COUNT(*) AS n FROM agents WHERE status = 'revoked'"
        ).fetchone()["n"]
        revocations = conn.execute(
            "SELECT COUNT(*) AS n FROM revocations"
        ).fetchone()["n"]
    return {
        "total_calls": int(row["total_calls"]),
        "attacks_blocked": int(row["blocked"]),
        "agents_revoked": int(revoked),
        "revocations_total": int(revocations),
        "avg_latency_ms": round(float(row["avg_latency"]), 2),
        "false_positives": 0,
        "kill_switch": monitor.last_kill_info(),
    }


# --------------------------------------------------------------------------
# Dashboard and health
# --------------------------------------------------------------------------
@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(DASHBOARD_PATH, media_type="text/html")


@app.get("/logo.png", include_in_schema=False)
def logo() -> FileResponse:
    return FileResponse(BASE_DIR / "dashboard" / "logo.png", media_type="image/png")


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> Response:
    return Response(status_code=204)


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "ayn-al-saqr",
        "port": PORT,
        "policy": str(policy.POLICY_PATH),
        "db": str(db.DB_PATH),
        "attack_trigger": ATTACKER_URL or "embedded",
    }


# --------------------------------------------------------------------------
# Identity and task tokens
# --------------------------------------------------------------------------
@app.post("/tasks/start")
def start_task(body: StartTaskBody):
    agent = auth.get_agent(body.agent_id)
    if agent is None:
        return JSONResponse(
            status_code=404,
            content={"decision": "deny", "reason": "unknown_agent", "agent_id": body.agent_id},
        )
    if agent["status"] != "active" or auth.active_revocation(body.agent_id):
        return JSONResponse(
            status_code=403,
            content={"decision": "deny", "reason": "revoked", "agent_id": body.agent_id},
        )

    scopes = policy.task_scopes(body.task)
    if scopes is None:
        return JSONResponse(
            status_code=400,
            content={"decision": "deny", "reason": "unknown_task", "task": body.task},
        )

    token, claims = auth.issue_task_token(body.agent_id, body.task, scopes)
    log.info("task token issued agent=%s task=%s scopes=%s", body.agent_id, body.task, scopes)
    return {
        "token": token,
        "token_type": "Bearer",
        "agent_id": body.agent_id,
        "task_id": claims["task_id"],
        "task": body.task,
        "scopes": scopes,
        "expires_in": auth.TOKEN_TTL_SECONDS,
        "expires_at": claims["expires_at"],
    }


# --------------------------------------------------------------------------
# The gateway
# --------------------------------------------------------------------------
@app.post("/gateway/call")
def gateway_call(body: GatewayCallBody):
    started = time.perf_counter()
    global _last_benefits_seen

    agent_id: str | None = None
    task_id: str | None = None
    agent_name: str | None = None

    def finish(
        reason: str | None,
        *,
        result: Any = None,
        revoked: bool = False,
        revocation_reason: str | None = None,
        detail: str | None = None,
        kill_latency: float | None = None,
    ):
        decision = "deny" if reason else "allow"
        latency = _elapsed_ms(started)
        entry = audit.append(
            agent_id=agent_id,
            task_id=task_id,
            resource=body.resource,
            action=body.action,
            decision=decision,
            reason=reason,
            latency_ms=latency,
        )
        bus.publish(
            {
                "type": "call",
                **entry,
                "tool": body.tool,
                "agent_name": agent_name,
                "revoked": revoked,
            }
        )
        if revoked:
            bus.publish(
                {
                    "type": "kill" if reason == KILL_REASON else "revocation",
                    "agent_id": agent_id,
                    "agent_name": agent_name,
                    "task_id": task_id,
                    "reason": revocation_reason or reason,
                    "latency_ms": (
                        kill_latency if kill_latency is not None else latency
                    ),
                }
            )

        payload: dict[str, Any] = {
            "decision": decision,
            "agent_id": agent_id,
            "task_id": task_id,
            "resource": body.resource,
            "action": body.action,
            "latency_ms": latency,
            "audit_id": entry["id"],
            "audit_hash": entry["hash"],
        }
        if decision == "allow":
            payload["result"] = result
            status_code = 200
        else:
            payload["reason"] = reason
            payload["revoked"] = revoked
            if detail:
                payload["detail"] = detail
            status_code = 403
        return JSONResponse(status_code=status_code, content=jsonable_encoder(payload))

    # 1. Token signature and expiry.
    try:
        claims = auth.decode_token(body.token)
    except auth.TokenError as exc:
        return finish("invalid_token", detail=exc.code)

    agent_id = str(claims["agent_id"])
    task_id = str(claims["task_id"])
    agent = auth.get_agent(agent_id)
    if agent is None:
        return finish("revoked", detail="unknown_agent")
    agent_name = agent["name"]
    auth.touch_task(agent_id, str(claims["task"]), task_id)
    if agent_id == "benefits-agent-01":
        _last_benefits_seen = time.monotonic()

    # 2. Agent and task revocation.
    if (
        agent["status"] != "active"
        or auth.active_revocation(agent_id)
        or auth.is_task_revoked(task_id)
    ):
        return finish("revoked", detail="agent_or_task_revoked")

    thresholds = policy.thresholds()
    critical = {r.strip().lower() for r in policy.critical_resources()}
    scope = f"{body.resource}:{body.action}"
    scopes = claims.get("scopes") or []

    reason: str | None = None
    result: Any = None
    detail: str | None = None
    revoked = False
    revocation_reason: str | None = None
    kill_latency: float | None = None

    # 3. Task scope.
    if scope not in scopes:
        reason = "out_of_scope"
        detail = f"requires scope '{scope}'"
    else:
        # 4a. Rate limit (sliding 60 second window).
        attempts = monitor.record_attempt(agent_id)
        limit = int(thresholds.get("max_calls_per_minute", 30))
        if attempts > limit:
            reason = "rate_limit_exceeded"
            detail = f"{attempts} calls in the last 60s (limit {limit})"

    # 5. Backend call only when the request survives the checks above.
    if reason is None:
        try:
            result = backend.execute(
                body.resource, body.action, body.params, agent_id=agent_id
            )
        except backend.BackendError as exc:
            reason = "backend_error"
            detail = str(exc)
        except Exception:  # pragma: no cover - defensive
            log.exception("backend failure")
            reason = "internal_error"
            detail = "unexpected backend failure"

    # 4b. Behaviour response: critical-resource denial -> immediate kill.
    if reason is not None:
        is_critical = body.resource.strip().lower() in critical
        fresh = auth.get_agent(agent_id)
        if (
            reason in {"out_of_scope", "rate_limit_exceeded"}
            and is_critical
            and bool(thresholds.get("kill_on_critical_denied", True))
            and fresh is not None
            and fresh["status"] == "active"
        ):
            kill_latency = _elapsed_ms(started)
            auth.revoke_agent(agent_id, KILL_REASON, task_id)
            monitor.register_kill(
                agent_id,
                task_id,
                KILL_REASON,
                kill_latency,
                resource=body.resource,
                action=body.action,
            )
            monitor.record_denial(agent_id, task_id)
            reason = KILL_REASON
            revoked = True
            revocation_reason = KILL_REASON
            log.warning(
                "KILL SWITCH agent=%s task=%s attempted %s:%s",
                agent_id,
                task_id,
                body.resource,
                body.action,
            )
        elif reason == "rate_limit_exceeded":
            auth.revoke_agent(agent_id, "rate_limit_exceeded", task_id)
            revoked = True
            revocation_reason = "rate_limit_exceeded"
        elif reason == "out_of_scope":
            denies = monitor.record_denial(agent_id, task_id)
            if denies > int(thresholds.get("max_denies_per_task", 3)):
                auth.revoke_agent(agent_id, "too_many_denials", task_id)
                revoked = True
                revocation_reason = "too_many_denials"

    # 6 + 7. Audit, SSE and latency happen inside finish().
    return finish(
        reason,
        result=result,
        revoked=revoked,
        revocation_reason=revocation_reason,
        detail=detail,
        kill_latency=kill_latency,
    )


# --------------------------------------------------------------------------
# Agents and kill switch
# --------------------------------------------------------------------------
@app.get("/agents")
def agents() -> dict[str, Any]:
    return {"agents": _agents_view()}


@app.post("/agents/{agent_id}/revoke")
def revoke_agent(agent_id: str):
    if auth.get_agent(agent_id) is None:
        return JSONResponse(
            status_code=404,
            content={"decision": "deny", "reason": "unknown_agent"},
        )
    info = auth.revoke_agent(agent_id, "manual revocation from dashboard")
    bus.publish(
        {
            "type": "revocation",
            "agent_id": agent_id,
            "reason": "manual revocation from dashboard",
            "latency_ms": 0,
        }
    )
    return {"status": "revoked", "revocation": info}


@app.post("/agents/{agent_id}/reinstate")
def reinstate_agent(agent_id: str):
    agent = auth.reinstate_agent(agent_id)
    if agent is None:
        return JSONResponse(
            status_code=404,
            content={"decision": "deny", "reason": "unknown_agent"},
        )
    monitor.reset_agent(agent_id)
    bus.publish({"type": "agent_update", "agent_id": agent_id, "status": "active"})
    return {"status": "active", "agent": agent}


# --------------------------------------------------------------------------
# Audit ledger
# --------------------------------------------------------------------------
@app.get("/audit")
def get_audit(limit: int = 10):
    entries = audit.recent(limit)
    return {
        "entries": entries,
        "count": len(entries),
        "head_hash": entries[0]["hash"] if entries else audit.GENESIS,
    }


@app.get("/audit/verify")
def verify_audit():
    return audit.verify_chain()


@app.post("/demo/tamper")
def tamper_audit():
    """DEMO ONLY: corrupt an old audit row without re-hashing."""
    return audit.tamper()


# --------------------------------------------------------------------------
# Demo control
# --------------------------------------------------------------------------
@app.post("/demo/trigger-attack")
def trigger_attack():
    global _attack_proc

    # Preferred path: a separate attacker service owns the compromised agent.
    # The gateway only dispatches the request, so the attack does not originate
    # from a subprocess spawned by the firewall itself.
    if ATTACKER_URL:
        try:
            status_response = httpx.get(f"{ATTACKER_URL}/status", timeout=3.0)
            status_response.raise_for_status()
            remote_status = status_response.json()
        except (httpx.HTTPError, ValueError) as exc:
            return JSONResponse(
                status_code=502,
                content={
                    "status": "error",
                    "reason": "attacker_unreachable",
                    "attacker": ATTACKER_URL,
                    "detail": str(exc),
                },
            )

        if remote_status.get("status") in {"launched", "running"}:
            return {
                "status": "already_running",
                "source": "external",
                "attacker": ATTACKER_URL,
                "job": remote_status,
            }

        reinstated = _reinstate_casefile_agent()
        try:
            launched = httpx.post(f"{ATTACKER_URL}/attack", timeout=5.0)
        except httpx.HTTPError as exc:
            return JSONResponse(
                status_code=502,
                content={
                    "status": "error",
                    "reason": "attacker_unreachable",
                    "attacker": ATTACKER_URL,
                    "detail": str(exc),
                },
            )

        if launched.status_code == 409:
            return {
                "status": "already_running",
                "source": "external",
                "attacker": ATTACKER_URL,
            }
        if launched.status_code >= 400:
            return JSONResponse(
                status_code=502,
                content={
                    "status": "error",
                    "reason": "attacker_rejected",
                    "attacker": ATTACKER_URL,
                    "detail": launched.text[:500],
                },
            )

        try:
            payload = launched.json()
        except ValueError:
            payload = {}
        bus.publish(
            {
                "type": "attack_started",
                "agent_id": "casefile-agent-02",
                "source": "external",
                "attacker": ATTACKER_URL,
                "job_id": payload.get("job_id"),
                "log": str(LOG_DIR / "casefile_agent.log"),
                "reinstated": reinstated,
            }
        )
        log.info(
            "attack dispatched to external attacker %s job=%s",
            ATTACKER_URL,
            payload.get("job_id"),
        )
        return {
            "status": "launched",
            "source": "external",
            "attacker": ATTACKER_URL,
            "job": payload,
            "reinstated": reinstated,
            "mode": payload.get("mode", "scripted"),
        }

    with _proc_lock:
        if _attack_proc is not None and _attack_proc.poll() is None:
            return {"status": "already_running", "pid": _attack_proc.pid, "source": "embedded"}

        reinstated = _reinstate_casefile_agent()
        _attack_proc, log_path = _spawn("casefile_agent.py", "casefile_agent.log")
        pid = _attack_proc.pid
    bus.publish(
        {
            "type": "attack_started",
            "agent_id": "casefile-agent-02",
            "source": "embedded",
            "log": str(log_path),
            "reinstated": reinstated,
        }
    )
    log.info("casefile agent launched pid=%s log=%s", pid, log_path)
    return {
        "status": "launched",
        "source": "embedded",
        "pid": pid,
        "log": str(log_path),
        "reinstated": reinstated,
        "mode": "llm" if os.environ.get("ANTHROPIC_API_KEY") else "scripted",
    }


@app.post("/demo/start-benefits")
def start_benefits():
    global _benefits_proc
    with _proc_lock:
        if time.monotonic() - _last_benefits_seen < 10:
            return {"status": "already_running", "source": "external"}
        if _benefits_proc is not None and _benefits_proc.poll() is None:
            return {"status": "already_running", "pid": _benefits_proc.pid}
        _benefits_proc, log_path = _spawn("benefits_agent.py", "benefits_agent_manual.log")
        pid = _benefits_proc.pid
    return {"status": "launched", "pid": pid, "log": str(log_path)}


@app.post("/demo/reset")
def reset_demo():
    global _attack_proc
    with _proc_lock:
        _terminate(_attack_proc)
        _attack_proc = None
    if ATTACKER_URL:
        try:
            httpx.post(f"{ATTACKER_URL}/cancel", timeout=3.0)
        except httpx.HTTPError as exc:
            log.warning("external attacker cancel failed: %s", exc)
    db.reset_demo()
    monitor.reset()
    bus.publish({"type": "reset"})
    log.info("demo reset")
    return {"status": "reset", "stats": _stats()}


# --------------------------------------------------------------------------
# Live stats and SSE
# --------------------------------------------------------------------------
@app.get("/stats")
def stats():
    return _stats()


@app.get("/events")
async def events(request: Request):
    queue = bus.subscribe()

    async def stream():
        yield "retry: 2000\n\n"
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    data = await asyncio.wait_for(queue.get(), timeout=10.0)
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                yield f"data: {data}\n\n"
        finally:
            bus.unsubscribe(queue)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=os.environ.get("AYN_HOST", "127.0.0.1"),
        port=PORT,
    )
