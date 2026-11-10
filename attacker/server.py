#!/usr/bin/env python3
"""Standalone attack control service for Ayn al-Saqr.

This Flask app is deliberately a *separate process* (default
http://127.0.0.1:5000) from the gateway. It owns the compromised case-file
agent and exposes a small HTTP API plus a browser console:

    POST /attack   launch the case-file agent against GATEWAY_URL
    POST /cancel   stop the running agent
    GET  /status   job state and recent agent output
    GET  /health   service and gateway reachability
    GET  /         external attack console (HTML)

The dashboard's Trigger Attack button calls the gateway, which delegates here
when ATTACKER_URL is set. The attack therefore originates from this service,
not from a subprocess spawned by the firewall itself.

DEMO ONLY. There is no authentication. It binds to loopback by default; set
ATTACKER_HOST=0.0.0.0 only on an isolated demo network.
"""

from __future__ import annotations

import atexit
import os
import subprocess
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from flask import Flask, Response, jsonify, request

BASE_DIR = Path(__file__).resolve().parent.parent
AGENT_SCRIPT = BASE_DIR / "agents" / "casefile_agent.py"
LOG_DIR = BASE_DIR / "logs"
LOG_PATH = LOG_DIR / "casefile_agent.log"

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://127.0.0.1:8000").rstrip("/")
PUBLIC_GATEWAY_URL = os.environ.get("PUBLIC_GATEWAY_URL", GATEWAY_URL).rstrip("/")
HOST = os.environ.get("ATTACKER_HOST", "127.0.0.1")
PORT = int(os.environ.get("ATTACKER_PORT", "5000"))

app = Flask(__name__)

_lock = threading.Lock()
_proc: subprocess.Popen[bytes] | None = None
_job: dict[str, Any] = {
    "job_id": None,
    "status": "idle",
    "pid": None,
    "started_at": None,
    "finished_at": None,
    "exit_code": None,
    "target": GATEWAY_URL,
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _tail(limit: int = 6000) -> str:
    try:
        data = LOG_PATH.read_bytes()
    except FileNotFoundError:
        return ""
    return data[-limit:].decode("utf-8", errors="replace")


def _mode() -> str:
    return "llm" if os.environ.get("ANTHROPIC_API_KEY") else "scripted"


def _snapshot() -> dict[str, Any]:
    with _lock:
        proc = _proc
        if proc is not None:
            code = proc.poll()
            if code is not None and _job["status"] in {"launched", "running"}:
                _job["status"] = "completed" if code == 0 else "failed"
                _job["exit_code"] = code
                _job["finished_at"] = _now()
        job = dict(_job)
    job["output"] = _tail()
    job["gateway"] = GATEWAY_URL
    job["mode"] = _mode()
    job["service"] = "ayn-attacker"
    return job


def _stop_child() -> None:
    global _proc
    proc = _proc
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass


atexit.register(_stop_child)


@app.get("/health")
def health():
    """Liveness first; use ?deep=1 to also probe the gateway."""
    payload = {
        "status": "ok",
        "service": "ayn-attacker",
        "port": PORT,
        "gateway": GATEWAY_URL,
        "mode": _mode(),
    }
    if request.args.get("deep") == "1":
        try:
            response = httpx.get(f"{GATEWAY_URL}/health", timeout=1.5)
            payload["gateway_reachable"] = response.status_code == 200
        except httpx.HTTPError:
            payload["gateway_reachable"] = False
    return jsonify(payload)


@app.post("/attack")
def launch_attack():
    global _proc
    with _lock:
        if _proc is not None and _proc.poll() is None:
            return (
                jsonify(
                    {
                        "status": "already_running",
                        "job_id": _job["job_id"],
                        "pid": _job["pid"],
                    }
                ),
                409,
            )

        LOG_DIR.mkdir(parents=True, exist_ok=True)
        # Keep the log for this run only, so /status reflects the current job.
        try:
            LOG_PATH.write_bytes(b"")
        except OSError:
            pass

        env = os.environ.copy()
        env["GATEWAY_URL"] = GATEWAY_URL
        env["PYTHONUNBUFFERED"] = "1"

        with open(LOG_PATH, "ab") as log_file:
            try:
                _proc = subprocess.Popen(
                    [sys.executable, str(AGENT_SCRIPT)],
                    cwd=str(BASE_DIR),
                    env=env,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                )
            except OSError as exc:
                _job["status"] = "failed"
                _job["finished_at"] = _now()
                return jsonify({"status": "failed", "error": str(exc)}), 500

        _job.update(
            job_id=uuid.uuid4().hex[:12],
            status="launched",
            pid=_proc.pid,
            started_at=_now(),
            finished_at=None,
            exit_code=None,
            target=GATEWAY_URL,
        )

    payload = _snapshot()
    return jsonify({"status": "launched", **payload}), 202


@app.post("/cancel")
def cancel_attack():
    global _proc
    with _lock:
        proc = _proc
        job_id = _job["job_id"]
        running = proc is not None and proc.poll() is None

    if not running:
        return jsonify({"status": _snapshot()["status"], "job_id": job_id})

    assert proc is not None
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass

    with _lock:
        _proc = None
        _job["status"] = "cancelled"
        _job["finished_at"] = _now()
        _job["exit_code"] = proc.returncode
    return jsonify({"status": "cancelled", "job_id": job_id})


@app.post("/tamper")
def tamper_audit():
    try:
        response = httpx.post(f"{GATEWAY_URL}/demo/tamper", timeout=3.0)
    except httpx.HTTPError as exc:
        return jsonify({"status": "error", "error": f"Gateway unavailable: {exc}"}), 502

    try:
        payload = response.json()
    except ValueError:
        return jsonify({"status": "error", "error": "Gateway returned invalid JSON"}), 502
    return jsonify(payload), response.status_code


@app.get("/status")
def status():
    return jsonify(_snapshot())


@app.get("/")
def index() -> Response:
    return Response(
        INDEX_HTML.replace("__PUBLIC_GATEWAY__", PUBLIC_GATEWAY_URL),
        mimetype="text/html",
    )


INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>External Attack Console · Ayn al-Saqr</title>
<style>
  :root {
    --bg: #070b12;
    --panel: #101827;
    --line: #223047;
    --text: #e6edf7;
    --muted: #8fa3bf;
    --cyan: #38bdf8;
    --red: #f87171;
    --green: #4ade80;
    --amber: #fbbf24;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    min-height: 100vh;
    background: radial-gradient(circle at 20% 0%, #0f1d31 0, var(--bg) 55%);
    color: var(--text);
    font: 14px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  main { max-width: 980px; margin: 0 auto; padding: 40px 22px 60px; }
  .eyebrow {
    margin: 0 0 8px;
    color: var(--cyan);
    font-size: 11px;
    letter-spacing: .16em;
    text-transform: uppercase;
  }
  h1 { margin: 0 0 10px; font-size: clamp(26px, 4vw, 38px); letter-spacing: -.04em; }
  .sub { margin: 0 0 26px; max-width: 760px; color: var(--muted); }
  .sub code { color: var(--text); }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 10px;
    margin-bottom: 18px;
  }
  .tile {
    border: 1px solid var(--line);
    border-radius: 10px;
    background: var(--panel);
    padding: 12px 14px;
    min-width: 0;
  }
  .tile span {
    display: block;
    color: var(--muted);
    font-size: 10px;
    letter-spacing: .12em;
    text-transform: uppercase;
    margin-bottom: 5px;
  }
  .tile strong {
    display: block;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 13px;
  }
  .actions { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; margin-bottom: 10px; }
  button {
    appearance: none;
    border: 1px solid transparent;
    border-radius: 8px;
    padding: 10px 16px;
    background: var(--red);
    color: #1b0606;
    font: inherit;
    font-weight: 700;
    cursor: pointer;
  }
  button.ghost { background: transparent; border-color: var(--line); color: var(--text); }
  button:disabled { opacity: .4; cursor: not-allowed; }
  a { color: var(--cyan); text-decoration: none; margin-left: auto; }
  a:hover { text-decoration: underline; }
  .message { min-height: 22px; margin: 4px 0 12px; color: var(--amber); font-size: 12px; }
  pre {
    margin: 0;
    min-height: 280px;
    max-height: 50vh;
    overflow: auto;
    border: 1px solid var(--line);
    border-radius: 10px;
    background: #05080e;
    padding: 16px;
    color: #c8d6e8;
    font-size: 12px;
    line-height: 1.55;
    white-space: pre-wrap;
    word-break: break-word;
  }
  footer { margin-top: 16px; color: var(--muted); font-size: 11px; }
  .status-RUNNING { color: var(--red); }
  .status-COMPLETED { color: var(--green); }
  .status-FAILED, .status-CANCELLED { color: var(--amber); }
</style>
</head>
<body>
<main>
  <p class="eyebrow">Separate service · not the firewall</p>
  <h1>External Attack Console</h1>
  <p class="sub">
    This Flask service launches the compromised case-file agent against the
    gateway at <code>__PUBLIC_GATEWAY__</code>. The attack originates here,
    outside the gateway process, and every data access still has to pass the
    gateway.
  </p>

  <section class="grid">
    <div class="tile"><span>Service</span><strong>ayn-attacker</strong></div>
    <div class="tile"><span>Status</span><strong id="status">IDLE</strong></div>
    <div class="tile"><span>Mode</span><strong id="mode">—</strong></div>
    <div class="tile"><span>PID</span><strong id="pid">—</strong></div>
  </section>

  <div class="actions">
    <button id="launch" type="button">Launch hijack</button>
    <button id="tamper" type="button">Tamper ledger</button>
    <button id="cancel" class="ghost" type="button" disabled>Cancel</button>
    <a href="__PUBLIC_GATEWAY__" target="_blank" rel="noreferrer">Open gateway dashboard ↗</a>
  </div>
  <p id="message" class="message"></p>
  <pre id="output">Waiting for a job…</pre>
  <footer>DEMO ONLY · no authentication · loopback by default · reset the gateway to re-run after a kill</footer>
</main>
<script>
  const $ = (id) => document.getElementById(id);
  let busy = false;

  async function refresh() {
    try {
      const response = await fetch("/status");
      const job = await response.json();
      const status = (job.status || "idle").toUpperCase();
      $("status").textContent = status;
      $("status").className = "status-" + status;
      $("mode").textContent = job.mode || "—";
      $("pid").textContent = job.pid || "—";
      $("output").textContent = job.output || "Waiting for a job…";
      const running = job.status === "launched" || job.status === "running";
      $("launch").disabled = running || busy;
      $("cancel").disabled = !running || busy;
    } catch (error) {
      $("message").textContent = "Cannot reach the attacker service: " + error.message;
    }
  }

  async function post(path) {
    busy = true;
    $("message").textContent = path === "/attack"
      ? "Dispatching…"
      : path === "/tamper" ? "Tampering…" : "Cancelling…";
    try {
      const response = await fetch(path, { method: "POST" });
      const body = await response.json();
      if (!response.ok) {
        throw new Error(body.detail || body.error || ("HTTP " + response.status));
      }
      if (path === "/attack") {
        $("message").textContent = "Attack dispatched from this external service.";
      } else if (path === "/tamper") {
        $("message").textContent = body.tampered
          ? "Audit ledger tampered. Verify the chain on the dashboard."
          : (body.error || "Nothing to tamper with.");
      } else {
        $("message").textContent = "Agent stopped.";
      }
    } catch (error) {
      $("message").textContent = "Error: " + error.message;
    } finally {
      busy = false;
      refresh();
    }
  }

  $("launch").addEventListener("click", () => post("/attack"));
  $("tamper").addEventListener("click", () => post("/tamper"));
  $("cancel").addEventListener("click", () => post("/cancel"));
  refresh();
  setInterval(refresh, 1500);
</script>
</body>
</html>
"""


if __name__ == "__main__":
    print(f"[ayn-attacker] external attack service on http://{HOST}:{PORT}")
    print(f"[ayn-attacker] target gateway: {GATEWAY_URL} ({_mode()} mode)")
    app.run(host=HOST, port=PORT, debug=False, threaded=True, use_reloader=False)
