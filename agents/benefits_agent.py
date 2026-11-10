#!/usr/bin/env python3
"""Benign demo agent: reads and renews municipal permits through the gateway.

It has no database credentials and no government API keys - every read and write
goes through POST /gateway/call with a task-scoped token.
"""

from __future__ import annotations

import os
import sys
import time
from datetime import datetime

import httpx

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://127.0.0.1:8000").rstrip("/")
AGENT_ID = os.environ.get("BENEFITS_AGENT_ID", "benefits-agent-01")
TASK = "renew_permit"
TASK_REFRESH_SECONDS = 240  # tokens live 5 minutes; refresh before expiry
LOOP_SECONDS = float(os.environ.get("BENEFITS_LOOP_SECONDS", "2"))


def stamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


def post(client: httpx.Client, path: str, payload: dict) -> tuple[int | None, dict]:
    try:
        response = client.post(f"{GATEWAY_URL}{path}", json=payload)
    except httpx.HTTPError as exc:
        return None, {"error": str(exc)}
    try:
        data = response.json()
    except ValueError:
        data = {}
    return response.status_code, data


def start_task(client: httpx.Client) -> str | None:
    status, data = post(client, "/tasks/start", {"agent_id": AGENT_ID, "task": TASK})
    if status != 200:
        print(
            f"[{stamp()}] task start refused ({status}): "
            f"{data.get('reason', data.get('error', 'unknown'))} - waiting for gateway/reset"
        )
        return None
    print(
        f"[{stamp()}] task {TASK} started | task_id={data['task_id'][:8]}... "
        f"| scopes={', '.join(data['scopes'])}"
    )
    return data["token"]


def call(client: httpx.Client, token: str, tool: str, resource: str, action: str, params: dict):
    status, data = post(
        client,
        "/gateway/call",
        {
            "token": token,
            "tool": tool,
            "resource": resource,
            "action": action,
            "params": params,
        },
    )
    if status is None:
        print(f"[{stamp()}] gateway unreachable: {data.get('error')}")
        return None, data
    if status == 200:
        print(
            f"[{stamp()}] ALLOW  {resource}:{action:<7} {params.get('permit_id', '')} "
            f"({data.get('latency_ms', 0)} ms)"
        )
    else:
        print(
            f"[{stamp()}] DENY   {resource}:{action:<7} "
            f"reason={data.get('reason')} ({data.get('latency_ms', 0)} ms)"
        )
    return status, data


def main() -> int:
    print("=" * 78)
    print(" Benefits Agent  |  Ayn al-Saqr")
    print(f" gateway={GATEWAY_URL}  agent={AGENT_ID}  task={TASK}")
    print("=" * 78)

    token: str | None = None
    token_started = 0.0
    permit_number = 0
    mode = "read"

    with httpx.Client(timeout=10.0) as client:
        while True:
            try:
                if token is None or time.monotonic() - token_started > TASK_REFRESH_SECONDS:
                    token = start_task(client)
                    token_started = time.monotonic()
                    if token is None:
                        time.sleep(5)
                        continue

                permit_id = f"PRM-2026-{(permit_number % 20) + 1:03d}"

                if mode == "read":
                    status, data = call(
                        client, token, "permits.read", "permits", "read",
                        {"permit_id": permit_id},
                    )
                    if status == 200:
                        permit = data["result"]["permit"]
                        print(
                            f"[{stamp()}]        permit {permit_id}: "
                            f"{permit['type']} | status={permit['status']} "
                            f"| expires={permit['expiry_date']}"
                        )
                    else:
                        token = None if data.get("reason") in {"revoked", "invalid_token"} else token
                    mode = "renew"
                else:
                    status, data = call(
                        client, token, "permits.renew", "permits", "update",
                        {"permit_id": permit_id, "status": "active"},
                    )
                    if status == 200:
                        permit = data["result"]["permit"]
                        print(
                            f"[{stamp()}]        renewed {permit_id} -> "
                            f"status={permit['status']} expiry={permit['expiry_date']}"
                        )
                        permit_number += 1
                    else:
                        token = None if data.get("reason") in {"revoked", "invalid_token"} else token
                    mode = "read"

                time.sleep(LOOP_SECONDS)
            except KeyboardInterrupt:
                print("\n[benefits-agent] stopped")
                return 0
            except Exception as exc:  # keep the demo agent alive
                print(f"[{stamp()}] agent error: {exc}")
                time.sleep(3)


if __name__ == "__main__":
    sys.exit(main())
