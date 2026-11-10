"""End-to-end tests for the Ayn al-Saqr gateway."""

from __future__ import annotations

import time

import jwt as pyjwt
import pytest
from fastapi.testclient import TestClient

from gateway import auth, db, monitor, policy
from gateway import main as gateway_main
from gateway.main import app


@pytest.fixture(scope="module")
def client():
    db.init_db()
    db.seed_data()
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def clean_state(client):
    response = client.post("/demo/reset")
    assert response.status_code == 200, response.text
    yield


def start(client: TestClient, agent_id: str, task: str) -> dict:
    response = client.post("/tasks/start", json={"agent_id": agent_id, "task": task})
    assert response.status_code == 200, response.text
    return response.json()


def call(
    client: TestClient,
    token: str,
    resource: str,
    action: str,
    params: dict | None = None,
):
    return client.post(
        "/gateway/call",
        json={
            "token": token,
            "tool": f"{resource}.{action}",
            "resource": resource,
            "action": action,
            "params": params or {},
        },
    )


def agent_status(client: TestClient, agent_id: str) -> dict:
    agents = client.get("/agents").json()["agents"]
    return next(agent for agent in agents if agent["agent_id"] == agent_id)


def test_valid_in_scope_call_is_allowed(client):
    session = start(client, "benefits-agent-01", "renew_permit")
    assert session["scopes"] == ["permits:read", "permits:update"]

    response = call(
        client, session["token"], "permits", "read", {"permit_id": "PRM-2026-001"}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "allow"
    assert body["result"]["permit"]["permit_id"] == "PRM-2026-001"
    assert body["latency_ms"] >= 0

    renew = call(
        client,
        session["token"],
        "permits",
        "update",
        {"permit_id": "PRM-2026-001"},
    )
    assert renew.status_code == 200
    assert renew.json()["result"]["permit"]["status"] == "active"


def test_out_of_scope_call_is_denied_without_revocation(client):
    session = start(client, "casefile-agent-02", "summarise_case_file")
    response = call(
        client, session["token"], "permits", "update", {"permit_id": "PRM-2026-002"}
    )
    assert response.status_code == 403
    body = response.json()
    assert body["decision"] == "deny"
    assert body["reason"] == "out_of_scope"
    assert body["revoked"] is False
    assert agent_status(client, "casefile-agent-02")["status"] == "active"


def test_critical_resource_denial_triggers_kill_switch(client):
    session = start(client, "casefile-agent-02", "summarise_case_file")
    response = call(client, session["token"], "citizens", "list")
    assert response.status_code == 403
    body = response.json()
    assert body["reason"] == "kill_switch: critical resource access attempt"
    assert body["revoked"] is True

    agent = agent_status(client, "casefile-agent-02")
    assert agent["status"] == "revoked"
    assert "kill_switch" in (agent["revoked_reason"] or "")

    stats = client.get("/stats").json()
    assert stats["agents_revoked"] >= 1
    assert stats["kill_switch"]["agent_id"] == "casefile-agent-02"
    assert stats["kill_switch"]["latency_ms"] >= 0


def test_revoked_agent_next_call_is_denied(client):
    session = start(client, "benefits-agent-01", "renew_permit")
    first = call(
        client, session["token"], "permits", "read", {"permit_id": "PRM-2026-001"}
    )
    assert first.status_code == 200

    revoke = client.post("/agents/benefits-agent-01/revoke")
    assert revoke.status_code == 200
    assert revoke.json()["status"] == "revoked"

    second = call(
        client, session["token"], "permits", "read", {"permit_id": "PRM-2026-001"}
    )
    assert second.status_code == 403
    assert second.json()["reason"] == "revoked"

    start_again = client.post(
        "/tasks/start", json={"agent_id": "benefits-agent-01", "task": "renew_permit"}
    )
    assert start_again.status_code == 403


def test_expired_and_forged_tokens_are_denied(client):
    _, claims = auth.issue_task_token(
        "benefits-agent-01",
        "renew_permit",
        ["permits:read", "permits:update"],
        ttl_seconds=-60,
    )
    expired = pyjwt.encode(
        {k: claims[k] for k in ("agent_id", "task_id", "task", "scopes", "iat", "exp")},
        auth.JWT_SECRET,
        algorithm="HS256",
    )
    response = call(client, expired, "permits", "read", {"permit_id": "PRM-2026-001"})
    assert response.status_code == 403
    assert response.json()["reason"] == "invalid_token"

    now = int(time.time())
    forged_claims = {
        "agent_id": "benefits-agent-01",
        "task_id": "forged-task",
        "task": "renew_permit",
        "scopes": ["permits:read"],
        "iat": now,
        "exp": now + 300,
    }
    forged = pyjwt.encode(forged_claims, "definitely-not-the-gateway-secret", algorithm="HS256")
    response = call(client, forged, "permits", "read", {"permit_id": "PRM-2026-001"})
    assert response.status_code == 403
    assert response.json()["reason"] == "invalid_token"


def test_audit_chain_verifies(client):
    session = start(client, "benefits-agent-01", "renew_permit")
    for permit_id in ("PRM-2026-001", "PRM-2026-002", "PRM-2026-003"):
        response = call(client, session["token"], "permits", "read", {"permit_id": permit_id})
        assert response.status_code == 200

    verification = client.get("/audit/verify").json()
    assert verification["valid"] is True
    assert verification["checked"] >= 3
    assert verification["first_broken_index"] is None

    entries = client.get("/audit?limit=10").json()["entries"]
    assert len(entries) >= 3
    assert len(entries[0]["hash"]) == 64
    assert entries[-1]["prev_hash"] == audit_genesis()


def audit_genesis() -> str:
    from gateway.audit import GENESIS

    return GENESIS


def test_tampering_is_detected(client):
    session = start(client, "benefits-agent-01", "renew_permit")
    for permit_id in ("PRM-2026-001", "PRM-2026-002", "PRM-2026-003", "PRM-2026-004"):
        assert call(
            client, session["token"], "permits", "read", {"permit_id": permit_id}
        ).status_code == 200

    assert client.get("/audit/verify").json()["valid"] is True

    tampered = client.post("/demo/tamper")
    assert tampered.status_code == 200
    assert tampered.json()["tampered"] is True
    assert tampered.json()["demo_only"] is True

    verification = client.get("/audit/verify").json()
    assert verification["valid"] is False
    assert verification["first_broken_index"] is not None
    assert verification["checked"] >= 4


def test_rate_limit_revokes_agent(client, monkeypatch):
    original = policy.load_policy

    def tight_policy():
        loaded = original()
        loaded["thresholds"]["max_calls_per_minute"] = 2
        loaded["thresholds"]["max_denies_per_task"] = 99
        loaded["thresholds"]["kill_on_critical_denied"] = False
        return loaded

    monkeypatch.setattr(policy, "load_policy", tight_policy)

    session = start(client, "benefits-agent-01", "renew_permit")
    first = call(client, session["token"], "permits", "read", {"permit_id": "PRM-2026-001"})
    second = call(client, session["token"], "permits", "read", {"permit_id": "PRM-2026-002"})
    third = call(client, session["token"], "permits", "read", {"permit_id": "PRM-2026-003"})
    assert (first.status_code, second.status_code) == (200, 200)
    assert third.status_code == 403
    assert third.json()["reason"] == "rate_limit_exceeded"
    assert agent_status(client, "benefits-agent-01")["status"] == "revoked"


def test_denial_threshold_revokes_agent(client, monkeypatch):
    original = policy.load_policy

    def tight_policy():
        loaded = original()
        loaded["thresholds"]["max_denies_per_task"] = 1
        loaded["thresholds"]["kill_on_critical_denied"] = False
        return loaded

    monkeypatch.setattr(policy, "load_policy", tight_policy)

    session = start(client, "casefile-agent-02", "summarise_case_file")
    first = call(client, session["token"], "permits", "read")
    assert first.status_code == 403
    assert first.json()["revoked"] is False

    second = call(client, session["token"], "permits", "read")
    assert second.status_code == 403
    assert second.json()["revoked"] is True
    assert agent_status(client, "casefile-agent-02")["status"] == "revoked"


class _FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def test_trigger_attack_delegates_to_external_attacker(client, monkeypatch):
    seen: list[tuple[str, str]] = []

    def fake_get(url, timeout):
        seen.append(("GET", url))
        return _FakeResponse(200, {"status": "idle"})

    def fake_post(url, timeout):
        seen.append(("POST", url))
        return _FakeResponse(
            202, {"status": "launched", "job_id": "job-1", "mode": "scripted"}
        )

    monkeypatch.setattr(gateway_main, "ATTACKER_URL", "http://attacker.test")
    monkeypatch.setattr(gateway_main.httpx, "get", fake_get)
    monkeypatch.setattr(gateway_main.httpx, "post", fake_post)

    response = client.post("/demo/trigger-attack")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "launched"
    assert body["source"] == "external"
    assert body["attacker"] == "http://attacker.test"
    assert body["job"]["job_id"] == "job-1"
    assert ("GET", "http://attacker.test/status") in seen
    assert ("POST", "http://attacker.test/attack") in seen


def test_reset_cancels_external_attacker(client, monkeypatch):
    seen: list[str] = []

    def fake_post(url, timeout):
        seen.append(url)
        return _FakeResponse(200, {"status": "cancelled"})

    monkeypatch.setattr(gateway_main, "ATTACKER_URL", "http://attacker.test")
    monkeypatch.setattr(gateway_main.httpx, "post", fake_post)

    response = client.post("/demo/reset")
    assert response.status_code == 200, response.text
    assert "http://attacker.test/cancel" in seen
