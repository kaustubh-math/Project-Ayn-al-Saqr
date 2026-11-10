# Ayn al-Saqr · عين الصقر

**Task firewall for government data.** A gateway that sits between automated
agents and government systems, outside the agent, so a compromised agent cannot
exceed the permissions of its task.

> An agent can be tricked. The rules cannot.

---

## What it is

Government agents increasingly read documents, summarise case files and update
records. A poisoned document can contain a prompt injection that tells the model
to fetch data it should never see. Ayn al-Saqr assumes the model may be fully
compromised and enforces the boundary outside it:

1. **Identity** — every task starts with a short-lived HS256 JWT issued to a
   registered agent (`POST /tasks/start`).
2. **Task-scoped permissions** — the token carries only the `resource:action`
   scopes that `policy.yaml` grants to that specific task.
3. **Behaviour monitoring** — per-agent sliding call window and per-task denial
   counts; breaching a threshold revokes the agent.
4. **Kill switch** — a denied attempt on a critical resource (`citizens`) revokes
   the agent and its task mid-run. Subsequent calls fail immediately.
5. **Tamper-evident audit** — every allow/deny is written to a SHA-256 hash
   chain. `/audit/verify` recomputes the whole chain and points at the first
   broken entry.

Two demo agents are registered:

| Agent | Department | Task | Scopes |
|---|---|---|---|
| `benefits-agent-01` | Ministry of Community Development | `renew_permit` | `permits:read`, `permits:update` |
| `casefile-agent-02` | Ministry of Justice | `summarise_case_file` | `case_files:read` |

Neither task can read `citizens`, by construction.

---

## Stack

- Python 3.11+ (tested on Python 3.14.7, Windows 11 / Git Bash)
- FastAPI + uvicorn gateway; Flask external attack service
- PyJWT, PyYAML, httpx
- SQLite via the standard library (WAL mode)
- A single static `dashboard/index.html` (vanilla JS/CSS, no build step)
- Live updates over Server-Sent Events at `/events`
- Optional model-backed case-file agent, only when `ANTHROPIC_API_KEY` is set

No API key, cloud account or external service is required for the demo. The app
is fully functional in scripted mode.

---

## Quick start

### Windows

Double-click `run-demo.bat`, or run this from PowerShell:

```powershell
.\run-demo.bat
```

This detects the active local IPv4 address, binds the dashboard and attack
site to all interfaces, and starts the benefits agent:

- Dashboard (My Laptop): `http://<detected-ipv4>:8000`
- Attacker Console (Friend's Laptop): `http://<detected-ipv4>:5000`

Stop everything with `Ctrl+C`.

### macOS/Linux

```bash
cd ayn-al-saqr
./run.sh
```

`run.sh` creates `.venv` if needed, installs `requirements.txt`, seeds the
database, starts the benefits agent (green traffic), starts the external Flask
attack service, and launches uvicorn:

- Dashboard: <http://localhost:8000>
- External attack console: <http://localhost:5000>
- Benefits agent log: `logs/benefits_agent.log`

Stop everything with `Ctrl+C`.

For a two-machine demo, run `./run.sh --lan`. It binds both services to all
interfaces and prints the LAN URLs; see
[Attack from another computer](#attack-from-another-computer-lan).

Useful environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `AYN_PORT` | `8000` | Gateway and dashboard port |
| `AYN_JWT_SECRET` | dev secret | JWT signing secret; set this outside the demo |
| `AYN_DB_PATH` | `data/ayn.db` | SQLite database path |
| `AYN_POLICY_PATH` | `policy.yaml` | Policy file |
| `ANTHROPIC_API_KEY` | unset | Enables LLM mode in the case file agent |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-5` | Model used in LLM mode |
| `GATEWAY_URL` | `http://127.0.0.1:8000` | Used by the demo agents and attacker service |
| `AYN_HOST` | `127.0.0.1` | Gateway bind address; `0.0.0.0` exposes it |
| `ATTACKER_PORT` | `5000` | External Flask attack console/API port |
| `ATTACKER_HOST` | `127.0.0.1` | Bind address for the attacker service |
| `ATTACKER_URL` | set by `run.sh` | Gateway → attacker service dispatch URL |

### Tests

```bash
cd ayn-al-saqr
.venv/Scripts/python.exe -m pytest -q      # Windows
# .venv/bin/python -m pytest -q             # macOS / Linux
```

Tests use an isolated temporary SQLite database and signing secret; they never
touch the demo database. Current suite: **11 passed**.

---

## Demo script (exact click order)

1. **Start the app**: `./run.sh`, then open <http://localhost:8000>.
   The benefits agent is already running, so green `permits:read` /
   `permits:update` calls stream into the live feed. If the feed is quiet, press
   **Start Benefits Agent**.
2. **Point out the baseline**: two agents ACTIVE, average added latency in single
   digit milliseconds, every call green.
3. **Click `Trigger Attack`**. The gateway delegates the launch to the external
   Flask attack service on port 5000; that separate process starts the case file
   agent. The agent reads `CF-2026-003` (a realistic permit-dispute file) through
   the gateway. Its body ends with a hidden instruction to fetch the full citizen
   list. In scripted mode the agent reproduces the same behavior deterministically;
   with an API key, a model can make the decision itself. You can also launch the same attack directly from
   <http://localhost:5000>.
4. **Watch the block**: a red `citizens:list` DENY appears in the live feed,
   `casefile-agent-02` flips to **REVOKED**, and the red banner reads
   *"Agent revoked in X ms. No data left the building."*
   The agent's follow-up `case_files:read` is also denied with `revoked`.
5. **Verify the ledger**: press **Verify Chain** → green **CHAIN VALID**.
6. **Tamper**: press **Tamper** (demo-only). It silently rewrites an old row's
   reason in SQLite without recomputing hashes.
7. **Verify again**: press **Verify Chain** → red **CHAIN BROKEN at entry #N**,
   with that row highlighted in the table.
8. **Reset Demo** to restore agents, clear revocations, the audit log and
   counters. The benefits agent resumes on its own.

The attack button reinstates `casefile-agent-02` automatically if it is still
revoked, so the demo can be repeated without a reset. The external Flask console
does not have that admin power: after a kill, press **Reset Demo** before launching
there again.

### Manual API walkthrough

```bash
# 1. Start a task and get a scoped token
curl -s -X POST localhost:8000/tasks/start \
  -H 'content-type: application/json' \
  -d '{"agent_id":"casefile-agent-02","task":"summarise_case_file"}'

# 2. Allowed read
curl -s -X POST localhost:8000/gateway/call -H 'content-type: application/json' \
  -d '{"token":"<TOKEN>","tool":"case_files.read","resource":"case_files","action":"read","params":{"case_id":"CF-2026-003"}}'

# 3. Hijacked call -> denied AND kill switch
curl -i -X POST localhost:8000/gateway/call -H 'content-type: application/json' \
  -d '{"token":"<TOKEN>","tool":"citizens.list","resource":"citizens","action":"list","params":{}}'

# 4. Chain verification
curl -s localhost:8000/audit/verify
```

---

### Attack from another computer (LAN)

By default both services bind to loopback, so other devices cannot reach them.
`--lan` opts into a two-machine demo:

1. **On this machine:**

   ```bash
   ./run.sh --lan
   ```

   The banner prints the LAN URLs, for example
   `http://192.168.1.229:8000` and `http://192.168.1.229:5000`.

2. **Allow the ports through the firewall.** On Windows, allow inbound TCP
   `8000` and `5000` on **Private** networks only, ideally scoped to the other
   computer's IP. Either use Windows Security → Firewall & network protection →
   Advanced settings → Inbound Rules, or an elevated PowerShell command:

   ```powershell
   New-NetFirewallRule -DisplayName "Ayn al-Saqr LAN" -Direction Inbound `
     -Protocol TCP -LocalPort 8000,5000 -Action Allow -Profile Private
   ```

3. **On the other computer**, choose one:

   **A — use this machine's attacker console.** Open
   `http://<this-machine-ip>:5000` and press **Launch hijack**. The agent runs on
   this machine, but the trigger comes from the other device.

   **B — run the compromised agent on the other computer.** This is a true
   remote-origin attack: the agent runs there and calls your gateway over the
   LAN.

   ```bash
   git clone https://github.com/XXspider07/ayn-al-saqr.git
   cd ayn-al-saqr
   python -m venv .venv
   # Windows:
   .venv/Scripts/python.exe -m pip install -r requirements.txt
   GATEWAY_URL=http://<this-machine-ip>:8000 \
     .venv/Scripts/python.exe agents/casefile_agent.py
   ```

   On macOS/Linux use `.venv/bin/python` instead. In PowerShell:

   ```powershell
   $env:GATEWAY_URL="http://<this-machine-ip>:8000"
   .venv\Scripts\python.exe agents\casefile_agent.py
   ```

   Alternatively run `attacker/server.py` on the other computer with
   `GATEWAY_URL` pointing here, then open its local console at
   `http://localhost:5000`.

4. **Reset** from the host dashboard, or:

   ```bash
   curl -X POST http://<this-machine-ip>:8000/demo/reset
   ```

> **Security:** LAN mode exposes the dashboard, demo controls, reset/tamper
> endpoints, and attacker API without authentication. Use it only on a trusted
> network, allow only the specific ports and source IP you need, and stop the
> server after the demo. Never port-forward these ports to the public internet;
> for off-site demos use a VPN or an authenticated tunnel.

---

## Architecture

```
┌──────────────────────────┐   POST /attack    ┌──────────────────────┐
│ External attacker service│ ────────────────▶ │  AI Agent            │
│ Flask :5000              │   launches        │  (may be fully       │
└──────────────────────────┘                   │   compromised)       │
                                               └──────────┬───────────┘
┌────────────────────┐    poisoned document              │
│ Government file    │ ─────────────────────────────────▶┘
│ CF-2026-003        │
│ "...SYSTEM NOTICE" │
└────────────────────┘
                                                         │
                                  POST /gateway/call     │  JWT: agent_id,
                                  {token, tool,          │  task_id, scopes
                                   resource, action,     │
                                   params}               ▼
                              ┌────────────────────────────────────────────┐
                              │        AYN AL-SAQR GATEWAY                 │
                              │                                            │
                              │  1. Verify JWT signature + expiry          │
                              │  2. Check agent/task revocation            │
                              │  3. Check resource:action in token scopes  │
                              │  4. Behaviour monitor                      │
                              │       · sliding 60s call window            │
                              │       · denials per task                   │
                              │       · critical deny -> KILL SWITCH       │
                              │  5. Allow -> backend / Deny -> 403         │
                              │  6. Audit hash chain + SSE event           │
                              │  7. Record added latency                   │
                              └───────────────┬────────────────────────────┘
                                              │
                     ┌────────────────────────┼────────────────────────┐
                     ▼                        ▼                        ▼
              ┌────────────┐          ┌────────────┐          ┌──────────────┐
              │  permits   │          │ case_files │          │  citizens    │
              │  (SQLite)  │          │  (SQLite)  │          │  (critical)  │
              └────────────┘          └────────────┘          └──────────────┘

                              ┌────────────────────────────┐
                              │ SQLite audit_log           │
                              │ hash_i = SHA256(           │
                              │   hash_(i-1) + JSON_i )    │
                              └────────────────────────────┘

  Dashboard ◀── SSE /events ── gateway        Browser ◀── / ── dashboard/index.html
```

### Files

```
ayn-al-saqr/
  README.md
  requirements.txt
  run.sh                       # venv + install + seed + attacker + benefits + uvicorn
  policy.yaml                  # task scopes, critical resources, thresholds
  gateway/main.py              # FastAPI routes, SSE, demo control, dispatch
  gateway/auth.py              # registry, JWT task tokens, revocation
  gateway/policy.py            # hot-reloading policy loader
  gateway/monitor.py           # sliding window, denial counts, kill bookkeeping
  gateway/audit.py             # SHA-256 hash chain, verify, demo tamper
  gateway/backend.py           # mock permits/case_files/citizens tools
  gateway/db.py                # SQLite schema and deterministic seed data
  attacker/server.py           # separate Flask attack service + console
  agents/benefits_agent.py     # benign permit renewal loop
  agents/casefile_agent.py     # scripted / LLM hijack demo
  agents/poisoned_case_file.txt
  dashboard/index.html         # SOC dashboard, SSE client, single file
  tests/conftest.py
  tests/test_gateway.py
```

---

## Gateway API

| Method | Path | Description |
|---|---|---|
| `POST` | `/tasks/start` | `{agent_id, task}` → short-lived JWT with task scopes |
| `POST` | `/gateway/call` | `{token, tool, resource, action, params}` → allow/deny |
| `GET` | `/agents` | Registry with status, task, scopes, revocation reason |
| `POST` | `/agents/{id}/revoke` | Manual kill switch from the dashboard |
| `POST` | `/agents/{id}/reinstate` | Clear revocations (demo reset helper) |
| `GET` | `/audit?limit=10` | Latest audit entries, newest first |
| `GET` | `/audit/verify` | `{valid, checked, first_broken_index, first_broken_id, head_hash}` |
| `POST` | `/demo/tamper` | **Demo only**: corrupt a row without re-hashing |
| `POST` | `/demo/reset` | Reset agents, revocations, audit log, counters |
| `POST` | `/demo/trigger-attack` | Dispatch the attack; delegates to the Flask service when `ATTACKER_URL` is set, otherwise uses the embedded launcher |
| `POST` | `/demo/start-benefits` | Launch the benefits agent if none is live |
| `GET` | `/stats` | Totals, blocked calls, revoked agents, average latency |
| `GET` | `/events` | SSE stream of calls, revocations, kills, resets |
| `GET` | `/health` | Liveness, DB/policy paths, and configured attack trigger |

A denied call returns HTTP 403 with
`{"decision":"deny","reason":"...","revoked":true|false,...}`. An allowed call
returns HTTP 200 with `{"decision":"allow","result":...}`. Every attempt, including
invalid tokens, is audited.

Denial reasons: `invalid_token`, `revoked`, `out_of_scope`, `rate_limit_exceeded`,
`backend_error`, `kill_switch: critical resource access attempt`.

### External attacker service API

The Flask service is a separate process, loopback-only by default. It has no
authentication; see the limitations below.

| Method | Path | Description |
|---|---|---|
| `POST` | `/attack` | Launch `casefile_agent.py` from this service |
| `POST` | `/cancel` | Terminate the running agent |
| `GET` | `/status` | Job state, PID, mode, and recent agent output |
| `GET` | `/health` | Liveness; add `?deep=1` to probe the gateway |
| `GET` | `/` | Browser attack console |

Set `ATTACKER_URL` on the gateway to point at another host, and run the Flask
service with `GATEWAY_URL` pointing back at the gateway.

### Policy hot reload

`gateway/policy.py` parses `policy.yaml` on every request. Edit thresholds or
scopes and the next call uses the new values — no restart. A missing or invalid
file falls back to the built-in defaults instead of crashing.

Example: lower `max_denies_per_task` to `1`, start `casefile-agent-02`, and two
out-of-scope calls will revoke it.

### Audit hash construction

For each entry:

```
hash = SHA256(prev_hash + canonical_json({
    timestamp, agent_id, task_id, resource, action,
    decision, reason, latency_ms
}))
```

`canonical_json` is sorted-key, compact JSON. The first entry chains from 64
zeros. `verify_chain()` walks ascending `id`, recomputes each hash and checks
`prev_hash` linkage, returning the zero-based position of the first bad row.

`POST /demo/tamper` deliberately uses a plain `UPDATE` with no re-hashing. It is
destructive demo behaviour; **Reset Demo** clears the log.

---

## Design decisions and assumptions

- **Port 8000** and a loopback-only bind.
- **Dev JWT secret** is used when `AYN_JWT_SECRET` is unset, so the demo runs
  without configuration. The string is printed nowhere; set your own secret for
  anything beyond a demo.
- **SQLite** lives in `data/ayn.db`; runtime data and logs are gitignored.
- **`run.sh` auto-starts the benefits agent** so the dashboard has green traffic
  immediately, satisfying the "open the dashboard and see traffic" requirement.
  The dashboard also has a `Start Benefits Agent` button (it detects live traffic
  and will not spawn a duplicate).
- **The benefits agent alternates one read and one renew every ~2 seconds**
  (≈30 calls/min) to stay at the configured `max_calls_per_minute: 30` rather
  than tripping its own rate limit. With the pair-of-calls-per-loop reading of
  the spec, the agent would issue 60 calls/min and be revoked.
- **Scripted mode is the default** for the attack. It deterministically
  demonstrates the injection and always exercises the kill switch. LLM mode is
  best-effort: if the API call fails, the agent falls back to scripted mode.
  Model behaviour is not guaranteed, which is the point — the gateway, not the
  model, is the control.
- **The kill switch keys off a denied call to a resource listed in
  `critical_resources`.** `citizens` is never granted to either demo task, so the
  attack is always out of scope first and triggers revocation.
- **Revocations are persisted in SQLite and checked on every call.** The
  sliding-window and denial counters are in memory; a process restart clears the
  counters but not revocations, which remain in force.
- **Stats:** "Attacks blocked" counts all deny decisions (policy denials plus
  revoked/invalid-token attempts), which is the useful demo signal. False
  positives is hard-coded to 0 because the demo has no labelled legitimate-denial
  data.
- **Latency** is measured from request entry to the decision, before the audit
  insert, so it reflects gateway decision overhead rather than SQLite write cost.
- **The attack is triggered from a separate service.** `attacker/server.py`
  (Flask, port 5000) owns the case-file agent. The dashboard calls the gateway,
  which delegates to `POST /attack`, so the compromise is launched outside the
  firewall process. Reset calls `/cancel`. If `ATTACKER_URL` is unset (plain
  uvicorn or tests), the gateway falls back to its embedded launcher. `run.sh`
  starts all three processes: gateway, attacker service, benefits agent.
- **The audit chain is tamper-evident, not tamper-proof.** An attacker with write
  access to the database can rewrite the entire chain. Production needs an
  append-only store, external anchoring or signatures.

---

## Honest limitations

- **Legitimate permissions can still be misused.** If a task genuinely needs
  `citizens:read`, this gateway cannot tell a good reason from a bad one. It
  enforces the ceiling, not intent.
- **Agents must route calls through the gateway.** A compromised agent with
  direct database or API credentials bypasses all of this. Enforcement only
  works when the gateway is the only path to the data.
- **Thresholds are fixed, not learned.** 30 calls/min and 3 denials are static
  values; there are no per-agent baselines, time-of-day models or anomaly
  scoring, so unusual-but-legitimate behaviour can trip the kill switch.
- **Malicious calls that stay in scope are allowed.** Scope checks are coarse
  (`resource:action`), with no row-level authorisation, argument validation or
  data-loss prevention inside the permitted action.
- **Single process, in-memory counters, SQLite.** Not horizontally scalable and
  counters reset on restart. Tokens cannot be individually revoked before expiry
  except by revoking the whole agent/task.
- **The audit log is only as trustworthy as the host.** Local SQLite with a hash
  chain detects casual edits, not a privileged attacker who rewrites everything.
- **LLM mode is non-deterministic and optional**, and the Anthropic path has not
  been exercised in CI (no key). Scripted mode is the tested path.
- **Authentication of the dashboard itself is absent.** Anyone who can reach the
  gateway can revoke agents or reset the demo; production needs operator SSO and
  audit of admin actions.
- **The external attacker service is unauthenticated** and can launch the
  compromised agent. It binds to loopback by default. Process separation is a
  demo of origin, not a hardened attacker environment; isolate it on its own host
  or network before using it beyond a local demo.
- **Demo tamper endpoint is intentionally destructive.** It exists to prove the
  chain works and must never ship in production.

---

## Next steps

1. **Human-approval tiers for sensitive actions.** Read-only low-risk scopes can
   auto-approve; `permits:update`, bulk reads and anything touching citizens go
   to a human queue with a signed approval token.
2. **Learned baselines.** Replace fixed thresholds with per-agent rolling
   profiles (call rate, resource mix, time-of-day) and score deviations; keep the
   kill switch as the hard backstop.
3. **Open policy format.** Publish a portable schema (task, scopes, data
   classification, approval tier, rate limits) that other agencies can adopt and
   diff, with signed policy bundles and a policy-change audit trail.
4. **Production audit anchoring.** Stream entry hashes to an append-only store or
   external notary; sign batches with an HSM-backed key.
5. **Gateway-only data plane.** Network policy and per-agent credentials so the
   gateway is structurally the only route to government data.
6. **Argument-aware authorisation.** Row-level rules, PII redaction and
   query-cost limits for actions that are legitimately in scope.

---

## Status

This is a hackathon prototype. The scripted demo path is deterministic and
requires no cloud account or API key. Run the test suite before submitting:

```bash
python -m pytest -q
```

The dashboard and demo endpoints are intentionally unauthenticated and should
only be exposed on a trusted network.
