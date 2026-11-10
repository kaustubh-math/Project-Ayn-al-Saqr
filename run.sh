#!/usr/bin/env bash
# Ayn al-Saqr - one command to start the gateway, dashboard and demo agent.
set -euo pipefail
cd "$(dirname "$0")"

LAN=0
for arg in "$@"; do
  case "$arg" in
    --lan) LAN=1 ;;
    -h|--help)
      echo "Usage: ./run.sh [--lan]"
      echo "  --lan  Bind the gateway and attacker console to all interfaces"
      echo "         so other devices on the LAN can reach them."
      echo "Env: AYN_PORT, ATTACKER_PORT, AYN_HOST, ATTACKER_HOST"
      exit 0
      ;;
    *)
      echo "[ayn] Unknown option: $arg (try --help)" >&2
      exit 2
      ;;
  esac
done

PORT="${AYN_PORT:-8000}"
ATTACKER_PORT="${ATTACKER_PORT:-5000}"
HOST="${AYN_HOST:-127.0.0.1}"
ATTACKER_HOST="${ATTACKER_HOST:-127.0.0.1}"
if [ "$LAN" = "1" ]; then
  HOST="0.0.0.0"
  ATTACKER_HOST="0.0.0.0"
fi
export ATTACKER_HOST
PYTHON_BIN="${PYTHON:-python}"

if [ ! -x ".venv/Scripts/python.exe" ] && [ ! -x ".venv/bin/python" ]; then
  echo "[ayn] creating virtual environment..."
  "$PYTHON_BIN" -m venv .venv
fi
if [ -x ".venv/Scripts/python.exe" ]; then
  VP=".venv/Scripts/python.exe"
else
  VP=".venv/bin/python"
fi

ATTACKER_PROBE_HOST="$ATTACKER_HOST"
if [ "$ATTACKER_PROBE_HOST" = "0.0.0.0" ]; then
  ATTACKER_PROBE_HOST="127.0.0.1"
fi

LAN_MODE=0
if [ "$HOST" = "0.0.0.0" ] || [ "$ATTACKER_HOST" = "0.0.0.0" ]; then
  LAN_MODE=1
fi
LAN_IP=""
if [ "$LAN_MODE" = "1" ]; then
  LAN_IP="$("$VP" -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(('8.8.8.8',80)); print(s.getsockname()[0]); s.close()" 2>/dev/null || true)"
  if [ -z "$LAN_IP" ]; then LAN_IP="<this-machine-ip>"; fi
fi

echo "[ayn] installing dependencies..."
"$VP" -m pip install --quiet --disable-pip-version-check -r requirements.txt

mkdir -p data logs
echo "[ayn] seeding database..."
"$VP" -m gateway.db

# Stop agents and services left behind by a previous run.sh, if any.
if [ -f logs/benefits_agent.pid ]; then
  OLD_PID="$(cat logs/benefits_agent.pid 2>/dev/null || true)"
  if [ -n "${OLD_PID:-}" ] && kill -0 "$OLD_PID" 2>/dev/null; then
    kill "$OLD_PID" 2>/dev/null || true
  fi
fi
if [ -f logs/attacker_server.pid ]; then
  OLD_ATTACKER_PID="$(cat logs/attacker_server.pid 2>/dev/null || true)"
  if [ -n "${OLD_ATTACKER_PID:-}" ] && kill -0 "$OLD_ATTACKER_PID" 2>/dev/null; then
    kill "$OLD_ATTACKER_PID" 2>/dev/null || true
  fi
fi

export GATEWAY_URL="http://127.0.0.1:${PORT}"
export ATTACKER_URL="http://127.0.0.1:${ATTACKER_PORT}"
if [ "$LAN_MODE" = "1" ]; then
  export PUBLIC_GATEWAY_URL="http://${LAN_IP}:${PORT}"
else
  export PUBLIC_GATEWAY_URL="http://127.0.0.1:${PORT}"
fi
export PYTHONUNBUFFERED=1

echo "[ayn] starting benefits agent (green traffic)..."
"$VP" agents/benefits_agent.py > logs/benefits_agent.log 2>&1 &
AGENT_PID=$!
echo "$AGENT_PID" > logs/benefits_agent.pid

echo "[ayn] starting external attacker service on port ${ATTACKER_PORT}..."
"$VP" attacker/server.py > logs/attacker_server.log 2>&1 &
ATTACKER_PID=$!
echo "$ATTACKER_PID" > logs/attacker_server.pid

cleanup() {
  kill "${AGENT_PID:-}" "${ATTACKER_PID:-}" 2>/dev/null || true
}
trap cleanup INT TERM EXIT

ATTACKER_READY=0
for _ in $(seq 1 40); do
  if "$VP" -c "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://${ATTACKER_PROBE_HOST}:${ATTACKER_PORT}/health', timeout=1).status == 200 else 1)" >/dev/null 2>&1; then
    ATTACKER_READY=1
    break
  fi
  sleep 0.25
done
if [ "$ATTACKER_READY" != "1" ]; then
  echo "[ayn] ERROR: attacker service did not start on port ${ATTACKER_PORT}." >&2
  echo "[ayn] See logs/attacker_server.log. Port in use? Try ATTACKER_PORT=5001 ./run.sh" >&2
  exit 1
fi

echo ""
echo "=================================================================="
echo "  Ayn al-Saqr | عين الصقر - Task Firewall"
echo "  Dashboard : http://localhost:${PORT}"
echo "  API docs  : http://localhost:${PORT}/docs"
echo "  Attacker  : http://localhost:${ATTACKER_PORT}"
echo "  Agent log : logs/benefits_agent.log"
if [ "$LAN_MODE" = "1" ]; then
  echo "------------------------------------------------------------------"
  echo "  LAN MODE  : reachable from other devices on this network"
  echo "  Gateway   : http://${LAN_IP}:${PORT}"
  echo "  Attacker  : http://${LAN_IP}:${ATTACKER_PORT}"
  echo "  Firewall  : allow inbound TCP ${PORT} and ${ATTACKER_PORT}"
  echo "              on Private networks only (or scope to the other IP)"
  echo "  Remote    : GATEWAY_URL=http://${LAN_IP}:${PORT} python agents/casefile_agent.py"
  echo "  WARNING   : demo and admin endpoints are unauthenticated."
  echo "              Use a trusted LAN and stop the server after the demo."
fi
echo "  Press Ctrl+C to stop."
echo "=================================================================="
echo ""

"$VP" -m uvicorn gateway.main:app --host "$HOST" --port "$PORT"
