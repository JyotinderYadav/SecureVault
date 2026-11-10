#!/usr/bin/env bash
# ==============================================================================
# SecureVault Startup Script
# Starts FastAPI backend (port 8000) and Streamlit frontend (port 8501)
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 1. Environment and dependencies check
if [ ! -d ".venv" ]; then
    echo "[!] Virtual environment .venv not found. Running setup.sh first..."
    ./setup.sh
fi

source .venv/bin/activate

# Load environment configuration if available
if [ -f ".env" ]; then
    set -a
    source .env
    set +a
fi

API_HOST="${API_HOST:-127.0.0.1}"
API_PORT="${API_PORT:-8000}"
STREAMLIT_PORT="${STREAMLIT_PORT:-8501}"

LOG_DIR="$SCRIPT_DIR/results/execution_logs"
mkdir -p "$LOG_DIR"

API_LOG="$LOG_DIR/api_server.log"
UI_LOG="$LOG_DIR/streamlit.log"
API_PID_FILE="$SCRIPT_DIR/.api.pid"
UI_PID_FILE="$SCRIPT_DIR/.ui.pid"

echo "=========================================================="
echo "🛡️  Starting SecureVault Research Platform..."
echo "=========================================================="

# Stop any previously running instances on these ports
if [ -f "./stop.sh" ]; then
    ./stop.sh --quiet 2>/dev/null || true
fi

# 2. Start FastAPI Backend Server
echo "[*] Launching FastAPI backend server on http://${API_HOST}:${API_PORT}..."
uvicorn app.main:app --host "$API_HOST" --port "$API_PORT" > "$API_LOG" 2>&1 &
API_PID=$!
echo "$API_PID" > "$API_PID_FILE"

# Wait for API to become ready
echo -n "[*] Waiting for API health check..."
for i in {1..20}; do
    if curl -s "http://${API_HOST}:${API_PORT}/api/v1/health" | grep -q "HEALTHY"; then
        echo " Ready!"
        break
    fi
    sleep 0.5
    echo -n "."
done

if ! curl -s "http://${API_HOST}:${API_PORT}/api/v1/health" | grep -q "HEALTHY"; then
    echo ""
    echo "[!] Error: FastAPI server failed to start within 10 seconds."
    echo "    Check logs at: $API_LOG"
    cat "$API_LOG" | tail -n 20
    exit 1
fi

# 3. Start Streamlit Frontend
echo "[*] Launching Streamlit Research Lab UI on port ${STREAMLIT_PORT}..."
streamlit run ui/app.py \
    --server.port "$STREAMLIT_PORT" \
    --server.address "$API_HOST" \
    --server.headless true \
    --browser.gatherUsageStats false > "$UI_LOG" 2>&1 &
UI_PID=$!
echo "$UI_PID" > "$UI_PID_FILE"

# Wait for Streamlit to start
echo -n "[*] Waiting for Streamlit UI..."
for i in {1..20}; do
    if curl -s -I "http://${API_HOST}:${STREAMLIT_PORT}" | grep -qE "200|304"; then
        echo " Ready!"
        break
    fi
    sleep 0.5
    echo -n "."
done

echo ""
echo "=========================================================="
echo "✅ SecureVault Services Successfully Running!"
echo "=========================================================="
echo "🌐 Streamlit Research Lab UI:  http://${API_HOST}:${STREAMLIT_PORT}"
echo "📚 FastAPI OpenAPI Docs:       http://${API_HOST}:${API_PORT}/docs"
echo "🔍 Health Check Endpoint:     http://${API_HOST}:${API_PORT}/api/v1/health"
echo "----------------------------------------------------------"
echo "Process IDs:  FastAPI Backend (PID $API_PID) | Streamlit UI (PID $UI_PID)"
echo "Logs:         $API_LOG"
echo "              $UI_LOG"
echo "Stop Servers: ./stop.sh"
echo "=========================================================="
