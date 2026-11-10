#!/usr/bin/env bash
# ==============================================================================
# SecureVault Shutdown Script
# Gracefully stops FastAPI backend and Streamlit frontend processes
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

QUIET=false
if [ "$1" == "--quiet" ]; then
    QUIET=true
fi

if [ "$QUIET" = false ]; then
    echo "=========================================================="
    echo "🛑 Shutting Down SecureVault Services..."
    echo "=========================================================="
fi

API_PID_FILE="$SCRIPT_DIR/.api.pid"
UI_PID_FILE="$SCRIPT_DIR/.ui.pid"

# 1. Stop FastAPI Backend from PID file
if [ -f "$API_PID_FILE" ]; then
    API_PID=$(cat "$API_PID_FILE")
    if kill -0 "$API_PID" 2>/dev/null; then
        if [ "$QUIET" = false ]; then echo "[*] Stopping FastAPI backend (PID $API_PID)..."; fi
        kill "$API_PID" 2>/dev/null || true
        # Wait up to 3 seconds for graceful shutdown
        for i in {1..6}; do
            if ! kill -0 "$API_PID" 2>/dev/null; then break; fi
            sleep 0.5
        done
        # Force kill if still alive
        if kill -0 "$API_PID" 2>/dev/null; then
            kill -9 "$API_PID" 2>/dev/null || true
        fi
    fi
    rm -f "$API_PID_FILE"
fi

# 2. Stop Streamlit Frontend from PID file
if [ -f "$UI_PID_FILE" ]; then
    UI_PID=$(cat "$UI_PID_FILE")
    if kill -0 "$UI_PID" 2>/dev/null; then
        if [ "$QUIET" = false ]; then echo "[*] Stopping Streamlit UI (PID $UI_PID)..."; fi
        kill "$UI_PID" 2>/dev/null || true
        for i in {1..6}; do
            if ! kill -0 "$UI_PID" 2>/dev/null; then break; fi
            sleep 0.5
        done
        if kill -0 "$UI_PID" 2>/dev/null; then
            kill -9 "$UI_PID" 2>/dev/null || true
        fi
    fi
    rm -f "$UI_PID_FILE"
fi

# 3. Clean up any remaining orphan processes on ports 8000 and 8501
if command -v lsof >/dev/null 2>&1; then
    ORPHAN_8000=$(lsof -ti:8000 2>/dev/null || true)
    if [ -n "$ORPHAN_8000" ]; then
        if [ "$QUIET" = false ]; then echo "[*] Releasing port 8000 (PID $ORPHAN_8000)..."; fi
        kill -9 $ORPHAN_8000 2>/dev/null || true
    fi

    ORPHAN_8501=$(lsof -ti:8501 2>/dev/null || true)
    if [ -n "$ORPHAN_8501" ]; then
        if [ "$QUIET" = false ]; then echo "[*] Releasing port 8501 (PID $ORPHAN_8501)..."; fi
        kill -9 $ORPHAN_8501 2>/dev/null || true
    fi
fi

# Ensure pattern-matched background jobs are terminated
pkill -f "uvicorn app.main:app" 2>/dev/null || true
pkill -f "streamlit run ui/app.py" 2>/dev/null || true

if [ "$QUIET" = false ]; then
    echo "=========================================================="
    echo "✅ All SecureVault services stopped cleanly."
    echo "=========================================================="
fi
