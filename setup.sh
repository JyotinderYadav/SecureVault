#!/usr/bin/env bash
# ==============================================================================
# SecureVault Setup Script (macOS / Apple Silicon & Linux Compatible)
# Sets up virtual environment, installs dependencies, initializes storage and DB
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================================="
echo "🛡️  SecureVault: Vulnerability-Oriented REST API Testing"
echo "    Environment Setup & Dependency Verification"
echo "=========================================================="

# 1. Detect Python 3.10+ (preferring 3.11/3.12 on macOS Apple Silicon)
PYTHON_BIN=""
for cmd in python3.11 python3.12 python3.13 python3.10 python3 python; do
    if command -v "$cmd" >/dev/null 2>&1; then
        PY_VER=$("$cmd" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        PY_MAJOR=$("$cmd" -c 'import sys; print(sys.version_info.major)')
        PY_MINOR=$("$cmd" -c 'import sys; print(sys.version_info.minor)')
        if [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -ge 10 ]; then
            PYTHON_BIN="$cmd"
            echo "[✓] Found compatible Python: $cmd (version $PY_VER)"
            break
        fi
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo "[!] Error: Python 3.10+ is required, but none was found on PATH."
    echo "    Please install Python via: brew install python@3.11"
    exit 1
fi

# 2. Create or verify virtual environment
VENV_DIR="$SCRIPT_DIR/.venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Creating Python virtual environment in .venv..."
    "$PYTHON_BIN" -m venv "$VENV_DIR"
    echo "[✓] Virtual environment created successfully."
else
    echo "[✓] Existing virtual environment found in .venv"
fi

VENV_PYTHON="$VENV_DIR/bin/python"
VENV_PIP="$VENV_DIR/bin/pip"

# 3. Install dependencies if not already satisfied
echo "[*] Checking dependencies in virtual environment..."
if "$VENV_PYTHON" -c "import fastapi, streamlit, pytest, yaml, jwt, matplotlib" >/dev/null 2>&1; then
    echo "[✓] Core dependencies are already installed and functional."
else
    echo "[*] Installing dependencies from requirements.txt..."
    "$VENV_PIP" install -r requirements.txt --quiet || "$VENV_PIP" install -r requirements.txt
    echo "[✓] Dependencies installed."
fi

# 4. Initialize environment configuration
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        echo "[*] Creating .env from .env.example..."
        cp .env.example .env
        echo "[✓] Created .env configuration."
    fi
fi

# 5. Initialize storage directories and canary files
echo "[*] Initializing local storage directories..."
mkdir -p app/storage/uploads
mkdir -p results/raw results/processed results/tables results/figures paper/tables paper/figures

# Ensure vault_secret.txt canary file exists
if [ ! -f "app/storage/vault_secret.txt" ]; then
    echo "VAULT_SECRET_KEY=SECUREVAULT_FLAG_{PATH_TRAVERSAL_CWE_22_VERIFIED}" > app/storage/vault_secret.txt
    echo "CONFIDENTIAL_METRIC_DATA=VaultRoot_Access_Granted_2026" >> app/storage/vault_secret.txt
    echo "[✓] Seeded app/storage/vault_secret.txt canary."
fi

# 6. Initialize SQLite database and seed records
echo "[*] Initializing SQLite database schema and seed data..."
"$VENV_PYTHON" -c "
from app.core.database import init_db
init_db()
print('[✓] SQLite database successfully initialized at app/storage/securevault.db')
"

# 7. Perform verification import checks
echo "[*] Verifying critical module imports..."
"$VENV_PYTHON" -c "
import fastapi
import uvicorn
import pydantic
import streamlit
import pandas
import plotly
import yaml
import requests
import httpx
import jwt
import matplotlib
import pytest
from app.main import app
from framework import OpenAPISpecParser, CandidateInterfaceExtractor, TestSequenceGenerator, FeedbackTestRunner
print('[✓] All core subsystems and dependencies verified successfully.')
"

# 8. Ensure scripts are executable
chmod +x setup.sh start.sh stop.sh 2>/dev/null || true

echo "=========================================================="
echo "✅ Setup Complete!"
echo "   Start the platform: ./start.sh"
echo "   Stop the platform:  ./stop.sh"
echo "   Run test suite:     ./.venv/bin/pytest -v"
echo "=========================================================="
