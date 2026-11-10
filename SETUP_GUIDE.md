# SecureVault — Complete Setup & Operation Guide (macOS / Apple Silicon & Linux)

**Project:** SecureVault: Vulnerability-Oriented Security Testing of RESTful APIs  
**Academic Course:** CS-473 Cloud Security and SRE | IIIT Dharwad  
**Primary Reference:** *Vulnerability-oriented Testing for RESTful APIs (VOAPI²)* — Wenlong Du et al., USENIX Security 2024  
**Target Environment:** macOS (including Apple Silicon M1/M2/M3/M4 ARM64) & Linux  

---

## 1. System Requirements & Prerequisites

- **Operating System:** macOS 12+ (Apple Silicon ARM64 or Intel x86_64) or Linux (Ubuntu 20.04+, Debian 11+, Fedora 38+)
- **Python Version:** Python 3.10, 3.11, 3.12, or 3.13 (Python 3.11 recommended for maximum stability)
- **Homebrew (macOS):** For installing native dependencies:
  ```bash
  brew install python@3.11
  ```
- **Shell:** `bash` or `zsh`

---

## 2. Automated One-Click Installation

SecureVault provides an automated setup script that verifies Python availability, provisions a local virtual environment, installs native ARM64 dependencies, initializes configuration, creates storage directories, and seeds the SQLite database.

```bash
# 1. Navigate to the project root
cd /path/to/SecureVault

# 2. Make scripts executable (if needed)
chmod +x setup.sh start.sh stop.sh

# 3. Execute setup
./setup.sh
```

### What `setup.sh` Automates:
1. Detects compatible native Python 3.10+ binaries (`python3.11`, `python3.12`, `python3`).
2. Creates isolated virtual environment in `.venv`.
3. Installs requirements from `requirements.txt` (`fastapi`, `uvicorn`, `streamlit`, `pydantic`, `pyyaml`, `requests`, `httpx`, `PyJWT`, `matplotlib`, `plotly`, `pandas`, `openpyxl`, `pytest`).
4. Generates `.env` from `.env.example`.
5. Prepares `app/storage/uploads/` and populates `app/storage/vault_secret.txt` canary.
6. Initializes SQLite database tables and seeds users, confidential vault records, and items.
7. Executes module verification imports.

---

## 3. Starting the Platform

Launch both the **FastAPI backend** (port 8000) and the **Streamlit Research Lab UI** (port 8501) with a single command:

```bash
./start.sh
```

### Expected Output:
```
==========================================================
🛡️  Starting SecureVault Research Platform...
==========================================================
[*] Launching FastAPI backend server on http://127.0.0.1:8000...
[*] Waiting for API health check.... Ready!
[*] Launching Streamlit Research Lab UI on port 8501...
[*] Waiting for Streamlit UI..... Ready!

==========================================================
✅ SecureVault Services Successfully Running!
==========================================================
🌐 Streamlit Research Lab UI:  http://127.0.0.1:8501
📚 FastAPI OpenAPI Docs:       http://127.0.0.1:8000/docs
🔍 Health Check Endpoint:     http://127.0.0.1:8000/api/v1/health
----------------------------------------------------------
Process IDs:  FastAPI Backend (PID 14823) | Streamlit UI (PID 14836)
Logs:         results/execution_logs/api_server.log
              results/execution_logs/streamlit.log
Stop Servers: ./stop.sh
==========================================================
```

---

## 4. Application URLs

| Service / Interface | Local URL | Description |
| :--- | :--- | :--- |
| **Streamlit Research Lab** | [http://127.0.0.1:8501](http://127.0.0.1:8501) | Primary 15-module interactive research platform |
| **FastAPI Swagger UI** | [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) | Interactive OpenAPI 3.1 contract & live API testing |
| **FastAPI ReDoc** | [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc) | Clean academic API specification reference |
| **Service Health Check** | [http://127.0.0.1:8000/api/v1/health](http://127.0.0.1:8000/api/v1/health) | Public health and security mode status |
| **Security Mode Switcher** | [http://127.0.0.1:8000/api/v1/system/mode](http://127.0.0.1:8000/api/v1/system/mode) | Check/switch between VULNERABLE and HARDENED |
| **HTML Audit Dashboard** | [http://127.0.0.1:8000/api/v1/vault/audit/logs/view](http://127.0.0.1:8000/api/v1/vault/audit/logs/view) | Stored XSS trigger & compliance view |

---

## 5. Stopping the Platform

To cleanly terminate all running processes and release ports 8000 and 8501:

```bash
./stop.sh
```

The script gracefully terminates backend and frontend processes, guarantees removal of PID files, and cleans up any orphan listeners.

---

## 6. Running Automated Tests

Run the complete 26-test regression suite:

```bash
# Run with virtual environment
./.venv/bin/pytest -v

# Or activate environment first
source .venv/bin/activate
pytest -v
```

Expected result:
```
======================== 26 passed in ~1.30s =========================
```

---

## 7. Configuration (.env)

Edit `.env` to configure system behavior:

```ini
# Server Host & Ports
API_HOST=127.0.0.1
API_PORT=8000
STREAMLIT_PORT=8501

# System Security Mode: VULNERABLE or HARDENED
SECURITY_MODE=VULNERABLE

# Authentication & Cryptography
JWT_SECRET=securevault-cs473-secret-key-2026
JWT_ALGORITHM=HS256

# Storage Settings
STORAGE_DIR=app/storage/uploads
VAULT_STORAGE=app/storage
```

---

## 8. Troubleshooting

### Port Conflicts (8000 or 8501 in use)
Run:
```bash
./stop.sh
```
Or manually free the ports:
```bash
lsof -ti:8000 | xargs kill -9 2>/dev/null || true
lsof -ti:8501 | xargs kill -9 2>/dev/null || true
```

### Missing Module or Python Version Incompatibility
Ensure Python 3.10+ is active:
```bash
python3 --version
./setup.sh
```

### Viewing Logs
```bash
tail -f results/execution_logs/api_server.log
tail -f results/execution_logs/streamlit.log
```
