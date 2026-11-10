# SecureVault: Deployment Fix Log & Modernization Changelog

**Project:** SecureVault — Vulnerability-Oriented Security Testing of RESTful APIs  
**Academic Affiliation:** IIIT Dharwad — CS-473 Cloud Security and SRE  
**Execution Phase:** Phase 7 UI/UX Modernization & Cloud Hardening  
**Target Git Branch:** `main`  

---

## 1. Cloud Deployment & Security Hardening Fixes

### FIX-DEPLOY-01: Deployment Environment Auto-Detection
- **Target File:** `config/settings.py`
- **Changes:**
  - Implemented `IS_HOSTED` detection checking `STREAMLIT_SHARING_MODE == "streamlit-cloud"`, `IS_STREAMLIT_CLOUD == "1"`, or `HOME` starting with `/home/appuser`.
  - Added `is_hosted` property to `SystemConfig`.
  - Added automatic verification test `test_cloud_environment_detection_and_safeguards`.

### FIX-DEPLOY-02: Public Cloud VULNERABLE Exploit Mode Prevention
- **Target Files:** `config/settings.py`, `ui/app.py`, `ui/views/overview.py`, `ui/views/attack_simulation.py`, `ui/views/feedback_testing.py`
- **Changes:**
  - When `is_hosted` is True, `SystemConfig.set_mode()` and `SystemConfig.toggle_mode()` strictly force `SecurityMode.HARDENED` and reject toggling into `VULNERABLE` mode.
  - Replaced the mode toggle button on cloud deployments with a prominent informational security badge: `"Hosted Cloud Policy: HARDENED DEFENSE ACTIVE"`.
  - Ensured that benign test probes in Stage 4 execution verify defensive filtering and mitigation rather than exposing a live exploit surface to public networks.

### FIX-DEPLOY-03: Cold-Start SQLite Database Auto-Initialization
- **Target File:** `streamlit_app.py`
- **Changes:**
  - Added idempotent call to `init_db()` upon Streamlit container launch.
  - Automatically initializes all 4 tables (`users`, `vault_records`, `audit_logs`, `vault_items`) and populates seed data with hashed credentials.

### FIX-DEPLOY-04: Graceful File Upload Fallback for Sandboxes
- **Target File:** `app/routers/file_upload.py`
- **Changes:**
  - Wrapped physical disk writes in a `try/except (OSError, PermissionError)` block.
  - Prevents 500 Internal Server Errors on read-only cloud container filesystems while preserving full response payload validation and oracle verification.

### FIX-DEPLOY-05: Vault Secret File Auto-Provisioning
- **Target File:** `config/settings.py`
- **Changes:**
  - Added automatic creation of `app/storage/vault_secret.txt` if missing to ensure Path Traversal (CWE-22) test probes consistently target valid ground-truth secret files.

### FIX-DEPLOY-06: Python 3.11 Runtime Pinning & System Packages
- **Target Files:** `.python-version`, `packages.txt`
- **Changes:**
  - Added `.python-version` with `3.11`.
  - Added `packages.txt` for Streamlit Community Cloud package manager.

---

## 2. Phase 7 UI/UX Modernization & Information Architecture

### FIX-UI-01: Information Architecture & 6-Group Navigation Reorganization
- **Target File:** `ui/app.py`
- **Changes:**
  - Reorganized all 15 modular views into 6 logical research groups (Phase 7.3):
    1. **Overview** (`📊 Dashboard`)
    2. **Research** (`🔬 Research Methodology`, `📂 Dataset Explorer`, `🛡️ Vulnerability Intelligence`)
    3. **Analysis Pipeline** (`📄 Specification Analyzer`, `🎯 Candidate Extraction`, `⚡ Sequence Generator`, `🔁 Feedback Testing`)
    4. **Security Testing** (`⚔️ Controlled Attack Simulation`, `🏛️ Benchmark Applications`)
    5. **Results** (`🧪 Experimental Evaluation`, `📈 Performance Analytics`, `🔍 Research Findings`, `📑 Research Reports`)
    6. **Documentation** (`📚 Project Documentation`)
  - Added `st.session_state["nav_selection"]` synchronization with one-click return to the Dashboard.

### FIX-UI-02: Dashboard Redesign & Live Telemetry KPI Cards
- **Target File:** `ui/views/overview.py`
- **Changes:**
  - Implemented 8 authentic data-driven KPI cards (Phase 7.4):
    - *API Operations Analyzed:* 422 Ops across 4 specs
    - *Vulnerability Candidates:* 341 candidates extracted
    - *Unique Candidate Ops:* 13 testbed candidate interfaces
    - *Target CWE Classes:* 6 evaluated categories
    - *Total Test Requests:* 126 requests (15 VOAPI² vs 48 baseline)
    - *Confirmed Vulnerabilities:* 7 confirmed exploits in Vulnerable mode
    - *Mitigated Defenses:* 10 defenses verified in Hardened mode
    - *Latest Experiment Status:* COMPLETED (100% precision reproduction)
  - Added Recent Security Testing Activity table extracted directly from `results/raw/voapi2_vulnerable_log.json`.
  - Added 4 Quick Action cards (`render_action_card`) for direct navigation.

### FIX-UI-03: Four-Stage Pipeline Visualizer Enhancement
- **Target File:** `ui/components/pipeline_visualizer.py`
- **Changes:**
  - Added clear Input / Output artifact contracts for each stage (Phase 7.5).
  - Added execution status badges (`✓ Completed`, `⚡ Running`, `○ Pending`).
  - Added real processing latency benchmarks (0.33 ms to 133.4 ms).
  - Added directional flow arrows indicating Stage 1 ➔ 2 ➔ 3 ➔ 4.

### FIX-UI-04: Design System & Visual Token Modernization
- **Target File:** `ui/components/styling.py`
- **Changes:**
  - Added `.action-card` styles with smooth cubic-bezier lift effects.
  - Added high-contrast status badge classes: `.badge-confirmed`, `.badge-negative`, `.badge-potential`.
  - Retained strict 65% Light Canvas / 35% Dark Command Console composition.

---

## 3. Automated Test Suite Expansion

- **Target File:** `tests/test_ui_and_models.py`
- **Added Tests:**
  - `test_cloud_environment_detection_and_safeguards`: Verifies `IS_HOSTED` detection and enforcement of `HARDENED` security policy.
  - `test_ui_app_navigation_structure`: Verifies all 15 modules and 6 logical groups are properly registered and callable.
- **Suite Result:** **28 / 28 PASSED** in 1.18s.
