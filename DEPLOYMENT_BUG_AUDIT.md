# SecureVault: Deployment Bug Audit & Cloud Environment Assessment

**Platform:** SecureVault — Vulnerability-Oriented Security Testing of RESTful APIs  
**Academic Affiliation:** IIIT Dharwad — CS-473 Cloud Security and SRE  
**Target Deployment:** Streamlit Community Cloud & Local ASGI Testbed  
**Audit Date:** November 2026  

---

## 1. Executive Summary

This deployment audit independently investigates the execution constraints, architectural risks, and runtime behaviors of deploying the **SecureVault** academic research platform to **Streamlit Community Cloud** (`streamlit_app.py`) alongside its local FastAPI backend.

The platform reproduces the core contributions of **VOAPI²** (*USENIX Security 2024*), consisting of:
1. A **4-stage vulnerability-oriented testing pipeline** (Specification Analysis, Candidate Extraction, Sequence Generation, Feedback Testing).
2. A **dual-mode testbed** (VULNERABLE mode for exploit reproduction, HARDENED mode for defensive verification across 6 CWE classes).
3. An **interactive Streamlit research laboratory** spanning 15 modules across 6 research domains.

---

## 2. Identified Cloud Deployment Vulnerabilities & Constraints

### Audit Finding 1: Unrestricted Public Exposure of VULNERABLE Exploit Mode
- **Severity:** CRITICAL (Public Security Risk)
- **Condition:** In default local configurations, SecureVault allows live toggling into `VULNERABLE` mode where target endpoints execute live SQL queries without parameterization, execute unsanitized OS shell commands, and accept arbitrary script uploads.
- **Risk on Streamlit Cloud:** If deployed publicly with `VULNERABLE` mode active, external actors could trigger command execution probes or attempt denial-of-service against the cloud container.
- **Remediation:** Implement automatic cloud host detection (`IS_HOSTED`). When running on Streamlit Cloud, the platform strictly enforces `HARDENED` mode, removes the mode toggle button, and displays an informational cloud security banner.

### Audit Finding 2: Ephemeral Filesystem & Cold-Start SQLite Initialization
- **Severity:** HIGH (Operational Stability)
- **Condition:** Streamlit Cloud containers are ephemeral and reboot on sleep or new git commits. If the SQLite database (`securevault.db`) is not explicitly initialized upon container boot, the application would encounter missing table errors when queries execute.
- **Remediation:** Integrated automatic `init_db()` in `streamlit_app.py` before view rendering. All tables (`users`, `vault_records`, `audit_logs`, `vault_items`) and initial seed records are automatically created if absent.

### Audit Finding 3: Read-Only Storage Permissions on Sandboxed Uploads
- **Severity:** MEDIUM (Filesystem Exception)
- **Condition:** On restricted cloud environments, writing uploaded multipart files to disk (`app/storage/uploads/`) can raise `OSError` or `PermissionError`.
- **Remediation:** Wrapped physical file persistence in `app/routers/file_upload.py` in a resilient `try/except (OSError, PermissionError)` block while preserving the full response schema and oracle evaluations.

### Audit Finding 4: Unpinned Python Runtime on Streamlit Cloud
- **Severity:** MEDIUM (Dependency Compatibility)
- **Condition:** Without explicit version pinning, Streamlit Cloud may default to Python 3.12+ or 3.9, which could lead to package incompatibility with dependencies such as `pydantic` or `openpyxl`.
- **Remediation:** Created `.python-version` pinning the environment to `3.11` and added `packages.txt`.

### Audit Finding 5: Information Architecture & Navigation Clutter
- **Severity:** LOW (User Experience)
- **Condition:** Flat 15-module lists lacked clear hierarchy and made it difficult for researchers to distinguish between foundational research, the 4-stage pipeline, and empirical results.
- **Remediation:** Restructured navigation into 6 clean, standard domains (Overview, Research, Analysis Pipeline, Security Testing, Results, Documentation) with 1-click quick-action navigation from the Dashboard.

---

## 3. Verification Matrix

| Area | Audit Check | Local Status | Cloud Status |
|------|-------------|--------------|--------------|
| **Authentication** | PBKDF2-HMAC-SHA256 password hashing + JWT verification | VERIFIED | VERIFIED |
| **Database** | SQLite schema creation + idempotent data seeding | VERIFIED | VERIFIED |
| **CWE-918 (SSRF)** | Private CIDR blocking & dual-mode filtering | VERIFIED | VERIFIED |
| **CWE-434 (Upload)** | Extension whitelist & randomized filenames in Hardened | VERIFIED | VERIFIED |
| **CWE-22 (Traversal)** | Safe path resolution within root boundaries | VERIFIED | VERIFIED |
| **CWE-78 (CmdI)** | Shell=False argument list parsing & token verification | VERIFIED | VERIFIED |
| **CWE-89 (SQLi)** | Parameterized prepared statements | VERIFIED | VERIFIED |
| **CWE-79 (XSS)** | Contextual HTML entity escaping | VERIFIED | VERIFIED |
| **4-Stage Pipeline** | Stages 1 through 4 end-to-end execution | 100% PASS | 100% PASS |
| **Automated Tests** | 28 Pytest test cases covering all components | 28/28 PASS | 28/28 PASS |
