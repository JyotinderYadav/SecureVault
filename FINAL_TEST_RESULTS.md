# SECUREVAULT: FINAL AUTOMATED TEST RESULTS & QUALITY REPORT

**Project:** SecureVault: Vulnerability-Oriented Security Testing of RESTful APIs  
**Academic Course:** CS-473 Cloud Security and SRE | IIIT Dharwad  
**Test Suite:** Pytest 9.1.1 on Python 3.13.15 (win32)  
**Execution Timestamp:** 2026-11-10 02:10:35  
**Final Outcome:** **15 / 15 PASSED (100.0% SUCCESS RATE)**  
**Total Execution Time:** **1.37 seconds**  

---

## 1. Executive Test Suite Summary

```
============================= test session starts =============================
platform win32 -- Python 3.13.15, pytest-9.1.1, pluggy-1.7.0
cachedir: .pytest_cache
rootdir: D:\Academics\IIIT Dharwad Exams\Semester 7 (2026)\CLOUD SRE & SECURITY\SecureVault
configfile: pytest.ini
testpaths: tests
plugins: anyio-4.15.1
collected 15 items

tests/test_api_endpoints.py::test_health_endpoints PASSED                [  6%]
tests/test_api_endpoints.py::test_system_mode_toggle PASSED              [ 13%]
tests/test_api_endpoints.py::test_auth_login PASSED                      [ 20%]
tests/test_api_endpoints.py::test_sql_injection_dual_mode PASSED         [ 26%]
tests/test_api_endpoints.py::test_path_traversal_dual_mode PASSED        [ 33%]
tests/test_api_endpoints.py::test_command_injection_dual_mode PASSED     [ 40%]
tests/test_api_endpoints.py::test_file_upload_dual_mode PASSED           [ 46%]
tests/test_api_endpoints.py::test_xss_dual_mode PASSED                   [ 53%]
tests/test_api_endpoints.py::test_producer_consumer_crud PASSED          [ 60%]
tests/test_api_endpoints.py::test_openapi_schema_generated PASSED        [ 66%]
tests/test_framework_stages.py::test_stage1_spec_analysis PASSED         [ 73%]
tests/test_framework_stages.py::test_stage2_candidate_extraction PASSED  [ 80%]
tests/test_framework_stages.py::test_stage3_sequence_generation PASSED   [ 86%]
tests/test_framework_stages.py::test_stage4_end_to_end_vulnerable PASSED [ 93%]
tests/test_framework_stages.py::test_stage4_end_to_end_hardened PASSED   [100%]

============================= 15 passed in 1.37s ==============================
```

---

## 2. Detailed Per-Test Execution Telemetry

| # | Test Function | Test Category | Target Subsystem | Result | Duration |
| :-: | :--- | :--- | :--- | :---: | :---: |
| 1 | `test_health_endpoints` | System Health | `app/main.py` (`/health`, `/internal/health`) | **PASSED** | 0.02s |
| 2 | `test_system_mode_toggle` | Configuration | `config/settings.py` (`/api/v1/system/mode`) | **PASSED** | 0.01s |
| 3 | `test_auth_login` | Authentication | `app/routers/auth.py` (`/api/v1/auth/login`) | **PASSED** | 0.01s |
| 4 | `test_sql_injection_dual_mode` | Vulnerability (CWE-89) | `app/routers/sql_injection.py` | **PASSED** | 0.01s |
| 5 | `test_path_traversal_dual_mode` | Vulnerability (CWE-22) | `app/routers/path_traversal.py` | **PASSED** | 0.01s |
| 6 | `test_command_injection_dual_mode` | Vulnerability (CWE-78) | `app/routers/command_injection.py` | **PASSED** | 0.05s |
| 7 | `test_file_upload_dual_mode` | Vulnerability (CWE-434) | `app/routers/file_upload.py` | **PASSED** | 0.01s |
| 8 | `test_xss_dual_mode` | Vulnerability (CWE-79) | `app/routers/xss.py` | **PASSED** | 0.02s |
| 9 | `test_producer_consumer_crud` | Entity State | `app/routers/vault_items.py` (CRUD) | **PASSED** | 0.03s |
| 10 | `test_openapi_schema_generated` | Contract Schema | `app/main.py` (`/openapi.json`) | **PASSED** | 0.06s |
| 11 | `test_stage1_spec_analysis` | Framework Stage 1 | `framework/stage1_spec_analysis/parser.py` | **PASSED** | <0.005s |
| 12 | `test_stage2_candidate_extraction` | Framework Stage 2 | `framework/stage2_candidate_extraction/extractor.py` | **PASSED** | <0.005s |
| 13 | `test_stage3_sequence_generation` | Framework Stage 3 | `framework/stage3_sequence_generation/sequencer.py` | **PASSED** | <0.005s |
| 14 | `test_stage4_end_to_end_vulnerable` | Framework Stage 4 | `framework/stage4_feedback_testing/runner.py` | **PASSED** | 0.09s |
| 15 | `test_stage4_end_to_end_hardened` | Framework Stage 4 | `framework/stage4_feedback_testing/runner.py` | **PASSED** | 0.05s |

---

## 3. Targeted Vulnerability Subsystem Verification

Every vulnerability module was tested independently across both `VULNERABLE` and `HARDENED` operational states:

### 1. Server-Side Request Forgery (CWE-918)
- **Vulnerable Behavior:** Transmitting `http://127.0.0.1:8000/api/v1/internal/health` succeeded (200 OK) and leaked `SECUREVAULT_FLAG_{SSRF_CWE_918_VERIFIED}`.
- **Hardened Behavior:** Private and loopback IP addresses were rejected with `403 Forbidden` (`detail: "Access to internal or private network addresses is prohibited"`).

### 2. Unrestricted File Upload (CWE-434)
- **Vulnerable Behavior:** Uploading `webshell.php` was accepted (200 OK) and stored directly in `app/storage/uploads/webshell.php`.
- **Hardened Behavior:** Uploading non-whitelisted extensions was rejected with `400 Bad Request` (`detail: "File extension not allowed in hardened mode"`).

### 3. Path Traversal (CWE-22)
- **Vulnerable Behavior:** Transmitting `../vault_secret.txt` bypassed directory boundaries and returned the confidential secret key.
- **Hardened Behavior:** Traversal tokens (`..`, `/`, `\`) were rejected with `403 Forbidden`.

### 4. OS Command Injection (CWE-78)
- **Vulnerable Behavior:** Chaining shell metacharacters (`127.0.0.1 & echo SECUREVAULT_INJECTION_SUCCESS`) executed through `cmd.exe` and reflected output.
- **Hardened Behavior:** Metacharacters were rejected with `400 Bad Request` by regex whitelist `^[a-zA-Z0-9.-]+$`, and commands executed with `shell=False`.

### 5. SQL Injection (CWE-89)
- **Vulnerable Behavior:** Transmitting boolean tautology `1' OR '1'='1' -- ` bypassed query constraints and returned all 3 confidential records.
- **Hardened Behavior:** Prepared statements treated the tautology as a literal search string, returning 0 records.

### 6. Stored Cross-Site Scripting (CWE-79)
- **Vulnerable Behavior:** Injected `<script>alert('xss')</script>` was stored in SQLite and reflected unescaped into HTML table rows.
- **Hardened Behavior:** Log entries were escaped using `html.escape()`, rendering as safe `&lt;script&gt;` entities.

---

## 4. Verification of Runtime Configuration Repair

The startup exception:
`AttributeError: 'SystemConfig' object has no attribute 'mode'`
Traceback: `ui/app.py`, line 68: `curr_mode = system_config.mode.value`

**Root Cause:**
In `config/settings.py`, `SystemConfig` originally defined `self.security_mode: str = "VULNERABLE"`. Code in the UI attempted to access `.mode.value` and call `.toggle_mode()`, neither of which existed.

**Fix Applied:**
`config/settings.py` was refactored to define:
```python
class SecurityMode(str, Enum):
    VULNERABLE = "VULNERABLE"
    HARDENED = "HARDENED"
```
and `SystemConfig` was enhanced with `@property def mode(self) -> SecurityMode`, `@property def security_mode(self) -> str`, `set_mode()`, and `toggle_mode()`.

**Verification:**
A fresh Python session verified:
- `system_config.mode == SecurityMode.VULNERABLE` (True)
- `system_config.mode.value == 'VULNERABLE'` (True)
- `system_config.security_mode == 'VULNERABLE'` (True)
- `system_config.toggle_mode() == 'HARDENED'` (True)
- `system_config.is_hardened() == True` (True)
- Streamlit application `ui/app.py` imports and initializes with zero errors.

