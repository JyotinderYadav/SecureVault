# SecureVault — Comprehensive Quality Assurance & Automated Test Report

**Project:** SecureVault: Vulnerability-Oriented Security Testing of RESTful APIs  
**Academic Course:** CS-473 Cloud Security and SRE | IIIT Dharwad  
**Primary Reference:** *Vulnerability-oriented Testing for RESTful APIs (VOAPI²)* — Wenlong Du et al., USENIX Security 2024  
**Date of Execution:** November 10, 2026  
**Test Framework:** Pytest 9.2.0 (Python 3.11.11, Apple Silicon Darwin ARM64)  
**Overall Result:** **26 / 26 TESTS PASSED (100% Pass Rate)**  
**Total Execution Time:** **1.30 seconds**  

---

## 1. Executive Test Suite Summary

| Subsystem Under Test | Module Name | Tests Executed | Passed | Failed | Pass Rate |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Backend REST API & Dual-Mode CWEs** | `tests/test_api_endpoints.py` | 10 | 10 | 0 | **100%** |
| **Datasets, SRE Hardening & DB** | `tests/test_datasets_and_audit.py` | 7 | 7 | 0 | **100%** |
| **VOAPI² 4-Stage Testing Pipeline** | `tests/test_framework_stages.py` | 5 | 5 | 0 | **100%** |
| **UI Data Models & View Entrypoints** | `tests/test_ui_and_models.py` | 4 | 4 | 0 | **100%** |
| **All Subsystems Combined** | **Full Regression Suite** | **26** | **26** | **0** | **100%** |

---

## 2. Granular Test Case Execution Results

### A. Backend REST API & Dual-Mode CWE Modules (`tests/test_api_endpoints.py`)

| Test Identifier | Category / Focus | Description | Duration | Status |
| :--- | :--- | :--- | :---: | :---: |
| `test_health_endpoints` | API Infrastructure | Verifies `/api/v1/health` and internal canary `/api/v1/internal/health` | 0.02s | **PASSED** |
| `test_system_mode_toggle` | Security Policy | Verifies dynamic mode switching between VULNERABLE and HARDENED | 0.01s | **PASSED** |
| `test_auth_login` | Authentication & JWT | Verifies login, invalid credential rejection, token issuance, and protected `/api/v1/auth/me` | 0.03s | **PASSED** |
| `test_sql_injection_dual_mode` | CWE-89 | Verifies boolean tautology bypass in Vulnerable mode vs parameterized literal match in Hardened mode | 0.02s | **PASSED** |
| `test_path_traversal_dual_mode` | CWE-22 | Verifies `../vault_secret.txt` leak in Vulnerable mode vs 403 Forbidden in Hardened mode | 0.02s | **PASSED** |
| `test_command_injection_dual_mode`| CWE-78 | Verifies shell command chaining in Vulnerable mode, metacharacter rejection (400), and safe execution on macOS in Hardened mode | 0.03s | **PASSED** |
| `test_file_upload_dual_mode` | CWE-434 | Verifies `.php` script execution in Vulnerable mode vs extension whitelisting rejection (400) in Hardened mode | 0.03s | **PASSED** |
| `test_xss_dual_mode` | CWE-79 | Verifies raw script reflection in Vulnerable mode vs HTML entity sanitization (`&lt;script&gt;`) in Hardened mode | 0.03s | **PASSED** |
| `test_producer_consumer_crud` | Stage 3 Prerequisites | Verifies POST item creation, GET item retrieval by dynamic UUID, and DELETE removal | 0.02s | **PASSED** |
| `test_openapi_schema_generated` | OpenAPI Contract | Verifies generation and structure of FastAPI OpenAPI 3.1.0 JSON contract | 0.02s | **PASSED** |

### B. Datasets, SRE Hardening & Database Operations (`tests/test_datasets_and_audit.py`)

| Test Identifier | Category / Focus | Description | Duration | Status |
| :--- | :--- | :--- | :---: | :---: |
| `test_dataset_cve_corpus_integrity`| Corpus Forensics | Reconciles 541 raw CVE rows, 274 ground-truth records (`detail_flag == '1'`), and semantic keywords | 0.04s | **PASSED** |
| `test_benchmark_specifications_parsing`| Stage 1 Scalability | Ingests all 4 OpenAPI specs (SecureVault 16, Appwrite 95, Rbaskets 20, Gitea 291 ops = 422 ops total) | 0.15s | **PASSED** |
| `test_multi_spec_candidate_extraction_counts`| Stage 2 Candidate Triage | Validates candidate extraction across all 4 benchmark specifications (exactly 341 candidate pairs) | 0.18s | **PASSED** |
| `test_ssrf_ip_filtering_rules` | CWE-918 SRE Hardening | Verifies blocking of 127.0.0.1, private RFC 1918 subnets, 169.254.169.254, and pass-through of public IPs | 0.01s | **PASSED** |
| `test_password_hashing_and_verification`| Cryptography & Auth | Tests PBKDF2-HMAC-SHA256 (100,000 rounds) hashing and verification with legacy fallback | 0.04s | **PASSED** |
| `test_database_initialization_and_operations`| Database Integrity | Verifies SQLite table creation, seeding, vulnerable query execution, and hardened parameterized query | 0.03s | **PASSED** |
| `test_experiment_logs_and_summaries_exist`| Evaluation Integrity | Confirms validity and presence of `comparison_summary.json` and raw execution traces | 0.01s | **PASSED** |

### C. VOAPI² 4-Stage Security Testing Pipeline (`tests/test_framework_stages.py`)

| Test Identifier | Stage Focus | Description | Duration | Status |
| :--- | :--- | :--- | :---: | :---: |
| `test_stage1_spec_analysis` | Stage 1 (Spec Analysis) | Normalizes operations, parameters, schemas, and resolves circular $ref pointers | 0.02s | **PASSED** |
| `test_stage2_candidate_extraction`| Stage 2 (Candidate Triage) | Keyword matching across all 6 CWEs, 3-tier priority scoring, and target parameter tagging | 0.02s | **PASSED** |
| `test_stage3_sequence_generation` | Stage 3 (Reverse Sequencing)| Algorithm 1 dependency resolution: synthesizes `⟨POST /items, GET /items/{id}⟩` for consumer endpoint | 0.02s | **PASSED** |
| `test_stage4_end_to_end_vulnerable`| Stage 4 (Targeted Testing) | Closed-loop testing of all 6 target CWE endpoints in VULNERABLE mode: confirms 6/6 detected | 0.18s | **PASSED** |
| `test_stage4_end_to_end_hardened` | Stage 4 (Mitigation Audit) | Closed-loop testing in HARDENED mode: verifies 100% defense mitigation across all 6 categories | 0.09s | **PASSED** |

### D. UI Data Models & View Entrypoints (`tests/test_ui_and_models.py`)

| Test Identifier | Category / Focus | Description | Duration | Status |
| :--- | :--- | :--- | :---: | :---: |
| `test_system_config_interface` | Configuration Model | Verifies SecurityMode enum, mode string compatibility, `.is_vulnerable()`, `.is_hardened()` | 0.01s | **PASSED** |
| `test_openapi_spec_parser_canonical_parse`| Parser Compatibility | Verifies `.parse()` and `.analyze()` dual interfaces on `OpenAPISpecParser` | 0.02s | **PASSED** |
| `test_findings_model_and_loader` | Findings Deserialization| Validates `FindingRecord` attribute and dictionary access, handling empty and wrapped log files | 0.02s | **PASSED** |
| `test_all_15_views_importable` | UI Navigation Hierarchy | Validates that all 15 modular view rendering functions are cleanly importable and callable | 0.03s | **PASSED** |

---

## 3. End-to-End Live Socket Verification

Active live testing against the running FastAPI testbed (`http://127.0.0.1:8000`) confirmed:

```
=== VULNERABLE MODE ===
✓ CWE-918 (SSRF): HTTP 200 OK — Leaked flag: SECUREVAULT_FLAG_{SSRF_CWE_918_VERIFIED}
✓ CWE-434 (Upload): HTTP 200 OK — Executable script stored (is_executable: True)
✓ CWE-22  (Path Traversal): HTTP 200 OK — Leaked flag: SECUREVAULT_FLAG_{PATH_TRAVERSAL_CWE_22_VERIFIED}
✓ CWE-78  (Command Injection): HTTP 200 OK — Command output reflected: VoAPICmdTest
✓ CWE-89  (SQL Injection): HTTP 200 OK — Tautology returned 3 confidential records
✓ CWE-79  (Stored XSS): HTTP 200 OK — Raw unescaped <script> tag reflected in HTML view

=== HARDENED MODE ===
✓ CWE-918 (SSRF): HTTP 403 Forbidden — Blocked private/loopback destination
✓ CWE-434 (Upload): HTTP 400 Bad Request — Disallowed dangerous extension
✓ CWE-22  (Path Traversal): HTTP 403 Forbidden — Traversal sequences blocked
✓ CWE-78  (Command Injection): HTTP 400 Bad Request — Metacharacters rejected; safe non-shell execution
✓ CWE-89  (SQL Injection): HTTP 200 OK — Parameterized query returned 0 matches
✓ CWE-79  (Stored XSS): HTTP 200 OK — Reflected output strictly HTML-escaped (&lt;script&gt;)
```

---

## 4. UI Module Verification

All 15 Streamlit views were independently verified using `streamlit.testing.v1.AppTest`:
- **Overview Dashboard:** PASSED (KPIs, Pipeline visualizer, Bar chart, Telemetry console)
- **Research Methodology:** PASSED (Theoretical foundations, Algorithm 1 trace)
- **Dataset Explorer:** PASSED (541 raw vs 274 ground-truth records, multi-field filtering)
- **Vulnerability Intelligence:** PASSED (Table 2 dictionaries, side-by-side code comparisons)
- **Specification Analyzer:** PASSED (4 OpenAPI specifications, circular graph topology)
- **Candidate Interface Extraction:** PASSED (Stage 2 triage, priority score distribution)
- **Test Sequence Generator:** PASSED (Algorithm 1 interactive reverse sequencing)
- **Feedback-Based Testing:** PASSED (Live sequence execution, payload injection, oracle evaluation)
- **Controlled Attack Simulation:** PASSED (6 CWE attack probes against local testbed)
- **Benchmark Applications:** PASSED (Comparative spec scale and candidate analysis)
- **Experimental Evaluation:** PASSED (Targeted vs unguided random fuzzing comparison)
- **Performance Analytics:** PASSED (Publication-grade latency and request efficiency charts)
- **Research Findings:** PASSED (Dual-mode forensic findings inspector)
- **Research Reports:** PASSED (Executive summary generation and Markdown/JSON export)
- **Project Documentation:** PASSED (Embedded architectural and threat model documents)
