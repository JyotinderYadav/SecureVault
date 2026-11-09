# SecureVault: Vulnerability-Oriented Security Testing of RESTful APIs

[![Python Version](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.162.2-009688.svg)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.66.1-FF4B4B.svg)](https://streamlit.io/)
[![Tests](https://img.shields.io/badge/tests-15%2F15%20passing-brightgreen.svg)]()
[![License](https://img.shields.io/badge/license-Academic%20Research-lightgrey.svg)]()
[![USENIX Security 2024](https://img.shields.io/badge/USENIX%20Security-2024%20Reproduction-blueviolet.svg)](https://www.usenix.org/conference/usenixsecurity24/presentation/du)

**Academic Course:** CS-473 Cloud Security and Site Reliability Engineering (SRE)  
**Institution:** Indian Institute of Information Technology (IIIT) Dharwad  
**Primary Research Foundation:** *"Vulnerability-oriented Testing for RESTful APIs (VOAPI²)"* — Wenlong Du et al., USENIX Security 2024  

---

## 1. Executive Overview

**SecureVault** is an independent clean-room implementation, forensic empirical evaluation, and interactive research laboratory reproducing and extending the methodology of **VOAPI² (USENIX Security 2024)**.

Traditional REST API dynamic security testing tools (e.g., RESTler, EvoMaster) rely on unguided fuzzing that treats all API endpoints equally. In complex enterprise services, this causes catastrophic efficiency loss: thousands of requests generate shallow client errors (`400 Bad Request` / `422 Unprocessable Entity`), while failing to satisfy the multi-step state prerequisites required to reach deep business logic.

SecureVault addresses this challenge by realizing a **vulnerability-oriented** testing paradigm:
1. **Focuses Resources on High-Risk Interfaces:** Uses empirical semantic keyword matching across paths and parameters to isolate candidate attack surfaces.
2. **Reverse Sequence Construction (Algorithm 1):** Recursively works backward from candidate targets to automatically synthesize valid prerequisite request sequences, resolving dynamic entity dependencies (e.g., creating an entity before modifying or searching it).
3. **Multi-Signal Vulnerability Verification:** Injects harmless, non-destructive test probes and evaluates HTTP status codes, leaked canary flags, database query tautologies, unescaped HTML reflections, and execution latency.

---

## 2. The Six Investigated Vulnerability Classes

SecureVault models, tests, and hardens six critical vulnerability categories investigated in the base research:

| CWE ID | Vulnerability Class | CVSS Severity | Testbed Endpoint | Empirical Corpus Hit Rate |
| :--- | :--- | :---: | :--- | :---: |
| **CWE-918** | Server-Side Request Forgery (SSRF) | CRITICAL (8.6) | `/api/v1/vault/sync` | **81.0%** (17 / 21) |
| **CWE-434** | Unrestricted File Upload | CRITICAL (9.8) | `/api/v1/vault/upload` | **83.3%** (35 / 42) |
| **CWE-22** | Path Traversal | HIGH (7.5) | `/api/v1/vault/files/read` | **51.6%** (16 / 31) |
| **CWE-78** | OS Command Injection | CRITICAL (9.8) | `/api/v1/vault/tools/ping-backup` | **40.0%** (22 / 55) |
| **CWE-89** | SQL Injection (SQLi) | CRITICAL (8.9) | `/api/v1/vault/records/search` | **52.9%** (37 / 70) |
| **CWE-79** | Stored Cross-Site Scripting (XSS) | HIGH (7.2) | `/api/v1/vault/audit/logs` | **34.5%** (19 / 55) |

---

## 3. The 4-Stage Vulnerability-Oriented Pipeline

```
  [ OpenAPI 2.0 / 3.0 / 3.1 / Swagger Specification ]
                         │
                         ▼
   Stage 1: Specification Analysis & Normalization
      ├── Schema parsing & circular $ref pointer resolution
      ├── Parameter standardization (path, query, header, cookie)
      └── Producer-Consumer schema mapping
                         │
                         ▼
   Stage 2: Candidate Interface Extraction
      ├── 72 path keywords & 56 parameter keywords from CVE corpus
      ├── Priority scoring: Score = w_path * N_path + w_param * N_param
      └── Primary vulnerable parameter tagging (p_target)
                         │
                         ▼
   Stage 3: Test Sequence Generation (Algorithm 1)
      ├── Reverse sequence construction from target candidate
      ├── CRUD semantic matching & resource hierarchy pruning
      └── 5-tier parameter hierarchy: CONSUMER -> SPEC -> FORMAT -> SUCCESS -> RANDOM
                         │
                         ▼
   Stage 4: Feedback-Based Testing & Verification
      ├── Prerequisite state execution & dynamic value extraction
      ├── Injection of benign, non-destructive test probes
      └── Multi-signal oracle evaluation (Canaries, Tautologies, HTML, Timing)
                         │
                         ▼
   [ Verified Findings • Empirical Metrics • Defensive Mitigations ]
```

---

## 4. Forensic Corpus Reconciliation (541 vs 274 Records)

During our investigation of the official author-provided dataset (`CVE-Information.xlsx`), we resolved a prominent discrepancy in the literature:
- **Paper Text:** Mentions *"544 vulnerability records"*.
- **Workbook Reality:** Contains exactly **541 valid data records** (533 unique CVEs across 6 worksheets).
- **The Ground Truth:** The authors embedded metadata notes in row 2 of each sheet. Applying the author-defined filter `Detail Flag == '1'` isolates **exactly 274 records** with complete paths and parameters.
- **Precision:** The keyword hit rates on these 274 records match Table 1 of the USENIX publication with **100% precision**.

---

## 5. Empirical Results & Comparative Evaluation

We benchmarked SecureVault against an unguided **Baseline Random Fuzzer** on the SecureVault API testbed, and evaluated specification scalability across three prominent real-world applications:

### A. Head-to-Head Vulnerability Detection (SecureVault API)

| Evaluation Metric | Baseline Generic Fuzzing | SecureVault (VOAPI²) | Advantage / Improvement |
| :--- | :---: | :---: | :---: |
| **Detection Rate (Vulnerable Mode)** | **0.0%** (0 / 6 CWEs) | **100.0%** (6 / 6 CWEs) | **+100% Precision** |
| **Total HTTP Requests Required** | 48 requests | 15 requests | **68.8% Request Reduction** |
| **Execution Latency** | 1,078.1 ms | 162.8 ms | **6.6x Speedup** |
| **False Positive Rate (Hardened Mode)** | 0.0% (No findings) | 0.0% (All mitigated) | **Zero False Positives** |

### B. Multi-Application Specification Analysis Benchmark

| Application | Version | Format | # Operations | Parse Time | Extraction Time | # Candidates | Candidate Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **SecureVault API** | 1.0.0 | OpenAPI 3.1 | 16 | 0.52 ms | 2.79 ms | 13 | 81.2% |
| **Appwrite** | 0.9.3 | OpenAPI 3.0 | 95 | 3.54 ms | 16.33 ms | 77 | 81.1% |
| **Request Baskets** | 1.2.3 | OpenAPI 3.0 YAML | 20 | 66.19 ms | 4.10 ms | 16 | 80.0% |
| **Gitea** | 1.16.7 | Swagger 2.0 | 291 | 7.46 ms | 63.66 ms | 207 | 71.1% |
| **Total Benchmark Scale** | — | — | **422 Operations** | **77.71 ms** | **86.88 ms** | **313 Candidates** | **74.2% (Avg)** |

---

## 6. Installation & Reproduction Guide (Windows 11)

### Prerequisites
- Windows 10/11 (PowerShell or Command Prompt)
- Python 3.10+ (Tested on Python 3.13.15)
- Git

### Step 1: Clone and Navigate to the Workspace
```powershell
cd "d:\Academics\IIIT Dharwad Exams\Semester 7 (2026)\CLOUD SRE & SECURITY\SecureVault"
```

### Step 2: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 3: Run the Complete Pytest Verification Suite
Verify that all 15 unit and integration tests pass cleanly:
```powershell
pytest -v
```
*(Expected: 15 passed in ~1.4s)*

### Step 4: Run the Experimental Benchmarking Suite
Execute the automated harness to regenerate all logs, summary metrics, publication tables, and figures:
```powershell
python experiments/benchmark_comparison/run_all_experiments.py
```
*(Outputs saved to `results/raw/`, `results/processed/`, `results/tables/`, `results/figures/`, `paper/tables/`, and `paper/figures/`)*

### Step 5: Launch the Interactive Streamlit Research Lab
Launch the 14-page cybersecurity research laboratory:
```powershell
streamlit run ui/app.py
```
The application will open automatically in your browser at `http://localhost:8501`.

### Step 6: (Optional) Run the Dual-Mode FastAPI Testbed Independently
```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Interactive OpenAPI documentation is available at `http://127.0.0.1:8000/docs`.

---

## 7. Project Workspace Layout

```
SecureVault/
│
├── app/                                    # Target REST API Dual-Mode Testbed
│   ├── config/settings.py                  # Dynamic security mode switcher (VULNERABLE / HARDENED)
│   ├── core/                               # Database manager, SQLite schema, JWT authentication
│   ├── models/schemas.py                   # Pydantic v2 data models with semantic keywords
│   ├── routers/                            # 6 CWE vulnerability routers + auth + CRUD items
│   └── main.py                             # FastAPI application entrypoint
│
├── framework/                              # VOAPI² 4-Stage Security Testing Engine
│   ├── stage1_spec_analysis/               # OpenAPI 2.0/3.0/3.1 & Swagger schema parser
│   ├── stage2_candidate_extraction/        # Semantic keyword extractor & parameter tagger
│   ├── stage3_sequence_generation/         # Algorithm 1 (Reverse Sequence Construction)
│   └── stage4_feedback_testing/            # Runner, multi-signal vulnerability oracles & payloads
│
├── datasets/                               # Empirical Corpus & API Specifications
│   ├── vulnerability_corpus/raw/           # Original CVE-Information.xlsx & webshell payloads
│   ├── vulnerability_corpus/processed/     # Extracted 274 ground-truth records, 541 records, keywords
│   └── api_specifications/raw/             # Appwrite, Request Baskets, Gitea, SecureVault specs
│
├── experiments/                            # Experimental Benchmarking
│   ├── baseline_testing/random_fuzzer.py   # Unguided black-box baseline fuzzer
│   ├── targeted_testing/voapi2_tester.py   # Targeted VOAPI² testing harness
│   └── benchmark_comparison/               # Unified multi-application benchmarking orchestrator
│
├── results/                                # Generated Evaluation Artifacts
│   ├── raw/                                # Detailed JSON execution logs
│   ├── processed/                          # Summarized benchmark comparison JSON
│   ├── tables/                             # Publication-ready CSV benchmark tables
│   └── figures/                            # High-resolution (300 DPI) visualization figures
│
├── ui/                                     # Streamlit Interactive Research Lab
│   ├── components/styling.py               # Dark slate cyber theme & custom CSS
│   ├── views/                              # 14 modular views (Dashboard, Lab, Explorer, Analytics, etc.)
│   └── app.py                              # Streamlit application entrypoint
│
├── paper/                                  # Academic Publication Draft & Tables
│   ├── research_paper.md                   # Full academic paper draft (USENIX / IEEE S&P format)
│   ├── tables/                             # Embedded evaluation tables
│   └── figures/                            # Embedded evaluation plots
│
├── tests/                                  # Pytest Automated Test Suite (15/15 Passing)
│   ├── test_api_endpoints.py               # Testbed dual-mode verification (10 tests)
│   └── test_framework_stages.py            # Stages 1-4 end-to-end testing (5 tests)
│
├── docs/                                   # Research & Threat Modeling Documentation
├── PROGRESS.md                             # Comprehensive 7-phase development progress audit log
└── requirements.txt                        # Python dependencies
```

---

## 8. Academic Citation & References

If referencing this work, please cite both our implementation and the primary research foundation:

```bibtex
@inproceedings{securevault2026,
  title={{SecureVault: Vulnerability-Oriented Security Testing of RESTful APIs}},
  author={{SecureVault Research Team}},
  booktitle={{CS-473 Cloud Security and SRE Course Laboratory}},
  institution={{Indian Institute of Information Technology (IIIT) Dharwad}},
  year={2026}
}

@inproceedings{voapi2du2024,
  author    = {Wenlong Du and Qingchuan Zhao and Yongsen Zheng and Yu Wang and Shouling Ji and Lin Zhang},
  title     = {{Vulnerability-oriented Testing for RESTful APIs}},
  booktitle = {33rd USENIX Security Symposium (USENIX Security 24)},
  year      = {2024},
  address   = {Philadelphia, PA},
  publisher = {USENIX Association}
}
```

---

## 9. Academic Disclaimer

*SecureVault is developed strictly for educational, defensive, and academic research purposes within the CS-473 Cloud Security and SRE curriculum at IIIT Dharwad. All security testing mechanisms are designed for and restricted to locally hosted, authorized test environments. Never deploy or execute security testing tools against systems or services without explicit written authorization.*
