# SECUREVAULT: EXPERIMENTAL REPRODUCIBILITY GUIDE & PROTOCOL

**Project:** SecureVault: Vulnerability-Oriented Security Testing of RESTful APIs  
**Academic Course:** CS-473 Cloud Security and SRE | IIIT Dharwad  
**Primary Research Foundation:** *"Vulnerability-oriented Testing for RESTful APIs (VOAPI²)"* — Wenlong Du et al., USENIX Security 2024  
**Operating Environment:** Windows 10/11 x64, Python 3.10+ (Verified on Python 3.13.15)  
**Budget & Infrastructure:** Strictly ₹0 (Localhost loopback; zero cloud or third-party paid services)  

---

## 1. Cryptographic Provenance of Raw Research Artifacts

To guarantee data integrity and prevent silent tampering, all raw research artifacts acquired from the official VOAPI² repository (`https://github.com/NSSL-SJTU/VoAPI2`) have been hashed using SHA-256:

| Artifact Path | SHA-256 Checksum | Description |
| :--- | :--- | :--- |
| `datasets/vulnerability_corpus/raw/CVE-Information.xlsx` | `36f589bee67c596848c9b8347f13be566c53c323452d568256f7aaabefd0a4e0` | Official 6-sheet vulnerability workbook |
| `datasets/api_specifications/raw/APISpec-appwrite.json` | `bab0700a3176c8a080015ef981fdac900f6b6234f98f46069675d2d6d330ee71` | Appwrite 0.9.3 OpenAPI 3.0 (95 operations) |
| `datasets/api_specifications/raw/rbaskets-openapi.yaml` | `0e4b05c61a457ce507f1a72defd3e29b64302297d1bfe3e0b03dd388131761e1` | Request Baskets 1.2.3 OpenAPI 3.0 (20 operations)|
| `datasets/api_specifications/raw/gitea-1.16.7-swagger.json` | `73c201ed67f0a65e1242c84cb2e7f529d8e8ee80c684792302813f5206537b4f` | Gitea 1.16.7 Swagger 2.0 (291 operations) |
| `datasets/vulnerability_corpus/raw/APIUploadPayloads/webshell.php` | `78eb5a522d4f6c12c8f93b657879c3734f42ac72531c9a1379f45836727610e0` | Benign probe webshell for PHP |
| `datasets/vulnerability_corpus/raw/APIUploadPayloads/webshell.jsp` | `2af6722cc7a4cdc6713d842f42deaf5106aabe26205ddbd29eabf1158a9f29e5` | Benign probe webshell for JSP |
| `datasets/vulnerability_corpus/raw/APIUploadPayloads/webshell.asp` | `ecabb2043d939612d945c4f0398a3b1a5f05645ea5f3a6a4668408d8d0e8bce1` | Benign probe webshell for ASP |
| `datasets/vulnerability_corpus/raw/APIUploadPayloads/webshell.aspx` | `8ed658b8b28c7cb7a089e34639c0f4c865ea3e82a402ef4be75f7f9265f7a757` | Benign probe webshell for ASPX |

---

## 2. Step-by-Step Reproduction Instructions

### Step 1: Environment Preparation (PowerShell)
```powershell
# Navigate to the project root directory
cd "d:\Academics\IIIT Dharwad Exams\Semester 7 (2026)\CLOUD SRE & SECURITY\SecureVault"

# Verify Python version (requires Python 3.10+)
python --version
# Output: Python 3.13.15 (or equivalent)

# Install required open-source dependencies
pip install -r requirements.txt
```

### Step 2: Quality Assurance & Automated Test Verification
Execute the test suite verifying all 15 unit and integration tests across the dual-mode testbed and 4 framework stages:
```powershell
pytest -v --durations=0
```
**Expected Output:**
```
============================= 15 passed in ~1.4s ==============================
```

### Step 3: Run the Complete Experimental Benchmark Harness
Re-run the automated experimental orchestrator to execute both Baseline Fuzzing and VOAPI² across Vulnerable and Hardened modes, analyze all 4 specifications, and regenerate all output tables and figures:
```powershell
python experiments/benchmark_comparison/run_all_experiments.py
```
**Expected Output:**
```
=========================================================
   SECUREVAULT EXPERIMENTAL BENCHMARK HARNESS
=========================================================
[*] Running Experiment 1: Comparative Evaluation on SecureVault...
    [+] Exported vulnerability detection table.
[*] Running Experiment 2: Specification Analysis on Real-World Benchmarks...
    [+] Exported specification analysis benchmark table.
[*] Generating Publication-Quality Figures...
    [+] Generated Figure 1: detection_comparison_chart.png
    [+] Generated Figure 2: cwe_distribution_chart.png
    [+] Generated Figure 3: request_efficiency_chart.png
=========================================================
   ALL EXPERIMENTS COMPLETED SUCCESSFULLY
=========================================================
```

### Step 4: Verify Output Files on Disk
Inspect generated evaluation tables and figures:
- `results/tables/vulnerability_detection_table.csv`
- `results/tables/spec_analysis_benchmark_table.csv`
- `results/processed/comparison_summary.json`
- `results/figures/detection_comparison_chart.png` (300 DPI)
- `results/figures/request_efficiency_chart.png` (300 DPI)
- `results/figures/cwe_distribution_chart.png` (300 DPI)

### Step 5: Launch the Interactive Research Lab (Streamlit UI 2.0)
```powershell
streamlit run ui/app.py
```
Open your browser to `http://localhost:8501`.
- Verify the 65% Light / 35% Dark visual composition.
- Test the sidebar mode switch button (`VULNERABLE` $\leftrightarrow$ `HARDENED`).
- Navigate through all 14 pages (Overview, Methodology, Dataset Explorer, Threat Intelligence, Spec Analyzer, Candidate Extractor, Sequence Generator, Attack Simulation, Findings, Benchmarks, Evaluation, Analytics, Reports, and Docs).
- In Page 8 (Live Attack Simulation Lab), select any of the 6 CWE classes and execute a live probe.

### Step 6: (Optional) Independent FastAPI Server Launch
```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Navigate to `http://127.0.0.1:8000/docs` to inspect interactive Swagger UI documentation.

---

## 3. Expected Numerical Results

| Metric | Baseline Generic Fuzzing | SecureVault (VOAPI²) |
| :--- | :---: | :---: |
| **Confirmed Vulnerabilities (Vulnerable Mode)** | 0 / 6 (0.0%) | **6 / 6 (100.0%)** |
| **Total HTTP Requests Required** | 48 | **15 (68.8% reduction)** |
| **Execution Latency** | ~400–1,000 ms | **~150 ms (6.6x speedup)** |
| **Hardened Mode Mitigations Verified** | 0 (No detections) | **10 / 10 (100.0%)** |
| **False Positives in Hardened Mode** | 0 | **0 (0.0% FPR)** |

---

## 4. Deterministic Parameter Configurations & Seeds

- **Random Seed:** 42 (configured in `experiments/baseline_testing/random_fuzzer.py` to ensure reproducible baseline fuzz permutations).
- **Candidate Interface Weights:** $w_{path} = 1.0$, $w_{param} = 2.0$ (configured in `framework/stage2_candidate_extraction/extractor.py`).
- **Algorithm 1 Max Search Depth:** 5 (configured in `framework/stage3_sequence_generation/sequencer.py`).
- **JWT Signing Algorithm:** HS256 (configured in `config/settings.py`).
