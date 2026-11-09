# SecureVault Datasets Catalog

This directory manages datasets, specifications, and metadata for the SecureVault project, inspired by the VOAPI² research methodology (USENIX Security 2024).

**Acquisition Date:** November 10, 2026  
**Primary Source:** [NSSL-SJTU/VoAPI2](https://github.com/NSSL-SJTU/VoAPI2)  

---

## Directory Inventory

### 1. `vulnerability_corpus/`
- **`raw/CVE-Information.xlsx`**: Original binary workbook provided by the authors of VOAPI² containing 541 vulnerability records across 6 worksheets, with detailed annotations.
- **`raw/APIUploadPayloads/`**: Original webshell probe payloads downloaded directly from the official repository (`webshell.php`, `webshell.jsp`, `webshell.asp`, `webshell.aspx`).
- **`processed/vulnerabilities_274.json`**: Filtered dataset of the 274 ground-truth vulnerabilities (`Detail Flag == 1`) corresponding to Table 1 in USENIX Security 2024.
- **`processed/vulnerabilities_all_541.json`**: Complete structured JSON representation of all 541 records from `CVE-Information.xlsx`.
- **`processed/semantic_keywords.json`**: Machine-readable keyword mappings for API paths and parameters across all six vulnerability classes (CWE-918, CWE-434, CWE-22, CWE-78, CWE-89, CWE-79).
- **`processed/test_payloads.json`**: Benign, non-destructive test payloads organized by CWE category for safe local testbed verification.

### 2. `api_specifications/`
- **`raw/APISpec-appwrite.json`**: Official OpenAPI 3.0 specification for Appwrite 0.9.3 (65 paths, 95 HTTP operations) from the VOAPI² repository.
- **`raw/rbaskets-openapi.yaml`**: Official OpenAPI 3.0 specification for Request Baskets (`darklynx/request-baskets`).
- **`raw/gitea-1.16.7-swagger.json`**: Official Swagger 2.0 template for Gitea 1.16.7 (184 paths, 291 HTTP operations).

### 3. `benchmark_applications/`
- Catalog definitions and metadata descriptors for the evaluated benchmark targets.

---

## Integrity & Licence Notice
- All downloaded original artifacts (`CVE-Information.xlsx`, `APISpec-appwrite.json`, `APIUploadPayloads/*`) are preserved unchanged.
- The original VOAPI² repository does not declare an open-source licence (All Rights Reserved by SJTU NSSL). Artifacts are retained solely under academic fair use for non-commercial research reproduction.
- Independently collected or converted files are strictly labeled in `processed/`.
