# Dataset Documentation, Schema & Verification Report

**Reference:** *Vulnerability-oriented Testing for RESTful APIs (VOAPI²)* — Wenlong Du et al., USENIX Security 2024.  
**Repository Source:** `https://github.com/NSSL-SJTU/VoAPI2`  
**Acquisition Timestamp:** 2026-11-10T01:10:00+05:30  
**Verification Tooling:** Python 3.13 reproducible parser (`scratch/inspect_cve_xlsx.py`, `scratch/check_detail_flags.py`)  

---

## 1. Provenance of the Original Vulnerability Corpus

The base paper (Section 3.1, Page 5) states:
> *"First, we collected 544 vulnerabilities related to APIs with publicly available detailed descriptions from sources such as CVE and NVD to build a dataset. We then clustered these vulnerabilities based on their CWE IDs and ranked the CWE IDs according to the number of vulnerabilities they encompassed. We selected the six clusters of CWE IDs with the highest proportion."*

In Footnote 2 (Page 4), the paper provides the link to the actual dataset:
> `https://github.com/NSSL-SJTU/VoAPI2/blob/main/CVE-Information.xlsx`

### File Characteristics
- **Filename:** `datasets/vulnerability_corpus/raw/CVE-Information.xlsx`
- **File Size:** 61,005 bytes
- **Format:** Microsoft Excel OpenXML Spreadsheet (`.xlsx`)
- **Licence:** No explicit open-source licence specified in the repository (All Rights Reserved, SJTU NSSL). Stored for academic research reproduction under Fair Use.

---

## 2. Workbook Structure & Worksheet Breakdown

The workbook contains **6 worksheets**, each corresponding to one of the six CWE categories:

| Sheet Index | Worksheet Name | Target CWE | Total Rows | Columns Count | Columns in Worksheet |
| :---: | :--- | :---: | :---: | :---: | :--- |
| **1** | `SSRF` | CWE-918 | 53 | 9 | `['CWE-ID', 'CVE IDs', 'Detail Flag', 'Vul Path', 'Vul Params', 'Functionality Source', 'Functionality', 'How we get functionality', 'Summary ']` |
| **2** | `Unrestricted  Upload` | CWE-434 | 71 | 9 | `['CWE-ID', 'CVE IDs', 'Detail Flag', 'Vul Path', 'Vul Params', 'Functionality Source', 'Functionality', 'How we get functionality', 'Summary']` |
| **3** | `Path Traversal ` | CWE-22 | 99 | 9 | `['CWE-ID', 'CVE IDs', 'Detail Flag', 'Vul Path', 'Vul Params', 'Functionality Source', 'Functionality', 'How we get functionality', 'Summary (added by bobo)']` |
| **4** | `SQL Injection` | CWE-89 | 99 | 6 | `['CWE-ID', 'CVE IDs', 'Detail Flag', 'Vul Path', 'Vul Params', 'Summary']` |
| **5** | `Command Injection` | CWE-78 | 120 | 10 | `['CWE-ID', 'CVE IDs', 'Detail Flag', 'Vul Path', 'Vul Params', 'Functionality Source', 'Functionality', 'How we get functionality', 'Summary (added by bobo)', '']` |
| **6** | `XSS` | CWE-79 | 99 | 6 | `['CWE-ID', 'CVE IDs', 'Detail Flag', 'Vul Path', 'Vul Params', 'Summary']` |

*Total raw rows across all 6 worksheets:* **541 data records** (plus 6 header rows).

---

## 3. Reconciliation: The 541 Records vs. Table 1 (274 Ground-Truth Records)

Forensic inspection of Column C (`Detail Flag`) reveals how the authors selected the 274 vulnerabilities reported in Table 1:

- `Detail Flag == '1'`: Vulnerabilities with detailed API endpoints, paths, and parameter locations disclosed.
- `Detail Flag == '0'`: Vulnerabilities without detailed API endpoint paths disclosed.

| Vulnerability Type | CWE ID | Total Records in Sheet | Detail Flag = '1' | Reported in Table 1 | Author Hit Rate Annotation in Row 2 |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Server-Side Request Forgery** | CWE-918 | 53 | **21** | **21** | `Hit Rate = 17/21 = 81%` |
| **Unrestricted File Upload** | CWE-434 | 71 | **42** | **42** | `Hit Rate = 35/42 = 83%` |
| **Path Traversal** | CWE-22 | 99 | **31** | **31** | `Hit Rate = 16/31 = 52%` |
| **SQL Injection** | CWE-89 | 99 | **70** | **70** | `Hit Rate = 37/70 = 53%` |
| **OS Command Injection** | CWE-78 | 120 | **56** (55 with path) | **55** | `Hit Rate = 22/55 = 40%` |
| **Cross-Site Scripting (XSS)** | CWE-79 | 99 | **55** | **55** | `Hit Rate = 19/55 = 35%` |
| **TOTAL** | — | **541** | **275** (274 with path) | **274** | **146 / 274 = 53.3%** |

### Findings:
1. The **541** rows in `CVE-Information.xlsx` correspond to the authors' initial pool of ~544 API CVEs (a minor 3-record difference, likely removed due to deprecation or duplicate merging).
2. The records marked with `Detail Flag == '1'` containing valid paths match the **274** ground-truth records in Table 1.
3. In Command Injection, record `CVE-2020-7633` has `Detail Flag == '1'` with parameter `pluginUri` but lacks `Vul Path`, accounting for the 56 vs 55 count.
4. Total unique CVEs across the workbook: **533** (with 6 CVE IDs appearing in multiple worksheets due to multi-vulnerability disclosures, e.g., `CVE-2020-25206` in both XSS and Command Injection).

---

## 4. Semantic Keywords Extracted (Table 2 vs. Codebase)

The extracted keywords are stored in machine-readable JSON at `datasets/vulnerability_corpus/processed/semantic_keywords.json`.

| CWE ID | Vulnerability Class | API Type | Table 2 Path Count | Codebase Path Count | Table 2 Param Count | Codebase Param Count |
| :---: | :--- | :--- | :---: | :---: | :---: | :---: |
| **CWE-918** | SSRF | Resource Request APIs | 10 | 10 | 22 | 22 |
| **CWE-434** | Unrestricted Upload | File Upload APIs | 12 | 12 | 8 | 8 |
| **CWE-22** | Path Traversal | Path Processing APIs | 12 | 6 | 3 | 3 |
| **CWE-78** | Command Injection | System Configuration APIs | 12 | 12 | 7 | 7 |
| **CWE-89** | SQL Injection | Database Operation APIs | 11 | 11 | 4 | 5 |
| **CWE-79** | XSS | Text Display APIs | 15 | 15 | 12 | 12 |
| **Total** | — | — | **72** | **66** | **56** | **57** |

*Discrepancy Notes:*
- For `path_api`, Table 2 listed 12 path keywords; the authors' runtime dictionary in `VoAPIGlobalData.py` contains 6 core keywords (`download`, `export`, `fetch`, `file`, `path`, `category`).
- For `database_api`, Table 2 listed 4 parameter keywords; the authors' runtime dictionary includes 5 keywords (`sql`, `query`, `id`, `select`, `field`).
- Both counts and definitions are formally preserved in `semantic_keywords.json`.

---

## 5. Acquired OpenAPI Specifications

Saved in `datasets/api_specifications/raw/`:

1. **`APISpec-appwrite.json`**:
   - **Source:** `NSSL-SJTU/VoAPI2` (AppwriteExample)
   - **Target Version:** Appwrite 0.9.3
   - **OpenAPI Version:** 3.0.0
   - **Paths Count:** 65
   - **HTTP Operations Count:** **95** (Exactly matches Table 4 #Endpoints = 95)
   - **Licence:** BSD-3-Clause

2. **`rbaskets-openapi.yaml`**:
   - **Source:** `darklynx/request-baskets` (doc/rbaskets-openapi.yaml)
   - **Target Version:** Request Baskets 1.2.3
   - **OpenAPI Version:** 3.0.0
   - **Paths Count:** 10 (22 total operations)
   - **Licence:** Apache-2.0

3. **`gitea-1.16.7-swagger.json`**:
   - **Source:** `go-gitea/gitea` (templates/swagger/v1_json.tmpl)
   - **Target Version:** Gitea 1.16.7
   - **OpenAPI Version:** Swagger 2.0
   - **Paths Count:** 184 (291 operations)
   - **Licence:** MIT
