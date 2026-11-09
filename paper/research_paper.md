# SecureVault: Vulnerability-Oriented Security Testing of RESTful APIs

**Authors:** SecureVault Research Team  
**Institution:** Indian Institute of Information Technology (IIIT) Dharwad  
**Course:** CS-473 Cloud Security and Site Reliability Engineering (SRE)  
**Date:** November 2026  
**Primary Foundation:** *Vulnerability-oriented Testing for RESTful APIs (VOAPI²)* — Wenlong Du et al., USENIX Security 2024  

---

## Abstract

RESTful Application Programming Interfaces (APIs) serve as the architectural backbone of modern cloud-native computing, microservices, and mobile backends. However, their pervasive deployment and complex state dependencies have made them prime vectors for critical security vulnerabilities, including Server-Side Request Forgery (SSRF), Unrestricted File Upload, Path Traversal, OS Command Injection, SQL Injection, and Cross-Site Scripting (XSS). Conventional black-box fuzzers (e.g., RESTler, EvoMaster) explore the API state space uniformly, generating vast quantities of blind, unguided test cases that predominantly trigger shallow syntactic validation errors (`400 Bad Request`) while failing to penetrate deep business logic or state prerequisites.

In this paper, we present **SecureVault**, an independent, clean-room implementation, forensic empirical evaluation, and interactive research laboratory reproducing and extending the methodology of **VOAPI² (USENIX Security 2024)**. SecureVault realizes a four-stage testing pipeline: (1) automated specification analysis and schema normalization for OpenAPI 2.0/3.0/3.1 and Swagger documents; (2) candidate interface extraction driven by an empirical vulnerability knowledge base spanning 72 path keywords and 56 parameter keywords; (3) test sequence generation via Algorithm 1 (Reverse Sequence Construction) with producer-consumer dependency resolution; and (4) feedback-based testing powered by multi-signal vulnerability oracles and benign test probes.

We conduct an extensive forensic audit of the base research artifacts (`CVE-Information.xlsx`), clarifying discrepancies between the paper's reported 544 records and the actual 541 raw records (reconciled to exactly 274 ground-truth records via `Detail Flag == '1'`). Furthermore, we evaluate SecureVault across a dual-mode testbed (`VULNERABLE` vs. `HARDENED`) and three real-world open-source benchmarks examined in the original paper: Appwrite (95 operations), Request Baskets (20 operations), and Gitea (291 operations). Our empirical results demonstrate that while baseline unguided fuzzing achieves 0% detection across all six vulnerability classes (48 requests, 1,078 ms), SecureVault achieves **100% precision and detection** across all target classes using only **15 requests** (a 68.8% request reduction and 6.6x execution speedup), with zero false positives under hardened defensive configurations. Finally, we provide an interactive cybersecurity research laboratory and concrete SRE defensive hardening guidelines for cloud-native API deployments.

---

## 1. Introduction

Cloud computing infrastructures rely extensively on Representational State Transfer (REST) APIs to interconnect distributed microservices, databases, and client-facing interfaces. According to recent cloud threat telemetry, application layer attacks directed against cloud APIs have increased significantly, with broken object level authorization, injection flaws, and request forgery representing the most exploited attack classes.

Despite the critical need for automated security assessment, traditional dynamic application security testing (DAST) and black-box fuzzing tools suffer from two foundational limitations when applied to RESTful services:
1. **The Uniform Exploration Penalty:** Fuzzers such as RESTler and EvoMaster treat all API paths and parameters with equal priority. In enterprise APIs featuring hundreds of operations, only a small subset handles dangerous operations (such as file system interactions, system commands, external HTTP synchronization, or dynamic SQL queries). Blind exploration expends CPU cycles and network bandwidth generating permutations for inert endpoints while missing high-risk injection vectors.
2. **The Broken State Dependency Barrier:** REST APIs are fundamentally stateful. Target endpoints that modify or delete resources frequently require preexisting entity identifiers produced by upstream operations (e.g., calling `POST /resources` before `GET /resources/{id}`). Blind requests to downstream endpoints fail prematurely with client errors (`400 Bad Request` or `404 Not Found`), never reaching the vulnerable backend execution paths.

To overcome these fundamental barriers, Du et al. introduced **VOAPI²** at USENIX Security 2024. VOAPI² shifts testing from undirected fuzzing toward a **vulnerability-oriented** methodology. By mining an empirical corpus of real-world Common Vulnerabilities and Exposures (CVEs), VOAPI² identifies semantic path and parameter keywords associated with six critical Common Weakness Enumeration (CWE) categories, extracts candidate interfaces, and recursively synthesizes valid prerequisite request sequences using reverse dependency construction.

### Contributions of SecureVault

In this work, we present **SecureVault**, an academic research project developed for the CS-473 Cloud Security and SRE curriculum at IIIT Dharwad. SecureVault makes the following key contributions:
- **Clean-Room 4-Stage Implementation:** We independently design and implement the complete VOAPI² pipeline in modern Python, supporting OpenAPI 2.0, 3.0, 3.1, and Swagger formats, with full support for `$ref` resolution, cyclic graph pruning, and five parameter generation strategies.
- **Forensic Dataset Audit & Verification:** We conduct an exhaustive audit of the published VOAPI² dataset (`CVE-Information.xlsx`), resolving discrepancies between the 544 text figure and the actual 541 raw rows, proving that the author-defined filter `Detail Flag == '1'` isolates the exact 274 ground-truth records matching Table 1 of the USENIX publication with 100% precision.
- **Dual-Mode Target Testbed:** We develop a production-grade FastAPI testbed simulating all six vulnerability classes under both exploitable (`VULNERABLE`) and defensive (`HARDENED`) modes, facilitating controlled, zero-budget, reproducible benchmarking.
- **Multi-Application Empirical Evaluation:** We benchmark SecureVault against four diverse API specifications (SecureVault, Appwrite, Request Baskets, and Gitea), totaling 422 operations, and evaluate detection performance against a baseline unguided fuzzer.
- **Interactive Research Lab UI:** We build an interactive, 14-page cybersecurity research dashboard utilizing Streamlit, enabling researchers to visualize dependency graphs, inspect candidate interfaces, simulate attacks in real time, and verify defensive mitigations.

---

## 2. Background and Threat Model

### 2.1 The Six Targeted Vulnerability Classes

Our investigation focuses on the six critical vulnerability categories investigated in the base research paper:

1. **Server-Side Request Forgery (SSRF) — CWE-918:** Occurs when an API endpoint accepts a user-controlled URL to fetch remote resources without validating the target destination. In cloud environments, SSRF can be leveraged to query internal loopback services, private VPC resources, or cloud instance metadata endpoints (e.g., `http://169.254.169.254/latest/meta-data/` on AWS), resulting in IAM credential theft.
2. **Unrestricted Upload of File with Dangerous Type — CWE-434:** Occurs when an API permits users to upload arbitrary files without validating file extensions, MIME types, or contents. Attackers upload server-side executable scripts (such as PHP, JSP, or ASPX webshells) into web-accessible directories, achieving remote code execution (RCE).
3. **Improper Limitation of a Pathname to a Restricted Directory (Path Traversal) — CWE-22:** Occurs when an API incorporates unvalidated user input into file system path operations. Attackers supply relative traversal sequences (`../`, `..\`) to escape the intended directory root and read sensitive configuration files, keys, or passwords.
4. **OS Command Injection — CWE-78:** Occurs when an API concatenates untrusted user input directly into operating system shell commands executed via functions like `os.system()` or `subprocess.run(shell=True)`. Injected shell meta-characters (`&`, `;`, `|`, `` ` ``) allow arbitrary operating system command execution.
5. **SQL Injection (SQLi) — CWE-89:** Occurs when an API constructs database queries using dynamic string concatenation of untrusted input. Injected SQL tokens (`' OR '1'='1`) alter query logic, permitting unauthorized data exfiltration or table modification.
6. **Cross-Site Scripting (XSS / Stored XSS) — CWE-79:** Occurs when an API stores unsanitized user input in a database and subsequently renders it into administrative dashboards or web interfaces without contextual HTML escaping, allowing persistent script execution in user browsers.

### 2.2 Threat Model & Environmental Assumptions

Our threat model adheres to standard black-box and grey-box REST API testing assumptions:
- **Attacker Profile:** The testing framework acts as an external security analyst or automated pipeline auditor interacting strictly via HTTP/HTTPS.
- **Specification Availability:** The tester possesses the machine-readable API specification (OpenAPI or Swagger) provided by the application developers.
- **Authentication:** For authenticated endpoints, valid credentials (e.g., Bearer tokens) are supplied or provisioned through authentication endpoints specified in the API contract.
- **Safety Boundary:** All payloads injected by SecureVault are strictly benign and non-destructive (e.g., canary loopback URLs, harmless webshell probes echoing static tokens, directory boundary reads of seeded test secrets, and SQL tautologies on test tables). No destructive operations (`DROP TABLE`, `rm -rf`, external network DDoS) are conducted.

---

## 3. Related Work

### 3.1 REST API Fuzzing Frameworks

Automated testing of RESTful APIs has witnessed rapid growth over the past decade:
- **RESTler (Microsoft Research):** Introduced by Atlidakis et al. (ICSE 2019), RESTler was the first stateful REST API fuzzer to infer dynamic producer-consumer dependencies directly from OpenAPI specifications. However, RESTler is an unguided fuzzer whose objective is maximizing broad code coverage and detecting server crashes (`500 Internal Server Error`). It lacks semantic awareness of specific vulnerability classes (such as SSRF or SQLi) and does not craft vulnerability-targeted payloads.
- **EvoMaster:** Developed by Arcuri (ICSE 2019), EvoMaster employs evolutionary algorithms (search-based software testing) to generate test cases. While effective at maximizing structural branch coverage in white-box settings, its black-box mode relies on random mutation heuristics that fail to satisfy complex semantic invariants required for injection vulnerabilities.
- **Schemathesis:** A property-based API testing tool that validates whether API implementations strictly conform to their OpenAPI schemas. Schemathesis excels at detecting schema violations, unexpected status codes, and unhandled exceptions, but does not simulate malicious attack vectors.

### 3.2 Vulnerability-Oriented Testing (VOAPI²)

VOAPI² (Du et al., USENIX Security 2024) fundamentally departed from coverage-oriented fuzzing by introducing vulnerability orientation. By recognizing that high-severity vulnerabilities leave identifiable semantic footprints in API paths and parameter names, VOAPI² demonstrated that selective candidate extraction and reverse sequence construction can uncover 2.3x more real-world vulnerabilities with substantially fewer HTTP requests than state-of-the-art tools.

---

## 4. Forensic Investigation of the Base Research Corpus

To establish an uncompromised scientific foundation, we downloaded and forensically audited the original author-provided dataset: `CVE-Information.xlsx` from the official repository (`https://github.com/NSSL-SJTU/VoAPI2`).

### 4.1 Reconciling Corpus Discrepancies (544 vs. 541 vs. 274)

In Section 3.1 of the VOAPI² paper, the authors state:
> *"We collected 544 CVE records across six categories... We filtered out records lacking complete API paths or parameter names, yielding 274 detailed records."*

Our programmatic inspection of the six worksheets of `CVE-Information.xlsx` reveals the exact row and column distribution detailed in Table I.

```
+---------------------------+------------+------------+---------------+----------------------+
| Worksheet Name            | Total Rows | Data Rows  | Columns Count | Detail Flag == '1'   |
+---------------------------+------------+------------+---------------+----------------------+
| SSRF                      | 44         | 42         | 9             | 21                   |
| Unrestricted  Upload      | 76         | 74         | 9             | 42                   |
| Path Traversal            | 65         | 63         | 9             | 31                   |
| Command Injection         | 104        | 102        | 9             | 55                   |
| SQL Injection             | 147        | 145        | 9             | 70                   |
| XSS                       | 116        | 115        | 9             | 55                   |
+---------------------------+------------+------------+---------------+----------------------+
| Total Across All Sheets   | 552        | 541        | —             | 274                  |
+---------------------------+------------+------------+---------------+----------------------+
```
*Table I: Forensic Audit of the Official VOAPI² CVE-Information.xlsx Workbook.*

#### Forensic Findings:
1. **Actual Data Row Count:** The workbook contains **541 valid data records** (excluding header rows and summary notes), not 544. There are 533 unique CVE identifiers due to 8 multi-entry CVEs spanning multiple vulnerable parameters.
2. **The Ground Truth Filter:** In row 2 of each worksheet, the authors embedded metadata notes recording the exact hit counts of their keyword dictionary against the detailed corpus. Applying the filter `Detail Flag == '1'` isolates **exactly 274 records**.
3. **Exact Hit Rate Match:** The proportion of records matched by the keyword dictionary on the detailed corpus matches the published figures in Table 1 of the USENIX paper to three decimal places:
   - SSRF: $17 / 21 = 81.0\%$
   - Unrestricted File Upload: $35 / 42 = 83.3\%$
   - Path Traversal: $16 / 31 = 51.6\%$
   - OS Command Injection: $22 / 55 = 40.0\%$
   - SQL Injection: $37 / 70 = 52.9\%$
   - Cross-Site Scripting: $19 / 55 = 34.5\%$

This forensic verification confirms that the published `CVE-Information.xlsx` artifact represents the authentic empirical foundation of the base paper.

---

## 5. System Architecture and Methodology Implementation

SecureVault realizes the four-stage vulnerability-oriented testing architecture illustrated below:

```
+-----------------------------------------------------------------------------+
|                          SECUREVAULT ARCHITECTURE                           |
+-----------------------------------------------------------------------------+
|                                                                             |
|   [ Target API Specification (OpenAPI 2.0 / 3.0 / 3.1 / Swagger) ]          |
|                                │                                            |
|                                ▼                                            |
|   +---------------------------------------------------------------------+   |
|   | STAGE 1: SPECIFICATION ANALYSIS & SCHEMA NORMALIZATION              |   |
|   | • JSON / YAML Ingestion      • $ref Pointer Resolution              |   |
|   | • Parameter Extraction       • JSON Schema Body Normalization       |   |
|   +---------------------------------------------------------------------+   |
|                                │                                            |
|                                ▼                                            |
|   +---------------------------------------------------------------------+   |
|   | STAGE 2: CANDIDATE INTERFACE EXTRACTION                             |   |
|   | • 72 Path Keywords           • 56 Parameter Keywords                |   |
|   | • CWE Mapping (6 Classes)    • Priority Weight Calculation          |   |
|   | • Primary Vulnerable Target Parameter Selection                     |   |
|   +---------------------------------------------------------------------+   |
|                                │                                            |
|                                ▼                                            |
|   +---------------------------------------------------------------------+   |
|   | STAGE 3: TEST SEQUENCE GENERATION (ALGORITHM 1)                     |   |
|   | • Producer-Consumer Graph    • CRUD Semantic Matching               |   |
|   | • Resource Hierarchy Pruning • 5-Tier Parameter Strategies          |   |
|   |   (CONSUMER -> SPECIFICATION -> FORMAT -> SUCCESS -> RANDOM)        |   |
|   +---------------------------------------------------------------------+   |
|                                │                                            |
|                                ▼                                            |
|   +---------------------------------------------------------------------+   |
|   | STAGE 4: FEEDBACK-BASED TESTING & MULTI-SIGNAL ORACLES              |   |
|   | • Prerequisite Execution     • Benign Payload Injection             |   |
|   | • Response Code Inspection   • Canary Token Leak Verification       |   |
|   | • Database Tautology Match   • Latency & Timing Delta Oracle        |   |
|   +---------------------------------------------------------------------+   |
|                                │                                            |
|                                ▼                                            |
|   [ Verified Findings | Interactive Research Lab | Hardening Telemetry ]    |
|                                                                             |
+-----------------------------------------------------------------------------+
```

### 5.1 Stage 1: Specification Analysis

The `OpenAPISpecParser` ingests machine-readable API definitions. To accommodate real-world specifications, our parser handles:
- **Specification Ingestion:** Supports OpenAPI 3.0.x, OpenAPI 3.1.x, and Swagger 2.0 in both JSON and YAML formats.
- **JSON Pointer Resolution:** Resolves `$ref` references (e.g., `#/components/schemas/Item` or `#/definitions/User`), including nested and circular references, utilizing an in-memory resolution cache.
- **Parameter Normalization:** Standardizes parameters across `path`, `query`, `header`, and `cookie` locations. To handle OpenAPI 3.1 schema polymorphism (e.g., Pydantic v2 generating `anyOf: [{'type': 'integer'}, {'type': 'null'}]`), our parser dynamically unpacks `anyOf` constructs into representative base types.
- **Request Body Unpacking:** Extracts property schemas from `application/json` and `multipart/form-data` request bodies.

### 5.2 Stage 2: Candidate Interface Extraction

The `CandidateInterfaceExtractor` scans the parsed endpoints against the empirical keyword library extracted from the 274 ground-truth CVE records:
- **Keyword Dictionaries:** Evaluates paths and parameters against 72 path keywords (e.g., `download`, `upload`, `file`, `exec`, `ping`, `search`, `proxy`, `webhook`) and 56 parameter keywords (e.g., `url`, `path`, `filename`, `cmd`, `query`, `host`, `html`).
- **Scoring Function:** For an endpoint $e$ with path tokens $T_{path}$ and parameter names $P$, the priority score for category $c$ is computed as:
  $$Score(e, c) = w_{path} \sum_{t \in T_{path}} \mathbb{I}(t \in K_{path}^{(c)}) + w_{param} \sum_{p \in P} \mathbb{I}(p \in K_{param}^{(c)})$$
  where we assign $w_{path} = 1.0$ and $w_{param} = 2.0$, reflecting the empirical observation that parameter names provide higher predictive fidelity for injection vectors.
- **Primary Target Selection:** The parameter matching the highest-weight keyword is tagged as the primary injection target $p_{target}$.

### 5.3 Stage 3: Test Sequence Generation (Algorithm 1)

Candidate interfaces often require preexisting server state. SecureVault implements Algorithm 1 (Reverse Sequence Construction) to dynamically build prerequisite execution sequences:

```
Algorithm 1: Reverse Sequence Construction
Input: Target candidate interface I_t, API Specification Spec
Output: Executable Test Sequence S = <I_1, I_2, ..., I_t>

1:  S <- [ I_t ]
2:  Visited <- { I_t }
3:  P <- ExtractRequiredParameters(I_t)
4:  While P is not empty and |S| < MAX_DEPTH do:
5:      p <- Pop(P)
6:      Prods <- { I in Spec \ Visited | SchemaMatches(Response(I), p) }
7:      Prods <- FilterCRUDAndHierarchy(Prods, I_t)
8:      If Prods is not empty then:
9:          I_p <- SelectHighestPriorityProducer(Prods)
10:         S <- Prepend(I_p, S)
11:         Visited <- Visited U { I_p }
12:         P <- P U ExtractRequiredParameters(I_p)
13:     End If
14: End While
15: Return S
```

#### Parameter Generation Hierarchy
For each step in the generated sequence, parameters are populated using a strict five-tier resolution hierarchy:
1. `CONSUMER`: Dynamic extraction of entity identifiers (e.g., `item_id`) from the JSON response body of earlier prerequisite steps.
2. `SPECIFICATION`: Explicit default values, enum sets, or schema examples provided in the OpenAPI document.
3. `FORMAT`: Regex- and format-driven generation respecting semantic types (UUID, ISO 8601 timestamps, email addresses, URIs).
4. `SUCCESS`: Replay of parameter values observed during previous successful (2xx) responses.
5. `RANDOM`: Pseudorandom fallback strings or numbers when no semantic context exists.

### 5.4 Stage 4: Feedback-Based Testing and Multi-Signal Oracles

The `FeedbackTestRunner` executes the synthesized sequence against the target application. At the final exploitation step $I_t$, the runner substitutes $p_{target}$ with a tailored test payload from our benign payload library.

The `VulnerabilityOracle` evaluates the HTTP response across multiple orthogonal signals:
1. **Canary Token Reflection:** Detects secret flags embedded in local simulations (e.g., `SECUREVAULT_FLAG_{SSRF_CWE_918_VERIFIED}`).
2. **File Content Extraction:** Verifies whether known file signatures (e.g., `root:x:0:0` or `CONFIDENTIAL_VAULT_MASTER_KEY_2026`) appear in response bodies.
3. **Database Tautology Matches:** Checks whether SQL boolean tautologies return records that should remain hidden from the querying user.
4. **HTML Context Unescaping:** Detects whether unescaped script tags (`<script>alert(...)`) are rendered directly into HTML responses.
5. **Differential Timing Analysis:** Detects anomalous server response latency delays indicative of command sleep execution or time-based SQL injection.

Based on these signals, findings are categorized into four formal verdicts:
- `CONFIRMED_VULNERABILITY`: Conclusive evidence of unauthorized data leakage or code execution.
- `POTENTIAL_VULNERABILITY`: Ambiguous indicators (e.g., unhandled 500 error leaking stack traces).
- `NEGATIVE`: Target parameter properly sanitized, rejected (400/403), or handled safely.
- `INCONCLUSIVE`: Prerequisite state setup failed (e.g., upstream 404/401 error).

---

## 6. Experimental Evaluation and Benchmarks

We evaluated SecureVault to answer three central research questions:
- **RQ1 (Detection Precision):** Can SecureVault discover all target vulnerability classes on the dual-mode testbed, and how does it compare against baseline unguided fuzzing?
- **RQ2 (Efficiency & Overhead):** What is the request volume and runtime overhead reduction achieved by vulnerability orientation?
- **RQ3 (Generalizability across Real-World APIs):** How effectively does the specification analysis and candidate extraction scale across diverse real-world open-source benchmarks?

### 6.1 Benchmark Targets

Our evaluation incorporates four API systems:
1. **SecureVault API (v1.0.0):** Our dual-mode FastAPI testbed (16 endpoints), featuring SQLite storage, JWT authentication, and intentional vulnerabilities mapped to all six target CWEs.
2. **Appwrite (v0.9.3):** Real-world backend-as-a-service examined in the VOAPI² paper, containing 95 operations.
3. **Request Baskets (v1.2.3):** Real-world HTTP request collector evaluated in VOAPI², containing 20 operations.
4. **Gitea (v1.16.7):** Enterprise self-hosted Git platform analyzed in VOAPI², containing 291 operations.

### 6.2 Empirical Comparative Results (RQ1 & RQ2)

We conducted head-to-head benchmarking between a **Baseline Random Fuzzer** (representing unguided black-box testing) and **SecureVault (VOAPI²)** on the SecureVault testbed under both `VULNERABLE` and `HARDENED` configurations. The results are summarized in Table II.

```
+----------+----------------------------+-----------------------+---------------------+-----------------------+
| CWE ID   | Vulnerability Class        | Target Endpoint       | Baseline Fuzzing    | SecureVault (VOAPI²)  |
+----------+----------------------------+-----------------------+---------------------+-----------------------+
| CWE-918  | Server-Side Request Forgery| /api/v1/vault/sync    | Missed (422 Error)  | CONFIRMED (Leaked)    |
| CWE-434  | Unrestricted File Upload   | /api/v1/vault/upload  | Missed (Bad Bytes)  | CONFIRMED (Stored)    |
| CWE-22   | Path Traversal             | /api/v1/vault/files/rd| Missed (Blind Str)  | CONFIRMED (Key Read)  |
| CWE-78   | OS Command Injection       | /api/v1/vault/tools/..| Missed (No Meta)    | CONFIRMED (Echoed)    |
| CWE-89   | SQL Injection              | /api/v1/vault/records | Missed (Syntax Err) | CONFIRMED (Tautology) |
| CWE-79   | Stored Cross-Site Scripting| /api/v1/vault/audit/..| Missed (Unchecked)  | CONFIRMED (Unescaped) |
+----------+----------------------------+-----------------------+---------------------+-----------------------+
| Overall  | 6 Target Categories        | 16 Operations         | 0% Detection (0/6)  | 100% Detection (6/6)  |
+----------+----------------------------+-----------------------+---------------------+-----------------------+
```
*Table II: Vulnerability Detection Results on SecureVault API Testbed.*

#### Quantitative Performance Metrics:
- **Detection Rate:** Baseline Random Fuzzing achieved a **0.0% detection rate** (0 of 6 confirmed vulnerabilities). In contrast, SecureVault achieved **100% detection** (6 of 6 confirmed vulnerabilities).
- **Request Volume:** Baseline fuzzing transmitted **48 requests**, primarily resulting in superficial client validation errors (`422 Unprocessable Entity` or `400 Bad Request`). SecureVault required only **15 requests** to confirm all six vulnerabilities—achieving a **68.8% request reduction**.
- **Execution Latency:** Total execution time for the testing campaign dropped from **1,078.1 ms** (baseline) to **162.8 ms** (SecureVault)—a **6.6x execution speedup**.
- **Defensive Hardening Verification:** When the SecureVault testbed was toggled to `HARDENED` mode, SecureVault verified that all six vulnerabilities were neutralized (returning 400 Bad Request or 403 Forbidden with zero false positives).

### 6.3 Multi-Application Specification Analysis (RQ3)

To assess the scalability of Stage 1 and Stage 2 across diverse API architectures, we evaluated SecureVault across all four benchmark specifications. The empirical results are detailed in Table III.

```
+--------------------+---------+-------------------+---------+------------+-------------+--------------+------------------+
| Application        | Version | Spec Format       | # Ops   | Parse (ms) | Extr. (ms)  | # Candidates | Candidate Rate   |
+--------------------+---------+-------------------+---------+------------+-------------+--------------+------------------+
| SecureVault API    | 1.0.0   | OpenAPI 3.1 (JSON)| 16      | 0.52 ms    | 2.79 ms     | 13           | 81.2%            |
| Appwrite           | 0.9.3   | OpenAPI 3.0 (JSON)| 95      | 3.54 ms    | 16.33 ms    | 77           | 81.1%            |
| Request Baskets    | 1.2.3   | OpenAPI 3.0 (YAML)| 20      | 66.19 ms   | 4.10 ms     | 16           | 80.0%            |
| Gitea              | 1.16.7  | Swagger 2.0 (JSON)| 291     | 7.46 ms    | 63.66 ms    | 207          | 71.1%            |
+--------------------+---------+-------------------+---------+------------+-------------+--------------+------------------+
| Cumulative Total   | —       | —                 | 422     | 77.71 ms   | 86.88 ms    | 313          | 74.2% (Average)  |
+--------------------+---------+-------------------+---------+------------+-------------+--------------+------------------+
```
*Table III: Multi-Application Specification Analysis and Candidate Extraction Benchmark.*

#### Analysis of Multi-Application Findings:
1. **Appwrite (95 Operations):** Replicating the scale reported in Table 4 of VOAPI², our parser extracted 77 candidate interfaces (81.1% candidate rate), with heavy concentrations in file uploads (15 candidates), SQL injection vectors (11 candidates), and webhook SSRF (5 candidates).
2. **Request Baskets (20 Operations):** Extracted 16 candidate interfaces (80.0% candidate rate), predominantly centered on basket configuration, token retrieval, and forward proxying.
3. **Gitea (291 Operations):** The largest benchmark evaluated, featuring 291 operations in Swagger 2.0 format. SecureVault parsed the complete specification in 7.46 ms and extracted 207 candidate interfaces (71.1% candidate rate), identifying 71 SQLi candidates, 78 XSS candidates, 20 file upload endpoints, 16 command execution hooks, and 15 SSRF vectors.
4. **Cumulative Efficiency:** Across 422 API operations, total parsing and extraction required less than **165 milliseconds**, demonstrating sub-millisecond per-endpoint scalability suitable for modern Continuous Integration / Continuous Deployment (CI/CD) pipelines.

---

## 7. Discussion and Defensive SRE Guidelines

Our experimental findings highlight actionable engineering guidelines for cloud and SRE teams:
- **Shift-Left Candidate Analysis in CI/CD:** Integrating Stage 2 keyword analysis directly into CI/CD linters allows security engineers to flag high-risk endpoints automatically during pull request reviews before deployment.
- **Defense-in-Depth against Cloud SSRF:** Validating destination IP addresses at the socket layer—blocking loopback (`127.0.0.0/8`), private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and link-local metadata addresses (`169.254.169.254`)—neutralizes SSRF vectors regardless of URL obfuscation.
- **Strict Boundary Resolution for File Systems:** Canonical path resolution (`path.resolve().is_relative_to(BASE_DIR)`) combined with strict filename token filtering completely eliminates path traversal vulnerabilities.
- **Strict Prohibition of Shell Interpolation:** Using parameterized execution (`subprocess.run(["cmd", arg], shell=False)`) prevents OS command injection entirely, avoiding the fragility of blacklist-based character sanitization.

---

## 8. Academic Disclosures and Limitations

In accordance with academic standards, we disclose the following limitations:
1. **Clean-Room Reproduction:** SecureVault is an independent implementation developed from the methodology described in Du et al. (2024). While our empirical datasets, keyword dictionaries, and benchmark specifications are forensically verified against the authors' published artifacts, our internal Python codebase was written clean-room.
2. **Local Testbed Simulation:** Full dynamic attack execution in this study was conducted against our dual-mode SecureVault testbed. Real-world benchmarks (Appwrite, Request Baskets, Gitea) were evaluated across Stages 1 through 3 (specification analysis and candidate extraction), avoiding live network exploitation against unowned third-party infrastructures.
3. **Specification Dependency:** SecureVault relies on the availability and accuracy of OpenAPI/Swagger documentation. Undocumented endpoints or parameters are inaccessible to specification-based parsers.

---

## 9. Conclusion and Future Work

In this paper, we presented **SecureVault**, an academic research implementation, forensic investigation, and experimental evaluation of vulnerability-oriented RESTful API security testing inspired by VOAPI² (USENIX Security 2024). We established the authentic baseline of the 541-record vulnerability corpus, proved that the 274 ground-truth records represent the exact empirical foundation of the published hit rates, and implemented the complete four-stage testing framework in modern Python.

Our experimental benchmarking confirmed that vulnerability-oriented testing outperforms unguided random fuzzing, achieving 100% detection across all six target CWE categories with 68.8% fewer requests and 6.6x faster execution, while maintaining zero false positives under hardened configurations. Future work includes extending Algorithm 1 with graph-neural-network-driven dependency inference for loosely coupled microservice meshes and investigating zero-shot semantic keyword expansion using large language models.

---

## References

1. **Wenlong Du, Qingchuan Zhao, Yongsen Zheng, Yu Wang, Shouling Ji, and Lin Zhang.** *Vulnerability-oriented Testing for RESTful APIs.* In Proceedings of the 33rd USENIX Security Symposium (USENIX Security 24), Philadelphia, PA, August 2024.
2. **Vaggelis Atlidakis, Patrice Godefroid, and Marina Polishchuk.** *RESTler: Stateful REST API Fuzzing.* In Proceedings of the 41st International Conference on Software Engineering (ICSE 2019), Montreal, Canada, May 2019.
3. **Andrea Arcuri.** *RESTful API Automated Test Case Generation with EvoMaster.* ACM Transactions on Software Engineering and Methodology (TOSEM), 28(1):1–37, 2019.
4. **Dmitry Dygalo.** *Schemathesis: Property-based testing for OpenAPI and GraphQL.* Open-Source Software, 2020.
5. **OWASP Foundation.** *OWASP Top 10 API Security Risks 2023.* Available at: `https://owasp.org/www-project-api-security/`.
6. **National Institute of Standards and Technology (NIST).** *Common Weakness Enumeration (CWE) Specification.* MITRE Corporation, 2024.
7. **National Vulnerability Database (NVD).** *Common Vulnerabilities and Exposures (CVE) Catalog.* NIST, 2024.
8. **OpenAPI Initiative.** *OpenAPI Specification Version 3.1.0.* Linux Foundation, 2021.
