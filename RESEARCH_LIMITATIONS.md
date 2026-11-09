# SECUREVAULT: ACADEMIC DISCLOSURES, THREATS TO VALIDITY & RESEARCH LIMITATIONS

**Project:** SecureVault: Vulnerability-Oriented Security Testing of RESTful APIs  
**Academic Course:** CS-473 Cloud Security and SRE | IIIT Dharwad  
**Primary Research Foundation:** *"Vulnerability-oriented Testing for RESTful APIs (VOAPI²)"* — Wenlong Du et al., USENIX Security 2024  
**Date:** November 2026  

---

## 1. Academic Disclosures

To maintain the highest standards of scientific integrity, the research team discloses the following architectural and empirical boundaries:

### 1.1 Clean-Room Reproduction Scope
SecureVault is an independent, clean-room implementation inspired by the four-stage methodology formulated by Wenlong Du et al. in *Vulnerability-oriented Testing for RESTful APIs (VOAPI²)*, presented at the 33rd USENIX Security Symposium (2024). While the research methodology, keyword dictionaries, and empirical dataset schemas were forensically verified against the authors' published artifacts (`CVE-Information.xlsx`), the entire Python codebase (`framework/`, `app/`, `ui/`, `experiments/`, `tests/`) was designed and authored independently.

### 1.2 Distinction Between Testbed Execution and In-the-Wild Exploitation
All live vulnerability test executions (Stage 4) and comparative fuzzing evaluations in this study were conducted strictly against our local, dual-mode SecureVault REST API testbed (`127.0.0.1:8000`). In accordance with legal, ethical, and academic boundaries:
- **No live penetration testing** or unauthorized exploitation was conducted against third-party production systems or unowned cloud services.
- Real-world benchmark applications (Appwrite 0.9.3, Request Baskets 1.2.3, and Gitea 1.16.7) were evaluated through **offline specification analysis and candidate interface extraction (Stages 1 through 3)** using their official open-source OpenAPI contracts.

### 1.3 Hardware-Backed Confidential Computing Claims
SecureVault does not require, utilize, or claim hardware-backed Trusted Execution Environments (TEEs), such as AWS Nitro Enclaves, Intel SGX, or AMD SEV. All security controls and mitigations operate strictly at the application and software runtime layer within the local Python environment.

---

## 2. Threats to Validity

### 2.1 Internal Threats to Validity
- **Testbed Design Bias:** The intentional vulnerabilities in the SecureVault testbed were modeled to reflect common real-world CVE patterns. Although they provide representative ground truth for all six CWE categories, artificial testbeds may omit edge cases present in massive monolithic legacy applications.
- **Oracle Precision:** Vulnerability oracles rely on multi-signal indicators (status codes, canary tokens, database record counts, and HTML escaping). While highly effective in controlled settings with known canary secrets, in black-box scenarios without canary knowledge, oracles may exhibit reduced sensitivity or require auxiliary out-of-band monitoring listeners.

### 2.2 External Threats to Validity
- **Specification Quality and Undocumented Endpoints:** The framework's efficacy depends fundamentally on the presence and completeness of machine-readable OpenAPI or Swagger specifications. If developers fail to document certain endpoints, parameters, or schema types, the parser cannot ingest or analyze them (shadow APIs).
- **Domain-Specific Vocabulary Drift:** The keyword dictionaries (72 path keywords, 56 parameter keywords) were derived from an empirical corpus of 274 ground-truth CVE records. APIs utilizing non-English naming conventions, heavily abbreviated tokens, or proprietary jargon may fall outside the dictionary's coverage, resulting in lower candidate extraction rates.

### 2.3 Construct Threats to Validity
- **Baseline Fuzzer Representation:** Our comparative baseline implements unguided, random black-box fuzzing (injecting generic strings, boundary numbers, format tokens, and empty inputs). While representative of naive random testing, state-of-the-art hybrid fuzzers (such as white-box EvoMaster) that leverage evolutionary search might achieve higher code coverage, albeit with significantly higher computational budgets.

---

## 3. Engineering & SRE Mitigations Summary

Despite these academic boundaries, SecureVault provides concrete, actionable takeaways for cloud security and Site Reliability Engineering (SRE) teams:
1. **Shift-Left Candidate Linting:** Stage 2 keyword extraction can be integrated into pre-commit hooks and CI/CD pipelines as a fast, zero-runtime static security linter for OpenAPI pull requests.
2. **Defensive Hardening Verification:** The dual-mode testbed architecture demonstrates that standard SRE practices (canonical path validation, parameterized SQL statements, strict destination IP checking, and context-aware HTML escaping) neutralize 100% of tested injection vectors with zero false positives.
3. **Reproducibility Guarantee:** Operating under a ₹0 budget on standard Windows 11 hardware ensures that any student, educator, or independent researcher can reproduce all findings without friction or cloud costs.
