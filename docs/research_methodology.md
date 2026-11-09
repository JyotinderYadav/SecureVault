# Research Methodology: VOAPI² Adaptation for SecureVault

**Reference:** *Vulnerability-oriented Testing for RESTful APIs (VOAPI²)* — Wenlong Du et al., USENIX Security 2024.

## Overview

SecureVault implements an experimental REST API security testing framework based on the four-stage methodology established in VOAPI²:

1. **Stage 1: Specification Analysis**
   - Ingestion and normalization of OpenAPI v2/v3 schemas.
   - Parsing endpoints, HTTP verbs, parameter locations (path, query, header, cookie, body, multipart/form-data), and response contracts.

2. **Stage 2: Candidate Interface Extraction**
   - Semantic keyword mapping between API endpoints and six targeted vulnerability categories (CWE-918 SSRF, CWE-434 File Upload, CWE-22 Path Traversal, CWE-78 Command Injection, CWE-89 SQL Injection, CWE-79 XSS).
   - Identification of test parameters and candidate interface categorization.

3. **Stage 3: Test Sequence Generation**
   - Reverse sequence construction based on producer-consumer parameter dependencies.
   - Filtering via CRUD semantics and resource hierarchy constraints.
   - Parameter value generation using priority strategies: CONSUMER, SPECIFICATION, FORMAT, SUCCESS, RANDOM.

4. **Stage 4: Feedback-Based Testing**
   - Category-tailored inspection payload injection.
   - Verification server and multi-signal feedback analysis (status codes, response latency, reflection escaping, error signature matching, triggering requests).

