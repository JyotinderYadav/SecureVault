# Reproduction Plan: VOAPI² Adaptation for Academic Evaluation

## Constraints
- **Hardware/OS:** Local Windows 11 Laptop.
- **Budget:** Strict ₹0 / Zero-Budget.
- **Tooling:** Python 3.13, FastAPI (for target testbed), Streamlit (for evaluation UI).
- **Network/Cloud:** Local execution only; no assumption of AWS credentials or enterprise infrastructure.

## Feasibility Categories
1. **Direct Reproduction:**
   - OpenAPI 3.0 specification parsing (Stage 1).
   - Keyword dictionary extraction matching the 6 CWEs (Stage 2).
   - Sequence generation with producer-consumer dependency resolution (Stage 3).
   - Dynamic feedback analysis and oracle verification (Stage 4).
   - Automated comparative benchmarking (Random/Naive Fuzzing vs. VOAPI² Guided Testing).

2. **Adapted Reproduction:**
   - Implementation in pure Python (FastAPI + requests/httpx + Pydantic) rather than requiring .NET 6.0 RESTler compiler toolchain.
   - Dedicated local testbed (`app/`) intentionally modeling real-world vault APIs across all 6 CWEs instead of running massive multi-GB multi-container stacks (like GitLab 8.17.0).
   - Lightweight evaluation of open-source benchmark specs (Appwrite, Rbaskets, etc.) offline.

3. **Not Feasible (Out of Scope for Academic Evaluation):**
   - Deploying 7 full-scale enterprise software instances simultaneously (GitLab 8.17.0 requires legacy Ruby/PostgreSQL/Redis and >8GB RAM alone).
   - Hardware-backed confidential computing (TEE / Nitro Enclaves) is explicitly out of scope for this REST API testing evaluation.

