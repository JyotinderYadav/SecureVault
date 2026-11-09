# Project Limitations & Academic Disclosures

1. **Hardware-Backed Confidentiality Disclosure:**
   - In accordance with academic honesty and course guidelines, this project does NOT claim hardware-backed confidential computing (such as AMD SEV-SNP, Intel SGX/TDX, or AWS Nitro Enclaves) or remote attestation unless physically deployed and cryptographically verified on attested hardware.
   - All tests run on standard consumer hardware (Windows 11).

2. **Environment & Resource Constraints:**
   - Testing is conducted locally under zero-budget constraints.
   - Full live deployment of large historical enterprise platforms (e.g., GitLab 8.17.0 from 2017) is constrained by local RAM, legacy dependency conflicts, and Docker requirements on Windows.

3. **Methodological Adaptation:**
   - The VOAPI² methodology is implemented as an independent Python testing engine faithful to the 4 stages described by Du et al. (USENIX Security 2024), without relying on .NET 6.0 RESTler binary dependencies.

