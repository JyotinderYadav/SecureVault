"""
Research Methodology View
Presents the formal 4-stage pipeline, Algorithm 1 (Reverse Sequence Construction),
parameter generation strategies, and comparative advantages over unguided fuzzing.
"""
import streamlit as st
from ui.components.styling import render_header

def render_methodology_view():
    render_header(
        title="Research Methodology",
        subtitle="Formal 4-Stage Vulnerability-Oriented Testing Formulation (Du et al., USENIX Security 2024)",
        badge="Methodology & Algorithms"
    )

    tabs = st.tabs([
        "1. Pipeline Architecture",
        "2. Algorithm 1: Reverse Sequencing",
        "3. Parameter Generation Strategies",
        "4. Unguided Fuzzing vs. VOAPI²"
    ])

    with tabs[0]:
        st.subheader("The 4-Stage Vulnerability-Oriented Testing Pipeline")
        st.markdown(
            """
            Conventional REST API fuzzers (such as RESTler and EvoMaster) generate random test sequences 
            exploring the entire API surface blindly. In contrast, **VOAPI²** introduces a **vulnerability-oriented** 
            testing philosophy that focuses testing resources specifically on candidate interfaces likely to exhibit 
            severe vulnerabilities.
            """
        )

        st.markdown("#### Formal Pipeline Representation")
        st.code(
            """
            [ OpenAPI / Swagger Specification ]
                         │
                         ▼
             Stage 1: Specification Analysis
                ├── Schema Parsing ($ref resolution)
                ├── Endpoint Parameter Normalization
                └── Producer-Consumer Candidate Mapping
                         │
                         ▼
             Stage 2: Candidate Interface Extraction
                ├── Semantic Keyword Matching (72 Path / 56 Param Keywords)
                ├── Primary Target Parameter Selection
                └── Candidate Vulnerability Scoring (CWE-918, 434, 22, 78, 89, 79)
                         │
                         ▼
             Stage 3: Test Sequence Generation
                ├── Algorithm 1: Reverse Sequence Construction
                ├── Producer-Consumer Data Dependency Resolution
                └── 5-Strategy Parameter Generation (CONSUMER, SPEC, FORMAT, SUCCESS, RANDOM)
                         │
                         ▼
             Stage 4: Feedback-Based Testing & Verification
                ├── Prerequisite Sequence Execution
                ├── Benign Vulnerability Payload Injection
                └── Multi-Signal Feedback Oracle Verification
                         │
                         ▼
            [ Verified Vulnerability Findings & Mitigations ]
            """,
            language="text"
        )

        st.markdown("#### Detailed Stage Descriptions")
        st.markdown(
            """
            - **Stage 1 — Specification Analysis:** Parses modern OpenAPI 3.x and Swagger 2.0 specifications. 
              Extracts endpoints $E = \\{e_1, e_2, \\dots, e_n\\}$, where each endpoint $e_i = (method, path, params, body, responses)$.
            - **Stage 2 — Candidate Interface Extraction:** Maps the empirical vulnerability knowledge base onto the API surface. 
              Endpoints whose paths or parameters contain semantic indicators (e.g. `url`, `file`, `path`, `cmd`, `query`, `html`) 
              are extracted as candidate interfaces $C \\subseteq E$.
            - **Stage 3 — Test Sequence Generation:** Uses reverse sequence construction (Algorithm 1) to satisfy 
              state prerequisites for target candidate operations (e.g., creating an entity before updating or querying it).
            - **Stage 4 — Feedback-Based Testing:** Transmits sequences, evaluates runtime responses (status codes, headers, body patterns, 
              leaked tokens, response delays), and classifies findings into formal verdicts.
            """
        )

    with tabs[1]:
        st.subheader("Algorithm 1: Reverse Sequence Construction")
        st.markdown(
            """
            When testing a target interface $I_t$, simply sending an isolated request frequently fails with 
            `400 Bad Request` or `404 Not Found` because backend resources have not been created. 
            **Algorithm 1** recursively works backward from the target interface to construct a valid 
            prerequisite sequence.
            """
        )

        st.markdown("#### Mathematical Algorithm Pseudocode")
        st.code(
            """
Algorithm 1: Reverse Sequence Construction (VOAPI²)
--------------------------------------------------------------------------
Input:  Target candidate interface I_t, API Specification Spec
Output: Executable Test Sequence S = <I_1, I_2, ..., I_t>

1:  Initialize sequence S <- [ I_t ]
2:  Initialize pending_parameters P <- ExtractRequiredParameters(I_t)
3:  While P is not empty and depth < MAX_DEPTH do:
4:      Select parameter p in P
5:      Find Candidate Producers Prods = { I | I in Spec, OutputSchema(I) matches p }
6:      Filter Prods using CRUD Semantic Matching & Resource Hierarchy
7:      If Prods is not empty then:
8:          Select highest-priority producer I_p in Prods
9:          Prepend I_p to sequence: S <- [ I_p ] + S
10:         Update pending_parameters:
11:             P <- (P \\ { p }) U ExtractRequiredParameters(I_p)
12:     Else:
13:         Remove p from P  (p will be resolved via Fallback Strategies)
14:     End If
15: End While
16: Return S
            """,
            language="text"
        )

        st.markdown("#### Key Heuristics in Reverse Sequencing")
        st.markdown(
            """
            1. **Resource Hierarchy Matching:** If target interface has path `/items/{item_id}`, candidates that match 
               the prefix `/items` with `POST` method are prioritized over unrelated endpoints.
            2. **CRUD Semantic Prioritization:** `POST` (Create) operations are natural producers for `GET`, `PUT`, `DELETE` operations.
            3. **Acyclic Path Enforcement:** Visited operations are tracked in a recursion set to prevent circular dependencies.
            """
        )

    with tabs[2]:
        st.subheader("The Five Parameter Generation Strategies")
        st.markdown(
            """
            To construct valid HTTP requests that penetrate deep into application logic, VOAPI² prioritizes 
            parameter values according to a hierarchy of five distinct generation strategies:
            """
        )

        s1, s2, s3, s4, s5 = st.columns(5)
        with s1:
            st.markdown(
                """
                <div style="background-color: #1C2541; border: 1px solid #3A506B; border-radius: 8px; padding: 12px; height: 100%;">
                    <div style="font-weight: 700; color: #48CAE4;">1. CONSUMER</div>
                    <div style="font-size: 0.8rem; color: #94A3B8; margin-top: 6px;">
                        Extracts actual dynamic runtime values from the responses of earlier producer operations in the sequence.
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
        with s2:
            st.markdown(
                """
                <div style="background-color: #1C2541; border: 1px solid #3A506B; border-radius: 8px; padding: 12px; height: 100%;">
                    <div style="font-weight: 700; color: #00B4D8;">2. SPECIFICATION</div>
                    <div style="font-size: 0.8rem; color: #94A3B8; margin-top: 6px;">
                        Extracts explicit default values, enum definitions, or schema examples provided in the OpenAPI document.
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
        with s3:
            st.markdown(
                """
                <div style="background-color: #1C2541; border: 1px solid #3A506B; border-radius: 8px; padding: 12px; height: 100%;">
                    <div style="font-weight: 700; color: #0077B6;">3. FORMAT</div>
                    <div style="font-size: 0.8rem; color: #94A3B8; margin-top: 6px;">
                        Generates type-conformant values respecting schema formats (e.g. UUID, email, date-time, uri, integer).
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
        with s4:
            st.markdown(
                """
                <div style="background-color: #1C2541; border: 1px solid #3A506B; border-radius: 8px; padding: 12px; height: 100%;">
                    <div style="font-weight: 700; color: #10B981;">4. SUCCESS</div>
                    <div style="font-size: 0.8rem; color: #94A3B8; margin-top: 6px;">
                        Reuses parameter values from previously observed successful (2xx) request executions during the test campaign.
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
        with s5:
            st.markdown(
                """
                <div style="background-color: #1C2541; border: 1px solid #3A506B; border-radius: 8px; padding: 12px; height: 100%;">
                    <div style="font-weight: 700; color: #F59E0B;">5. RANDOM</div>
                    <div style="font-size: 0.8rem; color: #94A3B8; margin-top: 6px;">
                        Generates pseudorandom strings or numbers when no prior specification or semantic context is available.
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

    with tabs[3]:
        st.subheader("Comparative Paradigm: Unguided Fuzzing vs. VOAPI²")
        st.markdown(
            """
            The following table summarizes the fundamental distinctions between traditional unguided REST API fuzzers 
            and the vulnerability-oriented paradigm of VOAPI²:
            """
        )

        comparison_data = [
            {"Dimension": "Testing Focus", "Unguided Fuzzers (RESTler, EvoMaster)": "Uniform exploration across all API endpoints", "VOAPI² (SecureVault)": "Candidate interfaces filtered by vulnerability semantic keywords"},
            {"Dimension": "Payload Strategy", "Unguided Fuzzers (RESTler, EvoMaster)": "Random boundary values, long strings, generic syntax tokens", "VOAPI² (SecureVault)": "CWE-tailored targeted test probes (SSRF URLs, webshells, traversal tokens, SQL tautologies)"},
            {"Dimension": "Sequence Construction", "Unguided Fuzzers (RESTler, EvoMaster)": "Forward exploration / random walks across dependency graph", "VOAPI² (SecureVault)": "Reverse sequence construction targeting candidate state prerequisites (Algorithm 1)"},
            {"Dimension": "Resource Efficiency", "Unguided Fuzzers (RESTler, EvoMaster)": "High request volume; high proportion of superficial 400/404 errors", "VOAPI² (SecureVault)": "Low request volume; deep penetration into vulnerable business logic"},
            {"Dimension": "Detection Oracles", "Unguided Fuzzers (RESTler, EvoMaster)": "500 Internal Server Error, server crash, schema violation", "VOAPI² (SecureVault)": "Multi-signal vulnerability oracles (canary reflections, leaked files, database tautologies)"}
        ]
        st.table(comparison_data)
