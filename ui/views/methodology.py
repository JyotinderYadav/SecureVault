"""
Research Methodology View (UI 2.0 Cinematic Redesign)
Interactive exploration of the formal 4-stage pipeline, Algorithm 1 (Reverse Sequence Construction),
parameter generation strategies, and comparative advantages over unguided fuzzing.
"""
import streamlit as st
from ui.components.styling import render_hero, render_dark_console

def render_methodology_view():
    render_hero(
        title="Research Methodology",
        subtitle="Formal 4-Stage Vulnerability-Oriented Testing Formulation (Du et al., USENIX Security 2024)",
        badge="Methodology & Algorithms",
        meta_items=[
            "📐 4 Sequential Stages",
            "🔄 Algorithm 1: Reverse Sequencing",
            "🎯 5 Parameter Generation Strategies",
            "🛡️ 6 Target CWE Categories"
        ]
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
            Conventional REST API fuzzers (e.g., RESTler, EvoMaster) explore the API surface uniformly, 
            wasting resources on superficial input permutations. **VOAPI²** introduces a **vulnerability-oriented** 
            testing philosophy that focuses resources specifically on candidate interfaces likely to exhibit severe flaws.
            """
        )

        st.markdown("#### Formal Architectural Flow (35% Dark Panel)")
        pipeline_ascii = """
[ Target OpenAPI / Swagger Specification ]
                │
                ▼
  STAGE 1: SPECIFICATION ANALYSIS (OpenAPISpecParser)
     ├── Schema Parsing & Recursive $ref Pointer Resolution
     ├── Parameter Normalization (path, query, header, cookie)
     └── Producer-Consumer Schema Output Mapping
                │
                ▼
  STAGE 2: CANDIDATE INTERFACE EXTRACTION (CandidateInterfaceExtractor)
     ├── Semantic Keyword Matching (72 Path / 56 Param Keywords)
     ├── Priority Scoring: Score = 1.0 * N_path + 2.0 * N_param
     └── Primary Target Parameter Tagging (p_target)
                │
                ▼
  STAGE 3: TEST SEQUENCE GENERATION (TestSequenceGenerator)
     ├── Algorithm 1: Reverse Sequence Construction
     ├── Producer-Consumer Dependency Resolution & CRUD Filtering
     └── 5 Parameter Strategies (CONSUMER -> SPEC -> FORMAT -> SUCCESS -> RANDOM)
                │
                ▼
  STAGE 4: FEEDBACK-BASED TESTING & VERIFICATION (FeedbackTestRunner)
     ├── Prerequisite Sequence Execution & Dynamic State Extraction
     ├── Injection of Benign Research Probes into p_target
     └── Multi-Signal Oracle Evaluation (Canaries, Tautologies, HTML, Timing)
                │
                ▼
[ Verified Vulnerability Findings & Defensive Telemetry ]
"""
        st.markdown(render_dark_console("VOAPI² 4-Stage Execution Architecture", f"<pre style='color: #38BDF8; margin: 0;'>{pipeline_ascii}</pre>", "CORE PIPELINE"), unsafe_allow_html=True)

        st.markdown("#### Detailed Stage Implementations")
        col_s1, col_s2 = st.columns(2)
        with col_s1:
            st.markdown(
                """
                <div class="light-card">
                    <b style="color: #0284C7;">Stage 1 — Specification Analysis</b>
                    <p style="font-size: 0.85rem; color: #64748B; margin-top: 6px;">
                        Ingests OpenAPI 2.0/3.0/3.1 and Swagger documents in JSON/YAML. Standardizes endpoints $E = \\{e_1, e_2, \\dots, e_n\\}$,
                        unpacks polymorphic schemas (Pydantic v2 <code>anyOf</code>), and maps output schemas for downstream producers.
                    </p>
                </div>
                <div class="light-card">
                    <b style="color: #0EA5E9;">Stage 2 — Candidate Interface Extraction</b>
                    <p style="font-size: 0.85rem; color: #64748B; margin-top: 6px;">
                        Scans path tokens and parameter names against empirical CVE dictionaries across 6 CWE classes.
                        Tags highest-weight parameters as primary injection vectors ($p_{target}$) with calculated candidate scores.
                    </p>
                </div>
                """,
                unsafe_allow_html=True
            )
        with col_s2:
            st.markdown(
                """
                <div class="light-card">
                    <b style="color: #0369A1;">Stage 3 — Test Sequence Generation</b>
                    <p style="font-size: 0.85rem; color: #64748B; margin-top: 6px;">
                        Implements Algorithm 1 to resolve state prerequisites for candidate interfaces.
                        Prioritizes CRUD semantic producers (e.g. <code>POST /items</code> before <code>GET /items/{id}</code>) and tracks recursion sets to prevent circular loops.
                    </p>
                </div>
                <div class="light-card">
                    <b style="color: #10B981;">Stage 4 — Feedback-Based Testing</b>
                    <p style="font-size: 0.85rem; color: #64748B; margin-top: 6px;">
                        Executes sequences dynamically against the target API. Replaces $p_{target}$ with benign probes,
                        inspects HTTP responses, canary flags, and database queries, yielding formal oracle verdicts.
                    </p>
                </div>
                """,
                unsafe_allow_html=True
            )

    with tabs[1]:
        st.subheader("Algorithm 1: Reverse Sequence Construction")
        st.markdown(
            """
            When testing a target interface $I_t$, sending an isolated request frequently fails with 
            `400 Bad Request` or `404 Not Found` because backend resources have not been created. 
            **Algorithm 1** recursively works backward from the target interface to construct a valid 
            prerequisite sequence.
            """
        )

        algo_code = """Algorithm 1: Reverse Sequence Construction (VOAPI²)
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
13:         Remove p from P  (p resolved via Fallback Strategies)
14:     End If
15: End While
16: Return S"""

        st.markdown(render_dark_console("Algorithm 1 Pseudocode Formulation", f"<pre style='color: #10B981; margin: 0;'>{algo_code}</pre>", "ALGORITHM 1"), unsafe_allow_html=True)

        st.markdown("#### Key Heuristics in Reverse Sequencing")
        col_h1, col_h2 = st.columns(2)
        with col_h1:
            st.info("**1. Resource Hierarchy Matching:** When candidate path is `/items/{item_id}`, candidates that match the prefix `/items` with `POST` method are prioritized over unrelated endpoints.")
        with col_h2:
            st.info("**2. Acyclic Path Enforcement:** Visited operations are tracked in a recursion set to prevent infinite cycles in complex microservice schemas.")

    with tabs[2]:
        st.subheader("The Five Parameter Generation Strategies")
        st.markdown(
            """
            To construct valid HTTP requests that penetrate deep into application business logic, 
            VOAPI² prioritizes parameter values according to a hierarchy of five distinct generation strategies:
            """
        )

        st1, st2, st3, st4, st5 = st.columns(5)
        with st1:
            st.markdown(
                """
                <div class="light-card" style="border-top: 3px solid #0284C7; text-align: center; height: 100%;">
                    <b style="color: #0284C7;">1. CONSUMER</b>
                    <p style="font-size: 0.8rem; color: #64748B; margin-top: 6px;">
                        Extracts actual dynamic runtime values from earlier producer step responses.
                    </p>
                </div>
                """,
                unsafe_allow_html=True
            )
        with st2:
            st.markdown(
                """
                <div class="light-card" style="border-top: 3px solid #0EA5E9; text-align: center; height: 100%;">
                    <b style="color: #0EA5E9;">2. SPECIFICATION</b>
                    <p style="font-size: 0.8rem; color: #64748B; margin-top: 6px;">
                        Extracts default values, enum definitions, or schema examples from OpenAPI.
                    </p>
                </div>
                """,
                unsafe_allow_html=True
            )
        with st3:
            st.markdown(
                """
                <div class="light-card" style="border-top: 3px solid #0369A1; text-align: center; height: 100%;">
                    <b style="color: #0369A1;">3. FORMAT</b>
                    <p style="font-size: 0.8rem; color: #64748B; margin-top: 6px;">
                        Generates type-conformant values (UUID, email, URI, ISO date, integer).
                    </p>
                </div>
                """,
                unsafe_allow_html=True
            )
        with st4:
            st.markdown(
                """
                <div class="light-card" style="border-top: 3px solid #10B981; text-align: center; height: 100%;">
                    <b style="color: #10B981;">4. SUCCESS</b>
                    <p style="font-size: 0.8rem; color: #64748B; margin-top: 6px;">
                        Reuses parameter values from previously observed successful (2xx) responses.
                    </p>
                </div>
                """,
                unsafe_allow_html=True
            )
        with st5:
            st.markdown(
                """
                <div class="light-card" style="border-top: 3px solid #F59E0B; text-align: center; height: 100%;">
                    <b style="color: #F59E0B;">5. RANDOM</b>
                    <p style="font-size: 0.8rem; color: #64748B; margin-top: 6px;">
                        Generates pseudorandom strings or numbers as a final fallback.
                    </p>
                </div>
                """,
                unsafe_allow_html=True
            )

    with tabs[3]:
        st.subheader("Unguided Fuzzing vs. Vulnerability-Oriented Testing")
        st.markdown(
            """
            The following table summarizes the fundamental distinctions between traditional unguided REST API fuzzers 
            and the vulnerability-oriented paradigm of VOAPI²:
            """
        )

        comparison_data = [
            {"Dimension": "Testing Focus", "Unguided Fuzzers (RESTler, EvoMaster)": "Uniform exploration across all API endpoints", "SecureVault (VOAPI²)": "Candidate interfaces filtered by vulnerability semantic keywords"},
            {"Dimension": "Payload Strategy", "Unguided Fuzzers (RESTler, EvoMaster)": "Random boundary values, long strings, generic format tokens", "SecureVault (VOAPI²)": "CWE-tailored targeted benign probes (SSRF URLs, webshells, traversal tokens, SQL tautologies)"},
            {"Dimension": "Sequence Construction", "Unguided Fuzzers (RESTler, EvoMaster)": "Forward exploration / random walks across dependency graph", "SecureVault (VOAPI²)": "Reverse sequence construction targeting candidate state prerequisites (Algorithm 1)"},
            {"Dimension": "Resource Efficiency", "Unguided Fuzzers (RESTler, EvoMaster)": "High request volume; high proportion of superficial 400/404 errors", "SecureVault (VOAPI²)": "Low request volume; deep penetration into vulnerable business logic"},
            {"Dimension": "Detection Oracles", "Unguided Fuzzers (RESTler, EvoMaster)": "500 Internal Server Error, server crash, schema violation", "SecureVault (VOAPI²)": "Multi-signal vulnerability oracles (canary reflections, leaked files, database tautologies)"}
        ]
        st.table(comparison_data)
