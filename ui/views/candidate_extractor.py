"""
Candidate Interface Extraction View
Executes Stage 2 keyword matching across paths and parameters,
tagging high-risk candidate interfaces and selecting primary injection targets.
"""
import time
import streamlit as st
import pandas as pd
import plotly.express as px
from config.settings import BASE_DIR
from framework.stage1_spec_analysis.parser import OpenAPISpecParser
from framework.stage2_candidate_extraction.extractor import CandidateInterfaceExtractor
from ui.components.styling import render_header, render_metric_card

SPECS_DICT = {
    "SecureVault Dual-Mode API": BASE_DIR / "datasets" / "api_specifications" / "raw" / "securevault_openapi.json",
    "Appwrite v0.9.3": BASE_DIR / "datasets" / "api_specifications" / "raw" / "APISpec-appwrite.json",
    "Request Baskets v1.2.3": BASE_DIR / "datasets" / "api_specifications" / "raw" / "rbaskets-openapi.yaml",
    "Gitea v1.16.7": BASE_DIR / "datasets" / "api_specifications" / "raw" / "gitea-1.16.7-swagger.json"
}

def render_candidate_extractor_view():
    render_header(
        title="Candidate Interface Extraction (Stage 2)",
        subtitle="Semantic Keyword Matching & Target Parameter Tagging across 6 Vulnerability Categories",
        badge="Stage 2 Engine"
    )

    spec_name = st.selectbox("Select Target Specification for Extraction:", list(SPECS_DICT.keys()))
    spec_path = SPECS_DICT[spec_name]

    parser = OpenAPISpecParser(spec_path)
    endpoints = parser.parse()

    extractor = CandidateInterfaceExtractor()
    t0 = time.perf_counter()
    candidates = extractor.extract(endpoints)
    extract_time = (time.perf_counter() - t0) * 1000

    cand_rate = (len(candidates) / len(endpoints) * 100) if endpoints else 0

    # Metric Cards
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(render_metric_card("Total Endpoints", str(len(endpoints)), spec_name, "#48CAE4"), unsafe_allow_html=True)
    with c2:
        st.markdown(render_metric_card("Extracted Candidates", str(len(candidates)), f"{cand_rate:.1f}% Candidate Rate", "#00B4D8"), unsafe_allow_html=True)
    with c3:
        st.markdown(render_metric_card("Extraction Latency", f"{extract_time:.2f} ms", "Sub-millisecond Token Scan", "#10B981"), unsafe_allow_html=True)
    with c4:
        st.markdown(render_metric_card("Corpus Coverage", "6 CWEs", "Table 2 Keyword Matching", "#F59E0B"), unsafe_allow_html=True)

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

    # Category Breakdown Chart
    counts = extractor.count_by_category(candidates)
    df_counts = pd.DataFrame(list(counts.items()), columns=["Vulnerability Class", "Candidate Count"])

    col_chart, col_explain = st.columns([1.5, 1])
    with col_chart:
        fig = px.bar(
            df_counts,
            x="Vulnerability Class",
            y="Candidate Count",
            color="Vulnerability Class",
            title=f"Extracted Candidates per Vulnerability Class ({spec_name})",
            color_discrete_sequence=["#48CAE4", "#00B4D8", "#0077B6", "#10B981", "#F59E0B", "#EF4444"]
        )
        fig.update_layout(paper_bgcolor="#162035", plot_bgcolor="#162035", font_color="#F8FAFC", showlegend=False, height=280, margin=dict(l=10, r=10, t=30, b=10))
        st.plotly_chart(fig, use_container_width=True)

    with col_explain:
        st.markdown("**Extraction Heuristics:**")
        st.markdown(
            """
            - **Path Keyword Weight:** $w_{path} = 1.0$ when endpoint path tokens match empirical CVE patterns.
            - **Parameter Keyword Weight:** $w_{param} = 2.0$ when parameter names directly match vulnerable arguments.
            - **Primary Target Selection:** Highest-weight parameter is marked as the primary injection target for Stage 3 & 4.
            """
        )

    # Candidate Interfaces Table
    st.subheader(f"Extracted Candidate Interfaces ({len(candidates)})")
    
    table_rows = []
    for c in candidates:
        table_rows.append({
            "Method": c.endpoint.method,
            "Path": c.endpoint.path,
            "CWE Category": c.cwe_category,
            "Target Parameter": c.primary_parameter or "(Path/General)",
            "Score": f"{c.score:.1f}",
            "Matched Path Keywords": ", ".join(c.matched_path_keywords) if c.matched_path_keywords else "-",
            "Matched Param Keywords": ", ".join(c.matched_param_keywords) if c.matched_param_keywords else "-"
        })
    df_cand = pd.DataFrame(table_rows)

    cwe_filter = st.selectbox("Filter Candidate Table by Category:", ["All Categories"] + sorted(list(counts.keys())))
    if cwe_filter != "All Categories":
        df_cand = df_cand[df_cand["CWE Category"] == cwe_filter]

    st.dataframe(df_cand, use_container_width=True, height=360)
