"""
Candidate Interface Extraction View (UI 2.0 Cinematic Redesign)
Executes Stage 2 semantic keyword matching across paths and parameters,
tagging high-risk candidate interfaces and selecting primary injection targets.
"""
import time
import streamlit as st
import pandas as pd
import plotly.express as px
from config.settings import BASE_DIR
from framework.stage1_spec_analysis.parser import OpenAPISpecParser
from framework.stage2_candidate_extraction.extractor import CandidateInterfaceExtractor
from ui.components.styling import render_hero, render_kpi_card

SPECS_DICT = {
    "SecureVault Dual-Mode API": BASE_DIR / "datasets" / "api_specifications" / "raw" / "securevault_openapi.json",
    "Appwrite v0.9.3": BASE_DIR / "datasets" / "api_specifications" / "raw" / "APISpec-appwrite.json",
    "Request Baskets v1.2.3": BASE_DIR / "datasets" / "api_specifications" / "raw" / "rbaskets-openapi.yaml",
    "Gitea v1.16.7": BASE_DIR / "datasets" / "api_specifications" / "raw" / "gitea-1.16.7-swagger.json"
}

def render_candidate_extractor_view():
    render_hero(
        title="Candidate Interface Extraction",
        subtitle="Semantic Keyword Matching, Target Parameter Tagging & Candidate Scoring across 6 Vulnerability Categories (Stage 2)",
        badge="Stage 2 Engine",
        meta_items=[
            "🔍 72 Path Keywords",
            "🎯 56 Parameter Keywords",
            "⚖️ Weighted Scoring Model",
            "🏷️ Primary Target Tagging"
        ]
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

    # KPI Cards (Light Surface)
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(render_kpi_card("Total Endpoints", str(len(endpoints)), spec_name, "#0284C7"), unsafe_allow_html=True)
    with c2:
        st.markdown(render_kpi_card("Extracted Candidates", str(len(candidates)), f"{cand_rate:.1f}% Candidate Rate", "#0EA5E9"), unsafe_allow_html=True)
    with c3:
        st.markdown(render_kpi_card("Extraction Latency", f"{extract_time:.2f} ms", "Sub-millisecond Token Scan", "#10B981"), unsafe_allow_html=True)
    with c4:
        st.markdown(render_kpi_card("Corpus Coverage", "6 CWEs", "Table 2 Keyword Matching", "#F59E0B"), unsafe_allow_html=True)

    st.markdown("<div style='height: 18px;'></div>", unsafe_allow_html=True)

    # Category Breakdown Chart & Extraction Heuristics
    counts = extractor.count_by_category(candidates)
    df_counts = pd.DataFrame(list(counts.items()), columns=["Vulnerability Class", "Candidate Count"])

    col_chart, col_explain = st.columns([1.6, 1.4])
    with col_chart:
        fig = px.bar(
            df_counts,
            x="Vulnerability Class",
            y="Candidate Count",
            color="Vulnerability Class",
            title=f"Extracted Candidates per Vulnerability Class ({spec_name})",
            color_discrete_sequence=["#0284C7", "#0EA5E9", "#0369A1", "#10B981", "#F59E0B", "#EF4444"]
        )
        fig.update_layout(paper_bgcolor="#FFFFFF", plot_bgcolor="#F8FAFC", font_color="#0F172A", showlegend=False, height=280, margin=dict(l=10, r=10, t=30, b=10))
        st.plotly_chart(fig, use_container_width=True)

    with col_explain:
        st.markdown("#### Extraction Scoring Heuristics")
        st.markdown(
            """
            <div class="light-card">
                <b>Priority Score Formula:</b><br/>
                <code>Score(e, c) = w_path * N_path + w_param * N_param</code><br/><br/>
                <ul style="font-size: 0.85rem; color: #64748B; padding-left: 20px; margin-bottom: 0;">
                    <li><b>Path Weight ($w_{path} = 1.0$):</b> Path token matches empirical CVE patterns (e.g. <code>sync</code>, <code>upload</code>, <code>download</code>, <code>exec</code>).</li>
                    <li><b>Parameter Weight ($w_{param} = 2.0$):</b> Parameter directly matches vulnerable arguments (e.g. <code>url</code>, <code>file</code>, <code>path</code>, <code>cmd</code>, <code>query</code>).</li>
                    <li><b>Primary Parameter Tagging:</b> Highest-scoring parameter is chosen as $p_{target}$ for payload injection.</li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True
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
