"""
Benchmark Applications View
Presents detailed architectural profiles and empirical specification analysis metrics
across the four investigated benchmark applications: SecureVault, Appwrite, Request Baskets, and Gitea.
"""
import streamlit as st
import pandas as pd
import plotly.express as px
from config.settings import BASE_DIR
from ui.components.styling import render_header, render_metric_card

@st.cache_data
def load_benchmark_table():
    csv_path = BASE_DIR / "results" / "tables" / "spec_analysis_benchmark_table.csv"
    if csv_path.exists():
        return pd.read_csv(csv_path)
    return pd.DataFrame()

def render_benchmarks_view():
    render_header(
        title="Benchmark Applications",
        subtitle="Empirical Multi-Application Specification Analysis across Real-World REST API Architectures",
        badge="4 Benchmarks"
    )

    df_bench = load_benchmark_table()

    # Top Metrics
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(render_metric_card("Total Benchmarks", "4 Applications", "Clean-Room & Real-World", "#48CAE4"), unsafe_allow_html=True)
    with c2:
        total_ops = df_bench["# Endpoints"].sum() if not df_bench.empty else 422
        st.markdown(render_metric_card("Total API Operations", str(total_ops), "Across All 4 Specs", "#00B4D8"), unsafe_allow_html=True)
    with c3:
        total_cand = df_bench["# Candidates"].sum() if not df_bench.empty else 313
        st.markdown(render_metric_card("Total Candidates", str(total_cand), "Candidate Interfaces", "#10B981"), unsafe_allow_html=True)
    with c4:
        avg_cand_rate = (total_cand / total_ops * 100) if total_ops else 74.2
        st.markdown(render_metric_card("Avg Candidate Rate", f"{avg_cand_rate:.1f}%", "Selective Prioritization", "#F59E0B"), unsafe_allow_html=True)

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

    st.subheader("Specification Analysis Benchmark Summary Table")
    st.dataframe(df_bench, use_container_width=True)

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

    # Comparison Charts
    col_chart1, col_chart2 = st.columns(2)
    with col_chart1:
        fig_ops = px.bar(
            df_bench,
            x="Application",
            y=["# Endpoints", "# Candidates"],
            barmode="group",
            title="Total Endpoints vs. Extracted Candidates",
            color_discrete_sequence=["#3A506B", "#48CAE4"]
        )
        fig_ops.update_layout(paper_bgcolor="#162035", plot_bgcolor="#162035", font_color="#F8FAFC", height=300, margin=dict(l=10, r=10, t=30, b=10))
        st.plotly_chart(fig_ops, use_container_width=True)

    with col_chart2:
        cwe_columns = ["SSRF (918)", "Upload (434)", "Traversal (22)", "CmdI (78)", "SQLi (89)", "XSS (79)"]
        available_cwe_cols = [c for c in cwe_columns if c in df_bench.columns]
        if available_cwe_cols:
            fig_cwe = px.bar(
                df_bench,
                x="Application",
                y=available_cwe_cols,
                title="Candidate Breakdown by Vulnerability Category",
                color_discrete_sequence=["#48CAE4", "#00B4D8", "#0077B6", "#10B981", "#F59E0B", "#EF4444"]
            )
            fig_cwe.update_layout(paper_bgcolor="#162035", plot_bgcolor="#162035", font_color="#F8FAFC", height=300, margin=dict(l=10, r=10, t=30, b=10))
            st.plotly_chart(fig_cwe, use_container_width=True)

    st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)

    # Detailed Application Profiles
    st.subheader("Architectural Profiles of Investigated Applications")
    p1, p2 = st.columns(2)
    with p1:
        st.markdown(
            """
            <div style="background-color: #162035; border: 1px solid #3A506B; border-radius: 8px; padding: 16px; margin-bottom: 12px;">
                <h4 style="color: #48CAE4; margin-top: 0;">1. SecureVault Dual-Mode API (v1.0.0)</h4>
                <p style="font-size: 0.85rem; color: #94A3B8;">
                    <b>Role:</b> Academic testbed with dynamic mode switching.<br/>
                    <b>Scale:</b> 16 operations across 11 path structures.<br/>
                    <b>Vulnerability Surface:</b> Explicitly models all 6 base paper CWEs with loopback flags,
                    webshell storage, path traversal, shell injection, SQL tautologies, and unescaped HTML reflection.
                </p>
            </div>
            <div style="background-color: #162035; border: 1px solid #3A506B; border-radius: 8px; padding: 16px;">
                <h4 style="color: #00B4D8; margin-top: 0;">2. Appwrite (v0.9.3)</h4>
                <p style="font-size: 0.85rem; color: #94A3B8;">
                    <b>Role:</b> Real-world backend-as-a-service platform evaluated in USENIX paper.<br/>
                    <b>Scale:</b> Exactly 95 HTTP operations matching Table 4 of the base paper.<br/>
                    <b>Vulnerability Surface:</b> Heavy concentration of file storage endpoints (15 Upload candidates), 
                    database collections (11 SQLi candidates), and webhooks (5 SSRF candidates).
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )
    with p2:
        st.markdown(
            """
            <div style="background-color: #162035; border: 1px solid #3A506B; border-radius: 8px; padding: 16px; margin-bottom: 12px;">
                <h4 style="color: #0077B6; margin-top: 0;">3. Request Baskets (v1.2.3)</h4>
                <p style="font-size: 0.85rem; color: #94A3B8;">
                    <b>Role:</b> Real-world HTTP request collector and webhook inspection service.<br/>
                    <b>Scale:</b> 20 operations in OpenAPI 3.0 YAML format.<br/>
                    <b>Vulnerability Surface:</b> Primarily basket creation, token retrieval, and webhook proxy forwarding.
                    Features 16 candidates concentrated around XSS and webhook proxy forwarding.
                </p>
            </div>
            <div style="background-color: #162035; border: 1px solid #3A506B; border-radius: 8px; padding: 16px;">
                <h4 style="color: #10B981; margin-top: 0;">4. Gitea (v1.16.7)</h4>
                <p style="font-size: 0.85rem; color: #94A3B8;">
                    <b>Role:</b> Enterprise self-hosted Git platform examined in VOAPI².<br/>
                    <b>Scale:</b> 291 operations in Swagger 2.0 JSON format.<br/>
                    <b>Vulnerability Surface:</b> Comprehensive surface: repository hooks (15 SSRF), LFS attachments (20 Upload),
                    raw blob viewing (7 Traversal), git exec hooks (16 CmdI), search queries (71 SQLi), and Markdown issues (78 XSS).
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )
