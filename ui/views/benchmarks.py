"""
Benchmark Applications View (UI 2.0 Cinematic Redesign)
Presents detailed architectural profiles and empirical specification analysis metrics
across the four investigated benchmark applications: SecureVault, Appwrite, Request Baskets, and Gitea.
"""
import streamlit as st
import pandas as pd
import plotly.express as px
from config.settings import BASE_DIR
from ui.components.styling import render_hero, render_kpi_card

@st.cache_data
def load_benchmark_table():
    csv_path = BASE_DIR / "results" / "tables" / "spec_analysis_benchmark_table.csv"
    if csv_path.exists():
        return pd.read_csv(csv_path)
    return pd.DataFrame()

def render_benchmarks_view():
    render_hero(
        title="Benchmark Applications",
        subtitle="Empirical Multi-Application Specification Analysis across Real-World REST API Architectures",
        badge="4 Real-World Specs",
        meta_items=[
            "🏛️ 4 Target Applications",
            "📊 422 Evaluated Operations",
            "🎯 313 Candidate Interfaces",
            "⚡ Sub-100ms Total Ingestion"
        ]
    )

    df_bench = load_benchmark_table()

    # KPI Cards (Light Surface)
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(render_kpi_card("Total Benchmarks", "4 Applications", "Clean-Room & Real-World", "#0284C7"), unsafe_allow_html=True)
    with c2:
        total_ops = df_bench["# Endpoints"].sum() if not df_bench.empty else 422
        st.markdown(render_kpi_card("Total API Operations", str(total_ops), "Across All 4 Specs", "#0EA5E9"), unsafe_allow_html=True)
    with c3:
        total_cand = df_bench["# Candidates"].sum() if not df_bench.empty else 313
        st.markdown(render_kpi_card("Total Candidates", str(total_cand), "Candidate Interfaces", "#10B981"), unsafe_allow_html=True)
    with c4:
        avg_cand_rate = (total_cand / total_ops * 100) if total_ops else 74.2
        st.markdown(render_kpi_card("Avg Candidate Rate", f"{avg_cand_rate:.1f}%", "Selective Prioritization", "#F59E0B"), unsafe_allow_html=True)

    st.markdown("<div style='height: 18px;'></div>", unsafe_allow_html=True)

    # Discrepancy Note Callout Box
    st.markdown(
        """
        <div class="cyber-callout-light">
            <b style="color: #0284C7;">Specification Counting Audit Note (Request Baskets 20 vs. 22 Operations):</b><br/>
            In preliminary research discussions, Request Baskets was informally noted as having <i>22 endpoints</i>. 
            Our automated OpenAPI 3.0 parser verifies that the official specification (<code>rbaskets-openapi.yaml</code>) 
            defines <b>exactly 10 path keys and 20 discrete HTTP operations</b>. 
            The informal figure of 22 originates from including two unversioned web frontend handler routes (<code>/</code> and <code>/{name}</code> forwarder) 
            outside the formal REST specification. SecureVault adheres strictly to verified machine-readable specifications.
        </div>
        """,
        unsafe_allow_html=True
    )

    st.subheader("Specification Analysis Benchmark Summary Table")
    st.dataframe(df_bench, use_container_width=True)

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

    # Comparison Charts (Plotly with Light Theme)
    col_chart1, col_chart2 = st.columns(2)
    with col_chart1:
        if not df_bench.empty:
            fig_ops = px.bar(
                df_bench,
                x="Application",
                y=["# Endpoints", "# Candidates"],
                barmode="group",
                title="Total Operations vs. Extracted Candidates",
                color_discrete_sequence=["#64748B", "#0284C7"]
            )
            fig_ops.update_layout(paper_bgcolor="#FFFFFF", plot_bgcolor="#F8FAFC", font_color="#0F172A", height=300, margin=dict(l=10, r=10, t=30, b=10))
            st.plotly_chart(fig_ops, use_container_width=True)

    with col_chart2:
        if not df_bench.empty:
            cwe_columns = ["SSRF (918)", "Upload (434)", "Traversal (22)", "CmdI (78)", "SQLi (89)", "XSS (79)"]
            available_cwe_cols = [c for c in cwe_columns if c in df_bench.columns]
            if available_cwe_cols:
                fig_cwe = px.bar(
                    df_bench,
                    x="Application",
                    y=available_cwe_cols,
                    title="Candidate Breakdown by Category",
                    color_discrete_sequence=["#0284C7", "#0EA5E9", "#0369A1", "#10B981", "#F59E0B", "#EF4444"]
                )
                fig_cwe.update_layout(paper_bgcolor="#FFFFFF", plot_bgcolor="#F8FAFC", font_color="#0F172A", height=300, margin=dict(l=10, r=10, t=30, b=10))
                st.plotly_chart(fig_cwe, use_container_width=True)

    st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)

    # Architectural Profiles (Light Elevated Cards)
    st.subheader("Architectural Profiles of Investigated Applications")
    p1, p2 = st.columns(2)
    with p1:
        st.markdown(
            """
            <div class="light-card">
                <b style="color: #0284C7; font-size: 1.05rem;">1. SecureVault Dual-Mode API (v1.0.0)</b>
                <p style="font-size: 0.85rem; color: #64748B; margin-top: 6px;">
                    <b>Role:</b> Academic testbed with dynamic mode switching.<br/>
                    <b>Scale:</b> 16 operations across 11 path structures.<br/>
                    <b>Surface:</b> Models all 6 base paper CWEs with loopback flags,
                    webshell storage, path traversal, shell injection, SQL tautologies, and unescaped HTML reflection.
                </p>
            </div>
            <div class="light-card">
                <b style="color: #0EA5E9; font-size: 1.05rem;">2. Appwrite (v0.9.3)</b>
                <p style="font-size: 0.85rem; color: #64748B; margin-top: 6px;">
                    <b>Role:</b> Real-world backend-as-a-service platform evaluated in VOAPI².<br/>
                    <b>Scale:</b> Exactly 95 HTTP operations matching Table 4 of the base paper.<br/>
                    <b>Surface:</b> File storage endpoints (15 Upload candidates), 
                    database collections (11 SQLi candidates), and webhooks (5 SSRF candidates).
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )
    with p2:
        st.markdown(
            """
            <div class="light-card">
                <b style="color: #0369A1; font-size: 1.05rem;">3. Request Baskets (v1.2.3)</b>
                <p style="font-size: 0.85rem; color: #64748B; margin-top: 6px;">
                    <b>Role:</b> Real-world HTTP request collector and webhook inspection service.<br/>
                    <b>Scale:</b> 20 operations in OpenAPI 3.0 YAML format.<br/>
                    <b>Surface:</b> Basket creation, token retrieval, and forward proxying.
                    Features 16 candidates concentrated around XSS and webhook proxy forwarding.
                </p>
            </div>
            <div class="light-card">
                <b style="color: #10B981; font-size: 1.05rem;">4. Gitea (v1.16.7)</b>
                <p style="font-size: 0.85rem; color: #64748B; margin-top: 6px;">
                    <b>Role:</b> Enterprise self-hosted Git platform examined in VOAPI².<br/>
                    <b>Scale:</b> 291 operations in Swagger 2.0 JSON format.<br/>
                    <b>Surface:</b> Repository hooks (15 SSRF), LFS attachments (20 Upload),
                    raw blob viewing (7 Traversal), git exec hooks (16 CmdI), search queries (71 SQLi), and Markdown issues (78 XSS).
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )
