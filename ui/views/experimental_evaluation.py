"""
Experimental Evaluation View
Presents the formal empirical comparison between Baseline Generic Fuzzing and VOAPI²
across the six targeted vulnerability categories in both Vulnerable and Hardened modes.
"""
import json
import streamlit as st
import pandas as pd
from config.settings import BASE_DIR
from ui.components.styling import render_header, render_metric_card

@st.cache_data
def load_eval_data():
    csv_path = BASE_DIR / "results" / "tables" / "vulnerability_detection_table.csv"
    summary_path = BASE_DIR / "results" / "processed" / "comparison_summary.json"
    
    df_results = pd.read_csv(csv_path) if csv_path.exists() else pd.DataFrame()
    summary = {}
    if summary_path.exists():
        with open(summary_path, "r", encoding="utf-8") as f:
            summary = json.load(f)
            
    return df_results, summary

def render_experimental_evaluation_view():
    render_header(
        title="Experimental Evaluation",
        subtitle="Empirical Head-to-Head Benchmarking: Baseline Fuzzing vs. VOAPI² on SecureVault",
        badge="Comparative Evaluation"
    )

    df_results, summary = load_eval_data()

    # Top Metric Comparisons
    st.subheader("Quantitative Performance Metrics")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(render_metric_card("VOAPI² Detection Rate", "100%", "6 / 6 Confirmed CWEs", "#10B981"), unsafe_allow_html=True)
    with c2:
        st.markdown(render_metric_card("Baseline Detection Rate", "0.0%", "0 / 6 Targets Discovered", "#EF4444"), unsafe_allow_html=True)
    with c3:
        st.markdown(render_metric_card("Request Reduction", "68.8%", "15 vs 48 Requests", "#00B4D8"), unsafe_allow_html=True)
    with c4:
        st.markdown(render_metric_card("Execution Speedup", "6.6x", "162.8 ms vs 1,078.1 ms", "#F59E0B"), unsafe_allow_html=True)

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

    # Detailed Comparison Table
    st.subheader("Vulnerability Detection by Category (Table 3 Reproduction)")
    st.dataframe(df_results, use_container_width=True)

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

    # Key Empirical Insights
    st.subheader("Key Empirical Takeaways")
    i1, i2 = st.columns(2)
    with i1:
        st.markdown(
            """
            <div class="cyber-callout">
                <b style="color: #48CAE4;">1. Why Baseline Generic Fuzzing Failed (0% Detection):</b><br/>
                Blindly injecting random boundary values, empty strings, and generic format strings failed across all categories:
                <ul>
                    <li><b>SSRF:</b> Blind fuzz strings like <code>%s%p</code> failed Pydantic URL format validation (422 Unprocessable Entity).</li>
                    <li><b>File Upload:</b> Random byte streams were treated as regular data and never triggered executable webshell handlers.</li>
                    <li><b>Path Traversal:</b> Blind strings like <code>AAAA...</code> failed to navigate directory hierarchies.</li>
                    <li><b>SQL Injection:</b> Generic quotes without boolean tautologies or comments produced unhandled syntax errors without exfiltrating records.</li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True
        )
    with i2:
        st.markdown(
            """
            <div class="cyber-callout">
                <b style="color: #10B981;">2. Why VOAPI² Succeeded (100% Detection):</b><br/>
                Targeted vulnerability-oriented sequence generation achieved complete precision:
                <ul>
                    <li><b>Candidate Prioritization:</b> Filtered 16 operations to 13 high-risk candidate targets with primary parameter tagging.</li>
                    <li><b>Semantic Payloads:</b> Injected tailored loopback URLs (CWE-918), polyglot webshells (CWE-434), relative traversal paths (CWE-22), and SQL tautologies (CWE-89).</li>
                    <li><b>Multi-Signal Oracles:</b> Inspected status codes, leaked environment canaries, database records, and unescaped HTML reflections.</li>
                    <li><b>Defensive Validation:</b> In hardened mode, verified 100% neutralization with 0 false positives.</li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

    # Raw Summary JSON Viewer
    with st.expander("View Full Experimental Summary (JSON)"):
        st.json(summary)
