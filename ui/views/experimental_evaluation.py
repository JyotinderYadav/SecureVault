"""
Experimental Evaluation View (UI 2.0 Cinematic Redesign)
Presents the formal empirical comparison between Baseline Generic Fuzzing and VOAPI²
across the six targeted vulnerability categories in both Vulnerable and Hardened modes.
"""
import json
import streamlit as st
import pandas as pd
from config.settings import BASE_DIR
from ui.components.styling import render_hero, render_kpi_card, render_dark_console

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
    render_hero(
        title="Experimental Evaluation",
        subtitle="Empirical Head-to-Head Benchmarking: Baseline Fuzzing vs. VOAPI² on SecureVault",
        badge="Comparative Evaluation",
        meta_items=[
            "🧪 Controlled Head-to-Head Testing",
            "🎯 100% Target Detection",
            "📉 68.8% Request Reduction",
            "⚡ 6.6x Execution Speedup"
        ]
    )

    df_results, summary = load_eval_data()

    # KPI Cards (Light Surface)
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(render_kpi_card("VOAPI² Detection Rate", "100%", "6 / 6 Confirmed CWEs", "#10B981"), unsafe_allow_html=True)
    with c2:
        st.markdown(render_kpi_card("Baseline Detection Rate", "0.0%", "0 / 6 Targets Discovered", "#EF4444"), unsafe_allow_html=True)
    with c3:
        st.markdown(render_kpi_card("Request Reduction", "68.8%", "15 vs 48 Requests", "#0284C7"), unsafe_allow_html=True)
    with c4:
        st.markdown(render_kpi_card("Execution Speedup", "6.6x", "162.8 ms vs 1,078.1 ms", "#F59E0B"), unsafe_allow_html=True)

    st.markdown("<div style='height: 18px;'></div>", unsafe_allow_html=True)

    # Detailed Comparison Table
    st.subheader("Vulnerability Detection by Category (Table 3 Reproduction)")
    st.dataframe(df_results, use_container_width=True)

    st.markdown("<div style='height: 18px;'></div>", unsafe_allow_html=True)

    # Key Empirical Insights
    st.subheader("Comparative Root-Cause Analysis")
    i1, i2 = st.columns(2)
    with i1:
        st.markdown(
            """
            <div class="light-card" style="border-left: 4px solid #EF4444;">
                <b style="color: #DC2626; font-size: 1rem;">1. Why Baseline Generic Fuzzing Failed (0% Detection):</b>
                <p style="font-size: 0.85rem; color: #64748B; margin-top: 8px; line-height: 1.5;">
                    Blindly injecting generic strings, empty inputs, and boundary integers failed across all categories:
                </p>
                <ul style="font-size: 0.82rem; color: #64748B; padding-left: 18px;">
                    <li><b>SSRF:</b> Blind fuzz strings like <code>%s%p</code> failed Pydantic URL format validation (422 Unprocessable Entity).</li>
                    <li><b>File Upload:</b> Random byte streams were treated as plain text and never executed script handlers.</li>
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
            <div class="light-card" style="border-left: 4px solid #10B981;">
                <b style="color: #059669; font-size: 1rem;">2. Why VOAPI² Succeeded (100% Detection):</b>
                <p style="font-size: 0.85rem; color: #64748B; margin-top: 8px; line-height: 1.5;">
                    Targeted vulnerability-oriented sequence generation achieved complete precision:
                </p>
                <ul style="font-size: 0.82rem; color: #64748B; padding-left: 18px;">
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

    # 35% Dark Console for Raw Summary JSON
    st.markdown("#### Full Benchmark Summary Telemetry (35% Dark Console)")
    json_summary = json.dumps(summary, indent=2)
    st.markdown(render_dark_console("Benchmark Summary JSON", f"<pre style='color: #38BDF8; margin: 0; max-height: 250px; overflow-y: auto;'>{json_summary}</pre>", "RAW ARTIFACT"), unsafe_allow_html=True)
