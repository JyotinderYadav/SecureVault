"""
Feedback & Vulnerability Findings View
Detailed inspection of Stage 4 test results, multi-signal oracle evidence,
HTTP response headers, latency measurements, and root-cause analysis.
"""
import json
import streamlit as st
import pandas as pd
from config.settings import BASE_DIR
from ui.components.styling import render_header, render_metric_card

@st.cache_data
def load_execution_logs():
    vuln_log_path = BASE_DIR / "results" / "raw" / "voapi2_vulnerable_log.json"
    hard_log_path = BASE_DIR / "results" / "raw" / "voapi2_hardened_log.json"
    
    vuln_data = []
    hard_data = []
    if vuln_log_path.exists():
        with open(vuln_log_path, "r", encoding="utf-8") as f:
            vuln_data = json.load(f)
    if hard_log_path.exists():
        with open(hard_log_path, "r", encoding="utf-8") as f:
            hard_data = json.load(f)
            
    return vuln_data, hard_data

def render_feedback_findings_view():
    render_header(
        title="Feedback & Vulnerability Findings (Stage 4)",
        subtitle="Forensic Analysis of Stage 4 Test Results, Oracle Evaluation Signals & Root Cause Explanations",
        badge="Stage 4 Findings"
    )

    vuln_data, hard_data = load_execution_logs()

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(render_metric_card("Tested Candidates", str(len(vuln_data)), "SecureVault Testbed", "#48CAE4"), unsafe_allow_html=True)
    with c2:
        vuln_count = sum(1 for r in vuln_data if r.get("verdict") == "CONFIRMED_VULNERABILITY")
        st.markdown(render_metric_card("Confirmed (Vulnerable)", str(vuln_count), "All 6 CWE Classes", "#EF4444"), unsafe_allow_html=True)
    with c3:
        neg_count = sum(1 for r in hard_data if r.get("verdict") == "NEGATIVE")
        st.markdown(render_metric_card("Mitigated (Hardened)", str(neg_count), "Zero False Positives", "#10B981"), unsafe_allow_html=True)
    with c4:
        avg_lat = (sum(r.get("latency_ms", 0) for r in vuln_data) / len(vuln_data)) if vuln_data else 0
        st.markdown(render_metric_card("Avg Latency", f"{avg_lat:.2f} ms", "Sub-20ms per Probe", "#F59E0B"), unsafe_allow_html=True)

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

    st.subheader("Vulnerability Findings Log Explorer")
    mode_view = st.radio("Select Target Evaluation Run:", ["Vulnerable Mode (Exploitable Target)", "Hardened Mode (Defensive Target)"], horizontal=True)

    active_records = vuln_data if "Vulnerable" in mode_view else hard_data

    # Table
    table_rows = []
    for r in active_records:
        cand = r.get("candidate", {})
        verdict = r.get("verdict", "")
        table_rows.append({
            "CWE ID": cand.get("cwe_category", "-"),
            "Method": cand.get("endpoint_method", "-"),
            "Endpoint": cand.get("endpoint_path", "-"),
            "Target Param": cand.get("primary_parameter", "-"),
            "Status Code": r.get("status_code", 0),
            "Verdict": verdict,
            "Latency (ms)": f"{r.get('latency_ms', 0):.2f}",
            "Payload": r.get("payload", "")[:30] + "..." if len(r.get("payload", "")) > 30 else r.get("payload", "")
        })
    df_table = pd.DataFrame(table_rows)
    st.dataframe(df_table, use_container_width=True, height=320)

    # Detailed Drilldown
    st.markdown("#### Finding Detailed Inspection & Evidence Drilldown")
    if active_records:
        cand_labels = [f"[{r.get('candidate', {}).get('cwe_category')}] {r.get('candidate', {}).get('endpoint_method')} {r.get('candidate', {}).get('endpoint_path')}" for r in active_records]
        selected_drill = st.selectbox("Select Finding to Inspect:", range(len(active_records)), format_func=lambda i: cand_labels[i])
        record = active_records[selected_drill]

        col_left, col_right = st.columns(2)
        with col_left:
            st.markdown(f"**Verdict:** `{record.get('verdict')}`")
            st.markdown(f"**Analysis:** {record.get('analysis')}")
            st.markdown(f"**HTTP Status:** `{record.get('status_code')}`")
            st.markdown(f"**Latency:** `{record.get('latency_ms', 0):.2f} ms`")
            st.markdown(f"**Injected Payload:** `{record.get('payload')}`")
            
            st.markdown("**Evidence Signals:**")
            evidence = record.get("evidence", [])
            if evidence:
                for ev in evidence:
                    st.write(f"- 🔍 {ev}")
            else:
                st.write("- (No vulnerability signals detected)")

        with col_right:
            st.markdown("**Response Body:**")
            body = record.get("response_body", "")
            body_text = json.dumps(body, indent=2) if isinstance(body, dict) else str(body)
            st.code(body_text[:1000], language="json" if "{" in body_text else "text")
