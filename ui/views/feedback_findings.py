"""
Feedback & Vulnerability Findings View (UI 2.0 Cinematic Redesign)
Detailed inspection of Stage 4 test results, multi-signal oracle evidence,
HTTP response headers, latency measurements, and root-cause analysis.
"""
import json
import streamlit as st
import pandas as pd
from config.settings import BASE_DIR
from ui.models.findings import load_finding_records, FindingRecord
from ui.components.styling import render_hero, render_kpi_card, render_dark_console

@st.cache_data
def load_execution_logs():
    vuln_log_path = BASE_DIR / "results" / "raw" / "voapi2_vulnerable_log.json"
    hard_log_path = BASE_DIR / "results" / "raw" / "voapi2_hardened_log.json"
    
    vuln_records = load_finding_records(vuln_log_path)
    hard_records = load_finding_records(hard_log_path)
            
    return vuln_records, hard_records

def render_feedback_findings_view():
    render_hero(
        title="Feedback & Vulnerability Findings",
        subtitle="Forensic Analysis of Stage 4 Test Results, Oracle Evaluation Signals & Root Cause Explanations",
        badge="Stage 4 Findings",
        meta_items=[
            "📑 13 Candidate Interfaces",
            "🔍 Multi-Signal Oracle Verifications",
            "⏱️ Millisecond Latency Telemetry",
            "🛡️ Dual-Mode Defense Validation"
        ]
    )

    vuln_data, hard_data = load_execution_logs()

    # KPI Cards (Light Surface)
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(render_kpi_card("Tested Candidates", str(len(vuln_data)), "SecureVault Testbed", "#0284C7"), unsafe_allow_html=True)
    with c2:
        vuln_count = sum(1 for r in vuln_data if r.verdict == "CONFIRMED_VULNERABILITY")
        st.markdown(render_kpi_card("Confirmed (Vulnerable)", str(vuln_count), "All 6 CWE Classes", "#EF4444"), unsafe_allow_html=True)
    with c3:
        neg_count = sum(1 for r in hard_data if r.verdict == "NEGATIVE")
        st.markdown(render_kpi_card("Mitigated (Hardened)", str(neg_count), "Zero False Positives", "#10B981"), unsafe_allow_html=True)
    with c4:
        avg_lat = (sum(r.latency_ms for r in vuln_data) / len(vuln_data)) if vuln_data else 0.0
        st.markdown(render_kpi_card("Avg Latency", f"{avg_lat:.2f} ms", "Sub-20ms per Probe", "#F59E0B"), unsafe_allow_html=True)

    st.markdown("<div style='height: 18px;'></div>", unsafe_allow_html=True)

    st.subheader("Vulnerability Findings Log Explorer")
    mode_view = st.radio("Select Target Evaluation Run:", ["Vulnerable Mode (Exploitable Target)", "Hardened Mode (Defensive Target)"], horizontal=True)

    active_records = vuln_data if "Vulnerable" in mode_view else hard_data

    # Findings Table
    table_rows = []
    for r in active_records:
        cand = r.get("candidate", {})
        verdict = r.verdict
        table_rows.append({
            "CWE ID": cand.get("cwe_category", r.cwe_id),
            "Method": cand.get("endpoint_method", r.endpoint_method),
            "Endpoint": cand.get("endpoint_path", r.endpoint_path),
            "Target Param": cand.get("primary_parameter", r.primary_parameter),
            "Status Code": r.status_code,
            "Verdict": verdict,
            "Latency (ms)": f"{r.latency_ms:.2f}",
            "Payload": r.payload[:30] + "..." if len(r.payload) > 30 else r.payload
        })
    df_table = pd.DataFrame(table_rows)
    st.dataframe(df_table, use_container_width=True, height=320)

    # Detailed Drilldown (35% Dark Console)
    st.markdown("#### Finding Detailed Inspection & Evidence Drilldown")
    if active_records:
        cand_labels = [f"[{r.cwe_id}] {r.endpoint_method} {r.endpoint_path} ({r.verdict})" for r in active_records]
        selected_drill = st.selectbox("Select Finding to Inspect:", range(len(active_records)), format_func=lambda i: cand_labels[i])
        record = active_records[selected_drill]

        col_left, col_right = st.columns(2)
        with col_left:
            st.markdown(f"**Verdict:** `{record.verdict}`")
            st.markdown(f"**Analysis:** {record.analysis}")
            st.markdown(f"**HTTP Status:** `{record.status_code}`")
            st.markdown(f"**Latency:** `{record.latency_ms:.2f} ms`")
            st.markdown(f"**Injected Payload:** `{record.payload}`")
            
            st.markdown("**Evidence Signals:**")
            evidence = record.evidence
            if evidence:
                for ev in evidence:
                    st.info(f"🔍 {ev}")
            else:
                st.write("- (No vulnerability signals detected / Attack mitigated)")

        with col_right:
            body = record.get("response_preview") or record.get("response_body", "")
            body_text = json.dumps(body, indent=2) if isinstance(body, dict) else str(body)
            st.markdown(render_dark_console("Server Response Body", f"<pre style='color: #38BDF8; margin: 0; max-height: 250px; overflow-y: auto;'>{body_text[:1000]}</pre>", "HTTP PAYLOAD"), unsafe_allow_html=True)
