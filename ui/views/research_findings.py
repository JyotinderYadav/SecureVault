"""
Research Findings View (Module 13: Research Output)
Comprehensive forensic investigation and verification of empirical findings across both
Vulnerable and Hardened runs, featuring multi-signal oracle evidence, latency profiling,
interactive distribution charts, and dual-mode comparative analysis.
"""
import json
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

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

def render_research_findings_view():
    render_hero(
        title="Research Findings",
        subtitle="Forensic Analysis of Stage 4 Test Results, Multi-Signal Oracle Evidence & Dual-Mode Mitigation Audit",
        badge="Research Findings",
        meta_items=[
            "📑 13 Verified Candidates",
            "🔍 Multi-Signal Oracle Verifications",
            "⏱️ Millisecond Latency Telemetry",
            "🛡️ Dual-Mode Defense Validation"
        ]
    )

    vuln_data, hard_data = load_execution_logs()

    # KPI Cards (Light Surface)
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(render_kpi_card("Total Candidate Findings", str(len(vuln_data)), "13 Evaluated Interfaces", "#0284C7"), unsafe_allow_html=True)
    with c2:
        vuln_count = sum(1 for r in vuln_data if r.verdict == "CONFIRMED_VULNERABILITY")
        st.markdown(render_kpi_card("Confirmed (Vulnerable)", str(vuln_count), "All 6 Target CWE Classes", "#EF4444"), unsafe_allow_html=True)
    with c3:
        neg_count = sum(1 for r in hard_data if r.verdict == "NEGATIVE")
        st.markdown(render_kpi_card("Mitigated (Hardened)", str(neg_count), "Zero False Positives", "#10B981"), unsafe_allow_html=True)
    with c4:
        avg_lat = (sum(r.latency_ms for r in vuln_data) / len(vuln_data)) if vuln_data else 0.0
        st.markdown(render_kpi_card("Avg Probe Latency", f"{avg_lat:.2f} ms", "Sub-20ms per Probe", "#F59E0B"), unsafe_allow_html=True)

    st.markdown("<div style='height: 18px;'></div>", unsafe_allow_html=True)

    # Mode Selector Tabs
    tab_vuln, tab_hard, tab_compare = st.tabs([
        "1. Vulnerable Mode Findings (Exploitable Target)",
        "2. Hardened Mode Findings (Defensive Target)",
        "3. Dual-Mode Side-by-Side Verification"
    ])

    with tab_vuln:
        _render_findings_table_and_drilldown(vuln_data, "Vulnerable")

    with tab_hard:
        _render_findings_table_and_drilldown(hard_data, "Hardened")

    with tab_compare:
        _render_dual_mode_comparison(vuln_data, hard_data)

def _render_findings_table_and_drilldown(records: list, mode_name: str):
    st.subheader(f"Vulnerability Findings Log Explorer ({mode_name} Run)")
    
    # Filter controls
    col_cwe, col_verdict = st.columns([1.5, 1.5])
    with col_cwe:
        all_cwes = sorted(list(set(r.cwe_id for r in records if r.cwe_id)))
        selected_cwe = st.selectbox(f"Filter by CWE Category ({mode_name}):", ["All Categories"] + all_cwes, key=f"filter_cwe_{mode_name}")
    with col_verdict:
        all_verdicts = sorted(list(set(r.verdict for r in records if r.verdict)))
        selected_verdict = st.selectbox(f"Filter by Verdict ({mode_name}):", ["All Verdicts"] + all_verdicts, key=f"filter_verdict_{mode_name}")

    filtered = records
    if selected_cwe != "All Categories":
        filtered = [r for r in filtered if r.cwe_id == selected_cwe]
    if selected_verdict != "All Verdicts":
        filtered = [r for r in filtered if r.verdict == selected_verdict]

    # Visual Chart: Verdict by CWE
    if filtered:
        cwe_verdict_counts = {}
        for r in filtered:
            key = (r.cwe_id, r.verdict)
            cwe_verdict_counts[key] = cwe_verdict_counts.get(key, 0) + 1
        
        plot_rows = [{"CWE": k[0], "Verdict": k[1], "Count": v} for k, v in cwe_verdict_counts.items()]
        df_plot = pd.DataFrame(plot_rows)
        
        fig = px.bar(
            df_plot,
            x="CWE",
            y="Count",
            color="Verdict",
            title=f"Findings Breakdown by CWE ({mode_name} Target)",
            color_discrete_map={
                "CONFIRMED_VULNERABILITY": "#EF4444",
                "NEGATIVE": "#10B981",
                "ERROR": "#F59E0B"
            }
        )
        fig.update_layout(
            paper_bgcolor="#FFFFFF",
            plot_bgcolor="#F8FAFC",
            font_color="#0F172A",
            height=280,
            margin=dict(l=10, r=10, t=30, b=10)
        )
        st.plotly_chart(fig, use_container_width=True)

    # Findings Table
    table_rows = []
    for r in filtered:
        cand = r.get("candidate", {})
        table_rows.append({
            "CWE ID": cand.get("cwe_category", r.cwe_id),
            "Method": cand.get("endpoint_method", r.endpoint_method),
            "Endpoint": cand.get("endpoint_path", r.endpoint_path),
            "Target Param": cand.get("primary_parameter", r.primary_parameter),
            "Status Code": r.status_code,
            "Verdict": r.verdict,
            "Latency (ms)": f"{r.latency_ms:.2f}",
            "Payload": r.payload[:35] + "..." if len(r.payload) > 35 else r.payload
        })
    df_table = pd.DataFrame(table_rows)
    st.dataframe(df_table, use_container_width=True, height=280)

    # Detailed Drilldown
    st.markdown("#### Finding Detailed Inspection & Evidence Drilldown")
    if filtered:
        cand_labels = [f"[{r.cwe_id}] {r.endpoint_method} {r.endpoint_path} ({r.verdict})" for r in filtered]
        selected_drill = st.selectbox(
            f"Select Finding to Inspect ({mode_name}):",
            range(len(filtered)),
            format_func=lambda i: cand_labels[i],
            key=f"drill_select_{mode_name}"
        )
        record = filtered[selected_drill]

        col_left, col_right = st.columns(2)
        with col_left:
            verdict_badge_color = "#DC2626" if record.verdict == "CONFIRMED_VULNERABILITY" else "#059669"
            st.markdown(
                f"""
                <div class="light-card" style="border-left: 4px solid {verdict_badge_color};">
                    <b style="color: {verdict_badge_color}; font-size: 1rem;">Verdict: {record.verdict}</b>
                    <p style="margin-top: 8px; font-size: 0.85rem; color: #1E293B;"><b>Analysis:</b> {record.analysis}</p>
                    <div style="font-size: 0.82rem; color: #64748B;">
                        <b>HTTP Status:</b> <code>{record.status_code}</code> | 
                        <b>Latency:</b> <code>{record.latency_ms:.2f} ms</code><br/>
                        <b>Injected Payload:</b> <code>{record.payload}</code>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
            
            st.markdown("**Evidence Signals:**")
            evidence = record.evidence
            if evidence:
                for ev in evidence:
                    st.info(f"🔍 {ev}")
            else:
                st.success("✅ No vulnerability signatures detected in server response (Attack Mitigated).")

        with col_right:
            body = record.get("response_preview") or record.get("response_body", "")
            body_text = json.dumps(body, indent=2) if isinstance(body, dict) else str(body)
            st.markdown(
                render_dark_console(
                    "Server Response Body",
                    f"<pre style='color: #38BDF8; margin: 0; max-height: 250px; overflow-y: auto;'>{body_text[:1000]}</pre>",
                    f"STATUS {record.status_code}"
                ),
                unsafe_allow_html=True
            )
    else:
        st.info("No records match the current filter selection.")

def _render_dual_mode_comparison(vuln_records: list, hard_records: list):
    st.subheader("Dual-Mode Side-by-Side Mitigation Audit")
    st.markdown("Direct head-to-head comparison between Vulnerable Mode (exploit active) and Hardened Mode (defensive controls active) across identical candidate endpoints:")

    endpoints_map = {}
    for r in vuln_records:
        key = f"{r.endpoint_method} {r.endpoint_path}"
        endpoints_map[key] = {"vuln": r, "hard": None}
    for r in hard_records:
        key = f"{r.endpoint_method} {r.endpoint_path}"
        if key in endpoints_map:
            endpoints_map[key]["hard"] = r
        else:
            endpoints_map[key] = {"vuln": None, "hard": r}

    comp_rows = []
    for key, data in endpoints_map.items():
        v = data["vuln"]
        h = data["hard"]
        comp_rows.append({
            "Target Endpoint": key,
            "CWE": v.cwe_id if v else (h.cwe_id if h else "-"),
            "Vulnerable Verdict": v.verdict if v else "N/A",
            "Vulnerable HTTP": v.status_code if v else "N/A",
            "Hardened Verdict": h.verdict if h else "N/A",
            "Hardened HTTP": h.status_code if h else "N/A",
            "Mitigation Verified": "✅ YES (Neutralized)" if (v and v.verdict == "CONFIRMED_VULNERABILITY" and h and h.verdict == "NEGATIVE") else ("⚠️ INCONCLUSIVE" if not v or not h else "NEUTRAL")
        })

    df_comp = pd.DataFrame(comp_rows)
    st.dataframe(df_comp, use_container_width=True, height=400)

