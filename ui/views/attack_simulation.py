"""
Attack Simulation Lab View
Provides an interactive real-time security testing environment against the SecureVault API testbed.
Allows selecting specific CWE targets, configuring benign test probes, executing test sequences,
and observing live HTTP request/response lifecycles and oracle verdicts.
"""
import time
import streamlit as st
from fastapi.testclient import TestClient

from app.main import app
from config.settings import system_config, BASE_DIR
from framework.stage1_spec_analysis.parser import OpenAPISpecParser
from framework.stage2_candidate_extraction.extractor import CandidateInterfaceExtractor
from framework.stage3_sequence_generation.sequencer import TestSequenceGenerator
from framework.stage4_feedback_testing.runner import FeedbackTestRunner
from ui.components.styling import render_header, render_metric_card

TARGET_CWES = [
    ("CWE-918", "Server-Side Request Forgery", "/api/v1/vault/sync"),
    ("CWE-434", "Unrestricted File Upload", "/api/v1/vault/upload"),
    ("CWE-22", "Path Traversal", "/api/v1/vault/files/read"),
    ("CWE-78", "OS Command Injection", "/api/v1/vault/tools/ping-backup"),
    ("CWE-89", "SQL Injection", "/api/v1/vault/records/search"),
    ("CWE-79", "Stored Cross-Site Scripting", "/api/v1/vault/audit/logs")
]

def render_attack_simulation_view():
    render_header(
        title="Attack Simulation Lab (Stage 4)",
        subtitle="Interactive Test Execution, Benign Payload Injection & Multi-Signal Oracle Verdicts",
        badge="Stage 4 Lab"
    )

    current_mode = system_config.mode.value
    badge_class = "badge-vulnerable" if current_mode == "VULNERABLE" else "badge-hardened"
    
    col_mode_info, col_toggle = st.columns([3, 1])
    with col_mode_info:
        st.markdown(
            f"""
            <div style="background-color: #1C2541; padding: 12px 18px; border-radius: 8px; border: 1px solid #3A506B;">
                Active Target Mode: <span class="{badge_class}">{current_mode}</span>
                <span style="font-size: 0.85rem; color: #94A3B8; margin-left: 12px;">
                    { 'Vulnerabilities are live and exploitable' if current_mode == 'VULNERABLE' else 'Input validation, parameterized SQL & boundaries active' }
                </span>
            </div>
            """,
            unsafe_allow_html=True
        )
    with col_toggle:
        if st.button("Toggle Mode: " + ("HARDENED" if current_mode == "VULNERABLE" else "VULNERABLE"), use_container_width=True):
            system_config.toggle_mode()
            st.rerun()

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

    # Candidate selection
    col_cwe, col_payload = st.columns(2)
    with col_cwe:
        cwe_labels = [f"[{cwe}] {name} ({ep})" for cwe, name, ep in TARGET_CWES]
        selected_idx = st.selectbox("Select Target Vulnerability to Test:", range(len(TARGET_CWES)), format_func=lambda i: cwe_labels[i])
        cwe_id, cwe_name, target_ep = TARGET_CWES[selected_idx]

    # Load default payloads
    spec_path = BASE_DIR / "datasets" / "api_specifications" / "raw" / "securevault_openapi.json"
    parser = OpenAPISpecParser(spec_path)
    endpoints = parser.parse()
    extractor = CandidateInterfaceExtractor()
    candidates = extractor.extract(endpoints)

    # Find the candidate matching this CWE and endpoint
    cand = next((c for c in candidates if c.cwe_category == cwe_id and c.endpoint.path == target_ep), None)
    if not cand:
        cand = next((c for c in candidates if c.cwe_category == cwe_id), candidates[0])

    # Runner setup
    client = TestClient(app)
    sequencer = TestSequenceGenerator(endpoints)
    runner = FeedbackTestRunner(client=client)

    default_payloads = runner.payload_library.get(cwe_id, {}).get("payloads", ["test_probe"])
    with col_payload:
        selected_payload = st.selectbox("Select Benign Test Payload:", default_payloads)

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
    launch_btn = st.button("🚀 Execute Vulnerability Test Sequence", use_container_width=True)

    if launch_btn:
        st.markdown("---")
        st.subheader("Live Execution Trace")
        
        sequence = sequencer.generate_sequence(cand)
        
        with st.spinner("Executing sequence and evaluating vulnerability oracles..."):
            t0 = time.perf_counter()
            result = runner.run_sequence(sequence, cand, custom_payload=selected_payload)
            elapsed = (time.perf_counter() - t0) * 1000

        # Verdict Banner
        is_vuln = (result.verdict.value == "CONFIRMED_VULNERABILITY")
        v_color = "#EF4444" if is_vuln else ("#10B981" if result.verdict.value == "NEGATIVE" else "#F59E0B")
        
        st.markdown(
            f"""
            <div style="background-color: #162035; border: 2px solid {v_color}; border-radius: 8px; padding: 18px; margin-bottom: 20px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-size: 1.3rem; font-weight: 800; color: {v_color};">
                        Oracle Verdict: {result.verdict.value}
                    </span>
                    <span style="font-size: 0.9rem; color: #94A3B8;">Execution Time: {elapsed:.2f} ms</span>
                </div>
                <div style="font-size: 0.95rem; color: #F8FAFC; margin-top: 8px;">
                    <b>Analysis:</b> {result.analysis}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # Response Details Cards
        rc1, rc2, rc3 = st.columns(3)
        with rc1:
            st.markdown(render_metric_card("HTTP Status", str(result.status_code), "Response Code", "#48CAE4"), unsafe_allow_html=True)
        with rc2:
            st.markdown(render_metric_card("Network Latency", f"{result.latency_ms:.2f} ms", "Roundtrip Time", "#00B4D8"), unsafe_allow_html=True)
        with rc3:
            st.markdown(render_metric_card("Evidence Count", str(len(result.evidence)), "Oracle Signals", "#10B981" if not is_vuln else "#EF4444"), unsafe_allow_html=True)

        st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

        col_req, col_resp = st.columns(2)
        with col_req:
            st.markdown("**Triggering Request Details:**")
            st.code(
                f"{cand.endpoint.method} {cand.endpoint.path}\nTarget Parameter: {cand.primary_parameter}\nInjected Payload: {selected_payload}",
                language="http"
            )
        with col_resp:
            st.markdown("**Server Response Body Preview:**")
            body_str = result.response_body if isinstance(result.response_body, str) else str(result.response_body)
            st.code(body_str[:800], language="json" if "{" in body_str else "text")

        if result.evidence:
            st.markdown("**Vulnerability Evidence / Signals:**")
            for ev in result.evidence:
                st.info(f"📌 {ev}")
