"""
Attack Simulation Lab View (UI 2.0 Cinematic Redesign)
Provides an interactive, real-time security testing environment against the SecureVault API testbed.
Executes real HTTP test sequences, injects benign research probes into target parameters,
displays raw outgoing/incoming HTTP traffic, and visualizes multi-signal oracle reasoning.
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
from ui.components.styling import render_hero, render_kpi_card, render_dark_console

TARGET_CWES = [
    ("CWE-918", "Server-Side Request Forgery", "/api/v1/vault/sync"),
    ("CWE-434", "Unrestricted File Upload", "/api/v1/vault/upload"),
    ("CWE-22", "Path Traversal", "/api/v1/vault/files/read"),
    ("CWE-78", "OS Command Injection", "/api/v1/vault/tools/ping-backup"),
    ("CWE-89", "SQL Injection", "/api/v1/vault/records/search"),
    ("CWE-79", "Stored Cross-Site Scripting", "/api/v1/vault/audit/logs")
]

def render_attack_simulation_view():
    render_hero(
        title="Live Attack Simulation Lab",
        subtitle="Real-Time Controlled Vulnerability Testing, Safe Probe Injection & Multi-Signal Oracle Analysis (Stage 4)",
        badge="Live Lab Console",
        meta_items=[
            "🎯 6 Targeted Vulnerability Classes",
            "🛡️ Dual-Mode Live Testbed",
            "🧪 Safe Benign Probes",
            "🔍 Multi-Signal Oracles"
        ]
    )

    curr_mode = system_config.security_mode
    is_vuln = (curr_mode == "VULNERABLE")
    mode_badge_class = "badge-vulnerable" if is_vuln else "badge-hardened"
    
    # Mode switch card / Cloud Guard
    if system_config.is_hosted:
        st.markdown(
            """
            <div style="background-color: #FFFFFF; border: 1px solid #BBF7D0; border-left: 4px solid #10B981; padding: 12px 18px; border-radius: 12px; display: flex; align-items: center; justify-content: space-between; box-shadow: 0 2px 6px rgba(15, 23, 42, 0.04);">
                <div>
                    <span style="font-size: 0.82rem; color: #166534; font-weight: 700;">CLOUD HOSTING POLICY:</span>
                    <span class="badge-hardened" style="margin-left: 10px;">HARDENED DEFENSE ENFORCED</span>
                </div>
                <div style="font-size: 0.82rem; color: #475569;">
                    Probes verify defensive controls. Intentionally vulnerable exploit mode is isolated to local testbeds.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        col_mode_info, col_toggle = st.columns([3.2, 1.2])
        with col_mode_info:
            st.markdown(
                f"""
                <div style="background-color: #FFFFFF; border: 1px solid #E2E8F0; padding: 12px 18px; border-radius: 12px; display: flex; align-items: center; justify-content: space-between; box-shadow: 0 2px 6px rgba(15, 23, 42, 0.04);">
                    <div>
                        <span style="font-size: 0.85rem; color: #64748B; font-weight: 600;">ACTIVE TARGET SECURITY MODE:</span>
                        <span class="{mode_badge_class}" style="margin-left: 10px;">{curr_mode}</span>
                    </div>
                    <div style="font-size: 0.85rem; color: #64748B;">
                        { 'Vulnerabilities are live & exploitable' if is_vuln else 'Defensive filters & parameterization active' }
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
        with col_toggle:
            toggle_label = "Switch to HARDENED Mode" if is_vuln else "Switch to VULNERABLE Mode"
            if st.button(toggle_label, key="lab_mode_toggle", use_container_width=True):
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
        selected_payload = st.selectbox("Select Approved Benign Research Probe:", default_payloads)

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
    launch_btn = st.button("🚀 Launch Controlled Vulnerability Test Sequence", use_container_width=True)

    if launch_btn:
        st.markdown("---")
        st.subheader("Live Real-Time Execution Trace")
        
        sequence = sequencer.generate_sequence(cand)
        
        # Real execution progress bar
        progress_bar = st.progress(0, text="Initializing state sequence...")
        time.sleep(0.05)
        progress_bar.progress(35, text="Executing prerequisite sequence steps (Algorithm 1)...")
        time.sleep(0.05)
        progress_bar.progress(70, text=f"Transmitting benign payload to target parameter: {cand.primary_parameter}...")
        
        t0 = time.perf_counter()
        result = runner.run_sequence(sequence, cand, custom_payload=selected_payload)
        elapsed = (time.perf_counter() - t0) * 1000
        
        progress_bar.progress(100, text="Oracle evaluation complete!")
        time.sleep(0.05)
        progress_bar.empty()

        # Verdict Banner
        is_confirmed = (result.verdict.value == "CONFIRMED_VULNERABILITY")
        v_color = "#DC2626" if is_confirmed else ("#059669" if result.verdict.value == "NEGATIVE" else "#D97706")
        v_bg = "#FEF2F2" if is_confirmed else ("#ECFDF5" if result.verdict.value == "NEGATIVE" else "#FFFBEB")
        v_border = "#FCA5A5" if is_confirmed else ("#6EE7B7" if result.verdict.value == "NEGATIVE" else "#FDE68A")
        
        st.markdown(
            f"""
            <div style="background-color: {v_bg}; border: 2px solid {v_border}; border-radius: 12px; padding: 20px; margin-bottom: 24px; box-shadow: 0 4px 12px rgba(15, 23, 42, 0.05);">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-size: 1.35rem; font-weight: 800; color: {v_color};">
                        Vulnerability Oracle Verdict: {result.verdict.value}
                    </span>
                    <span style="font-size: 0.9rem; color: #64748B; font-weight: 600;">Total Latency: {elapsed:.2f} ms</span>
                </div>
                <div style="font-size: 0.95rem; color: #0F172A; margin-top: 10px; line-height: 1.5;">
                    <b>Oracle Finding Analysis:</b> {result.analysis}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # Response Details Cards (Light Surface)
        rc1, rc2, rc3, rc4 = st.columns(4)
        with rc1:
            st.markdown(render_kpi_card("HTTP Status", str(result.status_code), "Response Code", "#0284C7"), unsafe_allow_html=True)
        with rc2:
            st.markdown(render_kpi_card("Network Latency", f"{result.latency_ms:.2f} ms", "Roundtrip Time", "#0EA5E9"), unsafe_allow_html=True)
        with rc3:
            st.markdown(render_kpi_card("Evidence Signals", str(len(result.evidence)), "Oracle Triggers", "#EF4444" if is_confirmed else "#10B981"), unsafe_allow_html=True)
        with rc4:
            st.markdown(render_kpi_card("Target Mode", curr_mode, "Active Testbed State", "#EF4444" if is_vuln else "#10B981"), unsafe_allow_html=True)

        st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

        # 35% Dark Consoles: HTTP Outgoing Request & Incoming Response Inspectors
        col_req, col_resp = st.columns(2)
        with col_req:
            req_content = f"""
<div style="color: #38BDF8; font-weight: 600;">{cand.endpoint.method} {cand.endpoint.path} HTTP/1.1</div>
<div style="color: #94A3B8;">Host: 127.0.0.1:8000</div>
<div style="color: #94A3B8;">User-Agent: SecureVault-VOAPI2-TestRunner/2.0</div>
<div style="color: #94A3B8;">Accept: application/json</div>
<div style="color: #94A3B8;">Authorization: Bearer [JWT_SESSION_TOKEN]</div>
<br/>
<div style="color: #F8FAFC;"><b>Target Parameter:</b> <span style="color: #F59E0B;">{cand.primary_parameter}</span></div>
<div style="color: #F8FAFC;"><b>Injected Probe:</b> <span style="color: #34D399;">{selected_payload}</span></div>
"""
            st.markdown(render_dark_console("Outgoing HTTP Request Inspector", req_content, "TRANSMITTED"), unsafe_allow_html=True)

        with col_resp:
            body_str = result.response_body if isinstance(result.response_body, str) else str(result.response_body)
            resp_content = f"""
<div style="color: {'#34D399' if result.status_code == 200 else '#F87171'}; font-weight: 600;">HTTP/1.1 {result.status_code}</div>
<div style="color: #94A3B8;">Content-Type: application/json; charset=utf-8</div>
<div style="color: #94A3B8;">X-SecureVault-Mode: {curr_mode}</div>
<div style="color: #94A3B8;">Response-Time: {result.latency_ms:.2f}ms</div>
<br/>
<div style="color: #E2E8F0; max-height: 180px; overflow-y: auto;">
<b>Response Body:</b><br/>
<code>{body_str[:600]}</code>
</div>
"""
            st.markdown(render_dark_console("Incoming HTTP Response Inspector", resp_content, "RECEIVED"), unsafe_allow_html=True)

        # Oracle Evidence Breakdown
        if result.evidence:
            st.markdown("#### Vulnerability Oracle Signals & Detected Artifacts")
            for ev in result.evidence:
                st.error(f"🚨 **Vulnerability Signal:** {ev}")
        else:
            st.success("🛡️ **Defensive Verification:** No vulnerability signals detected. All security boundaries held firm.")
