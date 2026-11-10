"""
Feedback-Based Testing View (Stage 4 Execution Engine)
Interactive end-to-end execution of Stage 4 of the VOAPI² pipeline:
Takes candidate interfaces from Stage 2 and synthesized reverse sequences from Stage 3,
executes prerequisite steps against the target testbed, injects targeted payloads,
evaluates multi-signal oracle reasoning, and delivers automated vulnerability verdicts.
"""
import time
import json
import streamlit as st
import pandas as pd
from fastapi.testclient import TestClient

from app.main import app
from config.settings import system_config, BASE_DIR
from framework.stage1_spec_analysis.parser import OpenAPISpecParser
from framework.stage2_candidate_extraction.extractor import CandidateInterfaceExtractor
from framework.stage3_sequence_generation.sequencer import TestSequenceGenerator
from framework.stage4_feedback_testing.runner import FeedbackTestRunner
from ui.components.styling import render_hero, render_kpi_card, render_dark_console
from ui.components.pipeline_visualizer import render_pipeline_visualizer

def render_feedback_testing_view():
    render_hero(
        title="Feedback-Based Testing Engine",
        subtitle="End-to-End Stage 4 Execution: Sequence Replay, Tailored Payload Injection & Multi-Signal Oracle Evaluation",
        badge="Stage 4 Pipeline Engine",
        meta_items=[
            "🔄 End-to-End Pipeline Interactivity",
            "⚡ Prerequisite Sequence Execution",
            "🎯 Table 2 Tailored Injection",
            "🔍 Multi-Signal Oracle Analysis"
        ]
    )

    # 1. Pipeline Position Indicator
    render_pipeline_visualizer(active_stage=4)
    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

    # 2. Target Security Mode Status & Toggle
    curr_mode = system_config.security_mode
    is_vuln = (curr_mode == "VULNERABLE")
    mode_badge_class = "badge-vulnerable" if is_vuln else "badge-hardened"
    
    col_mode_card, col_mode_action = st.columns([3.2, 1.2])
    with col_mode_card:
        st.markdown(
            f"""
            <div style="background-color: #FFFFFF; border: 1px solid #E2E8F0; padding: 12px 18px; border-radius: 12px; display: flex; align-items: center; justify-content: space-between; box-shadow: 0 2px 6px rgba(15, 23, 42, 0.04);">
                <div>
                    <span style="font-size: 0.85rem; color: #64748B; font-weight: 600;">ACTIVE TARGET ENVIRONMENT:</span>
                    <span class="{mode_badge_class}" style="margin-left: 10px;">{curr_mode}</span>
                </div>
                <div style="font-size: 0.85rem; color: #64748B;">
                    { 'Vulnerabilities are live on endpoints' if is_vuln else 'Defensive filters & parameterization active' }
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with col_mode_action:
        toggle_label = "Switch to HARDENED Mode" if is_vuln else "Switch to VULNERABLE Mode"
        if st.button(toggle_label, key="feedback_test_mode_toggle", use_container_width=True):
            system_config.toggle_mode()
            st.toast(f"Security mode updated to {system_config.security_mode}", icon="🛡️")
            st.rerun()

    st.markdown("<div style='height: 18px;'></div>", unsafe_allow_html=True)

    # 3. Load Specification & Stages 1-3 Context
    spec_path = BASE_DIR / "datasets" / "api_specifications" / "raw" / "securevault_openapi.json"
    parser = OpenAPISpecParser(spec_path)
    endpoints = parser.parse()

    extractor = CandidateInterfaceExtractor()
    candidates = extractor.extract(endpoints)

    sequencer = TestSequenceGenerator(endpoints)
    client = TestClient(app)
    runner = FeedbackTestRunner(client=client)

    st.subheader("Interactive Stage 4 Test Sequence Execution")
    st.markdown("Select an extracted candidate interface from the live specification, review its prerequisite sequence and payload, and execute the feedback loop:")

    candidate_labels = [
        f"[{c.cwe_category}] {c.endpoint.method} {c.endpoint.path} (Target: {c.primary_parameter or 'Path'}) — Priority Score: {c.score:.1f}"
        for c in candidates
    ]
    selected_idx = st.selectbox(
        "Select Target Candidate Interface (from Stage 2):",
        range(len(candidates)),
        format_func=lambda i: candidate_labels[i],
        key="stage4_cand_select"
    )
    candidate = candidates[selected_idx]

    # Synthesize reverse sequence (from Stage 3)
    sequence = sequencer.generate_sequence(candidate)
    
    # Payload selection
    cwe_payloads = runner.payload_categories.get(candidate.cwe_category, {})
    default_payloads = cwe_payloads.get("payloads", ["VoAPITestPayload"])
    
    col_payload_select, col_custom = st.columns([1.5, 1])
    with col_payload_select:
        selected_payload = st.selectbox(
            f"Select Tailored Payload for {candidate.cwe_category}:",
            default_payloads,
            key="stage4_payload_select"
        )
    with col_custom:
        custom_payload = st.text_input(
            "Or Input Custom Research Payload:",
            value=selected_payload,
            key="stage4_custom_payload"
        )

    active_payload = custom_payload.strip() if custom_payload.strip() else selected_payload

    # Execution Controls
    col_exec_btn, col_exec_info = st.columns([1.2, 3])
    execute_triggered = False
    with col_exec_btn:
        if st.button("🚀 Execute Feedback Test", type="primary", use_container_width=True, key="exec_stage4_test_btn"):
            execute_triggered = True
    with col_exec_info:
        st.caption(f"Sequence has **{len(sequence.steps)} step(s)**: {len(sequence.steps)-1} prerequisite producer step(s) + 1 target exploitation step.")

    # Execute and render results
    if execute_triggered:
        with st.spinner(f"Executing sequence for {candidate.endpoint.method} {candidate.endpoint.path} in {curr_mode} mode..."):
            t_start = time.perf_counter()
            result = runner.run_sequence(sequence, candidate, custom_payload=active_payload)
            elapsed_ms = (time.perf_counter() - t_start) * 1000.0

        st.toast(f"Execution complete: Verdict is {result.verdict.value} ({elapsed_ms:.1f}ms)", icon="🎯")

        # KPI Metrics of the execution
        st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            verdict_val = result.verdict.value
            verdict_color = "#EF4444" if verdict_val == "CONFIRMED_VULNERABILITY" else "#10B981"
            st.markdown(render_kpi_card("Oracle Verdict", verdict_val, "Multi-Signal Evaluation", verdict_color), unsafe_allow_html=True)
        with m2:
            st.markdown(render_kpi_card("HTTP Status", str(result.status_code), "Response Code", "#0284C7"), unsafe_allow_html=True)
        with m3:
            st.markdown(render_kpi_card("Execution Latency", f"{result.latency_ms:.2f} ms", "Roundtrip Time", "#F59E0B"), unsafe_allow_html=True)
        with m4:
            st.markdown(render_kpi_card("Target Mode", curr_mode, "Active Environment", "#0EA5E9"), unsafe_allow_html=True)

        st.markdown("<div style='height: 18px;'></div>", unsafe_allow_html=True)

        # Execution Results Breakdown
        res_col_left, res_col_right = st.columns([1.3, 1.2])
        with res_col_left:
            st.markdown("#### Oracle Verdict & Findings Analysis")
            st.markdown(
                f"""
                <div class="light-card" style="border-left: 5px solid {verdict_color};">
                    <b style="font-size: 1.05rem; color: {verdict_color};">Analysis & Forensic Conclusion:</b>
                    <p style="margin-top: 8px; font-size: 0.9rem; color: #1E293B;">
                        {result.analysis}
                    </p>
                </div>
                """,
                unsafe_allow_html=True
            )

            st.markdown("<b>Multi-Signal Detection Evidence:</b>", unsafe_allow_html=True)
            if result.evidence:
                for ev in result.evidence:
                    st.info(f"🔍 {ev}")
            else:
                st.success("✅ No vulnerability signatures detected in server response (Mitigation Verified).")

        with res_col_right:
            st.markdown("#### Live HTTP Response Inspector (35% Dark Console)")
            resp_body = result.response_body
            if isinstance(resp_body, dict):
                body_str = json.dumps(resp_body, indent=2)
            else:
                body_str = str(resp_body)
            st.markdown(
                render_dark_console(
                    f"HTTP {result.status_code} Response Body",
                    f"<pre style='color: #38BDF8; margin: 0; max-height: 280px; overflow-y: auto;'>{body_str[:1200]}</pre>",
                    status_tag=f"STATUS {result.status_code}"
                ),
                unsafe_allow_html=True
            )

        # Sequence Steps Execution Trace
        st.markdown("#### Sequence Execution Trace & State Propagation")
        for i, step in enumerate(sequence.steps, start=1):
            is_target_step = (i == len(sequence.steps))
            step_badge = "🔴 Target Injection Step" if is_target_step else f"🔵 Prerequisite Step {i}"
            border_c = "#EF4444" if is_target_step else "#0284C7"
            st.markdown(
                f"""
                <div class="light-card" style="border-left: 4px solid {border_c}; padding: 12px 18px; margin-bottom: 8px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="font-weight: 700; color: {border_c};">{step_badge}: <code>{step.endpoint.method} {step.endpoint.path}</code></span>
                        <span style="font-size: 0.8rem; color: #64748B;">Producer: {step.producers or 'None'}</span>
                    </div>
                    <div style="font-size: 0.82rem; color: #64748B; margin-top: 4px;">
                        <b>Applied Strategies:</b> {step.parameter_strategies or 'Default schema values'}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
    else:
        st.info("👆 Click **Execute Feedback Test** to run the complete 4-stage feedback sequence against the target endpoint.")

