"""
Test Sequence Generator View (UI 2.0 Cinematic Redesign)
Demonstrates Algorithm 1 (Reverse Sequence Construction),
resolving producer-consumer data dependencies and synthesizing executable prerequisite test sequences.
"""
import json
import streamlit as st
import pandas as pd
from config.settings import BASE_DIR
from framework.stage1_spec_analysis.parser import OpenAPISpecParser
from framework.stage2_candidate_extraction.extractor import CandidateInterfaceExtractor
from framework.stage3_sequence_generation.sequencer import TestSequenceGenerator
from ui.components.styling import render_hero, render_kpi_card, render_dark_console

def render_sequence_generator_view():
    render_hero(
        title="Test Sequence Generator",
        subtitle="Reverse Sequence Construction (Algorithm 1) & Producer-Consumer State Dependency Resolution (Stage 3)",
        badge="Stage 3 Engine",
        meta_items=[
            "🔄 Algorithm 1 Implementation",
            "🔗 Producer-Consumer Chains",
            "🛡️ Acyclic Recursion Pruning",
            "📊 5-Tier Parameter Strategies"
        ]
    )

    spec_path = BASE_DIR / "datasets" / "api_specifications" / "raw" / "securevault_openapi.json"
    parser = OpenAPISpecParser(spec_path)
    endpoints = parser.parse()

    extractor = CandidateInterfaceExtractor()
    candidates = extractor.extract(endpoints)

    sequencer = TestSequenceGenerator(endpoints)

    st.subheader("Interactive Reverse Sequence Construction")
    st.markdown("Select any target candidate interface to inspect its automatically synthesized prerequisite sequence:")

    candidate_labels = [f"[{c.cwe_category}] {c.endpoint.method} {c.endpoint.path} (Target: {c.primary_parameter})" for c in candidates]
    selected_idx = st.selectbox("Select Target Candidate Interface:", range(len(candidates)), format_func=lambda i: candidate_labels[i])
    selected_candidate = candidates[selected_idx]

    # Generate sequence
    sequence = sequencer.generate_sequence(selected_candidate)

    # KPI Cards (Light Surface)
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(render_kpi_card("Target Endpoint", selected_candidate.endpoint.path, selected_candidate.endpoint.method, "#0284C7"), unsafe_allow_html=True)
    with c2:
        st.markdown(render_kpi_card("Vulnerability Class", selected_candidate.cwe_category, f"Priority Score: {selected_candidate.score:.1f}", "#0EA5E9"), unsafe_allow_html=True)
    with c3:
        st.markdown(render_kpi_card("Sequence Length", f"{len(sequence.steps)} Steps", "Prerequisite Chain", "#10B981"), unsafe_allow_html=True)
    with c4:
        st.markdown(render_kpi_card("Primary Parameter", selected_candidate.primary_parameter or "(General)", "Injection Vector", "#F59E0B"), unsafe_allow_html=True)

    st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)

    # Sequence Flow Visualizer
    st.markdown("#### Synthesized Execution Sequence Trace (Algorithm 1)")
    
    for step_num, step in enumerate(sequence.steps, start=1):
        is_target = (step.endpoint.method == selected_candidate.endpoint.method and step.endpoint.path == selected_candidate.endpoint.path)
        border_color = "#EF4444" if is_target else "#0284C7"
        role_label = "🔴 TARGET EXPLOITATION STEP" if is_target else f"🔵 PREREQUISITE PRODUCER STEP {step_num}"

        st.markdown(
            f"""
            <div class="light-card" style="border-left: 5px solid {border_color}; margin-bottom: 12px; padding: 16px 20px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-weight: 700; color: {border_color}; font-size: 0.95rem;">{role_label}</span>
                    <span style="font-size: 0.85rem; color: #64748B;">Method: <b>{step.endpoint.method}</b> | Path: <code>{step.endpoint.path}</code></span>
                </div>
                <div style="margin-top: 8px; font-size: 0.85rem; color: #0F172A;">
                    <b>Parameter Strategies:</b> {', '.join([f'<code>{k}</code>: {v}' for k, v in step.parameter_strategies.items()]) if step.parameter_strategies else 'Default / Formatted'}
                </div>
                <div style="margin-top: 4px; font-size: 0.85rem; color: #64748B;">
                    <b>Generated Parameters:</b> <code>{step.parameters}</code>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # 35% Dark Console for Step Details
    st.markdown("#### Step Schema & Payload Inspector (35% Dark Console)")
    step_tabs = st.tabs([f"Step {i+1}: {s.endpoint.method} {s.endpoint.path}" for i, s in enumerate(sequence.steps)])
    for i, tab in enumerate(step_tabs):
        step = sequence.steps[i]
        with tab:
            step_dict = {
                "step_index": i + 1,
                "method": step.endpoint.method,
                "path": step.endpoint.path,
                "parameters": step.parameters,
                "request_body": step.request_body,
                "strategies": step.parameter_strategies,
                "producers_linked": step.producers
            }
            json_str = json.dumps(step_dict, indent=2)
            st.markdown(render_dark_console(f"Step {i+1} Definition", f"<pre style='color: #38BDF8; margin: 0;'>{json_str}</pre>", "IN-MEMORY STATE"), unsafe_allow_html=True)
