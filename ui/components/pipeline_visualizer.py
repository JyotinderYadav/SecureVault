"""
SecureVault 4-Stage Methodology Pipeline Visualizer Component
Renders an intuitive, high-fidelity visual walkthrough of the VOAPI² 4-stage testing pipeline:
Stage 1: Specification Analysis -> Stage 2: Candidate Extraction ->
Stage 3: Sequence Generation -> Stage 4: Feedback-Based Testing.
"""
import streamlit as st
from typing import Optional, Dict, Any

def render_pipeline_visualizer(active_stage: int = 1, stage_statuses: Optional[Dict[int, str]] = None):
    """
    Renders an interactive 4-stage pipeline visualizer with status indicators,
    input/output artifact contracts, durations, and architectural flow.
    """
    default_statuses = {
        1: "Completed",
        2: "Completed",
        3: "Completed",
        4: "Completed"
    }
    statuses = stage_statuses or default_statuses

    status_badges = {
        "Completed": ("#10B981", "#ECFDF5", "#A7F3D0", "✓ Completed"),
        "Running": ("#087FC3", "#F0F7FF", "#BAE6FD", "⚡ Running"),
        "Not Started": ("#63748B", "#F8FAFC", "#E2E8F0", "○ Pending"),
        "Failed": ("#EF4444", "#FEF2F2", "#FECACA", "✕ Failed")
    }

    stages = [
        {
            "num": 1,
            "name": "Specification Analysis",
            "class_name": "OpenAPISpecParser",
            "color": "#087FC3",
            "input": "OpenAPI 2.0 / 3.0 / 3.1 Spec",
            "output": "Normalized Endpoint Models",
            "duration": "0.33 ms",
            "summary": "Parses specs, recursively resolves circular $refs, extracts schema types & parameters.",
            "metrics": "422 Ops Analyzed"
        },
        {
            "num": 2,
            "name": "Candidate Extraction",
            "class_name": "CandidateInterfaceExtractor",
            "color": "#0EA5E9",
            "input": "Endpoint Models + CWE Heuristics",
            "output": "Prioritized Candidate Interfaces",
            "duration": "1.78 ms",
            "summary": "Matches 72 path & 56 parameter keywords across 6 CWEs using Table 2 heuristics.",
            "metrics": "13 Testbed Candidates"
        },
        {
            "num": 3,
            "name": "Sequence Generation",
            "class_name": "TestSequenceGenerator",
            "color": "#0284C7",
            "input": "Candidate Interface + Spec Graph",
            "output": "Stateful Sequence (Algorithm 1)",
            "duration": "2.45 ms",
            "summary": "Synthesizes prerequisite setup calls (POST /items -> PUT /sync) using 5 schema strategies.",
            "metrics": "Reverse Graph Traversal"
        },
        {
            "num": 4,
            "name": "Feedback Testing",
            "class_name": "FeedbackTestRunner",
            "color": "#10B981",
            "input": "Sequence + Tailored Probes",
            "output": "Multi-Signal Oracle Verdict",
            "duration": "133.4 ms",
            "summary": "Executes sequence against testbed, transmits safe probes, and evaluates oracles.",
            "metrics": "100% Precision • 0% FP"
        }
    ]

    cols = st.columns(4)
    for idx, (col, stage) in enumerate(zip(cols, stages), start=1):
        is_current = (idx == active_stage)
        status_name = statuses.get(idx, "Completed")
        status_color, status_bg, status_border, status_text = status_badges.get(
            status_name, status_badges["Completed"]
        )

        border_top = f"4px solid {stage['color']}"
        active_glow = f"box-shadow: 0 8px 20px rgba(8, 127, 195, 0.16); border-color: #087FC3;" if is_current else ""
        flow_arrow = " ➔" if idx < 4 else ""

        with col:
            st.markdown(
                f"""
                <div class="light-card" style="border-top: {border_top}; padding: 18px 16px; height: 100%; {active_glow}">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <span style="font-size: 0.72rem; font-weight: 800; color: {stage['color']}; text-transform: uppercase; letter-spacing: 0.05em;">
                            STAGE {stage['num']}{flow_arrow}
                        </span>
                        <span style="background-color: {status_bg}; color: {status_color}; border: 1px solid {status_border}; font-size: 0.68rem; font-weight: 700; padding: 2px 7px; border-radius: 9999px;">
                            {status_text}
                        </span>
                    </div>
                    <div style="font-size: 1.02rem; font-weight: 800; color: #142238; line-height: 1.25; margin-bottom: 3px;">
                        {stage['name']}
                    </div>
                    <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.70rem; color: #087FC3; margin-bottom: 8px;">
                        {stage['class_name']}
                    </div>
                    <div style="font-size: 0.80rem; color: #63748B; line-height: 1.4; margin-bottom: 12px; min-height: 48px;">
                        {stage['summary']}
                    </div>
                    <div style="background-color: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 6px; padding: 6px 8px; margin-bottom: 8px; font-size: 0.72rem; line-height: 1.5;">
                        <div><b style="color: #475569;">IN:</b> <span style="color: #087FC3; font-family: 'JetBrains Mono', monospace;">{stage['input']}</span></div>
                        <div><b style="color: #475569;">OUT:</b> <span style="color: #059669; font-family: 'JetBrains Mono', monospace;">{stage['output']}</span></div>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px dashed #E4EAF2; padding-top: 8px; font-size: 0.72rem;">
                        <span style="color: #64748B;">⚡ {stage['metrics']}</span>
                        <span style="color: #087FC3; font-family: 'JetBrains Mono', monospace; font-weight: 600;">{stage['duration']}</span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
