"""
SecureVault 4-Stage Methodology Pipeline Visualizer Component
Renders an interactive visual walkthrough of the VOAPI² 4-stage testing pipeline.
"""
import streamlit as st


def render_pipeline_visualizer(active_stage: int = 1):
    """
    Renders an interactive 4-stage pipeline visualizer with highlight indicators
    and architectural details.
    """
    stages = [
        {
            "num": 1,
            "name": "Specification Analysis",
            "class_name": "OpenAPISpecParser",
            "color": "#087FC3",
            "summary": "Parses OpenAPI 2.0/3.0/3.1 specs, resolves circular $refs, and normalizes parameters & request bodies.",
            "metrics": "422 Operations • 4 Specs"
        },
        {
            "num": 2,
            "name": "Candidate Extraction",
            "class_name": "CandidateInterfaceExtractor",
            "color": "#0EA5E9",
            "summary": "Scans 72 path & 56 parameter keywords across 6 CWE classes. Prioritizes primary target parameters.",
            "metrics": "13 Testbed Candidates • 6 CWEs"
        },
        {
            "num": 3,
            "name": "Sequence Generation",
            "class_name": "TestSequenceGenerator",
            "color": "#0284C7",
            "summary": "Executes Algorithm 1 (Reverse Sequence Construction) to satisfy producer-consumer prerequisites.",
            "metrics": "Algorithm 1 • 5 Strategies"
        },
        {
            "num": 4,
            "name": "Feedback Testing",
            "class_name": "FeedbackTestRunner",
            "color": "#10B981",
            "summary": "Transmits safe category-tailored probes, triggers stateful sinks, and evaluates multi-signal oracles.",
            "metrics": "100% Precision • 0% FP"
        }
    ]

    cols = st.columns(4)
    for idx, (col, stage) in enumerate(zip(cols, stages), start=1):
        is_current = (idx == active_stage)
        border_top = f"4px solid {stage['color']}"
        bg_card = "#FFFFFF"
        shadow = "0 8px 18px rgba(8, 127, 195, 0.12)" if is_current else "0 2px 6px rgba(20, 34, 56, 0.04)"
        active_pill = f"""<span style="background: {stage['color']}; color: #FFFFFF; font-size: 0.68rem; font-weight: 700; padding: 2px 8px; border-radius: 9999px; margin-left: 6px;">CURRENT</span>""" if is_current else ""

        with col:
            st.markdown(
                f"""
                <div class="light-card" style="border-top: {border_top}; box-shadow: {shadow}; padding: 18px 16px; height: 100%;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                        <span style="font-size: 0.75rem; font-weight: 700; color: {stage['color']}; text-transform: uppercase; letter-spacing: 0.05em;">
                            STAGE {stage['num']} {active_pill}
                        </span>
                    </div>
                    <div style="font-size: 1.02rem; font-weight: 800; color: #142238; line-height: 1.25; margin-bottom: 4px;">
                        {stage['name']}
                    </div>
                    <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #087FC3; margin-bottom: 8px;">
                        {stage['class_name']}
                    </div>
                    <div style="font-size: 0.82rem; color: #63748B; line-height: 1.45; margin-bottom: 12px;">
                        {stage['summary']}
                    </div>
                    <div style="font-size: 0.75rem; font-weight: 600; color: #087FC3; border-top: 1px dashed #E4EAF2; padding-top: 8px;">
                        ⚡ {stage['metrics']}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

