"""
SecureVault: Vulnerability-Oriented Security Testing of RESTful APIs
Streamlit Interactive Research Lab Application
Academic Research & Implementation Project (CS-473 Cloud Security and SRE | IIIT Dharwad)
Inspired by VOAPI² (Wenlong Du et al., USENIX Security 2024)
"""
import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st
from config.settings import system_config
from ui.components.styling import apply_styling

# Import all 14 modular views
from ui.views.overview import render_overview_view
from ui.views.methodology import render_methodology_view
from ui.views.dataset_explorer import render_dataset_explorer_view
from ui.views.vulnerability_kb import render_vulnerability_kb_view
from ui.views.spec_analyzer import render_spec_analyzer_view
from ui.views.candidate_extractor import render_candidate_extractor_view
from ui.views.sequence_generator import render_sequence_generator_view
from ui.views.attack_simulation import render_attack_simulation_view
from ui.views.feedback_findings import render_feedback_findings_view
from ui.views.benchmarks import render_benchmarks_view
from ui.views.experimental_evaluation import render_experimental_evaluation_view
from ui.views.performance_analytics import render_performance_analytics_view
from ui.views.research_reports import render_research_reports_view
from ui.views.documentation import render_documentation_view

# Streamlit Page Configuration
st.set_page_config(
    page_title="SecureVault — API Security Research Lab",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply Cyber Research Theme
apply_styling()

def main():
    # Sidebar Header & Branding
    st.sidebar.markdown(
        """
        <div style="text-align: center; padding: 12px 0 18px 0; border-bottom: 1px solid #1C2541;">
            <div style="font-size: 1.8rem; font-weight: 800; color: #48CAE4; letter-spacing: -0.5px;">
                🛡️ SECUREVAULT
            </div>
            <div style="font-size: 0.8rem; color: #94A3B8; margin-top: 4px;">
                API Security Research Lab
            </div>
            <div style="font-size: 0.72rem; color: #64748B; margin-top: 2px;">
                CS-473 Cloud Security & SRE • IIIT Dharwad
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.sidebar.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # Sidebar Live Mode Switcher
    curr_mode = system_config.mode.value
    mode_badge = "badge-vulnerable" if curr_mode == "VULNERABLE" else "badge-hardened"
    st.sidebar.markdown(
        f"""
        <div style="background-color: #162035; padding: 10px 14px; border-radius: 6px; border: 1px solid #3A506B; margin-bottom: 12px;">
            <div style="font-size: 0.75rem; color: #94A3B8; text-transform: uppercase;">Active Security Mode</div>
            <div style="margin-top: 4px;"><span class="{mode_badge}" style="font-size: 0.85rem;">{curr_mode}</span></div>
        </div>
        """,
        unsafe_allow_html=True
    )
    if st.sidebar.button("Toggle Mode (" + ("HARDENED" if curr_mode == "VULNERABLE" else "VULNERABLE") + ")", key="side_mode_toggle", use_container_width=True):
        system_config.toggle_mode()
        st.rerun()

    st.sidebar.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)

    # Navigation Menu
    PAGES = {
        "1. Overview Dashboard": render_overview_view,
        "2. Research Methodology": render_methodology_view,
        "3. Dataset Explorer": render_dataset_explorer_view,
        "4. Vulnerability Knowledge Base": render_vulnerability_kb_view,
        "5. Specification Analyzer": render_spec_analyzer_view,
        "6. Candidate Interface Extraction": render_candidate_extractor_view,
        "7. Test Sequence Generator": render_sequence_generator_view,
        "8. Attack Simulation Lab": render_attack_simulation_view,
        "9. Feedback & Findings": render_feedback_findings_view,
        "10. Benchmark Applications": render_benchmarks_view,
        "11. Experimental Evaluation": render_experimental_evaluation_view,
        "12. Performance Analytics": render_performance_analytics_view,
        "13. Research Reports": render_research_reports_view,
        "14. Project Documentation": render_documentation_view
    }

    selected_page_name = st.sidebar.radio(
        "Navigation",
        list(PAGES.keys()),
        label_visibility="collapsed"
    )

    st.sidebar.markdown(
        """
        <div style="margin-top: 24px; padding-top: 14px; border-top: 1px solid #1C2541; font-size: 0.72rem; color: #64748B; text-align: center;">
            Inspired by <b>VOAPI²</b> (USENIX Security 2024)<br/>
            Academic Research Implementation
        </div>
        """,
        unsafe_allow_html=True
    )

    # Render selected view
    page_func = PAGES[selected_page_name]
    page_func()

if __name__ == "__main__":
    main()
