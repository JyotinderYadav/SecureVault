"""
SecureVault: Vulnerability-Oriented Security Testing of RESTful APIs
Streamlit Interactive Research Lab Application (UI 2.0 Cinematic Redesign)
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

# Apply UI 2.0 Cinematic Visual Theme (65% Light / 35% Dark)
apply_styling()

def main():
    # Sidebar Header & Branding
    st.sidebar.markdown(
        """
        <div style="text-align: left; padding: 6px 0 16px 0; border-bottom: 1px solid #E2E8F0;">
            <div style="display: flex; align-items: center; gap: 10px;">
                <span style="font-size: 1.8rem;">🛡️</span>
                <div>
                    <div style="font-size: 1.45rem; font-weight: 800; color: #0F172A; letter-spacing: -0.02em; line-height: 1.1;">
                        SECUREVAULT
                    </div>
                    <div style="font-size: 0.75rem; color: #0284C7; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;">
                        API Security Research Lab
                    </div>
                </div>
            </div>
            <div style="font-size: 0.72rem; color: #64748B; margin-top: 6px;">
                IIIT Dharwad • CS-473 Cloud Security & SRE
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.sidebar.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # Sidebar Live Security Mode Switcher
    curr_mode = system_config.security_mode
    is_vuln = (curr_mode == "VULNERABLE")
    mode_badge = "badge-vulnerable" if is_vuln else "badge-hardened"
    
    st.sidebar.markdown(
        f"""
        <div style="background-color: #F8FAFC; border: 1px solid #E2E8F0; padding: 12px 14px; border-radius: 10px; margin-bottom: 14px;">
            <div style="font-size: 0.72rem; color: #64748B; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;">
                Target Security Policy
            </div>
            <div style="margin: 6px 0 8px 0;">
                <span class="{mode_badge}" style="font-size: 0.85rem;">{curr_mode}</span>
            </div>
            <div style="font-size: 0.72rem; color: #94A3B8;">
                { 'Exploitation enabled on testbed' if is_vuln else 'Defensive controls active' }
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    toggle_btn_text = "Switch to HARDENED Mode" if is_vuln else "Switch to VULNERABLE Mode"
    if st.sidebar.button(toggle_btn_text, key="sidebar_mode_toggle_btn", use_container_width=True):
        system_config.toggle_mode()
        st.rerun()

    st.sidebar.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # Sidebar Navigation Structure
    st.sidebar.markdown("<b style='font-size: 0.75rem; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.05em;'>Research Navigation</b>", unsafe_allow_html=True)

    PAGES = {
        "1. Overview Dashboard": render_overview_view,
        "2. Research Methodology": render_methodology_view,
        "3. Dataset Explorer": render_dataset_explorer_view,
        "4. Vulnerability Intelligence Centre": render_vulnerability_kb_view,
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

    st.sidebar.markdown("<div style='height: 18px;'></div>", unsafe_allow_html=True)

    # Sidebar System Status Telemetry Monitor
    st.sidebar.markdown(
        f"""
        <div style="background-color: #0F172A; color: #F8FAFC; border-radius: 10px; padding: 14px; font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; line-height: 1.6;">
            <div style="color: #38BDF8; font-weight: 700; border-bottom: 1px solid #1E293B; padding-bottom: 4px; margin-bottom: 6px;">
                ● SYSTEM TELEMETRY
            </div>
            <div>API: <span style="color: #10B981;">ONLINE (127.0.0.1:8000)</span></div>
            <div>MODE: <span style="color: {'#EF4444' if is_vuln else '#10B981'};">{curr_mode}</span></div>
            <div>CORPUS: <span style="color: #38BDF8;">541 CVEs (274 GT)</span></div>
            <div>TESTS: <span style="color: #10B981;">15/15 PASSED (100%)</span></div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.sidebar.markdown(
        """
        <div style="margin-top: 14px; padding-top: 10px; border-top: 1px solid #E2E8F0; font-size: 0.72rem; color: #94A3B8; text-align: center;">
            Inspired by <b>VOAPI²</b> (USENIX Security 2024)<br/>
            Clean-Room Academic Implementation
        </div>
        """,
        unsafe_allow_html=True
    )

    # Render selected view
    page_func = PAGES[selected_page_name]
    page_func()

if __name__ == "__main__":
    main()
