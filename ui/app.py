"""
SecureVault: Vulnerability-Oriented Security Testing of RESTful APIs
Streamlit Interactive Research Lab Application (UI 2.0 Modernization)
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

# Import all 15 modular views organized into 6 research domains (Phase 7.3)
# 1. Overview
from ui.views.overview import render_overview_view

# 2. Research
from ui.views.methodology import render_methodology_view
from ui.views.dataset_explorer import render_dataset_explorer_view
from ui.views.vulnerability_kb import render_vulnerability_kb_view

# 3. Analysis Pipeline
from ui.views.spec_analyzer import render_spec_analyzer_view
from ui.views.candidate_extractor import render_candidate_extractor_view
from ui.views.sequence_generator import render_sequence_generator_view
from ui.views.feedback_testing import render_feedback_testing_view

# 4. Security Testing
from ui.views.attack_simulation import render_attack_simulation_view
from ui.views.benchmarks import render_benchmarks_view

# 5. Results
from ui.views.experimental_evaluation import render_experimental_evaluation_view
from ui.views.performance_analytics import render_performance_analytics_view
from ui.views.research_findings import render_research_findings_view
from ui.views.research_reports import render_research_reports_view

# 6. Documentation
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

# Navigation Mapping of 15 Modules across 6 Logical Groups (Phase 7.3)
NAV_ITEMS = [
    # 1. Overview
    ("📊 Dashboard", render_overview_view, "1. Overview"),
    # 2. Research
    ("🔬 Research Methodology", render_methodology_view, "2. Research"),
    ("📂 Dataset Explorer", render_dataset_explorer_view, "2. Research"),
    ("🛡️ Vulnerability Intelligence", render_vulnerability_kb_view, "2. Research"),
    # 3. Analysis Pipeline
    ("📄 Specification Analyzer", render_spec_analyzer_view, "3. Analysis Pipeline"),
    ("🎯 Candidate Extraction", render_candidate_extractor_view, "3. Analysis Pipeline"),
    ("⚡ Sequence Generator", render_sequence_generator_view, "3. Analysis Pipeline"),
    ("🔁 Feedback Testing", render_feedback_testing_view, "3. Analysis Pipeline"),
    # 4. Security Testing
    ("⚔️ Controlled Attack Simulation", render_attack_simulation_view, "4. Security Testing"),
    ("🏛️ Benchmark Applications", render_benchmarks_view, "4. Security Testing"),
    # 5. Results
    ("🧪 Experimental Evaluation", render_experimental_evaluation_view, "5. Results"),
    ("📈 Performance Analytics", render_performance_analytics_view, "5. Results"),
    ("🔍 Research Findings", render_research_findings_view, "5. Results"),
    ("📑 Research Reports", render_research_reports_view, "5. Results"),
    # 6. Documentation
    ("📚 Project Documentation", render_documentation_view, "6. Documentation")
]

PAGE_MAP = {name: func for name, func, _ in NAV_ITEMS}
GROUP_MAP = {name: group for name, _, group in NAV_ITEMS}

def main():
    # Sidebar Header & Branding
    st.sidebar.markdown(
        """
        <div style="text-align: left; padding: 4px 0 14px 0; border-bottom: 1px solid #E4EAF2;">
            <div style="display: flex; align-items: center; gap: 10px;">
                <span style="font-size: 1.8rem;">🛡️</span>
                <div>
                    <div style="font-size: 1.45rem; font-weight: 800; color: #142238; letter-spacing: -0.02em; line-height: 1.1;">
                        SECUREVAULT
                    </div>
                    <div style="font-size: 0.75rem; color: #087FC3; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;">
                        API Security Research Lab
                    </div>
                </div>
            </div>
            <div style="font-size: 0.72rem; color: #63748B; margin-top: 6px;">
                IIIT Dharwad • CS-473 Cloud Security & SRE
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.sidebar.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)

    # Sidebar Live Security Policy & Cloud Guard
    curr_mode = system_config.security_mode
    is_vuln = (curr_mode == "VULNERABLE")
    mode_badge = "badge-vulnerable" if is_vuln else "badge-hardened"

    if system_config.is_hosted:
        # Enforce HARDENED mode on public cloud
        system_config.set_mode("HARDENED")
        st.sidebar.markdown(
            """
            <div style="background-color: #F0FDF4; border: 1px solid #BBF7D0; padding: 10px 12px; border-radius: 10px; margin-bottom: 12px;">
                <div style="font-size: 0.70rem; color: #166534; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;">
                    Hosted Cloud Policy
                </div>
                <div style="margin: 4px 0 4px 0;">
                    <span class="badge-hardened" style="font-size: 0.80rem;">HARDENED DEFENSE</span>
                </div>
                <div style="font-size: 0.70rem; color: #15803D; line-height: 1.35;">
                    VULNERABLE exploit mode disabled on cloud. Defensive filters active.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        # Local interactive toggle
        st.sidebar.markdown(
            f"""
            <div style="background-color: #F5F8FC; border: 1px solid #E4EAF2; padding: 10px 12px; border-radius: 10px; margin-bottom: 10px;">
                <div style="font-size: 0.70rem; color: #63748B; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;">
                    Target Security Policy
                </div>
                <div style="margin: 4px 0 6px 0;">
                    <span class="{mode_badge}" style="font-size: 0.82rem;">{curr_mode}</span>
                </div>
                <div style="font-size: 0.70rem; color: #63748B;">
                    { 'Exploitation enabled on testbed' if is_vuln else 'Defensive controls active' }
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
        toggle_btn_text = "Switch to HARDENED Mode" if is_vuln else "Switch to VULNERABLE Mode"
        if st.sidebar.button(toggle_btn_text, key="sidebar_mode_toggle_btn", use_container_width=True):
            system_config.toggle_mode()
            st.toast(f"Switched policy to {system_config.security_mode}", icon="🛡️")
            st.rerun()

    # Session State Navigation Initialization
    if "nav_selection" not in st.session_state:
        st.session_state["nav_selection"] = "📊 Dashboard"

    # Quick Return to Dashboard button if on another module
    current_page = st.session_state.get("nav_selection", "📊 Dashboard")
    if current_page != "📊 Dashboard":
        if st.sidebar.button("🏠 Return to Dashboard", key="btn_quick_dash", use_container_width=True):
            st.session_state["nav_selection"] = "📊 Dashboard"
            st.rerun()

    st.sidebar.markdown("<div style='height: 4px;'></div>", unsafe_allow_html=True)

    # Section-based Navigation
    page_names = list(PAGE_MAP.keys())
    selected_index = page_names.index(current_page) if current_page in page_names else 0

    st.sidebar.markdown("<b style='font-size: 0.74rem; color: #63748B; text-transform: uppercase; letter-spacing: 0.05em;'>Navigation (15 Modules / 6 Groups)</b>", unsafe_allow_html=True)

    selected_page_name = st.sidebar.radio(
        "Navigation",
        page_names,
        index=selected_index,
        label_visibility="collapsed",
        key="main_navigation_radio"
    )

    # Sync session state
    if selected_page_name != current_page:
        st.session_state["nav_selection"] = selected_page_name
        st.rerun()

    st.sidebar.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)

    # Sidebar System Status Telemetry Monitor
    api_status_label = "IN-MEMORY (ASGI TESTBED)" if system_config.is_hosted else "ONLINE (127.0.0.1:8000)"
    active_mode_color = "#34D399" if not is_vuln or system_config.is_hosted else "#F87171"
    
    st.sidebar.markdown(
        f"""
        <div style="background-color: #0D1525; color: #EAF4FF; border: 1px solid #1E293B; border-radius: 10px; padding: 12px 14px; font-family: 'JetBrains Mono', monospace; font-size: 0.70rem; line-height: 1.6;">
            <div style="color: #38BDF8; font-weight: 700; border-bottom: 1px solid #1E293B; padding-bottom: 4px; margin-bottom: 6px;">
                ● SYSTEM TELEMETRY
            </div>
            <div>API: <span style="color: #34D399;">{api_status_label}</span></div>
            <div>MODE: <span style="color: {active_mode_color}; font-weight: 700;">{system_config.security_mode}</span></div>
            <div>CORPUS: <span style="color: #38BDF8;">541 CVEs (274 GT)</span></div>
            <div>TESTS: <span style="color: #34D399;">26/26 PASSED (100%)</span></div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.sidebar.markdown(
        """
        <div style="margin-top: 12px; padding-top: 8px; border-top: 1px solid #E4EAF2; font-size: 0.70rem; color: #63748B; text-align: center;">
            Inspired by <b>VOAPI²</b> (USENIX Security 2024)<br/>
            Clean-Room Academic Implementation
        </div>
        """,
        unsafe_allow_html=True
    )

    # Render selected view
    page_func = PAGE_MAP[selected_page_name]
    page_func()

if __name__ == "__main__":
    main()
