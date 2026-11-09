"""
Overview Dashboard View
Displays project architecture, live security mode switcher, key metrics, and VOAPI² 4-stage pipeline summary.
"""
import streamlit as st
from config.settings import system_config
from ui.components.styling import render_header, render_metric_card

def render_overview_view():
    render_header(
        title="SecureVault — Research Lab Overview",
        subtitle="Vulnerability-Oriented Security Testing of RESTful APIs (CS-473 Cloud Security & SRE)",
        badge="USENIX Security 2024 Reproduction"
    )

    # Live Mode Switcher Banner
    current_mode = system_config.mode.value
    mode_color = "#EF4444" if current_mode == "VULNERABLE" else "#10B981"
    badge_class = "badge-vulnerable" if current_mode == "VULNERABLE" else "badge-hardened"

    col_mode, col_switch = st.columns([3, 1])
    with col_mode:
        st.markdown(
            f"""
            <div style="background-color: #1C2541; padding: 16px; border-radius: 8px; border: 1px solid #3A506B; display: flex; align-items: center; justify-content: space-between;">
                <div>
                    <span style="font-size: 1rem; color: #94A3B8; margin-right: 12px;">Active Testbed Security Mode:</span>
                    <span class="{badge_class}" style="font-size: 1.05rem; padding: 4px 14px;">{current_mode}</span>
                </div>
                <div style="font-size: 0.85rem; color: #94A3B8;">
                    { 'Vulnerabilities are live and exploitable' if current_mode == 'VULNERABLE' else 'All inputs validated, prepared statements & defensive controls active' }
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with col_switch:
        new_mode_toggle = st.button(
            "Toggle to " + ("HARDENED" if current_mode == "VULNERABLE" else "VULNERABLE"),
            use_container_width=True
        )
        if new_mode_toggle:
            system_config.toggle_mode()
            st.rerun()

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

    # Core Metric Cards
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(render_metric_card("Target Vulnerabilities", "6 CWEs", "SSRF, Upload, Traversal, CmdI, SQLi, XSS", "#48CAE4"), unsafe_allow_html=True)
    with c2:
        st.markdown(render_metric_card("Corpus CVEs", "541 (274)", "Raw Corpus vs. Ground Truth", "#00B4D8"), unsafe_allow_html=True)
    with c3:
        st.markdown(render_metric_card("Detection Precision", "100%", "6/6 Confirmed Targets", "#10B981"), unsafe_allow_html=True)
    with c4:
        st.markdown(render_metric_card("Request Reduction", "68.8%", "15 vs 48 Baseline Requests", "#F59E0B"), unsafe_allow_html=True)

    st.markdown("<div style='height: 24px;'></div>", unsafe_allow_html=True)

    # Architecture and Pipeline Section
    st.subheader("Architectural Workflow: 4-Stage Vulnerability-Oriented Testing")
    st.markdown(
        """
        SecureVault replicates the methodology formulated in **VOAPI² (Du et al., USENIX Security 2024)**, 
        shifting away from blind fuzzing toward **vulnerability-oriented, context-aware sequence generation**.
        """
    )

    stage_col1, stage_col2, stage_col3, stage_col4 = st.columns(4)
    with stage_col1:
        st.markdown(
            """
            <div style="background-color: #162035; border: 1px solid #3A506B; border-top: 4px solid #48CAE4; border-radius: 8px; padding: 16px; height: 100%;">
                <div style="font-weight: 700; color: #48CAE4; font-size: 1.05rem;">Stage 1</div>
                <div style="font-weight: 600; color: #F8FAFC; margin: 6px 0;">Specification Analysis</div>
                <div style="font-size: 0.85rem; color: #94A3B8;">
                    Parses OpenAPI 2.0/3.0/3.1 specs (JSON/YAML). Resolves <code>$ref</code> schemas, normalizes HTTP methods, query/path parameters, and JSON payloads.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with stage_col2:
        st.markdown(
            """
            <div style="background-color: #162035; border: 1px solid #3A506B; border-top: 4px solid #00B4D8; border-radius: 8px; padding: 16px; height: 100%;">
                <div style="font-weight: 700; color: #00B4D8; font-size: 1.05rem;">Stage 2</div>
                <div style="font-weight: 600; color: #F8FAFC; margin: 6px 0;">Candidate Extraction</div>
                <div style="font-size: 0.85rem; color: #94A3B8;">
                    Scans path & parameter tokens against 72 path & 56 parameter keywords. Tags primary target parameters and calculates vulnerability candidate scores.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with stage_col3:
        st.markdown(
            """
            <div style="background-color: #162035; border: 1px solid #3A506B; border-top: 4px solid #0077B6; border-radius: 8px; padding: 16px; height: 100%;">
                <div style="font-weight: 700; color: #0077B6; font-size: 1.05rem;">Stage 3</div>
                <div style="font-weight: 600; color: #F8FAFC; margin: 6px 0;">Sequence Generation</div>
                <div style="font-weight: 400; font-size: 0.85rem; color: #94A3B8;">
                    Executes Algorithm 1 (Reverse Sequence Construction). Matches producer-consumer dependencies, prepares prerequisite state, and resolves parameters.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with stage_col4:
        st.markdown(
            """
            <div style="background-color: #162035; border: 1px solid #3A506B; border-top: 4px solid #10B981; border-radius: 8px; padding: 16px; height: 100%;">
                <div style="font-weight: 700; color: #10B981; font-size: 1.05rem;">Stage 4</div>
                <div style="font-weight: 600; color: #F8FAFC; margin: 6px 0;">Feedback Testing</div>
                <div style="font-size: 0.85rem; color: #94A3B8;">
                    Executes dependency chains, injects harmless test probes into target parameters, and uses multi-signal oracles to evaluate vulnerability verdicts.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("<div style='height: 24px;'></div>", unsafe_allow_html=True)

    # Benchmark Scope Card
    st.subheader("Evaluated Real-World Benchmark Applications")
    st.markdown(
        """
        Our experimental evaluation tests both our local dual-mode SecureVault testbed and three prominent real-world open-source applications examined in the base paper:
        """
    )
    b1, b2, b3, b4 = st.columns(4)
    with b1:
        st.info("**SecureVault Testbed v1.0.0**\n\n16 endpoints • 13 candidates\n\nFull dual-mode local simulation")
    with b2:
        st.info("**Appwrite v0.9.3**\n\n95 endpoints • 77 candidates\n\nBackend Server Platform")
    with b3:
        st.info("**Request Baskets v1.2.3**\n\n20 endpoints • 16 candidates\n\nHTTP Request Collector")
    with b4:
        st.info("**Gitea v1.16.7**\n\n291 endpoints • 207 candidates\n\nGit Service Platform")
