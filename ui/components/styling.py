"""
SecureVault UI 2.0 Theme & Visual Architecture
Implements a strict 65% Light / 35% Dark cinematic cybersecurity research laboratory theme:
- 65% Light: Canvas (#F5F8FC), pure white elevated cards (#FFFFFF),
  slate borders (#E4EAF2), high-contrast dark typography (#142238, #63748B),
  and electric blue/cyan accents (#087FC3, #14B8D4).
- 35% Dark: Deep obsidian navy (#0D1525, #121E32, #192941) with border (#1E293B)
  selectively applied to security telemetry, attack consoles, HTTP inspectors,
  network visualizers, and code traces.
- Bulletproof 100% Opaque Sidebar: zero transparency, high-contrast typography,
  clear active navigation states, and responsive controls.
"""
import streamlit as st

CINEMATIC_CSS = """
<style>
/* Global Imports & Reset */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

/* Main Canvas (65% Light Theme) */
.stApp {
    background-color: #F5F8FC !important;
    color: #142238 !important;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
}

/* Keyframe Animations */
@keyframes fadeIn {
    from { opacity: 0; transform: translateY(6px); }
    to { opacity: 1; transform: translateY(0); }
}

@keyframes pulseGlow {
    0% { box-shadow: 0 0 0 0 rgba(8, 127, 195, 0.4); }
    70% { box-shadow: 0 0 0 8px rgba(8, 127, 195, 0); }
    100% { box-shadow: 0 0 0 0 rgba(8, 127, 195, 0); }
}

@keyframes scanline {
    0% { transform: translateY(-100%); }
    100% { transform: translateY(1000%); }
}

/* Hero Banner (Hybrid Cinematic Container) */
.vault-hero {
    background: linear-gradient(135deg, #0D1525 0%, #121E32 55%, #087FC3 100%);
    color: #FFFFFF;
    border-radius: 16px;
    padding: 30px 34px;
    margin-bottom: 26px;
    border: 1px solid #1E293B;
    box-shadow: 0 10px 25px -5px rgba(13, 21, 37, 0.25), 0 8px 10px -6px rgba(13, 21, 37, 0.2);
    position: relative;
    overflow: hidden;
    animation: fadeIn 0.35s ease-out;
}

.vault-hero::after {
    content: '';
    position: absolute;
    top: 0;
    right: 0;
    width: 380px;
    height: 100%;
    background: radial-gradient(circle, rgba(34, 211, 238, 0.15) 0%, rgba(13, 21, 37, 0) 70%);
    pointer-events: none;
}

.vault-hero-title {
    font-size: 2.25rem;
    font-weight: 800;
    letter-spacing: -0.03em;
    color: #FFFFFF;
    margin: 0;
    line-height: 1.2;
}

.vault-hero-badge {
    background: rgba(34, 211, 238, 0.18);
    color: #22D3EE;
    border: 1px solid rgba(34, 211, 238, 0.4);
    font-size: 0.8rem;
    font-weight: 600;
    padding: 4px 12px;
    border-radius: 9999px;
    display: inline-block;
    vertical-align: middle;
    margin-left: 12px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.vault-hero-subtitle {
    font-size: 1.02rem;
    color: #CBD5E1;
    margin-top: 10px;
    margin-bottom: 0;
    max-width: 880px;
    line-height: 1.5;
}

.vault-hero-meta {
    margin-top: 18px;
    display: flex;
    flex-wrap: wrap;
    gap: 18px;
    font-size: 0.85rem;
    color: #94A3B8;
}

.vault-hero-meta span {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: rgba(255, 255, 255, 0.08);
    padding: 3px 10px;
    border-radius: 6px;
    border: 1px solid rgba(255, 255, 255, 0.1);
}

/* Light Surface Cards (65% Composition) */
.light-card {
    background-color: #FFFFFF;
    border: 1px solid #E4EAF2;
    border-radius: 12px;
    padding: 22px;
    box-shadow: 0 4px 12px -2px rgba(20, 34, 56, 0.05), 0 2px 4px -2px rgba(20, 34, 56, 0.03);
    transition: transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease;
    animation: fadeIn 0.35s ease-out;
    margin-bottom: 20px;
}

.light-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 10px 20px -3px rgba(20, 34, 56, 0.08), 0 4px 6px -4px rgba(20, 34, 56, 0.04);
    border-color: #CBD5E1;
}

/* Metric / KPI Cards */
.kpi-card {
    background-color: #FFFFFF;
    border: 1px solid #E4EAF2;
    border-radius: 12px;
    padding: 20px 18px;
    text-align: center;
    box-shadow: 0 4px 10px rgba(20, 34, 56, 0.04);
    transition: all 0.25s ease;
    height: 100%;
}

.kpi-card:hover {
    transform: translateY(-3px);
    border-color: #087FC3;
    box-shadow: 0 12px 24px -4px rgba(8, 127, 195, 0.12);
}

.kpi-label {
    font-size: 0.8rem;
    font-weight: 600;
    color: #63748B;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 6px;
}

.kpi-value {
    font-size: 2.15rem;
    font-weight: 800;
    color: #087FC3;
    line-height: 1.1;
    margin: 4px 0;
    letter-spacing: -0.02em;
}

.kpi-subtext {
    font-size: 0.82rem;
    color: #059669;
    font-weight: 500;
    margin-top: 4px;
}

/* Dark Command Surfaces (35% Composition) */
.dark-console {
    background-color: #0D1525;
    color: #EAF4FF;
    border: 1px solid #1E293B;
    border-radius: 12px;
    padding: 22px;
    box-shadow: 0 8px 24px -4px rgba(13, 21, 37, 0.4);
    position: relative;
    font-family: 'JetBrains Mono', monospace;
    margin-bottom: 20px;
    animation: fadeIn 0.35s ease-out;
}

.dark-console-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid #1E293B;
    padding-bottom: 12px;
    margin-bottom: 14px;
    font-size: 0.85rem;
    color: #38BDF8;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.dark-console-dots {
    display: flex;
    gap: 6px;
}

.dark-console-dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    display: inline-block;
}

.dot-red { background-color: #EF4444; }
.dot-yellow { background-color: #F59E0B; }
.dot-green { background-color: #10B981; }

/* Status Badges */
.badge-vulnerable {
    background-color: #FEF2F2 !important;
    color: #DC2626 !important;
    border: 1px solid #FCA5A5 !important;
    padding: 4px 12px;
    border-radius: 9999px;
    font-size: 0.82rem;
    font-weight: 700;
    display: inline-flex;
    align-items: center;
    gap: 6px;
}

.badge-hardened {
    background-color: #ECFDF5 !important;
    color: #059669 !important;
    border: 1px solid #6EE7B7 !important;
    padding: 4px 12px;
    border-radius: 9999px;
    font-size: 0.82rem;
    font-weight: 700;
    display: inline-flex;
    align-items: center;
    gap: 6px;
}

.badge-pill {
    background-color: #F0F7FF;
    color: #087FC3;
    border: 1px solid #BAE6FD;
    padding: 3px 10px;
    border-radius: 6px;
    font-size: 0.78rem;
    font-weight: 600;
}

.badge-confirmed {
    background-color: #FEF2F2 !important;
    color: #DC2626 !important;
    border: 1px solid #FCA5A5 !important;
    padding: 3px 10px;
    border-radius: 9999px;
    font-size: 0.78rem;
    font-weight: 700;
    display: inline-flex;
    align-items: center;
    gap: 4px;
}

.badge-negative {
    background-color: #ECFDF5 !important;
    color: #059669 !important;
    border: 1px solid #6EE7B7 !important;
    padding: 3px 10px;
    border-radius: 9999px;
    font-size: 0.78rem;
    font-weight: 700;
    display: inline-flex;
    align-items: center;
    gap: 4px;
}

.badge-potential {
    background-color: #FFFBEB !important;
    color: #D97706 !important;
    border: 1px solid #FDE68A !important;
    padding: 3px 10px;
    border-radius: 9999px;
    font-size: 0.78rem;
    font-weight: 700;
    display: inline-flex;
    align-items: center;
    gap: 4px;
}

.action-card {
    transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
}

.action-card:hover {
    transform: translateY(-3px) !important;
    border-color: #087FC3 !important;
    box-shadow: 0 12px 24px -4px rgba(8, 127, 195, 0.12) !important;
}

/* Callout Box */
.cyber-callout-light {
    background-color: #F0F7FF;
    border-left: 4px solid #087FC3;
    padding: 16px 20px;
    border-radius: 0 8px 8px 0;
    margin: 16px 0;
    color: #142238;
    font-size: 0.95rem;
    box-shadow: 0 2px 6px rgba(8, 127, 195, 0.05);
}

/* BULLETPROOF SIDEBAR CUSTOMIZATION (100% OPAQUE) */
section[data-testid="stSidebar"] {
    background-color: #FFFFFF !important;
    border-right: 1px solid #E4EAF2 !important;
    box-shadow: 3px 0 14px rgba(20, 34, 56, 0.04) !important;
    opacity: 1.0 !important;
    visibility: visible !important;
}

section[data-testid="stSidebar"] > div {
    background-color: #FFFFFF !important;
    opacity: 1.0 !important;
}

section[data-testid="stSidebar"] [data-testid="stSidebarUserContent"] {
    padding: 1.2rem 1.1rem 2rem 1.1rem !important;
}

/* Navigation Radios in Sidebar */
section[data-testid="stSidebar"] div[data-testid="stRadio"] label {
    color: #142238 !important;
    font-weight: 500 !important;
    font-size: 0.86rem !important;
    padding: 6px 12px !important;
    border-radius: 8px !important;
    margin-bottom: 2px !important;
    transition: all 0.15s ease-in-out !important;
    display: flex !important;
    align-items: center !important;
    cursor: pointer !important;
}

section[data-testid="stSidebar"] div[data-testid="stRadio"] label:hover {
    background-color: #F5F8FC !important;
    color: #087FC3 !important;
}

/* High Contrast Active Navigation State */
section[data-testid="stSidebar"] div[data-testid="stRadio"] label:has(input:checked) {
    background-color: #F0F7FF !important;
    color: #087FC3 !important;
    font-weight: 700 !important;
    border-left: 3px solid #087FC3 !important;
}

/* Modern Primary Buttons */
.stButton>button {
    background: linear-gradient(135deg, #087FC3 0%, #0369A1 100%) !important;
    color: #FFFFFF !important;
    font-weight: 600 !important;
    border: none !important;
    border-radius: 8px !important;
    padding: 8px 18px !important;
    box-shadow: 0 4px 12px rgba(8, 127, 195, 0.25) !important;
    transition: all 0.2s ease !important;
}

.stButton>button:hover {
    background: linear-gradient(135deg, #0369A1 0%, #075985 100%) !important;
    box-shadow: 0 6px 16px rgba(8, 127, 195, 0.35) !important;
    transform: translateY(-1px) !important;
    color: #FFFFFF !important;
}

/* Interactive Tabs */
.stTabs [data-baseweb="tab-list"] {
    gap: 8px !important;
    background-color: #EEF2F6 !important;
    padding: 5px !important;
    border-radius: 10px !important;
    border: 1px solid #E4EAF2 !important;
}

.stTabs [data-baseweb="tab"] {
    border-radius: 8px !important;
    padding: 8px 18px !important;
    font-weight: 600 !important;
    color: #63748B !important;
    background-color: transparent !important;
    border: none !important;
    transition: all 0.2s ease !important;
}

.stTabs [aria-selected="true"] {
    background-color: #FFFFFF !important;
    color: #087FC3 !important;
    box-shadow: 0 2px 8px rgba(20, 34, 56, 0.08) !important;
}

/* Dataframe & Tables Styling */
div[data-testid="stDataFrame"], div[data-testid="stTable"] {
    background-color: #FFFFFF !important;
    border-radius: 10px !important;
    border: 1px solid #E4EAF2 !important;
    box-shadow: 0 2px 8px rgba(20, 34, 56, 0.03) !important;
    overflow: hidden !important;
}

/* Streamlit Header Override - Eliminate Permanent Black Header Strip */
header[data-testid="stHeader"] {
    background-color: transparent !important;
    color: #142238 !important;
}

/* Reduced Motion Accessibility Compliance */
@media (prefers-reduced-motion: reduce) {
    *, ::before, ::after {
        animation-delay: -1ms !important;
        animation-duration: 1ms !important;
        animation-iteration-count: 1 !important;
        background-attachment: initial !important;
        scroll-behavior: auto !important;
        transition-delay: 0s !important;
        transition-duration: 0s !important;
    }
}
</style>
"""

def apply_styling():
    """Injects the SecureVault UI 2.0 visual theme into the active Streamlit session."""
    st.markdown(CINEMATIC_CSS, unsafe_allow_html=True)

def render_hero(title: str, subtitle: str, badge: str = None, meta_items: list = None):
    """Renders a cinematic hero section combining modern SaaS typography with cybersecurity accents."""
    badge_html = f'<span class="vault-hero-badge">{badge}</span>' if badge else ""
    meta_html = ""
    if meta_items:
        spans = "".join([f"<span>{item}</span>" for item in meta_items])
        meta_html = f'<div class="vault-hero-meta">{spans}</div>'

    st.markdown(
        f"""
        <div class="vault-hero">
            <h1 class="vault-hero-title">{title} {badge_html}</h1>
            <p class="vault-hero-subtitle">{subtitle}</p>
            {meta_html}
        </div>
        """,
        unsafe_allow_html=True
    )

def render_kpi_card(label: str, value: str, subtext: str = None, color: str = "#087FC3"):
    """Renders a clean, elevated light KPI card with high-contrast metrics."""
    sub_html = f'<div class="kpi-subtext">{subtext}</div>' if subtext else ""
    return f"""
    <div class="kpi-card">
        <div class="kpi-label">{label}</div>
        <div class="kpi-value" style="color: {color};">{value}</div>
        {sub_html}
    </div>
    """

def render_action_card(title: str, description: str, icon: str = "⚡", badge: str = None, link_hint: str = None) -> str:
    """Renders a sleek interactive action card inspired by Linear and Vercel."""
    badge_html = f'<span class="badge-pill" style="font-size: 0.70rem;">{badge}</span>' if badge else ""
    hint_html = f'<div style="font-size: 0.75rem; color: #087FC3; font-weight: 600; margin-top: 10px;">{link_hint} →</div>' if link_hint else ""
    return f"""
    <div class="light-card action-card" style="padding: 18px 20px; height: 100%; border-radius: 12px;">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
            <div style="font-size: 1.5rem;">{icon}</div>
            {badge_html}
        </div>
        <div style="font-weight: 700; color: #142238; font-size: 1.02rem; margin-bottom: 6px;">{title}</div>
        <div style="font-size: 0.82rem; color: #63748B; line-height: 1.45;">{description}</div>
        {hint_html}
    </div>
    """

def render_dark_console(header_title: str, content_html: str, status_tag: str = "LIVE TELEMETRY"):
    """Renders a 35% dark command panel for code traces, logs, and attack consoles."""
    return f"""
    <div class="dark-console">
        <div class="dark-console-header">
            <div style="display: flex; align-items: center; gap: 10px;">
                <div class="dark-console-dots">
                    <span class="dark-console-dot dot-red"></span>
                    <span class="dark-console-dot dot-yellow"></span>
                    <span class="dark-console-dot dot-green"></span>
                </div>
                <span>{header_title}</span>
            </div>
            <span style="color: #38BDF8; font-size: 0.75rem; background: rgba(56, 189, 248, 0.15); padding: 2px 8px; border-radius: 4px;">{status_tag}</span>
        </div>
        <div>
            {content_html}
        </div>
    </div>
    """
