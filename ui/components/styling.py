"""
SecureVault UI 2.0 Theme & Visual Architecture
Implements a 65% Light / 35% Dark cinematic cybersecurity research laboratory theme:
- 65% Light: Crisp off-white surfaces (#F8FAFC), pure white elevated cards (#FFFFFF),
  slate borders (#E2E8F0), high-contrast dark typography (#0F172A, #334155),
  and vibrant cyan/blue highlights (#0284C7, #0EA5E9).
- 35% Dark: Deep navy & charcoal command panels (#0B132B, #0F172A, #1E293B)
  selectively applied to security telemetry, attack consoles, HTTP inspectors,
  network visualizers, and code traces.
- Polished CSS animations, card hover transitions, pulse glows, and responsive layout.
"""
import streamlit as st

CINEMATIC_CSS = """
<style>
/* Global Imports & Reset */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

/* Main Canvas (65% Light Theme) */
.stApp {
    background-color: #F8FAFC;
    color: #0F172A;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
}

/* Keyframe Animations */
@keyframes fadeIn {
    from { opacity: 0; transform: translateY(8px); }
    to { opacity: 1; transform: translateY(0); }
}

@keyframes pulseGlow {
    0% { box-shadow: 0 0 0 0 rgba(14, 165, 233, 0.4); }
    70% { box-shadow: 0 0 0 10px rgba(14, 165, 233, 0); }
    100% { box-shadow: 0 0 0 0 rgba(14, 165, 233, 0); }
}

@keyframes scanline {
    0% { transform: translateY(-100%); }
    100% { transform: translateY(1000%); }
}

/* Hero Banner (Hybrid Cinematic Container) */
.vault-hero {
    background: linear-gradient(135deg, #0F172A 0%, #1E293B 60%, #0369A1 100%);
    color: #FFFFFF;
    border-radius: 16px;
    padding: 32px 36px;
    margin-bottom: 28px;
    box-shadow: 0 10px 25px -5px rgba(15, 23, 42, 0.25), 0 8px 10px -6px rgba(15, 23, 42, 0.2);
    position: relative;
    overflow: hidden;
    animation: fadeIn 0.4s ease-out;
}

.vault-hero::after {
    content: '';
    position: absolute;
    top: 0;
    right: 0;
    width: 350px;
    height: 100%;
    background: radial-gradient(circle, rgba(56, 189, 248, 0.15) 0%, rgba(15, 23, 42, 0) 70%);
    pointer-events: none;
}

.vault-hero-title {
    font-size: 2.3rem;
    font-weight: 800;
    letter-spacing: -0.03em;
    color: #FFFFFF;
    margin: 0;
    line-height: 1.2;
}

.vault-hero-badge {
    background: rgba(56, 189, 248, 0.2);
    color: #38BDF8;
    border: 1px solid rgba(56, 189, 248, 0.4);
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
    font-size: 1.05rem;
    color: #CBD5E1;
    margin-top: 10px;
    margin-bottom: 0;
    max-width: 850px;
    line-height: 1.5;
}

.vault-hero-meta {
    margin-top: 18px;
    display: flex;
    gap: 20px;
    font-size: 0.85rem;
    color: #94A3B8;
}

.vault-hero-meta span {
    display: inline-flex;
    align-items: center;
    gap: 6px;
}

/* Light Surface Cards (65% Composition) */
.light-card {
    background-color: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-radius: 12px;
    padding: 22px;
    box-shadow: 0 4px 12px -2px rgba(15, 23, 42, 0.05), 0 2px 4px -2px rgba(15, 23, 42, 0.03);
    transition: transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease;
    animation: fadeIn 0.4s ease-out;
    margin-bottom: 20px;
}

.light-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 10px 20px -3px rgba(15, 23, 42, 0.08), 0 4px 6px -4px rgba(15, 23, 42, 0.04);
    border-color: #CBD5E1;
}

/* Metric / KPI Cards */
.kpi-card {
    background-color: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-radius: 12px;
    padding: 20px 18px;
    text-align: center;
    box-shadow: 0 4px 10px rgba(15, 23, 42, 0.04);
    transition: all 0.25s ease;
    height: 100%;
}

.kpi-card:hover {
    transform: translateY(-3px);
    border-color: #0284C7;
    box-shadow: 0 12px 24px -4px rgba(2, 132, 199, 0.12);
}

.kpi-label {
    font-size: 0.8rem;
    font-weight: 600;
    color: #64748B;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 6px;
}

.kpi-value {
    font-size: 2.2rem;
    font-weight: 800;
    color: #0284C7;
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
    background-color: #0F172A;
    color: #F8FAFC;
    border: 1px solid #1E293B;
    border-radius: 12px;
    padding: 22px;
    box-shadow: 0 8px 24px -4px rgba(15, 23, 42, 0.4);
    position: relative;
    font-family: 'JetBrains Mono', monospace;
    margin-bottom: 20px;
    animation: fadeIn 0.4s ease-out;
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
    background-color: #FEF2F2;
    color: #DC2626;
    border: 1px solid #FCA5A5;
    padding: 4px 12px;
    border-radius: 9999px;
    font-size: 0.85rem;
    font-weight: 700;
    display: inline-flex;
    align-items: center;
    gap: 6px;
}

.badge-hardened {
    background-color: #ECFDF5;
    color: #059669;
    border: 1px solid #6EE7B7;
    padding: 4px 12px;
    border-radius: 9999px;
    font-size: 0.85rem;
    font-weight: 700;
    display: inline-flex;
    align-items: center;
    gap: 6px;
}

.badge-pill {
    background-color: #F0F9FF;
    color: #0284C7;
    border: 1px solid #BAE6FD;
    padding: 3px 10px;
    border-radius: 6px;
    font-size: 0.78rem;
    font-weight: 600;
}

/* Callout Box */
.cyber-callout-light {
    background-color: #F0F9FF;
    border-left: 4px solid #0284C7;
    padding: 16px 20px;
    border-radius: 0 8px 8px 0;
    margin: 16px 0;
    color: #0F172A;
    font-size: 0.95rem;
}

/* Sidebar Customization */
section[data-testid="stSidebar"] {
    background-color: #FFFFFF;
    border-right: 1px solid #E2E8F0;
    box-shadow: 2px 0 8px rgba(15, 23, 42, 0.02);
}

/* Modern Primary Buttons */
.stButton>button {
    background: linear-gradient(135deg, #0284C7 0%, #0369A1 100%);
    color: #FFFFFF;
    font-weight: 600;
    border: none;
    border-radius: 8px;
    padding: 8px 20px;
    box-shadow: 0 4px 12px rgba(2, 132, 199, 0.25);
    transition: all 0.2s ease;
}

.stButton>button:hover {
    background: linear-gradient(135deg, #0369A1 0%, #075985 100%);
    box-shadow: 0 6px 16px rgba(2, 132, 199, 0.4);
    transform: translateY(-1px);
    color: #FFFFFF;
}

/* Interactive Tabs */
.stTabs [data-baseweb="tab-list"] {
    gap: 8px;
    background-color: #F1F5F9;
    padding: 6px;
    border-radius: 10px;
    border: 1px solid #E2E8F0;
}

.stTabs [data-baseweb="tab"] {
    border-radius: 8px;
    padding: 8px 18px;
    font-weight: 600;
    color: #64748B;
    background-color: transparent;
    border: none;
    transition: all 0.2s ease;
}

.stTabs [aria-selected="true"] {
    background-color: #FFFFFF !important;
    color: #0284C7 !important;
    box-shadow: 0 2px 8px rgba(15, 23, 42, 0.08) !important;
}

/* Dataframe & Tables Styling */
div[data-testid="stDataFrame"], div[data-testid="stTable"] {
    background-color: #FFFFFF;
    border-radius: 10px;
    border: 1px solid #E2E8F0;
    box-shadow: 0 2px 8px rgba(15, 23, 42, 0.03);
    overflow: hidden;
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

def render_kpi_card(label: str, value: str, subtext: str = None, color: str = "#0284C7"):
    """Renders a clean, elevated light KPI card with high-contrast metrics."""
    sub_html = f'<div class="kpi-subtext">{subtext}</div>' if subtext else ""
    return f"""
    <div class="kpi-card">
        <div class="kpi-label">{label}</div>
        <div class="kpi-value" style="color: {color};">{value}</div>
        {sub_html}
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
