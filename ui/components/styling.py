"""
SecureVault UI Theme & Custom Styling
Applies a modern, professional cybersecurity research lab visual theme:
- Dark slate / navy blue palette (#0B132B, #1C2541, #3A506B, #48CAE4, #0077B6)
- High-contrast typography and syntax styling
- Custom metrics cards, status badges, and glassmorphism containers
"""
import streamlit as st

CYBER_PALETTE = {
    "bg_dark": "#0B132B",
    "card_dark": "#1C2541",
    "accent_blue": "#3A506B",
    "cyan_glow": "#48CAE4",
    "cyan_bold": "#00B4D8",
    "deep_blue": "#0077B6",
    "success_green": "#10B981",
    "danger_red": "#EF4444",
    "warning_amber": "#F59E0B",
    "text_primary": "#F8FAFC",
    "text_muted": "#94A3B8"
}

CUSTOM_CSS = """
<style>
/* Main Background & Typography */
.main {
    background-color: #0B132B;
    color: #F8FAFC;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
}

/* Header & Banner */
.vault-header {
    background: linear-gradient(135deg, #1C2541 0%, #0B132B 100%);
    border: 1px solid #3A506B;
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 24px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
}

.vault-title {
    font-size: 2.2rem;
    font-weight: 800;
    color: #48CAE4;
    letter-spacing: -0.5px;
    margin: 0;
}

.vault-subtitle {
    font-size: 1.05rem;
    color: #94A3B8;
    margin-top: 6px;
    margin-bottom: 0;
}

/* Metric Cards */
.metric-card {
    background-color: #1C2541;
    border: 1px solid #3A506B;
    border-radius: 10px;
    padding: 18px;
    text-align: center;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
    transition: transform 0.2s ease, border-color 0.2s ease;
}

.metric-card:hover {
    transform: translateY(-2px);
    border-color: #48CAE4;
}

.metric-value {
    font-size: 2.0rem;
    font-weight: 700;
    color: #48CAE4;
    margin: 4px 0;
}

.metric-label {
    font-size: 0.85rem;
    color: #94A3B8;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

/* Badges */
.badge-vulnerable {
    background-color: rgba(239, 68, 68, 0.2);
    color: #EF4444;
    border: 1px solid #EF4444;
    padding: 3px 10px;
    border-radius: 12px;
    font-size: 0.8rem;
    font-weight: 600;
    display: inline-block;
}

.badge-hardened {
    background-color: rgba(16, 185, 129, 0.2);
    color: #10B981;
    border: 1px solid #10B981;
    padding: 3px 10px;
    border-radius: 12px;
    font-size: 0.8rem;
    font-weight: 600;
    display: inline-block;
}

.badge-cwe {
    background-color: rgba(72, 202, 228, 0.15);
    color: #48CAE4;
    border: 1px solid #48CAE4;
    padding: 2px 8px;
    border-radius: 8px;
    font-size: 0.75rem;
    font-weight: 600;
}

/* Callout Box */
.cyber-callout {
    background-color: #162035;
    border-left: 4px solid #48CAE4;
    padding: 16px 20px;
    border-radius: 0 8px 8px 0;
    margin: 16px 0;
}

/* Sidebar Styling */
section[data-testid="stSidebar"] {
    background-color: #0A0F24;
    border-right: 1px solid #1C2541;
}

/* Buttons */
.stButton>button {
    background: linear-gradient(135deg, #0077B6 0%, #0096C7 100%);
    color: white;
    font-weight: 600;
    border: none;
    border-radius: 8px;
    padding: 8px 18px;
    transition: all 0.2s ease;
}

.stButton>button:hover {
    background: linear-gradient(135deg, #0096C7 0%, #48CAE4 100%);
    box-shadow: 0 0 12px rgba(72, 202, 228, 0.4);
    color: #0B132B;
}

/* Table overrides */
div[data-testid="stTable"] {
    background-color: #1C2541;
    border-radius: 8px;
    overflow: hidden;
}
</style>
"""

def apply_styling():
    """Injects the SecureVault custom CSS styles into the current Streamlit app."""
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

def render_header(title: str, subtitle: str, badge: str = None):
    """Renders the top branding header banner."""
    badge_html = f'<span class="badge-cwe" style="margin-left: 12px;">{badge}</span>' if badge else ""
    st.markdown(
        f"""
        <div class="vault-header">
            <h1 class="vault-title">{title} {badge_html}</h1>
            <p class="vault-subtitle">{subtitle}</p>
        </div>
        """,
        unsafe_allow_html=True
    )

def render_metric_card(label: str, value: str, delta: str = None, color: str = "#48CAE4"):
    """Renders a styled metric card."""
    delta_html = f'<div style="font-size: 0.8rem; color: #10B981; margin-top: 2px;">{delta}</div>' if delta else ""
    return f"""
    <div class="metric-card">
        <div class="metric-label">{label}</div>
        <div class="metric-value" style="color: {color};">{value}</div>
        {delta_html}
    </div>
    """
