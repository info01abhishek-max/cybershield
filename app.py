"""CyberShield - Complete Cybersecurity Protection Platform."""
import streamlit as st
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database.connection import init_database
from components.ui import apply_custom_css, render_sidebar_logo, render_sidebar_navigation
from features.dashboard import render_dashboard
from features.network_monitor import render_network_monitor
from features.threat_detection import render_threat_detection
from features.phishing_detector import render_phishing_detector
from features.file_scanner import render_file_scanner
from features.ai_analyzer import render_ai_analyzer
from features.login_security import render_login_security
from features.alerts_center import render_alerts_center
from features.reports import render_reports


st.set_page_config(
    page_title="CyberShield - Cybersecurity Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


def render_coming_soon(page_name: str, icon: str, description: str) -> None:
    """Render a 'Coming Soon' placeholder page."""
    from components.ui import render_page_header, render_section_header, DARK_BLUE_THEME

    render_page_header(page_name, description, icon)

    st.markdown(f"""
    <div style="
        background: {DARK_BLUE_THEME['bg_card']};
        border: 1px solid {DARK_BLUE_THEME['border']};
        border-radius: 12px;
        padding: 3rem 2rem;
        text-align: center;
        margin-top: 2rem;
    ">
        <div style="font-size: 4rem; margin-bottom: 1rem;">🚧</div>
        <h2 style="margin: 0 0 1rem 0; color: {DARK_BLUE_THEME['text_primary']};">Coming Soon</h2>
        <p style="color: {DARK_BLUE_THEME['text_secondary']}; font-size: 1.1rem; margin: 0;">
            The <strong>{page_name}</strong> module is planned for Phase 2 development.
        </p>
        <p style="color: {DARK_BLUE_THEME['accent']}; margin-top: 1.5rem; font-weight: 500;">
            Stay tuned for advanced security features.
        </p>
    </div>
    """, unsafe_allow_html=True)

    render_section_header("Planned Features", "📋")

    planned_features = {
        "File Scanner": [
            "Real-time file system monitoring",
            "Malware signature detection",
            "Behavioral analysis engine",
            "Quarantine management",
            "Scheduled scan policies"
        ],
        "AI Security Analyzer": [
            "ML-based anomaly detection",
            "Threat intelligence correlation",
            "Automated incident response",
            "Predictive threat modeling",
            "Natural language query interface"
        ],
        "Login Security": [
            "Multi-factor authentication",
            "Brute force protection",
            "Geo-location anomaly detection",
            "Session management",
            "Password policy enforcement"
        ],
        "Alerts Center": [
            "Real-time alert dashboard",
            "Alert correlation engine",
            "Notification channels (Email, Slack, SMS)",
            "Escalation policies",
            "Alert acknowledgment workflow"
        ],
        "Reports": [
            "Executive security summaries",
            "Compliance reporting (PCI, HIPAA, SOC2)",
            "Custom report builder",
            "Scheduled report delivery",
            "Export to PDF/CSV"
        ],
        "Settings": [
            "Global security policies",
            "User role management",
            "Integration configurations",
            "Data retention policies",
            "System health monitoring"
        ],
    }

    features = planned_features.get(page_name, [
        "Advanced threat detection",
        "Automated response capabilities",
        "Integration APIs",
        "Custom rule engine",
        "Audit logging"
    ])

    cols = st.columns(2)
    for i, feature in enumerate(features):
        with cols[i % 2]:
            st.markdown(f"""
            <div style="
                background: {DARK_BLUE_THEME['bg_card']};
                border: 1px solid {DARK_BLUE_THEME['border']};
                border-radius: 8px;
                padding: 1rem;
                margin-bottom: 0.75rem;
            ">
                <span style="color: {DARK_BLUE_THEME['accent']};">▸</span>
                <span style="margin-left: 0.5rem; color: {DARK_BLUE_THEME['text_primary']};">{feature}</span>
            </div>
            """, unsafe_allow_html=True)


def main() -> None:
    """Main application entry point."""
    apply_custom_css()
    init_database()

    render_sidebar_logo()

    if "current_page" not in st.session_state:
        st.session_state.current_page = "dashboard"

    selected_page = render_sidebar_navigation(st.session_state.current_page)
    st.session_state.current_page = selected_page

    page_renderers = {
        "dashboard": render_dashboard,
        "network_monitor": render_network_monitor,
        "threat_detection": render_threat_detection,
        "phishing_detector": render_phishing_detector,
        "file_scanner": render_file_scanner,
        "ai_analyzer": render_ai_analyzer,
        "login_security": render_login_security,
        "alerts_center": render_alerts_center,
        "reports": render_reports,
        "settings": lambda: render_coming_soon("Settings", "⚙️", "Platform configuration and administration"),
    }

    renderer = page_renderers.get(selected_page, render_dashboard)
    renderer()


if __name__ == "__main__":
    main()