"""Dashboard feature module."""
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from database.connection import get_db
from components.ui import (
    render_page_header, render_section_header, metric_card, status_badge,
    severity_badge, create_severity_chart, create_activity_chart,
    get_demo_dates, alert_card, DARK_BLUE_THEME
)


def render_dashboard() -> None:
    """Render the main dashboard page."""
    render_page_header("Dashboard", "Real-time security posture overview", "📊")

    _render_security_status_row()
    _render_metrics_row()
    _render_charts_row()
    _render_recent_events()


def _render_security_status_row() -> None:
    """Render the security status indicators."""
    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown(f"""
        <div style="background: {DARK_BLUE_THEME['bg_card']}; border: 1px solid {DARK_BLUE_THEME['border']};
                    border-radius: 12px; padding: 1.5rem; text-align: center;">
            <div style="color: {DARK_BLUE_THEME['text_secondary']}; font-size: 0.875rem; margin-bottom: 0.5rem;">
                Overall Security Status
            </div>
            {status_badge('secure')}
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div style="background: {DARK_BLUE_THEME['bg_card']}; border: 1px solid {DARK_BLUE_THEME['border']};
                    border-radius: 12px; padding: 1.5rem; text-align: center;">
            <div style="color: {DARK_BLUE_THEME['text_secondary']}; font-size: 0.875rem; margin-bottom: 0.5rem;">
                Network Status
            </div>
            {status_badge('online')}
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div style="background: {DARK_BLUE_THEME['bg_card']}; border: 1px solid {DARK_BLUE_THEME['border']};
                    border-radius: 12px; padding: 1.5rem; text-align: center;">
            <div style="color: {DARK_BLUE_THEME['text_secondary']}; font-size: 0.875rem; margin-bottom: 0.5rem;">
                Threat Level
            </div>
            {status_badge('warning')}
        </div>
        """, unsafe_allow_html=True)


def _render_metrics_row() -> None:
    """Render the key metrics row."""
    with get_db() as conn:
        cursor = conn.cursor()

        cursor.execute('SELECT COUNT(*) FROM threat_detections WHERE mitigated = 0')
        active_threats = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM network_scans WHERE status = "Completed"')
        completed_scans = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM file_scans')
        files_scanned = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM phishing_urls WHERE is_phishing = 1')
        phishing_detected = cursor.fetchone()[0]

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        metric_card("Active Threats", str(active_threats), delta=f"+{active_threats} unmitigated", delta_color="inverse")

    with col2:
        metric_card("Network Scans", str(completed_scans), delta="Last 24h", delta_color="normal")

    with col3:
        metric_card("Files Scanned", str(files_scanned), delta="Total scans", delta_color="normal")

    with col4:
        metric_card("Phishing URLs", str(phishing_detected), delta="Blocked", delta_color="inverse")


def _render_charts_row() -> None:
    """Render charts row."""
    col1, col2 = st.columns([1, 1])

    with col1:
        render_section_header("Threat Severity Distribution", "📈")
        severity_data = _get_severity_data()
        fig = create_severity_chart(severity_data)
        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})

    with col2:
        render_section_header("Security Activity (7 Days)", "📊")
        dates = get_demo_dates(7)
        activity_data = [12, 19, 15, 25, 22, 18, 28]
        fig = create_activity_chart(dates, activity_data, "Events")
        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})


def _get_severity_data() -> dict:
    """Get threat severity distribution from database."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT severity, COUNT(*) as count
            FROM threat_detections
            GROUP BY severity
        ''')
        rows = cursor.fetchall()

    severity_map = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for row in rows:
        sev = row['severity'].upper()
        if sev in severity_map:
            severity_map[sev] = row['count']

    return {k: v for k, v in severity_map.items() if v > 0} or {'LOW': 1, 'INFO': 1}


def _render_recent_events() -> None:
    """Render recent security events table."""
    render_section_header("Recent Security Events", "🕐")

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT timestamp, event_type, severity, source, description
            FROM security_events
            ORDER BY timestamp DESC
            LIMIT 10
        ''')
        events = cursor.fetchall()

    if events:
        df = pd.DataFrame(events)
        df['timestamp'] = pd.to_datetime(df['timestamp']).dt.strftime('%Y-%m-%d %H:%M')
        df['severity_badge'] = df['severity'].apply(lambda s: severity_badge(s))

        st.dataframe(
            df[['timestamp', 'event_type', 'severity_badge', 'source', 'description']],
            column_config={
                'timestamp': 'Time',
                'event_type': 'Event Type',
                'severity_badge': st.column_config.TextColumn('Severity'),
                'source': 'Source',
                'description': 'Description',
            },
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No security events recorded yet.")