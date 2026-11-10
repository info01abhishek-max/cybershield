"""Phishing Detector feature module with integrated phishing detection engine."""
import json
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from typing import Dict
from database.connection import get_db
from components.ui import (
    render_page_header, render_section_header, metric_card, severity_badge,
    create_bar_chart, DARK_BLUE_THEME
)
from phishing_detector.detector import get_phishing_detector, URLAnalysisResult


def render_phishing_detector() -> None:
    """Render the phishing detector page."""
    render_page_header("Phishing Detector", "URL analysis and phishing classification", "🎣")

    detector = get_phishing_detector()

    _render_url_scanner(detector)
    _render_detection_metrics(detector)
    _render_detection_history(detector)
    _render_detailed_analysis(detector)


def _render_url_scanner(detector: 'PhishingDetector') -> None:
    """Render URL scanning interface."""
    render_section_header("URL Scanner", "🔍")

    st.caption("Enter a URL to analyze for phishing indicators. URLs are analyzed locally and never automatically visited or sent to external services.")

    col1, col2 = st.columns([3, 1])

    with col1:
        url_input = st.text_input(
            "Enter URL to scan",
            placeholder="https://example.com",
            key="phishing_url_input"
        )

    with col2:
        scan_clicked = st.button("Scan URL", type="primary", use_container_width=True)

    if scan_clicked and url_input:
        with st.spinner("Analyzing URL..."):
            result = detector.scan_url(url_input)
            detector.save_scan_result(result)
            _display_scan_result(result)
    elif scan_clicked:
        st.warning("Please enter a URL to scan")


def _display_scan_result(result: URLAnalysisResult) -> None:
    """Display URL scan result."""
    risk_colors = {
        'CRITICAL': DARK_BLUE_THEME['critical'],
        'HIGH': DARK_BLUE_THEME['danger'],
        'MEDIUM': DARK_BLUE_THEME['warning'],
        'LOW': DARK_BLUE_THEME['info'],
        'SAFE': DARK_BLUE_THEME['success'],
        'INVALID': DARK_BLUE_THEME['danger'],
    }

    risk_color = risk_colors.get(result.risk_level, DARK_BLUE_THEME['accent'])

    if result.risk_level == 'INVALID':
        st.error(f"❌ **Invalid URL:** {result.indicators[0] if result.indicators else 'Unknown error'}")
        return

    st.markdown(f"""
    <div style="
        background: {DARK_BLUE_THEME['bg_card']};
        border: 1px solid {risk_color};
        border-left: 4px solid {risk_color};
        border-radius: 12px;
        padding: 1.5rem;
        margin: 1rem 0;
    ">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
            <h3 style="margin: 0; color: {DARK_BLUE_THEME['text_primary']};">{result.url}</h3>
            <span style="
                background: {risk_color}20;
                color: {risk_color};
                padding: 0.5rem 1rem;
                border-radius: 20px;
                font-weight: 600;
                font-size: 0.9rem;
            ">{result.risk_level}</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Confidence", f"{result.confidence:.1%}")
    with col2:
        st.metric("Risk Level", result.risk_level)
    with col3:
        status = "🚨 PHISHING" if result.is_phishing else "✅ SAFE"
        st.metric("Status", status)

    st.divider()

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Extracted Features")
        if result.features:
            features_to_show = {
                'Uses HTTPS': result.features.get('uses_https', False),
                'Is IP Address': result.features.get('is_ip', False),
                'Hostname': result.features.get('hostname', 'N/A'),
                'URL Length': result.features.get('url_length', 0),
                'Subdomain Count': result.features.get('subdomain_count', 0),
                'Suspicious TLD': result.features.get('suspicious_tld', False),
                'Brand Keywords': ', '.join(result.features.get('brand_keywords', [])) or 'None',
                'Suspicious Subdomains': ', '.join(result.features.get('suspicious_subdomains', [])) or 'None',
                'Has @ Symbol': result.features.get('has_at_symbol', False),
                'Redirect Count': result.features.get('redirect_count', 0),
                'URL Shortener': result.features.get('shortened_url', False),
                'Entropy': f"{result.features.get('entropy', 0):.2f}",
            }
            for key, value in features_to_show.items():
                st.write(f"**{key}:** {value}")

    with col2:
        st.subheader("Risk Indicators")
        if result.indicators:
            for indicator in result.indicators:
                st.markdown(f"""
                <div style="
                    background: {DARK_BLUE_THEME['bg_card']};
                    border-left: 3px solid {risk_color};
                    padding: 0.75rem;
                    margin: 0.5rem 0;
                    border-radius: 4px;
                ">
                    <span style="color: {risk_color}; font-weight: 500;">⚠</span>
                    <span style="margin-left: 0.5rem;">{indicator.replace('_', ' ').title()}</span>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.success("No suspicious indicators detected")

    st.divider()

    st.caption("⚠️ This analysis is based on heuristic rules and feature extraction. It does not guarantee a URL is safe or malicious. Always verify through official channels.")


def _render_detection_metrics(detector: 'PhishingDetector') -> None:
    """Render detection metrics."""
    render_section_header("Detection Statistics", "📊")

    stats = detector.get_stats()

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        metric_card("URLs Scanned", str(stats['total_scanned']))

    with col2:
        metric_card("Phishing Detected", str(stats['phishing_detected']), delta="Confirmed", delta_color="inverse")

    with col3:
        metric_card("Safe URLs", str(stats['safe_urls']), delta="No threats", delta_color="normal")

    with col4:
        metric_card("Avg Confidence", f"{stats['avg_confidence']:.1%}")

    if stats['total_scanned'] > 0:
        col1, col2 = st.columns(2)

        with col1:
            render_section_header("Detection Results", "📈")
            _render_detection_pie(stats['phishing_detected'], stats['safe_urls'])

        with col2:
            render_section_header("Top Indicators", "🎯")
            _render_indicators_chart(stats['top_indicators'])


def _render_detection_history(detector: 'PhishingDetector') -> None:
    """Render detection history with filters."""
    render_section_header("Scan History", "📋")

    col1, col2 = st.columns([1, 3])

    with col1:
        filter_type = st.selectbox(
            "Filter",
            ["All", "Phishing", "Safe"],
            key="phishing_history_filter"
        )

    filter_map = {
        'All': 'all',
        'Phishing': 'phishing',
        'Safe': 'safe'
    }

    history = detector.get_scan_history(limit=50, filter_type=filter_map[filter_type])

    if history:
        df = pd.DataFrame(history)
        df['timestamp'] = pd.to_datetime(df['timestamp']).dt.strftime('%Y-%m-%d %H:%M')
        df['confidence_pct'] = df['confidence'].apply(lambda c: f"{c:.1%}")

        def status_badge(row):
            if row['is_phishing']:
                return f'<span style="background: {DARK_BLUE_THEME["danger"]}20; color: {DARK_BLUE_THEME["danger"]}; padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600;">🚨 Phishing</span>'
            else:
                return f'<span style="background: {DARK_BLUE_THEME["success"]}20; color: {DARK_BLUE_THEME["success"]}; padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600;">✅ Safe</span>'

        df['status_badge'] = df.apply(status_badge, axis=1)

        st.dataframe(
            df[['timestamp', 'url', 'status_badge', 'confidence_pct', 'indicators']],
            column_config={
                'timestamp': 'Scanned',
                'url': 'URL',
                'status_badge': st.column_config.TextColumn('Status'),
                'confidence_pct': 'Confidence',
                'indicators': 'Indicators',
            },
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No URLs scanned yet.")


def _render_detailed_analysis(detector: 'PhishingDetector') -> None:
    """Render detailed analysis for a selected scan."""
    render_section_header("Detailed Analysis", "🔬")

    history = detector.get_scan_history(limit=100, filter_type='all')

    if not history:
        st.info("No scans available for detailed analysis.")
        return

    scan_options = {f"{h['timestamp'][:19]} - {h['url']} ({'Phishing' if h['is_phishing'] else 'Safe'})": h for h in history}
    selected = st.selectbox("Select Scan for Details", list(scan_options.keys()), key="detailed_analysis_select")

    if selected:
        scan = scan_options[selected]

        col1, col2 = st.columns([2, 1])

        with col1:
            st.subheader("Scan Details")
            st.write(f"**URL:** {scan['url']}")
            st.write(f"**Scanned:** {scan['timestamp']}")
            st.write(f"**Result:** {'Phishing' if scan['is_phishing'] else 'Safe'}")
            st.write(f"**Confidence:** {scan['confidence']:.1%}")

            if scan.get('indicators'):
                try:
                    indicators = json.loads(scan['indicators'])
                    st.write("**Indicators:**")
                    for ind in indicators:
                        st.write(f"  • {ind.replace('_', ' ').title()}")
                except:
                    pass

        with col2:
            st.subheader("Risk Assessment")
            risk_level = 'HIGH' if scan['is_phishing'] else 'LOW'
            risk_color = DARK_BLUE_THEME['danger'] if scan['is_phishing'] else DARK_BLUE_THEME['success']

            st.markdown(f"""
            <div style="
                background: {DARK_BLUE_THEME['bg_card']};
                border: 1px solid {risk_color};
                border-radius: 12px;
                padding: 1rem;
                text-align: center;
            ">
                <div style="font-size: 2rem; margin-bottom: 0.5rem;">{'🚨' if scan['is_phishing'] else '✅'}</div>
                <div style="color: {risk_color}; font-weight: 600; font-size: 1.2rem;">{risk_level} RISK</div>
                <div style="margin-top: 0.5rem; color: {DARK_BLUE_THEME['text_secondary']};">Confidence: {scan['confidence']:.1%}</div>
            </div>
            """, unsafe_allow_html=True)


def _render_detection_pie(phishing_count: int, safe_count: int) -> None:
    """Render phishing detection pie chart."""
    labels = []
    values = []
    colors = []

    if phishing_count > 0:
        labels.append('Phishing')
        values.append(phishing_count)
        colors.append(DARK_BLUE_THEME['danger'])

    if safe_count > 0:
        labels.append('Safe')
        values.append(safe_count)
        colors.append(DARK_BLUE_THEME['success'])

    if not labels:
        st.info("No data available.")
        return

    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=0.6,
        marker=dict(colors=colors, line=dict(color=DARK_BLUE_THEME['bg_card'], width=2)),
        textinfo='label+percent',
        textfont=dict(color=DARK_BLUE_THEME['text_primary'], size=14),
    )])

    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color=DARK_BLUE_THEME['text_primary'], family='Inter'),
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5),
        margin=dict(t=20, b=20, l=20, r=20),
        height=280,
    )

    st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})


def _render_indicators_chart(top_indicators: Dict[str, int]) -> None:
    """Render top phishing indicators chart."""
    if not top_indicators:
        st.info("No indicator data available.")
        return

    labels = [ind.replace('_', ' ').title() for ind in top_indicators.keys()]
    values = list(top_indicators.values())
    colors = [DARK_BLUE_THEME['warning']] * len(labels)

    fig = create_bar_chart(labels, values, colors)
    st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})