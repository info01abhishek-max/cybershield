"""File Scanner feature module with integrated file security scanner."""
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from typing import Dict
from database.connection import get_db
from components.ui import (
    render_page_header, render_section_header, metric_card, severity_badge,
    create_bar_chart, DARK_BLUE_THEME
)
from file_scanner.scanner import get_file_scanner, FileScanResult


def render_file_scanner() -> None:
    """Render the file scanner page."""
    render_page_header("File Scanner", "Local file analysis and threat detection", "📁")

    scanner = get_file_scanner()

    _render_file_upload(scanner)
    _render_scan_metrics(scanner)
    _render_scan_history(scanner)
    _render_detailed_analysis(scanner)


def _render_file_upload(scanner: 'FileScanner') -> None:
    """Render file upload and scanning interface."""
    render_section_header("File Upload & Scan", "📤")

    st.caption("Select a file to scan. Maximum file size: 100 MB. Files are scanned locally and never executed.")

    uploaded_file = st.file_uploader(
        "Choose a file",
        type=None,
        accept_multiple_files=False,
        key="file_scanner_uploader",
        help="Supported: All file types. Maximum size: 100 MB"
    )

    if uploaded_file is not None:
        col1, col2 = st.columns([3, 1])

        with col1:
            st.info(f"Selected: **{uploaded_file.name}** ({uploaded_file.size:,} bytes)")

        with col2:
            if st.button("🔍 Scan File", type="primary", use_container_width=True):
                with st.spinner("Scanning file..."):
                    import tempfile
                    import os

                    with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{uploaded_file.name}") as tmp:
                        tmp.write(uploaded_file.getvalue())
                        tmp_path = tmp.name

                    try:
                        result = scanner.scan_file(tmp_path)
                        scanner.save_scan_result(result)
                        _display_scan_result(result)
                    finally:
                        try:
                            os.unlink(tmp_path)
                        except:
                            pass

    st.divider()

    st.caption("Or enter a local file path to scan:")
    file_path = st.text_input(
        "Local file path",
        placeholder="C:\\Users\\username\\Downloads\\file.exe",
        key="file_scanner_path_input"
    )

    if st.button("Scan Path", use_container_width=True) and file_path:
        if os.path.exists(file_path):
            with st.spinner("Scanning file..."):
                result = scanner.scan_file(file_path)
                scanner.save_scan_result(result)
                _display_scan_result(result)
        else:
            st.error("File not found. Please check the path.")


def _display_scan_result(result: FileScanResult) -> None:
    """Display file scan result."""
    risk_colors = {
        'MALICIOUS': DARK_BLUE_THEME['critical'],
        'SUSPICIOUS': DARK_BLUE_THEME['danger'],
        'POTENTIALLY_UNWANTED': DARK_BLUE_THEME['warning'],
        'LOW_RISK': DARK_BLUE_THEME['info'],
        'UNKNOWN': DARK_BLUE_THEME['accent'],
        'SAFE': DARK_BLUE_THEME['success'],
        'ERROR': DARK_BLUE_THEME['danger'],
    }

    risk_color = risk_colors.get(result.risk_level, DARK_BLUE_THEME['accent'])

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
            <h3 style="margin: 0; color: {DARK_BLUE_THEME['text_primary']};">{result.file_name}</h3>
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

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("File Size", _format_bytes(result.file_size))
    with col2:
        st.metric("SHA-256", result.sha256_hash[:16] + "...")
    with col3:
        st.metric("MD5", result.md5_hash[:16] + "...")
    with col4:
        st.metric("Scan Time", f"{result.scan_duration_ms:.1f} ms")

    st.divider()

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("File Information")
        st.write(f"**File Type:** {result.file_type}")
        st.write(f"**MIME Type:** {result.mime_type}")
        st.write(f"**Full SHA-256:** `{result.sha256_hash}`")
        st.write(f"**Full MD5:** `{result.md5_hash}`")

        if result.metadata:
            with st.expander("Metadata Details"):
                for key, value in result.metadata.items():
                    if key not in ['file_type', 'mime_type']:
                        st.write(f"**{key}:** {value}")

    with col2:
        st.subheader("Threat Analysis")
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
                    <span style="margin-left: 0.5rem;">{indicator}</span>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.success("No suspicious indicators detected")

        st.write(f"**Classification:** {result.threat_name}")

    st.divider()

    col1, col2 = st.columns(2)
    with col1:
        if st.button("📋 Copy SHA-256", use_container_width=True):
            st.code(result.sha256_hash)
    with col2:
        if st.button("🔍 Lookup Online", use_container_width=True):
            st.info("Feature coming soon: VirusTotal, Hybrid Analysis integration")


def _render_scan_metrics(scanner: 'FileScanner') -> None:
    """Render scan metrics."""
    render_section_header("Scan Statistics", "📊")

    stats = scanner.get_stats()

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        metric_card("Total Scanned", str(stats['total_scanned']))

    with col2:
        malicious = stats['by_result'].get('MALICIOUS', 0)
        metric_card("Malicious", str(malicious), delta="Confirmed threats", delta_color="inverse")

    with col3:
        suspicious = stats['by_result'].get('SUSPICIOUS', 0) + stats['by_result'].get('POTENTIALLY_UNWANTED', 0)
        metric_card("Suspicious", str(suspicious), delta="Review needed", delta_color="inverse")

    with col4:
        clean = stats['by_result'].get('SAFE', 0) + stats['by_result'].get('LOW_RISK', 0) + stats['by_result'].get('UNKNOWN', 0)
        metric_card("Clean/Low Risk", str(clean), delta="No threats", delta_color="normal")

    if stats['total_scanned'] > 0:
        col1, col2 = st.columns(2)

        with col1:
            render_section_header("Results Distribution", "📈")
            _render_results_pie(stats['by_result'])

        with col2:
            render_section_header("Scan Performance", "⚡")
            st.metric("Avg Scan Time", f"{stats['avg_duration_sec']:.3f} sec")
            st.metric("Total Data Scanned", _format_bytes(stats['total_bytes_scanned']))


def _render_scan_history(scanner: 'FileScanner') -> None:
    """Render scan history with filters."""
    render_section_header("Scan History", "📋")

    col1, col2 = st.columns([1, 3])

    with col1:
        filter_type = st.selectbox(
            "Filter",
            ["All", "Malicious", "Suspicious", "Clean"],
            key="file_scan_filter"
        )

    filter_map = {
        'All': 'all',
        'Malicious': 'malicious',
        'Suspicious': 'suspicious',
        'Clean': 'clean'
    }

    history = scanner.get_scan_history(limit=50, filter_type=filter_map[filter_type])

    if history:
        df = pd.DataFrame(history)
        df['timestamp'] = pd.to_datetime(df['timestamp']).dt.strftime('%Y-%m-%d %H:%M')
        df['file_size_fmt'] = df.apply(lambda r: _format_bytes(r.get('file_size', 0)), axis=1)

        def result_badge(result):
            colors = {
                'MALICIOUS': DARK_BLUE_THEME['critical'],
                'SUSPICIOUS': DARK_BLUE_THEME['danger'],
                'POTENTIALLY_UNWANTED': DARK_BLUE_THEME['warning'],
                'LOW_RISK': DARK_BLUE_THEME['info'],
                'UNKNOWN': DARK_BLUE_THEME['accent'],
                'SAFE': DARK_BLUE_THEME['success'],
                'ERROR': DARK_BLUE_THEME['danger'],
            }
            color = colors.get(result, DARK_BLUE_THEME['accent'])
            return f'<span style="background: {color}20; color: {color}; padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600;">{result}</span>'

        df['result_badge'] = df['scan_result'].apply(result_badge)

        st.dataframe(
            df[['timestamp', 'file_path', 'result_badge', 'file_size_fmt', 'scan_duration']],
            column_config={
                'timestamp': 'Scanned',
                'file_path': 'File Path',
                'result_badge': st.column_config.TextColumn('Result'),
                'file_size_fmt': 'Size',
                'scan_duration': st.column_config.NumberColumn('Duration (s)', format="%.3f"),
            },
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No scan history available.")


def _render_detailed_analysis(scanner: 'FileScanner') -> None:
    """Render detailed file analysis for a selected scan."""
    render_section_header("Detailed Analysis", "🔬")

    history = scanner.get_scan_history(limit=100, filter_type='all')

    if not history:
        st.info("No scans available for detailed analysis.")
        return

    scan_options = {f"{h['timestamp'][:19]} - {h['file_path']} ({h['scan_result']})": h for h in history}
    selected = st.selectbox("Select Scan for Details", list(scan_options.keys()), key="detailed_analysis_select")

    if selected:
        scan = scan_options[selected]

        col1, col2 = st.columns([2, 1])

        with col1:
            st.subheader("File Details")
            st.write(f"**File:** {scan['file_path']}")
            st.write(f"**SHA-256:** `{scan['file_hash']}`")
            st.write(f"**Result:** {scan['scan_result']}")
            st.write(f"**Scan Time:** {scan['timestamp']}")
            st.write(f"**Duration:** {scan.get('scan_duration', 0):.3f} sec")

            if scan.get('threats_found'):
                try:
                    threats = json.loads(scan['threats_found'])
                    st.write("**Threats/Indicators:**")
                    for threat in threats:
                        st.write(f"  • {threat}")
                except:
                    pass

        with col2:
            if scan.get('threats_found'):
                try:
                    threats = json.loads(scan['threats_found'])
                    threat_names = [t for t in threats if not t.startswith(('suspicious_', 'high_', 'excessive_', 'embedded_', 'potentially_', 'url_', 'hex_', 'tilde_', 'underscore_', 'known_malware'))]
                    indicators = [t for t in threats if t.startswith(('suspicious_', 'high_', 'excessive_', 'embedded_', 'potentially_', 'url_', 'hex_', 'tilde_', 'underscore_'))]
                    known_malware = [t for t in threats if t.startswith('known_malware')]

                    if known_malware:
                        st.error("**Known Malware Detected**")
                        for km in known_malware:
                            st.write(f"  • {km}")

                    if indicators:
                        st.warning(f"**Indicators ({len(indicators)})**")
                        for ind in indicators[:10]:
                            st.write(f"  • {ind}")
                except:
                    pass


def _render_results_pie(results: Dict[str, int]) -> None:
    """Render results distribution pie chart."""
    if not results:
        st.info("No data available.")
        return

    colors_map = {
        'MALICIOUS': DARK_BLUE_THEME['critical'],
        'SUSPICIOUS': DARK_BLUE_THEME['danger'],
        'POTENTIALLY_UNWANTED': DARK_BLUE_THEME['warning'],
        'LOW_RISK': DARK_BLUE_THEME['info'],
        'UNKNOWN': DARK_BLUE_THEME['accent'],
        'SAFE': DARK_BLUE_THEME['success'],
        'ERROR': DARK_BLUE_THEME['danger'],
    }

    labels = list(results.keys())
    values = list(results.values())
    colors = [colors_map.get(label, DARK_BLUE_THEME['accent']) for label in labels]

    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=0.6,
        marker=dict(colors=colors, line=dict(color=DARK_BLUE_THEME['bg_card'], width=2)),
        textinfo='label+percent',
        textfont=dict(color=DARK_BLUE_THEME['text_primary'], size=12),
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


def _format_bytes(bytes_val: int) -> str:
    """Format bytes to human readable string."""
    if bytes_val == 0:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024
    return f"{bytes_val:.1f} PB"