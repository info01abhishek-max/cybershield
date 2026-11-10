"""Network Monitor feature module with real-time network monitoring."""
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime
from database.connection import get_db
from components.ui import (
    render_page_header, render_section_header, metric_card, status_badge,
    create_bar_chart, DARK_BLUE_THEME, severity_badge
)
from network_monitor.monitor import get_network_monitor, NetworkInterface, NetworkConnection


def render_network_monitor() -> None:
    """Render the network monitor page."""
    render_page_header("Network Monitor", "Real-time network monitoring and scanning", "🌐")

    monitor = get_network_monitor()

    _render_refresh_controls()
    _render_interface_overview(monitor)
    _render_throughput_chart(monitor)
    _render_active_connections(monitor)
    _render_suspicious_alerts(monitor)
    _render_scan_controls()
    _render_scan_results()


def _render_refresh_controls() -> None:
    """Render refresh controls."""
    render_section_header("Monitoring Controls", "🎛️")

    col1, col2, col3, col4 = st.columns([1, 1, 1, 2])

    with col1:
        if st.button("🔄 Refresh Now", use_container_width=True, type="primary"):
            st.rerun()

    with col2:
        auto_refresh = st.checkbox("Auto Refresh (5s)", value=st.session_state.get('net_auto_refresh', False), key="net_auto_refresh")
        if auto_refresh:
            st.markdown("""
            <script>
                setTimeout(function() {
                    window.location.reload();
                }, 5000);
            </script>
            """, unsafe_allow_html=True)

    with col3:
        history_minutes = st.selectbox("History Window", [1, 5, 10, 30, 60], index=2, key="net_history_minutes")
        st.session_state['net_history_minutes'] = history_minutes

    with col4:
        st.caption(f"Last updated: {datetime.now().strftime('%H:%M:%S')}")


def _render_interface_overview(monitor: 'NetworkMonitor') -> None:
    """Render network interface overview."""
    render_section_header("Network Interfaces", "🔌")

    interfaces = monitor.get_interfaces()

    if not interfaces:
        st.warning("Unable to retrieve network interfaces. Administrator privileges may be required on Windows.")
        return

    cols = st.columns(min(len(interfaces), 4))

    for idx, iface in enumerate(interfaces):
        with cols[idx % 4]:
            status_class = "status-secure" if iface.is_up else "status-danger"
            status_text = "🟢 Up" if iface.is_up else "🔴 Down"

            st.markdown(f"""
            <div style="
                background: {DARK_BLUE_THEME['bg_card']};
                border: 1px solid {DARK_BLUE_THEME['border']};
                border-radius: 12px;
                padding: 1rem;
                margin-bottom: 0.5rem;
            ">
                <div style="font-weight: 600; color: {DARK_BLUE_THEME['text_primary']}; margin-bottom: 0.5rem;">
                    {iface.name}
                </div>
                <div class="status-indicator {status_class}">{status_text}</div>
                <div style="margin-top: 0.75rem; font-size: 0.8rem; color: {DARK_BLUE_THEME['text_secondary']};">
                    <div>↑ {monitor.format_bytes(iface.bytes_sent)}</div>
                    <div>↓ {monitor.format_bytes(iface.bytes_recv)}</div>
                    <div>Packets: {iface.packets_sent:,} / {iface.packets_recv:,}</div>
                    <div>Errors: {iface.errin} / {iface.errout}</div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            for addr in iface.addresses:
                if addr['address'] and not addr['address'].startswith('fe80'):
                    st.caption(f"{addr['family']}: {addr['address']}")


def _render_throughput_chart(monitor: 'NetworkMonitor') -> None:
    """Render network throughput chart."""
    render_section_header("Network Throughput", "📈")

    throughput = monitor.get_throughput()
    history_minutes = st.session_state.get('net_history_minutes', 10)
    history = monitor.get_throughput_history(history_minutes)

    if not history:
        st.info("Collecting throughput data... Refresh to see live data.")
        return

    timestamps = [h.timestamp for h in history]
    sent_bytes = [h.bytes_sent for h in history]
    recv_bytes = [h.bytes_recv for h in history]
    sent_pps = [h.packets_sent for h in history]
    recv_pps = [h.packets_recv for h in history]

    tab1, tab2 = st.tabs(["Bytes/sec", "Packets/sec"])

    with tab1:
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=timestamps, y=sent_bytes,
            mode='lines', name='Sent',
            line=dict(color=DARK_BLUE_THEME['danger'], width=2),
            fill='tozeroy', fillcolor=f'rgba(239, 68, 68, 0.1)',
        ))
        fig.add_trace(go.Scatter(
            x=timestamps, y=recv_bytes,
            mode='lines', name='Received',
            line=dict(color=DARK_BLUE_THEME['success'], width=2),
            fill='tozeroy', fillcolor=f'rgba(16, 185, 129, 0.1)',
        ))
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color=DARK_BLUE_THEME['text_primary'], family='Inter'),
            xaxis=dict(gridcolor=DARK_BLUE_THEME['border'], tickfont=dict(color=DARK_BLUE_THEME['text_secondary'])),
            yaxis=dict(gridcolor=DARK_BLUE_THEME['border'], tickfont=dict(color=DARK_BLUE_THEME['text_secondary'])),
            margin=dict(t=20, b=20, l=40, r=20),
            height=250,
            hovermode='x unified',
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        )
        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})

    with tab2:
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=timestamps, y=sent_pps,
            mode='lines', name='Sent',
            line=dict(color=DARK_BLUE_THEME['warning'], width=2),
        ))
        fig.add_trace(go.Scatter(
            x=timestamps, y=recv_pps,
            mode='lines', name='Received',
            line=dict(color=DARK_BLUE_THEME['info'], width=2),
        ))
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color=DARK_BLUE_THEME['text_primary'], family='Inter'),
            xaxis=dict(gridcolor=DARK_BLUE_THEME['border'], tickfont=dict(color=DARK_BLUE_THEME['text_secondary'])),
            yaxis=dict(gridcolor=DARK_BLUE_THEME['border'], tickfont=dict(color=DARK_BLUE_THEME['text_secondary'])),
            margin=dict(t=20, b=20, l=40, r=20),
            height=250,
            hovermode='x unified',
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        )
        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})

    col1, col2, col3, col4 = st.columns(4)
    current = history[-1] if history else None
    if current:
        with col1:
            st.metric("↑ Sent", monitor.format_speed(current.bytes_sent))
        with col2:
            st.metric("↓ Received", monitor.format_speed(current.bytes_recv))
        with col3:
            st.metric("↑ Pkts/s", f"{current.packets_sent:,}")
        with col4:
            st.metric("↓ Pkts/s", f"{current.packets_recv:,}")


def _render_active_connections(monitor: 'NetworkMonitor') -> None:
    """Render active network connections."""
    render_section_header("Active Connections", "🔗")

    connections = monitor.get_connections()
    monitor.record_connection_snapshot(connections)

    if not connections:
        st.info("No active connections or insufficient permissions to view connections.")
        st.caption("On Windows, Administrator privileges are required to view all process connections.")
        return

    filter_col1, filter_col2, filter_col3 = st.columns(3)
    with filter_col1:
        status_filter = st.selectbox("Status", ["All"] + sorted(set(c.status for c in connections)), key="conn_status_filter")
    with filter_col2:
        family_filter = st.selectbox("Protocol", ["All"] + sorted(set(c.family for c in connections)), key="conn_family_filter")
    with filter_col3:
        show_external_only = st.checkbox("External Only", value=False, key="conn_external_only")

    filtered = connections
    if status_filter != "All":
        filtered = [c for c in filtered if c.status == status_filter]
    if family_filter != "All":
        filtered = [c for c in filtered if c.family == family_filter]
    if show_external_only:
        filtered = [c for c in filtered if c.remote_address and not _is_private_ip(c.remote_address)]

    if filtered:
        df = pd.DataFrame([
            {
                'Protocol': c.family,
                'Local': f"{c.local_address}:{c.local_port}" if c.local_port else c.local_address,
                'Remote': f"{c.remote_address}:{c.remote_port}" if c.remote_address and c.remote_port else (c.remote_address or ''),
                'Status': c.status,
                'PID': c.pid,
                'Process': c.process_name,
                'Direction': _get_direction(c)
            }
            for c in filtered
        ])

        st.dataframe(
            df,
            column_config={
                'Protocol': 'Protocol',
                'Local': 'Local Address',
                'Remote': 'Remote Address',
                'Status': 'Status',
                'PID': 'PID',
                'Process': 'Process',
                'Direction': 'Direction',
            },
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No connections match the current filters.")


def _render_suspicious_alerts(monitor: 'NetworkMonitor') -> None:
    """Render suspicious connection alerts."""
    render_section_header("Security Alerts", "🚨")

    connections = monitor.get_connections()
    alerts = monitor.check_suspicious_patterns(connections)

    if alerts:
        for alert in alerts:
            severity_color = {
                'CRITICAL': DARK_BLUE_THEME['critical'],
                'HIGH': DARK_BLUE_THEME['danger'],
                'MEDIUM': DARK_BLUE_THEME['warning'],
                'LOW': DARK_BLUE_THEME['info'],
            }.get(alert['severity'], DARK_BLUE_THEME['accent'])

            st.markdown(f"""
            <div style="
                background: {DARK_BLUE_THEME['bg_card']};
                border-left: 4px solid {severity_color};
                border-radius: 8px;
                padding: 1rem;
                margin-bottom: 0.75rem;
            ">
                <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 0.5rem;">
                    <strong style="color: {DARK_BLUE_THEME['text_primary']};">{alert['type']}</strong>
                    {severity_badge(alert['severity'])}
                </div>
                <div style="color: {DARK_BLUE_THEME['text_secondary']}; margin-bottom: 0.5rem;">{alert['description']}</div>
                <div style="font-size: 0.75rem; color: {DARK_BLUE_THEME['accent']};">Indicator: {alert['indicator']} | {alert['timestamp'][:19]}</div>
            </div>
            """, unsafe_allow_html=True)

            monitor.store_monitoring_event(
                alert['type'],
                alert['severity'],
                alert['description'],
                {'source_ip': alert['source_ip'], 'target': alert['target'], 'indicator': alert['indicator']}
            )
    else:
        st.success("No suspicious patterns detected in current connections.")


def _render_scan_controls() -> None:
    """Render scan control buttons."""
    render_section_header("Network Scans", "🔍")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        if st.button("🔍 Quick Scan", use_container_width=True, type="primary"):
            st.toast("Quick scan initiated...", icon="🔍")

    with col2:
        if st.button("🔬 Full Scan", use_container_width=True):
            st.toast("Full scan initiated...", icon="🔬")

    with col3:
        if st.button("🛡️ Vulnerability Scan", use_container_width=True):
            st.toast("Vulnerability scan initiated...", icon="🛡️")

    with col4:
        if st.button("⏹️ Stop Scan", use_container_width=True):
            st.toast("Scan stopped", icon="⏹️")


def _render_scan_results() -> None:
    """Render recent scan results table."""
    render_section_header("Recent Scan Results", "📋")

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT timestamp, target_ip, scan_type, status, open_ports, vulnerabilities
            FROM network_scans
            ORDER BY timestamp DESC
            LIMIT 15
        ''')
        scans = cursor.fetchall()

    if scans:
        df = pd.DataFrame(scans)
        df['timestamp'] = pd.to_datetime(df['timestamp']).dt.strftime('%Y-%m-%d %H:%M')

        def status_badge_html(status):
            colors = {
                'Completed': DARK_BLUE_THEME['success'],
                'In Progress': DARK_BLUE_THEME['warning'],
                'Failed': DARK_BLUE_THEME['danger'],
            }
            color = colors.get(status, DARK_BLUE_THEME['info'])
            return f'<span style="background: {color}20; color: {color}; padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600;">{status}</span>'

        df['status_html'] = df['status'].apply(status_badge_html)

        st.dataframe(
            df[['timestamp', 'target_ip', 'scan_type', 'status_html', 'open_ports', 'vulnerabilities']],
            column_config={
                'timestamp': 'Time',
                'target_ip': 'Target IP',
                'scan_type': 'Scan Type',
                'status_html': st.column_config.TextColumn('Status'),
                'open_ports': 'Open Ports',
                'vulnerabilities': 'Vulnerabilities',
            },
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No scan results available. Initiate a scan to see results.")


def _is_private_ip(ip: str) -> bool:
    """Check if IP is private/internal."""
    if not ip or ip in ['', '::', '0.0.0.0']:
        return True

    parts = ip.split('.')
    if len(parts) == 4:
        try:
            first = int(parts[0])
            second = int(parts[1])
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 127:
                return True
            if first == 169 and second == 254:
                return True
        except ValueError:
            pass

    if ip.startswith('fe80:') or ip.startswith('fc00:') or ip == '::1':
        return True

    return False


def _get_direction(conn: NetworkConnection) -> str:
    """Determine connection direction."""
    if not conn.remote_address:
        return 'Listen'
    if _is_private_ip(conn.remote_address):
        return 'Internal'
    return 'External'