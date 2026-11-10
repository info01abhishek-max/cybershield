"""Threat Detection feature module with integrated threat detection engine."""
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime, timedelta
from typing import Dict
from database.connection import get_db
from components.ui import (
    render_page_header, render_section_header, metric_card, severity_badge,
    create_bar_chart, DARK_BLUE_THEME
)
from threat_engine.engine import get_threat_engine, SecurityEvent, EventStatus
from network_monitor.monitor import get_network_monitor


def render_threat_detection() -> None:
    """Render the threat detection page."""
    render_page_header("Threat Detection", "Security event analysis and threat detection engine", "🔍")

    engine = get_threat_engine()

    _render_analysis_controls(engine)
    _render_event_metrics(engine)
    _render_event_table(engine)
    _render_event_charts(engine)
    _render_investigation_panel(engine)
    _render_detection_rules(engine)


def _render_analysis_controls(engine: 'ThreatDetectionEngine') -> None:
    """Render analysis control buttons."""
    render_section_header("Analysis Controls", "🎛️")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        if st.button("🔍 Run Full Analysis", use_container_width=True, type="primary"):
            with st.spinner("Analyzing security events..."):
                monitor = get_network_monitor()
                connections = []
                try:
                    raw_connections = monitor.get_connections()
                    connections = [
                        {
                            'remote_address': c.remote_address,
                            'remote_port': c.remote_port,
                            'local_address': c.local_address,
                            'local_port': c.local_port,
                            'process_name': c.process_name,
                            'status': c.status,
                            'pid': c.pid
                        }
                        for c in raw_connections
                    ]
                except Exception:
                    pass

                events = engine.run_full_analysis(connections)
                if events:
                    st.success(f"Analysis complete: {len(events)} new events detected")
                    for e in events:
                        st.toast(f"[{e.severity}] {e.description[:50]}...", icon="⚠️")
                else:
                    st.info("No new threats detected")
                st.rerun()

    with col2:
        if st.button("🔄 Refresh Events", use_container_width=True):
            st.rerun()

    with col3:
        auto_analyze = st.checkbox("Auto-analyze (30s)", value=st.session_state.get('threat_auto_analyze', False), key="threat_auto_analyze")
        if auto_analyze:
            st.markdown("""
            <script>
                setTimeout(function() { window.location.reload(); }, 30000);
            </script>
            """, unsafe_allow_html=True)

    with col4:
        st.caption(f"Last updated: {datetime.now().strftime('%H:%M:%S')}")


def _render_event_metrics(engine: 'ThreatDetectionEngine') -> None:
    """Render event metrics."""
    stats = engine.get_event_stats()

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        metric_card("Total Events", str(stats['total']))

    with col2:
        new_count = stats['by_status'].get('NEW', 0)
        metric_card("New", str(new_count), delta="Require review", delta_color="inverse")

    with col3:
        investigating = stats['by_status'].get('INVESTIGATING', 0)
        metric_card("Investigating", str(investigating))

    with col4:
        resolved = stats['by_status'].get('RESOLVED', 0)
        metric_card("Resolved", str(resolved), delta="Closed", delta_color="normal")


def _render_event_table(engine: 'ThreatDetectionEngine') -> None:
    """Render security events table with filters."""
    render_section_header("Security Events", "📋")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        severity_filter = st.selectbox(
            "Severity",
            ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
            key="event_severity_filter"
        )

    with col2:
        status_filter = st.selectbox(
            "Status",
            ["All", "NEW", "INVESTIGATING", "RESOLVED"],
            key="event_status_filter"
        )

    with col3:
        type_filter = st.selectbox(
            "Event Type",
            ["All", "Authentication", "Network", "Process", "System", "File", "Vulnerability"],
            key="event_type_filter"
        )

    with col4:
        date_filter = st.selectbox(
            "Time Range",
            ["Last 24h", "Last 7d", "Last 30d", "All Time"],
            key="event_date_filter"
        )

    severity = None if severity_filter == "All" else severity_filter
    status = None if status_filter == "All" else status_filter
    event_type = None if type_filter == "All" else type_filter

    end_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if date_filter == "Last 24h":
        start_date = (datetime.now() - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
    elif date_filter == "Last 7d":
        start_date = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
    elif date_filter == "Last 30d":
        start_date = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')
    else:
        start_date = None

    events = engine.get_events(
        severity=severity,
        status=status,
        event_type=event_type,
        start_date=start_date,
        end_date=end_date,
        limit=100
    )

    if events:
        df = pd.DataFrame([
            {
                'Event ID': e.event_id,
                'Time': pd.to_datetime(e.timestamp).strftime('%Y-%m-%d %H:%M'),
                'Type': e.event_type,
                'Severity': severity_badge(e.severity),
                'Status': _status_badge(e.status),
                'Source': e.source,
                'Description': e.description[:80] + "..." if len(e.description) > 80 else e.description
            }
            for e in events
        ])

        st.dataframe(
            df,
            column_config={
                'Event ID': 'Event ID',
                'Time': 'Timestamp',
                'Type': 'Type',
                'Severity': st.column_config.TextColumn('Severity'),
                'Status': st.column_config.TextColumn('Status'),
                'Source': 'Source',
                'Description': 'Description',
            },
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No events match the current filters.")


def _render_event_charts(engine: 'ThreatDetectionEngine') -> None:
    """Render event analysis charts."""
    stats = engine.get_event_stats()

    col1, col2 = st.columns(2)

    with col1:
        render_section_header("Events by Severity", "📊")
        _render_severity_chart(stats['by_severity'])

    with col2:
        render_section_header("Events by Status", "📈")
        _render_status_chart(stats['by_status'])

    col3, col4 = st.columns(2)

    with col3:
        render_section_header("Events by Type", "📊")
        _render_type_chart(stats['by_type'])

    with col4:
        render_section_header("Events Timeline (24h)", "📈")
        _render_timeline_chart(engine)


def _render_severity_chart(severity_data: Dict[str, int]) -> None:
    """Render severity distribution chart."""
    if not severity_data:
        st.info("No severity data available.")
        return

    severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    severity_colors = {
        'CRITICAL': DARK_BLUE_THEME['critical'],
        'HIGH': DARK_BLUE_THEME['danger'],
        'MEDIUM': DARK_BLUE_THEME['warning'],
        'LOW': DARK_BLUE_THEME['info'],
        'INFO': DARK_BLUE_THEME['success'],
    }

    sorted_items = sorted(severity_data.items(), key=lambda x: severity_order.index(x[0]) if x[0] in severity_order else 999)
    labels = [item[0] for item in sorted_items]
    values = [item[1] for item in sorted_items]
    colors = [severity_colors.get(label, DARK_BLUE_THEME['accent']) for label in labels]

    fig = create_bar_chart(labels, values, colors)
    st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})


def _render_status_chart(status_data: Dict[str, int]) -> None:
    """Render status distribution chart."""
    if not status_data:
        st.info("No status data available.")
        return

    status_order = ['NEW', 'INVESTIGATING', 'RESOLVED']
    status_colors = {
        'NEW': DARK_BLUE_THEME['danger'],
        'INVESTIGATING': DARK_BLUE_THEME['warning'],
        'RESOLVED': DARK_BLUE_THEME['success'],
    }

    sorted_items = sorted(status_data.items(), key=lambda x: status_order.index(x[0]) if x[0] in status_order else 999)
    labels = [item[0] for item in sorted_items]
    values = [item[1] for item in sorted_items]
    colors = [status_colors.get(label, DARK_BLUE_THEME['accent']) for label in labels]

    fig = create_bar_chart(labels, values, colors)
    st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})


def _render_type_chart(type_data: Dict[str, int]) -> None:
    """Render event type distribution chart."""
    if not type_data:
        st.info("No type data available.")
        return

    labels = list(type_data.keys())
    values = list(type_data.values())
    colors = [DARK_BLUE_THEME['accent']] * len(labels)

    fig = create_bar_chart(labels, values, colors)
    st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})


def _render_timeline_chart(engine: 'ThreatDetectionEngine') -> None:
    """Render event timeline for last 24 hours."""
    events = engine.get_events(start_date=(datetime.now() - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S'), limit=500)

    if not events:
        st.info("No events in the last 24 hours.")
        return

    hourly_counts = {}
    for e in events:
        try:
            dt = pd.to_datetime(e.timestamp)
            hour_key = dt.strftime('%Y-%m-%d %H:00')
            hourly_counts[hour_key] = hourly_counts.get(hour_key, 0) + 1
        except Exception:
            pass

    if hourly_counts:
        sorted_hours = sorted(hourly_counts.items())
        labels = [h[0] for h in sorted_hours]
        values = [h[1] for h in sorted_hours]

        fig = go.Figure()
        fig.add_trace(go.Bar(
            x=labels,
            y=values,
            marker=dict(color=DARK_BLUE_THEME['accent']),
            hovertemplate='<b>%{x}</b><br>Events: %{y}<extra></extra>',
        ))

        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color=DARK_BLUE_THEME['text_primary'], family='Inter'),
            xaxis=dict(gridcolor=DARK_BLUE_THEME['border'], tickfont=dict(color=DARK_BLUE_THEME['text_secondary'], size=9), tickangle=45),
            yaxis=dict(gridcolor=DARK_BLUE_THEME['border'], tickfont=dict(color=DARK_BLUE_THEME['text_secondary'])),
            margin=dict(t=20, b=60, l=40, r=20),
            height=250,
        )

        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})


def _render_investigation_panel(engine: 'ThreatDetectionEngine') -> None:
    """Render event investigation panel."""
    render_section_header("Event Investigation", "🔬")

    events = engine.get_events(limit=50)

    if not events:
        st.info("No events to investigate.")
        return

    event_options = {f"{e.event_id} - {e.description[:60]}": e.event_id for e in events}
    selected_label = st.selectbox("Select Event to Investigate", list(event_options.keys()), key="investigate_event_select")

    if selected_label:
        event_id = event_options[selected_label]
        event = engine.get_event_by_id(event_id)

        if event:
            col1, col2 = st.columns([2, 1])

            with col1:
                st.markdown(f"""
                <div style="
                    background: {DARK_BLUE_THEME['bg_card']};
                    border: 1px solid {DARK_BLUE_THEME['border']};
                    border-radius: 12px;
                    padding: 1.5rem;
                ">
                    <h4 style="margin: 0 0 1rem 0; color: {DARK_BLUE_THEME['text_primary']};">{event.event_id}</h4>
                    <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.5rem; margin-bottom: 1rem;">
                        <div><strong>Timestamp:</strong> {event.timestamp}</div>
                        <div><strong>Type:</strong> {event.event_type}</div>
                        <div><strong>Severity:</strong> {severity_badge(event.severity)}</div>
                        <div><strong>Status:</strong> {_status_badge(event.status)}</div>
                        <div><strong>Source:</strong> {event.source}</div>
                        <div><strong>Assigned To:</strong> {event.assigned_to or 'Unassigned'}</div>
                    </div>
                    <div style="margin-bottom: 1rem;">
                        <strong>Description:</strong>
                        <p style="margin: 0.5rem 0; color: {DARK_BLUE_THEME['text_secondary']};">{event.description}</p>
                    </div>
                    <div>
                        <strong>Details:</strong>
                        <pre style="background: {DARK_BLUE_THEME['bg_primary']}; padding: 0.75rem; border-radius: 8px; overflow-x: auto; font-size: 0.8rem;">{event.details}</pre>
                    </div>
                </div>
                """, unsafe_allow_html=True)

            with col2:
                st.markdown("### Actions")

                current_status = event.status
                new_status = st.selectbox(
                    "Update Status",
                    ["NEW", "INVESTIGATING", "RESOLVED"],
                    index=["NEW", "INVESTIGATING", "RESOLVED"].index(current_status),
                    key=f"status_update_{event_id}"
                )

                assigned_to = st.text_input("Assigned To", value=event.assigned_to, key=f"assigned_{event_id}")
                notes = st.text_area("Investigation Notes", value=event.resolution_notes, key=f"notes_{event_id}")

                if st.button("Update Event", type="primary", use_container_width=True, key=f"update_{event_id}"):
                    if engine.update_event_status(event_id, new_status, assigned_to, notes):
                        st.success("Event updated successfully")
                        st.rerun()
                    else:
                        st.error("Failed to update event")

                if event.status == "NEW" and st.button("Start Investigation", use_container_width=True, key=f"start_inv_{event_id}"):
                    if engine.update_event_status(event_id, "INVESTIGATING", assigned_to, "Investigation started"):
                        st.success("Investigation started")
                        st.rerun()

                if event.status == "INVESTIGATING" and st.button("Mark Resolved", type="primary", use_container_width=True, key=f"resolve_{event_id}"):
                    if engine.update_event_status(event_id, "RESOLVED", assigned_to, notes or "Resolved"):
                        st.success("Event marked as resolved")
                        st.rerun()


def _render_detection_rules(engine: 'ThreatDetectionEngine') -> None:
    """Render detection rules configuration."""
    render_section_header("Detection Rules", "⚙️")

    rules = engine.get_rules()

    for rule in rules:
        with st.expander(f"{'🟢' if rule.enabled else '🔴'} {rule.name} ({rule.rule_id})", expanded=False):
            col1, col2 = st.columns([3, 1])

            with col1:
                st.write(f"**Description:** {rule.description}")
                st.write(f"**Event Type:** {rule.event_type}")
                st.write(f"**Default Severity:** {severity_badge(rule.severity)}")
                st.write(f"**Cooldown:** {rule.cooldown_seconds}s")
                st.write(f"**Conditions:**")
                st.json(rule.conditions)

            with col2:
                enabled = st.checkbox("Enabled", value=rule.enabled, key=f"rule_enabled_{rule.rule_id}")
                if enabled != rule.enabled:
                    engine.update_rule(rule.rule_id, enabled=enabled)
                    st.rerun()

                severity = st.selectbox(
                    "Severity",
                    ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    index=["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(rule.severity),
                    key=f"rule_severity_{rule.rule_id}"
                )
                if severity != rule.severity:
                    engine.update_rule(rule.rule_id, severity=severity)
                    st.rerun()


def _status_badge(status: str) -> str:
    """Return HTML for status badge."""
    colors = {
        'NEW': DARK_BLUE_THEME['danger'],
        'INVESTIGATING': DARK_BLUE_THEME['warning'],
        'RESOLVED': DARK_BLUE_THEME['success'],
    }
    color = colors.get(status, DARK_BLUE_THEME['info'])
    return f'<span style="background: {color}20; color: {color}; padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600;">{status}</span>'