"""Alerts Center feature module with centralized alert management."""
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime, timedelta
from database.connection import get_db
from components.ui import (
    render_page_header, render_section_header, metric_card, severity_badge,
    DARK_BLUE_THEME
)


def render_alerts_center() -> None:
    """Render the alerts center page."""
    render_page_header("Alerts Center", "Centralized security alert management and triage", "🚨")

    _render_alert_metrics()
    _render_alerts_table()
    _render_alert_details()
    _render_alert_statistics()


def _render_alert_metrics() -> None:
    """Render alert summary metrics."""
    with get_db() as conn:
        cursor = conn.cursor()

        cursor.execute('SELECT COUNT(*) FROM alerts')
        total = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM alerts WHERE acknowledged = 0')
        unacknowledged = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM alerts WHERE acknowledged = 1')
        acknowledged = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM alerts WHERE severity = "CRITICAL" AND acknowledged = 0')
        critical_unacked = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM alerts WHERE severity = "HIGH" AND acknowledged = 0')
        high_unacked = cursor.fetchone()[0]

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        metric_card("Total Alerts", str(total))

    with col2:
        metric_card("Unacknowledged", str(unacknowledged), delta=f"{unacknowledged} active", delta_color="inverse")

    with col3:
        metric_card("Acknowledged", str(acknowledged), delta_color="normal")

    with col4:
        metric_card("Critical (Active)", str(critical_unacked))

    with col5:
        metric_card("High (Active)", str(high_unacked))


def _render_alerts_table() -> None:
    """Render the main alerts table with filters and actions."""
    render_section_header("All Alerts", "📋")

    # Filters
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        status_filter = st.selectbox("Status", ["All", "Unacknowledged", "Acknowledged"], key="alert_status_filter")

    with col2:
        severity_filter = st.selectbox("Severity", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], key="alert_severity_filter")

    with col3:
        type_filter = st.selectbox("Type", ["All", "Threat Detection", "Network Anomaly", "Vulnerability", "Phishing", "Brute Force", "Login Security"], key="alert_type_filter")

    with col4:
        date_filter = st.selectbox("Time Range", ["Last 24h", "Last 7d", "Last 30d", "All"], key="alert_date_filter")

    with get_db() as conn:
        cursor = conn.cursor()

        query = "SELECT * FROM alerts WHERE 1=1"
        params = []

        if status_filter == "Unacknowledged":
            query += " AND acknowledged = 0"
        elif status_filter == "Acknowledged":
            query += " AND acknowledged = 1"

        if severity_filter != "All":
            query += " AND severity = ?"
            params.append(severity_filter)

        if type_filter != "All":
            query += " AND alert_type = ?"
            params.append(type_filter)

        if date_filter == "Last 24h":
            query += " AND timestamp >= datetime('now', '-1 day')"
        elif date_filter == "Last 7d":
            query += " AND timestamp >= datetime('now', '-7 days')"
        elif date_filter == "Last 30d":
            query += " AND timestamp >= datetime('now', '-30 days')"

        query += " ORDER BY timestamp DESC LIMIT 200"

        cursor.execute(query, params)
        rows = cursor.fetchall()

    if rows:
        df = pd.DataFrame(rows)
        df['timestamp'] = pd.to_datetime(df['timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S')

        # Add action columns
        def render_actions(row):
            if row['acknowledged']:
                return "✅ Acknowledged"
            else:
                return "⚠️ Unacknowledged"

        df['status_display'] = df.apply(render_actions, axis=1)

        st.dataframe(
            df[['id', 'timestamp', 'alert_type', 'severity', 'title', 'message', 'status_display']],
            column_config={
                'id': st.column_config.NumberColumn('ID', width='small'),
                'timestamp': st.column_config.TextColumn('Time', width='medium'),
                'alert_type': st.column_config.TextColumn('Type', width='medium'),
                'severity': st.column_config.TextColumn('Severity', width='small'),
                'title': st.column_config.TextColumn('Title', width='large'),
                'message': st.column_config.TextColumn('Message', width='large'),
                'status_display': st.column_config.TextColumn('Status', width='medium'),
            },
            use_container_width=True,
            hide_index=True,
            height=400,
        )

        # Bulk actions
        st.divider()
        col1, col2, col3 = st.columns(3)

        with col1:
            if st.button("✅ Acknowledge Selected", use_container_width=True):
                st.info("Select alerts above and click to acknowledge (multi-select not directly supported in dataframe). Use the detail view below for individual actions.")

        with col2:
            if st.button("📧 Export to CSV", use_container_width=True):
                csv = df.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name=f"alerts_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                    use_container_width=True
                )

        with col3:
            if st.button("🔄 Refresh", use_container_width=True):
                st.rerun()
    else:
        st.info("No alerts match the current filters.")


def _render_alert_details() -> None:
    """Render alert detail view and management."""
    render_section_header("Alert Management", "🔧")

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, title, severity, acknowledged FROM alerts ORDER BY timestamp DESC")
        alerts = cursor.fetchall()

    if not alerts:
        st.info("No alerts available.")
        return

    alert_options = {f"#{a['id']} - {a['title']} ({a['severity']}) {'✅' if a['acknowledged'] else '⚠️'}": a['id'] for a in alerts}
    selected_key = st.selectbox("Select Alert", list(alert_options.keys()), key="alert_detail_select")

    if selected_key:
        alert_id = alert_options[selected_key]
        _render_single_alert(alert_id)


def _render_single_alert(alert_id: int) -> None:
    """Render detailed view and actions for a single alert."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        alert = cursor.fetchone()

    if not alert:
        st.error("Alert not found.")
        return

    # Alert card
    severity_colors = {
        'CRITICAL': DARK_BLUE_THEME['critical'],
        'HIGH': DARK_BLUE_THEME['danger'],
        'MEDIUM': DARK_BLUE_THEME['warning'],
        'LOW': DARK_BLUE_THEME['info'],
        'INFO': DARK_BLUE_THEME['accent'],
    }
    color = severity_colors.get(alert['severity'], DARK_BLUE_THEME['accent'])

    st.markdown(f"""
    <div style="
        background: {DARK_BLUE_THEME['bg_card']};
        border: 1px solid {color};
        border-left: 4px solid {color};
        border-radius: 12px;
        padding: 1.5rem;
        margin: 1rem 0;
    ">
        <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 1rem;">
            <h3 style="margin: 0; color: {DARK_BLUE_THEME['text_primary']};">#{alert['id']} - {alert['title']}</h3>
            {severity_badge(alert['severity'])}
        </div>
        <div style="color: {DARK_BLUE_THEME['text_secondary']}; margin-bottom: 0.5rem;">
            <strong>Type:</strong> {alert['alert_type']} |
            <strong>Time:</strong> {alert['timestamp']} |
            <strong>Status:</strong> {"✅ Acknowledged" if alert['acknowledged'] else "⚠️ Unacknowledged"}
        </div>
        <div style="color: {DARK_BLUE_THEME['text_primary']};">{alert['message']}</div>
    </div>
    """, unsafe_allow_html=True)

    # Actions
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        if alert['acknowledged']:
            if st.button("🔄 Mark Unacknowledged", use_container_width=True, key=f"unack_{alert_id}"):
                _update_alert_ack(alert_id, 0)
                st.success("Alert marked as unacknowledged.")
                st.rerun()
        else:
            if st.button("✅ Acknowledge", type="primary", use_container_width=True, key=f"ack_{alert_id}"):
                _update_alert_ack(alert_id, 1)
                st.success("Alert acknowledged!")
                st.rerun()

    with col2:
        if st.button("📝 Add Note", use_container_width=True, key=f"note_{alert_id}"):
            st.session_state[f"show_note_{alert_id}"] = True

    with col3:
        if st.button("🔗 Related Events", use_container_width=True, key=f"related_{alert_id}"):
            _show_related_events(alert)

    with col4:
        if st.button("🗑️ Dismiss", use_container_width=True, key=f"dismiss_{alert_id}"):
            _dismiss_alert(alert_id)
            st.success("Alert dismissed.")
            st.rerun()

    # Note input
    if st.session_state.get(f"show_note_{alert_id}", False):
        note = st.text_area("Add Investigation Note", key=f"note_text_{alert_id}")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Save Note", key=f"save_note_{alert_id}"):
                _add_alert_note(alert_id, note)
                st.success("Note saved.")
                st.session_state[f"show_note_{alert_id}"] = False
                st.rerun()
        with col2:
            if st.button("Cancel", key=f"cancel_note_{alert_id}"):
                st.session_state[f"show_note_{alert_id}"] = False
                st.rerun()


def _update_alert_ack(alert_id: int, acknowledged: int) -> None:
    """Update alert acknowledgment status."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE alerts SET acknowledged = ? WHERE id = ?",
            (acknowledged, alert_id)
        )


def _add_alert_note(alert_id: int, note: str) -> None:
    """Add note to alert (stored in a notes table or appended to message)."""
    # For now, we'll append to the message field
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT message FROM alerts WHERE id = ?", (alert_id,))
        row = cursor.fetchone()
        if row:
            current_msg = row['message'] or ""
            new_msg = f"{current_msg}\n\n[Note {datetime.now().strftime('%Y-%m-%d %H:%M')}] {note}"
            cursor.execute("UPDATE alerts SET message = ? WHERE id = ?", (new_msg, alert_id))


def _dismiss_alert(alert_id: int) -> None:
    """Dismiss (delete) an alert."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))


def _show_related_events(alert: dict) -> None:
    """Show related security events for an alert."""
    st.markdown("---")
    st.subheader("Related Events")

    with get_db() as conn:
        cursor = conn.cursor()

        # Search security_events for related items
        search_terms = [alert['title'].split()[0].lower()] if alert['title'] else []
        if alert['source_ip']:
            search_terms.append(alert['source_ip'])

        if search_terms:
            query = "SELECT event_id, timestamp, event_type, severity, source, description, status FROM security_events WHERE 1=1"
            params = []
            for term in search_terms:
                query += " AND (description LIKE ? OR source LIKE ?)"
                params.extend([f"%{term}%", f"%{term}%"])
            query += " ORDER BY timestamp DESC LIMIT 10"

            cursor.execute(query, params)
            related = cursor.fetchall()

            if related:
                for event in related:
                    st.markdown(f"""
                    <div style="
                        background: {DARK_BLUE_THEME['bg_card']};
                        border-left: 3px solid {DARK_BLUE_THEME['accent']};
                        padding: 0.5rem;
                        margin: 0.25rem 0;
                        border-radius: 4px;
                    ">
                        <strong>{event['event_id']}</strong> | {event['timestamp']} | {event['event_type']} | {event['severity']}<br>
                        {event['description']}
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.info("No related events found.")


def _render_alert_statistics() -> None:
    """Render alert statistics and trends."""
    render_section_header("Alert Statistics", "📈")

    col1, col2 = st.columns(2)

    with col1:
        _render_severity_distribution()

    with col2:
        _render_alerts_over_time()

    col1, col2 = st.columns(2)

    with col1:
        _render_alert_types()

    with col2:
        _render_acknowledgment_rate()


def _render_severity_distribution() -> None:
    """Render alert severity distribution."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT severity, COUNT(*) as count
            FROM alerts
            GROUP BY severity
            ORDER BY
                CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    WHEN 'INFO' THEN 5
                    ELSE 6
                END
        ''')
        rows = cursor.fetchall()

    if rows:
        df = pd.DataFrame(rows)

        colors = {
            'CRITICAL': DARK_BLUE_THEME['critical'],
            'HIGH': DARK_BLUE_THEME['danger'],
            'MEDIUM': DARK_BLUE_THEME['warning'],
            'LOW': DARK_BLUE_THEME['info'],
            'INFO': DARK_BLUE_THEME['accent'],
        }

        fig = go.Figure(go.Pie(
            labels=df['severity'],
            values=df['count'],
            marker=dict(colors=[colors.get(s, DARK_BLUE_THEME['accent']) for s in df['severity']]),
            hole=0.4,
            textinfo='label+percent',
            hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>',
        ))

        fig.update_layout(
            title="Alerts by Severity",
            paper_bgcolor='rgba(0,0,0,0)',
            font=dict(color=DARK_BLUE_THEME['text_primary'], family='Inter'),
            margin=dict(t=40, b=20, l=20, r=20),
            height=350,
        )

        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
    else:
        st.info("No alert data available.")


def _render_alerts_over_time() -> None:
    """Render alerts over time."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT
                date(timestamp) as alert_date,
                COUNT(*) as count,
                SUM(CASE WHEN severity IN ('CRITICAL', 'HIGH') THEN 1 ELSE 0 END) as critical_high
            FROM alerts
            WHERE timestamp >= datetime('now', '-30 days')
            GROUP BY date(timestamp)
            ORDER BY alert_date
        ''')
        rows = cursor.fetchall()

    if rows:
        df = pd.DataFrame(rows)

        fig = go.Figure()

        fig.add_trace(go.Scatter(
            x=df['alert_date'],
            y=df['count'],
            mode='lines+markers',
            name='Total Alerts',
            line=dict(color=DARK_BLUE_THEME['accent'], width=2),
            marker=dict(size=6),
        ))

        fig.add_trace(go.Scatter(
            x=df['alert_date'],
            y=df['critical_high'],
            mode='lines+markers',
            name='Critical/High',
            line=dict(color=DARK_BLUE_THEME['danger'], width=2),
            marker=dict(size=6),
        ))

        fig.update_layout(
            title="Alerts Over Time (30 Days)",
            xaxis_title="Date",
            yaxis_title="Count",
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color=DARK_BLUE_THEME['text_primary'], family='Inter'),
            margin=dict(t=40, b=40, l=50, r=20),
            height=350,
            hovermode='x unified',
        )

        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
    else:
        st.info("No time series data available.")


def _render_alert_types() -> None:
    """Render alert type distribution."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT alert_type, COUNT(*) as count
            FROM alerts
            GROUP BY alert_type
            ORDER BY count DESC
        ''')
        rows = cursor.fetchall()

    if rows:
        df = pd.DataFrame(rows)

        fig = go.Figure(go.Bar(
            x=df['count'],
            y=df['alert_type'],
            orientation='h',
            marker=dict(color=DARK_BLUE_THEME['accent']),
            hovertemplate='<b>%{y}</b><br>Count: %{x}<extra></extra>',
        ))

        fig.update_layout(
            title="Alerts by Type",
            xaxis_title="Count",
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color=DARK_BLUE_THEME['text_primary'], family='Inter'),
            margin=dict(t=40, b=20, l=120, r=20),
            height=350,
        )

        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
    else:
        st.info("No alert type data available.")


def _render_acknowledgment_rate() -> None:
    """Render acknowledgment rate by severity."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT
                severity,
                COUNT(*) as total,
                SUM(CASE WHEN acknowledged = 1 THEN 1 ELSE 0 END) as acknowledged
            FROM alerts
            GROUP BY severity
            ORDER BY
                CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    WHEN 'INFO' THEN 5
                    ELSE 6
                END
        ''')
        rows = cursor.fetchall()

    if rows:
        df = pd.DataFrame(rows)
        df['ack_rate'] = (df['acknowledged'] / df['total'] * 100).round(1)

        fig = go.Figure(go.Bar(
            x=df['severity'],
            y=df['ack_rate'],
            marker=dict(
                color=[DARK_BLUE_THEME['success'] if r == 100 else DARK_BLUE_THEME['warning'] if r >= 50 else DARK_BLUE_THEME['danger'] for r in df['ack_rate']]
            ),
            hovertemplate='<b>%{x}</b><br>Total: %{customdata[0]}<br>Acknowledged: %{customdata[1]}<br>Rate: %{y}%<extra></extra>',
            customdata=df[['total', 'acknowledged']].values,
        ))

        fig.update_layout(
            title="Acknowledgment Rate by Severity",
            xaxis_title="Severity",
            yaxis_title="Rate (%)",
            yaxis=dict(range=[0, 100]),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color=DARK_BLUE_THEME['text_primary'], family='Inter'),
            margin=dict(t=40, b=40, l=50, r=20),
            height=350,
        )

        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
    else:
        st.info("No acknowledgment data available.")