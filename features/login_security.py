"""Login Security feature module with Windows login event analysis."""
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime, timedelta
from database.connection import get_db
from components.ui import (
    render_page_header, render_section_header, metric_card, severity_badge,
    create_bar_chart, DARK_BLUE_THEME
)


def render_login_security() -> None:
    """Render the login security page."""
    render_page_header("Login Security", "Windows login event analysis and anomaly detection", "🔐")

    _render_login_metrics()
    _render_failed_login_analysis()
    _render_unusual_patterns()
    _render_login_history()
    _render_geo_analysis()


def _render_login_metrics() -> None:
    """Render login security metrics."""
    with get_db() as conn:
        cursor = conn.cursor()

        cursor.execute('SELECT COUNT(*) FROM login_attempts')
        total = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM login_attempts WHERE success = 1')
        successful = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM login_attempts WHERE success = 0')
        failed = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(DISTINCT username) FROM login_attempts WHERE success = 0')
        failed_users = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(DISTINCT ip_address) FROM login_attempts WHERE success = 0')
        failed_ips = cursor.fetchone()[0]

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        metric_card("Total Attempts", str(total))

    with col2:
        metric_card("Successful", str(successful), delta=f"{(successful/max(total,1)*100):.1f}%", delta_color="normal")

    with col3:
        metric_card("Failed", str(failed), delta=f"{(failed/max(total,1)*100):.1f}%", delta_color="inverse")

    with col4:
        metric_card("Failed Users", str(failed_users))

    with col5:
        metric_card("Failed IPs", str(failed_ips))


def _render_failed_login_analysis() -> None:
    """Render failed login analysis."""
    render_section_header("Failed Login Analysis", "📊")

    col1, col2 = st.columns(2)

    with col1:
        _render_failed_by_ip()

    with col2:
        _render_failed_by_user()


def _render_failed_by_ip() -> None:
    """Render failed logins by IP address."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT ip_address, COUNT(*) as count,
                   SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as success,
                   SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed
            FROM login_attempts
            GROUP BY ip_address
            ORDER BY failed DESC
            LIMIT 15
        ''')
        rows = cursor.fetchall()

    if rows:
        df = pd.DataFrame(rows)
        df['success_rate'] = (df['success'] / df['count'] * 100).round(1)

        fig = go.Figure(go.Bar(
            x=df['failed'],
            y=df['ip_address'],
            orientation='h',
            marker=dict(color=DARK_BLUE_THEME['danger']),
            hovertemplate='<b>%{y}</b><br>Failed: %{x}<br>Success Rate: %{customdata}%<extra></extra>',
            customdata=df['success_rate']
        ))

        fig.update_layout(
            title="Top IPs by Failed Logins",
            xaxis_title="Failed Attempts",
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color=DARK_BLUE_THEME['text_primary'], family='Inter'),
            margin=dict(t=40, b=20, l=150, r=20),
            height=400,
        )

        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
    else:
        st.info("No failed login data available.")


def _render_failed_by_user() -> None:
    """Render failed logins by username."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT username, COUNT(*) as count,
                   SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as success,
                   SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed
            FROM login_attempts
            GROUP BY username
            ORDER BY failed DESC
            LIMIT 15
        ''')
        rows = cursor.fetchall()

    if rows:
        df = pd.DataFrame(rows)
        df['success_rate'] = (df['success'] / df['count'] * 100).round(1)

        fig = go.Figure(go.Bar(
            x=df['failed'],
            y=df['username'],
            orientation='h',
            marker=dict(color=DARK_BLUE_THEME['warning']),
            hovertemplate='<b>%{y}</b><br>Failed: %{x}<br>Success Rate: %{customdata}%<extra></extra>',
            customdata=df['success_rate']
        ))

        fig.update_layout(
            title="Top Users by Failed Logins",
            xaxis_title="Failed Attempts",
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color=DARK_BLUE_THEME['text_primary'], family='Inter'),
            margin=dict(t=40, b=20, l=150, r=20),
            height=400,
        )

        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
    else:
        st.info("No failed login data available.")


def _render_unusual_patterns() -> None:
    """Render unusual login pattern detection."""
    render_section_header("Unusual Pattern Detection", "🚨")

    patterns = _detect_unusual_patterns()

    if patterns:
        for pattern in patterns:
            severity = pattern['severity']
            color = {
                'CRITICAL': DARK_BLUE_THEME['critical'],
                'HIGH': DARK_BLUE_THEME['danger'],
                'MEDIUM': DARK_BLUE_THEME['warning'],
                'LOW': DARK_BLUE_THEME['info'],
            }.get(severity, DARK_BLUE_THEME['accent'])

            st.markdown(f"""
            <div style="
                background: {DARK_BLUE_THEME['bg_card']};
                border-left: 4px solid {color};
                border-radius: 8px;
                padding: 1rem;
                margin-bottom: 0.75rem;
            ">
                <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 0.5rem;">
                    <strong style="color: {DARK_BLUE_THEME['text_primary']};">{pattern['type']}</strong>
                    {severity_badge(severity)}
                </div>
                <div style="color: {DARK_BLUE_THEME['text_secondary']}; margin-bottom: 0.5rem;">{pattern['description']}</div>
                <div style="font-size: 0.75rem; color: {DARK_BLUE_THEME['accent']};">{pattern['details']}</div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.success("No unusual login patterns detected.")


def _detect_unusual_patterns() -> list:
    """Detect unusual login patterns."""
    patterns = []

    with get_db() as conn:
        cursor = conn.cursor()

        # Pattern 1: Multiple failed attempts from same IP in short time
        cursor.execute('''
            SELECT ip_address, COUNT(*) as failed_count,
                   MIN(timestamp) as first_attempt,
                   MAX(timestamp) as last_attempt
            FROM login_attempts
            WHERE success = 0
            GROUP BY ip_address
            HAVING failed_count >= 5
        ''')
        brute_force = cursor.fetchall()

        for row in brute_force:
            patterns.append({
                'type': 'Brute Force Attack',
                'severity': 'HIGH',
                'description': f"IP {row['ip_address']} has {row['failed_count']} failed login attempts",
                'details': f"Time window: {row['first_attempt']} to {row['last_attempt']}"
            })

        # Pattern 2: Same username, multiple IPs
        cursor.execute('''
            SELECT username, COUNT(DISTINCT ip_address) as ip_count,
                   COUNT(*) as total_attempts
            FROM login_attempts
            WHERE success = 0
            GROUP BY username
            HAVING ip_count >= 3
        ''')
        credential_stuffing = cursor.fetchall()

        for row in credential_stuffing:
            patterns.append({
                'type': 'Credential Stuffing',
                'severity': 'MEDIUM',
                'description': f"User '{row['username']}' attacked from {row['ip_count']} different IPs",
                'details': f"Total failed attempts: {row['total_attempts']}"
            })

        # Pattern 3: Successful login after many failures
        cursor.execute('''
            SELECT ip_address, username,
                   SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed_before_success
            FROM login_attempts
            WHERE success = 1
            GROUP BY ip_address, username
            HAVING failed_before_success >= 3
        ''')
        success_after_failures = cursor.fetchall()

        for row in success_after_failures:
            patterns.append({
                'type': 'Suspicious Success After Failures',
                'severity': 'HIGH',
                'description': f"IP {row['ip_address']} succeeded for '{row['username']}' after {row['failed_before_success']} failures",
                'details': "Possible credential guessing success"
            })

        # Pattern 4: Off-hours logins
        cursor.execute('''
            SELECT username, COUNT(*) as off_hours_count
            FROM login_attempts
            WHERE success = 1 AND (strftime('%H', timestamp) < '06' OR strftime('%H', timestamp) > '22')
            GROUP BY username
            HAVING off_hours_count >= 3
        ''')
        off_hours = cursor.fetchall()

        for row in off_hours:
            patterns.append({
                'type': 'Off-Hours Access',
                'severity': 'LOW',
                'description': f"User '{row['username']}' has {row['off_hours_count']} successful logins outside business hours",
                'details': "Business hours: 06:00 - 22:00"
            })

        # Pattern 5: Impossible travel (simplified - same user, different locations within short time)
        cursor.execute('''
            SELECT username, location, timestamp
            FROM login_attempts
            WHERE success = 1 AND location != 'Unknown'
            ORDER BY username, timestamp
        ''')
        locations = cursor.fetchall()

        user_locations = {}
        for row in locations:
            if row['username'] not in user_locations:
                user_locations[row['username']] = []
            user_locations[row['username']].append((row['location'], row['timestamp']))

        for user, locs in user_locations.items():
            if len(locs) >= 2:
                for i in range(1, len(locs)):
                    if locs[i][0] != locs[i-1][0]:
                        try:
                            t1 = datetime.fromisoformat(locs[i-1][1].replace('Z', '+00:00'))
                            t2 = datetime.fromisoformat(locs[i][1].replace('Z', '+00:00'))
                            if (t2 - t1).total_seconds() < 3600:  # Less than 1 hour
                                patterns.append({
                                    'type': 'Impossible Travel',
                                    'severity': 'CRITICAL',
                                    'description': f"User '{user}' logged in from {locs[i-1][0]} then {locs[i][0]} within 1 hour",
                                    'details': f"Times: {locs[i-1][1]} -> {locs[i][1]}"
                                })
                        except:
                            pass

    return patterns


def _render_login_history() -> None:
    """Render login history with filters."""
    render_section_header("Login History", "📋")

    col1, col2, col3 = st.columns(3)

    with col1:
        success_filter = st.selectbox("Status", ["All", "Successful", "Failed"], key="login_success_filter")

    with col2:
        date_filter = st.selectbox("Time Range", ["Last 24h", "Last 7d", "Last 30d", "All"], key="login_date_filter")

    with col3:
        search_user = st.text_input("Search User", placeholder="username", key="login_search_user")

    with get_db() as conn:
        cursor = conn.cursor()

        query = "SELECT timestamp, username, ip_address, success, location, user_agent FROM login_attempts WHERE 1=1"
        params = []

        if success_filter == "Successful":
            query += " AND success = 1"
        elif success_filter == "Failed":
            query += " AND success = 0"

        if date_filter == "Last 24h":
            query += " AND timestamp >= datetime('now', '-1 day')"
        elif date_filter == "Last 7d":
            query += " AND timestamp >= datetime('now', '-7 days')"
        elif date_filter == "Last 30d":
            query += " AND timestamp >= datetime('now', '-30 days')"

        if search_user:
            query += " AND username LIKE ?"
            params.append(f"%{search_user}%")

        query += " ORDER BY timestamp DESC LIMIT 100"

        cursor.execute(query, params)
        rows = cursor.fetchall()

    if rows:
        df = pd.DataFrame(rows)
        df['timestamp'] = pd.to_datetime(df['timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S')
        df['status'] = df['success'].apply(lambda s: "✅ Success" if s else "❌ Failed")

        st.dataframe(
            df[['timestamp', 'username', 'ip_address', 'status', 'location', 'user_agent']],
            column_config={
                'timestamp': 'Time',
                'username': 'User',
                'ip_address': 'IP Address',
                'status': 'Status',
                'location': 'Location',
                'user_agent': 'User Agent',
            },
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No login records match the current filters.")


def _render_geo_analysis() -> None:
    """Render geographic analysis of logins."""
    render_section_header("Geographic Analysis", "🌍")

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT location, COUNT(*) as count,
                   SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as success,
                   SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed
            FROM login_attempts
            WHERE location IS NOT NULL AND location != 'Unknown'
            GROUP BY location
            ORDER BY count DESC
        ''')
        rows = cursor.fetchall()

    if rows:
        df = pd.DataFrame(rows)
        df['failed_rate'] = (df['failed'] / df['count'] * 100).round(1)

        fig = go.Figure(go.Bar(
            x=df['count'],
            y=df['location'],
            orientation='h',
            marker=dict(
                color=[DARK_BLUE_THEME['danger'] if r > 50 else DARK_BLUE_THEME['warning'] if r > 20 else DARK_BLUE_THEME['success'] for r in df['failed_rate']]
            ),
            hovertemplate='<b>%{y}</b><br>Total: %{x}<br>Failed Rate: %{customdata}%<extra></extra>',
            customdata=df['failed_rate']
        ))

        fig.update_layout(
            title="Login Attempts by Location",
            xaxis_title="Attempts",
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color=DARK_BLUE_THEME['text_primary'], family='Inter'),
            margin=dict(t=40, b=20, l=120, r=20),
            height=350,
        )

        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})

        st.subheader("Location Details")
        for _, row in df.iterrows():
            status_color = DARK_BLUE_THEME['danger'] if row['failed_rate'] > 50 else DARK_BLUE_THEME['warning'] if row['failed_rate'] > 20 else DARK_BLUE_THEME['success']
            st.markdown(f"""
            <div style="
                background: {DARK_BLUE_THEME['bg_card']};
                border-left: 3px solid {status_color};
                padding: 0.5rem;
                margin: 0.25rem 0;
                border-radius: 4px;
            ">
                <strong>{row['location']}</strong>: {row['count']} attempts | Success: {row['success']} | Failed: {row['failed']} ({row['failed_rate']}%)
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No geographic data available.")