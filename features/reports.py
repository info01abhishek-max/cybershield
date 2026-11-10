"""Reports feature module with security reports and PDF/CSV export."""
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
import csv
import io
from database.connection import get_db
from components.ui import (
    render_page_header, render_section_header, metric_card, severity_badge,
    DARK_BLUE_THEME
)

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


def render_reports() -> None:
    """Render the reports page."""
    render_page_header("Reports", "Security reports with PDF and CSV export", "📊")

    _render_report_type_selector()
    _render_report_controls()
    _render_report_preview()
    _render_export_options()


def _render_report_type_selector() -> None:
    """Render report type selection."""
    render_section_header("Report Type", "📋")

    report_types = {
        "daily": "Daily Security Summary",
        "weekly": "Weekly Security Summary",
        "monthly": "Monthly Security Summary",
        "threat": "Threat Analysis Report",
        "network": "Network Activity Report",
        "login": "Login Security Report",
        "compliance": "Compliance Summary",
        "custom": "Custom Date Range Report",
    }

    selected = st.selectbox(
        "Select Report Type",
        options=list(report_types.keys()),
        format_func=lambda x: report_types[x],
        key="report_type_select"
    )

    st.session_state['report_type'] = selected


def _render_report_controls() -> None:
    """Render report generation controls."""
    render_section_header("Report Configuration", "⚙️")

    col1, col2, col3 = st.columns(3)

    report_type = st.session_state.get('report_type', 'daily')

    with col1:
        if report_type in ['daily', 'weekly', 'monthly']:
            if report_type == 'daily':
                default_date = datetime.now().date()
            elif report_type == 'weekly':
                default_date = datetime.now().date() - timedelta(days=datetime.now().weekday())
            else:
                default_date = datetime.now().date().replace(day=1)

            date_input = st.date_input("Report Date", value=default_date, key="report_date")
        else:
            end_date = st.date_input("End Date", value=datetime.now().date(), key="report_end_date")
            start_date = st.date_input("Start Date", value=datetime.now().date() - timedelta(days=7), key="report_start_date")

    with col2:
        include_charts = st.checkbox("Include Charts", value=True, key="report_include_charts")
        include_raw_data = st.checkbox("Include Raw Data Tables", value=False, key="report_include_raw")

    with col3:
        st.write("")  # spacing
        if st.button("📊 Generate Report", type="primary", use_container_width=True):
            _generate_report(report_type, include_charts, include_raw_data)
            st.success("Report generated!")
            st.rerun()


def _generate_report(report_type: str, include_charts: bool, include_raw_data: bool) -> dict:
    """Generate the selected report and store in session state."""
    report_data = {
        'type': report_type,
        'generated_at': datetime.now().isoformat(),
        'include_charts': include_charts,
        'include_raw_data': include_raw_data,
        'sections': {}
    }

    if report_type == 'daily':
        report_data['sections'] = _generate_daily_report()
    elif report_type == 'weekly':
        report_data['sections'] = _generate_weekly_report()
    elif report_type == 'monthly':
        report_data['sections'] = _generate_monthly_report()
    elif report_type == 'threat':
        report_data['sections'] = _generate_threat_report()
    elif report_type == 'network':
        report_data['sections'] = _generate_network_report()
    elif report_type == 'login':
        report_data['sections'] = _generate_login_report()
    elif report_type == 'compliance':
        report_data['sections'] = _generate_compliance_report()
    elif report_type == 'custom':
        start = st.session_state.get('report_start_date')
        end = st.session_state.get('report_end_date')
        report_data['sections'] = _generate_custom_report(start, end)

    st.session_state['current_report'] = report_data
    return report_data


def _render_report_preview() -> None:
    """Render the generated report preview."""
    if 'current_report' not in st.session_state:
        st.info("Generate a report to see the preview.")
        return

    report = st.session_state['current_report']

    render_section_header(f"Report Preview: {report['type'].title()}", "👁️")

    st.caption(f"Generated: {datetime.fromisoformat(report['generated_at']).strftime('%Y-%m-%d %H:%M:%S')}")

    for section_name, section_data in report['sections'].items():
        with st.expander(section_name, expanded=True):
            if isinstance(section_data, dict):
                if 'metrics' in section_data:
                    cols = st.columns(len(section_data['metrics']))
                    for i, (label, value) in enumerate(section_data['metrics'].items()):
                        with cols[i]:
                            metric_card(label, str(value))

                if 'table' in section_data:
                    df = pd.DataFrame(section_data['table'])
                    st.dataframe(df, use_container_width=True, hide_index=True)

                if 'chart' in section_data and report['include_charts']:
                    st.plotly_chart(section_data['chart'], use_container_width=True, config={'displayModeBar': False})

                if 'text' in section_data:
                    st.markdown(section_data['text'])
            elif isinstance(section_data, list):
                for item in section_data:
                    st.write(item)


def _render_export_options() -> None:
    """Render export options for the current report."""
    if 'current_report' not in st.session_state:
        return

    render_section_header("Export Report", "📤")

    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("📥 Export CSV", type="primary", use_container_width=True):
            csv_data = _export_report_csv(st.session_state['current_report'])
            st.download_button(
                label="Download CSV",
                data=csv_data,
                file_name=f"cybershield_report_{st.session_state['current_report']['type']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )

    with col2:
        if REPORTLAB_AVAILABLE:
            if st.button("📄 Export PDF", type="primary", use_container_width=True):
                pdf_data = _export_report_pdf(st.session_state['current_report'])
                st.download_button(
                    label="Download PDF",
                    data=pdf_data,
                    file_name=f"cybershield_report_{st.session_state['current_report']['type']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
        else:
            st.button("📄 Export PDF (Install reportlab)", disabled=True, use_container_width=True)
            st.caption("Run: pip install reportlab")

    with col3:
        if st.button("💾 Save to Database", use_container_width=True):
            _save_report_to_db(st.session_state['current_report'])
            st.success("Report saved to database!")


def _export_report_csv(report: dict) -> str:
    """Export report as CSV."""
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow(['CyberShield Security Report'])
    writer.writerow(['Report Type', report['type'].title()])
    writer.writerow(['Generated At', report['generated_at']])
    writer.writerow([])

    for section_name, section_data in report['sections'].items():
        writer.writerow([section_name])
        writer.writerow([])

        if isinstance(section_data, dict):
            if 'metrics' in section_data:
                writer.writerow(['Metrics'])
                for k, v in section_data['metrics'].items():
                    writer.writerow([k, v])
                writer.writerow([])

            if 'table' in section_data:
                df = pd.DataFrame(section_data['table'])
                writer.writerow(df.columns.tolist())
                for _, row in df.iterrows():
                    writer.writerow(row.tolist())
                writer.writerow([])

            if 'text' in section_data:
                writer.writerow(['Notes'])
                writer.writerow([section_data['text']])
                writer.writerow([])

    return output.getvalue()


def _export_report_pdf(report: dict) -> bytes:
    """Export report as PDF using reportlab."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.5*inch, bottomMargin=0.5*inch)
    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=24,
        textColor=colors.HexColor(DARK_BLUE_THEME['accent']),
        spaceAfter=12,
        alignment=TA_CENTER
    )

    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor(DARK_BLUE_THEME['text_primary']),
        spaceBefore=12,
        spaceAfter=6,
    )

    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor(DARK_BLUE_THEME['text_secondary']),
        spaceAfter=4,
    )

    story = []

    # Title page
    story.append(Paragraph("CyberShield Security Report", title_style))
    story.append(Spacer(1, 0.2*inch))
    story.append(Paragraph(f"Report Type: {report['type'].title()}", body_style))
    story.append(Paragraph(f"Generated: {datetime.fromisoformat(report['generated_at']).strftime('%Y-%m-%d %H:%M:%S')}", body_style))
    story.append(Spacer(1, 0.3*inch))

    for section_name, section_data in report['sections'].items():
        story.append(Paragraph(section_name, heading_style))
        story.append(Spacer(1, 0.1*inch))

        if isinstance(section_data, dict):
            if 'metrics' in section_data:
                # Metrics table
                data = [['Metric', 'Value']]
                for k, v in section_data['metrics'].items():
                    data.append([k, str(v)])

                table = Table(data, colWidths=[3*inch, 3*inch])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(DARK_BLUE_THEME['accent'])),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor(DARK_BLUE_THEME['bg_card'])),
                    ('GRID', (0, 0), (-1, -1), 1, colors.HexColor(DARK_BLUE_THEME['border'])),
                ]))
                story.append(table)
                story.append(Spacer(1, 0.15*inch))

            if 'table' in section_data:
                df = pd.DataFrame(section_data['table'])
                if len(df) > 0:
                    data = [df.columns.tolist()] + df.values.tolist()
                    col_width = 6.5*inch / len(df.columns)
                    table = Table(data, colWidths=[col_width]*len(df.columns))
                    table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(DARK_BLUE_THEME['accent'])),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 8),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor(DARK_BLUE_THEME['bg_card'])),
                        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor(DARK_BLUE_THEME['border'])),
                    ]))
                    story.append(table)
                    story.append(Spacer(1, 0.15*inch))

            if 'text' in section_data:
                story.append(Paragraph(section_data['text'], body_style))
                story.append(Spacer(1, 0.1*inch))

    doc.build(story)
    buffer.seek(0)
    return buffer.read()


def _save_report_to_db(report: dict) -> None:
    """Save report to database for history."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                report_type TEXT NOT NULL,
                content TEXT NOT NULL
            )
        ''')
        cursor.execute(
            'INSERT INTO reports (report_type, content) VALUES (?, ?)',
            (report['type'], json.dumps(report))
        )


def _generate_daily_report() -> dict:
    """Generate daily security summary."""
    target_date = st.session_state.get('report_date', datetime.now().date())
    start_dt = datetime.combine(target_date, datetime.min.time())
    end_dt = start_dt + timedelta(days=1)

    sections = {}

    with get_db() as conn:
        cursor = conn.cursor()

        # Threat metrics
        cursor.execute('''
            SELECT severity, COUNT(*) as count
            FROM threat_detections
            WHERE timestamp >= ? AND timestamp < ?
            GROUP BY severity
        ''', (start_dt.isoformat(), end_dt.isoformat()))
        threat_severity = cursor.fetchall()

        cursor.execute('''
            SELECT COUNT(*) as total FROM threat_detections
            WHERE timestamp >= ? AND timestamp < ?
        ''', (start_dt.isoformat(), end_dt.isoformat()))
        total_threats = cursor.fetchone()[0]

        cursor.execute('''
            SELECT COUNT(*) as total FROM security_events
            WHERE timestamp >= ? AND timestamp < ?
        ''', (start_dt.isoformat(), end_dt.isoformat()))
        total_events = cursor.fetchone()[0]

        cursor.execute('''
            SELECT COUNT(*) as total FROM alerts
            WHERE timestamp >= ? AND timestamp < ?
        ''', (start_dt.isoformat(), end_dt.isoformat()))
        total_alerts = cursor.fetchone()[0]

        cursor.execute('''
            SELECT COUNT(*) as total FROM login_attempts
            WHERE timestamp >= ? AND timestamp < ?
        ''', (start_dt.isoformat(), end_dt.isoformat()))
        total_logins = cursor.fetchone()[0]

        cursor.execute('''
            SELECT COUNT(*) as total FROM login_attempts
            WHERE timestamp >= ? AND timestamp < ? AND success = 0
        ''', (start_dt.isoformat(), end_dt.isoformat()))
        failed_logins = cursor.fetchone()[0]

        cursor.execute('''
            SELECT COUNT(*) as total FROM network_scans
            WHERE timestamp >= ? AND timestamp < ?
        ''', (start_dt.isoformat(), end_dt.isoformat()))
        total_scans = cursor.fetchone()[0]

        cursor.execute('''
            SELECT COUNT(*) as total FROM phishing_urls
            WHERE timestamp >= ? AND timestamp < ?
        ''', (start_dt.isoformat(), end_dt.isoformat()))
        total_phishing = cursor.fetchone()[0]

        cursor.execute('''
            SELECT COUNT(*) as total FROM file_scans
            WHERE timestamp >= ? AND timestamp < ?
        ''', (start_dt.isoformat(), end_dt.isoformat()))
        total_files = cursor.fetchone()[0]

    sections['Executive Summary'] = {
        'metrics': {
            'Date': target_date.strftime('%Y-%m-%d'),
            'Total Threats': total_threats,
            'Total Security Events': total_events,
            'Total Alerts': total_alerts,
            'Total Login Attempts': total_logins,
            'Failed Logins': failed_logins,
            'Network Scans': total_scans,
            'Phishing URLs Checked': total_phishing,
            'Files Scanned': total_files,
        },
        'text': f"Daily security summary for {target_date.strftime('%Y-%m-%d')}. This report provides an overview of all security activities detected during the 24-hour period."
    }

    if threat_severity:
        sections['Threat Breakdown by Severity'] = {
            'table': [{'Severity': row['severity'], 'Count': row['count']} for row in threat_severity],
        }

    return sections


def _generate_weekly_report() -> dict:
    """Generate weekly security summary."""
    target_date = st.session_state.get('report_date', datetime.now().date())
    start_dt = datetime.combine(target_date - timedelta(days=target_date.weekday()), datetime.min.time())
    end_dt = start_dt + timedelta(days=7)

    sections = {}

    with get_db() as conn:
        cursor = conn.cursor()

        cursor.execute('''
            SELECT date(timestamp) as day, COUNT(*) as count
            FROM threat_detections
            WHERE timestamp >= ? AND timestamp < ?
            GROUP BY date(timestamp)
            ORDER BY day
        ''', (start_dt.isoformat(), end_dt.isoformat()))
        threats_by_day = cursor.fetchall()

        cursor.execute('''
            SELECT threat_type, COUNT(*) as count
            FROM threat_detections
            WHERE timestamp >= ? AND timestamp < ?
            GROUP BY threat_type
            ORDER BY count DESC
        ''', (start_dt.isoformat(), end_dt.isoformat()))
        threats_by_type = cursor.fetchall()

        cursor.execute('''
            SELECT severity, COUNT(*) as count
            FROM alerts
            WHERE timestamp >= ? AND timestamp < ?
            GROUP BY severity
        ''', (start_dt.isoformat(), end_dt.isoformat()))
        alerts_by_severity = cursor.fetchall()

        cursor.execute('''
            SELECT date(timestamp) as day,
                   SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
                   SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed
            FROM login_attempts
            WHERE timestamp >= ? AND timestamp < ?
            GROUP BY date(timestamp)
            ORDER BY day
        ''', (start_dt.isoformat(), end_dt.isoformat()))
        logins_by_day = cursor.fetchall()

    sections['Weekly Overview'] = {
        'metrics': {
            'Week Starting': start_dt.strftime('%Y-%m-%d'),
            'Week Ending': (end_dt - timedelta(days=1)).strftime('%Y-%m-%d'),
            'Days Covered': 7,
        },
        'text': f"Weekly security summary from {start_dt.strftime('%Y-%m-%d')} to {(end_dt - timedelta(days=1)).strftime('%Y-%m-%d')}."
    }

    if threats_by_day:
        sections['Daily Threat Trend'] = {
            'table': [{'Date': row['day'], 'Threats': row['count']} for row in threats_by_day],
        }

    if threats_by_type:
        sections['Top Threat Types'] = {
            'table': [{'Threat Type': row['threat_type'], 'Count': row['count']} for row in threats_by_type],
        }

    if alerts_by_severity:
        sections['Alerts by Severity'] = {
            'table': [{'Severity': row['severity'], 'Count': row['count']} for row in alerts_by_severity],
        }

    if logins_by_day:
        sections['Daily Login Activity'] = {
            'table': [{'Date': row['day'], 'Successful': row['successful'], 'Failed': row['failed']} for row in logins_by_day],
        }

    return sections


def _generate_monthly_report() -> dict:
    """Generate monthly security summary."""
    target_date = st.session_state.get('report_date', datetime.now().date())
    start_dt = datetime.combine(target_date.replace(day=1), datetime.min.time())
    if target_date.month == 12:
        end_dt = start_dt.replace(year=target_date.year + 1, month=1)
    else:
        end_dt = start_dt.replace(month=target_date.month + 1)

    sections = {}

    with get_db() as conn:
        cursor = conn.cursor()

        cursor.execute('''
            SELECT strftime('%W', timestamp) as week, COUNT(*) as count
            FROM threat_detections
            WHERE timestamp >= ? AND timestamp < ?
            GROUP BY strftime('%W', timestamp)
            ORDER BY week
        ''', (start_dt.isoformat(), end_dt.isoformat()))
        threats_by_week = cursor.fetchall()

        cursor.execute('''
            SELECT alert_type, COUNT(*) as count
            FROM alerts
            WHERE timestamp >= ? AND timestamp < ?
            GROUP BY alert_type
            ORDER BY count DESC
        ''', (start_dt.isoformat(), end_dt.isoformat()))
        alerts_by_type = cursor.fetchall()

        cursor.execute('''
            SELECT status, COUNT(*) as count
            FROM security_events
            WHERE timestamp >= ? AND timestamp < ?
            GROUP BY status
        ''', (start_dt.isoformat(), end_dt.isoformat()))
        events_by_status = cursor.fetchall()

    sections['Monthly Overview'] = {
        'metrics': {
            'Month': target_date.strftime('%B %Y'),
            'Start Date': start_dt.strftime('%Y-%m-%d'),
            'End Date': (end_dt - timedelta(days=1)).strftime('%Y-%m-%d'),
        },
        'text': f"Monthly security summary for {target_date.strftime('%B %Y')}."
    }

    if threats_by_week:
        sections['Weekly Threat Trend'] = {
            'table': [{'Week': row['week'], 'Threats': row['count']} for row in threats_by_week],
        }

    if alerts_by_type:
        sections['Alert Types'] = {
            'table': [{'Alert Type': row['alert_type'], 'Count': row['count']} for row in alerts_by_type],
        }

    if events_by_status:
        sections['Event Resolution Status'] = {
            'table': [{'Status': row['status'], 'Count': row['count']} for row in events_by_status],
        }

    return sections


def _generate_threat_report() -> dict:
    """Generate detailed threat analysis report."""
    sections = {}

    with get_db() as conn:
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM threat_detections
            ORDER BY timestamp DESC
            LIMIT 100
        ''')
        threats = cursor.fetchall()

        cursor.execute('''
            SELECT threat_type, severity, COUNT(*) as count
            FROM threat_detections
            GROUP BY threat_type, severity
            ORDER BY count DESC
        ''')
        threat_matrix = cursor.fetchall()

        cursor.execute('''
            SELECT source_ip, COUNT(*) as count
            FROM threat_detections
            WHERE source_ip IS NOT NULL
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT 20
        ''')
        top_sources = cursor.fetchall()

    sections['Recent Threats'] = {
        'table': [{
            'Time': row['timestamp'],
            'Type': row['threat_type'],
            'Severity': row['severity'],
            'Source IP': row['source_ip'] or 'N/A',
            'Target': row['target'] or 'N/A',
            'Mitigated': 'Yes' if row['mitigated'] else 'No',
        } for row in threats],
    }

    if threat_matrix:
        sections['Threat Type vs Severity Matrix'] = {
            'table': [{'Threat Type': row['threat_type'], 'Severity': row['severity'], 'Count': row['count']} for row in threat_matrix],
        }

    if top_sources:
        sections['Top Threat Sources'] = {
            'table': [{'Source IP': row['source_ip'], 'Threat Count': row['count']} for row in top_sources],
        }

    return sections


def _generate_network_report() -> dict:
    """Generate network activity report."""
    sections = {}

    with get_db() as conn:
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM network_scans
            ORDER BY timestamp DESC
            LIMIT 50
        ''')
        scans = cursor.fetchall()

        cursor.execute('''
            SELECT status, COUNT(*) as count
            FROM network_scans
            GROUP BY status
        ''')
        scan_status = cursor.fetchall()

        cursor.execute('''
            SELECT target_ip, COUNT(*) as count
            FROM network_scans
            GROUP BY target_ip
            ORDER BY count DESC
            LIMIT 20
        ''')
        top_targets = cursor.fetchall()

    sections['Recent Network Scans'] = {
        'table': [{
            'Time': row['timestamp'],
            'Target': row['target_ip'],
            'Type': row['scan_type'],
            'Status': row['status'],
            'Open Ports': row['open_ports'] or 'N/A',
            'Vulnerabilities': row['vulnerabilities'] or 'None',
        } for row in scans],
    }

    if scan_status:
        sections['Scan Status Summary'] = {
            'table': [{'Status': row['status'], 'Count': row['count']} for row in scan_status],
        }

    if top_targets:
        sections['Most Scanned Targets'] = {
            'table': [{'Target IP': row['target_ip'], 'Scan Count': row['count']} for row in top_targets],
        }

    return sections


def _generate_login_report() -> dict:
    """Generate login security report."""
    sections = {}

    with get_db() as conn:
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM login_attempts
            ORDER BY timestamp DESC
            LIMIT 100
        ''')
        logins = cursor.fetchall()

        cursor.execute('''
            SELECT username, COUNT(*) as total,
                   SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
                   SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed
            FROM login_attempts
            GROUP BY username
            ORDER BY failed DESC
        ''')
        user_stats = cursor.fetchall()

        cursor.execute('''
            SELECT ip_address, COUNT(*) as total,
                   SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
                   SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed
            FROM login_attempts
            GROUP BY ip_address
            ORDER BY failed DESC
            LIMIT 20
        ''')
        ip_stats = cursor.fetchall()

        cursor.execute('''
            SELECT location, COUNT(*) as total,
                   SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
                   SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed
            FROM login_attempts
            WHERE location IS NOT NULL AND location != 'Unknown'
            GROUP BY location
            ORDER BY failed DESC
        ''')
        location_stats = cursor.fetchall()

    sections['Recent Login Attempts'] = {
        'table': [{
            'Time': row['timestamp'],
            'User': row['username'],
            'IP': row['ip_address'],
            'Status': 'Success' if row['success'] else 'Failed',
            'Location': row['location'] or 'Unknown',
        } for row in logins],
    }

    if user_stats:
        sections['User Login Statistics'] = {
            'table': [{
                'Username': row['username'],
                'Total': row['total'],
                'Successful': row['successful'],
                'Failed': row['failed'],
                'Fail Rate %': f"{(row['failed']/row['total']*100):.1f}" if row['total'] > 0 else "0"
            } for row in user_stats],
        }

    if ip_stats:
        sections['IP Address Login Statistics'] = {
            'table': [{
                'IP Address': row['ip_address'],
                'Total': row['total'],
                'Successful': row['successful'],
                'Failed': row['failed'],
                'Fail Rate %': f"{(row['failed']/row['total']*100):.1f}" if row['total'] > 0 else "0"
            } for row in ip_stats],
        }

    if location_stats:
        sections['Geographic Login Distribution'] = {
            'table': [{
                'Location': row['location'],
                'Total': row['total'],
                'Successful': row['successful'],
                'Failed': row['failed'],
            } for row in location_stats],
        }

    return sections


def _generate_compliance_report() -> dict:
    """Generate compliance summary report."""
    sections = {}

    with get_db() as conn:
        cursor = conn.cursor()

        cursor.execute('''
            SELECT COUNT(*) as total,
                   SUM(CASE WHEN acknowledged = 1 THEN 1 ELSE 0 END) as acknowledged
            FROM alerts
        ''')
        alert_stats = cursor.fetchone()

        cursor.execute('''
            SELECT status, COUNT(*) as count
            FROM security_events
            GROUP BY status
        ''')
        event_status = cursor.fetchall()

        cursor.execute('''
            SELECT COUNT(*) as total FROM file_scans
        ''')
        file_total = cursor.fetchone()[0]

        cursor.execute('''
            SELECT COUNT(*) as total FROM phishing_urls
        ''')
        phishing_total = cursor.fetchone()[0]

    ack_rate = (alert_stats['acknowledged'] / alert_stats['total'] * 100) if alert_stats['total'] > 0 else 0

    sections['Compliance Metrics'] = {
        'metrics': {
            'Total Alerts': alert_stats['total'],
            'Acknowledged': alert_stats['acknowledged'],
            'Acknowledgment Rate': f"{ack_rate:.1f}%",
            'Total Events': sum(row['count'] for row in event_status),
            'Resolved Events': next((row['count'] for row in event_status if row['status'] == 'RESOLVED'), 0),
            'Investigating Events': next((row['count'] for row in event_status if row['status'] == 'INVESTIGATING'), 0),
            'Files Scanned': file_total,
            'Phishing URLs Analyzed': phishing_total,
        },
        'text': "Compliance summary showing key security operations metrics. High acknowledgment rates and timely resolution indicate effective security operations."
    }

    if event_status:
        sections['Event Resolution Status'] = {
            'table': [{'Status': row['status'], 'Count': row['count']} for row in event_status],
        }

    return sections


def _generate_custom_report(start_date, end_date) -> dict:
    """Generate custom date range report."""
    sections = {}

    if not start_date or not end_date:
        return sections

    start_dt = datetime.combine(start_date, datetime.min.time())
    end_dt = datetime.combine(end_date, datetime.max.time())

    with get_db() as conn:
        cursor = conn.cursor()

        cursor.execute('''
            SELECT 'Threats' as category, COUNT(*) as count FROM threat_detections WHERE timestamp BETWEEN ? AND ?
            UNION ALL SELECT 'Events', COUNT(*) FROM security_events WHERE timestamp BETWEEN ? AND ?
            UNION ALL SELECT 'Alerts', COUNT(*) FROM alerts WHERE timestamp BETWEEN ? AND ?
            UNION ALL SELECT 'Logins', COUNT(*) FROM login_attempts WHERE timestamp BETWEEN ? AND ?
            UNION ALL SELECT 'Scans', COUNT(*) FROM network_scans WHERE timestamp BETWEEN ? AND ?
            UNION ALL SELECT 'Files', COUNT(*) FROM file_scans WHERE timestamp BETWEEN ? AND ?
        ''', (start_dt.isoformat(), end_dt.isoformat()) * 6)
        totals = cursor.fetchall()

    sections['Custom Report Summary'] = {
        'metrics': {
            'Start Date': start_date.strftime('%Y-%m-%d'),
            'End Date': end_date.strftime('%Y-%m-%d'),
            'Days': (end_date - start_date).days + 1,
        },
    }

    if totals:
        sections['Activity Totals'] = {
            'table': [{'Category': row['category'], 'Count': row['count']} for row in totals],
        }

    return sections