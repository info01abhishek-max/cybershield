"""Reusable UI components for CyberShield dashboard."""
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta


DARK_BLUE_THEME = {
    'bg_primary': '#0a0f1a',
    'bg_secondary': '#111827',
    'bg_card': '#1e293b',
    'border': '#2d3a4f',
    'text_primary': '#f1f5f9',
    'text_secondary': '#94a3b8',
    'accent': '#0ea5e9',
    'accent_glow': '#38bdf8',
    'success': '#10b981',
    'warning': '#f59e0b',
    'danger': '#ef4444',
    'info': '#06b6d4',
    'critical': '#f43f5e',
}


def apply_custom_css() -> None:
    """Apply custom CSS for dark blue cybersecurity theme."""
    st.markdown(f"""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@300;400;500;600;700&display=swap');

        .stApp {{
            background-color: {DARK_BLUE_THEME['bg_primary']};
            color: {DARK_BLUE_THEME['text_primary']};
        }}

        .main .block-container {{
            padding-top: 1rem;
            padding-bottom: 2rem;
            max-width: 100%;
        }}

        [data-testid="stSidebar"] {{
            background-color: {DARK_BLUE_THEME['bg_secondary']};
            border-right: 1px solid {DARK_BLUE_THEME['border']};
        }}

        [data-testid="stSidebar"] > div:first-child {{
            padding-top: 1rem;
        }}

        .stMetric {{
            background-color: {DARK_BLUE_THEME['bg_card']};
            border: 1px solid {DARK_BLUE_THEME['border']};
            border-radius: 12px;
            padding: 1.25rem;
        }}

        .stMetric label {{
            color: {DARK_BLUE_THEME['text_secondary']} !important;
            font-size: 0.875rem !important;
            font-weight: 500 !important;
        }}

        .stMetric [data-testid="stMetricValue"] {{
            color: {DARK_BLUE_THEME['text_primary']} !important;
            font-size: 2rem !important;
            font-weight: 700 !important;
            font-family: 'JetBrains Mono', monospace !important;
        }}

        .stMetric [data-testid="stMetricDelta"] {{
            color: {DARK_BLUE_THEME['success']} !important;
        }}

        div[data-testid="stExpander"] {{
            background-color: {DARK_BLUE_THEME['bg_card']};
            border: 1px solid {DARK_BLUE_THEME['border']};
            border-radius: 12px;
        }}

        .stButton > button {{
            background-color: {DARK_BLUE_THEME['bg_card']};
            color: {DARK_BLUE_THEME['text_primary']};
            border: 1px solid {DARK_BLUE_THEME['border']};
            border-radius: 8px;
            font-weight: 500;
            transition: all 0.2s ease;
        }}

        .stButton > button:hover {{
            background-color: {DARK_BLUE_THEME['accent']};
            border-color: {DARK_BLUE_THEME['accent']};
            color: {DARK_BLUE_THEME['bg_primary']};
        }}

        .stButton > button[kind="primary"] {{
            background-color: {DARK_BLUE_THEME['accent']};
            border-color: {DARK_BLUE_THEME['accent']};
            color: {DARK_BLUE_THEME['bg_primary']};
        }}

        .stTabs [data-baseweb="tab-list"] {{
            gap: 4px;
            background-color: {DARK_BLUE_THEME['bg_card']};
            border-radius: 12px;
            padding: 4px;
        }}

        .stTabs [data-baseweb="tab"] {{
            background-color: transparent;
            color: {DARK_BLUE_THEME['text_secondary']};
            border-radius: 8px;
            font-weight: 500;
        }}

        .stTabs [aria-selected="true"] {{
            background-color: {DARK_BLUE_THEME['accent']} !important;
            color: {DARK_BLUE_THEME['bg_primary']} !important;
        }}

        .stDataFrame {{
            background-color: {DARK_BLUE_THEME['bg_card']};
            border: 1px solid {DARK_BLUE_THEME['border']};
            border-radius: 12px;
        }}

        .stSelectbox > div > div {{
            background-color: {DARK_BLUE_THEME['bg_card']};
            border-color: {DARK_BLUE_THEME['border']};
        }}

        .stTextInput > div > div > input {{
            background-color: {DARK_BLUE_THEME['bg_card']};
            border-color: {DARK_BLUE_THEME['border']};
            color: {DARK_BLUE_THEME['text_primary']};
        }}

        .stSlider > div > div > div > div {{
            background-color: {DARK_BLUE_THEME['accent']};
        }}

        .stProgress > div > div > div > div {{
            background-color: {DARK_BLUE_THEME['accent']};
        }}

        .alert-card {{
            background-color: {DARK_BLUE_THEME['bg_card']};
            border: 1px solid {DARK_BLUE_THEME['border']};
            border-left: 4px solid {DARK_BLUE_THEME['accent']};
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 0.75rem;
            transition: all 0.2s ease;
        }}

        .alert-card:hover {{
            border-color: {DARK_BLUE_THEME['accent']};
            box-shadow: 0 4px 12px rgba(14, 165, 233, 0.15);
        }}

        .alert-critical {{ border-left-color: {DARK_BLUE_THEME['critical']}; }}
        .alert-high {{ border-left-color: {DARK_BLUE_THEME['danger']}; }}
        .alert-medium {{ border-left-color: {DARK_BLUE_THEME['warning']}; }}
        .alert-low {{ border-left-color: {DARK_BLUE_THEME['info']}; }}
        .alert-info {{ border-left-color: {DARK_BLUE_THEME['success']}; }}

        .status-indicator {{
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-weight: 500;
            font-size: 0.875rem;
        }}

        .status-secure {{
            background-color: rgba(16, 185, 129, 0.15);
            color: {DARK_BLUE_THEME['success']};
            border: 1px solid rgba(16, 185, 129, 0.3);
        }}

        .status-warning {{
            background-color: rgba(245, 158, 11, 0.15);
            color: {DARK_BLUE_THEME['warning']};
            border: 1px solid rgba(245, 158, 11, 0.3);
        }}

        .status-danger {{
            background-color: rgba(239, 68, 68, 0.15);
            color: {DARK_BLUE_THEME['danger']};
            border: 1px solid rgba(239, 68, 68, 0.3);
        }}

        .severity-badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .badge-critical {{ background-color: rgba(244, 63, 94, 0.2); color: {DARK_BLUE_THEME['critical']}; }}
        .badge-high {{ background-color: rgba(239, 68, 68, 0.2); color: {DARK_BLUE_THEME['danger']}; }}
        .badge-medium {{ background-color: rgba(245, 158, 11, 0.2); color: {DARK_BLUE_THEME['warning']}; }}
        .badge-low {{ background-color: rgba(6, 182, 212, 0.2); color: {DARK_BLUE_THEME['info']}; }}
        .badge-info {{ background-color: rgba(16, 185, 129, 0.2); color: {DARK_BLUE_THEME['success']}; }}

        .sidebar-nav-item {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.75rem 1rem;
            border-radius: 8px;
            color: {DARK_BLUE_THEME['text_secondary']};
            text-decoration: none;
            transition: all 0.2s ease;
            margin-bottom: 0.25rem;
            cursor: pointer;
        }}

        .sidebar-nav-item:hover {{
            background-color: {DARK_BLUE_THEME['bg_card']};
            color: {DARK_BLUE_THEME['text_primary']};
        }}

        .sidebar-nav-item.active {{
            background-color: rgba(14, 165, 233, 0.15);
            color: {DARK_BLUE_THEME['accent']};
            border-left: 3px solid {DARK_BLUE_THEME['accent']};
        }}

        .sidebar-nav-icon {{
            font-size: 1.25rem;
            width: 24px;
            text-align: center;
        }}

        .logo-container {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 1rem;
            margin-bottom: 1.5rem;
            border-bottom: 1px solid {DARK_BLUE_THEME['border']};
        }}

        .logo-icon {{
            font-size: 2rem;
            color: {DARK_BLUE_THEME['accent']};
        }}

        .logo-text {{
            font-size: 1.5rem;
            font-weight: 700;
            color: {DARK_BLUE_THEME['text_primary']};
            font-family: 'Inter', sans-serif;
        }}

        .version-badge {{
            background-color: {DARK_BLUE_THEME['bg_card']};
            color: {DARK_BLUE_THEME['text_secondary']};
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 500;
        }}
    </style>
    """, unsafe_allow_html=True)


def render_sidebar_logo() -> None:
    """Render the sidebar logo."""
    st.sidebar.markdown("""
    <div class="logo-container">
        <span class="logo-icon">🛡️</span>
        <span class="logo-text">CyberShield</span>
        <span class="version-badge">v1.0.0</span>
    </div>
    """, unsafe_allow_html=True)


def render_sidebar_navigation(current_page: str) -> str:
    """Render sidebar navigation and return selected page."""
    nav_items = [
        ("Dashboard", "📊", "dashboard"),
        ("Network Monitor", "🌐", "network_monitor"),
        ("Threat Detection", "🔍", "threat_detection"),
        ("Phishing Detector", "🎣", "phishing_detector"),
        ("File Scanner", "📁", "file_scanner"),
        ("AI Security Analyzer", "🤖", "ai_analyzer"),
        ("Login Security", "🔐", "login_security"),
        ("Alerts Center", "🚨", "alerts_center"),
        ("Reports", "📋", "reports"),
        ("Settings", "⚙️", "settings"),
    ]

    selected = current_page

    for label, icon, key in nav_items:
        is_active = "active" if key == current_page else ""
        if st.sidebar.button(
            f"{icon}  {label}",
            key=f"nav_{key}",
            use_container_width=True,
            type="primary" if is_active else "secondary"
        ):
            selected = key

    st.sidebar.markdown("---")
    st.sidebar.markdown("""
    <div style="padding: 0 1rem; color: #64748b; font-size: 0.75rem; text-align: center;">
        CyberShield Security Platform<br>
        Enterprise Grade Protection
    </div>
    """, unsafe_allow_html=True)

    return selected


def metric_card(label: str, value: str, delta: Optional[str] = None, delta_color: str = "normal") -> None:
    """Render a metric card."""
    st.metric(label=label, value=value, delta=delta, delta_color=delta_color)


def status_badge(status: str) -> str:
    """Return HTML for a status badge."""
    status_map = {
        'secure': ('status-secure', '🟢 Secure'),
        'warning': ('status-warning', '🟡 Warning'),
        'danger': ('status-danger', '🔴 Critical'),
        'online': ('status-secure', '🟢 Online'),
        'offline': ('status-danger', '🔴 Offline'),
        'scanning': ('status-warning', '🟡 Scanning'),
    }
    css_class, text = status_map.get(status.lower(), ('status-secure', status))
    return f'<span class="status-indicator {css_class}">{text}</span>'


def severity_badge(severity: str) -> str:
    """Return HTML for a severity badge."""
    severity_map = {
        'critical': 'badge-critical',
        'high': 'badge-high',
        'medium': 'badge-medium',
        'low': 'badge-low',
        'info': 'badge-info',
    }
    css_class = severity_map.get(severity.lower(), 'badge-info')
    return f'<span class="severity-badge {css_class}">{severity.upper()}</span>'


def alert_card(alert_type: str, severity: str, title: str, message: str, timestamp: str, acknowledged: bool = False) -> None:
    """Render an alert card."""
    severity_class = f"alert-{severity.lower()}"
    ack_text = " ✓ Acknowledged" if acknowledged else ""

    st.markdown(f"""
    <div class="alert-card {severity_class}">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.5rem;">
            <div>
                <span style="font-weight: 600; color: {DARK_BLUE_THEME['text_primary']};">{title}</span>
                {severity_badge(severity)}
            </div>
            <span style="color: {DARK_BLUE_THEME['text_secondary']}; font-size: 0.75rem;">{timestamp}</span>
        </div>
        <div style="color: {DARK_BLUE_THEME['text_secondary']}; margin-bottom: 0.5rem;">{message}</div>
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <span style="color: {DARK_BLUE_THEME['accent']}; font-size: 0.75rem; font-weight: 500;">{alert_type}{ack_text}</span>
        </div>
    </div>
    """, unsafe_allow_html=True)


def create_severity_chart(data: Dict[str, int]) -> go.Figure:
    """Create a threat severity donut chart."""
    labels = list(data.keys())
    values = list(data.values())
    colors = [
        DARK_BLUE_THEME['critical'],
        DARK_BLUE_THEME['danger'],
        DARK_BLUE_THEME['warning'],
        DARK_BLUE_THEME['info'],
        DARK_BLUE_THEME['success'],
    ]

    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=0.6,
        marker=dict(colors=colors, line=dict(color=DARK_BLUE_THEME['bg_card'], width=2)),
        textinfo='label+percent',
        textfont=dict(color=DARK_BLUE_THEME['text_primary'], size=12),
        hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>',
    )])

    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color=DARK_BLUE_THEME['text_primary'], family='Inter'),
        showlegend=True,
        legend=dict(
            orientation="v",
            yanchor="middle",
            y=0.5,
            xanchor="left",
            x=1.05,
            font=dict(size=11, color=DARK_BLUE_THEME['text_secondary']),
            bgcolor=DARK_BLUE_THEME['bg_card'],
            bordercolor=DARK_BLUE_THEME['border'],
            borderwidth=1,
        ),
        margin=dict(t=20, b=20, l=20, r=20),
        height=300,
    )

    return fig


def create_activity_chart(dates: List[str], values: List[int], label: str = "Activity") -> go.Figure:
    """Create a line chart for security activity over time."""
    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=dates,
        y=values,
        mode='lines+markers',
        name=label,
        line=dict(color=DARK_BLUE_THEME['accent'], width=3, shape='spline'),
        marker=dict(size=6, color=DARK_BLUE_THEME['accent'], line=dict(width=2, color=DARK_BLUE_THEME['bg_primary'])),
        fill='tozeroy',
        fillcolor=f'rgba(14, 165, 233, 0.1)',
        hovertemplate='<b>%{x}</b><br>' + label + ': %{y}<extra></extra>',
    ))

    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color=DARK_BLUE_THEME['text_primary'], family='Inter'),
        xaxis=dict(
            gridcolor=DARK_BLUE_THEME['border'],
            tickfont=dict(color=DARK_BLUE_THEME['text_secondary'], size=10),
            showgrid=True,
            zeroline=False,
        ),
        yaxis=dict(
            gridcolor=DARK_BLUE_THEME['border'],
            tickfont=dict(color=DARK_BLUE_THEME['text_secondary'], size=10),
            showgrid=True,
            zeroline=False,
        ),
        margin=dict(t=20, b=20, l=40, r=20),
        height=300,
        hovermode='x unified',
        showlegend=False,
    )

    return fig


def create_bar_chart(labels: List[str], values: List[int], colors: List[str] = None) -> go.Figure:
    """Create a horizontal bar chart."""
    if colors is None:
        colors = [DARK_BLUE_THEME['accent']] * len(labels)

    fig = go.Figure(data=[go.Bar(
        y=labels,
        x=values,
        orientation='h',
        marker=dict(
            color=colors,
            line=dict(color=DARK_BLUE_THEME['border'], width=1),
        ),
        hovertemplate='<b>%{y}</b><br>Count: %{x}<extra></extra>',
    )])

    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color=DARK_BLUE_THEME['text_primary'], family='Inter'),
        xaxis=dict(
            gridcolor=DARK_BLUE_THEME['border'],
            tickfont=dict(color=DARK_BLUE_THEME['text_secondary'], size=10),
            showgrid=True,
            zeroline=False,
        ),
        yaxis=dict(
            tickfont=dict(color=DARK_BLUE_THEME['text_primary'], size=11),
            showgrid=False,
            zeroline=False,
        ),
        margin=dict(t=20, b=20, l=120, r=20),
        height=300,
    )

    return fig


def render_page_header(title: str, subtitle: str = "", icon: str = "") -> None:
    """Render a consistent page header."""
    st.markdown(f"""
    <div style="margin-bottom: 1.5rem;">
        <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem;">
            <span style="font-size: 1.75rem;">{icon}</span>
            <h1 style="margin: 0; font-size: 1.75rem; font-weight: 700; color: {DARK_BLUE_THEME['text_primary']};">{title}</h1>
        </div>
        {f'<p style="margin: 0; color: {DARK_BLUE_THEME["text_secondary"]}; font-size: 1rem;">{subtitle}</p>' if subtitle else ''}
    </div>
    """, unsafe_allow_html=True)


def render_section_header(title: str, icon: str = "") -> None:
    """Render a section header."""
    st.markdown(f"""
    <div style="display: flex; align-items: center; gap: 0.5rem; margin: 1.5rem 0 1rem 0;">
        <span style="font-size: 1.25rem;">{icon}</span>
        <h2 style="margin: 0; font-size: 1.25rem; font-weight: 600; color: {DARK_BLUE_THEME['text_primary']};">{title}</h2>
    </div>
    """, unsafe_allow_html=True)


def get_demo_dates(days: int = 7) -> List[str]:
    """Generate demo dates for charts."""
    dates = []
    for i in range(days):
        date = datetime.now() - timedelta(days=days - 1 - i)
        dates.append(date.strftime('%m/%d'))
    return dates


def format_timestamp(dt: datetime) -> str:
    """Format timestamp for display."""
    return dt.strftime('%Y-%m-%d %H:%M:%S')