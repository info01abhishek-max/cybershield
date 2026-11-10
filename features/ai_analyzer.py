"""AI Security Analyzer feature module with ML-based security classification."""
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import numpy as np
import json
from datetime import datetime
from typing import List
from database.connection import get_db
from components.ui import (
    render_page_header, render_section_header, metric_card, severity_badge,
    create_bar_chart, DARK_BLUE_THEME
)
from ml_analyzer.analyzer import (
    get_ai_analyzer, SecurityModel, AnomalyDetector, DatasetPreparator,
    generate_sample_training_data, ModelMetrics, PredictionResult
)
from network_monitor.monitor import get_network_monitor
from threat_engine.engine import get_threat_engine


def render_ai_analyzer() -> None:
    """Render the AI Security Analyzer page."""
    render_page_header("AI Security Analyzer", "ML-based threat classification and anomaly detection", "🤖")

    model, anomaly_detector = get_ai_analyzer()

    _render_model_status(model)
    _render_training_controls(model, anomaly_detector)
    _render_model_metrics(model)
    _render_prediction_interface(model, anomaly_detector)
    _render_feature_analysis(model)
    _render_anomaly_detection(anomaly_detector)


def _render_model_status(model: SecurityModel) -> None:
    """Render model status and basic info."""
    render_section_header("Model Status", "📊")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        status = "✅ Trained" if model.is_trained else "⚠️ Not Trained"
        metric_card("Status", status)

    with col2:
        metric_card("Model Type", model.model_type.replace('_', ' ').title())

    with col3:
        features = len(model.preparator.get_feature_names()) if model.preparator.get_feature_names() else 0
        metric_card("Features", str(features))

    with col4:
        classes = len(model.preparator.label_encoder.classes_) if model.is_trained and model.preparator.label_encoder.classes_ is not None else 0
        metric_card("Classes", str(classes))


def _render_training_controls(model: SecurityModel, anomaly_detector: AnomalyDetector) -> None:
    """Render model training controls."""
    render_section_header("Model Training", "🎯")

    st.caption("Train the model using network and threat event data. For best results, use labeled data from your environment.")

    col1, col2, col3 = st.columns([1, 1, 2])

    with col1:
        model_type = st.selectbox(
            "Model Type",
            ["random_forest", "logistic"],
            index=0,
            key="ml_model_type"
        )

    with col2:
        if st.button("🔄 Generate Sample Data & Train", type="primary", use_container_width=True):
            with st.spinner("Generating sample data and training model..."):
                model.model_type = model_type
                network_events, threat_events = generate_sample_training_data(1000)

                try:
                    metrics = model.train(network_events, threat_events)
                    anomaly_detector.fit(network_events, threat_events)

                    model.save()

                    st.success(f"Model trained successfully! Accuracy: {metrics.accuracy:.2%}, F1: {metrics.f1_score:.2%}")
                    st.rerun()
                except Exception as e:
                    st.error(f"Training failed: {str(e)}")

    with col3:
        if st.button("📂 Load Saved Model", use_container_width=True):
            _load_model_dialog(model, anomaly_detector)

    st.divider()

    if st.checkbox("Train on Real Data (Network + Threat Events)", key="train_real_data"):
        col1, col2 = st.columns(2)

        with col1:
            net_limit = st.number_input("Network Events Limit", 10, 10000, 500, key="ml_net_limit")
        with col2:
            threat_limit = st.number_input("Threat Events Limit", 10, 10000, 200, key="ml_threat_limit")

        if st.button("Train on Real Data", type="primary"):
            with st.spinner("Loading real data and training..."):
                model.model_type = model_type
                _train_on_real_data(model, anomaly_detector, net_limit, threat_limit)


def _load_model_dialog(model: SecurityModel, anomaly_detector: AnomalyDetector) -> None:
    """Show model loading dialog."""
    import os
    MODEL_DIR = os.path.join(os.path.dirname(__file__), '..', 'models')

    if not os.path.exists(MODEL_DIR):
        st.warning("No models directory found.")
        return

    model_files = [f for f in os.listdir(MODEL_DIR) if f.endswith('.pkl')]

    if not model_files:
        st.warning("No saved models found.")
        return

    selected = st.selectbox("Select Model", model_files, key="ml_model_select")

    if st.button("Load Selected Model"):
        try:
            path = os.path.join(MODEL_DIR, selected)
            loaded_model = SecurityModel.load(path)
            model.__dict__.update(loaded_model.__dict__)
            st.success(f"Model loaded: {selected}")
            st.rerun()
        except Exception as e:
            st.error(f"Failed to load model: {str(e)}")


def _train_on_real_data(model: SecurityModel, anomaly_detector: AnomalyDetector, net_limit: int, threat_limit: int) -> None:
    """Train model on real data from database."""
    try:
        with get_db() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute('''
                SELECT * FROM network_scans ORDER BY timestamp DESC LIMIT ?
            ''', (net_limit,))
            net_rows = cursor.fetchall()

            network_events = []
            for row in net_rows:
                event = dict(row)
                event['label'] = 'benign' if event.get('status') == 'Completed' else 'suspicious'
                network_events.append(event)

            cursor.execute('''
                SELECT * FROM threat_detections ORDER BY timestamp DESC LIMIT ?
            ''', (threat_limit,))
            threat_rows = cursor.fetchall()

            threat_events = []
            for row in threat_rows:
                event = dict(row)
                severity = event.get('severity', '').lower()
                event['label'] = 'malicious' if severity in ['high', 'critical'] else 'benign'
                threat_events.append(event)

        if len(network_events) < 10:
            st.warning("Insufficient network events for training. At least 10 events needed.")
            return

        metrics = model.train(network_events, threat_events)
        anomaly_detector.fit(network_events, threat_events)
        model.save()

        st.success(f"Model trained on real data! Accuracy: {metrics.accuracy:.2%}, F1: {metrics.f1_score:.2%}")
        st.rerun()

    except Exception as e:
        st.error(f"Training on real data failed: {str(e)}")


def _render_model_metrics(model: SecurityModel) -> None:
    """Render model evaluation metrics."""
    if not model.is_trained or model.metrics is None:
        return

    render_section_header("Model Performance Metrics", "📈")

    metrics = model.metrics

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        metric_card("Accuracy", f"{metrics.accuracy:.2%}")
    with col2:
        metric_card("Precision", f"{metrics.precision:.2%}")
    with col3:
        metric_card("Recall", f"{metrics.recall:.2%}")
    with col4:
        metric_card("F1-Score", f"{metrics.f1_score:.2%}")

    col1, col2 = st.columns(2)

    with col1:
        metric_card("ROC-AUC", f"{metrics.roc_auc:.2%}")
        st.caption(f"Trained: {metrics.training_samples} samples | Tested: {metrics.test_samples} samples")
        st.caption(f"Model: {metrics.model_type} | {metrics.timestamp[:19]}")

    with col2:
        _render_confusion_matrix(metrics.confusion_matrix, model.preparator.label_encoder.classes_)

    with st.expander("Detailed Classification Report"):
        st.code(metrics.classification_report, language='text')


def _render_confusion_matrix(cm: List[List[int]], class_names: np.ndarray) -> None:
    """Render confusion matrix as heatmap."""
    if not cm:
        return

    fig = go.Figure(data=go.Heatmap(
        z=cm,
        x=[str(c) for c in class_names],
        y=[str(c) for c in class_names],
        colorscale='Blues',
        text=cm,
        texttemplate='%{text}',
        textfont={"size": 14},
        showscale=True,
        colorbar=dict(title="Count")
    ))

    fig.update_layout(
        title="Confusion Matrix",
        xaxis_title="Predicted",
        yaxis_title="Actual",
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color=DARK_BLUE_THEME['text_primary'], family='Inter'),
        margin=dict(t=50, b=40, l=60, r=40),
        height=300,
    )

    st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})


def _render_prediction_interface(model: SecurityModel, anomaly_detector: AnomalyDetector) -> None:
    """Render real-time prediction interface."""
    render_section_header("Real-time Prediction", "🔮")

    if not model.is_trained:
        st.info("Train a model first to enable predictions.")
        return

    tab1, tab2, tab3 = st.tabs(["Network Event", "Threat Event", "Combined"])

    with tab1:
        _render_network_prediction(model, anomaly_detector)

    with tab2:
        _render_threat_prediction(model, anomaly_detector)

    with tab3:
        _render_combined_prediction(model, anomaly_detector)


def _render_network_prediction(model: SecurityModel, anomaly_detector: AnomalyDetector) -> None:
    """Render network event prediction form."""
    col1, col2 = st.columns(2)

    with col1:
        bytes_sent = st.number_input("Bytes Sent", 0, 100000000, 10000, key="ml_bytes_sent")
        bytes_recv = st.number_input("Bytes Received", 0, 100000000, 50000, key="ml_bytes_recv")
        packets_sent = st.number_input("Packets Sent", 0, 100000, 100, key="ml_packets_sent")
        packets_recv = st.number_input("Packets Received", 0, 100000, 200, key="ml_packets_recv")
        connection_count = st.number_input("Connection Count", 0, 1000, 5, key="ml_conn_count")

    with col2:
        unique_ports = st.number_input("Unique Ports", 0, 100, 5, key="ml_unique_ports")
        unique_ips = st.number_input("Unique IPs", 0, 100, 3, key="ml_unique_ips")
        failed_conns = st.number_input("Failed Connections", 0, 100, 0, key="ml_failed_conns")
        external_conns = st.number_input("External Connections", 0, 100, 2, key="ml_external_conns")
        internal_conns = st.number_input("Internal Connections", 0, 100, 3, key="ml_internal_conns")

    protocol = st.selectbox("Protocol", ["tcp", "udp"], key="ml_protocol")
    status = st.selectbox("Status", ["established", "syn_sent", "time_wait", "close_wait"], key="ml_status")

    if st.button("🔮 Predict Network Event", type="primary", use_container_width=True):
        event = {
            'bytes_sent': bytes_sent,
            'bytes_recv': bytes_recv,
            'packets_sent': packets_sent,
            'packets_recv': packets_recv,
            'connection_count': connection_count,
            'unique_ports': unique_ports,
            'unique_ips': unique_ips,
            'failed_connections': failed_conns,
            'external_connections': external_conns,
            'internal_connections': internal_conns,
            'protocol': protocol,
            'status': status,
        }

        result = model.predict(network_event=event)
        is_anomaly, anomaly_score = anomaly_detector.predict(network_event=event)
        result.anomaly_score = anomaly_score
        result.is_anomaly = is_anomaly

        _display_prediction_result(result)


def _render_threat_prediction(model: SecurityModel, anomaly_detector: AnomalyDetector) -> None:
    """Render threat event prediction form."""
    col1, col2 = st.columns(2)

    with col1:
        severity = st.selectbox("Severity", ["info", "low", "medium", "high", "critical"], index=2, key="ml_severity")
        threat_type = st.selectbox("Threat Type", [
            "malware", "brute_force", "data_exfiltration", "ransomware",
            "phishing", "network_scan", "vulnerability"
        ], key="ml_threat_type")

    with col2:
        mitigated = st.checkbox("Mitigated", value=False, key="ml_mitigated")
        source_ip = st.text_input("Source IP", "10.0.0.100", key="ml_source_ip")

    if st.button("🔮 Predict Threat Event", type="primary", use_container_width=True):
        event = {
            'severity': severity,
            'threat_type': threat_type,
            'mitigated': mitigated,
            'source_ip': source_ip,
        }

        result = model.predict(threat_event=event)
        is_anomaly, anomaly_score = anomaly_detector.predict(threat_event=event)
        result.anomaly_score = anomaly_score
        result.is_anomaly = is_anomaly

        _display_prediction_result(result)


def _render_combined_prediction(model: SecurityModel, anomaly_detector: AnomalyDetector) -> None:
    """Render combined network + threat prediction."""
    st.info("Provide both network and threat event data for combined analysis.")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Network Event")
        bytes_sent = st.number_input("Bytes Sent", 0, 100000000, 10000, key="ml_combined_bytes_sent")
        bytes_recv = st.number_input("Bytes Received", 0, 100000000, 50000, key="ml_combined_bytes_recv")
        packets_sent = st.number_input("Packets Sent", 0, 100000, 100, key="ml_combined_packets_sent")
        external_conns = st.number_input("External Connections", 0, 100, 2, key="ml_combined_external")
        protocol = st.selectbox("Protocol", ["tcp", "udp"], key="ml_combined_protocol")

    with col2:
        st.subheader("Threat Event")
        severity = st.selectbox("Severity", ["info", "low", "medium", "high", "critical"], index=2, key="ml_combined_severity")
        threat_type = st.selectbox("Threat Type", ["malware", "brute_force", "data_exfiltration", "ransomware", "phishing"], key="ml_combined_threat_type")
        mitigated = st.checkbox("Mitigated", key="ml_combined_mitigated")
        source_ip = st.text_input("Source IP", "10.0.0.100", key="ml_combined_source_ip")

    if st.button("🔮 Predict Combined Event", type="primary", use_container_width=True):
        net_event = {
            'bytes_sent': bytes_sent,
            'bytes_recv': bytes_recv,
            'packets_sent': packets_sent,
            'external_connections': external_conns,
            'protocol': protocol,
        }
        threat_event = {
            'severity': severity,
            'threat_type': threat_type,
            'mitigated': mitigated,
            'source_ip': source_ip,
        }

        result = model.predict(network_event=net_event, threat_event=threat_event)
        is_anomaly, anomaly_score = anomaly_detector.predict(network_event=net_event, threat_event=threat_event)
        result.anomaly_score = anomaly_score
        result.is_anomaly = is_anomaly

        _display_prediction_result(result)


def _display_prediction_result(result: PredictionResult) -> None:
    """Display prediction result with confidence and explanation."""
    risk_colors = {
        'malicious': DARK_BLUE_THEME['critical'],
        'benign': DARK_BLUE_THEME['success'],
        'suspicious': DARK_BLUE_THEME['warning'],
    }

    pred_lower = result.prediction.lower()
    risk_color = risk_colors.get(pred_lower, DARK_BLUE_THEME['accent'])

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
            <h3 style="margin: 0; color: {DARK_BLUE_THEME['text_primary']};">Prediction: {result.prediction.upper()}</h3>
            <span style="
                background: {risk_color}20;
                color: {risk_color};
                padding: 0.5rem 1rem;
                border-radius: 20px;
                font-weight: 600;
            ">Confidence: {result.confidence:.1%}</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Confidence", f"{result.confidence:.1%}")
    with col2:
        st.metric("Anomaly Score", f"{result.anomaly_score:.1f}%" if result.anomaly_score is not None else "N/A")
    with col3:
        anomaly_label = "🚨 ANOMALY" if result.is_anomaly else "✅ Normal"
        st.metric("Anomaly Detection", anomaly_label)

    st.divider()

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Class Probabilities")
        if result.probabilities:
            for cls, prob in result.probabilities.items():
                st.progress(prob, text=f"{cls}: {prob:.1%}")

    with col2:
        st.subheader("Top Feature Importance")
        if result.feature_importance:
            for feat, imp in list(result.feature_importance.items())[:10]:
                st.write(f"**{feat}:** {imp:.4f}")


def _render_feature_analysis(model: SecurityModel) -> None:
    """Render global feature importance analysis."""
    if not model.is_trained or not hasattr(model.model, 'feature_importances_'):
        return

    render_section_header("Global Feature Importance", "📊")

    features = model.preparator.get_feature_names()
    importances = model.model.feature_importances_

    if not features or len(features) != len(importances):
        return

    feat_imp = pd.DataFrame({
        'feature': features,
        'importance': importances
    }).sort_values('importance', ascending=True).tail(15)

    fig = go.Figure(go.Bar(
        x=feat_imp['importance'],
        y=feat_imp['feature'],
        orientation='h',
        marker=dict(color=DARK_BLUE_THEME['accent']),
        hovertemplate='<b>%{y}</b><br>Importance: %{x:.4f}<extra></extra>',
    ))

    fig.update_layout(
        title="Top 15 Most Important Features",
        xaxis_title="Importance",
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color=DARK_BLUE_THEME['text_primary'], family='Inter'),
        margin=dict(t=40, b=20, l=150, r=20),
        height=400,
    )

    st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})


def _render_anomaly_detection(anomaly_detector: AnomalyDetector) -> None:
    """Render anomaly detection results."""
    render_section_header("Anomaly Detection", "🔍")

    if not anomaly_detector.is_fitted:
        st.info("Train the anomaly detector by training the main model first.")
        return

    st.caption("Isolation Forest anomaly detector trained on historical data.")

    col1, col2 = st.columns(2)

    with col1:
        st.metric("Contamination", f"{anomaly_detector.contamination:.1%}")
        st.metric("Features", len(anomaly_detector.feature_names) if anomaly_detector.feature_names else 0)

    with col2:
        if st.button("🔍 Test on Recent Network Events", use_container_width=True):
            _test_anomaly_on_recent(anomaly_detector)


def _test_anomaly_on_recent(anomaly_detector: AnomalyDetector) -> None:
    """Test anomaly detector on recent network events."""
    try:
        monitor = get_network_monitor()
        connections = monitor.get_connections()

        if not connections:
            st.warning("No network connections available for testing.")
            return

        network_events = []
        for c in connections[:20]:
            network_events.append({
                'bytes_sent': 0,
                'bytes_recv': 0,
                'packets_sent': 0,
                'packets_recv': 0,
                'connection_count': 1,
                'unique_ports': 1,
                'unique_ips': 1,
                'failed_connections': 0,
                'external_connections': 1 if c.remote_address and not c.remote_address.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '127.', '::1')) else 0,
                'internal_connections': 0,
                'protocol': c.family.lower(),
                'status': c.status.lower(),
            })

        if network_events:
            results = []
            for event in network_events:
                is_anomaly, score = anomaly_detector.predict(network_event=event)
                results.append({
                    'remote': f"{event.get('protocol', '').upper()} {event.get('remote_address', '')}:{event.get('remote_port', '')}",
                    'anomaly': '🚨 Anomaly' if is_anomaly else '✅ Normal',
                    'score': f"{score:.1f}%"
                })

            df = pd.DataFrame(results)
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("No events to test.")

    except Exception as e:
        st.error(f"Anomaly test failed: {str(e)}")


import sqlite3