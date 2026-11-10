"""Tests for reports module."""
import pytest
import sys
import os
import json
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.connection import get_db, init_database
from features.reports import (
    _generate_daily_report, _generate_weekly_report, _generate_monthly_report,
    _generate_threat_report, _generate_network_report, _generate_login_report,
    _generate_compliance_report, _generate_custom_report,
    _export_report_csv, _export_report_pdf
)


class MockStreamlit:
    """Mock streamlit for testing."""
    def __init__(self):
        self.session_state = MockSessionState()

class MockSessionState:
    """Mock session state."""
    def __init__(self):
        self.data = {}
    def get(self, key, default=None):
        return self.data.get(key, default)
    def __setitem__(self, key, value):
        self.data[key] = value


class TestReports:
    """Test report generation functions."""

    @pytest.fixture(autouse=True)
    def setup_db(self, test_db_path, monkeypatch):
        """Set up test database with data for reports."""
        import database.connection as db_module
        monkeypatch.setattr(db_module, 'DB_PATH', test_db_path)
        init_database()

        # Clear demo data and add test data for reports
        with get_db() as conn:
            cursor = conn.cursor()

            # Clear all tables
            cursor.execute('DELETE FROM threat_detections')
            cursor.execute('DELETE FROM security_events')
            cursor.execute('DELETE FROM alerts')
            cursor.execute('DELETE FROM login_attempts')
            cursor.execute('DELETE FROM network_scans')
            cursor.execute('DELETE FROM file_scans')
            cursor.execute('DELETE FROM phishing_urls')

            # Add recent threat detections
            now = datetime.now()
            yesterday = now - timedelta(days=1)

            threats = [
                ('Malware', 'HIGH', '10.0.0.1', 'workstation-01', 'Trojan detected', 0, now.isoformat()),
                ('Brute Force', 'MEDIUM', '10.0.0.2', 'ssh-server', 'SSH brute force', 1, now.isoformat()),
                ('Phishing', 'LOW', None, 'user@company.com', 'Credential harvesting', 1, yesterday.isoformat()),
            ]

            for t in threats:
                cursor.execute('''
                    INSERT INTO threat_detections (threat_type, severity, source_ip, target, description, mitigated, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', t)

            # Add security events
            events = [
                ('EVT-001', now.isoformat(), 'Threat', 'HIGH', '10.0.0.1', 'Test', '{}', 'NEW', '', '', now.isoformat(), now.isoformat()),
                ('EVT-002', now.isoformat(), 'Network Scan', 'INFO', '192.168.1.0/24', 'Scan', '{}', 'RESOLVED', '', '', now.isoformat(), now.isoformat()),
            ]

            for e in events:
                cursor.execute('''
                    INSERT INTO security_events (event_id, timestamp, event_type, severity, source, description, details, status, assigned_to, resolution_notes, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', e)

            # Add alerts
            alerts = [
                ('Threat Detection', 'CRITICAL', 'Test Alert 1', 'Message 1', 0, now.isoformat()),
                ('Network Anomaly', 'HIGH', 'Test Alert 2', 'Message 2', 1, now.isoformat()),
            ]

            for a in alerts:
                cursor.execute('''
                    INSERT INTO alerts (alert_type, severity, title, message, acknowledged, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', a)

            # Add login attempts
            logins = [
                ('admin', '192.168.1.100', 1, 'New York', 'Mozilla', now.isoformat()),
                ('admin', '10.0.0.1', 0, 'Unknown', 'curl', now.isoformat()),
                ('user1', '192.168.1.101', 1, 'London', 'Chrome', now.isoformat()),
            ]

            for l in logins:
                cursor.execute('''
                    INSERT INTO login_attempts (username, ip_address, success, location, user_agent, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', l)

            # Add network scans
            scans = [
                ('192.168.1.10', 'Full Scan', 'Completed', '22,80,443', 'None', now.isoformat()),
                ('10.0.0.5', 'Vulnerability', 'Completed', '22,3389', 'CVE-2023-1234', now.isoformat()),
            ]

            for s in scans:
                cursor.execute('''
                    INSERT INTO network_scans (target_ip, scan_type, status, open_ports, vulnerabilities, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', s)

            # Add file scans
            files = [
                ('/test/file1.exe', 'hash1', 'Infected', '["Trojan"]', 1.5, now.isoformat()),
                ('/test/file2.txt', 'hash2', 'Clean', '[]', 0.5, now.isoformat()),
            ]

            for f in files:
                cursor.execute('''
                    INSERT INTO file_scans (file_path, file_hash, scan_result, threats_found, scan_duration, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', f)

            # Add phishing URLs
            phishing = [
                ('http://fake.com', 1, 0.95, '["phishing"]', now.isoformat()),
                ('https://google.com', 0, 0.01, '[]', now.isoformat()),
            ]

            for p in phishing:
                cursor.execute('''
                    INSERT INTO phishing_urls (url, is_phishing, confidence, indicators, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                ''', p)

            conn.commit()

    def test_generate_daily_report(self, test_db_path, monkeypatch):
        """Test daily report generation."""
        import database.connection as db_module
        import features.reports as reports_module
        monkeypatch.setattr(db_module, 'DB_PATH', test_db_path)

        # Mock streamlit
        mock_st = MockStreamlit()
        mock_st.session_state['report_date'] = datetime.now().date()
        monkeypatch.setattr(reports_module, 'st', mock_st)

        report = _generate_daily_report()

        assert 'Executive Summary' in report
        assert 'metrics' in report['Executive Summary']
        metrics = report['Executive Summary']['metrics']
        assert 'Total Threats' in metrics
        assert 'Total Security Events' in metrics

    def test_generate_weekly_report(self, test_db_path, monkeypatch):
        """Test weekly report generation."""
        import database.connection as db_module
        import features.reports as reports_module
        monkeypatch.setattr(db_module, 'DB_PATH', test_db_path)

        mock_st = MockStreamlit()
        mock_st.session_state['report_date'] = datetime.now().date()
        monkeypatch.setattr(reports_module, 'st', mock_st)

        report = _generate_weekly_report()

        assert 'Weekly Overview' in report
        assert 'metrics' in report['Weekly Overview']

    def test_generate_monthly_report(self, test_db_path, monkeypatch):
        """Test monthly report generation."""
        import database.connection as db_module
        import features.reports as reports_module
        monkeypatch.setattr(db_module, 'DB_PATH', test_db_path)

        mock_st = MockStreamlit()
        mock_st.session_state['report_date'] = datetime.now().date()
        monkeypatch.setattr(reports_module, 'st', mock_st)

        report = _generate_monthly_report()

        assert 'Monthly Overview' in report
        assert 'metrics' in report['Monthly Overview']

    def test_generate_threat_report(self, test_db_path, monkeypatch):
        """Test threat report generation."""
        import database.connection as db_module
        monkeypatch.setattr(db_module, 'DB_PATH', test_db_path)

        report = _generate_threat_report()

        assert 'Recent Threats' in report
        assert 'table' in report['Recent Threats']
        assert len(report['Recent Threats']['table']) > 0

    def test_generate_network_report(self, test_db_path, monkeypatch):
        """Test network report generation."""
        import database.connection as db_module
        monkeypatch.setattr(db_module, 'DB_PATH', test_db_path)

        report = _generate_network_report()

        assert 'Recent Network Scans' in report
        assert 'table' in report['Recent Network Scans']
        assert len(report['Recent Network Scans']['table']) > 0

    def test_generate_login_report(self, test_db_path, monkeypatch):
        """Test login report generation."""
        import database.connection as db_module
        monkeypatch.setattr(db_module, 'DB_PATH', test_db_path)

        report = _generate_login_report()

        assert 'Recent Login Attempts' in report
        assert 'table' in report['Recent Login Attempts']
        assert len(report['Recent Login Attempts']['table']) > 0

    def test_generate_compliance_report(self, test_db_path, monkeypatch):
        """Test compliance report generation."""
        import database.connection as db_module
        monkeypatch.setattr(db_module, 'DB_PATH', test_db_path)

        report = _generate_compliance_report()

        assert 'Compliance Metrics' in report
        assert 'metrics' in report['Compliance Metrics']
        metrics = report['Compliance Metrics']['metrics']
        assert 'Total Alerts' in metrics

    def test_generate_custom_report(self, test_db_path, monkeypatch):
        """Test custom date range report generation."""
        import database.connection as db_module
        monkeypatch.setattr(db_module, 'DB_PATH', test_db_path)

        start = datetime.now().date() - timedelta(days=7)
        end = datetime.now().date()

        report = _generate_custom_report(start, end)

        assert 'Custom Report Summary' in report
        assert 'metrics' in report['Custom Report Summary']

    def test_export_report_csv(self, test_db_path, monkeypatch):
        """Test CSV export."""
        import database.connection as db_module
        monkeypatch.setattr(db_module, 'DB_PATH', test_db_path)

        # Create a sample report
        report = {
            'type': 'daily',
            'generated_at': datetime.now().isoformat(),
            'sections': {
                'Test Section': {
                    'metrics': {'Metric1': 'Value1', 'Metric2': 'Value2'},
                    'table': [{'Col1': 'A', 'Col2': 'B'}, {'Col1': 'C', 'Col2': 'D'}],
                    'text': 'Test note'
                }
            }
        }

        csv_data = _export_report_csv(report)

        assert isinstance(csv_data, str)
        assert 'CyberShield Security Report' in csv_data
        assert 'Test Section' in csv_data
        assert 'Metric1' in csv_data
        assert 'Col1' in csv_data
        assert 'A' in csv_data

    @pytest.mark.skipif(True, reason="Requires reportlab")
    def test_export_report_pdf(self, test_db_path, monkeypatch):
        """Test PDF export (requires reportlab)."""
        pass