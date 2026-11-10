"""Tests for login security and alerts center modules."""
import pytest
import sys
import os
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.connection import get_db, init_database


class TestLoginSecurity:
    """Test login security analysis functions."""

    @pytest.fixture(autouse=True)
    def setup_db(self, test_db_path, monkeypatch):
        """Set up test database."""
        import database.connection as db_module
        monkeypatch.setattr(db_module, 'DB_PATH', test_db_path)
        init_database()

        # Clear demo data and add test login data
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM login_attempts')

            # Add various login attempts
            test_logins = [
                ('admin', '192.168.1.100', 1, 'New York, US', 'Mozilla/5.0'),
                ('admin', '192.168.1.100', 1, 'New York, US', 'Mozilla/5.0'),
                ('admin', '203.0.113.45', 0, 'Unknown', 'curl/7.68.0'),
                ('admin', '203.0.113.45', 0, 'Unknown', 'curl/7.68.0'),
                ('admin', '203.0.113.45', 0, 'Unknown', 'curl/7.68.0'),
                ('admin', '203.0.113.45', 0, 'Unknown', 'curl/7.68.0'),
                ('admin', '203.0.113.45', 0, 'Unknown', 'curl/7.68.0'),  # 5 failures
                ('john.doe', '192.168.1.105', 1, 'London, UK', 'Mozilla/5.0'),
                ('jane.smith', '198.51.100.23', 0, 'Unknown', 'Python-urllib/3.11'),
                ('jane.smith', '198.51.100.24', 0, 'Unknown', 'Python-urllib/3.11'),
                ('jane.smith', '198.51.100.25', 0, 'Unknown', 'Python-urllib/3.11'),
            ]

            for login in test_logins:
                cursor.execute('''
                    INSERT INTO login_attempts (username, ip_address, success, location, user_agent)
                    VALUES (?, ?, ?, ?, ?)
                ''', login)

            conn.commit()

    def test_failed_login_detection(self, test_db_path, monkeypatch):
        """Test detection of failed login attempts."""
        import database.connection as db_module
        monkeypatch.setattr(db_module, 'DB_PATH', test_db_path)

        with get_db() as conn:
            cursor = conn.cursor()

            # Check for IPs with 5+ failed attempts
            cursor.execute('''
                SELECT ip_address, COUNT(*) as failed_count
                FROM login_attempts
                WHERE success = 0
                GROUP BY ip_address
                HAVING failed_count >= 5
            ''')

            results = cursor.fetchall()
            assert len(results) == 1
            assert results[0]['ip_address'] == '203.0.113.45'
            assert results[0]['failed_count'] == 5

    def test_credential_stuffing_detection(self, test_db_path, monkeypatch):
        """Test detection of credential stuffing (same user, multiple IPs)."""
        import database.connection as db_module
        monkeypatch.setattr(db_module, 'DB_PATH', test_db_path)

        with get_db() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                SELECT username, COUNT(DISTINCT ip_address) as ip_count
                FROM login_attempts
                WHERE success = 0
                GROUP BY username
                HAVING ip_count >= 3
            ''')

            results = cursor.fetchall()
            assert len(results) == 1
            assert results[0]['username'] == 'jane.smith'
            assert results[0]['ip_count'] == 3

    def test_brute_force_pattern(self, test_db_path, monkeypatch):
        """Test brute force pattern detection."""
        import database.connection as db_module
        monkeypatch.setattr(db_module, 'DB_PATH', test_db_path)

        with get_db() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                SELECT ip_address, COUNT(*) as failed_count
                FROM login_attempts
                WHERE success = 0
                GROUP BY ip_address
                HAVING failed_count >= 5
            ''')

            results = cursor.fetchall()
            # Should detect 203.0.113.45 with 5 failed attempts
            assert len(results) == 1

    def test_successful_login_after_failures(self, test_db_path, monkeypatch):
        """Test detection of successful login after multiple failures."""
        import database.connection as db_module
        monkeypatch.setattr(db_module, 'DB_PATH', test_db_path)

        # Add a success after failures for the same IP/user
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO login_attempts (username, ip_address, success, location, user_agent)
                VALUES (?, ?, ?, ?, ?)
            ''', ('admin', '203.0.113.45', 1, 'Unknown', 'Mozilla/5.0'))
            conn.commit()

        with get_db() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                SELECT ip_address, username,
                       SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed_count
                FROM login_attempts
                GROUP BY ip_address, username
                HAVING SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) >= 1
                   AND SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) >= 3
            ''')

            results = cursor.fetchall()
            assert len(results) == 1
            assert results[0]['ip_address'] == '203.0.113.45'
            assert results[0]['username'] == 'admin'
            assert results[0]['failed_count'] >= 3

    def test_geographic_analysis(self, test_db_path, monkeypatch):
        """Test geographic login analysis."""
        import database.connection as db_module
        monkeypatch.setattr(db_module, 'DB_PATH', test_db_path)

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

            results = cursor.fetchall()

            locations = {row['location'] for row in results}
            assert 'New York, US' in locations
            assert 'London, UK' in locations

    def test_login_statistics(self, test_db_path, monkeypatch):
        """Test login statistics queries."""
        import database.connection as db_module
        monkeypatch.setattr(db_module, 'DB_PATH', test_db_path)

        with get_db() as conn:
            cursor = conn.cursor()

            # Total attempts
            cursor.execute('SELECT COUNT(*) FROM login_attempts')
            total = cursor.fetchone()[0]
            assert total >= 11

            # Successful
            cursor.execute('SELECT COUNT(*) FROM login_attempts WHERE success = 1')
            successful = cursor.fetchone()[0]

            # Failed
            cursor.execute('SELECT COUNT(*) FROM login_attempts WHERE success = 0')
            failed = cursor.fetchone()[0]

            assert successful + failed == total
            assert failed > successful  # More failures in test data


class TestAlertsCenter:
    """Test alerts center functionality."""

    @pytest.fixture(autouse=True)
    def setup_alerts_db(self, test_db_path, monkeypatch):
        """Set up test database with alerts."""
        import database.connection as db_module
        monkeypatch.setattr(db_module, 'DB_PATH', test_db_path)
        init_database()

        # Clear demo data and add test alerts
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM alerts')

            test_alerts = [
                ('Threat Detection', 'CRITICAL', 'Ransomware Activity', 'File encryption detected', 0),
                ('Network Anomaly', 'HIGH', 'Unusual Outbound Traffic', 'Large data transfer', 0),
                ('Vulnerability', 'HIGH', 'Critical CVE', 'CVE-2024-12345 detected', 0),
                ('Phishing', 'MEDIUM', 'Phishing Campaign', '5 emails blocked', 1),
                ('Brute Force', 'MEDIUM', 'SSH Brute Force', '47 failed attempts', 1),
            ]

            for alert in test_alerts:
                cursor.execute('''
                    INSERT INTO alerts (alert_type, severity, title, message, acknowledged)
                    VALUES (?, ?, ?, ?, ?)
                ''', alert)

            conn.commit()

    def test_alert_metrics(self, test_db_path, monkeypatch):
        """Test alert metrics queries."""
        import database.connection as db_module
        monkeypatch.setattr(db_module, 'DB_PATH', test_db_path)

        with get_db() as conn:
            cursor = conn.cursor()

            cursor.execute('SELECT COUNT(*) FROM alerts')
            total = cursor.fetchone()[0]
            assert total == 5

            cursor.execute('SELECT COUNT(*) FROM alerts WHERE acknowledged = 0')
            unacked = cursor.fetchone()[0]
            assert unacked == 3

            cursor.execute('SELECT COUNT(*) FROM alerts WHERE acknowledged = 1')
            acked = cursor.fetchone()[0]
            assert acked == 2

            cursor.execute('SELECT COUNT(*) FROM alerts WHERE severity = "CRITICAL" AND acknowledged = 0')
            critical = cursor.fetchone()[0]
            assert critical == 1

    def test_alert_acknowledgment(self, test_db_path, monkeypatch):
        """Test alert acknowledgment workflow."""
        import database.connection as db_module
        monkeypatch.setattr(db_module, 'DB_PATH', test_db_path)

        with get_db() as conn:
            cursor = conn.cursor()

            # Get an unacknowledged alert
            cursor.execute('SELECT id FROM alerts WHERE acknowledged = 0 LIMIT 1')
            alert = cursor.fetchone()
            assert alert is not None
            alert_id = alert['id']

            # Acknowledge it
            cursor.execute('UPDATE alerts SET acknowledged = 1 WHERE id = ?', (alert_id,))
            conn.commit()

            # Verify
            cursor.execute('SELECT acknowledged FROM alerts WHERE id = ?', (alert_id,))
            assert cursor.fetchone()['acknowledged'] == 1

    def test_alert_filtering(self, test_db_path, monkeypatch):
        """Test alert filtering by severity and type."""
        import database.connection as db_module
        monkeypatch.setattr(db_module, 'DB_PATH', test_db_path)

        with get_db() as conn:
            cursor = conn.cursor()

            # Filter by severity
            cursor.execute('SELECT * FROM alerts WHERE severity = "HIGH"')
            high_alerts = cursor.fetchall()
            assert len(high_alerts) == 2

            # Filter by type
            cursor.execute('SELECT * FROM alerts WHERE alert_type = "Phishing"')
            phishing_alerts = cursor.fetchall()
            assert len(phishing_alerts) == 1

            # Filter by status
            cursor.execute('SELECT * FROM alerts WHERE acknowledged = 0')
            unacked = cursor.fetchall()
            assert len(unacked) == 3

    def test_severity_distribution(self, test_db_path, monkeypatch):
        """Test severity distribution query."""
        import database.connection as db_module
        monkeypatch.setattr(db_module, 'DB_PATH', test_db_path)

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

            results = cursor.fetchall()
            severities = {row['severity']: row['count'] for row in results}

            assert severities.get('CRITICAL', 0) == 1
            assert severities.get('HIGH', 0) == 2
            assert severities.get('MEDIUM', 0) == 2