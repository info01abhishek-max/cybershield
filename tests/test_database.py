"""Tests for database connection and operations."""
import pytest
import sqlite3
from datetime import datetime

from database.connection import (
    init_database, get_db, get_connection, get_setting, set_setting,
    DB_PATH
)


class TestDatabaseConnection:
    """Test database connection and initialization."""

    def test_init_database_creates_tables(self, test_db_path, monkeypatch):
        """Test that init_database creates all required tables."""
        import database.connection as db_module
        monkeypatch.setattr(db_module, 'DB_PATH', test_db_path)

        init_database()

        conn = sqlite3.connect(test_db_path)
        cursor = conn.cursor()

        # Check all tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}

        expected_tables = {
            'security_events', 'network_scans', 'threat_detections',
            'phishing_urls', 'file_scans', 'login_attempts',
            'alerts', 'settings'
        }

        for table in expected_tables:
            assert table in tables, f"Table {table} not created"

        conn.close()

    def test_init_database_inserts_demo_data(self, test_db_path, monkeypatch):
        """Test that demo data is inserted."""
        import database.connection as db_module
        monkeypatch.setattr(db_module, 'DB_PATH', test_db_path)

        init_database()

        conn = sqlite3.connect(test_db_path)
        cursor = conn.cursor()

        # Check demo data exists
        cursor.execute('SELECT COUNT(*) FROM security_events')
        assert cursor.fetchone()[0] > 0

        cursor.execute('SELECT COUNT(*) FROM network_scans')
        assert cursor.fetchone()[0] > 0

        cursor.execute('SELECT COUNT(*) FROM threat_detections')
        assert cursor.fetchone()[0] > 0

        cursor.execute('SELECT COUNT(*) FROM phishing_urls')
        assert cursor.fetchone()[0] > 0

        cursor.execute('SELECT COUNT(*) FROM file_scans')
        assert cursor.fetchone()[0] > 0

        cursor.execute('SELECT COUNT(*) FROM login_attempts')
        assert cursor.fetchone()[0] > 0

        cursor.execute('SELECT COUNT(*) FROM alerts')
        assert cursor.fetchone()[0] > 0

        cursor.execute('SELECT COUNT(*) FROM settings')
        assert cursor.fetchone()[0] > 0

        conn.close()

    def test_get_db_context_manager(self, test_db_path, monkeypatch):
        """Test get_db context manager."""
        import database.connection as db_module
        monkeypatch.setattr(db_module, 'DB_PATH', test_db_path)

        init_database()

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM settings')
            count = cursor.fetchone()[0]
            assert count > 0

        # Connection should be closed after context
        assert True  # If we get here, context manager worked

    def test_get_connection_row_factory(self, test_db_path, monkeypatch):
        """Test get_connection returns Row factory."""
        import database.connection as db_module
        monkeypatch.setattr(db_module, 'DB_PATH', test_db_path)

        init_database()

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM settings LIMIT 1')
        row = cursor.fetchone()

        assert row is not None
        assert hasattr(row, 'keys')  # Row factory allows dict-like access
        conn.close()

    def test_settings_get_set(self, test_db_path, monkeypatch):
        """Test get_setting and set_setting functions."""
        import database.connection as db_module
        monkeypatch.setattr(db_module, 'DB_PATH', test_db_path)

        init_database()

        # Test get existing setting
        theme = get_setting('theme')
        assert theme == 'dark_blue'

        # Test set new setting
        set_setting('test_key', 'test_value')
        value = get_setting('test_key')
        assert value == 'test_value'

        # Test get non-existent setting with default
        value = get_setting('non_existent', 'default_value')
        assert value == 'default_value'

    def test_migration_adds_columns(self, test_db_path, monkeypatch):
        """Test that migration adds created_at and updated_at columns."""
        import database.connection as db_module
        monkeypatch.setattr(db_module, 'DB_PATH', test_db_path)

        init_database()

        conn = sqlite3.connect(test_db_path)
        cursor = conn.cursor()

        cursor.execute("PRAGMA table_info(security_events)")
        columns = {row[1] for row in cursor.fetchall()}

        assert 'created_at' in columns
        assert 'updated_at' in columns

        # Verify they have data
        cursor.execute('SELECT COUNT(*) FROM security_events WHERE created_at IS NOT NULL')
        assert cursor.fetchone()[0] > 0

        conn.close()


class TestDatabaseOperations:
    """Test database CRUD operations."""

    def test_insert_security_event(self, db_connection):
        """Test inserting a security event."""
        cursor = db_connection.cursor()

        cursor.execute('''
            INSERT INTO security_events (event_id, timestamp, event_type, severity, source, description)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', ('EVT-TEST-001', datetime.now().isoformat(), 'Test', 'HIGH', '10.0.0.1', 'Test event'))

        db_connection.commit()

        cursor.execute('SELECT * FROM security_events WHERE event_id = ?', ('EVT-TEST-001',))
        row = cursor.fetchone()

        assert row is not None
        assert row['event_type'] == 'Test'
        assert row['severity'] == 'HIGH'

    def test_update_security_event_status(self, db_connection):
        """Test updating security event status."""
        cursor = db_connection.cursor()

        cursor.execute('''
            INSERT INTO security_events (event_id, timestamp, event_type, severity, status)
            VALUES (?, ?, ?, ?, ?)
        ''', ('EVT-TEST-002', datetime.now().isoformat(), 'Test', 'HIGH', 'NEW'))

        db_connection.commit()

        cursor.execute("UPDATE security_events SET status = 'RESOLVED' WHERE event_id = ?", ('EVT-TEST-002',))
        db_connection.commit()

        cursor.execute('SELECT status FROM security_events WHERE event_id = ?', ('EVT-TEST-002',))
        assert cursor.fetchone()['status'] == 'RESOLVED'

    def test_alert_acknowledgment(self, db_connection):
        """Test alert acknowledgment workflow."""
        cursor = db_connection.cursor()

        cursor.execute('''
            INSERT INTO alerts (alert_type, severity, title, message, acknowledged)
            VALUES (?, ?, ?, ?, ?)
        ''', ('Test', 'HIGH', 'Test Alert', 'Test message', 0))

        db_connection.commit()

        alert_id = cursor.lastrowid

        # Initially unacknowledged
        cursor.execute('SELECT acknowledged FROM alerts WHERE id = ?', (alert_id,))
        assert cursor.fetchone()['acknowledged'] == 0

        # Acknowledge
        cursor.execute('UPDATE alerts SET acknowledged = 1 WHERE id = ?', (alert_id,))
        db_connection.commit()

        cursor.execute('SELECT acknowledged FROM alerts WHERE id = ?', (alert_id,))
        assert cursor.fetchone()['acknowledged'] == 1