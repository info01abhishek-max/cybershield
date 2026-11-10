"""Pytest configuration and fixtures for CyberShield tests."""
import pytest
import sys
import os
import tempfile
import sqlite3
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(scope="session")
def test_db_path():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name
    yield db_path
    # Cleanup
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.fixture(scope="function")
def db_connection(test_db_path):
    """Create a database connection with test schema."""
    conn = sqlite3.connect(test_db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Create all tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            source TEXT,
            description TEXT,
            details TEXT,
            status TEXT DEFAULT 'NEW',
            assigned_to TEXT DEFAULT '',
            resolution_notes TEXT DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS network_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            target_ip TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            status TEXT NOT NULL,
            open_ports TEXT,
            vulnerabilities TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            threat_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT,
            target TEXT,
            description TEXT,
            mitigated BOOLEAN DEFAULT 0
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS phishing_urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            url TEXT NOT NULL,
            is_phishing BOOLEAN NOT NULL,
            confidence REAL,
            indicators TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            file_path TEXT NOT NULL,
            file_hash TEXT,
            scan_result TEXT NOT NULL,
            threats_found TEXT,
            scan_duration REAL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            success BOOLEAN NOT NULL,
            location TEXT,
            user_agent TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT,
            acknowledged BOOLEAN DEFAULT 0
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    yield conn
    conn.close()


@pytest.fixture(scope="function")
def sample_network_event():
    """Sample network event for testing."""
    return {
        'bytes_sent': 10000,
        'bytes_recv': 50000,
        'packets_sent': 100,
        'packets_recv': 200,
        'connection_count': 5,
        'unique_ports': 3,
        'unique_ips': 2,
        'failed_connections': 0,
        'external_connections': 2,
        'internal_connections': 3,
        'protocol': 'tcp',
        'status': 'established',
    }


@pytest.fixture(scope="function")
def sample_threat_event():
    """Sample threat event for testing."""
    return {
        'severity': 'high',
        'threat_type': 'malware',
        'mitigated': False,
        'source_ip': '10.0.0.100',
    }


@pytest.fixture(scope="function")
def sample_file_info():
    """Sample file info for testing."""
    return {
        'path': '/tmp/test.exe',
        'name': 'test.exe',
        'size': 1024,
    }


@pytest.fixture(scope="function")
def sample_urls():
    """Sample URLs for phishing detection testing."""
    return {
        'legitimate': 'https://www.google.com',
        'phishing': 'http://paypal-security.fake.com/login',
        'suspicious': 'http://microsoft-verify.phishersite.net/auth',
    }