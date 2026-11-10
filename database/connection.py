"""SQLite database initialization and connection management."""
import sqlite3
import os
from contextlib import contextmanager
from typing import Generator
from datetime import datetime


DB_PATH = os.path.join(os.path.dirname(__file__), 'cybershield.db')


def get_connection() -> sqlite3.Connection:
    """Get a database connection with row factory."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    """Context manager for database connections."""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_database() -> None:
    """Initialize the database with all required tables."""
    with get_db() as conn:
        cursor = conn.cursor()

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

        _migrate_security_events_table(cursor)

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

        _insert_demo_data(cursor)


def _migrate_security_events_table(cursor: sqlite3.Cursor) -> None:
    """Migrate security_events table to add new columns if they don't exist."""
    cursor.execute("PRAGMA table_info(security_events)")
    columns = {row[1] for row in cursor.fetchall()}

    # Add columns one by one, handling UNIQUE constraints properly
    if "event_id" not in columns:
        try:
            # First add without UNIQUE, then populate
            cursor.execute('ALTER TABLE security_events ADD COLUMN event_id TEXT')
            cursor.execute("SELECT id FROM security_events WHERE event_id IS NULL OR event_id = ''")
            for row in cursor.fetchall():
                event_id = f"EVT-{datetime.now().strftime('%Y%m%d')}-{row[0]:08d}"
                cursor.execute("UPDATE security_events SET event_id = ? WHERE id = ?", (event_id, row[0]))
        except sqlite3.OperationalError as e:
            print(f"Migration warning (event_id): {e}")

    if "status" not in columns:
        try:
            cursor.execute("ALTER TABLE security_events ADD COLUMN status TEXT DEFAULT 'NEW'")
        except sqlite3.OperationalError as e:
            print(f"Migration warning (status): {e}")

    if "assigned_to" not in columns:
        try:
            cursor.execute("ALTER TABLE security_events ADD COLUMN assigned_to TEXT DEFAULT ''")
        except sqlite3.OperationalError as e:
            print(f"Migration warning (assigned_to): {e}")

    if "resolution_notes" not in columns:
        try:
            cursor.execute("ALTER TABLE security_events ADD COLUMN resolution_notes TEXT DEFAULT ''")
        except sqlite3.OperationalError as e:
            print(f"Migration warning (resolution_notes): {e}")

    # For created_at and updated_at, SQLite doesn't allow DEFAULT CURRENT_TIMESTAMP in ALTER TABLE
    # So we add them without default, then populate
    if "created_at" not in columns:
        try:
            cursor.execute("ALTER TABLE security_events ADD COLUMN created_at DATETIME")
        except sqlite3.OperationalError as e:
            print(f"Migration warning (created_at): {e}")

    if "updated_at" not in columns:
        try:
            cursor.execute("ALTER TABLE security_events ADD COLUMN updated_at DATETIME")
        except sqlite3.OperationalError as e:
            print(f"Migration warning (updated_at): {e}")

    # Update any rows that still have NULL/empty values for the new columns
    cursor.execute("SELECT id FROM security_events WHERE event_id IS NULL OR event_id = ''")
    for row in cursor.fetchall():
        event_id = f"EVT-{datetime.now().strftime('%Y%m%d')}-{row[0]:08d}"
        cursor.execute(
            "UPDATE security_events SET event_id = ?, created_at = COALESCE(created_at, timestamp), updated_at = COALESCE(updated_at, timestamp) WHERE id = ?",
            (event_id, row[0])
        )

    cursor.execute("UPDATE security_events SET status = 'NEW' WHERE status IS NULL OR status = ''")
    cursor.execute("UPDATE security_events SET assigned_to = '' WHERE assigned_to IS NULL")
    cursor.execute("UPDATE security_events SET resolution_notes = '' WHERE resolution_notes IS NULL")
    cursor.execute("UPDATE security_events SET created_at = COALESCE(created_at, timestamp) WHERE created_at IS NULL")
    cursor.execute("UPDATE security_events SET updated_at = COALESCE(updated_at, timestamp) WHERE updated_at IS NULL")


def _insert_demo_data(cursor: sqlite3.Cursor) -> None:
    """Insert demonstration data for testing."""
    cursor.execute('SELECT COUNT(*) FROM security_events')
    if cursor.fetchone()[0] == 0:
        demo_events = [
            ('EVT-20241110-A1B2C3D4', '2024-11-10 10:00:00', 'Network Scan', 'INFO', '192.168.1.1', 'Scheduled network discovery scan completed', '{}', 'RESOLVED', '', '', '2024-11-10 10:00:00', '2024-11-10 10:05:00'),
            ('EVT-20241110-E5F6G7H8', '2024-11-10 11:30:00', 'Threat Detected', 'HIGH', '10.0.0.45', 'Suspicious outbound connection to known C2 server', '{"protocol": "TCP", "port": 4444}', 'NEW', '', '', '2024-11-10 11:30:00', '2024-11-10 11:30:00'),
            ('EVT-20241110-I9J0K1L2', '2024-11-10 12:15:00', 'Phishing Blocked', 'MEDIUM', 'user@company.com', 'Blocked phishing email with malicious attachment', '{"sender": "fake@bank.com"}', 'RESOLVED', '', '', '2024-11-10 12:15:00', '2024-11-10 12:20:00'),
            ('EVT-20241110-M3N4O5P6', '2024-11-10 13:00:00', 'File Scan', 'LOW', '/home/user/downloads/report.pdf', 'Clean file scan completed', '{}', 'RESOLVED', '', '', '2024-11-10 13:00:00', '2024-11-10 13:00:00'),
            ('EVT-20241110-Q7R8S9T0', '2024-11-10 14:45:00', 'Login Attempt', 'INFO', '192.168.1.100', 'Successful login for admin', '{}', 'RESOLVED', '', '', '2024-11-10 14:45:00', '2024-11-10 14:45:00'),
            ('EVT-20241110-U1V2W3X4', '2024-11-10 15:30:00', 'Vulnerability Found', 'CRITICAL', 'web-server-01', 'CVE-2024-12345 detected in Apache', '{"cve": "CVE-2024-12345", "cvss": 9.8}', 'INVESTIGATING', 'analyst1', '', '2024-11-10 15:30:00', '2024-11-10 15:35:00'),
            ('EVT-20241110-Y5Z6A7B8', '2024-11-10 16:00:00', 'Network Scan', 'INFO', '192.168.1.0/24', 'Daily network inventory scan completed', '{}', 'RESOLVED', '', '', '2024-11-10 16:00:00', '2024-11-10 16:05:00'),
            ('EVT-20241110-C9D0E1F2', '2024-11-10 17:20:00', 'Threat Detected', 'MEDIUM', '10.0.0.22', 'Multiple failed SSH attempts detected', '{"attempts": 47}', 'NEW', '', '', '2024-11-10 17:20:00', '2024-11-10 17:20:00'),
        ]
        cursor.executemany(
            'INSERT INTO security_events (event_id, timestamp, event_type, severity, source, description, details, status, assigned_to, resolution_notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            demo_events
        )

    cursor.execute('SELECT COUNT(*) FROM network_scans')
    if cursor.fetchone()[0] == 0:
        demo_scans = [
            ('192.168.1.10', 'Full Scan', 'Completed', '22,80,443,3306', 'None'),
            ('192.168.1.20', 'Quick Scan', 'Completed', '80,443', 'None'),
            ('10.0.0.5', 'Vulnerability Scan', 'Completed', '22,80,443,3389', 'CVE-2023-1234'),
            ('192.168.1.50', 'Full Scan', 'In Progress', '', ''),
        ]
        cursor.executemany(
            'INSERT INTO network_scans (target_ip, scan_type, status, open_ports, vulnerabilities) VALUES (?, ?, ?, ?, ?)',
            demo_scans
        )

    cursor.execute('SELECT COUNT(*) FROM threat_detections')
    if cursor.fetchone()[0] == 0:
        demo_threats = [
            ('Malware', 'HIGH', '10.0.0.45', 'workstation-07', 'Trojan.Generic detected', 0),
            ('Brute Force', 'MEDIUM', '10.0.0.22', 'ssh-server', 'SSH brute force attack', 1),
            ('Data Exfiltration', 'CRITICAL', '10.0.0.88', 'database-01', 'Unusual large data transfer', 0),
            ('Phishing', 'MEDIUM', None, 'user@company.com', 'Credential harvesting attempt', 1),
            ('Ransomware', 'CRITICAL', '10.0.0.12', 'fileserver-02', 'File encryption activity detected', 0),
        ]
        cursor.executemany(
            'INSERT INTO threat_detections (threat_type, severity, source_ip, target, description, mitigated) VALUES (?, ?, ?, ?, ?, ?)',
            demo_threats
        )

    cursor.execute('SELECT COUNT(*) FROM phishing_urls')
    if cursor.fetchone()[0] == 0:
        demo_phishing = [
            ('http://paypal-security-update.fake.com/login', 1, 0.97, '["suspicious_domain", "brand_impersonation", "urgency_tactics"]'),
            ('https://www.google.com', 0, 0.01, '[]'),
            ('http://microsoft-account-verify.phishersite.net/auth', 1, 0.94, '["typosquatting", "credential_harvesting"]'),
            ('https://github.com/user/repo', 0, 0.02, '[]'),
            ('http://amazon-order-confirmation.scam-site.org/track', 1, 0.91, '["brand_impersonation", "fake_order"]'),
        ]
        cursor.executemany(
            'INSERT INTO phishing_urls (url, is_phishing, confidence, indicators) VALUES (?, ?, ?, ?)',
            demo_phishing
        )

    cursor.execute('SELECT COUNT(*) FROM file_scans')
    if cursor.fetchone()[0] == 0:
        demo_files = [
            ('/home/user/document.pdf', 'a1b2c3d4e5f6', 'Clean', '[]', 1.2),
            ('/home/user/downloads/setup.exe', 'f6e5d4c3b2a1', 'Infected', '["Trojan.Win32.Generic", "PUA.InstallCore"]', 3.5),
            ('/home/user/image.png', '123456789abc', 'Clean', '[]', 0.8),
            ('/home/user/scripts/backup.sh', 'abcdef123456', 'Suspicious', '["Shell.Command.Injection"]', 2.1),
        ]
        cursor.executemany(
            'INSERT INTO file_scans (file_path, file_hash, scan_result, threats_found, scan_duration) VALUES (?, ?, ?, ?, ?)',
            demo_files
        )

    cursor.execute('SELECT COUNT(*) FROM login_attempts')
    if cursor.fetchone()[0] == 0:
        demo_logins = [
            ('admin', '192.168.1.100', 1, 'New York, US', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'),
            ('john.doe', '192.168.1.105', 1, 'London, UK', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'),
            ('admin', '203.0.113.45', 0, 'Unknown', 'curl/7.68.0'),
            ('jane.smith', '192.168.1.110', 1, 'Tokyo, JP', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'),
            ('admin', '198.51.100.23', 0, 'Unknown', 'Python-urllib/3.11'),
        ]
        cursor.executemany(
            'INSERT INTO login_attempts (username, ip_address, success, location, user_agent) VALUES (?, ?, ?, ?, ?)',
            demo_logins
        )

    cursor.execute('SELECT COUNT(*) FROM alerts')
    if cursor.fetchone()[0] == 0:
        demo_alerts = [
            ('Threat Detection', 'CRITICAL', 'Ransomware Activity Detected', 'File encryption detected on fileserver-02', 0),
            ('Network Anomaly', 'HIGH', 'Unusual Outbound Traffic', 'Large data transfer to unknown IP 10.0.0.88', 0),
            ('Vulnerability', 'HIGH', 'Critical CVE Detected', 'CVE-2024-12345 on web-server-01', 0),
            ('Phishing', 'MEDIUM', 'Phishing Campaign Blocked', '5 phishing emails blocked in last hour', 1),
            ('Brute Force', 'MEDIUM', 'SSH Brute Force Attempt', '47 failed attempts from 10.0.0.22', 1),
        ]
        cursor.executemany(
            'INSERT INTO alerts (alert_type, severity, title, message, acknowledged) VALUES (?, ?, ?, ?, ?)',
            demo_alerts
        )

    cursor.execute('SELECT COUNT(*) FROM settings')
    if cursor.fetchone()[0] == 0:
        default_settings = [
            ('theme', 'dark_blue'),
            ('auto_refresh', '30'),
            ('alert_sound', 'enabled'),
            ('scan_schedule', 'daily'),
            ('retention_days', '90'),
        ]
        cursor.executemany(
            'INSERT INTO settings (key, value) VALUES (?, ?)',
            default_settings
        )


def get_setting(key: str, default: str = '') -> str:
    """Get a setting value."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
        row = cursor.fetchone()
        return row['value'] if row else default


def set_setting(key: str, value: str) -> None:
    """Set a setting value."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            'INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)',
            (key, value)
        )