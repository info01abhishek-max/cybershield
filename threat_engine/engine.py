"""Centralized security event processing and threat detection engine."""
import sqlite3
import os
import json
import hashlib
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import threading


DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'database', 'cybershield.db')


class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventStatus(Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"


@dataclass
class SecurityEvent:
    """Security event data class."""
    id: Optional[int] = None
    event_id: str = ""
    timestamp: str = ""
    event_type: str = ""
    severity: str = "LOW"
    source: str = ""
    description: str = ""
    details: str = "{}"
    status: str = "NEW"
    assigned_to: str = ""
    resolution_notes: str = ""
    created_at: str = ""
    updated_at: str = ""


@dataclass
class DetectionRule:
    """Detection rule configuration."""
    rule_id: str
    name: str
    description: str
    event_type: str
    severity: str
    conditions: Dict[str, Any]
    enabled: bool = True
    cooldown_seconds: int = 300


class ThreatDetectionEngine:
    """Centralized security event processing engine."""

    def __init__(self):
        self._rules: List[DetectionRule] = []
        self._lock = threading.Lock()
        self._load_default_rules()
        self._last_analysis = {}

    def _load_default_rules(self) -> None:
        """Load default detection rules."""
        self._rules = [
            DetectionRule(
                rule_id="FAILED_LOGIN_BRUTE_FORCE",
                name="Brute Force Login Detection",
                description="Detect repeated failed login attempts from same IP",
                event_type="Authentication",
                severity="HIGH",
                conditions={
                    "failed_count": 5,
                    "time_window_minutes": 15,
                    "group_by": "ip_address"
                },
                enabled=True,
                cooldown_seconds=300
            ),
            DetectionRule(
                rule_id="FAILED_LOGIN_USER_ENUMERATION",
                name="User Enumeration Detection",
                description="Detect failed logins for many different usernames from same IP",
                event_type="Authentication",
                severity="MEDIUM",
                conditions={
                    "unique_usernames": 10,
                    "time_window_minutes": 15,
                    "group_by": "ip_address"
                },
                enabled=True,
                cooldown_seconds=300
            ),
            DetectionRule(
                rule_id="UNUSUAL_CONNECTION_FREQUENCY",
                name="Unusual Connection Frequency",
                description="Detect abnormally high connection rate to external hosts",
                event_type="Network",
                severity="MEDIUM",
                conditions={
                    "connections_per_minute": 100,
                    "time_window_minutes": 5,
                    "external_only": True
                },
                enabled=True,
                cooldown_seconds=300
            ),
            DetectionRule(
                rule_id="SUSPICIOUS_PROCESS_CONNECTION",
                name="Suspicious Process Network Activity",
                description="Detect network connections from suspicious processes",
                event_type="Process",
                severity="HIGH",
                conditions={
                    "suspicious_processes": [
                        "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
                        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
                        "bitsadmin.exe", "wmic.exe"
                    ],
                    "external_connections": True
                },
                enabled=True,
                cooldown_seconds=600
            ),
            DetectionRule(
                rule_id="PRIVILEGED_PORT_NON_SYSTEM",
                name="Non-System Process on Privileged Port",
                description="Detect non-system processes listening on ports < 1024",
                event_type="Network",
                severity="HIGH",
                conditions={
                    "port_threshold": 1024,
                    "exclude_system_users": ["SYSTEM", "root", "LOCAL SERVICE", "NETWORK SERVICE"]
                },
                enabled=True,
                cooldown_seconds=600
            ),
            DetectionRule(
                rule_id="CONNECTION_TO_SUSPICIOUS_PORT",
                name="Connection to Suspicious Port",
                description="Detect connections to commonly abused ports",
                event_type="Network",
                severity="MEDIUM",
                conditions={
                    "suspicious_ports": [
                        4444, 5555, 6666, 7777, 8888, 9999,
                        31337, 12345, 54321, 27374, 65000,
                        135, 139, 445, 1433, 3389, 5900
                    ]
                },
                enabled=True,
                cooldown_seconds=300
            ),
            DetectionRule(
                rule_id="MULTIPLE_FAILED_SUDO",
                name="Multiple Failed Sudo/Privilege Escalation",
                description="Detect repeated failed privilege escalation attempts",
                event_type="Authentication",
                severity="CRITICAL",
                conditions={
                    "failed_count": 3,
                    "time_window_minutes": 10
                },
                enabled=True,
                cooldown_seconds=300
            ),
            DetectionRule(
                rule_id="LOG_CLEARING",
                name="Security Log Clearing",
                description="Detect security event log clearing attempts",
                event_type="System",
                severity="CRITICAL",
                conditions={
                    "event_ids": [1102, 1100]
                },
                enabled=True,
                cooldown_seconds=600
            ),
        ]

    def get_rules(self) -> List[DetectionRule]:
        """Get all detection rules."""
        return self._rules

    def get_rule(self, rule_id: str) -> Optional[DetectionRule]:
        """Get a specific rule by ID."""
        for rule in self._rules:
            if rule.rule_id == rule_id:
                return rule
        return None

    def update_rule(self, rule_id: str, **kwargs) -> bool:
        """Update a detection rule."""
        for i, rule in enumerate(self._rules):
            if rule.rule_id == rule_id:
                for key, value in kwargs.items():
                    if hasattr(rule, key):
                        setattr(rule, key, value)
                return True
        return False

    def _generate_event_id(self) -> str:
        """Generate a unique event ID."""
        timestamp = str(time.time_ns())
        random_part = hashlib.md5(timestamp.encode()).hexdigest()[:8]
        return f"EVT-{datetime.now().strftime('%Y%m%d')}-{random_part.upper()}"

    def _save_event(self, event: SecurityEvent) -> int:
        """Save a security event to the database."""
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO security_events (
                    event_id, timestamp, event_type, severity, source,
                    description, details, status, assigned_to,
                    resolution_notes, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event.event_id,
                event.timestamp,
                event.event_type,
                event.severity,
                event.source,
                event.description,
                event.details,
                event.status,
                event.assigned_to,
                event.resolution_notes,
                event.created_at,
                event.updated_at
            ))
            return cursor.lastrowid

    def analyze_failed_logins(self) -> List[SecurityEvent]:
        """Analyze login attempts for brute force and enumeration patterns."""
        events = []
        cutoff = datetime.now() - timedelta(minutes=15)
        cutoff_str = cutoff.strftime('%Y-%m-%d %H:%M:%S')

        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute('''
                SELECT ip_address, username, timestamp, success
                FROM login_attempts
                WHERE timestamp >= ?
                ORDER BY timestamp DESC
            ''', (cutoff_str,))
            attempts = cursor.fetchall()

        if not attempts:
            return events

        ip_attempts = {}
        for attempt in attempts:
            ip = attempt['ip_address']
            if ip not in ip_attempts:
                ip_attempts[ip] = {'failed': 0, 'usernames': set(), 'timestamps': []}
            if not attempt['success']:
                ip_attempts[ip]['failed'] += 1
                ip_attempts[ip]['usernames'].add(attempt['username'])
            ip_attempts[ip]['timestamps'].append(attempt['timestamp'])

        for ip, data in ip_attempts.items():
            if data['failed'] >= 5:
                event = SecurityEvent(
                    event_id=self._generate_event_id(),
                    timestamp=datetime.now().isoformat(),
                    event_type="Authentication",
                    severity="HIGH",
                    source=ip,
                    description=f"Brute force attack detected: {data['failed']} failed login attempts from {ip} in 15 minutes",
                    details=json.dumps({
                        "failed_count": data['failed'],
                        "unique_usernames": len(data['usernames']),
                        "usernames": list(data['usernames']),
                        "time_window_minutes": 15,
                        "rule_id": "FAILED_LOGIN_BRUTE_FORCE"
                    }),
                    status="NEW",
                    created_at=datetime.now().isoformat(),
                    updated_at=datetime.now().isoformat()
                )
                self._save_event(event)
                events.append(event)

            elif len(data['usernames']) >= 10:
                event = SecurityEvent(
                    event_id=self._generate_event_id(),
                    timestamp=datetime.now().isoformat(),
                    event_type="Authentication",
                    severity="MEDIUM",
                    source=ip,
                    description=f"User enumeration detected: {len(data['usernames'])} unique usernames attempted from {ip} in 15 minutes",
                    details=json.dumps({
                        "failed_count": data['failed'],
                        "unique_usernames": len(data['usernames']),
                        "usernames": list(data['usernames']),
                        "time_window_minutes": 15,
                        "rule_id": "FAILED_LOGIN_USER_ENUMERATION"
                    }),
                    status="NEW",
                    created_at=datetime.now().isoformat(),
                    updated_at=datetime.now().isoformat()
                )
                self._save_event(event)
                events.append(event)

        return events

    def analyze_network_connections(self, connections: List[Dict[str, Any]]) -> List[SecurityEvent]:
        """Analyze network connections for suspicious patterns."""
        events = []
        now = datetime.now()

        suspicious_processes = {
            "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
            "bitsadmin.exe", "wmic.exe", "schtasks.exe", "at.exe"
        }

        suspicious_ports = {
            4444, 5555, 6666, 7777, 8888, 9999,
            31337, 12345, 54321, 27374, 65000,
            135, 139, 445, 1433, 3389, 5900
        }

        for conn in connections:
            remote_ip = conn.get('remote_address', '')
            remote_port = conn.get('remote_port', 0)
            local_port = conn.get('local_port', 0)
            process_name = conn.get('process_name', '').lower()
            status = conn.get('status', '')
            pid = conn.get('pid', 0)

            if not remote_ip or remote_ip in ['', '::', '0.0.0.0']:
                continue

            is_private = self._is_private_ip(remote_ip)

            if not is_private and process_name in suspicious_processes and status == 'ESTABLISHED':
                event = SecurityEvent(
                    event_id=self._generate_event_id(),
                    timestamp=now.isoformat(),
                    event_type="Process",
                    severity="HIGH",
                    source=remote_ip,
                    description=f"Suspicious process '{process_name}' (PID: {pid}) connected to external IP {remote_ip}:{remote_port}",
                    details=json.dumps({
                        "process_name": process_name,
                        "pid": pid,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "local_port": local_port,
                        "status": status,
                        "rule_id": "SUSPICIOUS_PROCESS_CONNECTION"
                    }),
                    status="NEW",
                    created_at=now.isoformat(),
                    updated_at=now.isoformat()
                )
                self._save_event(event)
                events.append(event)

            if remote_port in suspicious_ports and status in ['ESTABLISHED', 'SYN_SENT']:
                severity = "HIGH" if remote_port in [4444, 31337, 12345, 54321] else "MEDIUM"
                event = SecurityEvent(
                    event_id=self._generate_event_id(),
                    timestamp=now.isoformat(),
                    event_type="Network",
                    severity=severity,
                    source=remote_ip,
                    description=f"Connection to suspicious port {remote_port} on {remote_ip} by '{process_name}' (PID: {pid})",
                    details=json.dumps({
                        "process_name": process_name,
                        "pid": pid,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "local_port": local_port,
                        "status": status,
                        "rule_id": "CONNECTION_TO_SUSPICIOUS_PORT"
                    }),
                    status="NEW",
                    created_at=now.isoformat(),
                    updated_at=now.isoformat()
                )
                self._save_event(event)
                events.append(event)

            if local_port > 0 and local_port < 1024:
                try:
                    import psutil
                    if pid:
                        proc = psutil.Process(pid)
                        username = proc.username()
                        if username not in ["SYSTEM", "root", "LOCAL SERVICE", "NETWORK SERVICE"]:
                            event = SecurityEvent(
                                event_id=self._generate_event_id(),
                                timestamp=now.isoformat(),
                                event_type="Network",
                                severity="HIGH",
                                source="localhost",
                                description=f"Non-system process '{process_name}' (PID: {pid}, User: {username}) listening on privileged port {local_port}",
                                details=json.dumps({
                                    "process_name": process_name,
                                    "pid": pid,
                                    "username": username,
                                    "local_port": local_port,
                                    "local_address": conn.get('local_address', ''),
                                    "rule_id": "PRIVILEGED_PORT_NON_SYSTEM"
                                }),
                                status="NEW",
                                created_at=now.isoformat(),
                                updated_at=now.isoformat()
                            )
                            self._save_event(event)
                            events.append(event)
                except (ImportError, psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        return events

    def analyze_connection_frequency(self, connections: List[Dict[str, Any]]) -> List[SecurityEvent]:
        """Analyze connection frequency for unusual patterns."""
        events = []
        now = datetime.now()

        external_connections = [
            c for c in connections
            if c.get('remote_address') and not self._is_private_ip(c.get('remote_address', ''))
        ]

        if len(external_connections) > 100:
            event = SecurityEvent(
                event_id=self._generate_event_id(),
                timestamp=now.isoformat(),
                event_type="Network",
                severity="MEDIUM",
                source="multiple",
                description=f"Unusually high connection rate: {len(external_connections)} external connections detected",
                details=json.dumps({
                    "connection_count": len(external_connections),
                    "time_window_minutes": 5,
                    "external_only": True,
                    "rule_id": "UNUSUAL_CONNECTION_FREQUENCY"
                }),
                status="NEW",
                created_at=now.isoformat(),
                updated_at=now.isoformat()
            )
            self._save_event(event)
            events.append(event)

        return events

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal."""
        if not ip or ip in ['', '::', '0.0.0.0']:
            return True

        parts = ip.split('.')
        if len(parts) == 4:
            try:
                first = int(parts[0])
                second = int(parts[1])
                if first == 10:
                    return True
                if first == 172 and 16 <= second <= 31:
                    return True
                if first == 192 and second == 168:
                    return True
                if first == 127:
                    return True
                if first == 169 and second == 254:
                    return True
            except ValueError:
                pass

        if ip.startswith('fe80:') or ip.startswith('fc00:') or ip == '::1':
            return True

        return False

    def run_full_analysis(self, connections: List[Dict[str, Any]] = None) -> List[SecurityEvent]:
        """Run complete threat analysis."""
        all_events = []

        all_events.extend(self.analyze_failed_logins())

        if connections:
            all_events.extend(self.analyze_network_connections(connections))
            all_events.extend(self.analyze_connection_frequency(connections))

        return all_events

    def get_events(self,
                   severity: Optional[str] = None,
                   status: Optional[str] = None,
                   event_type: Optional[str] = None,
                   start_date: Optional[str] = None,
                   end_date: Optional[str] = None,
                   limit: int = 100) -> List[SecurityEvent]:
        """Get security events with filters."""
        query = "SELECT * FROM security_events WHERE 1=1"
        params = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if start_date:
            query += " AND timestamp >= ?"
            params.append(start_date)
        if end_date:
            query += " AND timestamp <= ?"
            params.append(end_date)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        events = []
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            for row in cursor.fetchall():
                events.append(SecurityEvent(
                    id=row['id'],
                    event_id=row['event_id'],
                    timestamp=row['timestamp'],
                    event_type=row['event_type'],
                    severity=row['severity'],
                    source=row['source'],
                    description=row['description'],
                    details=row['details'],
                    status=row['status'],
                    assigned_to=row['assigned_to'],
                    resolution_notes=row['resolution_notes'],
                    created_at=row['created_at'],
                    updated_at=row['updated_at']
                ))

        return events

    def get_event_by_id(self, event_id: str) -> Optional[SecurityEvent]:
        """Get a specific event by event_id."""
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM security_events WHERE event_id = ?', (event_id,))
            row = cursor.fetchone()
            if row:
                return SecurityEvent(
                    id=row['id'],
                    event_id=row['event_id'],
                    timestamp=row['timestamp'],
                    event_type=row['event_type'],
                    severity=row['severity'],
                    source=row['source'],
                    description=row['description'],
                    details=row['details'],
                    status=row['status'],
                    assigned_to=row['assigned_to'],
                    resolution_notes=row['resolution_notes'],
                    created_at=row['created_at'],
                    updated_at=row['updated_at']
                )
        return None

    def update_event_status(self, event_id: str, status: str, assigned_to: str = "", notes: str = "") -> bool:
        """Update event status."""
        valid_statuses = [s.value for s in EventStatus]
        if status not in valid_statuses:
            return False

        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE security_events
                SET status = ?, assigned_to = ?, resolution_notes = ?, updated_at = ?
                WHERE event_id = ?
            ''', (status, assigned_to, notes, datetime.now().isoformat(), event_id))
            return cursor.rowcount > 0

    def get_event_stats(self) -> Dict[str, Any]:
        """Get event statistics."""
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()

            cursor.execute('SELECT COUNT(*) FROM security_events')
            total = cursor.fetchone()[0]

            cursor.execute('SELECT severity, COUNT(*) FROM security_events GROUP BY severity')
            by_severity = dict(cursor.fetchall())

            cursor.execute('SELECT status, COUNT(*) FROM security_events GROUP BY status')
            by_status = dict(cursor.fetchall())

            cursor.execute('SELECT event_type, COUNT(*) FROM security_events GROUP BY event_type')
            by_type = dict(cursor.fetchall())

            cursor.execute('''
                SELECT COUNT(*) FROM security_events
                WHERE timestamp >= datetime('now', '-24 hours')
            ''')
            last_24h = cursor.fetchone()[0]

            return {
                "total": total,
                "by_severity": by_severity,
                "by_status": by_status,
                "by_type": by_type,
                "last_24h": last_24h
            }


_engine_instance = None

def get_threat_engine() -> ThreatDetectionEngine:
    """Get singleton threat detection engine instance."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = ThreatDetectionEngine()
    return _engine_instance