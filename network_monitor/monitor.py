"""Network monitoring module using psutil for local network monitoring."""
import psutil
import time
import threading
import sqlite3
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import os


DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'database', 'cybershield.db')


@dataclass
class NetworkInterface:
    """Network interface information."""
    name: str
    is_up: bool
    speed: int
    mtu: int
    addresses: List[Dict[str, str]]
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    errin: int
    errout: int
    dropin: int
    dropout: int


@dataclass
class NetworkConnection:
    """Network connection information."""
    fd: int
    family: str
    type: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    status: str
    pid: int
    process_name: str


@dataclass
class ThroughputData:
    """Network throughput data point."""
    timestamp: datetime
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int


class NetworkMonitor:
    """Local network monitoring using psutil."""

    def __init__(self):
        self._history_lock = threading.Lock()
        self._throughput_history: List[ThroughputData] = []
        self._connection_history: List[Dict[str, Any]] = []
        self._max_history = 1000
        self._last_io_counters = None
        self._last_check_time = None

    def get_interfaces(self) -> List[NetworkInterface]:
        """Get all network interfaces with statistics."""
        interfaces = []

        try:
            io_counters = psutil.net_io_counters(pernic=True)
            ifaddrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
        except (PermissionError, OSError) as e:
            return interfaces

        for name, counters in io_counters.items():
            is_up = False
            speed = 0
            mtu = 0

            if name in stats:
                stat = stats[name]
                is_up = stat.isup
                speed = stat.speed
                mtu = stat.mtu

            addresses = []
            if name in ifaddrs:
                for addr in ifaddrs[name]:
                    addresses.append({
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    })

            interface = NetworkInterface(
                name=name,
                is_up=is_up,
                speed=speed,
                mtu=mtu,
                addresses=addresses,
                bytes_sent=counters.bytes_sent,
                bytes_recv=counters.bytes_recv,
                packets_sent=counters.packets_sent,
                packets_recv=counters.packets_recv,
                errin=counters.errin,
                errout=counters.errout,
                dropin=counters.dropin,
                dropout=counters.dropout
            )
            interfaces.append(interface)

        return interfaces

    def get_connections(self) -> List[NetworkConnection]:
        """Get active network connections."""
        connections = []

        try:
            conns = psutil.net_connections(kind='inet')
        except (PermissionError, OSError) as e:
            return connections

        for conn in conns:
            if conn.status == 'NONE':
                continue

            local_addr = ''
            local_port = 0
            remote_addr = ''
            remote_port = 0

            if conn.laddr:
                local_addr = conn.laddr.ip
                local_port = conn.laddr.port

            if conn.raddr:
                remote_addr = conn.raddr.ip
                remote_port = conn.raddr.port

            family = 'TCP' if conn.family == 2 else 'UDP' if conn.family == 10 else 'OTHER'
            conn_type = 'TCP' if conn.type == 1 else 'UDP' if conn.type == 2 else 'OTHER'

            pid = conn.pid or 0
            process_name = ''
            if pid:
                try:
                    proc = psutil.Process(pid)
                    process_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_name = 'Unknown'

            connection = NetworkConnection(
                fd=conn.fd or -1,
                family=family,
                type=conn_type,
                local_address=local_addr,
                local_port=local_port,
                remote_address=remote_addr,
                remote_port=remote_port,
                status=conn.status,
                pid=pid,
                process_name=process_name
            )
            connections.append(connection)

        return connections

    def get_throughput(self) -> Optional[ThroughputData]:
        """Calculate current network throughput."""
        try:
            current_io = psutil.net_io_counters()
        except (PermissionError, OSError):
            return None

        current_time = datetime.now()

        if self._last_io_counters is None or self._last_check_time is None:
            self._last_io_counters = current_io
            self._last_check_time = current_time
            return None

        time_delta = (current_time - self._last_check_time).total_seconds()
        if time_delta <= 0:
            return None

        bytes_sent_delta = current_io.bytes_sent - self._last_io_counters.bytes_sent
        bytes_recv_delta = current_io.bytes_recv - self._last_io_counters.bytes_recv
        packets_sent_delta = current_io.packets_sent - self._last_io_counters.packets_sent
        packets_recv_delta = current_io.packets_recv - self._last_io_counters.packets_recv

        throughput = ThroughputData(
            timestamp=current_time,
            bytes_sent=bytes_sent_delta,
            bytes_recv=bytes_recv_delta,
            packets_sent=packets_sent_delta,
            packets_recv=packets_recv_delta
        )

        self._last_io_counters = current_io
        self._last_check_time = current_time

        with self._history_lock:
            self._throughput_history.append(throughput)
            if len(self._throughput_history) > self._max_history:
                self._throughput_history = self._throughput_history[-self._max_history:]

        return throughput

    def get_throughput_history(self, minutes: int = 10) -> List[ThroughputData]:
        """Get throughput history for the last N minutes."""
        cutoff = datetime.now() - timedelta(minutes=minutes)
        with self._history_lock:
            return [t for t in self._throughput_history if t.timestamp >= cutoff]

    def get_connection_history(self, minutes: int = 10) -> List[Dict[str, Any]]:
        """Get connection history for the last N minutes."""
        cutoff = datetime.now() - timedelta(minutes=minutes)
        with self._history_lock:
            return [c for c in self._connection_history if c['timestamp'] >= cutoff]

    def record_connection_snapshot(self, connections: List[NetworkConnection]) -> None:
        """Record a snapshot of connections to history."""
        snapshot = {
            'timestamp': datetime.now(),
            'connections': [
                {
                    'local_address': c.local_address,
                    'local_port': c.local_port,
                    'remote_address': c.remote_address,
                    'remote_port': c.remote_port,
                    'status': c.status,
                    'pid': c.pid,
                    'process_name': c.process_name,
                    'family': c.family
                }
                for c in connections
            ]
        }

        with self._history_lock:
            self._connection_history.append(snapshot)
            if len(self._connection_history) > self._max_history:
                self._connection_history = self._connection_history[-self._max_history:]

    def check_suspicious_patterns(self, connections: List[NetworkConnection]) -> List[Dict[str, Any]]:
        """Check for suspicious connection patterns using rule-based detection."""
        alerts = []
        now = datetime.now()

        for conn in connections:
            if conn.remote_address and not self._is_private_ip(conn.remote_address):
                if conn.local_port == 0 and conn.status == 'ESTABLISHED':
                    alerts.append({
                        'type': 'Suspicious Outbound Connection',
                        'severity': 'MEDIUM',
                        'description': f'Process "{conn.process_name}" (PID: {conn.pid}) has established connection to external IP {conn.remote_address}:{conn.remote_port}',
                        'indicator': 'outbound_to_external',
                        'source_ip': conn.remote_address,
                        'target': f'{conn.local_address}:{conn.local_port}',
                        'timestamp': now.isoformat()
                    })

                if conn.status == 'SYN_SENT':
                    alerts.append({
                        'type': 'Connection Attempt',
                        'severity': 'LOW',
                        'description': f'Process "{conn.process_name}" attempting connection to {conn.remote_address}:{conn.remote_port}',
                        'indicator': 'syn_sent_external',
                        'source_ip': conn.remote_address,
                        'target': f'{conn.local_address}:{conn.local_port}',
                        'timestamp': now.isoformat()
                    })

            if conn.local_port > 0 and conn.local_port < 1024 and conn.pid > 0:
                try:
                    proc = psutil.Process(conn.pid)
                    if proc.username() != 'SYSTEM' and proc.username() != 'root':
                        alerts.append({
                            'type': 'Privileged Port Usage',
                            'severity': 'HIGH',
                            'description': f'Non-system process "{conn.process_name}" (PID: {conn.pid}) listening on privileged port {conn.local_port}',
                            'indicator': 'privileged_port',
                            'source_ip': conn.local_address,
                            'target': f'{conn.local_address}:{conn.local_port}',
                            'timestamp': now.isoformat()
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            if conn.remote_address and self._is_suspicious_port(conn.remote_port):
                alerts.append({
                    'type': 'Suspicious Port Connection',
                    'severity': 'MEDIUM',
                    'description': f'Connection to suspicious port {conn.remote_port} on {conn.remote_address} by "{conn.process_name}"',
                    'indicator': 'suspicious_port',
                    'source_ip': conn.remote_address,
                    'target': f'{conn.local_address}:{conn.local_port}',
                    'timestamp': now.isoformat()
                })

            if conn.status in ['ESTABLISHED', 'SYN_SENT'] and conn.remote_address:
                if self._is_high_volume_connection(conn):
                    alerts.append({
                        'type': 'High Volume Connection',
                        'severity': 'MEDIUM',
                        'description': f'Process "{conn.process_name}" has high-volume connection to {conn.remote_address}:{conn.remote_port}',
                        'indicator': 'high_volume',
                        'source_ip': conn.remote_address,
                        'target': f'{conn.local_address}:{conn.local_port}',
                        'timestamp': now.isoformat()
                    })

        return alerts

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

    def _is_suspicious_port(self, port: int) -> bool:
        """Check if port is commonly associated with malicious activity."""
        suspicious_ports = {
            4444, 5555, 6666, 7777, 8888, 9999,
            31337, 12345, 54321, 27374, 65000,
            135, 139, 445, 1433, 3389, 5900,
            6667, 6668, 6669, 7000, 8080, 8888
        }
        return port in suspicious_ports

    def _is_high_volume_connection(self, conn: NetworkConnection) -> bool:
        """Check if connection has unusually high volume (placeholder for future implementation)."""
        return False

    def scan_ports(self, host: str, ports: List[int], timeout: float = 1.0) -> List[int]:
        """Scan TCP ports on a host."""
        import socket
        open_ports = []

        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    result = sock.connect_ex((host, port))
                    if result == 0:
                        open_ports.append(port)
            except (socket.error, OSError):
                pass

        return open_ports

    def store_monitoring_event(self, event_type: str, severity: str, description: str, details: Dict[str, Any]) -> None:
        """Store a monitoring event in the database."""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO security_events (event_type, severity, source, description, details)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                event_type,
                severity,
                details.get('source_ip', 'localhost'),
                description,
                str(details)
            ))
            conn.commit()
            conn.close()
        except Exception:
            pass

    def get_total_bytes(self) -> Dict[str, int]:
        """Get total bytes sent/received across all interfaces."""
        try:
            io = psutil.net_io_counters()
            return {
                'bytes_sent': io.bytes_sent,
                'bytes_recv': io.bytes_recv,
                'packets_sent': io.packets_sent,
                'packets_recv': io.packets_recv
            }
        except (PermissionError, OSError):
            return {'bytes_sent': 0, 'bytes_recv': 0, 'packets_sent': 0, 'packets_recv': 0}

    def format_bytes(self, bytes_val: int) -> str:
        """Format bytes to human readable string."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024
        return f"{bytes_val:.1f} PB"

    def format_speed(self, bytes_per_sec: int) -> str:
        """Format bytes per second to human readable string."""
        return self.format_bytes(bytes_per_sec) + "/s"


_network_monitor_instance = None

def get_network_monitor() -> NetworkMonitor:
    """Get singleton network monitor instance."""
    global _network_monitor_instance
    if _network_monitor_instance is None:
        _network_monitor_instance = NetworkMonitor()
    return _network_monitor_instance