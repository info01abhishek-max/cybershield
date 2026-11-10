"""File Security Scanner module with hash calculation and threat detection."""
import os
import hashlib
import json
import sqlite3
import mimetypes
import magic
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import stat


DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'database', 'cybershield.db')

MAX_FILE_SIZE = 100 * 1024 * 1024

SUSPICIOUS_EXTENSIONS = {
    '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar',
    '.scr', '.com', '.pif', '.msi', '.app', '.dmg', '.pkg', '.deb',
    '.rpm', '.apk', '.ipa', '.bin', '.out', '.so', '.dylib'
}

SUSPICIOUS_MIME_TYPES = {
    'application/x-msdownload', 'application/x-msdos-program',
    'application/x-executable', 'application/x-sharedlib',
    'application/x-object', 'application/x-dosexec',
    'application/java-archive', 'application/x-jar',
    'application/x-python-code', 'application/x-perl',
    'application/x-shellscript'
}

KNOWN_MALWARE_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "EICAR_TEST_FILE",
    "d41d8cd98f00b204e9800998ecf8427e": "EMPTY_FILE",
}

HIGH_ENTROPY_THRESHOLD = 7.5


@dataclass
class FileScanResult:
    """Result of file scan."""
    file_path: str
    file_name: str
    file_size: int
    file_type: str
    mime_type: str
    sha256_hash: str
    md5_hash: str
    is_suspicious: bool
    risk_level: str
    threat_name: str
    indicators: List[str]
    metadata: Dict[str, Any]
    scan_timestamp: str
    scan_duration_ms: float


class FileScanner:
    """File security scanner with hash calculation and threat detection."""

    def __init__(self):
        self._threat_db = KNOWN_MALWARE_HASHES.copy()
        self._load_custom_threats()

    def _load_custom_threats(self) -> None:
        """Load custom threat hashes from database."""
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT file_hash, threats_found FROM file_scans
                    WHERE scan_result = 'Infected' AND file_hash IS NOT NULL
                ''')
                for row in cursor.fetchall():
                    if row[0] and row[1]:
                        try:
                            threats = json.loads(row[1])
                            for threat in threats:
                                self._threat_db[row[0]] = threat
                        except:
                            pass
        except Exception:
            pass

    def add_threat_hash(self, file_hash: str, threat_name: str) -> None:
        """Add a known threat hash to the local database."""
        self._threat_db[file_hash.lower()] = threat_name

    def calculate_hashes(self, file_path: str) -> Tuple[str, str]:
        """Calculate SHA-256 and MD5 hashes of a file."""
        sha256_hash = hashlib.sha256()
        md5_hash = hashlib.md5()

        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256_hash.update(chunk)
                    md5_hash.update(chunk)
        except (IOError, OSError, PermissionError) as e:
            raise Exception(f"Cannot read file: {str(e)}")

        return sha256_hash.hexdigest(), md5_hash.hexdigest()

    def get_file_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract file metadata."""
        metadata = {}
        try:
            stat_info = os.stat(file_path)
            metadata['size'] = stat_info.st_size
            metadata['created'] = datetime.fromtimestamp(stat_info.st_ctime).isoformat()
            metadata['modified'] = datetime.fromtimestamp(stat_info.st_mtime).isoformat()
            metadata['accessed'] = datetime.fromtimestamp(stat_info.st_atime).isoformat()
            metadata['permissions'] = oct(stat_info.st_mode & 0o777)
            metadata['is_executable'] = bool(stat_info.st_mode & stat.S_IXUSR)
            metadata['is_readonly'] = not bool(stat_info.st_mode & stat.S_IWUSR)
            metadata['uid'] = stat_info.st_uid
            metadata['gid'] = stat_info.st_gid
        except Exception:
            pass

        try:
            mime_type, encoding = mimetypes.guess_type(file_path)
            metadata['mimetypes_guess'] = mime_type
            metadata['encoding'] = encoding
        except Exception:
            pass

        try:
            file_type = magic.from_file(file_path, mime=False)
            mime_type = magic.from_file(file_path, mime=True)
            metadata['file_type'] = file_type
            metadata['mime_type'] = mime_type
        except Exception:
            pass

        return metadata

    def analyze_indicators(self, file_path: str, metadata: Dict[str, Any],
                          sha256_hash: str) -> List[str]:
        """Analyze file for suspicious indicators."""
        indicators = []
        file_name = os.path.basename(file_path)
        file_ext = os.path.splitext(file_name)[1].lower()

        if sha256_hash.lower() in self._threat_db:
            indicators.append(f'known_malware_hash: {self._threat_db[sha256_hash.lower()]}')

        if file_ext in SUSPICIOUS_EXTENSIONS:
            indicators.append(f'suspicious_extension: {file_ext}')

        mime_type = metadata.get('mime_type', '')
        if mime_type in SUSPICIOUS_MIME_TYPES:
            indicators.append(f'suspicious_mime_type: {mime_type}')

        if metadata.get('is_executable', False):
            indicators.append('executable_file')

        file_size = metadata.get('size', 0)
        if file_size > MAX_FILE_SIZE:
            indicators.append('oversized_file')

        if file_size == 0:
            indicators.append('empty_file')

        entropy = self._calculate_entropy(file_path)
        metadata['entropy'] = entropy
        if entropy > HIGH_ENTROPY_THRESHOLD:
            indicators.append(f'high_entropy: {entropy:.2f}')

        if self._has_embedded_files(file_path):
            indicators.append('embedded_content')

        if self._has_suspicious_strings(file_path):
            indicators.append('suspicious_strings')

        if self._is_packed(file_path, metadata):
            indicators.append('potentially_packed')

        return indicators

    def _calculate_entropy(self, file_path: str) -> float:
        """Calculate Shannon entropy of file content."""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(8192)
                if not data:
                    return 0.0

                from collections import Counter
                import math
                counts = Counter(data)
                length = len(data)
                entropy = -sum((count/length) * math.log2(count/length)
                              for count in counts.values())
                return entropy
        except Exception:
            return 0.0

    def _has_embedded_files(self, file_path: str) -> bool:
        """Check for embedded files (simple heuristic)."""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(32768)
                signatures = [
                    b'PK\x03\x04',  # ZIP
                    b'\x1f\x8b\x08',  # GZIP
                    b'BZh',  # BZIP2
                    b'\xfd7zXZ\x00',  # 7Z
                    b'Rar!\x1a\x07',  # RAR
                    b'MZ',  # PE executable
                    b'\x7fELF',  # ELF
                ]
                for sig in signatures:
                    if data.count(sig) > 1:
                        return True
        except Exception:
            pass
        return False

    def _has_suspicious_strings(self, file_path: str) -> bool:
        """Check for suspicious strings in file."""
        suspicious_strings = [
            b'CreateRemoteThread', b'VirtualAllocEx', b'WriteProcessMemory',
            b'OpenProcess', b'LoadLibrary', b'GetProcAddress',
            b'WinExec', b'ShellExecute', b'URLDownloadToFile',
            b'HttpSendRequest', b'InternetOpen', b'InternetConnect',
            b'cmd.exe', b'powershell', b'wscript', b'cscript',
            b'regsvr32', b'rundll32', b'certutil', b'bitsadmin',
            b'eval(', b'exec(', b'system(', b'shell_exec',
            b'base64_decode', b'gzinflate', b'str_rot13'
        ]
        try:
            with open(file_path, 'rb') as f:
                data = f.read(65536).lower()
                for s in suspicious_strings:
                    if s.lower() in data:
                        return True
        except Exception:
            pass
        return False

    def _is_packed(self, file_path: str, metadata: Dict[str, Any]) -> bool:
        """Heuristic check for packed executables."""
        file_type = metadata.get('file_type', '').lower()
        if 'pe32' in file_type or 'executable' in file_type:
            entropy = metadata.get('entropy', 0)
            if entropy > 7.0:
                return True
        return False

    def classify_risk(self, indicators: List[str], metadata: Dict[str, Any]) -> Tuple[str, str]:
        """Classify risk level and threat name from indicators."""
        if not indicators:
            return 'SAFE', 'No threats detected'

        threat_name = 'Unknown'
        for ind in indicators:
            if ind.startswith('known_malware_hash:'):
                threat_name = ind.split(': ')[1]
                return 'MALICIOUS', threat_name

        high_risk_indicators = [
            'high_entropy', 'executable_file', 'suspicious_strings',
            'potentially_packed', 'embedded_content'
        ]

        medium_risk_indicators = [
            'suspicious_extension', 'suspicious_mime_type',
            'suspicious_strings'
        ]

        high_count = sum(1 for ind in indicators if any(h in ind for h in high_risk_indicators))
        medium_count = sum(1 for ind in indicators if any(m in ind for m in medium_risk_indicators))

        if high_count >= 2 or (high_count >= 1 and medium_count >= 1):
            return 'SUSPICIOUS', 'Potentially unwanted or malicious'
        elif high_count >= 1 or medium_count >= 2:
            return 'POTENTIALLY_UNWANTED', 'Suspicious characteristics detected'
        elif medium_count >= 1:
            return 'LOW_RISK', 'Minor suspicious indicators'
        else:
            return 'UNKNOWN', 'Unable to classify'

    def scan_file(self, file_path: str) -> FileScanResult:
        """Scan a single file."""
        start_time = datetime.now()
        file_name = os.path.basename(file_path)

        try:
            file_size = os.path.getsize(file_path)
        except Exception:
            file_size = 0

        if file_size > MAX_FILE_SIZE:
            return FileScanResult(
                file_path=file_path,
                file_name=file_name,
                file_size=file_size,
                file_type='',
                mime_type='',
                sha256_hash='',
                md5_hash='',
                is_suspicious=True,
                risk_level='ERROR',
                threat_name='FileTooLarge',
                indicators=[f'file_exceeds_size_limit: {file_size} bytes'],
                metadata={'error': 'File exceeds maximum scan size'},
                scan_timestamp=start_time.isoformat(),
                scan_duration_ms=0
            )

        try:
            sha256_hash, md5_hash = self.calculate_hashes(file_path)
        except Exception as e:
            return FileScanResult(
                file_path=file_path,
                file_name=file_name,
                file_size=file_size,
                file_type='',
                mime_type='',
                sha256_hash='',
                md5_hash='',
                is_suspicious=True,
                risk_level='ERROR',
                threat_name='ReadError',
                indicators=[str(e)],
                metadata={'error': str(e)},
                scan_timestamp=start_time.isoformat(),
                scan_duration_ms=0
            )

        metadata = self.get_file_metadata(file_path)
        file_type = metadata.get('file_type', 'Unknown')
        mime_type = metadata.get('mime_type', 'Unknown')

        indicators = self.analyze_indicators(file_path, metadata, sha256_hash)
        risk_level, threat_name = self.classify_risk(indicators, metadata)
        is_suspicious = risk_level not in ['SAFE', 'LOW_RISK', 'UNKNOWN']

        scan_duration = (datetime.now() - start_time).total_seconds() * 1000

        return FileScanResult(
            file_path=file_path,
            file_name=file_name,
            file_size=file_size,
            file_type=file_type,
            mime_type=mime_type,
            sha256_hash=sha256_hash,
            md5_hash=md5_hash,
            is_suspicious=is_suspicious,
            risk_level=risk_level,
            threat_name=threat_name,
            indicators=indicators,
            metadata=metadata,
            scan_timestamp=start_time.isoformat(),
            scan_duration_ms=scan_duration
        )

    def save_scan_result(self, result: FileScanResult) -> None:
        """Save scan result to database."""
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO file_scans (
                        file_path, file_hash, scan_result, threats_found, scan_duration
                    ) VALUES (?, ?, ?, ?, ?)
                ''', (
                    result.file_path,
                    result.sha256_hash,
                    result.risk_level,
                    json.dumps([result.threat_name] + result.indicators),
                    result.scan_duration_ms / 1000.0
                ))
        except Exception as e:
            print(f"Failed to save scan result: {e}")

    def get_scan_history(self, limit: int = 100, filter_type: str = 'all') -> List[Dict[str, Any]]:
        """Get file scan history."""
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            if filter_type == 'malicious':
                cursor.execute('''
                    SELECT * FROM file_scans WHERE scan_result = 'MALICIOUS'
                    ORDER BY timestamp DESC LIMIT ?
                ''', (limit,))
            elif filter_type == 'suspicious':
                cursor.execute('''
                    SELECT * FROM file_scans WHERE scan_result IN ('SUSPICIOUS', 'POTENTIALLY_UNWANTED')
                    ORDER BY timestamp DESC LIMIT ?
                ''', (limit,))
            elif filter_type == 'clean':
                cursor.execute('''
                    SELECT * FROM file_scans WHERE scan_result IN ('SAFE', 'LOW_RISK', 'UNKNOWN')
                    ORDER BY timestamp DESC LIMIT ?
                ''', (limit,))
            else:
                cursor.execute('''
                    SELECT * FROM file_scans ORDER BY timestamp DESC LIMIT ?
                ''', (limit,))

            return [dict(row) for row in cursor.fetchall()]

    def get_stats(self) -> Dict[str, Any]:
        """Get file scanner statistics."""
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()

            cursor.execute('SELECT COUNT(*) FROM file_scans')
            total = cursor.fetchone()[0]

            cursor.execute('SELECT scan_result, COUNT(*) FROM file_scans GROUP BY scan_result')
            by_result = dict(cursor.fetchall())

            cursor.execute('SELECT AVG(scan_duration) FROM file_scans')
            avg_duration = cursor.fetchone()[0] or 0

            cursor.execute('SELECT SUM(file_size) FROM file_scans')
            total_bytes = cursor.fetchone()[0] or 0

            return {
                'total_scanned': total,
                'by_result': by_result,
                'avg_duration_sec': avg_duration,
                'total_bytes_scanned': total_bytes
            }


_scanner_instance = None

def get_file_scanner() -> FileScanner:
    """Get singleton file scanner instance."""
    global _scanner_instance
    if _scanner_instance is None:
        _scanner_instance = FileScanner()
    return _scanner_instance