"""Tests for file scanner."""
import pytest
import sys
import os
import tempfile
import hashlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from file_scanner.scanner import FileScanner, FileScanResult, get_file_scanner


class TestFileScanner:
    """Test the file scanner."""

    def test_scanner_singleton(self):
        """Test that get_file_scanner returns singleton."""
        scanner1 = get_file_scanner()
        scanner2 = get_file_scanner()
        assert scanner1 is scanner2

    def test_calculate_hashes(self, test_db_path, monkeypatch):
        """Test SHA-256 and MD5 hash calculation."""
        import file_scanner.scanner as scanner_module
        monkeypatch.setattr(scanner_module, 'DB_PATH', test_db_path)

        scanner = FileScanner()

        # Create a temporary file with known content
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"Hello, World!")
            temp_path = f.name

        try:
            sha256_hash, md5_hash = scanner.calculate_hashes(temp_path)

            # Verify hashes
            expected_sha256 = hashlib.sha256(b"Hello, World!").hexdigest()
            expected_md5 = hashlib.md5(b"Hello, World!").hexdigest()

            assert sha256_hash == expected_sha256
            assert md5_hash == expected_md5
        finally:
            os.unlink(temp_path)

    def test_extract_metadata(self, test_db_path, monkeypatch):
        """Test file metadata extraction."""
        import file_scanner.scanner as scanner_module
        monkeypatch.setattr(scanner_module, 'DB_PATH', test_db_path)

        scanner = FileScanner()

        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"Test content for metadata")
            temp_path = f.name

        try:
            metadata = scanner.get_file_metadata(temp_path)

            assert 'size' in metadata
            assert metadata['size'] > 0
            assert 'created' in metadata
            assert 'modified' in metadata
            assert 'permissions' in metadata
        finally:
            os.unlink(temp_path)

    def test_scan_clean_file(self, test_db_path, monkeypatch):
        """Test scanning a clean file."""
        import file_scanner.scanner as scanner_module
        monkeypatch.setattr(scanner_module, 'DB_PATH', test_db_path)

        scanner = FileScanner()

        with tempfile.NamedTemporaryFile(mode='wb', suffix='.txt', delete=False) as f:
            f.write(b"This is a clean text file with no threats.")
            temp_path = f.name

        try:
            result = scanner.scan_file(temp_path)

            assert isinstance(result, FileScanResult)
            assert result.file_path == temp_path
            assert result.risk_level in ['SAFE', 'LOW_RISK', 'UNKNOWN', 'POTENTIALLY_UNWANTED', 'SUSPICIOUS', 'MALICIOUS', 'ERROR']
            assert isinstance(result.indicators, list)
            assert result.scan_duration_ms >= 0
        finally:
            os.unlink(temp_path)

    def test_scan_suspicious_patterns(self, test_db_path, monkeypatch):
        """Test detection of suspicious patterns in files."""
        import file_scanner.scanner as scanner_module
        monkeypatch.setattr(scanner_module, 'DB_PATH', test_db_path)

        scanner = FileScanner()

        # Create file with suspicious content
        suspicious_content = b"""
        eval(base64_decode("malicious_code"))
        powershell -enc aQBuAHYAbwBrAGUALQBtAGkAbQBpAGsAYQB0AHoA
        cmd.exe /c whoami
        """

        with tempfile.NamedTemporaryFile(mode='wb', suffix='.ps1', delete=False) as f:
            f.write(suspicious_content)
            temp_path = f.name

        try:
            result = scanner.scan_file(temp_path)

            # Should detect suspicious patterns
            assert result.risk_level in ['SUSPICIOUS', 'MALICIOUS', 'POTENTIALLY_UNWANTED']
            assert len(result.indicators) > 0
        finally:
            os.unlink(temp_path)

    def test_scan_malware_signatures(self, test_db_path, monkeypatch):
        """Test detection of known malware signatures."""
        import file_scanner.scanner as scanner_module
        import hashlib
        monkeypatch.setattr(scanner_module, 'DB_PATH', test_db_path)

        scanner = FileScanner()

        # EICAR test string (standard antivirus test)
        eicar = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        eicar_sha256 = hashlib.sha256(eicar).hexdigest()

        # Add EICAR hash to scanner's threat database
        scanner.add_threat_hash(eicar_sha256, "EICAR_TEST_FILE")

        with tempfile.NamedTemporaryFile(mode='wb', suffix='.com', delete=False) as f:
            f.write(eicar)
            temp_path = f.name

        try:
            result = scanner.scan_file(temp_path)

            # Should detect EICAR
            assert result.risk_level == 'MALICIOUS'
            assert 'EICAR' in result.threat_name
        finally:
            os.unlink(temp_path)

    def test_scan_nonexistent_file(self, test_db_path, monkeypatch):
        """Test scanning a non-existent file."""
        import file_scanner.scanner as scanner_module
        monkeypatch.setattr(scanner_module, 'DB_PATH', test_db_path)

        scanner = FileScanner()

        result = scanner.scan_file("/path/that/does/not/exist.exe")

        assert result.risk_level == 'ERROR'
        assert len(result.indicators) > 0
        assert 'read' in result.indicators[0].lower() or 'not found' in result.indicators[0].lower() or 'cannot' in result.indicators[0].lower()

    def test_get_threat_intelligence(self, test_db_path, monkeypatch):
        """Test threat intelligence database."""
        import file_scanner.scanner as scanner_module
        monkeypatch.setattr(scanner_module, 'DB_PATH', test_db_path)

        scanner = FileScanner()

        # Check that threat intelligence is loaded
        assert hasattr(scanner, '_threat_db')
        assert isinstance(scanner._threat_db, dict)
        assert len(scanner._threat_db) > 0

        # Check for common signatures
        sig_text = str(scanner._threat_db).lower()
        assert 'eicar' in sig_text or 'malware' in sig_text

    def test_risk_level_classification(self, test_db_path, monkeypatch):
        """Test risk level classification."""
        import file_scanner.scanner as scanner_module
        monkeypatch.setattr(scanner_module, 'DB_PATH', test_db_path)

        scanner = FileScanner()

        # Test various threat counts
        risk, name = scanner.classify_risk([], {})
        assert risk == 'SAFE'

        risk, name = scanner.classify_risk(['suspicious_extension: .exe'], {})
        assert risk in ['POTENTIALLY_UNWANTED', 'LOW_RISK', 'UNKNOWN']

        risk, name = scanner.classify_risk(['known_malware_hash: EICAR_TEST_FILE'], {})
        assert risk == 'MALICIOUS'
        assert 'EICAR' in name

    def test_file_scan_result_dataclass(self):
        """Test FileScanResult dataclass."""
        result = FileScanResult(
            file_path="/test/file.exe",
            file_name="file.exe",
            file_size=1024,
            file_type="PE32 executable",
            mime_type="application/x-msdownload",
            sha256_hash="abc123",
            md5_hash="def456",
            is_suspicious=True,
            risk_level="MALICIOUS",
            threat_name="EICAR_TEST_FILE",
            indicators=["known_malware_hash: EICAR_TEST_FILE"],
            metadata={"size": 1024},
            scan_timestamp="2024-01-01T00:00:00",
            scan_duration_ms=100.0
        )

        assert result.file_path == "/test/file.exe"
        assert result.file_name == "file.exe"
        assert result.file_size == 1024
        assert result.sha256_hash == "abc123"
        assert result.risk_level == "MALICIOUS"
        assert result.threat_name == "EICAR_TEST_FILE"


class TestFileScannerIntegration:
    """Integration tests for file scanner."""

    def test_scan_multiple_files(self, test_db_path, monkeypatch):
        """Test scanning multiple files."""
        import file_scanner.scanner as scanner_module
        monkeypatch.setattr(scanner_module, 'DB_PATH', test_db_path)

        scanner = FileScanner()

        test_files = []
        for i in range(3):
            with tempfile.NamedTemporaryFile(mode='wb', suffix=f'.txt', delete=False) as f:
                f.write(f"Test file {i}".encode())
                test_files.append(f.name)

        try:
            results = []
            for file_path in test_files:
                result = scanner.scan_file(file_path)
                results.append(result)

            assert len(results) == 3
            for result in results:
                assert isinstance(result, FileScanResult)
        finally:
            for file_path in test_files:
                os.unlink(file_path)