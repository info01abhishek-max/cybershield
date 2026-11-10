# CyberShield - Cybersecurity Protection Platform

A comprehensive cybersecurity monitoring and analysis platform built with Python and Streamlit. CyberShield provides real-time network monitoring, threat detection, phishing analysis, file scanning, AI-powered anomaly detection, login security analysis, alert management, and compliance reporting.

## Features

### Phase 1: Core Platform
- **Dashboard** - Real-time security metrics, threat severity visualization, activity trends, and recent events
- **Database** - SQLite with 8 tables for security events, network scans, threat detections, phishing URLs, file scans, login attempts, alerts, and settings
- **UI Components** - Dark blue cybersecurity theme with reusable metric cards, charts, and status badges

### Phase 2: Network Monitoring
- Real-time network interface monitoring with throughput charts
- Active connection tracking with process information
- Port scanning capabilities (Quick/Full/Vulnerability)
- Suspicious pattern detection (C2, data exfiltration, port scans)

### Phase 3: Threat Detection Engine
- Rule-based detection for authentication anomalies, network anomalies, and process anomalies
- Severity classification (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Event status tracking (NEW, INVESTIGATING, RESOLVED)
- Investigation panel with event details and timeline

### Phase 4: Phishing Detection
- Local URL analysis (no external API calls)
- Feature extraction: domain analysis, URL structure, brand impersonation
- Risk scoring with confidence levels
- Detection history with detailed analysis view

### Phase 5: File Scanner
- SHA-256/MD5 hash calculation
- File metadata extraction (MIME type, permissions, magic bytes)
- Threat intelligence matching (malware signatures, suspicious patterns)
- Risk classification (Clean/Suspicious/Infected)

### Phase 6: AI Security Analyzer
- ML-based threat classification (RandomForest, Logistic Regression)
- Anomaly detection (Isolation Forest)
- Model training with real or sample data
- Feature importance analysis
- Real-time prediction interface

### Phase 7: Login Security & Alerts & Reports
- **Login Security** - Windows login event analysis, brute force detection, credential stuffing, impossible travel detection, geographic analysis
- **Alerts Center** - Centralized alert management with acknowledgment workflow, severity filtering, statistics, and related event correlation
- **Reports** - Daily/Weekly/Monthly/Threat/Network/Login/Compliance/Custom reports with CSV and PDF export

## Requirements

- Python 3.10+
- Windows 10/11 (primary), Linux, macOS
- 4GB+ RAM recommended
- 500MB+ disk space

## Installation

### Quick Start (Windows)

```powershell
# Clone or navigate to the project
cd C:\path\to\cybershild

# Create virtual environment (recommended)
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
streamlit run app.py
```

### Quick Start (Linux/macOS)

```bash
# Clone or navigate to the project
cd /path/to/cybershild

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# For file type detection on Linux
sudo apt-get install libmagic1  # Debian/Ubuntu
# or
brew install libmagic  # macOS

# Run the application
streamlit run app.py
```

### Installing ReportLab for PDF Export

```bash
pip install reportlab
```

## Usage

1. Start the application: `streamlit run app.py`
2. Open your browser to `http://localhost:8501`
3. Navigate through the sidebar tabs:
   - **Dashboard** - Overview of security posture
   - **Network Monitor** - Interface monitoring, connections, scanning
   - **Threat Detection** - Event analysis, investigation, detection rules
   - **Phishing Detector** - URL scanning and analysis
   - **File Scanner** - File upload and malware detection
   - **AI Security Analyzer** - ML model training and prediction
   - **Login Security** - Authentication anomaly detection
   - **Alerts Center** - Alert triage and management
   - **Reports** - Generate and export security reports
   - **Settings** - Platform configuration

## Architecture

```
cybershild/
├── app.py                      # Main entry point, navigation
├── requirements.txt            # Python dependencies
├── README.md                   # This file
├── database/
│   ├── __init__.py
│   └── connection.py           # SQLite connection, migrations, demo data
├── components/
│   ├── __init__.py
│   └── ui.py                   # Reusable UI components, theme
├── features/                   # Streamlit page modules
│   ├── __init__.py
│   ├── dashboard.py
│   ├── network_monitor.py
│   ├── threat_detection.py
│   ├── phishing_detector.py
│   ├── file_scanner.py
│   ├── ai_analyzer.py
│   ├── login_security.py
│   ├── alerts_center.py
│   └── reports.py
├── network_monitor/
│   ├── __init__.py
│   └── monitor.py              # Network interface/connection monitoring
├── threat_engine/
│   ├── __init__.py
│   └── engine.py               # Rule-based threat detection
├── phishing_detector/
│   ├── __init__.py
│   └── detector.py             # URL phishing analysis
├── file_scanner/
│   ├── __init__.py
│   └── scanner.py              # File analysis and threat detection
└── ml_analyzer/
    ├── __init__.py
    └── analyzer.py             # ML models, anomaly detection
```

### Data Flow

1. **Data Collection** - Network monitor, file scanner, phishing detector collect raw data
2. **Storage** - All data persisted to SQLite via `database/connection.py`
3. **Analysis** - Threat engine, ML analyzer process data for anomalies
4. **Presentation** - Features render interactive Streamlit dashboards
5. **Alerting** - Alerts generated and managed in Alerts Center
6. **Reporting** - Reports module aggregates data for export

### Database Schema

| Table | Purpose |
|-------|---------|
| `security_events` | Central event log with status tracking |
| `network_scans` | Port scan results and vulnerabilities |
| `threat_detections` | Detected threats with severity |
| `phishing_urls` | Analyzed URLs with phishing classification |
| `file_scans` | File analysis results and hashes |
| `login_attempts` | Authentication events |
| `alerts` | Security alerts with acknowledgment |
| `settings` | Platform configuration |
| `reports` | Generated report history (created on demand) |

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test module
pytest tests/test_database.py -v
pytest tests/test_threat_engine.py -v
pytest tests/test_phishing_detector.py -v
pytest tests/test_file_scanner.py -v
pytest tests/test_network_monitor.py -v
pytest tests/test_ml_analyzer.py -v
```

## Windows 11 Compatibility

CyberShield is developed and tested on Windows 11 Pro. All system monitoring uses `psutil` which provides cross-platform compatibility. Windows-specific features:
- Network interface enumeration
- Process-to-connection mapping
- File permission checking
- Event log analysis (via login security module)

## Security Considerations

### Data Privacy
- All analysis performed locally - no external API calls for security operations
- No telemetry or data collection
- SQLite database stored locally

### Limitations
1. **Not a replacement for enterprise SIEM** - This is a demonstration/educational platform
2. **No real-time Windows Event Log integration** - Login security uses demo data; production would need Windows Event Log API
3. **No automatic response** - Alerts require manual acknowledgment
4. **ML models require training** - Default models use synthetic data; production needs labeled data
5. **File scanner uses signature matching** - Not a substitute for commercial AV/EDR
6. **Phishing detection is heuristic-based** - No threat intelligence feeds integrated

### Security Disclaimer

> **IMPORTANT**: CyberShield is a security monitoring and analysis platform designed for educational, demonstration, and development purposes. It is NOT a production-ready enterprise security solution.
>
> - Do not rely solely on CyberShield for critical infrastructure protection
> - Always validate findings with dedicated security tools
> - The ML models use synthetic training data and may produce false positives/negatives
> - Network monitoring requires appropriate permissions (Administrator/root)
> - File scanning does not execute or sandbox files
> - No warranty is provided for detection accuracy or completeness
>
> For production environments, use established solutions like:
> - SIEM: Splunk, Elastic, Microsoft Sentinel
> - EDR: CrowdStrike, SentinelOne, Microsoft Defender for Endpoint
> - Network Monitoring: Zeek, Suricata, Corelight
> - Vulnerability Management: Tenable, Qualys, Rapid7

## Contributing

This is a demonstration project. For educational purposes, feel free to extend and modify.

## License

MIT License - See LICENSE file for details.

## Version History

- **v1.0.0** - Phase 1-7 complete: Dashboard, Network Monitor, Threat Detection, Phishing Detector, File Scanner, AI Analyzer, Login Security, Alerts Center, Reports