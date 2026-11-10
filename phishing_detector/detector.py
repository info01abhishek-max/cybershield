"""Phishing detection module with URL analysis and classification."""
import re
import json
import sqlite3
import os
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from urllib.parse import urlparse
import ipaddress


DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'database', 'cybershield.db')


@dataclass
class URLAnalysisResult:
    """Result of URL analysis."""
    url: str
    is_phishing: bool
    confidence: float
    risk_level: str
    indicators: List[str]
    features: Dict[str, Any]
    timestamp: str


class PhishingDetector:
    """URL analysis and phishing classification system."""

    def __init__(self):
        self._model = None
        self._model_loaded = False
        self._suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club', '.online',
            '.site', '.website', '.space', '.tech', '.info', '.biz', '.cc',
            '.pw', '.ws', '.me', '.co', '.io', '.live', '.app', '.dev'
        }
        self._brand_keywords = {
            'paypal', 'microsoft', 'amazon', 'apple', 'google', 'facebook',
            'bank', 'chase', 'wellsfargo', 'citibank', 'bankofamerica',
            'netflix', 'spotify', 'steam', 'discord', 'twitter', 'instagram',
            'linkedin', 'github', 'gitlab', 'bitbucket', 'dropbox', 'onedrive',
            'icloud', 'adobe', 'office365', 'outlook', 'yahoo', 'aol',
            'coinbase', 'binance', 'kraken', 'blockchain', 'wallet'
        }
        self._suspicious_subdomains = {
            'security', 'verify', 'update', 'login', 'account', 'auth',
            'signin', 'signup', 'password', 'reset', 'confirm', 'validate',
            'verification', 'authentication', 'authorize', 'oauth', 'sso',
            'secure', 'safety', 'protection', 'support', 'help', 'service',
            'admin', 'administrator', 'root', 'system', 'webmail', 'mail',
            'email', 'corp', 'corporate', 'internal', 'intranet', 'vpn',
            'remote', 'access', 'portal', 'gateway', 'proxy', 'tunnel'
        }

    def validate_url(self, url: str) -> Tuple[bool, str]:
        """Validate URL format."""
        if not url or not url.strip():
            return False, "URL cannot be empty"

        url = url.strip()

        if not re.match(r'^https?://', url, re.IGNORECASE):
            url = 'http://' + url

        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return False, "Invalid URL format: missing hostname"

            if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$', parsed.netloc.split(':')[0]):
                if not self._is_ip_address(parsed.netloc.split(':')[0]):
                    return False, "Invalid hostname format"

            return True, url
        except Exception as e:
            return False, f"Invalid URL: {str(e)}"

    def _is_ip_address(self, host: str) -> bool:
        """Check if host is an IP address."""
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def extract_features(self, url: str) -> Dict[str, Any]:
        """Extract features from URL for analysis."""
        features = {}
        parsed = urlparse(url)

        features['url'] = url
        features['scheme'] = parsed.scheme
        features['netloc'] = parsed.netloc
        features['path'] = parsed.path
        features['query'] = parsed.query
        features['fragment'] = parsed.fragment

        hostname = parsed.netloc.split(':')[0]
        features['hostname'] = hostname
        features['is_ip'] = self._is_ip_address(hostname)
        features['port'] = parsed.port or (443 if parsed.scheme == 'https' else 80)

        features['uses_https'] = parsed.scheme == 'https'
        features['url_length'] = len(url)
        features['hostname_length'] = len(hostname)
        features['path_length'] = len(parsed.path)
        features['query_length'] = len(parsed.query)

        features['dot_count'] = hostname.count('.')
        features['subdomain_count'] = max(0, hostname.count('.') - 1)

        features['has_at_symbol'] = '@' in url
        features['has_dash'] = '-' in hostname
        features['has_underscore'] = '_' in hostname
        features['has_tilde'] = '~' in url

        features['digit_count'] = sum(c.isdigit() for c in url)
        features['digit_ratio'] = features['digit_count'] / len(url) if url else 0

        features['suspicious_tld'] = any(hostname.endswith(tld) for tld in self._suspicious_tlds)

        brand_matches = []
        for brand in self._brand_keywords:
            if brand in url.lower():
                brand_matches.append(brand)
        features['brand_keywords'] = brand_matches
        features['brand_keyword_count'] = len(brand_matches)

        subdomain_parts = hostname.split('.')[:-2] if hostname.count('.') >= 2 else []
        suspicious_subdomain_matches = []
        for sub in subdomain_parts:
            for sus in self._suspicious_subdomains:
                if sus in sub.lower():
                    suspicious_subdomain_matches.append(sus)
        features['suspicious_subdomains'] = list(set(suspicious_subdomain_matches))
        features['suspicious_subdomain_count'] = len(features['suspicious_subdomains'])

        features['excessive_subdomains'] = features['subdomain_count'] > 3

        features['has_credential_in_url'] = '@' in url and ':' in url.split('@')[0]

        features['redirect_count'] = url.lower().count('http://') + url.lower().count('https://') - 1
        features['redirect_count'] = max(0, features['redirect_count'])

        features['shortened_url'] = any(short in hostname for short in
            ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly'])

        features['hex_encoded'] = bool(re.search(r'%[0-9a-fA-F]{2}', url))

        features['entropy'] = self._calculate_entropy(hostname)

        return features

    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not string:
            return 0.0
        from collections import Counter
        import math
        counts = Counter(string)
        length = len(string)
        entropy = -sum((count/length) * math.log2(count/length) for count in counts.values())
        return entropy

    def analyze_indicators(self, features: Dict[str, Any]) -> List[str]:
        """Analyze features and return list of suspicious indicators."""
        indicators = []

        if features['is_ip']:
            indicators.append('ip_address_in_host')

        if not features['uses_https']:
            indicators.append('no_https')

        if features['suspicious_tld']:
            indicators.append('suspicious_tld')

        if features['brand_keyword_count'] > 0:
            indicators.append('brand_impersonation')

        if features['suspicious_subdomain_count'] > 0:
            indicators.append('suspicious_subdomain')

        if features['excessive_subdomains']:
            indicators.append('excessive_subdomains')

        if features['has_at_symbol']:
            indicators.append('credential_in_url')

        if features['has_dash'] and features['brand_keyword_count'] > 0:
            indicators.append('typosquatting_attempt')

        if features['redirect_count'] > 0:
            indicators.append('url_redirect')

        if features['shortened_url']:
            indicators.append('url_shortener')

        if features['hex_encoded']:
            indicators.append('hex_encoding')

        if features['entropy'] > 3.5:
            indicators.append('high_entropy_hostname')

        if features['digit_ratio'] > 0.3:
            indicators.append('high_digit_ratio')

        if features['url_length'] > 200:
            indicators.append('excessive_url_length')

        if features['has_underscore']:
            indicators.append('underscore_in_hostname')

        if features['has_tilde']:
            indicators.append('tilde_in_url')

        return indicators

    def calculate_risk_score(self, features: Dict[str, Any], indicators: List[str]) -> Tuple[float, str]:
        """Calculate risk score and level from features and indicators."""
        score = 0.0

        weights = {
            'ip_address_in_host': 0.30,
            'no_https': 0.10,
            'suspicious_tld': 0.15,
            'brand_impersonation': 0.25,
            'suspicious_subdomain': 0.15,
            'excessive_subdomains': 0.10,
            'credential_in_url': 0.20,
            'typosquatting_attempt': 0.25,
            'url_redirect': 0.10,
            'url_shortener': 0.15,
            'hex_encoding': 0.10,
            'high_entropy_hostname': 0.15,
            'high_digit_ratio': 0.10,
            'excessive_url_length': 0.05,
            'underscore_in_hostname': 0.10,
            'tilde_in_url': 0.05,
        }

        for indicator in indicators:
            score += weights.get(indicator, 0.05)

        if features['brand_keyword_count'] > 1:
            score += 0.1 * (features['brand_keyword_count'] - 1)

        if features['suspicious_subdomain_count'] > 1:
            score += 0.05 * (features['suspicious_subdomain_count'] - 1)

        if features['is_ip'] and not features['uses_https']:
            score += 0.15

        score = min(score, 1.0)

        if score >= 0.7:
            risk_level = 'CRITICAL'
        elif score >= 0.5:
            risk_level = 'HIGH'
        elif score >= 0.3:
            risk_level = 'MEDIUM'
        elif score >= 0.1:
            risk_level = 'LOW'
        else:
            risk_level = 'SAFE'

        return score, risk_level

    def scan_url(self, url: str) -> URLAnalysisResult:
        """Scan a URL for phishing indicators."""
        valid, validated_url = self.validate_url(url)

        if not valid:
            return URLAnalysisResult(
                url=url,
                is_phishing=False,
                confidence=0.0,
                risk_level='INVALID',
                indicators=[validated_url],
                features={},
                timestamp=datetime.now().isoformat()
            )

        features = self.extract_features(validated_url)
        indicators = self.analyze_indicators(features)
        confidence, risk_level = self.calculate_risk_score(features, indicators)
        is_phishing = risk_level in ['CRITICAL', 'HIGH', 'MEDIUM']

        return URLAnalysisResult(
            url=validated_url,
            is_phishing=is_phishing,
            confidence=confidence,
            risk_level=risk_level,
            indicators=indicators,
            features=features,
            timestamp=datetime.now().isoformat()
        )

    def save_scan_result(self, result: URLAnalysisResult) -> None:
        """Save scan result to database."""
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO phishing_urls (
                        url, is_phishing, confidence, indicators, timestamp
                    ) VALUES (?, ?, ?, ?, ?)
                ''', (
                    result.url,
                    1 if result.is_phishing else 0,
                    result.confidence,
                    json.dumps(result.indicators),
                    result.timestamp
                ))
        except Exception as e:
            print(f"Failed to save scan result: {e}")

    def get_scan_history(self, limit: int = 100, filter_type: str = 'all') -> List[Dict[str, Any]]:
        """Get URL scan history."""
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            if filter_type == 'phishing':
                cursor.execute('''
                    SELECT * FROM phishing_urls WHERE is_phishing = 1
                    ORDER BY timestamp DESC LIMIT ?
                ''', (limit,))
            elif filter_type == 'safe':
                cursor.execute('''
                    SELECT * FROM phishing_urls WHERE is_phishing = 0
                    ORDER BY timestamp DESC LIMIT ?
                ''', (limit,))
            else:
                cursor.execute('''
                    SELECT * FROM phishing_urls
                    ORDER BY timestamp DESC LIMIT ?
                ''', (limit,))

            return [dict(row) for row in cursor.fetchall()]

    def get_stats(self) -> Dict[str, Any]:
        """Get phishing detection statistics."""
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()

            cursor.execute('SELECT COUNT(*) FROM phishing_urls')
            total = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM phishing_urls WHERE is_phishing = 1')
            phishing = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM phishing_urls WHERE is_phishing = 0')
            safe = cursor.fetchone()[0]

            cursor.execute('SELECT AVG(confidence) FROM phishing_urls WHERE is_phishing = 1')
            avg_conf = cursor.fetchone()[0] or 0

            cursor.execute('''
                SELECT indicators FROM phishing_urls WHERE is_phishing = 1
            ''')
            rows = cursor.fetchall()

            indicator_counts = {}
            for row in rows:
                try:
                    indicators = json.loads(row[0])
                    for ind in indicators:
                        indicator_counts[ind] = indicator_counts.get(ind, 0) + 1
                except:
                    pass

            return {
                'total_scanned': total,
                'phishing_detected': phishing,
                'safe_urls': safe,
                'avg_confidence': avg_conf,
                'top_indicators': dict(sorted(indicator_counts.items(), key=lambda x: x[1], reverse=True)[:10])
            }

    def load_model(self, model_path: str) -> bool:
        """Load a trained scikit-learn model if available."""
        try:
            import joblib
            self._model = joblib.load(model_path)
            self._model_loaded = True
            return True
        except Exception:
            self._model = None
            self._model_loaded = False
            return False

    def predict_with_model(self, features: Dict[str, Any]) -> Optional[float]:
        """Use loaded ML model for prediction if available."""
        if not self._model_loaded or self._model is None:
            return None

        try:
            feature_vector = self._features_to_vector(features)
            prob = self._model.predict_proba([feature_vector])[0][1]
            return float(prob)
        except Exception:
            return None

    def _features_to_vector(self, features: Dict[str, Any]) -> List[float]:
        """Convert features to model input vector."""
        return [
            float(features.get('uses_https', False)),
            float(features.get('is_ip', False)),
            float(features.get('suspicious_tld', False)),
            float(features.get('brand_keyword_count', 0)),
            float(features.get('suspicious_subdomain_count', 0)),
            float(features.get('subdomain_count', 0)),
            float(features.get('has_at_symbol', False)),
            float(features.get('has_dash', False)),
            float(features.get('redirect_count', 0)),
            float(features.get('shortened_url', False)),
            float(features.get('hex_encoded', False)),
            float(features.get('entropy', 0.0)),
            float(features.get('digit_ratio', 0.0)),
            float(features.get('url_length', 0)),
            float(features.get('hostname_length', 0)),
        ]


_detector_instance = None

def get_phishing_detector() -> PhishingDetector:
    """Get singleton phishing detector instance."""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = PhishingDetector()
    return _detector_instance