"""AI Security Analyzer module with ML-based security classification."""
import os
import json
import pickle
import warnings
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, asdict
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report, confusion_matrix, precision_recall_fscore_support,
    accuracy_score, roc_auc_score
)
from sklearn.pipeline import Pipeline
from sklearn.base import BaseEstimator, TransformerMixin


MODEL_DIR = os.path.join(os.path.dirname(__file__), '..', 'models')
os.makedirs(MODEL_DIR, exist_ok=True)


@dataclass
class ModelMetrics:
    """Model evaluation metrics."""
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    roc_auc: float
    confusion_matrix: List[List[int]]
    classification_report: str
    timestamp: str
    model_type: str
    training_samples: int
    test_samples: int


@dataclass
class PredictionResult:
    """Prediction result with confidence and explanation."""
    prediction: str
    confidence: float
    probabilities: Dict[str, float]
    feature_importance: Dict[str, float]
    anomaly_score: Optional[float] = None
    is_anomaly: bool = False


class FeatureValidator(BaseEstimator, TransformerMixin):
    """Validate and sanitize input features."""

    def __init__(self, feature_names: List[str] = None):
        self.feature_names = feature_names or []
        self.expected_features = len(feature_names) if feature_names else 0

    def fit(self, X, y=None):
        if self.feature_names is None and hasattr(X, 'columns'):
            self.feature_names = list(X.columns)
            self.expected_features = len(self.feature_names)
        return self

    def transform(self, X):
        X_df = pd.DataFrame(X) if not isinstance(X, pd.DataFrame) else X.copy()

        if self.feature_names:
            missing = set(self.feature_names) - set(X_df.columns)
            extra = set(X_df.columns) - set(self.feature_names)

            for col in missing:
                X_df[col] = 0

            X_df = X_df[self.feature_names]

        X_df = X_df.replace([np.inf, -np.inf], np.nan)
        X_df = X_df.fillna(0)

        return X_df.values


class DatasetPreparator:
    """Prepare datasets for training and inference."""

    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_names = None
        self.is_fitted = False

    def prepare_network_features(self, events: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare features from network events."""
        if not events:
            return np.array([]), np.array([])

        features = []
        labels = []

        for event in events:
            feat = self._extract_network_features(event)
            features.append(feat)
            labels.append(event.get('label', 'benign'))

        X = pd.DataFrame(features)
        if self.feature_names is None:
            self.feature_names = list(X.columns)

        y = self.label_encoder.fit_transform(labels)

        return X.values, y

    def prepare_threat_features(self, events: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare features from threat detection events."""
        if not events:
            return np.array([]), np.array([])

        features = []
        labels = []

        for event in events:
            feat = self._extract_threat_features(event)
            features.append(feat)
            labels.append(event.get('label', 'benign'))

        X = pd.DataFrame(features)
        if self.feature_names is None:
            self.feature_names = list(X.columns)

        y = self.label_encoder.fit_transform(labels)

        return X.values, y

    def prepare_combined_features(self, network_events: List[Dict], threat_events: List[Dict]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare combined features from both network and threat events."""
        net_features = []
        net_labels = []
        threat_features = []
        threat_labels = []

        for event in network_events:
            net_features.append(self._extract_network_features(event))
            net_labels.append(event.get('label', 'benign'))

        for event in threat_events:
            threat_features.append(self._extract_threat_features(event))
            threat_labels.append(event.get('label', 'benign'))

        if net_features and threat_features:
            X_net = pd.DataFrame(net_features)
            X_threat = pd.DataFrame(threat_features)

            all_columns = set(X_net.columns) | set(X_threat.columns)

            for col in all_columns:
                if col not in X_net.columns:
                    X_net[col] = 0
                if col not in X_threat.columns:
                    X_threat[col] = 0

            X_net = X_net[sorted(all_columns)]
            X_threat = X_threat[sorted(all_columns)]

            X = np.vstack([X_net.values, X_threat.values])
            y = np.array(net_labels + threat_labels)
        elif net_features:
            X = pd.DataFrame(net_features).values
            y = np.array(net_labels)
        elif threat_features:
            X = pd.DataFrame(threat_features).values
            y = np.array(threat_labels)
        else:
            return np.array([]), np.array([])

        if self.feature_names is None:
            self.feature_names = sorted(all_columns)

        y = self.label_encoder.fit_transform(y)

        return X, y

    def _extract_network_features(self, event: Dict[str, Any]) -> Dict[str, float]:
        """Extract numerical features from network event."""
        features = {}

        features['bytes_sent'] = float(event.get('bytes_sent', 0))
        features['bytes_recv'] = float(event.get('bytes_recv', 0))
        features['packets_sent'] = float(event.get('packets_sent', 0))
        features['packets_recv'] = float(event.get('packets_recv', 0))
        features['connection_count'] = float(event.get('connection_count', 1))
        features['unique_ports'] = float(event.get('unique_ports', 0))
        features['unique_ips'] = float(event.get('unique_ips', 0))
        features['failed_connections'] = float(event.get('failed_connections', 0))
        features['external_connections'] = float(event.get('external_connections', 0))
        features['internal_connections'] = float(event.get('internal_connections', 0))
        features['avg_packet_size'] = (features['bytes_sent'] + features['bytes_recv']) / max(features['packets_sent'] + features['packets_recv'], 1)
        features['sent_recv_ratio'] = features['bytes_sent'] / max(features['bytes_recv'], 1)

        proto = event.get('protocol', '').lower()
        features['is_tcp'] = 1.0 if 'tcp' in proto else 0.0
        features['is_udp'] = 1.0 if 'udp' in proto else 0.0

        status = event.get('status', '').lower()
        features['is_established'] = 1.0 if 'established' in status else 0.0
        features['is_syn_sent'] = 1.0 if 'syn_sent' in status else 0.0
        features['is_time_wait'] = 1.0 if 'time_wait' in status else 0.0

        return features

    def _extract_threat_features(self, event: Dict[str, Any]) -> Dict[str, float]:
        """Extract numerical features from threat event."""
        features = {}

        severity_map = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4, 'info': 0}
        features['severity_score'] = float(severity_map.get(event.get('severity', '').lower(), 0))

        features['is_mitigated'] = 1.0 if event.get('mitigated', False) else 0.0
        features['source_ip_external'] = 1.0 if event.get('source_ip') and not self._is_private_ip(event.get('source_ip', '')) else 0.0

        threat_type = event.get('threat_type', '').lower()
        features['is_malware'] = 1.0 if 'malware' in threat_type else 0.0
        features['is_brute_force'] = 1.0 if 'brute' in threat_type else 0.0
        features['is_exfiltration'] = 1.0 if 'exfiltrat' in threat_type else 0.0
        features['is_phishing'] = 1.0 if 'phish' in threat_type else 0.0
        features['is_ransomware'] = 1.0 if 'ransom' in threat_type else 0.0

        return features

    def _is_private_ip(self, ip: str) -> bool:
        if not ip:
            return True
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return True

    def fit_scaler(self, X: np.ndarray):
        """Fit the scaler on training data."""
        self.scaler.fit(X)
        self.is_fitted = True

    def transform(self, X: np.ndarray) -> np.ndarray:
        """Transform features using fitted scaler."""
        if not self.is_fitted:
            self.fit_scaler(X)
        return self.scaler.transform(X)

    def get_feature_names(self) -> List[str]:
        return self.feature_names or []


class SecurityModel:
    """Lightweight security classification model."""

    def __init__(self, model_type: str = 'random_forest'):
        self.model_type = model_type
        self.model = None
        self.preparator = DatasetPreparator()
        self.metrics: Optional[ModelMetrics] = None
        self.is_trained = False

    def _create_model(self):
        """Create the base model."""
        if self.model_type == 'random_forest':
            return RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1,
                class_weight='balanced'
            )
        elif self.model_type == 'logistic':
            return LogisticRegression(
                max_iter=1000,
                class_weight='balanced',
                random_state=42,
                solver='lbfgs'
            )
        else:
            return RandomForestClassifier(n_estimators=50, max_depth=8, random_state=42)

    def train(self, network_events: List[Dict], threat_events: List[Dict] = None) -> ModelMetrics:
        """Train the model on security events."""
        if threat_events is None:
            threat_events = []

        X, y = self.preparator.prepare_combined_features(network_events, threat_events)

        if len(X) == 0 or len(np.unique(y)) < 2:
            raise ValueError("Insufficient training data or only one class present")

        X_scaled = self.preparator.fit_scaler(X)
        X_scaled = self.preparator.transform(X)

        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )

        self.model = self._create_model()
        self.model.fit(X_train, y_train)

        y_pred = self.model.predict(X_test)
        y_proba = self.model.predict_proba(X_test)[:, 1] if hasattr(self.model, 'predict_proba') else y_pred

        precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted', zero_division=0)
        accuracy = accuracy_score(y_test, y_pred)

        try:
            roc_auc = roc_auc_score(y_test, y_proba)
        except:
            roc_auc = 0.0

        cm = confusion_matrix(y_test, y_pred)
        cr = classification_report(y_test, y_pred, target_names=self.preparator.label_encoder.classes_, zero_division=0)

        self.metrics = ModelMetrics(
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1,
            roc_auc=roc_auc,
            confusion_matrix=cm.tolist(),
            classification_report=cr,
            timestamp=datetime.now().isoformat(),
            model_type=self.model_type,
            training_samples=len(X_train),
            test_samples=len(X_test)
        )

        self.is_trained = True
        return self.metrics

    def predict(self, network_event: Dict = None, threat_event: Dict = None) -> PredictionResult:
        """Make prediction on a single event."""
        if not self.is_trained or self.model is None:
            raise ValueError("Model not trained. Call train() first.")

        if network_event and threat_event:
            features = {**self.preparator._extract_network_features(network_event),
                       **self.preparator._extract_threat_features(threat_event)}
        elif network_event:
            features = self.preparator._extract_network_features(network_event)
        elif threat_event:
            features = self.preparator._extract_threat_features(threat_event)
        else:
            raise ValueError("At least one event must be provided")

        X = pd.DataFrame([features])

        if self.preparator.feature_names:
            for col in self.preparator.feature_names:
                if col not in X.columns:
                    X[col] = 0
            X = X[self.preparator.feature_names]

        X_scaled = self.preparator.transform(X.values)

        prediction = self.model.predict(X_scaled)[0]
        proba = self.model.predict_proba(X_scaled)[0] if hasattr(self.model, 'predict_proba') else None

        pred_label = self.preparator.label_encoder.inverse_transform([prediction])[0]

        probabilities = {}
        if proba is not None:
            for i, cls in enumerate(self.preparator.label_encoder.classes_):
                probabilities[cls] = float(proba[i])

        confidence = float(max(proba)) if proba is not None else 0.0

        feature_importance = {}
        if hasattr(self.model, 'feature_importances_') and self.preparator.feature_names:
            importances = self.model.feature_importances_
            for i, name in enumerate(self.preparator.feature_names):
                if i < len(importances):
                    feature_importance[name] = float(importances[i])

        feature_importance = dict(sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)[:10])

        return PredictionResult(
            prediction=pred_label,
            confidence=confidence,
            probabilities=probabilities,
            feature_importance=feature_importance
        )

    def save(self, path: str = None) -> str:
        """Save the trained model."""
        if not self.is_trained:
            raise ValueError("No trained model to save")

        if path is None:
            path = os.path.join(MODEL_DIR, f'security_model_{self.model_type}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pkl')

        model_data = {
            'model': self.model,
            'preparator': self.preparator,
            'metrics': self.metrics,
            'model_type': self.model_type,
            'is_trained': self.is_trained,
            'timestamp': datetime.now().isoformat()
        }

        with open(path, 'wb') as f:
            pickle.dump(model_data, f)

        return path

    @classmethod
    def load(cls, path: str) -> 'SecurityModel':
        """Load a trained model."""
        with open(path, 'rb') as f:
            model_data = pickle.load(f)

        instance = cls(model_data.get('model_type', 'random_forest'))
        instance.model = model_data['model']
        instance.preparator = model_data['preparator']
        instance.metrics = model_data.get('metrics')
        instance.is_trained = model_data.get('is_trained', False)

        return instance


class AnomalyDetector:
    """Anomaly detection for security events."""

    def __init__(self, contamination: float = 0.1):
        self.contamination = contamination
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42,
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.feature_names = None
        self.is_fitted = False

    def fit(self, network_events: List[Dict], threat_events: List[Dict] = None):
        """Fit the anomaly detector on normal data."""
        if threat_events is None:
            threat_events = []

        preparator = DatasetPreparator()
        X, _ = preparator.prepare_combined_features(network_events, threat_events)

        if len(X) == 0:
            return

        self.feature_names = preparator.feature_names
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_fitted = True

    def predict(self, network_event: Dict = None, threat_event: Dict = None) -> Tuple[bool, float]:
        """Predict if an event is anomalous."""
        if not self.is_fitted:
            return False, 0.0

        preparator = DatasetPreparator()
        preparator.feature_names = self.feature_names

        if network_event and threat_event:
            features = {**preparator._extract_network_features(network_event),
                       **preparator._extract_threat_features(threat_event)}
        elif network_event:
            features = preparator._extract_network_features(network_event)
        elif threat_event:
            features = preparator._extract_threat_features(threat_event)
        else:
            return False, 0.0

        X = pd.DataFrame([features])

        for col in self.feature_names:
            if col not in X.columns:
                X[col] = 0
        X = X[self.feature_names]

        X_scaled = self.scaler.transform(X.values)

        anomaly_score = self.model.decision_function(X_scaled)[0]
        is_anomaly = self.model.predict(X_scaled)[0] == -1

        normalized_score = float((anomaly_score + 0.5) * 100)
        normalized_score = max(0, min(100, normalized_score))

        return bool(is_anomaly), normalized_score


_analyzer_instance = None

def get_ai_analyzer() -> Tuple[SecurityModel, AnomalyDetector]:
    """Get singleton AI analyzer instances."""
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = (SecurityModel(), AnomalyDetector())
    return _analyzer_instance


def generate_sample_training_data(n_samples: int = 1000) -> Tuple[List[Dict], List[Dict]]:
    """Generate sample training data for demonstration."""
    np.random.seed(42)

    network_events = []
    threat_events = []

    for _ in range(n_samples):
        is_malicious = np.random.random() < 0.3

        if is_malicious:
            net_event = {
                'bytes_sent': np.random.exponential(1000000),
                'bytes_recv': np.random.exponential(500000),
                'packets_sent': np.random.poisson(1000),
                'packets_recv': np.random.poisson(500),
                'connection_count': np.random.poisson(50),
                'unique_ports': np.random.poisson(20),
                'unique_ips': np.random.poisson(10),
                'failed_connections': np.random.poisson(15),
                'external_connections': np.random.poisson(30),
                'internal_connections': np.random.poisson(5),
                'protocol': 'tcp',
                'status': 'established',
                'label': 'malicious'
            }
        else:
            net_event = {
                'bytes_sent': np.random.exponential(10000),
                'bytes_recv': np.random.exponential(50000),
                'packets_sent': np.random.poisson(50),
                'packets_recv': np.random.poisson(100),
                'connection_count': np.random.poisson(5),
                'unique_ports': np.random.poisson(3),
                'unique_ips': np.random.poisson(2),
                'failed_connections': np.random.poisson(1),
                'external_connections': np.random.poisson(2),
                'internal_connections': np.random.poisson(3),
                'protocol': np.random.choice(['tcp', 'udp']),
                'status': np.random.choice(['established', 'time_wait', 'close_wait']),
                'label': 'benign'
            }
        network_events.append(net_event)

    for _ in range(n_samples // 2):
        is_malicious = np.random.random() < 0.3

        severity = np.random.choice(['low', 'medium', 'high', 'critical'], p=[0.4, 0.3, 0.2, 0.1])

        if is_malicious:
            threat_event = {
                'severity': severity,
                'mitigated': np.random.random() < 0.3,
                'source_ip': f"10.0.0.{np.random.randint(1, 255)}",
                'threat_type': np.random.choice(['malware', 'brute_force', 'data_exfiltration', 'ransomware']),
                'label': 'malicious'
            }
        else:
            threat_event = {
                'severity': np.random.choice(['low', 'info']),
                'mitigated': True,
                'source_ip': f"192.168.1.{np.random.randint(1, 255)}",
                'threat_type': np.random.choice(['network_scan', 'phishing_blocked', 'file_scan']),
                'label': 'benign'
            }
        threat_events.append(threat_event)

    return network_events, threat_events