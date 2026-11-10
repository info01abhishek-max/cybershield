"""Tests for ML analyzer."""
import pytest
import sys
import os
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml_analyzer.analyzer import (
    SecurityModel, AnomalyDetector, DatasetPreparator,
    generate_sample_training_data, ModelMetrics, PredictionResult,
    get_ai_analyzer
)


class TestDatasetPreparator:
    """Test the dataset preparator."""

    def test_prepare_network_features(self):
        """Test preparing network features."""
        preparator = DatasetPreparator()

        network_events = [
            {
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
                'label': 'benign'
            }
        ]

        X, y = preparator.prepare_network_features(network_events)

        assert X.shape[0] == 1
        assert len(y) == 1
        assert y[0] in [0, 1]  # Encoded labels
        assert preparator.feature_names is not None
        assert len(preparator.feature_names) > 0

    def test_prepare_threat_features(self):
        """Test preparing threat features."""
        preparator = DatasetPreparator()

        threat_events = [
            {
                'severity': 'high',
                'mitigated': False,
                'source_ip': '10.0.0.100',
                'threat_type': 'malware',
                'label': 'malicious'
            }
        ]

        X, y = preparator.prepare_threat_features(threat_events)

        assert X.shape[0] == 1
        assert len(y) == 1
        assert preparator.feature_names is not None

    def test_prepare_combined_features(self):
        """Test preparing combined features."""
        preparator = DatasetPreparator()

        network_events = [{
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
            'label': 'benign'
        }]

        threat_events = [{
            'severity': 'high',
            'mitigated': False,
            'source_ip': '10.0.0.100',
            'threat_type': 'malware',
            'label': 'malicious'
        }]

        X, y = preparator.prepare_combined_features(network_events, threat_events)

        assert X.shape[0] == 2
        assert len(y) == 2

    def test_feature_scaling(self):
        """Test feature scaling."""
        preparator = DatasetPreparator()

        X = np.array([[10000, 50000, 100], [20000, 60000, 200]], dtype=float)

        X_scaled = preparator.fit_scaler(X)
        X_transformed = preparator.transform(X)

        assert X_transformed.shape == X.shape
        # Check that scaling happened (mean ~0, std ~1)
        assert abs(np.mean(X_transformed[:, 0])) < 0.1

    def test_get_feature_names(self):
        """Test getting feature names."""
        preparator = DatasetPreparator()

        network_events = [{
            'bytes_sent': 10000,
            'bytes_recv': 50000,
            'label': 'benign'
        }]

        preparator.prepare_network_features(network_events)
        names = preparator.get_feature_names()

        assert isinstance(names, list)
        assert len(names) > 0
        assert 'bytes_sent' in names
        assert 'bytes_recv' in names


class TestSecurityModel:
    """Test the security model."""

    def test_model_creation(self):
        """Test model creation."""
        model = SecurityModel(model_type='random_forest')

        assert model.model_type == 'random_forest'
        assert model.is_trained == False
        assert model.model is None

    def test_model_training(self):
        """Test model training with sample data."""
        model = SecurityModel(model_type='random_forest')

        network_events, threat_events = generate_sample_training_data(100)

        metrics = model.train(network_events, threat_events)

        assert isinstance(metrics, ModelMetrics)
        assert model.is_trained == True
        assert model.model is not None
        assert 0 <= metrics.accuracy <= 1
        assert 0 <= metrics.precision <= 1
        assert 0 <= metrics.recall <= 1
        assert 0 <= metrics.f1_score <= 1

    def test_model_prediction(self):
        """Test model prediction."""
        model = SecurityModel(model_type='random_forest')

        network_events, threat_events = generate_sample_training_data(100)
        model.train(network_events, threat_events)

        # Test network event prediction
        network_event = {
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

        result = model.predict(network_event=network_event)

        assert isinstance(result, PredictionResult)
        assert result.prediction in ['benign', 'malicious', 'suspicious']
        assert 0 <= result.confidence <= 1
        assert isinstance(result.probabilities, dict)
        assert isinstance(result.feature_importance, dict)

    def test_model_prediction_threat_event(self):
        """Test model prediction with threat event."""
        model = SecurityModel(model_type='random_forest')

        network_events, threat_events = generate_sample_training_data(100)
        model.train(network_events, threat_events)

        threat_event = {
            'severity': 'high',
            'threat_type': 'malware',
            'mitigated': False,
            'source_ip': '10.0.0.100',
        }

        result = model.predict(threat_event=threat_event)

        assert isinstance(result, PredictionResult)
        assert result.prediction in ['benign', 'malicious', 'suspicious']

    def test_model_prediction_combined(self):
        """Test model prediction with both event types."""
        model = SecurityModel(model_type='random_forest')

        network_events, threat_events = generate_sample_training_data(100)
        model.train(network_events, threat_events)

        network_event = {'bytes_sent': 10000, 'protocol': 'tcp'}
        threat_event = {'severity': 'high', 'threat_type': 'malware'}

        result = model.predict(network_event=network_event, threat_event=threat_event)

        assert isinstance(result, PredictionResult)

    def test_model_save_load(self, tmp_path):
        """Test model save and load."""
        model = SecurityModel(model_type='random_forest')

        network_events, threat_events = generate_sample_training_data(100)
        model.train(network_events, threat_events)

        save_path = tmp_path / "test_model.pkl"
        saved_path = model.save(str(save_path))

        assert os.path.exists(saved_path)

        loaded_model = SecurityModel.load(saved_path)

        assert loaded_model.is_trained == True
        assert loaded_model.model_type == 'random_forest'
        assert loaded_model.metrics is not None

    def test_untrained_model_prediction_error(self):
        """Test that untrained model raises error on prediction."""
        model = SecurityModel()

        with pytest.raises(ValueError, match="Model not trained"):
            model.predict(network_event={'bytes_sent': 1000})

    def test_logistic_regression_model(self):
        """Test logistic regression model type."""
        model = SecurityModel(model_type='logistic')

        network_events, threat_events = generate_sample_training_data(100)
        metrics = model.train(network_events, threat_events)

        assert model.is_trained == True
        assert metrics.model_type == 'logistic'


class TestAnomalyDetector:
    """Test the anomaly detector."""

    def test_anomaly_detector_creation(self):
        """Test anomaly detector creation."""
        detector = AnomalyDetector(contamination=0.1)

        assert detector.contamination == 0.1
        assert detector.is_fitted == False
        assert detector.model is not None

    def test_anomaly_detector_fit(self):
        """Test fitting anomaly detector."""
        detector = AnomalyDetector(contamination=0.1)

        network_events, threat_events = generate_sample_training_data(200)

        detector.fit(network_events, threat_events)

        assert detector.is_fitted == True
        assert detector.feature_names is not None

    def test_anomaly_prediction(self):
        """Test anomaly prediction."""
        detector = AnomalyDetector(contamination=0.1)

        network_events, threat_events = generate_sample_training_data(200)
        detector.fit(network_events, threat_events)

        network_event = {
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

        is_anomaly, score = detector.predict(network_event=network_event)

        assert isinstance(is_anomaly, bool)
        assert isinstance(score, float)
        assert 0 <= score <= 100

    def test_anomaly_prediction_unfitted(self):
        """Test anomaly prediction on unfitted detector."""
        detector = AnomalyDetector()

        is_anomaly, score = detector.predict(network_event={'bytes_sent': 1000})

        assert is_anomaly == False
        assert score == 0.0


class TestSampleDataGeneration:
    """Test sample data generation."""

    def test_generate_sample_training_data(self):
        """Test sample data generation."""
        network_events, threat_events = generate_sample_training_data(100)

        assert len(network_events) == 100
        assert len(threat_events) == 50  # Half of network events

        # Check structure
        for event in network_events:
            assert 'bytes_sent' in event
            assert 'label' in event
            assert event['label'] in ['benign', 'malicious']

        for event in threat_events:
            assert 'severity' in event
            assert 'label' in event
            assert event['label'] in ['benign', 'malicious']

    def test_data_balance(self):
        """Test that generated data has both classes."""
        network_events, threat_events = generate_sample_training_data(200)

        network_labels = [e['label'] for e in network_events]
        threat_labels = [e['label'] for e in threat_events]

        assert 'benign' in network_labels
        assert 'malicious' in network_labels
        assert 'benign' in threat_labels
        assert 'malicious' in threat_labels


class TestAIAnalyzerSingleton:
    """Test the AI analyzer singleton."""

    def test_get_ai_analyzer(self):
        """Test getting AI analyzer singleton."""
        model1, detector1 = get_ai_analyzer()
        model2, detector2 = get_ai_analyzer()

        assert model1 is model2
        assert detector1 is detector2