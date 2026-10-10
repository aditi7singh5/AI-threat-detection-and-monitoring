import numpy as np
from sklearn.ensemble import IsolationForest
import uuid
from typing import List, Tuple, Optional
from datetime import datetime, timezone

from app.models.schemas import (
    LogEvent, SecurityAlert, CloudProvider, SeverityLevel,
    AttackCategory, AlertStatus
)
from app.config import settings

class MLEngine:
    """
    Machine Learning Anomaly Detection Engine using Isolation Forest and Statistical Feature Vectors.
    """
    def __init__(self):
        self.model = IsolationForest(contamination=settings.ML_CONTAMINATION, random_state=42)
        self.is_fitted = False
        self._init_baseline_model()

    def _extract_features(self, log: LogEvent) -> List[float]:
        """Convert a LogEvent into a numeric feature vector for ML scoring."""
        bytes_val = float(log.bytes_transferred)
        tokens_val = float(log.token_count)
        
        # Action risk rating (0 - 10 scale)
        high_risk_actions = ["AttachUserPolicy", "CreatePrivilegedPod", "PutBucketPolicy", "DeleteBucket", "BatchGetSecretValue"]
        med_risk_actions = ["GetSecretValue", "CreatePod", "ChatCompletion", "ModifySecurityGroup"]
        
        if log.action in high_risk_actions:
            action_risk = 9.5
        elif log.action in med_risk_actions:
            action_risk = 5.0
        else:
            action_risk = 1.0

        # Geo Risk (0 - 10 scale)
        high_risk_geos = ["RU-Moscow", "CN-Beijing", "RO-Bucharest", "KP-Pyongyang"]
        geo_risk = 9.0 if any(g in log.geo_location for g in high_risk_geos) else 1.0

        # Payload Entropy / Keyword Count
        payload_str = str(log.payload)
        entropy = len(payload_str) / 50.0  # Proxy score

        return [bytes_val, tokens_val, action_risk, geo_risk, entropy]

    def _init_baseline_model(self):
        """Train IsolationForest on synthetic normal baseline vectors."""
        baseline_samples = []
        for _ in range(200):
            # Normal routine cloud traffic
            bytes_val = float(np.random.exponential(scale=15000))
            tokens_val = float(np.random.randint(50, 1500))
            action_risk = float(np.random.choice([1.0, 2.0, 3.0], p=[0.7, 0.2, 0.1]))
            geo_risk = 1.0
            entropy = float(np.random.uniform(0.5, 4.0))
            baseline_samples.append([bytes_val, tokens_val, action_risk, geo_risk, entropy])
        
        self.model.fit(baseline_samples)
        self.is_fitted = True

    def process_event(self, log: LogEvent) -> Tuple[LogEvent, Optional[SecurityAlert]]:
        features = self._extract_features(log)
        
        if self.is_fitted:
            # IsolationForest score range roughly -0.5 (extreme anomaly) to +0.5 (very normal)
            raw_score = self.model.decision_function([features])[0]
            # Convert raw_score to 0.0 - 100.0 Anomaly Score Index
            # Score near -0.3 maps to ~95.0 anomaly, score near 0.3 maps to ~5.0 anomaly
            normalized_anomaly = max(0.0, min(100.0, (0.3 - raw_score) * 160.0))
        else:
            normalized_anomaly = 10.0

        # If high risk features detected, boost score
        if features[2] > 8.0 or features[3] > 8.0:
            normalized_anomaly = max(normalized_anomaly, 85.0)

        log.anomaly_score = round(normalized_anomaly, 1)

        # Trigger ML Anomaly Alert if anomaly exceeds threshold
        ml_alert = None
        if log.anomaly_score >= settings.ANOMALY_SCORE_THRESHOLD:
            ml_alert = SecurityAlert(
                id=f"ALT-ML-{uuid.uuid4().hex[:6].upper()}",
                timestamp=log.timestamp,
                title=f"ML Anomaly Detected: {log.action} Deviation",
                description=f"Isolation Forest identified statistical anomaly score of {log.anomaly_score}/100 for identity '{log.identity}'.",
                category=AttackCategory.ANOMALOUS_ACCESS,
                severity=SeverityLevel.HIGH if log.anomaly_score > 88 else SeverityLevel.MEDIUM,
                status=AlertStatus.ACTIVE,
                provider=log.provider,
                source_log_id=log.id,
                rule_id="RULE-ML-ANOMALY",
                mitre_tactic="TA0006 - Unsupervised Anomaly Detection",
                mitre_technique="T1078 - Statistical Outlier Access",
                anomaly_score=log.anomaly_score,
                identity=log.identity,
                ip_address=log.ip_address,
                geo_location=log.geo_location
            )

        return log, ml_alert

ml_engine = MLEngine()
